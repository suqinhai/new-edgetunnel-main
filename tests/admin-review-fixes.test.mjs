import test from 'node:test';
import assert from 'node:assert/strict';
import worker, { __test } from '../_worker.js';

test('未绑定 D1 时定时任务正常跳过，不创建失败的后台任务', async () => {
  for (const env of [{}, { KV: { get() {}, put() {} } }, { DB: {} }]) {
    const tasks = [];
    await worker.scheduled({}, env, { waitUntil(task) { tasks.push(task); } });
    const results = await Promise.allSettled(tasks);
    assert.deepEqual(results, []);
  }
});

test('已绑定 D1 时仍执行定时任务，并保留真实数据库错误', async () => {
  const failure = new Error('database unavailable');
  const tasks = [];
  await worker.scheduled({}, { DB: { prepare() {}, async batch() { throw failure; } } }, {
    waitUntil(task) { tasks.push(task); }
  });
  assert.equal(tasks.length, 1);
  await assert.rejects(tasks[0], error => error === failure);
});

async function dialogFixture() {
  const html = await __test.访问链接增强管理页面().text();
  const source = html.slice(html.indexOf('function confirmDialog('), html.indexOf('function actionSpec('));
  // Model the browser's asynchronous close event, including the default Escape action.
  const dialog = new class extends EventTarget {
    open = false;
    showModal() { assert.equal(this.open, false); this.open = true; }
    close() {
      if (!this.open) return;
      this.open = false;
      setTimeout(() => this.dispatchEvent(new Event('close')), 0);
    }
    escape() {
      if (this.dispatchEvent(new Event('cancel', { cancelable: true }))) this.close();
    }
  }();
  const form = { onsubmit: null, fields: [] };
  const elements = { '#actionDialog': dialog, '#actionForm': form, '#dialogFields': {}, '#dialogTitle': {}, '#dialogMessage': {} };
  const confirmDialog = new Function('$', 'FormData', source + '; return confirmDialog;')(
    selector => elements[selector], class { constructor(input) { return new Map(input.fields); } }
  );
  const submit = value => form.onsubmit({ preventDefault() {}, submitter: { value } });
  return { dialog, form, confirmDialog, submit };
}

test('Esc 关闭确认弹窗后结束等待，恢复调用方按钮状态', { timeout: 1000 }, async () => {
  const { dialog, form, confirmDialog } = await dialogFixture();
  let disabled = true;
  const result = confirmDialog('停用链接', '', '').finally(() => { disabled = false; });
  dialog.escape();
  assert.equal(await result, null);
  assert.equal(disabled, false);
  assert.equal(form.onsubmit, null);
});

test('确认后立即打开二次确认，不会被上一弹窗的 close 事件取消', { timeout: 1000 }, async () => {
  const { dialog, form, confirmDialog, submit } = await dialogFixture();
  form.fields = [['mode', 'overwrite']];
  const first = confirmDialog('恢复备份', '', '');
  submit('confirm');
  assert.deepEqual(await first, { mode: 'overwrite' });
  form.fields = [['confirmOverwrite', 'RESTORE OVERWRITE']];
  const second = confirmDialog('二次确认', '', '');
  await new Promise(resolve => setTimeout(resolve, 10));
  assert.equal(dialog.open, true);
  submit('confirm');
  assert.deepEqual(await second, { confirmOverwrite: 'RESTORE OVERWRITE' });
});

test('取消按钮及再次打开后的 Esc 均不会返回上一次的确认数据', { timeout: 1000 }, async () => {
  const { dialog, form, confirmDialog, submit } = await dialogFixture();
  form.fields = [['hours', '24']];
  const first = confirmDialog('续期', '', '');
  submit('cancel');
  assert.equal(await first, null);
  const second = confirmDialog('续期', '', '');
  dialog.escape();
  assert.equal(await second, null);
});
