import test from 'node:test';
import assert from 'node:assert/strict';
import { __test } from '../_worker.js';

const base = (overrides = {}) => ({
  id: 1,
  token: 'x'.repeat(43),
  uuid: '00000000-0000-4000-8000-000000000000',
  status: 'active',
  duration_seconds: 3600,
  first_used_at: null,
  expires_at: null,
  connection_count: 0,
  active_connections: 0,
  max_concurrent_connections: 0,
  max_total_connections: 0,
  bind_first_ip: 0,
  bound_ip: null,
  connection_epoch: 0,
  ...overrides
});

test('首次真实连接开始计时并更新计数', () => {
  const now = 1_700_000_000_000;
  const result = __test.模拟访问链接激活(base(), now, '203.0.113.8');
  assert.equal(result.first_used_at, now);
  assert.equal(result.last_used_at, now);
  assert.equal(result.expires_at, now + 3_600_000);
  assert.equal(result.connection_count, 1);
  assert.equal(result.active_connections, 1);
});

test('永久链接不生成到期时间', () => {
  const result = __test.模拟访问链接激活(base({ duration_seconds: 0 }), 10_000, '203.0.113.8');
  assert.equal(result.first_used_at, 10_000);
  assert.equal(result.expires_at, null);
  assert.equal(__test.获取访问记录状态错误(result, 99_999), null);
});

test('过期链接拒绝连接', () => {
  assert.deepEqual(__test.获取访问记录状态错误(base({ expires_at: 999 }), 1000), { status: 410, message: '访问链接已过期' });
});

test('停用拒绝；恢复只允许未过期的 revoked 链接', () => {
  const now = 2000;
  assert.equal(__test.获取访问记录状态错误(base({ status: 'revoked' }), now).status, 403);
  assert.equal(__test.获取访问恢复错误(base({ status: 'revoked', expires_at: 3000 }), now), null);
  assert.match(__test.获取访问恢复错误(base({ status: 'revoked', expires_at: 1000 }), now), /续期/);
});

test('续期从当前时间或原到期时间中较晚者开始', () => {
  assert.equal(__test.计算续期到期时间(5000, 4000, 1), 3_605_000);
  assert.equal(__test.计算续期到期时间(3000, 4000, 1), 3_604_000);
});

test('未使用链接续期只增加可用时长且不提前开始倒计时', () => {
  const unused = base({ duration_seconds: 3 * 3600, first_used_at: null, expires_at: null });
  assert.equal(__test.计算访问链接续期到期时间(unused, 5000, 1), null);
  const used = base({ first_used_at: 1000, expires_at: 4000 });
  assert.equal(__test.计算访问链接续期到期时间(used, 5000, 1), 3_605_000);
});

test('重置计时清除分配、绑定和统计并增加连接代次', () => {
  const result = __test.模拟重置访问链接(base({ proxy_ip: 'proxy.example', first_used_at: 1, expires_at: 2, connection_count: 9, active_connections: 2, bound_ip: '203.0.113.8', connection_epoch: 4 }));
  assert.equal(result.proxy_ip, null);
  assert.equal(result.first_used_at, null);
  assert.equal(result.connection_count, 0);
  assert.equal(result.active_connections, 0);
  assert.equal(result.bound_ip, null);
  assert.equal(result.connection_epoch, 5);
});

test('并发与累计连接限制均在激活前拒绝', () => {
  assert.match(__test.访问限制错误(base({ max_concurrent_connections: 2, active_connections: 2 }), '', 1).message, /并发上限/);
  assert.match(__test.访问限制错误(base({ max_total_connections: 3, connection_count: 3 }), '', 1).message, /累计连接次数/);
});

test('首次 IP 绑定后只允许相同 IP', () => {
  const first = __test.模拟访问链接激活(base({ bind_first_ip: 1 }), 1000, '203.0.113.8');
  assert.equal(first.bound_ip, '203.0.113.8');
  assert.equal(__test.访问限制错误(first, '203.0.113.8', 1001), null);
  assert.match(__test.访问限制错误(first, '203.0.113.9', 1001).message, /绑定其他客户端/);
});

test('Token/UUID 可分别或同时轮换且保留业务状态', () => {
  const original = base({ country: 'TW', connection_count: 12 });
  const tokenOnly = __test.生成轮换访问凭据(original, 'token');
  assert.notEqual(tokenOnly.token, original.token);
  assert.equal(tokenOnly.uuid, original.uuid);
  assert.equal(tokenOnly.connection_count, 12);
  const both = __test.生成轮换访问凭据(original, 'both');
  assert.notEqual(both.token, original.token);
  assert.notEqual(both.uuid, original.uuid);
});

test('故障转移跳过当前、隔离及冷却候选并优先评分', () => {
  const now = 1000;
  const selected = __test.选择健康故障转移候选([
    { proxy_ip: 'current', enabled: 1, health_status: 'healthy', health_score: 99 },
    { proxy_ip: 'cooldown', enabled: 1, health_status: 'healthy', cooldown_until: 2000, health_score: 98 },
    { proxy_ip: 'bad', enabled: 1, health_status: 'unhealthy', health_score: 90 },
    { proxy_ip: 'backup-a', enabled: 1, health_status: 'healthy', health_score: 70, latency_ms: 80 },
    { proxy_ip: 'backup-b', enabled: 1, health_status: 'healthy', health_score: 80, latency_ms: 120 }
  ], 'current', now);
  assert.equal(selected.proxy_ip, 'backup-b');
});

test('登录连续失败达到阈值后进入短时封禁', () => {
  let state = { failure_count: 3, blocked_until: null };
  state = __test.计算登录失败状态(state, 1000, 5, 60_000);
  assert.equal(state.blocked_until, null);
  state = __test.计算登录失败状态(state, 2000, 5, 60_000);
  assert.equal(state.blocked_until, 62_000);
});

test('CSRF 与 Origin 必须同时通过', async () => {
  const csrf = 'csrf-value';
  const session = { csrf_hash: await __test.SHA256十六进制(csrf) };
  const good = new Request('https://example.com/admin/access/api/links/action', { method: 'POST', headers: { Origin: 'https://example.com', Cookie: 'admin_csrf=' + csrf, 'X-CSRF-Token': csrf } });
  assert.equal(await __test.验证管理员修改请求(good, {}, new URL(good.url), session, true), null);
  const badOrigin = new Request(good.url, { method: 'POST', headers: { Origin: 'https://evil.example', Cookie: 'admin_csrf=' + csrf, 'X-CSRF-Token': csrf } });
  assert.equal((await __test.验证管理员修改请求(badOrigin, {}, new URL(good.url), session, true)).status, 403);
  const noCsrf = new Request(good.url, { method: 'POST', headers: { Origin: 'https://example.com' } });
  assert.equal((await __test.验证管理员修改请求(noCsrf, {}, new URL(good.url), session, true)).status, 403);
});

test('批量操作能报告部分成功与失败明细', () => {
  const summary = __test.汇总批量操作结果([{ id: 1, success: true }, { id: 2, success: false, error: 'expired' }]);
  assert.equal(summary.affected, 1);
  assert.equal(summary.partial, true);
  assert.deepEqual(summary.failed.map(item => item.id), [2]);
});

test('批量链接导出每条记录独占一行并包含订阅与访问链接', () => {
  const content = __test.格式化批量访问链接导出([
    { subscription_url: 'https://example.com/sub?token=one', node_url: 'vless://first@example.com' },
    { subscription_url: "https://example.com/sub?token=o'ne", node_url: 'vless://second\\path@example.com' }
  ]);
  assert.equal(content,
    "['https://example.com/sub?token=one','vless://first@example.com']\r\n" +
    "['https://example.com/sub?token=o\\'ne','vless://second\\\\path@example.com']\r\n");
  assert.equal(__test.格式化批量访问链接导出([]), '');
});

test('访问链接页面提供勾选记录的批量订阅和链接导出', async () => {
  const html = await __test.访问链接增强管理页面().text();
  assert.match(html, /<option value="export">导出订阅和链接<\/option>/);
  assert.match(html, /action==='export'\?exportSelected\(ids\):runAction/);
  assert.match(html, /复制订阅<\/button><button[^>]+>复制链接<\/button>/);
});

test('外部数据源仅允许 HTTPS 且阻止本地与私网地址', () => {
  assert.equal(__test.标准化访问数据源URL('https://example.com/list.json'), 'https://example.com/list.json');
  assert.throws(() => __test.标准化访问数据源URL('http://example.com/list'), /HTTPS/);
  assert.throws(() => __test.标准化访问数据源URL('https://127.0.0.1/list'), /本地或私有/);
  assert.throws(() => __test.标准化访问数据源URL('https://192.168.1.2/list'), /本地或私有/);
  assert.throws(() => __test.标准化访问数据源URL('https://[::1]/list'), /本地或私有/);
});

test('每个请求独立保存代理配置且显式关闭 SOCKS 不回退到全局值', async () => {
  const baseProxy = { 反代IP: 'fallback.example', 启用反代兜底: true, 启用SOCKS5反代: null, 启用SOCKS5全局反代: false, parsedSocks5Address: {} };
  const [first, second] = await Promise.all([
    __test.反代参数获取(new URL('https://example.com/?socks5=proxy-a.example:1080'), '', baseProxy),
    __test.反代参数获取(new URL('https://example.com/?socks5=proxy-b.example:1080'), '', baseProxy)
  ]);
  assert.equal(first.parsedSocks5Address.hostname, 'proxy-a.example');
  assert.equal(second.parsedSocks5Address.hostname, 'proxy-b.example');
  assert.notEqual(first.parsedSocks5Address, second.parsedSocks5Address);
  assert.equal(__test.获取TCP反代配置().启用SOCKS5反代, null);
  const accessProxy = __test.获取TCP反代配置({ ...baseProxy, 启用SOCKS5反代: null });
  assert.equal(accessProxy.启用SOCKS5反代, null);
});

test('管理页面渲染后的内嵌脚本可被浏览器解析', async () => {
  const response = __test.访问链接增强管理页面();
  const html = await response.text();
  const script = html.match(/<script>([\s\S]*?)<\/script>/)?.[1];
  assert.ok(script, '管理页面应包含内嵌脚本');
  assert.doesNotThrow(() => new Function(script));
  assert.match(script, /'\\n→\\n'/);
});

test('并发 TCP 拨号不会在调用连接器前引用未定义变量', async () => {
  const opened = [];
  const pending = new ReadableStream();
  const request = {
    fetcher: {
      connect(options) {
        opened.push(options);
        return {
          opened: Promise.resolve(),
          closed: new Promise(() => {}),
          readable: pending,
          writable: new WritableStream(),
          close() {}
        };
      }
    }
  };
  const bridge = { readyState: WebSocket.OPEN, send() {}, close() { this.readyState = WebSocket.CLOSED; } };
  await __test.forwardataTCP('203.0.113.10', 443, new Uint8Array([1]), bridge, null, {}, base().uuid, request, {
    反代IP: '203.0.113.11',
    启用反代兜底: false,
    启用SOCKS5反代: null
  });
  assert.equal(opened.length, 2);
});

test('SOCKS5 握手支持分包并保留下游同包数据', async () => {
  const chunks = [
    new Uint8Array([0x05]),
    new Uint8Array([0x00]),
    new Uint8Array([0x05, 0x00]),
    new Uint8Array([0x00, 0x01, 0, 0]),
    new Uint8Array([0, 0, 0, 0, 9, 8])
  ];
  let index = 0;
  const socket = {
    readable: new ReadableStream({ pull(controller) { index < chunks.length ? controller.enqueue(chunks[index++]) : controller.close(); } }),
    writable: new WritableStream(),
    closed: new Promise(() => {}),
    close() {}
  };
  const connected = await __test.socks5Connect('example.com', 443, new Uint8Array(), () => socket, { hostname: 'proxy.example', port: 1080 });
  const first = await connected.readable.getReader().read();
  assert.deepEqual(Array.from(first.value), [9, 8]);
});

test('XHTTP 上传结束后保留租约直到下行连接结束', async () => {
  const uuid = base().uuid;
  const requestHeader = new Uint8Array([0, ...Buffer.from(uuid.replaceAll('-', ''), 'hex'), 0, 1, 1, 187, 1, 203, 0, 113, 10, 65]);
  const statements = [];
  const DB = {
    prepare(sql) { return { sql, bind() { return this; }, async run() { return { meta: { changes: 1 } }; }, async first() { return record; } }; },
    async batch(items) { statements.push(...items.map(item => item.sql)); return []; }
  };
  const record = base({ expires_at: Date.now() + 60_000 });
  const context = { 记录: record, env: { DB }, 激活任务: Promise.resolve(record), leaseId: 'lease-1', 代理连接成功: true, 已释放: false };
  context.反代上下文 = { 反代IP: '203.0.113.11', 启用反代兜底: false, 启用SOCKS5反代: null, 访问授权上下文: context };
  const request = {
    body: new ReadableStream({ start(controller) { controller.enqueue(requestHeader); controller.close(); } }),
    fetcher: {
      connect() {
        return {
          opened: Promise.resolve(),
          closed: new Promise(() => {}),
          readable: new ReadableStream(),
          writable: new WritableStream(),
          close() {}
        };
      }
    }
  };
  const response = await __test.处理XHTTP请求(request, uuid, context);
  try {
    await new Promise(resolve => setTimeout(resolve, 0));
    assert.equal(context.已释放, false);
    assert.equal(statements.some(sql => sql.startsWith('DELETE FROM access_connection_leases')), false);
  } finally {
    await response.body.cancel();
  }
  assert.equal(context.已释放, true);
});
