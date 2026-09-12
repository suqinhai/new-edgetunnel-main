import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import worker, { __test } from '../_worker.js';

const uuid = '00000000-0000-4000-8000-000000000000';
const tick = () => new Promise(resolve => setTimeout(resolve, 0));

function mockWorkerRuntime(t) {
  const digest = crypto.subtle.digest.bind(crypto.subtle);
  t.mock.method(crypto.subtle, 'digest', (algorithm, data) =>
    String(algorithm).toLowerCase() === 'md5'
      ? Promise.resolve(Uint8Array.from(createHash('md5').update(new Uint8Array(data)).digest()).buffer)
      : digest(algorithm, data));
  t.mock.method(globalThis, 'fetch', async url => {
    assert.match(String(url), /^https:\/\/raw\.githubusercontent\.com\/cmliu\/cmliu\/main\/CF-CIDR/);
    return new Response('203.0.113.0/24');
  });
}

function subscriptionRequest(token, extra = '') {
  const request = new Request('https://worker.example/sub?token=' + token + extra, {
    headers: { 'User-Agent': 'Mozilla/5.0' }
  });
  Object.defineProperty(request, 'cf', { value: { asn: 0, colo: 'TPE' } });
  return request;
}

test('伪装页转发移除认证信息并保留普通请求头', async t => {
  const digest = crypto.subtle.digest.bind(crypto.subtle);
  // Cloudflare 支持 MD5；Node 的 Web Crypto 需用等价实现补齐。
  t.mock.method(crypto.subtle, 'digest', (algorithm, data) =>
    String(algorithm).toLowerCase() === 'md5'
      ? Promise.resolve(Uint8Array.from(createHash('md5').update(new Uint8Array(data)).digest()).buffer)
      : digest(algorithm, data));
  const outgoing = [];
  t.mock.method(globalThis, 'fetch', async (url, options) => {
    outgoing.push({ url, headers: options.headers });
    return new Response('cover page');
  });
  const request = new Request('https://worker.example/', { headers: {
    Cookie: 'admin_session=test-session; admin_csrf=test-csrf',
    Authorization: 'Bearer test-token', 'Proxy-Authorization': 'Basic test',
    'X-CSRF-Token': 'test-csrf', Accept: 'text/html'
  } });
  const response = await worker.fetch(request, {
    ADMIN: 'test-password', UUID: uuid, PROXYIP: '203.0.113.1', URL: 'https://cover.example'
  }, { waitUntil() {} });
  assert.equal(await response.text(), 'cover page');
  assert.equal(outgoing.length, 1);
  assert.equal(outgoing[0].url, 'https://cover.example/');
  for (const header of ['Cookie', 'Authorization', 'Proxy-Authorization', 'X-CSRF-Token']) {
    assert.equal(outgoing[0].headers.has(header), false, header);
  }
  assert.equal(outgoing[0].headers.get('Accept'), 'text/html');
});

function createDatabase(t) {
  const db = new DatabaseSync(':memory:');
  t.after(() => db.close());
  const migrations = new URL('../migrations/', import.meta.url);
  for (const file of readdirSync(migrations).filter(name => name.endsWith('.sql')).sort()) {
    db.exec(readFileSync(new URL(file, migrations), 'utf8'));
  }
  // 使用真实 SQLite 执行生产 SQL；异步边界允许读写交错。
  const DB = {
    prepare(sql) {
      const statement = db.prepare(sql);
      let args = {};
      return {
        bind(...values) { args = Object.fromEntries(values.map((value, i) => [String(i + 1), value])); return this; },
        async first() { return statement.get(args); },
        async all() { return { results: statement.all(args) }; },
        async run() { const r = statement.run(args); return { meta: { changes: r.changes, last_row_id: r.lastInsertRowid } }; }
      };
    },
    async batch(statements) {
      const results = [];
      for (const statement of statements) results.push(await statement.run());
      return results;
    }
  };
  return { db, DB };
}

function insertLink(db, firstUsed, expiry, duration = 3600) {
  db.prepare(`INSERT INTO access_links(token, uuid, country, duration_seconds, created_at, first_used_at, expires_at)
    VALUES (?, ?, 'TW', ?, ?, ?, ?)`).run('x'.repeat(43), uuid, duration, Date.now(), firstUsed, expiry);
}

function renew(DB, session = DB) {
  return __test.执行访问链接操作({
    session, env: { DB }, request: new Request('https://worker.example/admin/access/api/links/action'),
    adminSession: null, id: 1, action: 'renew', body: { hours: 1 }
  });
}

test('两个并发续期请求都累加到实际到期时间', async t => {
  const { db, DB } = createDatabase(t);
  const expiry = Date.now() + 3600000;
  insertLink(db, Date.now(), expiry);
  await Promise.all([renew(DB), renew(DB)]);
  const row = db.prepare('SELECT * FROM access_links WHERE id = 1').get();
  assert.equal(row.duration_seconds, 10800);
  assert.equal(row.expires_at, expiry + 7200000);
});

test('未使用链接续期保持未激活，过期链接从当前时间续期', async t => {
  const { db, DB } = createDatabase(t);
  insertLink(db, null, null);
  await renew(DB);
  let row = db.prepare('SELECT * FROM access_links WHERE id = 1').get();
  assert.equal(row.first_used_at, null);
  assert.equal(row.expires_at, null);
  assert.equal(row.duration_seconds, 7200);
  db.prepare('UPDATE access_links SET first_used_at = 1, expires_at = 2').run();
  const start = Date.now();
  await renew(DB);
  row = db.prepare('SELECT * FROM access_links WHERE id = 1').get();
  assert.ok(row.expires_at >= start + 3600000 && row.expires_at <= Date.now() + 3600000);
});

test('续期读取之后发生首次激活时，不会把到期时间覆盖成 NULL', async t => {
  const { db, DB } = createDatabase(t);
  insertLink(db, null, null);
  const expiry = Date.now() + 3600000;
  let injected = false;
  const session = {
    prepare(sql) {
      const statement = DB.prepare(sql);
      if (sql.startsWith('SELECT * FROM access_links') && !injected) {
        const first = statement.first;
        statement.first = async () => {
          const snapshot = await first();
          injected = true;
          db.prepare('UPDATE access_links SET first_used_at = ?, expires_at = ? WHERE id = 1').run(Date.now(), expiry);
          return snapshot;
        };
      }
      return statement;
    }
  };
  await renew(DB, session);
  assert.equal(db.prepare('SELECT expires_at FROM access_links WHERE id = 1').get().expires_at, expiry + 3600000);
});

function grpcFixture({ keepUploadOpen = false, failWrite = false } = {}) {
  const header = new Uint8Array([0, ...Buffer.from(uuid.replaceAll('-', ''), 'hex'), 0, 1, 1, 187, 1, 203, 0, 113, 10, 65]);
  const frame = new Uint8Array([0, 0, 0, 0, header.length + 2, 10, header.length, ...header]);
  const sockets = [], statements = [];
  let uploadCancelled = false;
  const record = { id: 1, expires_at: Date.now() + 60000 };
  const DB = {
    prepare(sql) { return { sql, bind() { return this; }, async run() { return {}; }, async first() { return record; } }; },
    async batch(items) { statements.push(...items.map(item => item.sql)); return []; }
  };
  const context = { 记录: record, env: { DB }, 激活任务: Promise.resolve(record), leaseId: 'test-lease', 已释放: false };
  context.反代上下文 = { 反代IP: '203.0.113.11', 启用反代兜底: false, 启用SOCKS5反代: null, 访问授权上下文: context };
  const request = {
    body: new ReadableStream({
      start(c) { c.enqueue(frame); if (!keepUploadOpen) c.close(); },
      cancel() { uploadCancelled = true; }
    }),
    fetcher: { connect() {
      let controller, finish;
      const socket = {
        opened: Promise.resolve(), closed: new Promise(resolve => { finish = resolve; }),
        readable: new ReadableStream({ start(c) { controller = c; } }),
        writable: new WritableStream({
          write() { if (failWrite) throw new Error('test write failure'); },
          close() { socket.uploadClosed = true; }
        }),
        uploadClosed: false, didClose: false,
        send(bytes) { controller.enqueue(Uint8Array.from(bytes)); },
        end() { controller.close(); finish(); },
        close() { this.didClose = true; try { controller.close(); } catch {} finish(); }
      };
      sockets.push(socket);
      return socket;
    } }
  };
  return { request, context, sockets, statements, get uploadCancelled() { return uploadCancelled; } };
}

test('gRPC 上传 EOF 后仍接收延迟响应，且下行结束才释放租约', { timeout: 3000 }, async () => {
  const fixture = grpcFixture();
  const response = await __test.处理gRPC请求(fixture.request, uuid, fixture.context);
  try {
    await tick();
    const active = fixture.sockets.find(socket => !socket.didClose);
    assert.ok(active, '上传结束后 TCP 读端必须保持打开');
    assert.equal(active.uploadClosed, true);
    assert.equal(fixture.context.已释放, false);
    active.send([9, 8, 7]);
    active.end();
    const bytes = new Uint8Array(await response.arrayBuffer());
    assert.deepEqual(Array.from(bytes.slice(-3)), [9, 8, 7]);
    await fixture.context.释放任务;
    assert.equal(fixture.context.已释放, true);
    assert.equal(fixture.statements.filter(sql => sql.startsWith('DELETE FROM access_connection_leases')).length, 1);
  } finally { if (!response.body.locked) await response.body.cancel(); }
});

test('gRPC 客户端取消会关闭 TCP、取消未结束上传并释放租约', { timeout: 3000 }, async () => {
  const fixture = grpcFixture({ keepUploadOpen: true });
  const response = await __test.处理gRPC请求(fixture.request, uuid, fixture.context);
  await tick();
  await response.body.cancel();
  assert.ok(fixture.sockets.every(socket => socket.didClose));
  assert.equal(fixture.uploadCancelled, true);
  assert.equal(fixture.context.已释放, true);
});

test('gRPC 拨号写入失败仍关闭连接并释放租约', { timeout: 3000 }, async () => {
  const fixture = grpcFixture({ failWrite: true });
  const response = await __test.处理gRPC请求(fixture.request, uuid, fixture.context);
  await response.arrayBuffer();
  await fixture.context.释放任务;
  assert.ok(fixture.sockets.length > 0);
  assert.ok(fixture.sockets.every(socket => socket.didClose));
  assert.equal(fixture.context.已释放, true);
});

function dnsFixture(responses) {
  const sockets = [], sent = [], queries = [];
  const bridge = { readyState: WebSocket.OPEN, send(bytes) { sent.push(Array.from(new Uint8Array(bytes))); } };
  const request = { fetcher: { connect() {
    const chunks = responses[sockets.length];
    let controller;
    const socket = {
      readable: new ReadableStream({ start(c) { controller = c; } }),
      writable: new WritableStream({ write(bytes) {
        queries.push(Array.from(bytes));
        for (const chunk of chunks) controller.enqueue(Uint8Array.from(chunk));
        // 故意不关闭上游读端，模拟 DNS 持久连接。
      } }),
      didClose: false,
      close() { this.didClose = true; try { controller.close(); } catch {} }
    };
    sockets.push(socket);
    return socket;
  } } };
  return { sockets, sent, queries, bridge, request };
}

test('DNS 完整响应到达即完成，后续查询不等待上游 EOF', { timeout: 1000 }, async () => {
  const f = dnsFixture([[[0], [3, 9], [8, 7]], [[0, 2, 6, 5]]]);
  await __test.forwardataudp(Uint8Array.from([0, 1, 1]), f.bridge, Uint8Array.from([0, 0]), f.request);
  await __test.forwardataudp(Uint8Array.from([0, 1, 2]), f.bridge, null, f.request);
  assert.deepEqual(f.sent, [[0, 0, 0, 3, 9, 8, 7], [0, 2, 6, 5]]);
  assert.deepEqual(f.queries, [[0, 1, 1], [0, 1, 2]]);
  assert.ok(f.sockets.every(socket => socket.didClose));
});

test('DNS 请求分包和合包均保留完整帧，响应头只发送一次', { timeout: 1000 }, async () => {
  const f = dnsFixture([[[0, 1, 9]], [[0, 1, 8]]]);
  await __test.forwardataudp(Uint8Array.from([0]), f.bridge, Uint8Array.from([0, 0]), f.request);
  assert.equal(f.sockets.length, 0);
  await __test.forwardataudp(Uint8Array.from([2, 1, 2, 0, 1, 3]), f.bridge, null, f.request);
  assert.deepEqual(f.queries, [[0, 2, 1, 2], [0, 1, 3]]);
  assert.deepEqual(f.sent, [[0, 0, 0, 1, 9], [0, 1, 8]]);
});

test('DNS 响应封装器接收完整消息', { timeout: 1000 }, async () => {
  const f = dnsFixture([[[0], [2, 9], [8]]]);
  const wrapped = [];
  await __test.forwardataudp(Uint8Array.from([0, 1, 1]), f.bridge, null, f.request, bytes => {
    wrapped.push(Array.from(bytes));
    return [bytes.slice(2)];
  });
  assert.deepEqual(wrapped, [[0, 2, 9, 8]]);
  assert.deepEqual(f.sent, [[9, 8]]);
});

for (const fixedUUID of [false, true]) {
  test(`仅绑定 D1 的限时订阅可生成节点（UUID 环境变量：${fixedUUID}）`, async t => {
    mockWorkerRuntime(t);
    const { db, DB } = createDatabase(t);
    insertLink(db, null, null);
    const token = 'x'.repeat(43);
    const env = { ADMIN: 'test-password', DB };
    if (fixedUUID) env.UUID = '00000000-0000-4000-8000-000000000001';
    const pending = [];
    const response = await worker.fetch(subscriptionRequest(token), env, { waitUntil(p) { pending.push(p); } });
    await Promise.all(pending);
    assert.equal(response.status, 200);
    assert.match(response.headers.get('Content-Type'), /text\/plain/);
    const nodes = (await response.text()).split('\n').map(link => new URL(link));
    assert.equal(nodes.length, 16);
    for (const node of nodes) {
      assert.equal(node.protocol, 'vless:');
      assert.equal(node.username, uuid);
      assert.equal(node.searchParams.get('path'), '/u/' + token);
    }
    const row = db.prepare('SELECT * FROM access_links WHERE id = 1').get();
    assert.equal(row.first_used_at, null);
    assert.equal(row.connection_count, 0);
  });
}

test('链式代理备注保留限时订阅的令牌路径，普通订阅仍使用链式代理', async t => {
  mockWorkerRuntime(t);
  const { db, DB } = createDatabase(t);
  insertLink(db, null, null);
  const token = 'x'.repeat(43), values = new Map();
  const KV = { async get(key) { return values.get(key) ?? null; }, async put(key, value) { values.set(key, value); } };
  const env = { ADMIN: 'test-password', UUID: uuid, DB, KV, OFF_LOG: 'true' };
  const ctx = { waitUntil() {} };
  await worker.fetch(subscriptionRequest(token), env, ctx);
  const config = JSON.parse(values.get('config.json'));
  config.PATH = '/custom?test=1';
  config.启用0RTT = true;
  config.优选订阅生成.本地IP库.随机IP = false;
  values.set('config.json', JSON.stringify(config));
  values.set('ADD.txt', ['socks5', 'http', 'https', 'turn', 'sstp'].map(type =>
    `203.0.113.5#${type} $${type}://proxy.example:1080`).join('\n'));
  const limited = await worker.fetch(subscriptionRequest(token), env, ctx);
  assert.equal(limited.status, 200);
  const nodes = (await limited.text()).split('\n').map(link => new URL(link));
  assert.equal(nodes.length, 5);
  for (const node of nodes) {
    assert.equal(node.searchParams.get('path'), '/custom/u/' + token + '?test=1&ed=2560');
    assert.doesNotMatch(decodeURIComponent(node.hash), /proxy\.example/);
  }
  const md5 = value => createHash('md5').update(value).digest('hex');
  const masterToken = md5(md5('worker.example' + uuid).slice(7, 27));
  const ordinary = await worker.fetch(subscriptionRequest(masterToken), env, ctx);
  assert.equal(ordinary.status, 200);
  for (const link of (await ordinary.text()).split('\n')) {
    const node = new URL(link), path = node.searchParams.get('path');
    assert.match(path, /^\/video\//);
    const proxy = await __test.反代参数获取(new URL(path, 'https://worker.example'), uuid);
    assert.equal(proxy.parsedSocks5Address.hostname, 'proxy.example');
    assert.equal(proxy.启用SOCKS5反代, decodeURIComponent(node.hash.slice(1)));
  }
});

for (const rotationStage of ['beforeActivation', 'beforeAdmission', 'unchanged']) {
  test(`XHTTP 激活时校验请求 UUID（${rotationStage}）`, { timeout: 3000 }, async t => {
    const { db, DB } = createDatabase(t);
    insertLink(db, null, null);
    db.prepare("INSERT INTO proxy_ip_pool(country, proxy_ip, created_at) VALUES ('TW', '203.0.113.11', ?)").run(Date.now());
    const record = db.prepare('SELECT * FROM access_links WHERE id = 1').get();
    const env = { DB };
    const context = { 记录: record, env, clientIP: '', request: new Request('https://worker.example/') };
    if (rotationStage === 'beforeActivation') {
      await __test.执行访问链接操作({ session: DB, env, request: context.request, adminSession: null,
        id: 1, action: 'rotate', body: { mode: 'uuid' } });
    } else if (rotationStage === 'beforeAdmission') {
      const prepare = DB.prepare.bind(DB);
      t.mock.method(DB, 'prepare', sql => {
        if (sql.startsWith('INSERT INTO access_connection_leases')) {
          db.prepare('UPDATE access_links SET uuid = ? WHERE id = 1').run(crypto.randomUUID());
        }
        return prepare(sql);
      });
    }
    const sockets = grpcFixture();
    const header = new Uint8Array([0, ...Buffer.from(uuid.replaceAll('-', ''), 'hex'), 0, 1, 1, 187, 1, 203, 0, 113, 10, 65]);
    const response = await __test.处理XHTTP请求({
      body: new ReadableStream({ start(c) { c.enqueue(header); c.close(); } }),
      fetcher: sockets.request.fetcher
    }, uuid, context);
    try {
      await tick();
      const row = db.prepare('SELECT * FROM access_links WHERE id = 1').get();
      if (rotationStage === 'unchanged') {
        assert.equal(response.status, 200);
        assert.equal(row.connection_count, 1);
        assert.equal(row.active_connections, 1);
      } else {
        assert.ok([403, 409].includes(response.status), `旧 UUID 不应通过认证，实际 HTTP ${response.status}`);
        assert.equal(row.first_used_at, null);
        assert.equal(row.connection_count, 0);
        assert.equal(row.active_connections, 0);
        assert.equal(db.prepare('SELECT COUNT(*) AS n FROM access_connection_leases').get().n, 0);
        assert.equal(db.prepare('SELECT COUNT(*) AS n FROM access_connection_events').get().n, 0);
        assert.equal(sockets.sockets.length, 0);
      }
    } finally {
      await response.body.cancel();
      await context.释放任务;
    }
  });
}
