import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { Worker } from 'node:worker_threads';
import worker, { __test } from '../_worker.js';

test('数据源阻止 IPv4 映射 IPv6 的本地与私网地址', () => {
  for (const host of ['[::ffff:127.0.0.1]', '[::ffff:10.0.0.1]', '[::ffff:192.168.1.1]']) {
    assert.throws(() => __test.标准化访问数据源URL(`https://${host}/source`), /不允许指向本地或私有网络/);
  }
  assert.equal(__test.标准化访问数据源URL('https://[::ffff:8.8.8.8]/source'), 'https://[::ffff:808:808]/source');
});

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

function clashSubscriptionRequest(token, extra = '') {
  const request = new Request('https://worker.example/sub?token=' + token + extra, {
    headers: { 'User-Agent': 'Clash Verge' }
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
      const run = () => { const r = statement.run(args); return { meta: { changes: r.changes, last_row_id: r.lastInsertRowid } }; };
      return {
        sql, runSync: run,
        bind(...values) { args = Object.fromEntries(values.map((value, i) => [String(i + 1), value])); return this; },
        async first() { return statement.get(args); },
        async all() { return { results: statement.all(args) }; },
        async run() { return run(); }
      };
    },
    async batch(statements) {
      // D1 batch 在事务内执行，不能在批内插入另一请求的写操作。
      db.exec('BEGIN');
      try {
        const results = statements.map(statement => statement.runSync());
        db.exec('COMMIT');
        return results;
      } catch (error) { db.exec('ROLLBACK'); throw error; }
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

function loginRequest(password = 'wrong') {
  return new Request('https://worker.example/login', { method: 'POST', headers: {
    Origin: 'https://worker.example', 'CF-Connecting-IP': '203.0.113.8',
    'Content-Type': 'application/x-www-form-urlencoded'
  }, body: new URLSearchParams({ password }) });
}

test('同 IP 并发登录失败原子累加并触发封禁', { timeout: 3000 }, async t => {
  mockWorkerRuntime(t);
  const { db, DB } = createDatabase(t);
  const prepare = DB.prepare.bind(DB);
  let reads = 0, release;
  const allRead = new Promise(resolve => { release = resolve; });
  t.mock.method(DB, 'prepare', sql => {
    const statement = prepare(sql);
    if (sql.startsWith('SELECT * FROM admin_login_attempts')) {
      const first = statement.first;
      statement.first = async () => {
        const snapshot = await first();
        if (++reads === 10) release();
        await allRead;
        return snapshot;
      };
    }
    return statement;
  });
  const env = { DB, ADMIN: 'test-password', PROXYIP: '203.0.113.11' };
  const responses = await Promise.all(Array.from({ length: 10 }, () =>
    worker.fetch(loginRequest(), env, { waitUntil() {} })));
  const row = db.prepare('SELECT * FROM admin_login_attempts').get();
  assert.equal(row.failure_count, 10);
  assert.ok(row.blocked_until > Date.now());
  assert.equal(responses.filter(r => r.status === 401).length, 4);
  assert.equal(responses.filter(r => r.status === 429).length, 6);
  const blocked = await worker.fetch(loginRequest('test-password'), env, { waitUntil() {} });
  assert.equal(blocked.status, 429);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM admin_sessions').get().n, 0);
});

test('登录失败窗口过期后重新计数，成功登录清除失败记录', async t => {
  mockWorkerRuntime(t);
  const { db, DB } = createDatabase(t);
  const env = { DB, ADMIN: 'test-password', PROXYIP: '203.0.113.11' };
  const ipHash = await __test.SHA256十六进制('203.0.113.8');
  db.prepare(`INSERT INTO admin_login_attempts VALUES (?, ?, 4, NULL, ?)`)
    .run(ipHash, Date.now() - 11 * 60000, Date.now() - 11 * 60000);
  assert.equal((await worker.fetch(loginRequest(), env, { waitUntil() {} })).status, 401);
  assert.equal(db.prepare('SELECT failure_count FROM admin_login_attempts').get().failure_count, 1);
  assert.equal((await worker.fetch(loginRequest('test-password'), env, { waitUntil() {} })).status, 200);
  const row = db.prepare('SELECT * FROM admin_login_attempts').get();
  assert.equal(row.failure_count, 0);
  assert.equal(row.blocked_until, null);
});

for (const afterData of [false, true]) {
  test(`直连读取报错${afterData ? '且已返回数据时不重放请求' : '且无响应时回退到 PROXYIP'}`, { timeout: 3000 }, async () => {
    const sockets = [], wrapper = {}, sent = [];
    let resolveSent;
    const sentData = new Promise(resolve => { resolveSent = resolve; });
    const bridge = { readyState: WebSocket.OPEN, send(data) { sent.push(Array.from(data)); resolveSent(); },
      close() { this.readyState = WebSocket.CLOSED; } };
    const request = { fetcher: { connect(options) {
      let controller;
      const socket = { ...options, opened: Promise.resolve(), closed: new Promise(() => {}),
        readable: new ReadableStream({ start(c) { controller = c; } }),
        writable: new WritableStream(),
        send(bytes) { controller.enqueue(Uint8Array.from(bytes)); },
        fail() { controller.error(new Error('upstream reset')); },
        close() { try { controller.close(); } catch {} }
      };
      sockets.push(socket);
      return socket;
    } } };
    try {
      await __test.forwardataTCP('203.0.113.10', 443, Uint8Array.from([1]), bridge, null, wrapper, uuid, request,
        { 反代IP: '203.0.113.11', 启用反代兜底: false, 启用SOCKS5反代: null });
      if (afterData) { wrapper.socket.send([9]); await sentData; }
      wrapper.socket.fail();
      await tick();
      await tick();
      const proxies = sockets.filter(s => s.hostname === '203.0.113.11');
      assert.equal(proxies.length, afterData ? 0 : 1);
      assert.equal(bridge.readyState, afterData ? WebSocket.CLOSED : WebSocket.OPEN);
      if (!afterData) {
        proxies[0].send([8, 7]);
        await sentData;
        assert.deepEqual(sent, [[8, 7]]);
      }
    } finally { bridge.close(); for (const socket of sockets) socket.close(); await tick(); }
  });
}

test('强制 IPv4 模式跳过 IPv6 PROXYIP 入口', async () => {
  const sockets = [];
  const bridge = { readyState: WebSocket.OPEN, send() {}, close() { this.readyState = WebSocket.CLOSED; } };
  const request = { fetcher: { connect(options) {
    let controller;
    const socket = { ...options, opened: Promise.resolve(), closed: new Promise(() => {}),
      readable: new ReadableStream({ start(c) { controller = c; } }), writable: new WritableStream(),
      close() { try { controller.close(); } catch {} }
    };
    sockets.push(socket);
    return socket;
  } } };
  const wrapper = {};
  try {
    await __test.forwardataTCP('203.0.113.10', 443, Uint8Array.from([1]), bridge, null, wrapper, uuid, request,
      { 反代IP: '[2001:db8::1],203.0.113.11', 启用反代兜底: false, 强制IPv4: true, 启用SOCKS5反代: null });
    assert.deepEqual(sockets.map(socket => socket.hostname), ['203.0.113.11']);
  } finally {
    bridge.close();
    for (const socket of sockets) socket.close();
    await tick();
  }
});

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

for (const modes of [['token', 'uuid'], ['uuid', 'token']]) {
  test(`并发轮换 ${modes.join(' / ')} 不恢复旧凭据`, async t => {
    const { db, DB } = createDatabase(t);
    insertLink(db, 1000, Date.now() + 3600000);
    const before = db.prepare('SELECT * FROM access_links WHERE id = 1').get();
    const results = await Promise.all(modes.map(mode => __test.执行访问链接操作({
      session: DB, env: { DB }, request: new Request('https://worker.example/admin/access/api/links/action'),
      adminSession: null, id: 1, action: 'rotate', body: { mode }
    })));
    assert.ok(results.every(result => result.success));
    const after = db.prepare('SELECT * FROM access_links WHERE id = 1').get();
    assert.notEqual(after.token, before.token);
    assert.notEqual(after.uuid, before.uuid);
    const { token: oldToken, uuid: oldUuid, ...beforeState } = before;
    const { token: newToken, uuid: newUuid, ...afterState } = after;
    assert.deepEqual(afterState, beforeState);
  });
}

function grpcFixture({ keepUploadOpen = false, failWrite = false, transport = 'grpc', delayedOpen = false } = {}) {
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
      start(c) { c.enqueue(transport === 'xhttp' ? header : frame); if (!keepUploadOpen) c.close(); },
      cancel() { uploadCancelled = true; }
    }),
    fetcher: { connect() {
      let controller, finish, rejectClosed, open;
      const socket = {
        opened: delayedOpen ? new Promise(resolve => { open = resolve; }) : Promise.resolve(),
        closed: new Promise((resolve, reject) => { finish = resolve; rejectClosed = reject; }),
        readable: new ReadableStream({ start(c) { controller = c; } }),
        writable: new WritableStream({
          write(bytes) { socket.writeCount++; socket.writes.push(...bytes); if (failWrite) throw new Error('test write failure'); },
          close() { socket.uploadClosed = true; }
        }),
        uploadClosed: false, didClose: false, writeCount: 0, writes: [],
        open() { open?.(); },
        send(bytes) { controller.enqueue(Uint8Array.from(bytes)); },
        end() { controller.close(); finish(); },
        fail() { const error = new Error('upstream reset'); controller.error(error); rejectClosed(error); },
        close() { this.didClose = true; try { controller.close(); } catch {} finish(); }
      };
      sockets.push(socket);
      return socket;
    } }
  };
  return { request, context, sockets, statements, get uploadCancelled() { return uploadCancelled; } };
}

for (const frozenFetcher of [false, true]) {
for (const delayedOpen of [true, false]) {
  test(`XHTTP 在${delayedOpen ? '拨号期间' : '等待上传时'}取消会清理连接和租约（连接器只读：${frozenFetcher}）`, { timeout: 3000 }, async () => {
    const f = grpcFixture({ transport: 'xhttp', keepUploadOpen: true, delayedOpen });
    if (frozenFetcher) Object.freeze(f.request.fetcher);
    const originalConnect = f.request.fetcher.connect;
    const response = await __test.处理XHTTP请求(f.request, uuid, f.context);
    try {
      await tick();
      assert.equal(f.sockets.length, 2);
      assert.equal(f.request.fetcher.connect, originalConnect, '不能修改运行时的连接器');
      await response.body.cancel();
      assert.ok(f.sockets.every(socket => socket.didClose), '取消时应立即关闭所有正在拨号或已建立的 socket');
      assert.equal(f.uploadCancelled, true);
      for (const socket of f.sockets) socket.open();
      await tick();
      if (delayedOpen) assert.ok(f.sockets.every(socket => socket.writeCount === 0), '延迟拨号完成后不能再发送首包');
      assert.equal(f.sockets.length, 2, '取消后不能发起重试');
      assert.equal(f.request.body.locked, false);
      assert.equal(f.context.已释放, true);
      assert.equal(f.statements.filter(sql => sql.startsWith('DELETE FROM access_connection_leases')).length, 1);
    } finally {
      for (const socket of f.sockets) { socket.open(); socket.close(); }
      await response.body.cancel();
      await tick();
    }
  });
}
}

for (const failure of [false, true]) {
  test(`XHTTP 上游${failure ? '异常关闭没有未处理拒绝' : '正常关闭'}时取消上传并释放资源`, { timeout: 3000 }, async () => {
    const f = grpcFixture({ transport: 'xhttp', keepUploadOpen: true });
    const response = await __test.处理XHTTP请求(f.request, uuid, f.context);
    try {
      await tick();
      const socket = f.sockets.find(s => !s.didClose);
      socket.send([9, 8, 7]);
      await tick();
      if (failure) socket.fail(); else socket.end();
      await response.arrayBuffer();
      await tick(); await tick();
      await f.context.释放任务;
      assert.equal(f.uploadCancelled, true);
      assert.equal(f.request.body.locked, false);
      assert.ok(f.sockets.every(s => s.didClose));
      assert.equal(f.sockets.length, 2, '返回数据后不能重放首包');
      assert.equal(f.statements.filter(sql => sql.startsWith('DELETE FROM access_connection_leases')).length, 1);
    } finally {
      for (const socket of f.sockets) socket.close();
      if (!response.body.locked) await response.body.cancel();
    }
  });
}

function encodeGrpcFrame(payload) {
  const length = [];
  let n = payload.length;
  while (n > 127) { length.push((n & 127) | 128); n >>>= 7; }
  length.push(n);
  const size = 1 + length.length + payload.length;
  return Uint8Array.from([0, size >>> 24, size >>> 16 & 255, size >>> 8 & 255, size & 255, 10, ...length, ...payload]);
}

function proxyHeader(protocol, addressType) {
  const address = addressType === 'ipv4' ? [203, 0, 113, 10]
    : addressType === 'ipv6' ? [0x20, 1, 0x0d, 0xb8, ...new Array(11).fill(0), 1]
    : [11, ...Buffer.from('example.com')];
  if (protocol === 'trojan') return Uint8Array.from([
    ...Buffer.from(createHash('sha224').update(uuid).digest('hex')), 13, 10, 1,
    { ipv4: 1, domain: 3, ipv6: 4 }[addressType], ...address, 1, 187, 13, 10
  ]);
  return Uint8Array.from([
    0, ...Buffer.from(uuid.replaceAll('-', ''), 'hex'), 3, 1, 2, 3, 1, 1, 187,
    { ipv4: 1, domain: 2, ipv6: 3 }[addressType], ...address
  ]);
}

for (const protocol of ['vless', 'trojan']) {
for (const addressType of ['ipv4', 'domain', 'ipv6']) {
  test(`gRPC ${protocol}/${addressType} 首包逐字节跨消息传输仍完整转发数据`, { timeout: 3000 }, async () => {
    const f = grpcFixture();
    const header = proxyHeader(protocol, addressType);
    const payload = Uint8Array.from({ length: 200 }, (_, i) => i);
    f.request.body = new ReadableStream({ start(c) {
      for (const byte of header.slice(0, -1)) c.enqueue(encodeGrpcFrame([byte]));
      const tail = encodeGrpcFrame([header.at(-1), ...payload]);
      c.enqueue(tail.slice(0, 3));
      c.enqueue(tail.slice(3, 8));
      c.enqueue(Uint8Array.from([...tail.slice(8), ...encodeGrpcFrame([201, 202])]));
      c.close();
    } });
    const response = await __test.处理gRPC请求(f.request, uuid, f.context);
    try {
      await tick(); await tick();
      const socket = f.sockets.find(s => !s.didClose);
      assert.ok(socket, '完整首包到达后才建立连接');
      assert.deepEqual(socket.writes, [...payload, 201, 202]);
      assert.equal(socket.uploadClosed, true);
      assert.equal(f.context.已释放, false);
      socket.send([9, 8, 7]); socket.end();
      assert.deepEqual(Array.from(new Uint8Array(await response.arrayBuffer()).slice(-3)), [9, 8, 7]);
    } finally {
      for (const socket of f.sockets) socket.close();
      if (!response.body.locked) await response.body.cancel();
      await f.context.释放任务;
    }
  });
}
}

for (const mode of ['incomplete', 'invalid', 'cancel']) {
  test(`gRPC 拆分首包 ${mode} 时不拨号且释放上传锁`, { timeout: 3000 }, async () => {
    const f = grpcFixture();
    let cancelled = false;
    const bytes = mode === 'invalid' ? new Uint8Array(2048).fill(255) : proxyHeader('trojan', 'domain').slice(0, 60);
    f.request.body = new ReadableStream({ start(c) {
      c.enqueue(encodeGrpcFrame(bytes.slice(0, 12)));
      c.enqueue(encodeGrpcFrame(bytes.slice(12)));
      if (mode !== 'cancel') c.close();
    }, cancel() { cancelled = true; } });
    const response = await __test.处理gRPC请求(f.request, uuid);
    if (mode === 'cancel') { await tick(); await response.body.cancel(); assert.equal(cancelled, true); }
    else assert.equal((await response.arrayBuffer()).byteLength, 0);
    await tick();
    assert.equal(f.sockets.length, 0);
    assert.equal(f.request.body.locked, false);
  });
}

test('XHTTP 正常上传 EOF 后仍收到延迟响应，下行结束才释放租约', { timeout: 3000 }, async () => {
  const f = grpcFixture({ transport: 'xhttp' });
  const response = await __test.处理XHTTP请求(f.request, uuid, f.context);
  try {
    await tick();
    const active = f.sockets.find(socket => !socket.didClose);
    assert.ok(active);
    assert.equal(active.uploadClosed, true);
    assert.equal(f.context.已释放, false);
    active.send([9, 8, 7]);
    active.end();
    assert.deepEqual(Array.from(new Uint8Array(await response.arrayBuffer())), [0, 0, 9, 8, 7]);
    await f.context.释放任务;
    assert.equal(f.context.已释放, true);
    assert.equal(f.statements.filter(sql => sql.startsWith('DELETE FROM access_connection_leases')).length, 1);
  } finally { if (!response.body.locked) await response.body.cancel(); }
});

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

for (const delayedOpen of [false, true]) {
test(`gRPC ${delayedOpen ? '拨号期间' : '连接建立后'}取消会关闭 TCP 且不再发送首包`, { timeout: 3000 }, async () => {
  const fixture = grpcFixture({ keepUploadOpen: true, delayedOpen });
  const response = await __test.处理gRPC请求(fixture.request, uuid, fixture.context);
  try {
    await tick();
    assert.equal(fixture.sockets.length, 2);
    await response.body.cancel();
    assert.ok(fixture.sockets.every(socket => socket.didClose));
    assert.equal(fixture.uploadCancelled, true);
    assert.equal(fixture.context.已释放, true);
    for (const socket of fixture.sockets) socket.open();
    await tick(); await tick();
    if (delayedOpen) assert.ok(fixture.sockets.every(socket => socket.writeCount === 0));
    assert.equal(fixture.sockets.length, 2, '取消后不能重试拨号');
    assert.equal(fixture.request.body.locked, false);
    assert.equal(fixture.statements.filter(sql => sql.startsWith('DELETE FROM access_connection_leases')).length, 1);
  } finally {
    for (const socket of fixture.sockets) { socket.open(); socket.close(); }
    await response.body.cancel();
    await tick();
  }
});
}

test('异常 gRPC 帧及时结束且不拨号（隔离线程防止死循环挂起测试）', { timeout: 5000 }, async t => {
  const code = `
    import assert from 'node:assert/strict';
    import { parentPort, workerData } from 'node:worker_threads';
    const { __test } = await import(workerData.url);
    const invalid = [
      [0,255,255,255,251], [0,128,0,0,0], [0,255,255,255,255],
      [0,1,0,0,1], [1,0,0,0,0], [0,0,0], [0,0,0,0,3,10]
    ];
    for (const bytes of invalid) {
      let dialed = false;
      const response = await __test.处理gRPC请求({
        body: new ReadableStream({start(c) { c.enqueue(Uint8Array.from(bytes)); c.close(); }}),
        fetcher: {connect() { dialed = true; throw new Error('unexpected dial'); }}
      }, workerData.uuid);
      assert.equal((await response.arrayBuffer()).byteLength, 0);
      assert.equal(dialed, false);
    }
    parentPort.postMessage('ok');
  `;
  const child = new Worker(new URL('data:text/javascript,' + encodeURIComponent(code)), {
    execArgv: [], workerData: { url: new URL('../_worker.js', import.meta.url).href, uuid }
  });
  t.after(() => child.terminate());
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('gRPC 帧解析未及时结束')), 3000);
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('message', message => { clearTimeout(timer); try { assert.equal(message, 'ok'); resolve(); } catch (error) { reject(error); } });
  });
});

test('合法 gRPC 帧支持分包、合包和空帧，并保留延迟下行响应', { timeout: 3000 }, async () => {
  const f = grpcFixture();
  const frame = new Uint8Array(await new Response(f.request.body).arrayBuffer());
  f.request.body = new ReadableStream({ start(c) {
    c.enqueue(frame.slice(0, 2));
    c.enqueue(frame.slice(2, 8));
    c.enqueue(Uint8Array.from([...frame.slice(8), 0,0,0,0,0, 0,0,0,0,3,10,1,66]));
    c.close();
  } });
  const response = await __test.处理gRPC请求(f.request, uuid, f.context);
  try {
    await tick(); await tick();
    const socket = f.sockets.find(s => !s.didClose);
    assert.ok(socket);
    assert.equal(socket.writeCount, 2);
    assert.equal(socket.uploadClosed, true);
    socket.send([9,8,7]); socket.end();
    assert.deepEqual(Array.from(new Uint8Array(await response.arrayBuffer()).slice(-3)), [9,8,7]);
  } finally {
    for (const socket of f.sockets) socket.close();
    if (!response.body.locked) await response.body.cancel();
    await f.context.释放任务;
  }
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
    assert.equal(nodes.length, 1);
    for (const node of nodes) {
      assert.equal(node.protocol, 'vless:');
      assert.equal(node.username, uuid);
      assert.equal(node.hostname, 'worker.example');
      assert.equal(node.searchParams.get('path'), '/u/' + token);
      assert.match(decodeURIComponent(node.hash.slice(1)), /TW/);
    }
    const row = db.prepare('SELECT * FROM access_links WHERE id = 1').get();
    assert.equal(row.first_used_at, null);
    assert.equal(row.connection_count, 0);
  });
}

test('Clash 限时订阅使用最简配置，只保留国家节点和选择组', async t => {
  mockWorkerRuntime(t);
  const { db, DB } = createDatabase(t);
  insertLink(db, null, null);
  db.prepare("UPDATE access_links SET country = 'TH', duration_seconds = 86400, note = '自定义备注' WHERE id = 1").run();
  const token = 'x'.repeat(43);
  const response = await worker.fetch(clashSubscriptionRequest(token), { ADMIN: 'test-password', DB }, { waitUntil() {} });
  assert.equal(response.status, 200);
  assert.match(response.headers.get('Content-Type'), /application\/x-yaml/);
  assert.equal(response.headers.get('Content-Disposition'), `attachment; filename*=UTF-8''${encodeURIComponent('泰国 (TH) - 24小时')}`);
  const yaml = await response.text();
  assert.match(yaml, /proxies:\n  - name: "泰国 \(TH\) - 自定义备注"/);
  assert.match(yaml, /proxy-groups:\n  - name: "泰国 \(TH\)"/);
  assert.match(yaml, /rules:\n  - MATCH,泰国 \(TH\)/);
  assert.doesNotMatch(yaml, /全球直连|全球拦截|漏网之鱼|CloudFlareCDN/);
  assert.doesNotMatch(yaml, /^dns:/m);
  assert.equal((yaml.match(/^  - name:/gm) || []).length, 2);
});

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
  assert.equal(nodes.length, 1);
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

for (const resetStage of ['beforeAdmission', 'afterAdmission', 'afterValidation']) {
  test(`计时重置与激活交错仍拒绝或断开旧连接（${resetStage}）`, { timeout: 3000 }, async t => {
    const { db, DB } = createDatabase(t);
    insertLink(db, null, null);
    db.prepare("INSERT INTO proxy_ip_pool(country, proxy_ip, created_at) VALUES ('TW', '203.0.113.11', ?)").run(Date.now());
    const context = { 记录: db.prepare('SELECT * FROM access_links WHERE id = 1').get(), env: { DB },
      clientIP: '', request: new Request('https://worker.example/') };
    const reset = () => __test.执行访问链接操作({ session: DB, env: { DB }, request: context.request,
      adminSession: null, id: 1, action: 'reset' });
    let injected = false, check;
    const setTimer = globalThis.setTimeout;
    t.mock.method(globalThis, 'setTimeout', (fn, ms, ...args) => {
      if (ms === 30000) check = fn;
      return setTimer(fn, ms, ...args);
    });
    if (resetStage === 'afterValidation') {
      const prepare = DB.prepare.bind(DB);
      t.mock.method(DB, 'prepare', sql => {
        const statement = prepare(sql);
        if (sql.startsWith('INSERT INTO access_connection_events')) {
          const run = statement.run;
          statement.run = async () => { const result = await run(); injected = true; await reset(); return result; };
        }
        return statement;
      });
    } else {
      const batch = DB.batch.bind(DB);
      t.mock.method(DB, 'batch', async statements => {
        const inject = !injected && statements.some(s => s.sql.startsWith('INSERT INTO access_connection_leases'));
        if (inject) injected = true;
        if (inject && resetStage === 'beforeAdmission') await reset();
        const result = await batch(statements);
        if (inject && resetStage === 'afterAdmission') await reset();
        return result;
      });
    }
    const f = grpcFixture({ transport: 'xhttp', keepUploadOpen: true });
    const response = await __test.处理XHTTP请求(f.request, uuid, context);
    try {
      await tick();
      assert.equal(injected, true);
      if (resetStage === 'afterValidation') {
        assert.equal(response.status, 200);
        assert.equal(context.connectionEpoch, 0, '不能采用重置后的代次');
        assert.equal(typeof check, 'function');
        clearTimeout(context.监控定时器);
        await check();
        await context.释放任务;
        assert.equal(context.已释放, true);
        assert.ok(f.sockets.every(s => s.didClose));
      } else {
        assert.equal(response.status, 409);
        assert.equal(f.sockets.length, 0);
        assert.equal(db.prepare('SELECT COUNT(*) AS n FROM access_connection_events').get().n, 0);
      }
      const row = db.prepare('SELECT * FROM access_links WHERE id = 1').get();
      assert.equal(row.connection_epoch, 1);
      assert.equal(row.first_used_at, null);
      assert.equal(row.expires_at, null);
      assert.equal(row.connection_count, 0);
      assert.equal(row.active_connections, 0);
      assert.equal(db.prepare('SELECT COUNT(*) AS n FROM access_connection_leases').get().n, 0);
    } finally {
      clearTimeout(context.监控定时器);
      await response.body.cancel();
      await context.释放任务;
      for (const socket of f.sockets) socket.close();
      await tick();
    }
  });
}

for (const leaseState of ['deleted', 'expired', 'valid']) {
  test(`访问心跳只续订仍有效的租约（${leaseState}）`, { timeout: 3000 }, async t => {
    const { db, DB } = createDatabase(t);
    insertLink(db, null, null);
    db.prepare("INSERT INTO proxy_ip_pool(country, proxy_ip, created_at) VALUES ('TW', '203.0.113.11', ?)").run(Date.now());
    const context = { 记录: db.prepare('SELECT * FROM access_links WHERE id = 1').get(), env: { DB },
      clientIP: '', request: new Request('https://worker.example/') };
    let check;
    const setTimer = globalThis.setTimeout;
    t.mock.method(globalThis, 'setTimeout', (fn, ms, ...args) => {
      if (ms === 30000) check = fn;
      return setTimer(fn, ms, ...args);
    });
    const f = grpcFixture({ transport: 'xhttp', keepUploadOpen: true });
    const response = await __test.处理XHTTP请求(f.request, uuid, context);
    try {
      await tick();
      assert.equal(response.status, 200);
      if (leaseState === 'deleted') db.exec('DELETE FROM access_connection_leases');
      if (leaseState === 'expired') db.exec('UPDATE access_connection_leases SET expires_at = 1');
      clearTimeout(context.监控定时器);
      await check();
      if (leaseState === 'valid') {
        assert.ok(!context.已释放);
        assert.equal(db.prepare('SELECT COUNT(*) AS n FROM access_connection_leases').get().n, 1);
        assert.ok(f.sockets.some(s => !s.didClose));
      } else {
        await context.释放任务;
        assert.equal(context.已释放, true);
        assert.ok(f.sockets.every(s => s.didClose));
        assert.equal(db.prepare('SELECT COUNT(*) AS n FROM access_connection_leases').get().n, 0);
        assert.equal(db.prepare('SELECT active_connections FROM access_links').get().active_connections, 0);
      }
    } finally {
      clearTimeout(context.监控定时器);
      await response.body.cancel();
      await context.释放任务;
      for (const socket of f.sockets) socket.close();
      await tick();
    }
  });
}

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
