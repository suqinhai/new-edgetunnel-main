import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync, readdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { __test } from '../_worker.js';
import { verifiedProxy } from './helpers/country-probe.mjs';

const workerSource = readFileSync(new URL('../_worker.js', import.meta.url), 'utf8');
const { accessHandler } = await import('data:text/javascript;base64,' + Buffer.from(workerSource +
  '\nexport { 处理访问链接管理请求 as accessHandler };').toString('base64'));

const uuid = '00000000-0000-4000-8000-000000000000';
const proxy = '111.125.75.92';

function report(ip = proxy, country = 'PH', port = 443) {
  return { success: true, proxyIP: ip, portRemote: port, responseTime: 30,
    supports_ipv4: true, supports_ipv6: false,
    probe_results: { ipv4: { ok: true, exit: { ip, country, colo: 'MNL' } } } };
}

function database(t) {
  // Cloudflare 支持 MD5 WebCrypto；Node 的页面状态测试需要补齐这个运行时差异。
  const digest = crypto.subtle.digest.bind(crypto.subtle);
  t.mock.method(crypto.subtle, 'digest', (algorithm, data) => String(algorithm).toLowerCase() === 'md5'
    ? Promise.resolve(Uint8Array.from(createHash('md5').update(new Uint8Array(data)).digest()).buffer)
    : digest(algorithm, data));
  const db = new DatabaseSync(':memory:');
  const migrations = new URL('../migrations/', import.meta.url);
  for (const file of readdirSync(migrations).filter(name => name.endsWith('.sql')).sort()) {
    db.exec(readFileSync(new URL(file, migrations), 'utf8'));
  }
  t.after(() => db.close());
  const DB = {
    prepare(sql) {
      const stmt = db.prepare(sql);
      let params = {};
      const run = () => { const r = stmt.run(params); return { meta: { changes: r.changes, last_row_id: r.lastInsertRowid } }; };
      return { sql, runSync: run,
        bind(...values) { params = Object.fromEntries(values.map((v, i) => [String(i + 1), v])); return this; },
        async run() { return run(); }, async first() { return stmt.get(params); }, async all() { return { results: stmt.all(params) }; } };
    },
    async batch(statements) {
      db.exec('BEGIN');
      try { const r = statements.map(stmt => stmt.runSync()); db.exec('COMMIT'); return r; }
      catch (error) { db.exec('ROLLBACK'); throw error; }
    }
  };
  db.prepare(`INSERT INTO access_links(token, uuid, country, duration_seconds, created_at)
    VALUES (?, ?, 'PH', 10800, ?)`).run('x'.repeat(43), uuid, Date.now());
  return { db, DB, context: { env: { DB }, clientIP: '', request: new Request('https://worker.example/'),
    记录: db.prepare('SELECT * FROM access_links').get() } };
}

function addProxy(db, ip, score = 50) {
  db.prepare(`INSERT INTO proxy_ip_pool(country, proxy_ip, enabled, created_at, health_status, health_score)
    VALUES ('PH', ?, 1, ?, 'healthy', ?)`).run(ip, Date.now(), score);
}

function mockNetwork(t, { countries = {}, failGeo = false, geoCountry, geoStatus } = {}) {
  const requests = [];
  t.mock.method(globalThis, 'fetch', async input => {
    const url = new URL(input);
    requests.push(url.hostname);
    if (url.hostname === 'api.090227.xyz') {
      const endpoint = new URL('https://' + url.searchParams.get('proxyip'));
      return Response.json(report(endpoint.hostname, countries[endpoint.hostname] || 'PH', Number(endpoint.port || 443)));
    }
    assert.equal(url.hostname, 'ipwho.is');
    if (failGeo) throw new Error('geo service unavailable');
    if (geoStatus) return new Response('rate limited', { status: geoStatus });
    const ip = decodeURIComponent(url.pathname.slice(1));
    return Response.json({ success: true, ip, country_code: geoCountry || countries[ip] || 'PH' });
  });
  return requests;
}

async function manage(DB, path, { body, csrf = true } = {}) {
  const url = new URL('https://worker.example/admin/access/api/' + path);
  const token = 'test-verification-csrf';
  const admin = { id: 'test-admin', expires_at: Date.now() + 60000, csrf_hash: await __test.SHA256十六进制(token) };
  const headers = { Origin: url.origin, 'Content-Type': 'application/json', Cookie: 'admin_csrf=' + token };
  if (csrf) headers['X-CSRF-Token'] = token;
  const request = new Request(url, { method: body === undefined ? 'GET' : 'POST', headers,
    ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  const response = await accessHandler(request, { DB }, url.hostname, uuid, 'test', url, admin);
  return { status: response.status, body: await response.json() };
}

test('PH 标签不能覆盖截图地址实测的美国出口', () => {
  assert.throws(() => __test.校验访问代理出口检测(report('129.158.198.241', 'US', 8443), 'PH', '129.158.198.241:8443'), /要求 PH，实际 US/);
});

test('菲律宾出口验证使用 exit.country，忽略检测服务器所在的 colo', () => {
  const data = { ...report(), colo: 'IAD' };
  assert.deepEqual(__test.校验访问代理出口检测(data, 'PH', proxy), [{ ip: proxy, country: 'PH' }]);
});

test('仅返回 success 或标签、缺少实际出口的旧检测结果拒绝使用', () => {
  const data = { success: true, proxyIP: proxy, portRemote: 443, country: 'PH', colo: 'MNL' };
  assert.throws(() => __test.校验访问代理出口检测(data, 'PH', proxy), /实际出口/);
});

test('IPv4 是 PH、IPv6 是 US 的双栈地址拒绝使用', () => {
  const data = report();
  data.supports_ipv6 = true;
  data.probe_results.ipv6 = { ok: true, exit: { ip: '2001:db8::1', country: 'US' } };
  assert.throws(() => __test.校验访问代理出口检测(data, 'PH', proxy), /实际 US/);
});

test('声称支持 IPv6 却未返回成功出口证据时拒绝使用', () => {
  const data = { ...report(), supports_ipv6: true };
  assert.throws(() => __test.校验访问代理出口检测(data, 'PH', proxy), /ipv6/);
});

test('检测服务检查了另一个 IP 或端口时拒绝使用', () => {
  assert.throws(() => __test.校验访问代理出口检测(report(), 'PH', proxy + ':8443'), /端口/);
  assert.throws(() => __test.校验访问代理出口检测(report(), 'PH', '38.54.81.111'), /地址/);
});

test('国家节点拒绝会改变 DNS 解析结果的域名', () => {
  assert.throws(() => __test.获取固定访问反代地址('proxy.example:443'), /固定 IP/);
});

test('旧 PH 池中美国地址被立即隔离，分配真正 PH 出口后才开始计时', async t => {
  const { db, context } = database(t);
  addProxy(db, '129.158.198.241:8443', 99);
  addProxy(db, proxy);
  mockNetwork(t, { countries: { '129.158.198.241': 'US' } });
  await __test.激活访问授权上下文(context);
  const link = db.prepare('SELECT * FROM access_links').get();
  assert.equal(link.proxy_ip, proxy);
  assert.equal(link.connection_count, 1);
  assert.ok(link.first_used_at);
  const us = db.prepare('SELECT * FROM proxy_ip_pool WHERE proxy_ip = ?').get('129.158.198.241:8443');
  assert.equal(us.exit_country, 'US');
  assert.equal(us.country_verified_at, null);
  assert.equal(us.health_status, 'unhealthy');
  assert.ok(us.cooldown_until > Date.now());
  assert.deepEqual(context.已验证代理候选.map(x => x.proxy_ip), [proxy]);
});

test('只有标为 PH 的美国地址时拒绝激活，不启动计时或消耗次数', async t => {
  const { db, context } = database(t);
  addProxy(db, '129.158.198.241:8443');
  mockNetwork(t, { countries: { '129.158.198.241': 'US' } });
  await assert.rejects(__test.激活访问授权上下文(context), error => error.status === 503);
  const link = db.prepare('SELECT * FROM access_links').get();
  assert.equal(link.first_used_at, null);
  assert.equal(link.proxy_ip, null);
  assert.equal(link.connection_count, 0);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM access_connection_leases').get().n, 0);
});

test('检测报告 PH、独立 IP 库报告 US 时拒绝激活', async t => {
  const { db, context } = database(t);
  addProxy(db, proxy);
  mockNetwork(t, { geoCountry: 'US' });
  await assert.rejects(__test.激活访问授权上下文(context), /暂无通过/);
  const pool = db.prepare('SELECT * FROM proxy_ip_pool').get();
  assert.equal(pool.country_verified_at, null);
  assert.match(pool.country_error, /交叉核验/);
});

test('检测服务故障不能使用旧的国家验证结果', async t => {
  const { db, context } = database(t);
  addProxy(db, proxy);
  db.prepare("UPDATE proxy_ip_pool SET exit_country = 'PH', exit_ip = ?, country_verified_at = ?").run(proxy, Date.now());
  mockNetwork(t, { failGeo: true });
  await assert.rejects(__test.激活访问授权上下文(context), /暂无通过/);
  assert.equal(db.prepare('SELECT country_verified_at FROM proxy_ip_pool').get().country_verified_at, null);
  assert.equal(db.prepare('SELECT connection_count FROM access_links').get().connection_count, 0);
});

test('默认关闭跳过开关，ipwho.is 返回 429 时仍要求交叉核验', async t => {
  const { db, DB } = database(t);
  addProxy(db, proxy);
  const requests = mockNetwork(t, { geoStatus: 429 });
  await assert.rejects(__test.验证访问代理出口({ DB }, db.prepare('SELECT * FROM proxy_ip_pool').get(), 'PH'), /HTTP 429/);
  assert.equal(requests.filter(host => host === 'ipwho.is').length, 2);
  assert.equal(db.prepare('SELECT country_verified_at FROM proxy_ip_pool').get().country_verified_at, null);
  assert.equal((await manage(DB, 'state')).body.verification.skip_ipwho_is, false);
});

test('开关保存到 D1 并在新页面请求中保留，切换后重新检测且不扣分', async t => {
  const { db, DB } = database(t);
  addProxy(db, proxy);
  db.prepare("UPDATE proxy_ip_pool SET exit_country = 'PH', exit_ip = ?, country_verified_at = ?").run(proxy, Date.now());
  const before = db.prepare('SELECT * FROM proxy_ip_pool').get();
  const saved = await manage(DB, 'health/settings', { body: { skipIpwhoIs: true } });
  assert.equal(saved.status, 200);
  assert.equal(saved.body.verification.skip_ipwho_is, true);
  assert.equal(db.prepare("SELECT value FROM schema_metadata WHERE key = 'skip_ipwho_is_verification'").get().value, 'true');
  assert.equal((await manage(DB, 'state')).body.verification.skip_ipwho_is, true);
  const after = db.prepare('SELECT * FROM proxy_ip_pool').get();
  assert.equal(after.country_verified_at, null);
  assert.equal(after.health_status, 'unknown');
  assert.equal(after.health_score, before.health_score);
  assert.equal(after.failure_count, before.failure_count);
  const audit = db.prepare("SELECT * FROM audit_logs WHERE action = 'proxy.verification.update'").get();
  assert.equal(JSON.parse(audit.before_summary).skip_ipwho_is, false);
  assert.equal(JSON.parse(audit.after_summary).skip_ipwho_is, true);

  db.prepare("UPDATE proxy_ip_pool SET health_status = 'healthy', country_verified_at = ?").run(Date.now());
  const verifiedAt = db.prepare('SELECT country_verified_at FROM proxy_ip_pool').get().country_verified_at;
  await manage(DB, 'health/settings', { body: { skipIpwhoIs: true } });
  assert.equal(db.prepare('SELECT country_verified_at FROM proxy_ip_pool').get().country_verified_at, verifiedAt);
});

test('开启跳过后后台检测和真实连接均不请求 ipwho.is，关闭后恢复查询', async t => {
  const { db, DB, context } = database(t);
  addProxy(db, proxy);
  await manage(DB, 'health/settings', { body: { skipIpwhoIs: true } });
  const requests = mockNetwork(t, { geoStatus: 429 });
  const checked = await __test.检测访问PROXYIP池({ DB }, 'PH', 8);
  assert.equal(checked.success, 1);
  assert.equal(checked.failed, 0);
  assert.equal(checked.unavailable, 0);
  assert.equal((await __test.获取已验证国家池状态(DB, 'PH')).healthy, 1);
  await __test.激活访问授权上下文(context);
  assert.equal(db.prepare('SELECT proxy_ip FROM access_links').get().proxy_ip, proxy);
  assert.equal(db.prepare('SELECT connection_count FROM access_links').get().connection_count, 1);
  assert.deepEqual(requests, ['api.090227.xyz', 'api.090227.xyz']);

  const restored = await manage(DB, 'health/settings', { body: { skipIpwhoIs: false } });
  assert.equal(restored.body.verification.skip_ipwho_is, false);
  assert.equal((await manage(DB, 'state')).body.verification.skip_ipwho_is, false);
  assert.equal((await __test.获取已验证国家池状态(DB, 'PH')).healthy, 0);
  await assert.rejects(__test.验证访问代理出口({ DB }, db.prepare('SELECT * FROM proxy_ip_pool').get(), 'PH'), /HTTP 429/);
  assert.equal(requests.filter(host => host === 'ipwho.is').length, 2);
});

test('跳过 ipwho.is 后仍拒绝其他国家出口及不通的代理', async t => {
  const { db, DB } = database(t);
  addProxy(db, proxy);
  await manage(DB, 'health/settings', { body: { skipIpwhoIs: true } });
  const candidate = db.prepare('SELECT * FROM proxy_ip_pool').get();
  mockNetwork(t, { countries: { [proxy]: 'US' } });
  await assert.rejects(__test.验证访问代理出口({ DB }, candidate, 'PH'), error => error.code === 'country_mismatch');
  assert.equal(db.prepare('SELECT health_status FROM proxy_ip_pool').get().health_status, 'unhealthy');
  t.mock.method(globalThis, 'fetch', async () => Response.json({ ...report(), success: false }));
  await assert.rejects(__test.验证访问代理出口({ DB }, candidate, 'PH'), error => error.code === 'probe_failed');
});

test('修改跳过开关需要 CSRF 且只接受明确的布尔值', async t => {
  const { db, DB } = database(t);
  const forbidden = await manage(DB, 'health/settings', { body: { skipIpwhoIs: true }, csrf: false });
  assert.equal(forbidden.status, 403);
  t.mock.method(console, 'error', () => {});
  const invalid = await manage(DB, 'health/settings', { body: { skipIpwhoIs: 'false' } });
  assert.equal(invalid.status, 400);
  assert.equal(db.prepare("SELECT value FROM schema_metadata WHERE key = 'skip_ipwho_is_verification'").get(), undefined);
});

test('重选 IP 会拒绝其他国家的备用地址，保留当前分配', async t => {
  const { db, DB, context } = database(t);
  addProxy(db, proxy);
  addProxy(db, '129.158.198.241:8443');
  db.prepare('UPDATE access_links SET proxy_ip = ?').run(proxy);
  mockNetwork(t, { countries: { '129.158.198.241': 'US' } });
  await assert.rejects(__test.执行访问链接操作({ session: DB, env: { DB }, request: context.request,
    adminSession: null, id: 1, action: 'reassign' }), /没有其他通过/);
  assert.equal(db.prepare('SELECT proxy_ip FROM access_links').get().proxy_ip, proxy);
});

test('配置混入未验证备用地址或过期证据时拒绝拨号', () => {
  const context = { 记录: { country: 'PH' }, 已验证代理候选: [verifiedProxy('PH', proxy)] };
  assert.throws(() => __test.校验国家出口连接配置(context, { 反代IP: proxy + ',129.158.198.241:8443' }), /未验证/);
  context.已验证代理候选[0].country_verified_at -= 61000;
  assert.throws(() => __test.校验国家出口连接配置(context, { 反代IP: proxy }), /过期/);
});

test('国家节点只拨号已验证反代，反代失败时不直连也不使用公共兜底', async t => {
  const dialed = [];
  const context = { 记录: { country: 'PH' }, 已验证代理候选: [verifiedProxy('PH', proxy)],
    env: { DB: { prepare() { return { bind() { return this; }, async first() { return null; } }; } } } };
  const request = { fetcher: { connect(address) {
    dialed.push(address);
    return { opened: Promise.reject(new Error('offline')), close() {} };
  } } };
  const bridge = { readyState: WebSocket.OPEN, close() { this.readyState = WebSocket.CLOSED; } };
  await assert.rejects(__test.forwardataTCP('target.example', 443, Uint8Array.of(65), bridge, null, {}, uuid, request,
    { 反代IP: proxy, 启用反代兜底: true, 访问授权上下文: context }), /连接终止/);
  assert.deepEqual(dialed, [{ hostname: proxy, port: 443 }]);
});

test('严格国家节点的 UDP DNS 不能绕过代理直连公共解析器', async () => {
  let dialed = false;
  await assert.rejects(__test.forwardataudp(Uint8Array.of(0, 1, 65), { readyState: WebSocket.OPEN }, null,
    { fetcher: { connect() { dialed = true; } } }, null, { 记录: { country: 'PH' } }), /HTTPS DNS/);
  assert.equal(dialed, false);
});

test('反代故障时先验证备用出口，跳过 US 并连接 PH 备用', async t => {
  const { db, context } = database(t);
  const backup = '38.54.81.111';
  addProxy(db, proxy, 99);
  addProxy(db, '129.158.198.241:8443', 98);
  addProxy(db, backup, 50);
  mockNetwork(t, { countries: { '129.158.198.241': 'US' } });
  await __test.激活访问授权上下文(context);
  const dialed = [], writes = [];
  let controller, resolveClosed;
  const socket = {
    opened: Promise.resolve(), closed: new Promise(resolve => { resolveClosed = resolve; }),
    readable: new ReadableStream({ start(c) { controller = c; } }),
    writable: new WritableStream({ write(bytes) { writes.push([...bytes]); } }),
    close() { try { controller.close(); } catch {} resolveClosed(); }
  };
  const request = { fetcher: { connect(address) {
    dialed.push(address);
    return address.hostname === proxy
      ? { opened: Promise.reject(new Error('primary offline')), close() {} } : socket;
  } } };
  const bridge = { readyState: WebSocket.OPEN, close() { this.readyState = WebSocket.CLOSED; }, send() {} };
  t.after(async () => { bridge.close(); socket.close(); await new Promise(resolve => setTimeout(resolve, 0)); });
  await __test.forwardataTCP('target.example', 443, Uint8Array.of(65), bridge, null, {}, uuid, request, context.反代上下文);
  assert.deepEqual(dialed, [{ hostname: proxy, port: 443 }, { hostname: backup, port: 443 }]);
  assert.deepEqual(writes, [[65]]);
  assert.equal(db.prepare('SELECT proxy_ip FROM access_links').get().proxy_ip, backup);
  assert.equal(db.prepare('SELECT proxy_ip FROM access_connection_leases').get().proxy_ip, backup);
  assert.equal(db.prepare('SELECT country_verified_at FROM proxy_ip_pool WHERE proxy_ip = ?').get('129.158.198.241:8443').country_verified_at, null);
});

test('升级清除未验证旧分配并增加连接代次，保留计时、凭据和统计', t => {
  const db = new DatabaseSync(':memory:');
  t.after(() => db.close());
  const migrations = new URL('../migrations/', import.meta.url);
  for (const file of readdirSync(migrations).filter(name => name.endsWith('.sql') && name < '0006').sort()) {
    db.exec(readFileSync(new URL(file, migrations), 'utf8'));
  }
  db.prepare(`INSERT INTO access_links(token, uuid, country, duration_seconds, created_at,
    proxy_ip, first_used_at, expires_at, connection_count, connection_epoch)
    VALUES (?, ?, 'PH', 10800, 1000, '129.158.198.241:8443', 2000, 10802000, 332, 3)`)
    .run('x'.repeat(43), uuid);
  db.exec(readFileSync(new URL('0006_strict_country_egress.sql', migrations), 'utf8'));
  const row = db.prepare('SELECT * FROM access_links').get();
  assert.equal(row.proxy_ip, null);
  assert.equal(row.connection_epoch, 4);
  assert.equal(row.first_used_at, 2000);
  assert.equal(row.expires_at, 10802000);
  assert.equal(row.connection_count, 332);
  assert.equal(row.uuid, uuid);
});

test('国家池可用数不包含未验证、错误国家或过期的健康地址', async t => {
  const { db, DB } = database(t);
  for (const ip of [proxy, '38.54.81.111', '38.54.86.233']) addProxy(db, ip);
  db.prepare("UPDATE proxy_ip_pool SET exit_country = 'PH', country_verified_at = ? WHERE proxy_ip = ?").run(Date.now(), proxy);
  db.prepare("UPDATE proxy_ip_pool SET exit_country = 'US', country_verified_at = ? WHERE proxy_ip = ?").run(Date.now(), '38.54.81.111');
  assert.equal((await __test.获取已验证国家池状态(DB, 'PH')).healthy, 1);
});

test('CM all.json 的 3 个 PH 候选是权威列表，不被滞后 ZIP 覆盖', async t => {
  const all = JSON.stringify({ data: [
    { ip: '111.125.75.92', port: [443], meta: { country: 'PH' } },
    { ip: '38.54.81.111', port: [443], meta: { country: 'PH' } },
    { ip: '38.54.86.233', port: [443], meta: { country: 'PH' } }
  ] });
  const parsed = __test.解析访问PROXYIP数据源(all);
  assert.deepEqual(parsed.entries.filter(item => item.country === 'PH').map(item => item.proxy_ip), [
    '111.125.75.92', '38.54.81.111', '38.54.86.233'
  ]);
  let zipRequested = false;
  t.mock.method(globalThis, 'fetch', async input => {
    const url = new URL(input);
    if (url.pathname.endsWith('/ip.zip')) { zipRequested = true; return new Response('stale ZIP content', { status: 200, headers: { 'Content-Type': 'application/zip' } }); }
    return new Response(all, { status: 200, headers: { 'Content-Type': 'application/json' } });
  });
  const text = await __test.获取访问PROXYIP数据源内容({ url: 'https://zip.cm.edu.kg.cmliussss.net/all.json' }, 'PH');
  assert.deepEqual(__test.解析访问PROXYIP数据源(text).entries.map(item => item.proxy_ip), [
    '111.125.75.92', '38.54.81.111', '38.54.86.233'
  ]);
  assert.equal(zipRequested, false);
});
