import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import worker, { __test } from '../_worker.js';

const secret = 'test-relay-secret-that-is-long-and-random';
const encoder = new TextEncoder();

function createDatabase(t) {
  const db = new DatabaseSync(':memory:');
  t.after(() => db.close());
  const migrations = new URL('../migrations/', import.meta.url);
  for (const file of readdirSync(migrations).filter(name => name.endsWith('.sql')).sort()) {
    db.exec(readFileSync(new URL(file, migrations), 'utf8'));
  }
  const DB = {
    prepare(sql) {
      const statement = db.prepare(sql);
      let args = {};
      const run = () => {
        const result = statement.run(args);
        return { meta: { changes: result.changes, last_row_id: result.lastInsertRowid } };
      };
      return {
        sql,
        bind(...values) { args = Object.fromEntries(values.map((value, index) => [String(index + 1), value])); return this; },
        async first() { return statement.get(args); },
        async all() { return { results: statement.all(args) }; },
        async run() { return run(); },
        runSync: run
      };
    },
    async batch(statements) {
      db.exec('BEGIN');
      try {
        const results = statements.map(statement => statement.runSync());
        db.exec('COMMIT');
        return results;
      } catch (error) {
        db.exec('ROLLBACK');
        throw error;
      }
    }
  };
  return { db, DB };
}

function validBody(overrides = {}) {
  const base = {
    country: 'SG',
    accessToken: 'user-provided-access-token',
    payload: {
      plan_name: 'chatgptteamplan',
      team_plan_data: { workspace_name: 'Test workspace', price_interval: 'month', seat_quantity: 2 },
      billing_details: { country: 'SG', currency: 'SGD' },
      cancel_url: 'https://chatgpt.com/?promoCode=SAVE',
      promo_code: 'SAVE',
      checkout_ui_mode: 'hosted'
    }
  };
  return { ...base, ...overrides, payload: overrides.payload ? { ...base.payload, ...overrides.payload } : base.payload };
}

async function signedRequest(body, { timestamp = Date.now().toString(), nonce = crypto.randomUUID().replaceAll('-', ''), signature, contentType = 'application/json' } = {}) {
  const raw = typeof body === 'string' ? body : JSON.stringify(body);
  const signed = signature ?? await __test.计算ChatGPT中继签名(secret, timestamp, nonce, raw);
  return new Request('https://worker.example/internal/chatgpt/checkout', {
    method: 'POST',
    headers: {
      'Content-Type': contentType,
      'X-Relay-Timestamp': timestamp,
      'X-Relay-Nonce': nonce,
      'X-Relay-Signature': signed,
      'CF-Connecting-IP': '203.0.113.55'
    },
    body: raw
  });
}

function insertProxy(db, overrides = {}) {
  const row = { country: 'SG', proxy_ip: 'proxy.example:443', health_status: 'healthy', health_score: 90, latency_ms: 20, ...overrides };
  db.prepare(`INSERT INTO proxy_ip_pool(country, proxy_ip, enabled, created_at, health_status, health_score, latency_ms, updated_at)
    VALUES (?, ?, 1, ?, ?, ?, ?, ?)`)
    .run(row.country, row.proxy_ip, Date.now(), row.health_status, row.health_score, row.latency_ms, Date.now());
}

const successTransport = async () => ({
  status: 200,
  headers: new Headers({ 'Content-Type': 'application/json' }),
  body: encoder.encode(JSON.stringify({ url: 'https://checkout.stripe.com/c/pay_test', checkout_session_id: 'cs_test_123' }))
});

async function callRelay(t, body = validBody(), transport = successTransport, envOverrides = {}) {
  const { db, DB } = createDatabase(t);
  insertProxy(db);
  const request = await signedRequest(body);
  const response = await __test.处理ChatGPTCheckout中继(request, { DB, RADAR_RELAY_SECRET: secret, OFF_LOG: 'true', ...envOverrides }, {}, transport);
  return { db, response, json: await response.json() };
}

test('正确签名请求通过且仅返回经过筛选的 checkout 字段', async t => {
  const { response, json } = await callRelay(t);
  assert.equal(response.status, 200);
  assert.deepEqual(json, {
    ok: true,
    url: 'https://checkout.stripe.com/c/pay_test',
    checkoutSessionId: 'cs_test_123',
    country: 'SG',
    network: 'country-relay'
  });
});

test('固定路由在通用 POST/XHTTP 分流前处理，缺少配置返回 503', async () => {
  const response = await worker.fetch(new Request('https://worker.example/internal/chatgpt/checkout', { method: 'POST' }), {}, { waitUntil() {} });
  assert.equal(response.status, 503);
  assert.equal((await response.json()).error, 'relay_unconfigured');
});

test('错误签名被拒绝且不会占用 nonce', async t => {
  const { DB } = createDatabase(t);
  const request = await signedRequest(validBody(), { signature: '0'.repeat(64) });
  const response = await __test.处理ChatGPTCheckout中继(request, { DB, RADAR_RELAY_SECRET: secret });
  assert.equal(response.status, 401);
  assert.equal((await response.json()).error, 'invalid_signature');
});

test('超过五分钟的时间戳被拒绝', async t => {
  const { DB } = createDatabase(t);
  const request = await signedRequest(validBody(), { timestamp: String(Date.now() - 301000) });
  const response = await __test.处理ChatGPTCheckout中继(request, { DB, RADAR_RELAY_SECRET: secret });
  assert.equal((await response.json()).error, 'request_expired');
});

test('nonce 原文不落库且重放被拒绝', async t => {
  const { db, DB } = createDatabase(t);
  insertProxy(db);
  const body = validBody(), timestamp = Date.now().toString(), nonce = 'replay_nonce_1234567890';
  const first = await __test.处理ChatGPTCheckout中继(await signedRequest(body, { timestamp, nonce }), { DB, RADAR_RELAY_SECRET: secret }, {}, successTransport);
  const second = await __test.处理ChatGPTCheckout中继(await signedRequest(body, { timestamp, nonce }), { DB, RADAR_RELAY_SECRET: secret }, {}, successTransport);
  assert.equal(first.status, 200);
  assert.equal(second.status, 409);
  assert.equal((await second.json()).error, 'replayed_nonce');
  const stored = db.prepare('SELECT nonce_hash FROM chatgpt_relay_nonces').get();
  assert.notEqual(stored.nonce_hash, nonce);
  assert.equal(stored.nonce_hash.length, 64);
});

test('中继按来源 IP 执行每分钟限流', async t => {
  const { db, DB } = createDatabase(t);
  insertProxy(db);
  const env = { DB, RADAR_RELAY_SECRET: secret, RADAR_RELAY_RATE_LIMIT: '1' };
  const first = await __test.处理ChatGPTCheckout中继(await signedRequest(validBody()), env, {}, successTransport);
  const second = await __test.处理ChatGPTCheckout中继(await signedRequest(validBody()), env, {}, successTransport);
  assert.equal(first.status, 200);
  assert.equal(second.status, 429);
  assert.equal((await second.json()).error, 'rate_limited');
});

test('请求体硬上限不超过 64 KB', async t => {
  const { DB } = createDatabase(t);
  const request = new Request('https://worker.example/internal/chatgpt/checkout', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Relay-Timestamp': Date.now().toString(), 'X-Relay-Nonce': 'oversized_nonce_1234567890', 'X-Relay-Signature': '0'.repeat(64) },
    body: 'x'.repeat(65537)
  });
  const response = await __test.处理ChatGPTCheckout中继(request, { DB, RADAR_RELAY_SECRET: secret });
  assert.equal(response.status, 413);
  assert.equal((await response.json()).error, 'invalid_payload');
});

test('任意 target URL 字段被严格 schema 拒绝', async t => {
  const { response, json } = await callRelay(t, { ...validBody(), target: 'https://example.com/' });
  assert.equal(response.status, 400);
  assert.equal(json.error, 'invalid_payload');
});

for (const [name, mutate] of [
  ['非法 country', body => ({ ...body, country: 'sg' })],
  ['billing country 不一致', body => ({ ...body, payload: { ...body.payload, billing_details: { country: 'US', currency: 'SGD' } } })],
  ['非法 currency', body => ({ ...body, payload: { ...body.payload, billing_details: { country: 'SG', currency: 'BTC' } } })],
  ['非法 workspace UUID', body => ({ ...body, payload: { ...body.payload, team_plan_data: { ...body.payload.team_plan_data, existing_workspace_id: 'not-a-uuid' } } })]
]) {
  test(`${name} 被拒绝`, async t => {
    const { response, json } = await callRelay(t, mutate(validBody()));
    assert.equal(response.status, 400);
    assert.equal(json.error, 'invalid_payload');
  });
}

test('没有健康代理时强制同步该国家数据源后重新选择', async t => {
  const { db, DB } = createDatabase(t);
  db.exec('ALTER TABLE proxy_ip_sources ADD COLUMN sync_lock TEXT; ALTER TABLE proxy_ip_sources ADD COLUMN sync_lock_expires_at INTEGER');
  const now = Date.now();
  db.prepare(`INSERT INTO proxy_ip_sources(name, url, default_country, enabled, refresh_minutes, max_per_country, last_status, created_at, updated_at)
    VALUES ('builtin-disabled', 'https://zip.cm.edu.kg.cmliussss.net/all.json', '', 0, 60, 100, 'never', ?, ?),
           ('test-source', 'https://source.example/proxies', 'SG', 1, 60, 100, 'never', ?, ?)`)
    .run(now, now, now, now);
  let synced = 0, selectedProxy = '';
  t.mock.method(globalThis, 'fetch', async url => {
    assert.equal(String(url), 'https://source.example/proxies');
    synced++;
    return new Response('fresh-proxy.example:443', { headers: { 'Content-Type': 'text/plain' } });
  });
  const response = await __test.处理ChatGPTCheckout中继(await signedRequest(validBody()), { DB, RADAR_RELAY_SECRET: secret }, {}, async (_request, proxy) => {
    selectedProxy = proxy;
    return successTransport();
  });
  assert.equal(response.status, 200);
  assert.equal(synced, 1);
  assert.equal(selectedProxy, 'fresh-proxy.example:443');
});

test('代理网络错误记录失败并返回通用错误', async t => {
  let attempts = 0;
  const { db, response, json } = await callRelay(t, validBody(), async () => { attempts++; throw new Error('secret transport detail'); });
  assert.equal(response.status, 502);
  assert.equal(json.error, 'proxy_connect_failed');
  assert.equal(attempts, 1, 'checkout POST 不得自动重试');
  const row = db.prepare('SELECT real_failure_count, last_error FROM proxy_ip_pool').get();
  assert.equal(row.real_failure_count, 1);
  assert.equal(row.last_error, 'relay_network_failure');
});

test('ChatGPT 401 不会将代理记录为失败', async t => {
  const { db, response, json } = await callRelay(t, validBody(), async () => ({ status: 401, headers: new Headers(), body: encoder.encode('{}') }));
  assert.equal(response.status, 401);
  assert.equal(json.error, 'chatgpt_auth_failed');
  const row = db.prepare('SELECT real_success_count, real_failure_count FROM proxy_ip_pool').get();
  assert.equal(row.real_success_count, 1);
  assert.equal(row.real_failure_count, 0);
});

for (const url of ['http://checkout.stripe.com/pay', 'https://evil.example/pay']) {
  test(`支付 URL ${url} 被拒绝`, async t => {
    const transport = async () => ({ status: 200, headers: new Headers(), body: encoder.encode(JSON.stringify({ url })) });
    const { response, json } = await callRelay(t, validBody(), transport);
    assert.equal(response.status, 502);
    assert.equal(json.error, 'checkout_url_invalid');
  });
}

test('Access Token 不出现在日志、错误响应或 D1 中', async t => {
  const token = 'very-sensitive-access-token-value';
  const messages = [];
  for (const method of ['log', 'warn', 'error']) t.mock.method(console, method, (...args) => messages.push(args.join(' ')));
  const { db, json } = await callRelay(t, validBody({ accessToken: token }), async () => { throw new Error(`network failed ${token}`); });
  const text = JSON.stringify(json);
  assert.doesNotMatch(text, new RegExp(token));
  assert.doesNotMatch(messages.join('\n'), new RegExp(token));
  const persisted = db.prepare(`SELECT group_concat(value, '|') AS values_text FROM (
    SELECT nonce_hash AS value FROM chatgpt_relay_nonces
    UNION ALL SELECT client_hash FROM chatgpt_relay_rate_limits
    UNION ALL SELECT last_error FROM proxy_ip_pool)`).get().values_text;
  assert.doesNotMatch(String(persisted), new RegExp(token));
});

test('接口只接受 POST 且不返回宽泛 CORS', async () => {
  const response = await __test.处理ChatGPTCheckout中继(new Request('https://worker.example/internal/chatgpt/checkout', { method: 'OPTIONS' }), { RADAR_RELAY_SECRET: secret, DB: {} });
  assert.equal(response.status, 405);
  assert.equal(response.headers.has('Access-Control-Allow-Origin'), false);
});
