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

test('外部数据源仅允许 HTTPS 且阻止本地与私网地址', () => {
  assert.equal(__test.标准化访问数据源URL('https://example.com/list.json'), 'https://example.com/list.json');
  assert.throws(() => __test.标准化访问数据源URL('http://example.com/list'), /HTTPS/);
  assert.throws(() => __test.标准化访问数据源URL('https://127.0.0.1/list'), /本地或私有/);
  assert.throws(() => __test.标准化访问数据源URL('https://192.168.1.2/list'), /本地或私有/);
  assert.throws(() => __test.标准化访问数据源URL('https://[::1]/list'), /本地或私有/);
});
