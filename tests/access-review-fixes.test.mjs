import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';

// 在内存中额外导出生产路由，避免为本组回归扩大 Worker 的测试接口。
const workerSource = readFileSync(new URL('../_worker.js', import.meta.url), 'utf8');
const { restoreHandler, parseSource, __test } = await import('data:text/javascript;base64,' + Buffer.from(workerSource +
  '\nexport { 处理访问链接管理请求 as restoreHandler, 解析访问PROXYIP数据源 as parseSource };').toString('base64'));

function createDatabase(t) {
  const db = new DatabaseSync(':memory:');
  db.exec('PRAGMA foreign_keys = ON');
  t.after(() => db.close());
  const migrations = new URL('../migrations/', import.meta.url);
  for (const name of readdirSync(migrations).filter(name => name.endsWith('.sql')).sort()) {
    db.exec(readFileSync(new URL(name, migrations), 'utf8'));
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
        bind(...values) { args = Object.fromEntries(values.map((value, i) => [String(i + 1), value])); return this; },
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
      } catch (error) { db.exec('ROLLBACK'); throw error; }
    }
  };
  return { db, DB };
}

async function restore(DB, data, mode = 'merge') {
  const url = new URL('https://worker.example/admin/access/api/backup/restore');
  const csrf = 'test-restore-csrf';
  const session = { id: 'test-admin', csrf_hash: await __test.SHA256十六进制(csrf) };
  const request = new Request(url, {
    method: 'POST',
    headers: { Origin: url.origin, 'Content-Type': 'application/json', Cookie: 'admin_csrf=' + csrf, 'X-CSRF-Token': csrf },
    body: JSON.stringify({ product: 'edgetunnel-access', schema_version: 5, mode, confirmOverwrite: 'RESTORE OVERWRITE', data })
  });
  const response = await restoreHandler(request, { DB }, url.hostname,
    '00000000-0000-4000-8000-000000000000', 'test', url, session);
  return { status: response.status, body: await response.json() };
}

function insertLink(db, id = 1) {
  db.prepare(`INSERT INTO access_links(id, token, uuid, country, duration_seconds, created_at, first_used_at, expires_at, note)
    VALUES (?, ?, ?, 'TW', 3600, ?, ?, ?, 'original')`)
    .run(id, String(id).repeat(43), `00000000-0000-4000-8000-${String(id).padStart(12, '0')}`, Date.now(), Date.now(), Date.now() + 3600000);
}

test('覆盖恢复更新链接且保留既有事件和有效租约', async t => {
  const { db, DB } = createDatabase(t);
  insertLink(db);
  db.prepare('INSERT INTO access_connection_events(access_link_id, started_at, ended_at, success) VALUES (1, ?, ?, 1)')
    .run(Date.now() - 1000, Date.now());
  db.prepare(`INSERT INTO access_connection_leases(id, access_link_id, created_at, heartbeat_at, expires_at)
    VALUES ('active-lease', 1, ?, ?, ?)`)
    .run(Date.now(), Date.now(), Date.now() + 600000);
  const event = db.prepare('SELECT * FROM access_connection_events').get();
  const lease = db.prepare('SELECT * FROM access_connection_leases').get();
  const record = db.prepare('SELECT * FROM access_links').get();
  const result = await restore(DB, { access_links: [{ ...record, note: 'restored' }] }, 'overwrite');
  assert.equal(result.status, 200);
  assert.equal(result.body.inserted, 1);
  assert.deepEqual(result.body.failed, []);
  assert.equal(db.prepare('SELECT note FROM access_links WHERE id = 1').get().note, 'restored');
  assert.deepEqual(db.prepare('SELECT * FROM access_connection_events').get(), event);
  assert.deepEqual(db.prepare('SELECT * FROM access_connection_leases').get(), lease);
  assert.equal(db.prepare('SELECT active_connections FROM access_links WHERE id = 1').get().active_connections, 1);
});

test('覆盖恢复遇到其他主键的凭据冲突时报错且不删除任一链接', async t => {
  const { db, DB } = createDatabase(t);
  insertLink(db, 1);
  insertLink(db, 2);
  const before = db.prepare('SELECT * FROM access_links ORDER BY id').all();
  const result = await restore(DB, { access_links: [{ ...before[0], token: before[1].token }] }, 'overwrite');
  assert.equal(result.status, 207);
  assert.equal(result.body.failed.length, 1);
  assert.deepEqual(db.prepare('SELECT * FROM access_links ORDER BY id').all(), before);
});

const sourceCases = [
  { name: '同 ID 不同 URL', existingId: 10, incomingId: 10, existingURL: 'https://existing.example/source', incomingURL: 'https://backup.example/source', reused: false },
  { name: '同 URL 不同 ID', existingId: 10, incomingId: 20, existingURL: 'https://backup.example/source', incomingURL: 'https://backup.example/source', reused: true },
  { name: '来源 ID 未冲突', existingId: 10, incomingId: 20, existingURL: 'https://existing.example/source', incomingURL: 'https://backup.example/source', reused: false }
];
for (const scenario of sourceCases) {
  test(`合并恢复正确关联来源与同步状态：${scenario.name}`, async t => {
    const { db, DB } = createDatabase(t);
    db.prepare('INSERT INTO proxy_ip_sources(id, name, url, created_at, updated_at) VALUES (?, ?, ?, 1, 1)')
      .run(scenario.existingId, 'existing', scenario.existingURL);
    const existing = db.prepare('SELECT * FROM proxy_ip_sources WHERE id = ?').get(scenario.existingId);
    const result = await restore(DB, {
      proxy_ip_sources: [{ id: scenario.incomingId, name: 'from backup', url: scenario.incomingURL, enabled: 0, created_at: 2, updated_at: 2 }],
      proxy_ip_pool: [{ id: 99, country: 'TW', proxy_ip: '203.0.113.8', created_at: 2, source_id: scenario.incomingId }],
      proxy_ip_source_sync: [{ source_id: scenario.incomingId, country: 'TW', last_synced_at: 2, last_status: 'success', last_error: '' }]
    });
    assert.equal(result.status, 200);
    assert.deepEqual(result.body.failed, []);
    const source = db.prepare('SELECT * FROM proxy_ip_sources WHERE url = ?').get(scenario.incomingURL);
    assert.ok(source);
    assert.deepEqual(db.prepare('SELECT * FROM proxy_ip_sources WHERE id = ?').get(scenario.existingId), existing);
    if (scenario.reused) assert.equal(source.id, scenario.existingId);
    else {
      assert.notEqual(source.id, scenario.existingId);
      assert.equal(source.name, 'from backup');
      if (scenario.incomingId !== scenario.existingId) assert.equal(source.id, scenario.incomingId);
    }
    assert.equal(db.prepare('SELECT source_id FROM proxy_ip_pool WHERE id = 99').get().source_id, source.id);
    assert.equal(db.prepare('SELECT source_id FROM proxy_ip_source_sync WHERE country = ?').get('TW').source_id, source.id);
  });
}

test('来源恢复失败时拒绝关联记录，避免复用同 ID 的无关来源', async t => {
  const { db, DB } = createDatabase(t);
  db.exec("INSERT INTO proxy_ip_sources(id, name, url, created_at, updated_at) VALUES (10, 'existing', 'https://existing.example', 1, 1)");
  const result = await restore(DB, {
    proxy_ip_sources: [{ id: 10, name: null, url: 'https://invalid-backup.example', created_at: 2, updated_at: 2 }],
    proxy_ip_pool: [{ id: 99, country: 'TW', proxy_ip: '203.0.113.8', created_at: 2, source_id: 10 }]
  });
  assert.equal(result.status, 207);
  assert.equal(result.body.failed.some(item => item.table === 'proxy_ip_pool'), true);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM proxy_ip_pool').get().n, 0);
});

test('CSV 保留空字段的位置并允许缺省端口', () => {
  for (const defaultCountry of ['', 'TW']) {
    assert.deepEqual(parseSource('ip,port,country\n203.0.113.8,,TW', defaultCountry), {
      entries: [{ country: 'TW', proxy_ip: '203.0.113.8' }], skipped: 0
    });
  }
  assert.deepEqual(parseSource('name,ip,port,country\n,203.0.113.8,8443,TW'), {
    entries: [{ country: 'TW', proxy_ip: '203.0.113.8:8443' }], skipped: 0
  });
  assert.deepEqual(parseSource('ip,country\n,TW'), { entries: [], skipped: 1 });
});
