import test from 'node:test';
import assert from 'node:assert/strict';
import { __test } from '../_worker.js';

const uuid = '00000000-0000-4000-8000-000000000000';
const encoder = new TextEncoder();
const header = 'HTTP/1.1 200 Connection established\r\n\r\n';
const tick = () => new Promise(resolve => setTimeout(resolve, 0));

function fixture(t, { handshakeChunks = [header], proxy = 'http', failInitialWrite = false, cancelOnInitialWrite = false } = {}) {
  let controller, resolveClosed, rejectClosed, resolveClientClosed;
  const sent = [], writes = [];
  const state = { socket: null, sockets: new Set() };
  const bridge = {
    readyState: WebSocket.OPEN,
    closed: new Promise(resolve => { resolveClientClosed = resolve; }),
    send(bytes) { assert.equal(this.readyState, WebSocket.OPEN); sent.push(...bytes); },
    close() { this.readyState = WebSocket.CLOSED; resolveClientClosed(); }
  };
  const socket = {
    didClose: false, readCancelled: false,
    opened: Promise.resolve(),
    closed: new Promise((resolve, reject) => { resolveClosed = resolve; rejectClosed = reject; }),
    readable: new ReadableStream({
      start(c) { controller = c; },
      cancel() { socket.readCancelled = true; }
    }),
    writable: new WritableStream({
      write(bytes) {
        writes.push(Uint8Array.from(bytes));
        if (writes.length === 1) {
          for (const chunk of handshakeChunks) controller.enqueue(encoder.encode(chunk));
        } else {
          if (cancelOnInitialWrite) { state.cancelled = true; bridge.close(); }
          if (failInitialWrite) throw new Error('initial write failed');
        }
      }
    }),
    send(bytes) { controller.enqueue(Uint8Array.from(bytes)); },
    end(bytes = []) {
      if (bytes.length) this.send(bytes);
      controller.close();
      resolveClosed();
    },
    fail() {
      const error = new Error('upstream reset');
      controller.error(error);
      rejectClosed(error);
    },
    close() {
      this.didClose = true;
      try { controller.close(); } catch {}
      resolveClosed();
    }
  };
  const request = { fetcher: { connect() { return socket; } } };
  const connect = () => __test.forwardataTCP('target.example', 443, Uint8Array.of(65), bridge,
    Uint8Array.of(0, 0), state, uuid, request, {
      启用SOCKS5反代: proxy, 启用SOCKS5全局反代: true,
      parsedSocks5Address: { hostname: 'proxy.example', port: 8080 }
    });
  t.after(async () => {
    bridge.close();
    socket.close();
    await tick();
  });
  return { connect, bridge, socket, state, sent, writes };
}

for (const proxy of ['http', 'https']) {
  for (const split of [false, true]) {
    test(`${proxy} CONNECT ${split ? '拆分响应头并夹带首包' : '响应头与首包合并'}不阻塞且保留数据顺序`, { timeout: 1500 }, async t => {
      const handshakeChunks = split ? ['HTTP/1.1 200 Connection established\r\n\r', '\nhello'] : [header + 'hello'];
      const f = fixture(t, { handshakeChunks, proxy });
      await f.connect();
      assert.equal(f.writes.length, 2);
      assert.deepEqual([...f.writes[1]], [65]);
      f.socket.end(encoder.encode(' world'));
      await f.bridge.closed;
      await tick();
      assert.deepEqual(f.sent, [0, 0, ...encoder.encode('hello world')]);
      assert.equal(f.socket.readable.locked, false);
      assert.equal(f.socket.writable.locked, false);
    });
  }
}

for (const size of [3, 32771]) {
  test(`代理 socket.closed 与 EOF 同时到达仍完整发送 ${size} 字节响应`, { timeout: 1500 }, async t => {
    const f = fixture(t);
    await f.connect();
    const payload = Uint8Array.from({ length: size }, (_, i) => i % 251);
    f.socket.end(payload);
    await f.bridge.closed;
    await tick();
    assert.deepEqual(f.sent, [0, 0, ...payload]);
    assert.equal(f.socket.readable.locked, false);
  });
}

test('CONNECT 夹带首包后读取失败会关闭客户端并释放读取器', { timeout: 1500 }, async t => {
  const f = fixture(t, { handshakeChunks: [header + 'hello'] });
  await f.connect();
  f.socket.fail();
  await f.bridge.closed;
  await tick();
  assert.equal(f.socket.didClose, true);
  assert.equal(f.socket.readable.locked, false);
  assert.equal(f.socket.writable.locked, false);
});

test('CONNECT 夹带首包后取消下行读取会关闭 socket 并释放读取器', { timeout: 1500 }, async t => {
  const f = fixture(t, { handshakeChunks: [header + 'hello'] });
  let resolveSendStarted, rejectSend;
  const sendStarted = new Promise(resolve => { resolveSendStarted = resolve; });
  f.bridge.send = () => {
    resolveSendStarted();
    return new Promise((_, reject) => { rejectSend = reject; });
  };
  await f.connect();
  // 让转发器等待一次下行发送，然后模拟客户端取消该发送。
  f.socket.send(new Uint8Array(32768));
  await sendStarted;
  rejectSend(new Error('client cancelled'));
  await f.bridge.closed;
  await tick();
  assert.equal(f.socket.readCancelled, true);
  assert.equal(f.socket.didClose, true);
  assert.equal(f.socket.readable.locked, false);
});

test('CONNECT 包装连接在下行读取启动前取消也会释放握手读取器', { timeout: 1500 }, async t => {
  const f = fixture(t, { handshakeChunks: [header + 'hello'], cancelOnInitialWrite: true });
  await f.connect();
  await tick();
  assert.equal(f.state.socket, null);
  assert.equal(f.socket.readCancelled, true);
  assert.equal(f.socket.didClose, true);
  assert.equal(f.socket.readable.locked, false);
  assert.equal(f.socket.writable.locked, false);
  assert.deepEqual(f.sent, []);
});

test('CONNECT 后写入首包失败不会遗留读写锁', { timeout: 1500 }, async t => {
  const f = fixture(t, { handshakeChunks: [header + 'hello'], failInitialWrite: true });
  await assert.rejects(f.connect(), /initial write failed/);
  assert.equal(f.socket.didClose, true);
  assert.equal(f.socket.readable.locked, false);
  assert.equal(f.socket.writable.locked, false);
});
