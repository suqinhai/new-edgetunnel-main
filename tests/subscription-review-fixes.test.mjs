import test from 'node:test';
import assert from 'node:assert/strict';
import { __test } from '../_worker.js';

const baseProxy = {
  反代IP: 'fallback.example',
  启用反代兜底: true,
  启用SOCKS5反代: null,
  启用SOCKS5全局反代: false,
  parsedSocks5Address: {}
};

test('兼容反代路径忽略参数名大小写但保留代理凭据大小写', async () => {
  for (const prefix of ['proxyip=', 'PrOxYiP=', 'PROXYIP.', 'PyIp=', 'IP=']) {
    for (const protocol of ['socks5', 'http', 'https', 'turn', 'sstp']) {
      const url = new URL(`https://worker.example/custom/${prefix}${protocol}://User:PaSS:Tail@proxy.example:1080`);
      const proxy = await __test.反代参数获取(url, '', baseProxy);
      assert.equal(proxy.启用SOCKS5反代, protocol, prefix);
      assert.equal(proxy.启用SOCKS5全局反代, true);
      assert.deepEqual(proxy.parsedSocks5Address, {
        username: 'User', password: 'PaSS:Tail', hostname: 'proxy.example', port: 1080
      }, `${prefix}${protocol}`);
    }
  }
});

test('反代路径修复保留普通 IP 参数及原有代理 URL 入口行为', async () => {
  const direct = await __test.反代参数获取(new URL('https://worker.example/PrOxYiP=203.0.113.5:8443'), '', baseProxy);
  assert.equal(direct.反代IP, '203.0.113.5:8443');
  assert.equal(direct.启用SOCKS5反代, null);
  assert.equal(direct.启用反代兜底, false);
  for (const path of [
    '/socks5://User:PaSS@proxy.example:1080',
    '/?proxyip=socks5://User:PaSS@proxy.example:1080'
  ]) {
    const proxy = await __test.反代参数获取(new URL(path, 'https://worker.example'), '', baseProxy);
    assert.equal(proxy.parsedSocks5Address.username, 'User');
    assert.equal(proxy.parsedSocks5Address.password, 'PaSS');
  }
});

test('代理明文及 Base64 凭据均保留密码内的所有冒号', () => {
  for (const password of ['first:second', ':leading', 'trailing:', 'one::three']) {
    for (const auth of [`User:${password}`, btoa(`User:${password}`)]) {
      const proxy = __test.获取SOCKS5账号(`${auth}@proxy.example:1080`);
      assert.equal(proxy.username, 'User');
      assert.equal(proxy.password, password, auth);
    }
  }
  const anonymous = __test.获取SOCKS5账号('proxy.example:1080');
  assert.equal(anonymous.username, undefined);
  assert.equal(anonymous.password, undefined);
  assert.throws(() => __test.获取SOCKS5账号('User:@proxy.example:1080'), /认证部分必须/);
});

for (const source of ['https', 'base64', 'sub']) {
  test(`${source} 订阅的 API 备注只更新 URI fragment，保留连接参数`, async t => {
    const links = [
      'vless://11111111-1111-4111-8111-111111111111@host.example:443?security=tls&type=ws',
      'trojan://password@host.example:443?security=tls&type=ws&path=%2Fcustom%3Ftoken%3DABC',
      'vless://11111111-1111-4111-8111-111111111111@host.example:443?type=ws#Original%20name'
    ];
    const raw = links.join('\r\n');
    t.mock.method(globalThis, 'fetch', async url => {
      if (source === 'sub') {
        assert.equal(String(url), 'https://api.example/sub?host=example.com&uuid=00000000-0000-4000-8000-000000000000');
      } else {
        assert.equal(String(url), 'https://api.example/list');
      }
      return new Response(source === 'https' ? raw : btoa(raw));
    });
    const remark = '测试 # A&B';
    const sourceURL = source === 'sub' ? 'sub://api.example' : 'https://api.example/list';
    const [ips, result] = await __test.请求优选API([`${sourceURL}#${encodeURIComponent(remark)}`]);
    assert.deepEqual(ips, []);
    assert.equal(result.length, links.length);
    for (let i = 0; i < links.length; i++) {
      const before = new URL(links[i]);
      const after = new URL(result[i]);
      assert.equal(after.search, before.search);
      assert.equal(after.searchParams.get('type'), 'ws');
      assert.equal(after.searchParams.get('path'), before.searchParams.get('path'));
      assert.equal(decodeURIComponent(after.hash.slice(1)), i === 2 ? `Original name [${remark}]` : `[${remark}]`);
      before.hash = '';
      after.hash = '';
      assert.equal(after.href, before.href);
    }
  });
}
