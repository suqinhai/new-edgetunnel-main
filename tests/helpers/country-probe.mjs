export function verifiedProxy(country = 'TW', proxy_ip = '203.0.113.11') {
  return { proxy_ip, exit_country: country, exit_ip: proxy_ip, country_verified_at: Date.now() };
}

export function mockCountryProbe(t, country = 'TW') {
  t.mock.method(globalThis, 'fetch', async input => {
    const url = new URL(input);
    if (url.hostname === 'api.090227.xyz') {
      const candidate = url.searchParams.get('proxyip');
      const address = new URL('https://' + candidate);
      return Response.json({ success: true, proxyIP: address.hostname, portRemote: Number(address.port || 443),
        supports_ipv4: true, supports_ipv6: false, responseTime: 12,
        probe_results: { ipv4: { ok: true, exit: { ip: address.hostname, country } } } });
    }
    if (url.hostname === 'ipwho.is') {
      return Response.json({ success: true, ip: decodeURIComponent(url.pathname.slice(1)), country_code: country });
    }
    throw new Error('Unexpected network request: ' + url.hostname);
  });
}
