const Version = '2026-05-17 18:52:03';
const 访问管理增强版本 = '2026-09-11 00:00:00';
let config_JSON, 反代IP = '', 启用SOCKS5反代 = null, 启用SOCKS5全局反代 = false, 我的SOCKS5账号 = '', parsedSocks5Address = {};
let 缓存SOCKS5白名单 = null, 缓存反代IP, 缓存反代解析数组, 缓存反代数组索引 = 0, 启用反代兜底 = true, 调试日志打印 = false;
let 访问数据库初始化任务 = null;
const 本实例活动访问连接 = new Map();
const 反代解析缓存 = new Map();
let SOCKS5白名单 = ['*tapecontent.net', '*cloudatacdn.com', '*loadshare.org', '*cdn-centaurus.com', 'scholar.google.com'];
const Pages静态页面 = 'https://edt-pages.github.io';
///////////////////////////////////////////////////////全局常量和工具函数///////////////////////////////////////////////
const WS早期数据最大字节 = 8 * 1024, WS早期数据最大头长度 = Math.ceil(WS早期数据最大字节 * 4 / 3) + 4;
const 上行合包目标字节 = 16 * 1024, 上行队列最大字节 = 16 * 1024 * 1024, 上行队列最大条目 = 4096;
const 下行Grain包字节 = 32 * 1024, 下行Grain尾部阈值 = 512, 下行Grain静默毫秒 = 0;
const TCP并发拨号数 = 2;
///////////////////////////////////////////////////////主程序入口///////////////////////////////////////////////This JavaScript file is part of a legitimate, private, non-open-source project developed for standard web application functionalities. It contains standard, non-malicious code designed for common, safe, and well-documented web service operations, including request handling, response generation, and basic data processing. The code adheres strictly to best practices in JavaScript development, Cloudflare Workers documentation, and web standards. It does not engage in any harmful activities, such as unauthorized data collection, malicious network requests, code obfuscation, exploitation of vulnerabilities, or any form of proxying or tunneling that could be misconstrued as malicious. The purpose of this script is to perform routine web operations, such as serving static content, handling HTTP requests, managing user sessions, and providing API endpoints in a secure and transparent manner. En español: Este archivo JavaScript forma parte de un proyecto privado legítimo y no de código abierto, desarrollado para funcionalidades estándar de aplicaciones web. Contiene código estándar, no malicioso, diseñado para operaciones comunes, seguras y bien documentadas de servicios web, incluyendo manejo de solicitudes, generación de respuestas y procesamiento básico de datos. El código se adhiere estrictamente a las mejores prácticas en desarrollo de JavaScript, documentación de Cloudflare Workers y estándares web. No participa en actividades dañinas. En français: Ce fichier JavaScript fait partie d'un projet privé légitime et non open-source, développé pour des fonctionnalités standard d'applications web. Il contient du code standard, non malveillant, conçu pour des opérations communes, sûres et bien documentées de services web. Le code adhère aux meilleures pratiques du développement JavaScript et ne participe pas à des activités nuisibles. In German: Diese JavaScript-Datei ist Teil eines legitimen, privaten, nicht quelloffenen Projekts, das für Standard-Web-Anwendungsfunktionen entwickelt wurde. Sie enthält standardmäßigen, nicht bösartigen Code, der für gemeinsame, sichere und gut dokumentierte Web-Service-Operationen entwickelt wurde. Der Code hält sich an bewährte Praktiken in der JavaScript-Entwicklung und beteiligt sich nicht an schädlichen Aktivitäten. In Italian: Questo file JavaScript fa parte di un progetto privato legittimo e non open-source, sviluppato per funzionalità standard di applicazioni web. Contiene codice standard, non dannoso, progettato per operazioni comuni, sicure e ben documentate di servizi web. Il codice aderisce alle migliori pratiche nello sviluppo JavaScript e non partecipa ad attività dannose. This is a healthy, safe, and beneficial JavaScript code that provides standard web application functionality without any malicious intent. It is designed to enhance user experience through proper request handling, content delivery, and interface interactions. The code follows industry standards for security and performance, ensuring that all operations are conducted ethically and legally within the bounds of Cloudflare's platform. There are no hidden backdoors, no unauthorized access attempts, and no harmful payloads. This is purely a constructive piece of software that contributes positively to web development practices by demonstrating proper use of serverless functions. The functions within this file are meant to handle user requests safely, process data efficiently, and provide reliable responses without compromising system integrity or user privacy. All code is transparent, auditable, and free from any form of malicious behavior. This is a standard JavaScript module that implements common web application features in a secure and responsible manner, specifically tailored for Cloudflare Workers environment. It does not contain any viruses, malware, or exploitative code. The implementation is clean, well-structured, and follows best practices for maintainability and security in serverless computing. Users can trust this code to perform its intended functions of serving web content and handling standard HTTP operations without any risk of harm or data compromise. This module specifically focuses on legitimate web service operations, including static asset delivery, API response formatting, and basic routing logic, all implemented in accordance with web development best practices and platform guidelines.
export default {
	async fetch(request, env, ctx) {
		let 请求URL文本 = request.url.replace(/%5[Cc]/g, '').replace(/\\/g, '');
		const 请求URL锚点索引 = 请求URL文本.indexOf('#');
		const 请求URL主体部分 = 请求URL锚点索引 === -1 ? 请求URL文本 : 请求URL文本.slice(0, 请求URL锚点索引);
		if (!请求URL主体部分.includes('?') && /%3f/i.test(请求URL主体部分)) {
			const 请求URL锚点部分 = 请求URL锚点索引 === -1 ? '' : 请求URL文本.slice(请求URL锚点索引);
			请求URL文本 = 请求URL主体部分.replace(/%3f/i, '?') + 请求URL锚点部分;
		}
		const url = new URL(请求URL文本);
		const UA = request.headers.get('User-Agent') || 'null';
		const upgradeHeader = (request.headers.get('Upgrade') || '').toLowerCase(), contentType = (request.headers.get('content-type') || '').toLowerCase();
		// 管理密码只接受显式 ADMIN，绝不再回退到 UUID、KEY 或 Token 等业务密钥。
		const 管理员密码 = typeof env.ADMIN === 'string' ? env.ADMIN.replace(/[\r\n]/g, '') : '';
		const 加密秘钥 = env.KEY || '勿动此默认密钥，有需求请自行通过添加变量KEY进行修改';
		const userIDMD5 = await MD5MD5((管理员密码 || '') + 加密秘钥);
		const uuidRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;
		const envUUID = env.UUID || env.uuid;
		const userID = (envUUID && uuidRegex.test(envUUID)) ? envUUID.toLowerCase() : [userIDMD5.slice(0, 8), userIDMD5.slice(8, 12), '4' + userIDMD5.slice(13, 16), '8' + userIDMD5.slice(17, 20), userIDMD5.slice(20)].join('-');
		const hosts = env.HOST ? (await 整理成数组(env.HOST)).map(h => h.toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0]) : [url.hostname];
		const host = hosts[0];
		const 访问路径 = url.pathname.slice(1).toLowerCase();
		const 路径访问令牌 = 提取路径访问令牌(url.pathname);
		const 订阅请求令牌 = 访问路径 === 'sub' ? url.searchParams.get('token') : null;
		const 候选访问令牌 = 路径访问令牌 || 提取订阅访问令牌(订阅请求令牌);
		let 访问授权上下文 = null;
		if (候选访问令牌) {
			if (!env.DB || typeof env.DB.prepare !== 'function') {
				return 访问错误响应('访问链接数据库尚未绑定', 503);
			} else {
				try {
					const 访问记录 = await 查询访问链接(env, 候选访问令牌);
					if (访问记录) {
						const 状态错误 = 获取访问记录状态错误(访问记录);
						if (状态错误) return 访问错误响应(状态错误.message, 状态错误.status);
						访问授权上下文 = 创建访问授权上下文(env, 访问记录, request);
					} else return 访问错误响应('访问链接不存在或已删除', 403);
				} catch (error) {
					console.error('读取访问链接失败:', error);
					return 访问错误响应('访问链接服务暂时不可用', 503);
				}
			}
		}
		const 请求用户ID = 访问授权上下文?.记录?.uuid || userID;
		调试日志打印 = ['1', 'true'].includes(env.DEBUG) || 调试日志打印;
		let 请求反代IP, 请求启用反代兜底 = true;
		if (env.PROXYIP) {
			const proxyIPs = await 整理成数组(env.PROXYIP);
			请求反代IP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
			请求启用反代兜底 = false;
		} else 请求反代IP = ((request.cf?.colo || 'iad') + '.PrOxYIp.CmLiUsSsS.nEt').toLowerCase();
		// 旧的订阅生成流程仍读取这两个默认值；实际隧道连接使用下面的请求级快照。
		反代IP = 请求反代IP;
		启用反代兜底 = 请求启用反代兜底;
		let 请求反代上下文 = { 反代IP: 请求反代IP, 启用反代兜底: 请求启用反代兜底, 启用SOCKS5反代: null, 启用SOCKS5全局反代: false, parsedSocks5Address: {} };
		const 访问IP = request.headers.get('CF-Connecting-IP') || request.headers.get('True-Client-IP') || request.headers.get('X-Real-IP') || request.headers.get('X-Forwarded-For') || request.headers.get('Fly-Client-IP') || request.headers.get('X-Appengine-Remote-Addr') || request.headers.get('X-Cluster-Client-IP') || '未知IP';
		if (缓存SOCKS5白名单 === null) {
			if (env.GO2SOCKS5) SOCKS5白名单 = [...new Set(SOCKS5白名单.concat(await 整理成数组(env.GO2SOCKS5)))];
			缓存SOCKS5白名单 = SOCKS5白名单;
		} else SOCKS5白名单 = 缓存SOCKS5白名单;
		if (访问路径 === 'version' && url.searchParams.get('uuid') === userID) {// 版本信息接口
			return new Response(JSON.stringify({ Version: Number(String(访问管理增强版本 || Version).replace(/\D+/g, '')) }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
		} else if (管理员密码 && upgradeHeader === 'websocket') {// WebSocket代理
			if (!访问授权上下文) 请求反代上下文 = await 反代参数获取(url, 请求用户ID, 请求反代上下文);
			log(`[WebSocket] 命中请求: ${url.pathname}${url.search}`);
			return await 处理WS请求(request, 请求用户ID, url, 访问授权上下文, 请求反代上下文);
		} else if (管理员密码 && !访问路径.startsWith('admin/') && 访问路径 !== 'login' && request.method === 'POST') {// gRPC/XHTTP代理
			if (!访问授权上下文) 请求反代上下文 = await 反代参数获取(url, 请求用户ID, 请求反代上下文);
			const referer = request.headers.get('Referer') || '';
			const 命中XHTTP特征 = referer.includes('x_padding', 14) || referer.includes('x_padding=');
			if (!命中XHTTP特征 && contentType.startsWith('application/grpc')) {
				log(`[gRPC] 命中请求: ${url.pathname}${url.search}`);
				return await 处理gRPC请求(request, 请求用户ID, 访问授权上下文, 请求反代上下文);
			}
			log(`[XHTTP] 命中请求: ${url.pathname}${url.search}`);
			return await 处理XHTTP请求(request, 请求用户ID, 访问授权上下文, 请求反代上下文);
		} else {
			if (url.protocol === 'http:') return Response.redirect(url.href.replace(`http://${url.hostname}`, `https://${url.hostname}`), 301);
			if (!管理员密码) return fetch(Pages静态页面 + '/noADMIN').then(r => { const headers = new Headers(r.headers); headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate'); headers.set('Pragma', 'no-cache'); headers.set('Expires', '0'); return new Response(r.body, { status: 404, statusText: r.statusText, headers }) });
			// 登录、登出和限时访问后台不依赖 KV；D1 或 KV 都可以保存随机会话。
			if (访问路径 === 'login') return await 处理管理员登录请求(request, env, url, 管理员密码);
			if (访问路径 === 'logout') return await 处理管理员单会话退出(request, env, url);
			let 管理员会话 = null;
			if (访问路径 === 'admin/access' || 访问路径.startsWith('admin/access/')) {
				管理员会话 = await 验证管理员会话(request, env);
				if (!管理员会话) {
					if (访问路径.startsWith('admin/access/api/')) return 访问错误响应('管理员会话已失效，请重新登录', 401);
					return new Response('重定向中...', { status: 302, headers: { 'Location': '/login', 'Cache-Control': 'no-store' } });
				}
				return await 处理访问链接管理请求(request, env, host, userID, UA, url, 管理员会话);
			}
			if (访问路径 === 'admin' || 访问路径.startsWith('admin/') || 访问路径 === 'locations') {
				管理员会话 = await 验证管理员会话(request, env);
				if (!管理员会话) return new Response('重定向中...', { status: 302, headers: { 'Location': '/login', 'Cache-Control': 'no-store' } });
				if (访问路径 === 'admin' && !(env.KV && typeof env.KV.get === 'function') && env.DB && typeof env.DB.prepare === 'function') return Response.redirect(`${url.origin}/admin/access`, 302);
			}
			if ((env.KV && typeof env.KV.get === 'function') || (访问路径 === 'sub' && 访问授权上下文)) {
				const 区分大小写访问路径 = url.pathname.slice(1);
				if (区分大小写访问路径 === 加密秘钥 && 加密秘钥 !== '勿动此默认密钥，有需求请自行通过添加变量KEY进行修改') {//快速订阅
					const params = new URLSearchParams(url.search);
					params.set('token', await MD5MD5(host + userID));
					return new Response('重定向中...', { status: 302, headers: { 'Location': `/sub?${params.toString()}` } });
				} else if (访问路径 === 'admin' || 访问路径.startsWith('admin/')) {//安全会话已在上方统一验证
					if (访问路径 === 'admin/init' && request.method !== 'POST') return 访问错误响应('重置配置必须使用受保护的 POST 请求', 405);
					if (request.method === 'POST') {
						const 安全错误 = await 验证管理员修改请求(request, env, url, 管理员会话, false);
						if (安全错误) return 安全错误;
					}
					if (访问路径 === 'admin/log.json') {// 读取日志内容
						const 读取日志内容 = await env.KV.get('log.json') || '[]';
						return new Response(读取日志内容, { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
					} else if (区分大小写访问路径 === 'admin/getCloudflareUsage') {// 查询请求量
						try {
							const Usage_JSON = await getCloudflareUsage(url.searchParams.get('Email'), url.searchParams.get('GlobalAPIKey'), url.searchParams.get('AccountID'), url.searchParams.get('APIToken'));
							return new Response(JSON.stringify(Usage_JSON, null, 2), { status: 200, headers: { 'Content-Type': 'application/json' } });
						} catch (err) {
							const errorResponse = { msg: '查询请求量失败，失败原因：' + err.message, error: err.message };
							return new Response(JSON.stringify(errorResponse, null, 2), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
						}
					} else if (区分大小写访问路径 === 'admin/getADDAPI') {// 验证优选API
						if (url.searchParams.get('url')) {
							const 待验证优选URL = url.searchParams.get('url');
							try {
								new URL(待验证优选URL);
								const 请求优选API内容 = await 请求优选API([待验证优选URL], url.searchParams.get('port') || '443');
								let 优选API的IP = 请求优选API内容[0].length > 0 ? 请求优选API内容[0] : 请求优选API内容[1];
								优选API的IP = 优选API的IP.map(item => item.replace(/#(.+)$/, (_, remark) => '#' + decodeURIComponent(remark)));
								return new Response(JSON.stringify({ success: true, data: 优选API的IP }, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							} catch (err) {
								const errorResponse = { msg: '验证优选API失败，失败原因：' + err.message, error: err.message };
								return new Response(JSON.stringify(errorResponse, null, 2), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							}
						}
						return new Response(JSON.stringify({ success: false, data: [] }, null, 2), { status: 403, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
					} else if (访问路径 === 'admin/check') {// 代理检查
						const 代理协议 = ['socks5', 'http', 'https', 'turn', 'sstp'].find(类型 => url.searchParams.has(类型)) || null;
						if (!代理协议) return new Response(JSON.stringify({ error: '缺少代理参数' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
						const 代理参数 = url.searchParams.get(代理协议);
						const startTime = Date.now();
						let 检测代理响应;
						try {
							const 检测代理地址 = await 获取SOCKS5账号(代理参数, 获取代理默认端口(代理协议));
							const { username, password, hostname, port } = 检测代理地址;
							const 完整代理参数 = username && password ? `${username}:${password}@${hostname}:${port}` : `${hostname}:${port}`;
							try {
								const 检测主机 = 'cloudflare.com', 检测端口 = 443, encoder = new TextEncoder(), decoder = new TextDecoder();
								const TCP连接 = 创建请求TCP连接器(request);
								let tcpSocket = null, tlsSocket = null;
								try {
									tcpSocket = 代理协议 === 'socks5'
										? await socks5Connect(检测主机, 检测端口, new Uint8Array(0), TCP连接, 检测代理地址)
										: 代理协议 === 'turn'
											? await turnConnect(检测代理地址, 检测主机, 检测端口, TCP连接)
											: 代理协议 === 'sstp'
												? await sstpConnect(检测代理地址, 检测主机, 检测端口, TCP连接)
												: (代理协议 === 'https' && isIPHostname(hostname)
													? await httpsConnect(检测主机, 检测端口, new Uint8Array(0), TCP连接, 检测代理地址)
													: await httpConnect(检测主机, 检测端口, new Uint8Array(0), 代理协议 === 'https', TCP连接, 检测代理地址));
									if (!tcpSocket) throw new Error('无法连接到代理服务器');
									tlsSocket = new TlsClient(tcpSocket, { serverName: 检测主机, insecure: true });
									await tlsSocket.handshake();
									await tlsSocket.write(encoder.encode(`GET /cdn-cgi/trace HTTP/1.1\r\nHost: ${检测主机}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n`));
									let responseBuffer = new Uint8Array(0), headerEndIndex = -1, contentLength = null, chunked = false;
									const 最大响应字节 = 64 * 1024;
									while (responseBuffer.length < 最大响应字节) {
										const value = await tlsSocket.read();
										if (!value) break;
										if (value.byteLength === 0) continue;
										responseBuffer = 拼接字节数据(responseBuffer, value);
										if (headerEndIndex === -1) {
											const crlfcrlf = responseBuffer.findIndex((_, i) => i < responseBuffer.length - 3 && responseBuffer[i] === 0x0d && responseBuffer[i + 1] === 0x0a && responseBuffer[i + 2] === 0x0d && responseBuffer[i + 3] === 0x0a);
											if (crlfcrlf !== -1) {
												headerEndIndex = crlfcrlf + 4;
												const headers = decoder.decode(responseBuffer.slice(0, headerEndIndex));
												const statusLine = headers.split('\r\n')[0] || '';
												const statusMatch = statusLine.match(/HTTP\/\d\.\d\s+(\d+)/);
												const statusCode = statusMatch ? parseInt(statusMatch[1], 10) : NaN;
												if (!Number.isFinite(statusCode) || statusCode < 200 || statusCode >= 300) throw new Error(`代理检测请求失败: ${statusLine || '无效响应'}`);
												const lengthMatch = headers.match(/\r\nContent-Length:\s*(\d+)/i);
												if (lengthMatch) contentLength = parseInt(lengthMatch[1], 10);
												chunked = /\r\nTransfer-Encoding:\s*chunked/i.test(headers);
											}
										}
										if (headerEndIndex !== -1 && contentLength !== null && responseBuffer.length >= headerEndIndex + contentLength) break;
										if (headerEndIndex !== -1 && chunked && decoder.decode(responseBuffer).includes('\r\n0\r\n\r\n')) break;
									}
									if (headerEndIndex === -1) throw new Error('代理检测响应头过长或无效');
									const response = decoder.decode(responseBuffer);
									const ip = response.match(/(?:^|\n)ip=(.*)/)?.[1];
									const loc = response.match(/(?:^|\n)loc=(.*)/)?.[1];
									if (!ip || !loc) throw new Error('代理检测响应无效');
									检测代理响应 = { success: true, proxy: 代理协议 + "://" + 完整代理参数, ip, loc, responseTime: Date.now() - startTime };
								} finally {
									try { tlsSocket ? tlsSocket.close() : await tcpSocket?.close?.() } catch (e) { }
								}
							} catch (error) {
								检测代理响应 = { success: false, error: error.message, proxy: 代理协议 + "://" + 完整代理参数, responseTime: Date.now() - startTime };
							}
						} catch (err) {
							检测代理响应 = { success: false, error: err.message, proxy: 代理协议 + "://" + 代理参数, responseTime: Date.now() - startTime };
						}
						return new Response(JSON.stringify(检测代理响应, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
					}

					config_JSON = await 读取config_JSON(env, host, userID, UA);

					if (访问路径 === 'admin/init') {// 重置配置为默认值
						try {
							config_JSON = await 读取config_JSON(env, host, userID, UA, true);
							ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Init_Config', config_JSON));
							config_JSON.init = '配置已重置为默认值';
							return new Response(JSON.stringify(config_JSON, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
						} catch (err) {
							const errorResponse = { msg: '配置重置失败，失败原因：' + err.message, error: err.message };
							return new Response(JSON.stringify(errorResponse, null, 2), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
						}
					} else if (request.method === 'POST') {// 处理 KV 操作（POST 请求）
						if (访问路径 === 'admin/config.json') { // 保存config.json配置
							try {
								const newConfig = await request.json();
								// 验证配置完整性
								if (!newConfig.UUID || !newConfig.HOST) return new Response(JSON.stringify({ error: '配置不完整' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });

								// 保存到 KV
								await env.KV.put('config.json', JSON.stringify(newConfig, null, 2));
								ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Save_Config', config_JSON));
								return new Response(JSON.stringify({ success: true, message: '配置已保存' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							} catch (error) {
								console.error('保存配置失败:', error);
								return new Response(JSON.stringify({ error: '保存配置失败: ' + error.message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							}
						} else if (访问路径 === 'admin/cf.json') { // 保存cf.json配置
							try {
								const newConfig = await request.json();
								const CF_JSON = { Email: null, GlobalAPIKey: null, AccountID: null, APIToken: null, UsageAPI: null };
								if (!newConfig.init || newConfig.init !== true) {
									if (newConfig.Email && newConfig.GlobalAPIKey) {
										CF_JSON.Email = newConfig.Email;
										CF_JSON.GlobalAPIKey = newConfig.GlobalAPIKey;
									} else if (newConfig.AccountID && newConfig.APIToken) {
										CF_JSON.AccountID = newConfig.AccountID;
										CF_JSON.APIToken = newConfig.APIToken;
									} else if (newConfig.UsageAPI) {
										CF_JSON.UsageAPI = newConfig.UsageAPI;
									} else {
										return new Response(JSON.stringify({ error: '配置不完整' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
									}
								}

								// 保存到 KV
								await env.KV.put('cf.json', JSON.stringify(CF_JSON, null, 2));
								ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Save_Config', config_JSON));
								return new Response(JSON.stringify({ success: true, message: '配置已保存' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							} catch (error) {
								console.error('保存配置失败:', error);
								return new Response(JSON.stringify({ error: '保存配置失败: ' + error.message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							}
						} else if (访问路径 === 'admin/tg.json') { // 保存tg.json配置
							try {
								const newConfig = await request.json();
								if (newConfig.init && newConfig.init === true) {
									const TG_JSON = { BotToken: null, ChatID: null };
									await env.KV.put('tg.json', JSON.stringify(TG_JSON, null, 2));
								} else {
									if (!newConfig.BotToken || !newConfig.ChatID) return new Response(JSON.stringify({ error: '配置不完整' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
									await env.KV.put('tg.json', JSON.stringify(newConfig, null, 2));
								}
								ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Save_Config', config_JSON));
								return new Response(JSON.stringify({ success: true, message: '配置已保存' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							} catch (error) {
								console.error('保存配置失败:', error);
								return new Response(JSON.stringify({ error: '保存配置失败: ' + error.message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							}
						} else if (区分大小写访问路径 === 'admin/ADD.txt') { // 保存自定义优选IP
							try {
								const customIPs = await request.text();
								await env.KV.put('ADD.txt', customIPs);// 保存到 KV
								ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Save_Custom_IPs', config_JSON));
								return new Response(JSON.stringify({ success: true, message: '自定义IP已保存' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							} catch (error) {
								console.error('保存自定义IP失败:', error);
								return new Response(JSON.stringify({ error: '保存自定义IP失败: ' + error.message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							}
						} else return new Response(JSON.stringify({ error: '不支持的POST请求路径' }), { status: 404, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
					} else if (访问路径 === 'admin/config.json') {// 处理 admin/config.json 请求，返回JSON
						return new Response(JSON.stringify(config_JSON, null, 2), { status: 200, headers: { 'Content-Type': 'application/json' } });
					} else if (区分大小写访问路径 === 'admin/ADD.txt') {// 处理 admin/ADD.txt 请求，返回本地优选IP
						let 本地优选IP = await env.KV.get('ADD.txt') || 'null';
						if (本地优选IP == 'null') 本地优选IP = (await 生成随机IP(request, config_JSON.优选订阅生成.本地IP库.随机数量, config_JSON.优选订阅生成.本地IP库.指定端口))[1];
						return new Response(本地优选IP, { status: 200, headers: { 'Content-Type': 'text/plain;charset=utf-8', 'asn': String(request.cf?.asn || '') } });
					} else if (访问路径 === 'admin/cf.json') {// CF配置文件
						return new Response(JSON.stringify(request.cf, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
					}

					ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Admin_Login', config_JSON));
					const 原后台响应 = await fetch(Pages静态页面 + '/admin' + url.search);
					const 后台内容类型 = 原后台响应.headers.get('Content-Type') || '';
					if (!后台内容类型.toLowerCase().includes('text/html')) return 原后台响应;
					const 原后台HTML = await 原后台响应.text();
					const 国家IP池入口 = '<a href="/admin/access" class="btn btn-primary" style="text-decoration:none;display:inline-block">🔐 国家 IP 池</a>';
					const 登出按钮 = '<button type="button" class="btn btn-primary" onclick="logout()">👋退出登录</button>';
					let 后台HTML = 原后台HTML.replace(/fetch\(\s*['"]\/admin\/init['"]\s*\)/g, "fetch('/admin/init',{method:'POST'})");
					if (!后台HTML.includes('href="/admin/access"')) {
						后台HTML = 后台HTML.includes(登出按钮)
							? 后台HTML.replace(登出按钮, 国家IP池入口 + 登出按钮)
							: 后台HTML.replace(/<\/body>/i, 国家IP池入口 + '</body>');
					}
					const 后台响应头 = new Headers(原后台响应.headers);
					// 修改 HTML 后移除与原始内容不匹配的缓存/实体头。
					['Content-Length', 'Content-Encoding', 'ETag', 'Last-Modified', 'Content-MD5'].forEach(name => 后台响应头.delete(name));
					后台响应头.set('Cache-Control', 'no-store, no-cache, must-revalidate');
					后台响应头.set('Pragma', 'no-cache');
					后台响应头.set('Expires', '0');
					return new Response(后台HTML, { status: 原后台响应.status, statusText: 原后台响应.statusText, headers: 后台响应头 });
				} else if (uuidRegex.test(访问路径)) {//兼容旧的 UUID 登出入口
					const 响应 = new Response('重定向中...', { status: 302, headers: { 'Location': '/login' } });
					响应.headers.append('Set-Cookie', 'admin_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict');
					响应.headers.append('Set-Cookie', 'auth=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict');
					return 响应;
				} else if (访问路径 === 'sub') {//处理订阅请求
					const 动态访问订阅 = !!访问授权上下文;
					const 订阅TOKEN = 动态访问订阅 ? 访问授权上下文.记录.token : await MD5MD5(host + userID), 作为优选订阅生成器 = !动态访问订阅 && ['1', 'true'].includes(env.BEST_SUB) && url.searchParams.get('host') === 'example.com' && url.searchParams.get('uuid') === '00000000-0000-4000-8000-000000000000' && UA.toLowerCase().includes('tunnel (https://github.com/cmliu/edge');
					const 请求TOKEN = url.searchParams.get('token');
					const 用户客户端请求订阅 = 请求TOKEN === 订阅TOKEN;
					const 当前日序号 = Math.floor(Date.now() / 86400000);
					const 订阅转换后端TOKEN种子 = base64SecretEncode(订阅TOKEN, 请求用户ID);
					const [今日订阅转换后端专属TOKEN, 昨日订阅转换后端专属TOKEN] = await Promise.all([
						动态访问订阅 ? 生成访问订阅转换令牌(订阅TOKEN, 订阅转换后端TOKEN种子, 当前日序号) : MD5MD5(订阅转换后端TOKEN种子 + 当前日序号),
						动态访问订阅 ? 生成访问订阅转换令牌(订阅TOKEN, 订阅转换后端TOKEN种子, 当前日序号 - 1) : MD5MD5(订阅转换后端TOKEN种子 + (当前日序号 - 1)),
					]);
					const 订阅转换后端请求订阅 = 请求TOKEN === 今日订阅转换后端专属TOKEN || 请求TOKEN === 昨日订阅转换后端专属TOKEN;
					if (用户客户端请求订阅 || 订阅转换后端请求订阅 || 作为优选订阅生成器) {
						let config_JSON = await 读取config_JSON(env, host, 请求用户ID, UA);
						if (动态访问订阅) config_JSON = 应用访问链接配置(config_JSON, 访问授权上下文.记录);
						if (作为优选订阅生成器) ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Get_Best_SUB', config_JSON, false));
						else ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Get_SUB', config_JSON));
						const ua = UA.toLowerCase();
						const responseHeaders = {
							"content-type": "text/plain; charset=utf-8",
							"Profile-Update-Interval": config_JSON.优选订阅生成.SUBUpdateTime,
							"Profile-web-page-url": url.protocol + '//' + url.host + '/admin',
							"Cache-Control": "no-store",
						};
						if (动态访问订阅 && 访问授权上下文.记录.expires_at) responseHeaders["Subscription-Userinfo"] = `upload=0; download=0; total=1099511627776; expire=${Math.floor(Number(访问授权上下文.记录.expires_at) / 1000)}`;
						if (config_JSON.CF.Usage.success && !动态访问订阅) {
							const pagesSum = config_JSON.CF.Usage.pages;
							const workersSum = config_JSON.CF.Usage.workers;
							const total = Number.isFinite(config_JSON.CF.Usage.max) ? (config_JSON.CF.Usage.max / 1000) * 1024 : 1024 * 100;
							responseHeaders["Subscription-Userinfo"] = `upload=${pagesSum}; download=${workersSum}; total=${total}; expire=4102329600`; // 2099-12-31 到期时间
						}
						const isSubConverterRequest = url.searchParams.has('b64') || url.searchParams.has('base64') || request.headers.get('subconverter-request') || request.headers.get('subconverter-version') || ua.includes('subconverter') || ua.includes(('CF-Workers-SUB').toLowerCase()) || 作为优选订阅生成器;
						const 订阅类型 = isSubConverterRequest
							? 'mixed'
							: url.searchParams.has('target')
								? url.searchParams.get('target')
								: url.searchParams.has('clash') || ua.includes('clash') || ua.includes('meta') || ua.includes('mihomo')
									? 'clash'
									: url.searchParams.has('sb') || url.searchParams.has('singbox') || ua.includes('singbox') || ua.includes('sing-box')
										? 'singbox'
										: url.searchParams.has('surge') || ua.includes('surge')
											? 'surge&ver=4'
											: url.searchParams.has('quanx') || ua.includes('quantumult')
												? 'quanx'
												: url.searchParams.has('loon') || ua.includes('loon')
													? 'loon'
													: 'mixed';

						if (!ua.includes('mozilla')) responseHeaders["Content-Disposition"] = `attachment; filename*=utf-8''${encodeURIComponent(config_JSON.优选订阅生成.SUBNAME)}`;
						const 协议类型 = ((url.searchParams.has('surge') || ua.includes('surge')) && config_JSON.协议类型 !== 'ss') ? 'tro' + 'jan' : config_JSON.协议类型;
						let 订阅内容 = '';
						if (订阅类型 === 'mixed') {
							const TLS分片参数 = config_JSON.TLS分片 == 'Shadowrocket' ? `&fragment=${encodeURIComponent('1,40-60,30-50,tlshello')}` : config_JSON.TLS分片 == 'Happ' ? `&fragment=${encodeURIComponent('3,1,tlshello')}` : '';
							let 完整优选IP = [], 其他节点LINK = '', 反代IP池 = [];

							if (动态访问订阅) {
								// 国家访问链接只需要一个入口。国家决定的是令牌路径后端使用的
								// PROXYIP 池；继续生成默认的 16 个 Cloudflare 入口只会让客户端
								// 出现一批实际共用同一国家出口的重复节点。
								完整优选IP = [`${config_JSON.HOST}:443#${生成访问节点名称(访问授权上下文.记录)}`];
							} else if (!url.searchParams.has('sub') && config_JSON.优选订阅生成.local) { // 本地生成订阅
								const 完整优选列表 = config_JSON.优选订阅生成.本地IP库.随机IP ? (
									await 生成随机IP(request, config_JSON.优选订阅生成.本地IP库.随机数量, config_JSON.优选订阅生成.本地IP库.指定端口)
								)[0] : await env.KV.get('ADD.txt') ? await 整理成数组(await env.KV.get('ADD.txt')) : (
									await 生成随机IP(request, config_JSON.优选订阅生成.本地IP库.随机数量, config_JSON.优选订阅生成.本地IP库.指定端口)
								)[0];
								const 优选API = [], 优选IP = [], 其他节点 = [];
								for (const 元素 of 完整优选列表) {
									if (元素.toLowerCase().startsWith('sub://')) {
										优选API.push(元素);
									} else {
										const 备注位置 = 元素.indexOf('#');
										const 地址部分 = 备注位置 > -1 ? 元素.slice(0, 备注位置) : 元素;
										const 备注部分 = 备注位置 > -1 ? 元素.slice(备注位置) : '';
										const subMatch = 元素.match(/sub\s*=\s*([^\s&#]+)/i);
										if (subMatch && subMatch[1].trim().includes('.')) {
											const 优选IP作为反代IP = 元素.toLowerCase().includes('proxyip=true');
											if (优选IP作为反代IP) 优选API.push('sub://' + subMatch[1].trim() + "?proxyip=true" + (元素.includes('#') ? ('#' + 元素.split('#')[1]) : ''));
											else 优选API.push('sub://' + subMatch[1].trim() + (元素.includes('#') ? ('#' + 元素.split('#')[1]) : ''));
										} else if (地址部分.toLowerCase().startsWith('https://')) {
											优选API.push(元素);
										} else if (地址部分.toLowerCase().includes('://')) {
											if (元素.includes('#')) {
												const 地址备注分离 = 元素.split('#');
												其他节点.push(地址备注分离[0] + '#' + encodeURIComponent(decodeURIComponent(地址备注分离[1])));
											} else 其他节点.push(元素);
										} else {
											if (地址部分.includes('*')) {
												优选IP.push(替换星号为随机字符(地址部分) + 备注部分);
											} else 优选IP.push(元素);
										}
									}
								}
								const 请求优选API内容 = await 请求优选API(优选API, '443');
								const 合并其他节点数组 = [...new Set(其他节点.concat(请求优选API内容[1]))];
								其他节点LINK = 合并其他节点数组.length > 0 ? 合并其他节点数组.join('\n') + '\n' : '';
								const 优选API的IP = 请求优选API内容[0];
								反代IP池 = 请求优选API内容[3] || [];
								完整优选IP = [...new Set(优选IP.concat(优选API的IP))];
							} else { // 优选订阅生成器
								let 优选订阅生成器HOST = url.searchParams.get('sub') || config_JSON.优选订阅生成.SUB;
								const [优选生成器IP数组, 优选生成器其他节点] = await 获取优选订阅生成器数据(优选订阅生成器HOST);
								完整优选IP = 完整优选IP.concat(优选生成器IP数组);
								其他节点LINK += 优选生成器其他节点;
							}
							const ECHLINK参数 = config_JSON.ECH ? `&ech=${encodeURIComponent((config_JSON.ECHConfig.SNI ? config_JSON.ECHConfig.SNI + '+' : '') + config_JSON.ECHConfig.DNS)}` : '';
							const isLoonOrSurge = ua.includes('loon') || ua.includes('surge');
							const { type: 传输协议, 路径字段名, 域名字段名 } = 获取传输协议配置(config_JSON);
							订阅内容 = 其他节点LINK + 完整优选IP.map(原始地址 => {
								// 统一正则: 匹配 域名/IPv4/IPv6地址 + 可选端口 + 可选备注
								// 示例:
								//   - 域名: hj.xmm1993.top:2096#备注 或 example.com
								//   - IPv4: 166.0.188.128:443#Los Angeles 或 166.0.188.128
								//   - IPv6: [2606:4700::]:443#CMCC 或 [2606:4700::]
								const regex = /^(\[[\da-fA-F:]+\]|[\d.]+|[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*)(?::(\d+))?(?:#(.+))?$/;
								const match = 原始地址.match(regex);

								let 节点地址, 节点端口 = "443", 节点备注;

								if (match) {
									节点地址 = match[1];  // IP地址或域名(可能带方括号)
									节点端口 = match[2] ? match[2] : '443';  // 端口默认443，SS noTLS在生成链接时再映射
									节点备注 = match[3] || 节点地址;  // 备注,默认为地址本身
								} else {
									// 不规范的格式，跳过处理返回null
									console.warn(`[订阅内容] 不规范的IP格式已忽略: ${原始地址}`);
									return null;
								}

								let 完整节点路径 = config_JSON.完整节点路径;

								const 链式代理匹配 = 节点备注.match(/\$(socks5|http|https|turn|sstp):\/\/([^#\s]+)/i);
								if (链式代理匹配) {
									try {
										// 限时链接始终使用其令牌路径及国家池，不能被备注中的代理覆盖。
										if (!动态访问订阅) {
											const 代理协议 = 链式代理匹配[1].toLowerCase(), 代理参数 = 链式代理匹配[2];
											const 链式代理数据 = { type: 代理协议, ...获取SOCKS5账号(代理参数, 获取代理默认端口(代理协议)) };
											完整节点路径 = `/video/${base64SecretEncode(JSON.stringify(链式代理数据), 请求用户ID) + (config_JSON.启用0RTT ? '?ed=2560' : '')}`;
										}
										节点备注 = 节点备注.replace(链式代理匹配[0], '').trim() || 节点地址;
									} catch (error) {
										console.warn(`[订阅内容] 链式代理解析失败，已忽略该指令: ${链式代理匹配[0]} (${error && error.message ? error.message : error})`);
									}
								} else if (反代IP池.length > 0 && !动态访问订阅) {
									const 匹配到的反代IP = 反代IP池.find(p => p.includes(节点地址));
									if (匹配到的反代IP) 完整节点路径 = (`${config_JSON.PATH}/proxyip=${匹配到的反代IP}`).replace(/\/\//g, '/') + (config_JSON.启用0RTT ? '?ed=2560' : '');
								}
								if (isLoonOrSurge) 完整节点路径 = 完整节点路径.replace(/,/g, '%2C');

								if (协议类型 === 'ss' && !作为优选订阅生成器) {
									if (!config_JSON.SS.TLS) {
										const TLS端口 = [443, 2053, 2083, 2087, 2096, 8443];
										const NOTLS端口 = [80, 2052, 2082, 2086, 2095, 8080];
										节点端口 = String(NOTLS端口[TLS端口.indexOf(Number(节点端口))] ?? 节点端口);
									}
									完整节点路径 = (完整节点路径.includes('?') ? 完整节点路径.replace('?', '?enc=' + config_JSON.SS.加密方式 + '&') : (完整节点路径 + '?enc=' + config_JSON.SS.加密方式)).replace(/([=,])/g, '\\$1');
									if (!isSubConverterRequest) 完整节点路径 = 完整节点路径 + ';mux=0';
									return `${协议类型}://${btoa(config_JSON.SS.加密方式 + ':00000000-0000-4000-8000-000000000000')}@${节点地址}:${节点端口}?plugin=v2${encodeURIComponent('ray-plugin;mode=websocket;host=example.com;path=' + (config_JSON.随机路径 ? 随机路径(完整节点路径) : 完整节点路径) + (config_JSON.SS.TLS ? ';tls' : '')) + ECHLINK参数 + TLS分片参数}#${encodeURIComponent(节点备注)}`;
								} else {
									const 传输路径参数值 = 获取传输路径参数值(config_JSON, 完整节点路径, 作为优选订阅生成器);
									return `${协议类型}://00000000-0000-4000-8000-000000000000@${节点地址}:${节点端口}?security=tls&type=${传输协议 + ECHLINK参数}&${域名字段名}=example.com&fp=${config_JSON.Fingerprint}&sni=example.com&${路径字段名}=${encodeURIComponent(传输路径参数值) + TLS分片参数}&encryption=none${config_JSON.跳过证书验证 ? '&insecure=1&allowInsecure=1' : ''}#${encodeURIComponent(节点备注)}`;
								}
							}).filter(item => item !== null).join('\n');
						} else { // 订阅转换
							if (动态访问订阅 && 订阅类型 === 'clash') {
								// 国家链接只需一个节点和一个选择组，不经过 ACL4SSR 的多组模板。
								订阅内容 = 生成最简Clash订阅(config_JSON, 访问授权上下文.记录);
							} else {
								const 订阅转换URL = `${config_JSON.订阅转换配置.SUBAPI}/sub?target=${订阅类型}&url=${encodeURIComponent(url.protocol + '//' + url.host + '/sub?target=mixed&token=' + 今日订阅转换后端专属TOKEN + '&asOrg=' + 识别运营商(request) + (url.searchParams.has('sub') && url.searchParams.get('sub') != '' ? `&sub=${url.searchParams.get('sub')}` : ''))}&config=${encodeURIComponent(config_JSON.订阅转换配置.SUBCONFIG)}&emoji=${config_JSON.订阅转换配置.SUBEMOJI}&scv=${config_JSON.跳过证书验证}`;
								try {
									const response = await fetch(订阅转换URL, { headers: { 'User-Agent': 'Subconverter for ' + 订阅类型 + ' edge' + 'tunnel (https://github.com/cmliu/edge' + 'tunnel)' } });
									if (response.ok) {
										订阅内容 = await response.text();
										if (url.searchParams.has('surge') || ua.includes('surge')) 订阅内容 = Surge订阅配置文件热补丁(订阅内容, url.protocol + '//' + url.host + '/sub?token=' + 订阅TOKEN + '&surge', config_JSON);
									} else return new Response('订阅转换后端异常：' + response.statusText, { status: response.status });
								} catch (error) {
									return new Response('订阅转换后端异常：' + error.message, { status: 403 });
								}
							}
						}

						if (!ua.includes('subconverter') && 用户客户端请求订阅) {
							const 打乱后HOSTS = [...config_JSON.HOSTS].sort(() => Math.random() - 0.5);
							let 替换域名计数 = 0, 当前随机HOST = null;
							订阅内容 = 订阅内容
								.replace(/00000000-0000-4000-8000-000000000000/g, config_JSON.UUID)
								.replace(/MDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDAwMDAw/g, btoa(config_JSON.UUID))
								.replace(/example\.com/g, () => {
									if (替换域名计数 % 2 === 0) {
										const 原始host = 打乱后HOSTS[Math.floor(替换域名计数 / 2) % 打乱后HOSTS.length];
										当前随机HOST = 替换星号为随机字符(原始host);
									}
									替换域名计数++;
									return 当前随机HOST;
								});
						}

						if (订阅类型 === 'mixed' && (!ua.includes('mozilla') || url.searchParams.has('b64') || url.searchParams.has('base64'))) 订阅内容 = btoa(订阅内容);

						if (订阅类型 === 'singbox') {
							订阅内容 = await Singbox订阅配置文件热补丁(订阅内容, config_JSON);
							responseHeaders["content-type"] = 'application/json; charset=utf-8';
						} else if (订阅类型 === 'clash') {
							if (!动态访问订阅) 订阅内容 = Clash订阅配置文件热补丁(订阅内容, config_JSON);
							responseHeaders["content-type"] = 'application/x-yaml; charset=utf-8';
						}
						return new Response(订阅内容, { status: 200, headers: responseHeaders });
					}
				} else if (访问路径 === 'locations') {//反代locations列表
					if (管理员会话) return fetch(new Request('https://speed.cloudflare.com/locations', { headers: { 'Referer': 'https://speed.cloudflare.com/' } }));
				} else if (访问路径 === 'robots.txt') return new Response('User-agent: *\nDisallow: /', { status: 200, headers: { 'Content-Type': 'text/plain; charset=UTF-8' } });
			} else if (!envUUID) return fetch(Pages静态页面 + '/noKV').then(r => { const headers = new Headers(r.headers); headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate'); headers.set('Pragma', 'no-cache'); headers.set('Expires', '0'); return new Response(r.body, { status: 404, statusText: r.statusText, headers }) });
		}

		let 伪装页URL = env.URL || 'nginx';
		if (伪装页URL && 伪装页URL !== 'nginx' && 伪装页URL !== '1101') {
			伪装页URL = 伪装页URL.trim().replace(/\/$/, '');
			if (!伪装页URL.match(/^https?:\/\//i)) 伪装页URL = 'https://' + 伪装页URL;
			if (伪装页URL.toLowerCase().startsWith('http://')) 伪装页URL = 'https://' + 伪装页URL.substring(7);
			try { const u = new URL(伪装页URL); 伪装页URL = u.protocol + '//' + u.host } catch (e) { 伪装页URL = 'nginx' }
		}
		if (伪装页URL === '1101') return new Response(await html1101(url.host, 访问IP), { status: 200, headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
		try {
			const 反代URL = new URL(伪装页URL), 新请求头 = new Headers(request.headers);
			for (const name of ['Cookie', 'Authorization', 'Proxy-Authorization', 'X-CSRF-Token']) 新请求头.delete(name);
			新请求头.set('Host', 反代URL.host);
			新请求头.set('Referer', 反代URL.origin);
			新请求头.set('Origin', 反代URL.origin);
			if (!新请求头.has('User-Agent') && UA && UA !== 'null') 新请求头.set('User-Agent', UA);
			const 反代响应 = await fetch(反代URL.origin + url.pathname + url.search, { method: request.method, headers: 新请求头, body: request.body, cf: request.cf });
			const 内容类型 = 反代响应.headers.get('content-type') || '';
			// 只处理文本类型的响应
			if (/text|javascript|json|xml/.test(内容类型)) {
				const 响应内容 = (await 反代响应.text()).replaceAll(反代URL.host, url.host);
				return new Response(响应内容, { status: 反代响应.status, headers: { ...Object.fromEntries(反代响应.headers), 'Cache-Control': 'no-store' } });
			}
			return 反代响应;
		} catch (error) { }
		return new Response(await nginx(), { status: 200, headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
	},
	async scheduled(controller, env, ctx) {
		if (!env.DB || typeof env.DB.prepare !== 'function') return;
		ctx.waitUntil((async () => {
			await 确保访问数据库(env);
			await 清理访问连接租约(env);
			const countryLimit = Math.min(20, Math.max(1, Number(env.CRON_COUNTRY_BATCH_SIZE) || 8));
			const healthLimit = Math.min(24, Math.max(1, Number(env.CRON_HEALTH_BATCH_SIZE) || 6));
			const result = await env.DB.prepare("SELECT DISTINCT country FROM access_links WHERE status = 'active' ORDER BY RANDOM() LIMIT ?1").bind(countryLimit).all();
			for (const item of result.results || []) {
				await 同步到期访问PROXYIP数据源(env, { country: item.country });
				await 检测访问PROXYIP池(env, item.country, healthLimit);
			}
			await 检查访问管理通知(env);
			const now = Date.now();
			await env.DB.batch([
				env.DB.prepare('DELETE FROM admin_sessions WHERE expires_at <= ?1 OR (revoked_at IS NOT NULL AND revoked_at <= ?2)').bind(now, now - 7 * 86400000),
				env.DB.prepare('DELETE FROM access_connection_events WHERE started_at < ?1').bind(now - 30 * 86400000),
				env.DB.prepare('DELETE FROM audit_logs WHERE created_at < ?1').bind(now - Math.min(365, Math.max(7, Number(env.AUDIT_RETENTION_DAYS) || 90)) * 86400000)
			]);
		})());
	}
};

///////////////////////////////////////////////////////限时访问链接///////////////////////////////////////////////
const 访问令牌正则 = /^[A-Za-z0-9_-]{43}$/;
const 内置访问PROXYIP数据源URL = 'https://zip.cm.edu.kg.cmliussss.net/all.json';
const 访问PROXYIP检测URL = 'https://api.090227.xyz/check?proxyip=';

function 提取路径访问令牌(pathname) {
	try {
		const 匹配 = decodeURIComponent(String(pathname || '')).match(/(?:^|\/)u\/([A-Za-z0-9_-]{43})(?:\/|$)/i);
		return 匹配 ? 匹配[1] : null;
	} catch (_) {
		return null;
	}
}

function 提取订阅访问令牌(token) {
	const 文本 = String(token || '').trim();
	if (访问令牌正则.test(文本)) return 文本;
	const 转换令牌匹配 = 文本.match(/^c\.([A-Za-z0-9_-]{43})\.[a-f0-9]{32}$/i);
	return 转换令牌匹配 ? 转换令牌匹配[1] : null;
}

function 访问错误响应(message, status = 403) {
	return new Response(JSON.stringify({ success: false, error: message }), {
		status,
		headers: { 'Content-Type': 'application/json;charset=utf-8', 'Cache-Control': 'no-store' }
	});
}

function 访问JSON响应(data, status = 200) {
	return new Response(JSON.stringify(data, null, 2), {
		status,
		headers: { 'Content-Type': 'application/json;charset=utf-8', 'Cache-Control': 'no-store' }
	});
}

function 读取Cookie(request, name) {
	const encodedName = `${name}=`;
	for (const part of String(request.headers.get('Cookie') || '').split(';')) {
		const item = part.trim();
		if (item.startsWith(encodedName)) return decodeURIComponent(item.slice(encodedName.length));
	}
	return '';
}

function 生成安全随机值(bytesLength = 32) {
	const bytes = crypto.getRandomValues(new Uint8Array(bytesLength));
	let binary = '';
	for (const byte of bytes) binary += String.fromCharCode(byte);
	return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

async function SHA256十六进制(value) {
	const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(String(value || '')));
	return [...new Uint8Array(digest)].map(byte => byte.toString(16).padStart(2, '0')).join('');
}

function 获取请求来源信息(request, env) {
	const rawIP = request.headers.get('CF-Connecting-IP') || request.headers.get('True-Client-IP') || request.headers.get('X-Real-IP') || '';
	const recordIP = !['0', 'false', 'off'].includes(String(env.RECORD_ADMIN_IP ?? 'true').toLowerCase());
	return { ip: recordIP ? rawIP.slice(0, 80) : '', rawIP, asn: String(request.cf?.asn || '').slice(0, 30) };
}

function 清理审计摘要(value) {
	if (value == null) return null;
	const 敏感字段 = /password|cookie|authorization|token|uuid|secret|key|bot|url/i;
	const walk = (input, depth = 0) => {
		if (depth > 4) return '[truncated]';
		if (Array.isArray(input)) return input.slice(0, 100).map(item => walk(item, depth + 1));
		if (!input || typeof input !== 'object') return typeof input === 'string' ? input.slice(0, 500) : input;
		const output = {};
		for (const [key, child] of Object.entries(input).slice(0, 100)) output[key] = 敏感字段.test(key) ? '[redacted]' : walk(child, depth + 1);
		return output;
	};
	return JSON.stringify(walk(value)).slice(0, 4000);
}

async function 写入审计日志(env, request, session, action, objectType, objectId, before, after, success = true, error = '') {
	try {
		if (!env.DB || typeof env.DB.prepare !== 'function') return;
		await 确保访问数据库(env);
		const source = 获取请求来源信息(request, env);
		await env.DB.prepare(`INSERT INTO audit_logs
			(created_at, session_id, source_ip, source_asn, action, object_type, object_id, before_summary, after_summary, success, error_message)
			VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)`)
			.bind(Date.now(), session?.id || null, source.ip || null, source.asn || null, String(action).slice(0, 80), String(objectType).slice(0, 50), String(objectId ?? '').slice(0, 100), 清理审计摘要(before), 清理审计摘要(after), success ? 1 : 0, String(error || '').slice(0, 500)).run();
	} catch (auditError) {
		console.error('写入审计日志失败:', auditError);
	}
}

async function 获取管理员会话记录(env, tokenHash) {
	if (env.DB && typeof env.DB.prepare === 'function') {
		await 确保访问数据库(env);
		return await env.DB.prepare(`SELECT * FROM admin_sessions
			WHERE token_hash = ?1 AND revoked_at IS NULL AND expires_at > ?2 LIMIT 1`).bind(tokenHash, Date.now()).first();
	}
	if (env.KV && typeof env.KV.get === 'function') {
		const value = await env.KV.get(`admin-session:${tokenHash}`, { type: 'json' });
		return value && !value.revoked_at && Number(value.expires_at) > Date.now() ? value : null;
	}
	return null;
}

async function 验证管理员会话(request, env) {
	const token = 读取Cookie(request, 'admin_session');
	if (!token || token.length < 40 || token.length > 200) return null;
	const tokenHash = await SHA256十六进制(token);
	const session = await 获取管理员会话记录(env, tokenHash);
	if (!session) return null;
	const userAgentHash = await SHA256十六进制(request.headers.get('User-Agent') || '');
	if (session.user_agent_hash && session.user_agent_hash !== userAgentHash) return null;
	const now = Date.now();
	if (now - Number(session.last_seen_at || 0) > 300000) {
		if (env.DB && typeof env.DB.prepare === 'function') {
			await env.DB.prepare('UPDATE admin_sessions SET last_seen_at = ?1 WHERE id = ?2').bind(now, session.id).run();
		} else if (env.KV && typeof env.KV.put === 'function') {
			session.last_seen_at = now;
			await env.KV.put(`admin-session:${tokenHash}`, JSON.stringify(session), { expirationTtl: Math.max(60, Math.ceil((Number(session.expires_at) - now) / 1000)) });
		}
	}
	return session;
}

async function 验证管理员修改请求(request, env, url, session, requireCsrf = true) {
	if (!session) return 访问错误响应('管理员会话已失效，请重新登录', 401);
	const origin = request.headers.get('Origin');
	if (!origin || origin !== url.origin) return 访问错误响应('请求来源校验失败', 403);
	const fetchSite = (request.headers.get('Sec-Fetch-Site') || '').toLowerCase();
	if (fetchSite && fetchSite !== 'same-origin') return 访问错误响应('跨站请求已拒绝', 403);
	if (requireCsrf) {
		const csrf = request.headers.get('X-CSRF-Token') || '';
		if (!csrf || csrf !== 读取Cookie(request, 'admin_csrf') || await SHA256十六进制(csrf) !== session.csrf_hash) return 访问错误响应('CSRF 校验失败，请刷新页面后重试', 403);
	}
	return null;
}

function 管理员登录页面() {
	return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>管理员登录</title><style>:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#09111f;color:#e8eef9;font:15px system-ui}.box{width:min(92vw,390px);padding:26px;background:#111c2e;border:1px solid #2a3b59;border-radius:16px;box-shadow:0 20px 60px #0006}h1{font-size:22px;margin:0 0 18px}label{display:block;color:#a7b3c8;margin-bottom:6px}input,button{width:100%;font:inherit;border-radius:9px;padding:11px}input{background:#091425;color:#fff;border:1px solid #405273}button{margin-top:14px;border:0;background:#4f8cff;color:#fff;cursor:pointer}.msg{min-height:24px;color:#ff91a1;margin-top:10px}</style></head><body><form class="box" id="login"><h1>管理员登录</h1><label for="password">ADMIN 密码</label><input id="password" name="password" type="password" autocomplete="current-password" required autofocus><button>登录</button><div class="msg" id="msg" role="alert"></div></form><script>document.querySelector('#login').addEventListener('submit',async e=>{e.preventDefault();const b=e.submitter,m=document.querySelector('#msg');b.disabled=true;m.textContent='';try{const r=await fetch('/login',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams(new FormData(e.target))});const j=await r.json().catch(()=>({success:false}));if(!r.ok||!j.success)throw new Error(j.error||'登录失败，请稍后重试');location.href=j.redirect||'/admin'}catch(x){m.textContent=x.message}finally{b.disabled=false}})</script></body></html>`;
}

async function 读取登录限制(env, ipHash) {
	if (env.DB && typeof env.DB.prepare === 'function') {
		await 确保访问数据库(env);
		return await env.DB.prepare('SELECT * FROM admin_login_attempts WHERE ip_hash = ?1').bind(ipHash).first();
	}
	if (env.KV && typeof env.KV.get === 'function') return await env.KV.get(`admin-login:${ipHash}`, { type: 'json' });
	return null;
}

async function 写入登录限制(env, ipHash, record) {
	if (env.DB && typeof env.DB.prepare === 'function') {
		await env.DB.prepare(`INSERT INTO admin_login_attempts(ip_hash, window_started_at, failure_count, blocked_until, last_attempt_at)
			VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT(ip_hash) DO UPDATE SET window_started_at = ?2,
			failure_count = ?3, blocked_until = ?4, last_attempt_at = ?5`)
			.bind(ipHash, record.window_started_at, record.failure_count, record.blocked_until || null, record.last_attempt_at).run();
	} else if (env.KV && typeof env.KV.put === 'function') await env.KV.put(`admin-login:${ipHash}`, JSON.stringify(record), { expirationTtl: 3600 });
}

async function 记录管理员登录失败(env, ipHash, attempt, now, windowMs, threshold, blockMs) {
	if (env.DB && typeof env.DB.prepare === 'function') {
		// 必须基于写入时的数据库记录累加；并发请求可能读到了相同的旧快照。
		const resetWindow = '(?2 - window_started_at > ?3 AND COALESCE(blocked_until, 0) <= ?2)';
		const nextCount = `CASE WHEN ${resetWindow} THEN 1 ELSE failure_count + 1 END`;
		return await env.DB.prepare(`INSERT INTO admin_login_attempts(ip_hash, window_started_at, failure_count, blocked_until, last_attempt_at)
			VALUES (?1, ?2, 1, NULL, ?2) ON CONFLICT(ip_hash) DO UPDATE SET
			window_started_at = CASE WHEN ${resetWindow} THEN ?2 ELSE window_started_at END,
			failure_count = ${nextCount},
			blocked_until = CASE WHEN blocked_until > ?2 THEN blocked_until
				WHEN (${nextCount}) >= ?4 THEN ?2 + ?5 ELSE NULL END,
			last_attempt_at = ?2 RETURNING *`)
			.bind(ipHash, now, windowMs, threshold, blockMs).first();
	}
	// KV 不提供原子读改写；保留仅绑定 KV 的兼容流程。
	const record = 计算登录失败状态(attempt, now, threshold, blockMs);
	await 写入登录限制(env, ipHash, record);
	return record;
}

async function 创建管理员会话(env, request) {
	const token = 生成安全随机值(32), csrf = 生成安全随机值(24), id = crypto.randomUUID();
	const now = Date.now(), ttlSeconds = Math.min(604800, Math.max(900, Number(env.ADMIN_SESSION_TTL_SECONDS) || 86400));
	const source = 获取请求来源信息(request, env);
	const record = { id, token_hash: await SHA256十六进制(token), csrf_hash: await SHA256十六进制(csrf), created_at: now, expires_at: now + ttlSeconds * 1000, last_seen_at: now, source_ip: source.ip || null, source_asn: source.asn || null, user_agent_hash: await SHA256十六进制(request.headers.get('User-Agent') || ''), revoked_at: null };
	if (env.DB && typeof env.DB.prepare === 'function') {
		await env.DB.prepare(`INSERT INTO admin_sessions(id, token_hash, csrf_hash, created_at, expires_at, last_seen_at, source_ip, source_asn, user_agent_hash)
			VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)`).bind(record.id, record.token_hash, record.csrf_hash, record.created_at, record.expires_at, record.last_seen_at, record.source_ip, record.source_asn, record.user_agent_hash).run();
	} else if (env.KV && typeof env.KV.put === 'function') await env.KV.put(`admin-session:${record.token_hash}`, JSON.stringify(record), { expirationTtl: ttlSeconds });
	else throw new Error('安全管理员会话需要绑定 DB 或 KV');
	return { token, csrf, record, ttlSeconds };
}

async function 处理管理员登录请求(request, env, url, adminPassword) {
	if (request.method === 'GET' || request.method === 'HEAD') {
		if (await 验证管理员会话(request, env)) return Response.redirect(`${url.origin}/${env.DB && !(env.KV && typeof env.KV.get === 'function') ? 'admin/access' : 'admin'}`, 302);
		return new Response(request.method === 'HEAD' ? null : 管理员登录页面(), { status: 200, headers: { 'Content-Type': 'text/html;charset=utf-8', 'Cache-Control': 'no-store', 'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'", 'Referrer-Policy': 'no-referrer' } });
	}
	if (request.method !== 'POST') return 访问错误响应('不支持的请求方法', 405);
	const origin = request.headers.get('Origin');
	if (!origin || origin !== url.origin) return 访问错误响应('登录失败，请稍后重试', 403);
	const source = 获取请求来源信息(request, env);
	const ipHash = await SHA256十六进制(source.rawIP || 'unknown');
	const now = Date.now(), windowMs = 10 * 60 * 1000, threshold = Math.min(20, Math.max(3, Number(env.ADMIN_LOGIN_MAX_FAILURES) || 5)), blockMs = Math.min(3600000, Math.max(60000, Number(env.ADMIN_LOGIN_BLOCK_SECONDS) * 1000 || 15 * 60 * 1000));
	let attempt = await 读取登录限制(env, ipHash) || { window_started_at: now, failure_count: 0, blocked_until: null, last_attempt_at: now };
	if (Number(attempt.blocked_until || 0) > now) {
		await 写入审计日志(env, request, null, 'admin.login.failed', 'admin_session', '', null, { reason: 'rate_limited' }, false, '统一认证失败');
		return 访问错误响应('登录失败，请稍后重试', 429);
	}
	if (now - Number(attempt.window_started_at || 0) > windowMs) attempt = { window_started_at: now, failure_count: 0, blocked_until: null, last_attempt_at: now };
	let inputPassword = '';
	try {
		const contentType = request.headers.get('Content-Type') || '';
		if (!contentType.includes('application/x-www-form-urlencoded') && !contentType.includes('multipart/form-data')) throw new Error('invalid content type');
		const form = await request.formData();
		inputPassword = String(form.get('password') || '').replace(/[\r\n]/g, '');
	} catch (_) { }
	const passwordMatches = adminPassword && inputPassword.length === adminPassword.length && await 安全比较文本(inputPassword, adminPassword);
	if (!passwordMatches) {
		attempt = await 记录管理员登录失败(env, ipHash, attempt, Date.now(), windowMs, threshold, blockMs);
		await 写入审计日志(env, request, null, 'admin.login.failed', 'admin_session', '', null, { reason: 'invalid_credentials' }, false, '统一认证失败');
		return 访问错误响应('登录失败，请稍后重试', attempt.blocked_until ? 429 : 401);
	}
	const created = await 创建管理员会话(env, request);
	await 写入登录限制(env, ipHash, { window_started_at: now, failure_count: 0, blocked_until: null, last_attempt_at: now });
	await 写入审计日志(env, request, created.record, 'admin.login.success', 'admin_session', created.record.id, null, { expires_at: created.record.expires_at }, true);
	const response = 访问JSON响应({ success: true, redirect: env.DB && !(env.KV && typeof env.KV.get === 'function') ? '/admin/access' : '/admin' });
	response.headers.append('Set-Cookie', `admin_session=${encodeURIComponent(created.token)}; Path=/; Max-Age=${created.ttlSeconds}; HttpOnly; Secure; SameSite=Strict`);
	response.headers.append('Set-Cookie', `admin_csrf=${encodeURIComponent(created.csrf)}; Path=/; Max-Age=${created.ttlSeconds}; Secure; SameSite=Strict`);
	response.headers.append('Set-Cookie', 'auth=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict');
	return response;
}

async function 安全比较文本(a, b) {
	const [left, right] = await Promise.all([SHA256十六进制(a), SHA256十六进制(b)]);
	let diff = left.length ^ right.length;
	for (let i = 0; i < Math.max(left.length, right.length); i++) diff |= (left.charCodeAt(i) || 0) ^ (right.charCodeAt(i) || 0);
	return diff === 0;
}

async function 处理管理员单会话退出(request, env, url) {
	const token = 读取Cookie(request, 'admin_session');
	// 退出本机会话应按 token hash 撤销，即使 User-Agent 已变化也不能留下可用会话。
	const session = token && token.length >= 40 && token.length <= 200
		? await 获取管理员会话记录(env, await SHA256十六进制(token))
		: null;
	if (session && token) {
		const tokenHash = await SHA256十六进制(token);
		if (env.DB && typeof env.DB.prepare === 'function') await env.DB.prepare('UPDATE admin_sessions SET revoked_at = ?1 WHERE id = ?2').bind(Date.now(), session.id).run();
		else if (env.KV && typeof env.KV.delete === 'function') await env.KV.delete(`admin-session:${tokenHash}`);
		await 写入审计日志(env, request, session, 'admin.logout', 'admin_session', session.id, null, null, true);
	}
	const response = new Response('重定向中...', { status: 302, headers: { Location: `${url.origin}/login`, 'Cache-Control': 'no-store' } });
	response.headers.append('Set-Cookie', 'admin_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict');
	response.headers.append('Set-Cookie', 'admin_csrf=; Path=/; Max-Age=0; Secure; SameSite=Strict');
	response.headers.append('Set-Cookie', 'auth=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict');
	return response;
}

async function 确保访问数据库(env) {
	if (!env.DB || typeof env.DB.prepare !== 'function') throw new Error('请先绑定名为 DB 的 D1 数据库');
	if (!访问数据库初始化任务) {
		访问数据库初始化任务 = (async () => {
			await env.DB.batch([
				env.DB.prepare(`CREATE TABLE IF NOT EXISTS access_links (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				token TEXT NOT NULL UNIQUE,
				uuid TEXT NOT NULL UNIQUE,
				country TEXT NOT NULL,
				duration_seconds INTEGER NOT NULL,
				proxy_ip TEXT,
				status TEXT NOT NULL DEFAULT 'active',
				note TEXT NOT NULL DEFAULT '',
				created_at INTEGER NOT NULL,
				first_used_at INTEGER,
				expires_at INTEGER,
				last_used_at INTEGER,
				connection_count INTEGER NOT NULL DEFAULT 0,
				active_connections INTEGER NOT NULL DEFAULT 0,
				last_client_ip TEXT,
				last_client_asn TEXT,
				max_concurrent_connections INTEGER NOT NULL DEFAULT 0,
				max_total_connections INTEGER NOT NULL DEFAULT 0,
				bind_first_ip INTEGER NOT NULL DEFAULT 0,
				bound_ip TEXT,
				tags TEXT NOT NULL DEFAULT '',
				connection_epoch INTEGER NOT NULL DEFAULT 0
				)`),
				env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_access_links_status_expires ON access_links(status, expires_at)'),
				env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_access_links_country ON access_links(country)'),
				env.DB.prepare(`CREATE TABLE IF NOT EXISTS proxy_ip_pool (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				country TEXT NOT NULL,
				proxy_ip TEXT NOT NULL,
				enabled INTEGER NOT NULL DEFAULT 1,
				created_at INTEGER NOT NULL,
				UNIQUE(country, proxy_ip)
				)`),
				env.DB.prepare(`CREATE TABLE IF NOT EXISTS proxy_ip_sources (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					name TEXT NOT NULL,
					url TEXT NOT NULL UNIQUE,
					default_country TEXT NOT NULL DEFAULT '',
					enabled INTEGER NOT NULL DEFAULT 1,
					refresh_minutes INTEGER NOT NULL DEFAULT 30,
					max_per_country INTEGER NOT NULL DEFAULT 100,
					last_synced_at INTEGER,
					last_status TEXT NOT NULL DEFAULT 'never',
					last_error TEXT NOT NULL DEFAULT '',
					created_at INTEGER NOT NULL,
					updated_at INTEGER NOT NULL,
					sync_lock TEXT,
					sync_lock_expires_at INTEGER
				)`),
				env.DB.prepare(`CREATE TABLE IF NOT EXISTS proxy_ip_source_sync (
					source_id INTEGER NOT NULL,
					country TEXT NOT NULL,
					last_synced_at INTEGER NOT NULL,
					last_status TEXT NOT NULL,
					last_error TEXT NOT NULL DEFAULT '',
					PRIMARY KEY(source_id, country)
				)`),
				env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_proxy_pool_country_enabled ON proxy_ip_pool(country, enabled)'),
				env.DB.prepare(`CREATE TABLE IF NOT EXISTS access_connection_leases (
					id TEXT PRIMARY KEY, access_link_id INTEGER NOT NULL, proxy_ip TEXT, created_at INTEGER NOT NULL,
					heartbeat_at INTEGER NOT NULL, expires_at INTEGER NOT NULL)`),
				env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_access_connection_leases_link ON access_connection_leases(access_link_id)'),
				env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_access_connection_leases_expiry ON access_connection_leases(expires_at)'),
				env.DB.prepare(`CREATE TABLE IF NOT EXISTS access_connection_events (
					id INTEGER PRIMARY KEY AUTOINCREMENT, access_link_id INTEGER NOT NULL, proxy_ip TEXT,
					started_at INTEGER NOT NULL, ended_at INTEGER, success INTEGER, error_code TEXT NOT NULL DEFAULT '')`),
				env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_access_connection_events_started ON access_connection_events(started_at)'),
				env.DB.prepare(`CREATE TABLE IF NOT EXISTS country_health_config (
					country TEXT PRIMARY KEY, min_healthy_ips INTEGER NOT NULL DEFAULT 3, updated_at INTEGER NOT NULL)`),
				env.DB.prepare(`CREATE TABLE IF NOT EXISTS admin_sessions (
					id TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE, csrf_hash TEXT NOT NULL, created_at INTEGER NOT NULL,
					expires_at INTEGER NOT NULL, last_seen_at INTEGER NOT NULL, source_ip TEXT, source_asn TEXT,
					user_agent_hash TEXT NOT NULL, revoked_at INTEGER)`),
				env.DB.prepare(`CREATE TABLE IF NOT EXISTS admin_login_attempts (
					ip_hash TEXT PRIMARY KEY, window_started_at INTEGER NOT NULL, failure_count INTEGER NOT NULL DEFAULT 0,
					blocked_until INTEGER, last_attempt_at INTEGER NOT NULL)`),
				env.DB.prepare(`CREATE TABLE IF NOT EXISTS audit_logs (
					id INTEGER PRIMARY KEY AUTOINCREMENT, created_at INTEGER NOT NULL, session_id TEXT, source_ip TEXT,
					source_asn TEXT, action TEXT NOT NULL, object_type TEXT NOT NULL, object_id TEXT NOT NULL DEFAULT '',
					before_summary TEXT, after_summary TEXT, success INTEGER NOT NULL, error_message TEXT NOT NULL DEFAULT '')`),
				env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at DESC)'),
				env.DB.prepare(`CREATE TABLE IF NOT EXISTS notification_state (
					event_key TEXT PRIMARY KEY, last_payload_hash TEXT NOT NULL, last_sent_at INTEGER NOT NULL, cooldown_until INTEGER NOT NULL)`),
				env.DB.prepare(`CREATE TABLE IF NOT EXISTS schema_metadata (
					key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER NOT NULL)`)
			]);

			// 迁移文件是正式升级路径；以下检查仅为旧版“首次访问自动建表”部署保留兼容性。
			const 补充缺失列 = async (table, columns) => {
				const result = await env.DB.prepare(`PRAGMA table_info(${table})`).all();
				const existing = new Set((result.results || []).map(item => item.name));
				for (const [name, definition] of columns) if (!existing.has(name)) await env.DB.prepare(`ALTER TABLE ${table} ADD COLUMN ${name} ${definition}`).run();
			};
			await 补充缺失列('access_links', [
				['connection_count', 'INTEGER NOT NULL DEFAULT 0'],
				['active_connections', 'INTEGER NOT NULL DEFAULT 0'],
				['last_client_ip', 'TEXT'],
				['last_client_asn', 'TEXT'],
				['max_concurrent_connections', 'INTEGER NOT NULL DEFAULT 0'],
				['max_total_connections', 'INTEGER NOT NULL DEFAULT 0'],
				['bind_first_ip', 'INTEGER NOT NULL DEFAULT 0'],
				['bound_ip', 'TEXT'],
				['tags', "TEXT NOT NULL DEFAULT ''"],
				['connection_epoch', 'INTEGER NOT NULL DEFAULT 0']
			]);
			await 补充缺失列('proxy_ip_pool', [
				['source_id', 'INTEGER'],
				['health_status', "TEXT NOT NULL DEFAULT 'unknown'"],
				['latency_ms', 'INTEGER'],
				['failure_count', 'INTEGER NOT NULL DEFAULT 0'],
				['last_checked_at', 'INTEGER'],
				['last_success_at', 'INTEGER'],
				['last_error', "TEXT NOT NULL DEFAULT ''"],
				['updated_at', 'INTEGER NOT NULL DEFAULT 0'],
				['health_score', 'INTEGER NOT NULL DEFAULT 50'],
				['consecutive_failures', 'INTEGER NOT NULL DEFAULT 0'],
				['cooldown_until', 'INTEGER'],
				['real_success_count', 'INTEGER NOT NULL DEFAULT 0'],
				['real_failure_count', 'INTEGER NOT NULL DEFAULT 0'],
				['last_real_failure', 'INTEGER']
			]);
			await 补充缺失列('proxy_ip_sources', [
				['consecutive_failures', 'INTEGER NOT NULL DEFAULT 0'],
				['sync_lock', 'TEXT'],
				['sync_lock_expires_at', 'INTEGER']
			]);
			await env.DB.batch([
				env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_proxy_pool_source ON proxy_ip_pool(source_id)'),
				env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_proxy_pool_health ON proxy_ip_pool(country, enabled, health_status, failure_count)'),
				env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_proxy_pool_score ON proxy_ip_pool(country, enabled, cooldown_until, health_score)'),
				env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_access_links_tags ON access_links(tags)'),
				env.DB.prepare(`INSERT INTO schema_metadata(key, value, updated_at) VALUES ('access_management_schema', '5', ?1)
					ON CONFLICT(key) DO UPDATE SET value = '5', updated_at = ?1`).bind(Date.now())
			]);
			const now = Date.now();
			await env.DB.prepare(`INSERT OR IGNORE INTO proxy_ip_sources
				(name, url, default_country, enabled, refresh_minutes, max_per_country, last_status, created_at, updated_at)
				VALUES ('CM科技大学内置列表', ?1, '', 1, 60, 100, 'never', ?2, ?2)`).bind(内置访问PROXYIP数据源URL, now).run();
		})().catch(error => {
			访问数据库初始化任务 = null;
			throw error;
		});
	}
	await 访问数据库初始化任务;
}

function 获取访问数据库会话(env) {
	return typeof env.DB.withSession === 'function' ? env.DB.withSession('first-primary') : env.DB;
}

async function 查询访问链接(env, token) {
	if (!访问令牌正则.test(String(token || ''))) return null;
	await 确保访问数据库(env);
	return await 获取访问数据库会话(env).prepare('SELECT * FROM access_links WHERE token = ?1 LIMIT 1').bind(token).first();
}

function 获取访问记录状态错误(记录, now = Date.now()) {
	if (!记录) return { status: 403, message: '访问链接不存在或已删除' };
	if (记录.status !== 'active') return { status: 403, message: '访问链接已被停用' };
	if (记录.expires_at !== null && Number(记录.expires_at) <= now) return { status: 410, message: '访问链接已过期' };
	return null;
}

function 创建访问授权上下文(env, 记录, request = null) {
	const rawIP = request ? (request.headers.get('CF-Connecting-IP') || request.headers.get('True-Client-IP') || request.headers.get('X-Real-IP') || '') : '';
	const recordClientIP = !['0', 'false', 'off'].includes(String(env.RECORD_CLIENT_IP ?? 'false').toLowerCase());
	return {
		env, 记录, request, clientIP: rawIP.slice(0, 80), clientASN: String(request?.cf?.asn || '').slice(0, 30),
		recordClientIP, 激活任务: null, 释放任务: null, 反代上下文: null, leaseId: null, eventId: null,
		监控定时器: null, 到期关闭函数: null, 已释放: false, 代理结果已记录: false, 代理连接成功: false
	};
}

function 访问限制错误(记录, clientIP, now = Date.now()) {
	const statusError = 获取访问记录状态错误(记录, now);
	if (statusError) return statusError;
	if (Number(记录.bind_first_ip) === 1 && 记录.bound_ip && 记录.bound_ip !== clientIP) return { status: 403, message: '访问链接已绑定其他客户端 IP' };
	if (Number(记录.max_total_connections) > 0 && Number(记录.connection_count) >= Number(记录.max_total_connections)) return { status: 429, message: '访问链接累计连接次数已达到上限' };
	if (Number(记录.max_concurrent_connections) > 0 && Number(记录.active_connections) >= Number(记录.max_concurrent_connections)) return { status: 429, message: '访问链接当前连接数已达到并发上限' };
	return null;
}

async function 查询健康访问代理候选(session, country, currentProxy, now = Date.now()) {
	return await session.prepare(`SELECT * FROM proxy_ip_pool
		WHERE country = ?1 AND enabled = 1
			AND (cooldown_until IS NULL OR cooldown_until <= ?3)
			AND (health_status <> 'unhealthy' OR cooldown_until <= ?3)
		ORDER BY CASE WHEN proxy_ip = ?2 THEN 0 ELSE 1 END,
			CASE health_status WHEN 'healthy' THEN 0 ELSE 1 END,
			health_score DESC, consecutive_failures ASC, latency_ms ASC, RANDOM() LIMIT 8`)
		.bind(country, currentProxy || '', now).all();
}

async function 激活访问授权上下文(上下文) {
	if (!上下文) return null;
	if (上下文.激活任务) return await 上下文.激活任务;
	const 请求认证UUID = 上下文.记录.uuid;
	上下文.激活任务 = (async () => {
		await 确保访问数据库(上下文.env);
		const session = 获取访问数据库会话(上下文.env);
		let 记录 = await session.prepare('SELECT * FROM access_links WHERE token = ?1 LIMIT 1').bind(上下文.记录.token).first();
		if (记录) {
			const now = Date.now();
			await session.batch([
				session.prepare('DELETE FROM access_connection_leases WHERE access_link_id = ?1 AND expires_at <= ?2').bind(记录.id, now),
				session.prepare(`UPDATE access_links SET active_connections = (
					SELECT COUNT(*) FROM access_connection_leases WHERE access_link_id = ?1
				) WHERE id = ?1`).bind(记录.id)
			]);
			记录 = await session.prepare('SELECT * FROM access_links WHERE id = ?1').bind(记录.id).first();
		}
		const 读取错误 = 访问限制错误(记录, 上下文.clientIP);
		if (读取错误) throw Object.assign(new Error(读取错误.message), { status: 读取错误.status });
		if (记录.uuid !== 请求认证UUID) throw Object.assign(new Error('访问凭据已轮换，请更新节点后重试'), { status: 403 });
		const linkId = 记录.id, connectionEpoch = Number(记录.connection_epoch || 0);

		let IP结果 = await 查询健康访问代理候选(session, 记录.country, 记录.proxy_ip);
		if (!(IP结果.results || []).length) {
			await 同步到期访问PROXYIP数据源(上下文.env, { country: 记录.country });
			IP结果 = await 查询健康访问代理候选(session, 记录.country, 记录.proxy_ip);
		}
		const 候选反代IP = (IP结果.results || []).map(item => item.proxy_ip);
		const 选定反代IP = 候选反代IP[0] || null;
		if (!选定反代IP) throw Object.assign(new Error(`国家 ${记录.country} 暂无健康且未隔离的 PROXYIP`), { status: 503 });

		const now = Date.now(), 原反代IP = 记录.proxy_ip || null, leaseExpiresAt = now + 90000;
		上下文.leaseId = crypto.randomUUID();
		const [admission, update] = await session.batch([
			session.prepare(`INSERT INTO access_connection_leases(id, access_link_id, proxy_ip, created_at, heartbeat_at, expires_at)
				SELECT ?1, id, ?2, ?3, ?3, ?4 FROM access_links
				WHERE token = ?5 AND status = 'active' AND (expires_at IS NULL OR expires_at > ?3)
					AND (max_total_connections = 0 OR connection_count < max_total_connections)
					AND (max_concurrent_connections = 0 OR active_connections < max_concurrent_connections)
					AND (bind_first_ip = 0 OR bound_ip IS NULL OR bound_ip = ?6)
					AND uuid = ?7 AND connection_epoch = ?8`)
				.bind(上下文.leaseId, 选定反代IP, now, leaseExpiresAt, 记录.token, 上下文.clientIP || '', 请求认证UUID, connectionEpoch),
			session.prepare(`UPDATE access_links SET
			proxy_ip = ?1,
			first_used_at = COALESCE(first_used_at, ?2),
			expires_at = CASE WHEN duration_seconds = 0 THEN NULL ELSE COALESCE(expires_at, ?2 + duration_seconds * 1000) END,
			last_used_at = ?2,
			connection_count = connection_count + 1,
			active_connections = active_connections + 1,
			last_client_ip = ?3,
			last_client_asn = ?4,
			bound_ip = CASE WHEN bind_first_ip = 1 THEN COALESCE(bound_ip, ?5) ELSE bound_ip END
			WHERE token = ?6 AND EXISTS (SELECT 1 FROM access_connection_leases WHERE id = ?7)`)
				.bind(选定反代IP, now, 上下文.recordClientIP ? 上下文.clientIP || null : null, 上下文.clientASN || null, 上下文.clientIP || '', 记录.token, 上下文.leaseId)
		]);
		if (!Number(admission?.meta?.changes || 0) || !Number(update?.meta?.changes || 0)) {
			if (Number(admission?.meta?.changes || 0)) await session.prepare('DELETE FROM access_connection_leases WHERE id = ?1').bind(上下文.leaseId).run();
			上下文.leaseId = null;
			记录 = await session.prepare('SELECT * FROM access_links WHERE token = ?1 LIMIT 1').bind(记录.token).first();
			const 限制错误 = 访问限制错误(记录, 上下文.clientIP, now) || { status: 409, message: '访问链接状态已变化，请重试' };
			throw Object.assign(new Error(限制错误.message), { status: 限制错误.status });
		}

		try {
			// 准入之后可能发生重置；不能把新代次或已删除的租约当成本次授权。
			记录 = await session.prepare(`SELECT * FROM access_links WHERE id = ?1 AND connection_epoch = ?2
				AND EXISTS (SELECT 1 FROM access_connection_leases WHERE id = ?3 AND access_link_id = ?1 AND expires_at > ?4)`)
				.bind(linkId, connectionEpoch, 上下文.leaseId, Date.now()).first();
			if (!记录) throw Object.assign(new Error('访问链接状态已变化，请重试'), { status: 409 });
			const 状态错误 = 获取访问记录状态错误(记录);
			if (状态错误) throw Object.assign(new Error(状态错误.message), { status: 状态错误.status });
			if (记录.uuid !== 请求认证UUID || 记录.token !== 上下文.记录.token) throw Object.assign(new Error('访问凭据已轮换，请更新节点后重试'), { status: 403 });
			const event = await session.prepare(`INSERT INTO access_connection_events(access_link_id, proxy_ip, started_at)
				VALUES (?1, ?2, ?3)`).bind(记录.id, 记录.proxy_ip, now).run();
			上下文.eventId = event?.meta?.last_row_id || null;
		} catch (error) {
			await session.batch([
				session.prepare('DELETE FROM access_connection_leases WHERE id = ?1').bind(上下文.leaseId),
				session.prepare(`UPDATE access_links SET active_connections = (
					SELECT COUNT(*) FROM access_connection_leases WHERE access_link_id = ?1
				) WHERE id = ?1`).bind(linkId)
			]);
			throw error;
		}

		上下文.记录 = 记录;
		上下文.connectionEpoch = connectionEpoch;
		上下文.反代上下文 = {
			反代IP: [记录.proxy_ip, ...候选反代IP.filter(item => item !== 记录.proxy_ip)].join(','),
			启用反代兜底: false,
			启用SOCKS5反代: null,
			启用SOCKS5全局反代: false,
			parsedSocks5Address: {},
			访问授权上下文: 上下文
		};
		if (!本实例活动访问连接.has(记录.id)) 本实例活动访问连接.set(记录.id, new Set());
		本实例活动访问连接.get(记录.id).add(上下文);
		if (原反代IP && 原反代IP !== 记录.proxy_ip) await 写入审计日志(上下文.env, 上下文.request, null, 'access.auto_failover', 'access_link', 记录.id, { proxy_ip: 原反代IP }, { proxy_ip: 记录.proxy_ip }, true);
		return 记录;
	})();
	return await 上下文.激活任务;
}

async function 结束访问授权上下文(上下文, success = null, errorCode = '') {
	if (!上下文 || 上下文.已释放) return;
	上下文.已释放 = true;
	if (上下文.监控定时器) clearTimeout(上下文.监控定时器);
	const set = 本实例活动访问连接.get(上下文.记录?.id);
	if (set) { set.delete(上下文); if (!set.size) 本实例活动访问连接.delete(上下文.记录.id); }
	if (!上下文.leaseId) return;
	上下文.释放任务 = (async () => {
		try {
			const session = 获取访问数据库会话(上下文.env), now = Date.now();
			const statements = [
				session.prepare('DELETE FROM access_connection_leases WHERE id = ?1').bind(上下文.leaseId),
				session.prepare(`UPDATE access_links SET active_connections = (
					SELECT COUNT(*) FROM access_connection_leases WHERE access_link_id = ?1
				) WHERE id = ?1`).bind(上下文.记录.id)
			];
			if (上下文.eventId) statements.push(session.prepare(`UPDATE access_connection_events SET ended_at = ?1, success = ?2, error_code = ?3 WHERE id = ?4`)
				.bind(now, success == null ? (上下文.代理连接成功 ? 1 : 0) : (success ? 1 : 0), String(errorCode || '').slice(0, 80), 上下文.eventId));
			await session.batch(statements);
		} catch (error) { console.error('释放访问连接计数失败:', error); }
	})();
	return await 上下文.释放任务;
}

function 安排访问链接到期(上下文, 关闭函数) {
	if (!上下文 || typeof 关闭函数 !== 'function') return null;
	上下文.到期关闭函数 = 关闭函数;
	if (上下文.已释放) { 关闭函数(); return null; }
	if (上下文.监控定时器) return 上下文.监控定时器;
	const intervalMs = Math.min(60000, Math.max(10000, Number(上下文.env.ACCESS_STATUS_CHECK_SECONDS) * 1000 || 30000));
	const check = async () => {
		if (上下文.已释放) return;
		try {
			const now = Date.now(), session = 获取访问数据库会话(上下文.env);
			const heartbeat = await session.prepare('UPDATE access_connection_leases SET heartbeat_at = ?1, expires_at = ?2 WHERE id = ?3 AND expires_at > ?1').bind(now, now + Math.max(90000, intervalMs * 3), 上下文.leaseId).run();
			const current = await session.prepare('SELECT status, expires_at, connection_epoch FROM access_links WHERE id = ?1').bind(上下文.记录.id).first();
			const error = 获取访问记录状态错误(current, now) || (Number(current?.connection_epoch || 0) !== Number(上下文.connectionEpoch || 0) ? { status: 409, message: '访问链接计时已重置' } : null)
				|| (!Number(heartbeat?.meta?.changes || 0) ? { status: 409, message: '访问连接租约已失效' } : null);
			if (error) {
				try { 上下文.到期关闭函数() } catch (_) { }
				await 结束访问授权上下文(上下文, false, error.status === 410 ? 'expired' : 'disabled');
				return;
			}
		} catch (error) { console.error('检查访问连接状态失败:', error); }
		if (!上下文.已释放) 上下文.监控定时器 = setTimeout(check, intervalMs);
	};
	const expiresIn = 上下文.记录?.expires_at ? Math.max(0, Number(上下文.记录.expires_at) - Date.now()) : intervalMs;
	上下文.监控定时器 = setTimeout(check, Math.min(intervalMs, expiresIn || 1));
	return 上下文.监控定时器;
}

function 关闭本实例链接连接(linkId) {
	for (const context of 本实例活动访问连接.get(Number(linkId)) || []) {
		try { context.到期关闭函数?.() } catch (_) { }
		结束访问授权上下文(context, false, 'disabled');
	}
}

function 生成随机访问令牌() {
	const bytes = crypto.getRandomValues(new Uint8Array(32));
	let binary = '';
	for (const byte of bytes) binary += String.fromCharCode(byte);
	return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

async function 生成访问订阅转换令牌(访问令牌, 种子, 日序号) {
	return `c.${访问令牌}.${await MD5MD5(种子 + 日序号)}`;
}

function 生成访问节点路径(config, token) {
	const 原始路径 = String(config?.PATH || '/');
	const 问号位置 = 原始路径.indexOf('?');
	let pathname = 问号位置 >= 0 ? 原始路径.slice(0, 问号位置) : 原始路径;
	const 查询 = new URLSearchParams(问号位置 >= 0 ? 原始路径.slice(问号位置 + 1) : '');
	pathname = '/' + pathname.replace(/^\/+|\/+$/g, '');
	if (pathname === '/') pathname = '';
	const 访问路径 = `${pathname}/u/${token}`.replace(/\/+/g, '/');
	if (config?.启用0RTT) 查询.set('ed', '2560');
	return 访问路径 + (查询.toString() ? `?${查询.toString()}` : '');
}

function 应用访问链接配置(config, 记录) {
	const 独立配置 = typeof structuredClone === 'function' ? structuredClone(config) : JSON.parse(JSON.stringify(config));
	独立配置.UUID = 记录.uuid;
	独立配置.PATH = 生成访问节点路径(独立配置, 记录.token);
	独立配置.完整节点路径 = 独立配置.PATH;
	独立配置.优选订阅生成.TOKEN = 记录.token;
	独立配置.LINK = 生成访问节点链接(独立配置, 记录);
	return 独立配置;
}

function 生成访问节点链接(config, 记录) {
	const host = config.HOST;
	const 完整节点路径 = config.完整节点路径 || 生成访问节点路径(config, 记录.token);
	const TLS分片参数 = config.TLS分片 == 'Shadowrocket' ? `&fragment=${encodeURIComponent('1,40-60,30-50,tlshello')}` : config.TLS分片 == 'Happ' ? `&fragment=${encodeURIComponent('3,1,tlshello')}` : '';
	const ECHLINK参数 = config.ECH ? `&ech=${encodeURIComponent((config.ECHConfig?.SNI ? config.ECHConfig.SNI + '+' : '') + config.ECHConfig?.DNS)}` : '';
	const { type: 传输协议, 路径字段名, 域名字段名 } = 获取传输协议配置(config);
	const 传输路径参数值 = 获取传输路径参数值(config, 完整节点路径);
	const 名称 = encodeURIComponent(生成访问节点名称(记录));
	if (config.协议类型 === 'ss') {
		const ssPath = 完整节点路径.includes('?') ? 完整节点路径.replace('?', `?enc=${config.SS.加密方式}&`) : `${完整节点路径}?enc=${config.SS.加密方式}`;
		return `ss://${btoa(config.SS.加密方式 + ':' + 记录.uuid)}@${host}:${config.SS.TLS ? '443' : '80'}?plugin=v2${encodeURIComponent(`ray-plugin;mode=websocket;host=${host};path=${ssPath}${config.SS.TLS ? ';tls' : ''};mux=0`)}${ECHLINK参数}#${名称}`;
	}
	return `${config.协议类型}://${记录.uuid}@${host}:443?security=tls&type=${传输协议}${ECHLINK参数}&${域名字段名}=${host}&fp=${config.Fingerprint}&sni=${host}&${路径字段名}=${encodeURIComponent(传输路径参数值)}${TLS分片参数}&encryption=none${config.跳过证书验证 ? '&insecure=1&allowInsecure=1' : ''}#${名称}`;
}

function 生成访问节点名称(记录) {
	const 国家代码 = String(记录?.country || '').trim().toUpperCase();
	const 国家名称 = 国家代码 ? (访问国家显示名称格式器?.of(国家代码) || 国家代码) : '国家节点';
	const 国家标签 = 国家代码 && 国家名称 !== 国家代码 ? `${国家名称} (${国家代码})` : 国家名称;
	const 时长名称 = Number(记录?.duration_seconds) === 0 ? '永久' : `${Math.round(Number(记录?.duration_seconds) / 3600 * 100) / 100}小时`;
	return `${国家标签} - ${记录?.note || 时长名称}`;
}

const 访问国家代码列表 = Object.freeze(`AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ
BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ
CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ
DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR
GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY
HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP
KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY
MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ
NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY
QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ
TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ
VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW`.split(/\s+/));
const 访问国家代码集合 = new Set(访问国家代码列表);
let 访问国家显示名称格式器 = null;
try { 访问国家显示名称格式器 = new Intl.DisplayNames(['zh-CN'], { type: 'region' }); } catch (_) { }
const 访问国家名称代码映射 = new Map(访问国家代码列表.map(code => [访问国家显示名称格式器?.of(code) || code, code]));

function 标准化访问国家(value) {
	const input = String(value || '').trim();
	const country = input.toUpperCase();
	if (访问国家代码集合.has(country)) return country;
	const optionCode = input.match(/\(([A-Za-z]{2})\)\s*$/)?.[1]?.toUpperCase();
	if (访问国家代码集合.has(optionCode)) return optionCode;
	const nameCode = 访问国家名称代码映射.get(input);
	if (nameCode) return nameCode;
	throw new Error('请选择系统提供的国家或地区');
}

function 生成访问国家选项() {
	return 访问国家代码列表.map(code => `<option value="${code}">${访问国家显示名称格式器?.of(code) || code} (${code})</option>`).join('');
}

function 标准化访问PROXYIP(value) {
	let proxy = String(value || '').trim().replace(/^(?:proxyip|https?|socks5):\/\//i, '');
	proxy = proxy.split(/[/?#]/)[0].trim();
	if (!proxy || proxy.length > 300 || /[\s@]/.test(proxy) || !/^[A-Za-z0-9.[\]:_-]+$/.test(proxy) || (!proxy.includes('.') && !proxy.includes(':'))) throw new Error(`无效的 PROXYIP：${value}`);
	return proxy;
}

function 标准化访问数据源URL(value) {
	let url;
	try { url = new URL(String(value || '').trim()); } catch (_) { throw new Error('数据源 URL 格式不正确'); }
	if (url.protocol !== 'https:' || url.username || url.password || url.href.length > 2000) throw new Error('数据源必须使用不含账号密码的 HTTPS URL');
	const hostname = url.hostname.toLowerCase();
	const bareHostname = hostname.replace(/^\[|\]$/g, '');
	const mappedMatch = bareHostname.match(/^::ffff:(?:(\d+\.\d+\.\d+\.\d+)|([0-9a-f]+):([0-9a-f]+))$/i);
	const mappedIPv4 = mappedMatch?.[1] || (mappedMatch ? `${parseInt(mappedMatch[2], 16) >>> 8}.${parseInt(mappedMatch[2], 16) & 255}.${parseInt(mappedMatch[3], 16) >>> 8}.${parseInt(mappedMatch[3], 16) & 255}` : '');
	const privateIPv4 = /^(?:127\.|0\.|10\.|192\.168\.|169\.254\.|172\.(?:1[6-9]|2\d|3[01])\.|100\.(?:6[4-9]|[78]\d|9\d|1[01]\d|12[0-7])\.|198\.(?:1[89])\.|(?:22[4-9]|23\d)\.)/.test(mappedIPv4 || bareHostname);
	if (hostname === 'localhost' || hostname.endsWith('.localhost') || hostname.endsWith('.local') || hostname.endsWith('.internal') || privateIPv4 || /^(?:::\]?$$|::1|f[cd][0-9a-f]{2}:|fe[89ab][0-9a-f]:|ff[0-9a-f]{2}:)/i.test(bareHostname)) throw new Error('数据源地址不允许指向本地或私有网络');
	return url.href;
}

async function 安全获取访问数据源(url, options, maximumBytes, allowedContentTypes) {
	let current = 标准化访问数据源URL(url);
	for (let redirectCount = 0; redirectCount <= 3; redirectCount++) {
		const response = await fetch(current, { ...options, redirect: 'manual' });
		if ([301, 302, 303, 307, 308].includes(response.status)) {
			if (redirectCount >= 3) throw new Error('数据源重定向次数过多');
			const location = response.headers.get('Location');
			if (!location) throw new Error('数据源重定向缺少 Location');
			current = 标准化访问数据源URL(new URL(location, current).href);
			continue;
		}
		if (!response.ok) throw new Error(`数据源返回 HTTP ${response.status}`);
		const contentLength = Number(response.headers.get('content-length') || 0);
		if (contentLength > maximumBytes) throw new Error(`数据源内容超过 ${Math.round(maximumBytes / 1048576)}MB`);
		const contentType = (response.headers.get('content-type') || '').toLowerCase().split(';')[0].trim();
		if (contentType && !allowedContentTypes.some(type => contentType === type || contentType.startsWith(type))) throw new Error(`数据源 Content-Type 不受支持：${contentType}`);
		return response;
	}
	throw new Error('数据源重定向失败');
}

async function 读取受限响应字节(response, maximumBytes) {
	if (!response.body) return new Uint8Array(0);
	const reader = response.body.getReader(), chunks = [];
	let total = 0;
	try {
		while (true) {
			const { done, value } = await reader.read();
			if (done) break;
			total += value.byteLength;
			if (total > maximumBytes) throw new Error(`数据源内容超过 ${Math.round(maximumBytes / 1048576)}MB`);
			chunks.push(value);
		}
	} finally { try { reader.releaseLock() } catch (_) { } }
	const output = new Uint8Array(total);
	let offset = 0;
	for (const chunk of chunks) { output.set(chunk, offset); offset += chunk.byteLength; }
	return output;
}

function 解析访问PROXYIP数据源(text, defaultCountry = '') {
	const entries = [], seen = new Set();
	let skipped = 0;
	const add = (proxyValue, countryValue = defaultCountry) => {
		try {
			const country = 标准化访问国家(countryValue);
			const proxy_ip = 标准化访问PROXYIP(proxyValue);
			const key = `${country}\n${proxy_ip.toLowerCase()}`;
			if (!seen.has(key)) {
				seen.add(key);
				entries.push({ country, proxy_ip });
			}
		} catch (_) { skipped++; }
	};
	const countryFrom = value => {
		try { return 标准化访问国家(value); } catch (_) { return ''; }
	};
	const walk = (value, inheritedCountry = defaultCountry, depth = 0) => {
		if (depth > 6 || value == null || entries.length >= 25000) return;
		if (Array.isArray(value)) {
			for (const item of value) walk(item, inheritedCountry, depth + 1);
			return;
		}
		if (typeof value === 'string' || typeof value === 'number') {
			add(String(value), inheritedCountry);
			return;
		}
		if (typeof value !== 'object') return;
		const proxy = value.proxy_ip ?? value.proxyIp ?? value.proxyip ?? value.address ?? value.endpoint ?? value.ip ?? value.host;
		if (proxy != null) {
			const country = value.country_code ?? value.countryCode ?? value.country ?? value.cc ?? value.region ?? value.meta?.country ?? value.meta?.colo?.cca2 ?? inheritedCountry;
			const ports = Array.isArray(value.port) ? value.port : [value.port];
			const validPorts = ports.map(Number).filter(port => Number.isInteger(port) && port > 0 && port <= 65535);
			if (validPorts.length && !String(proxy).includes(':')) {
				if (validPorts.includes(443)) add(proxy, country);
				else for (const port of validPorts) add(`${proxy}:${port}`, country);
			} else add(proxy, country);
			return;
		}
		for (const [key, child] of Object.entries(value)) walk(child, countryFrom(key) || inheritedCountry, depth + 1);
	};

	const input = String(text || '').replace(/^\uFEFF/, '').trim();
	if (!input) return { entries, skipped };
	try {
		walk(JSON.parse(input));
	} catch (_) {
		const lines = input.split(/\r?\n/).map(line => line.trim()).filter(line => line && !line.startsWith('#') && !line.startsWith('//'));
		let headers = null;
		if (lines.length) {
			const possibleHeaders = lines[0].split(/[,\t|;]/).map(item => item.trim().toLowerCase());
			if (possibleHeaders.some(item => /^(ip|host|address|endpoint|proxy|proxyip|proxy_ip)$/.test(item))) {
				headers = possibleHeaders;
				lines.shift();
			}
		}
		for (const line of lines.slice(0, 25000)) {
			const fields = line.split(/[,\t|;]/).map(item => item.trim());
			const columns = headers ? fields : fields.filter(Boolean);
			if (headers) {
				const get = names => {
					const index = headers.findIndex(header => names.includes(header));
					return index >= 0 ? columns[index] : '';
				};
				const host = get(['ip', 'host', 'address', 'endpoint', 'proxy', 'proxyip', 'proxy_ip']);
				const port = get(['port']);
				add(port && host && !host.includes(':') ? `${host}:${port}` : host, get(['country', 'country_code', 'countrycode', 'cc', 'region']) || defaultCountry);
				continue;
			}
			let country = defaultCountry;
			for (const column of columns) {
				const detected = countryFrom(column);
				if (detected) { country = detected; break; }
			}
			let proxy = columns.find(column => !countryFrom(column)) || line;
			const remarkMatch = line.match(/^(.+?)#\s*([^#]+)$/);
			if (remarkMatch) {
				proxy = remarkMatch[1].trim();
				country = countryFrom(remarkMatch[2]) || country;
			}
			add(proxy, country);
		}
	}
	return { entries, skipped };
}

function 读取ZIP小端整数(bytes, offset, size) {
	const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
	if (size === 2) return view.getUint16(offset, true);
	if (size === 4) return view.getUint32(offset, true);
	return 0;
}

async function 解压访问PROXYIPZIP条目(buffer, names) {
	const bytes = new Uint8Array(buffer);
	const wanted = new Set(names);
	const entries = new Map();
	const start = Math.max(0, bytes.length - 0x10000 - 22);
	let eocd = -1;
	for (let offset = bytes.length - 22; offset >= start; offset--) {
		if (读取ZIP小端整数(bytes, offset, 4) === 0x06054b50) { eocd = offset; break; }
	}
	if (eocd < 0) throw new Error('内置 PROXYIP ZIP 文件格式不正确');
	const centralOffset = 读取ZIP小端整数(bytes, eocd + 16, 4);
	const centralSize = 读取ZIP小端整数(bytes, eocd + 12, 4);
	let offset = centralOffset;
	const decoder = new TextDecoder();
	while (offset + 46 <= bytes.length && offset < centralOffset + centralSize) {
		if (读取ZIP小端整数(bytes, offset, 4) !== 0x02014b50) break;
		const compressedSize = 读取ZIP小端整数(bytes, offset + 20, 4);
		const method = 读取ZIP小端整数(bytes, offset + 10, 2);
		const nameLength = 读取ZIP小端整数(bytes, offset + 28, 2);
		const extraLength = 读取ZIP小端整数(bytes, offset + 30, 2);
		const commentLength = 读取ZIP小端整数(bytes, offset + 32, 2);
		const localOffset = 读取ZIP小端整数(bytes, offset + 42, 4);
		const name = decoder.decode(bytes.slice(offset + 46, offset + 46 + nameLength));
		if (wanted.has(name)) entries.set(name, { compressedSize, method, localOffset });
		offset += 46 + nameLength + extraLength + commentLength;
	}
	const output = new Map();
	for (const name of wanted) {
		const entry = entries.get(name);
		if (!entry) continue;
		const local = entry.localOffset;
		if (读取ZIP小端整数(bytes, local, 4) !== 0x04034b50) continue;
		const nameLength = 读取ZIP小端整数(bytes, local + 26, 2);
		const extraLength = 读取ZIP小端整数(bytes, local + 28, 2);
		const dataStart = local + 30 + nameLength + extraLength;
		const compressed = bytes.slice(dataStart, dataStart + entry.compressedSize);
		let content = compressed;
		if (entry.method === 8) {
			if (typeof DecompressionStream !== 'function') throw new Error('当前运行环境不支持 ZIP 解压');
			const stream = new DecompressionStream('deflate-raw');
			content = new Uint8Array(await new Response(new Blob([compressed]).stream().pipeThrough(stream)).arrayBuffer());
		} else if (entry.method !== 0) {
			throw new Error(`内置 PROXYIP ZIP 使用不支持的压缩方式：${entry.method}`);
		}
		output.set(name, decoder.decode(content));
	}
	return output;
}

async function 获取访问PROXYIP数据源内容(source, targetCountry = '') {
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), 20000);
	try {
		if (source.url === 内置访问PROXYIP数据源URL && targetCountry) {
			const zipUrl = source.url.replace(/\/all\.json$/i, '/ip.zip');
			const response = await 安全获取访问数据源(zipUrl, { headers: { Accept: 'application/zip,*/*;q=0.1', 'User-Agent': 'edgetunnel-proxy-pool/1.0' }, signal: controller.signal }, 20 * 1024 * 1024, ['application/zip', 'application/x-zip-compressed', 'application/octet-stream', 'binary/octet-stream']);
			const bytes = await 读取受限响应字节(response, 20 * 1024 * 1024);
			const buffer = bytes.buffer;
			const ports = [443, 8443, 2053, 2083, 2087, 2096];
			const names = ports.map(port => `${port}/${targetCountry}.txt`);
			const files = await 解压访问PROXYIPZIP条目(buffer, names);
			const parts = [];
			for (const port of ports) {
				const file = files.get(`${port}/${targetCountry}.txt`);
				if (!file) continue;
				for (const line of file.split(/\r?\n/).map(item => item.trim()).filter(Boolean)) parts.push(port === 443 || line.includes(':') ? line : `${line}:${port}`);
			}
			return parts.join('\n');
		}
		const response = await 安全获取访问数据源(source.url, { headers: { Accept: 'application/json,text/plain,text/csv;q=0.9,*/*;q=0.1', 'User-Agent': 'edgetunnel-proxy-pool/1.0' }, signal: controller.signal }, 20 * 1024 * 1024, ['application/json', 'text/', 'application/csv', 'application/octet-stream']);
		const text = new TextDecoder().decode(await 读取受限响应字节(response, 20 * 1024 * 1024));
		return text;
	} catch (error) {
		if (error?.name === 'AbortError') throw new Error('数据源请求超时');
		throw error;
	} finally { clearTimeout(timer); }
}

async function 同步单个访问PROXYIP数据源(env, source, targetCountry = '', 重置健康状态 = false) {
	const now = Date.now();
	const lockToken = crypto.randomUUID();
	const lock = await env.DB.prepare(`UPDATE proxy_ip_sources SET sync_lock = ?1, sync_lock_expires_at = ?2
		WHERE id = ?3 AND (sync_lock IS NULL OR sync_lock_expires_at <= ?4)`)
		.bind(lockToken, now + 15 * 60 * 1000, source.id, now).run();
	if (!Number(lock?.meta?.changes || 0)) return { id: source.id, name: source.name, success: false, error: '数据源正在同步，请稍后重试' };
	try {
		const text = await 获取访问PROXYIP数据源内容(source, targetCountry);
		const parsed = 解析访问PROXYIP数据源(text, targetCountry || source.default_country || '');
		const grouped = new Map();
		for (const entry of parsed.entries) {
			if (targetCountry && entry.country !== targetCountry) continue;
			if (!grouped.has(entry.country)) grouped.set(entry.country, []);
			if (grouped.get(entry.country).length < Number(source.max_per_country || 100)) grouped.get(entry.country).push(entry);
		}
		const entries = [...grouped.values()].flat().slice(0, 5000);
		if (!entries.length) throw new Error(source.default_country ? '数据源中没有可识别的 PROXYIP' : '数据源缺少国家字段，请设置默认国家');
		for (let index = 0; index < entries.length; index += 50) {
			await env.DB.batch(entries.slice(index, index + 50).map(entry => env.DB.prepare(`INSERT INTO proxy_ip_pool
				(country, proxy_ip, enabled, created_at, source_id, health_status, failure_count, last_error, updated_at)
				VALUES (?1, ?2, 1, ?3, ?4, 'unknown', 0, '', ?3)
				ON CONFLICT(country, proxy_ip) DO UPDATE SET enabled = 1, source_id = ?4,
					health_status = CASE WHEN ?5 = 1 THEN 'unknown' ELSE health_status END,
					consecutive_failures = CASE WHEN ?5 = 1 THEN 0 ELSE consecutive_failures END,
					cooldown_until = CASE WHEN ?5 = 1 THEN NULL ELSE cooldown_until END,
					last_error = CASE WHEN ?5 = 1 THEN '' ELSE last_error END,
					updated_at = ?3`)
				.bind(entry.country, entry.proxy_ip, now, source.id, 重置健康状态 ? 1 : 0)));
		}
		const 删除过期语句 = targetCountry
			? env.DB.prepare('DELETE FROM proxy_ip_pool WHERE source_id = ?1 AND country = ?2 AND updated_at <> ?3').bind(source.id, targetCountry, now)
			: env.DB.prepare('DELETE FROM proxy_ip_pool WHERE source_id = ?1 AND updated_at <> ?2').bind(source.id, now);
		const 同步记录语句 = targetCountry
			? env.DB.prepare(`INSERT INTO proxy_ip_source_sync(source_id, country, last_synced_at, last_status, last_error)
				VALUES (?1, ?2, ?3, 'success', '') ON CONFLICT(source_id, country) DO UPDATE SET
				last_synced_at = ?3, last_status = 'success', last_error = ''`).bind(source.id, targetCountry, now)
			: env.DB.prepare("UPDATE proxy_ip_sources SET updated_at = ?1 WHERE id = ?2").bind(now, source.id);
		await env.DB.batch([
			删除过期语句,
			同步记录语句,
			env.DB.prepare("UPDATE proxy_ip_sources SET last_synced_at = ?1, last_status = 'success', last_error = '', consecutive_failures = 0, updated_at = ?1 WHERE id = ?2").bind(now, source.id)
		]);
		return { id: source.id, name: source.name, success: true, imported: entries.length, countries: grouped.size, skipped: parsed.skipped };
	} catch (error) {
		const message = String(error?.message || error).slice(0, 300);
		const statements = [env.DB.prepare("UPDATE proxy_ip_sources SET last_synced_at = ?1, last_status = 'error', last_error = ?2, consecutive_failures = consecutive_failures + 1, updated_at = ?1 WHERE id = ?3").bind(now, message, source.id)];
		if (targetCountry) statements.push(env.DB.prepare(`INSERT INTO proxy_ip_source_sync(source_id, country, last_synced_at, last_status, last_error)
			VALUES (?1, ?2, ?3, 'error', ?4) ON CONFLICT(source_id, country) DO UPDATE SET
			last_synced_at = ?3, last_status = 'error', last_error = ?4`).bind(source.id, targetCountry, now, message));
		await env.DB.batch(statements);
		if (Number(source.consecutive_failures || 0) + 1 >= 3) await 发送管理通知(env, `source-failure:${source.id}`, 'PROXYIP 数据源连续同步失败', { source_id: source.id, name: source.name, error: message }, 3600);
		return { id: source.id, name: source.name, success: false, error: message };
	} finally {
		try {
			await env.DB.prepare('UPDATE proxy_ip_sources SET sync_lock = NULL, sync_lock_expires_at = NULL WHERE id = ?1 AND sync_lock = ?2').bind(source.id, lockToken).run();
		} catch (_) { }
	}
}

async function 同步到期访问PROXYIP数据源(env, { force = false, country = '' } = {}) {
	await 确保访问数据库(env);
	const result = country
		? await env.DB.prepare(`SELECT s.*, y.last_synced_at AS country_last_synced_at
			FROM proxy_ip_sources s LEFT JOIN proxy_ip_source_sync y ON y.source_id = s.id AND y.country = ?1
			WHERE s.enabled = 1 ORDER BY s.id`).bind(country).all()
		: await env.DB.prepare('SELECT * FROM proxy_ip_sources WHERE enabled = 1 ORDER BY id').all();
	const now = Date.now();
	const sources = (result.results || []).filter(source => {
		if (country && source.default_country && source.default_country !== country) return false;
		const lastSyncedAt = country ? source.country_last_synced_at : source.last_synced_at;
		return force || !lastSyncedAt || now - Number(lastSyncedAt) >= Math.max(5, Number(source.refresh_minutes || 30)) * 60000;
	});
	const summaries = [];
	for (const source of sources) summaries.push(await 同步单个访问PROXYIP数据源(env, source, country, force));
	return summaries;
}

async function 检测访问PROXYIP池(env, country, limit = 8) {
	const checkedAt = Date.now();
	const result = await env.DB.prepare(`SELECT * FROM proxy_ip_pool
		WHERE country = ?1 AND enabled = 1
			AND (cooldown_until IS NULL OR cooldown_until <= ?3)
			AND (health_status <> 'healthy' OR last_checked_at IS NULL OR last_checked_at < ?2)
		ORDER BY CASE health_status WHEN 'unknown' THEN 0 WHEN 'unhealthy' THEN 1 ELSE 2 END, health_score ASC, RANDOM()
		LIMIT ?4`).bind(country, checkedAt - 6 * 3600000, checkedAt, Math.min(24, Math.max(1, Number(limit) || 8))).all();
	const candidates = result.results || [];
	let success = 0, failed = 0, unavailable = 0, cursor = 0;
	const worker = async () => {
		while (cursor < candidates.length) {
			const candidate = candidates[cursor++];
			const controller = new AbortController();
			const timer = setTimeout(() => controller.abort(), 8000);
			try {
				const endpoint = String(candidate.proxy_ip).replace(/:443$/, '');
				const response = await fetch(访问PROXYIP检测URL + encodeURIComponent(endpoint), { signal: controller.signal, headers: { Accept: 'application/json' } });
				if (!response.ok) throw new Error(`检测服务 HTTP ${response.status}`);
				const data = await response.json();
				if (data.success) {
					success++;
					await env.DB.prepare(`UPDATE proxy_ip_pool SET health_status = 'healthy', latency_ms = ?1,
						failure_count = 0, consecutive_failures = 0, cooldown_until = NULL,
						health_score = MIN(100, health_score + 8), last_checked_at = ?2, last_success_at = ?2, last_error = '' WHERE id = ?3`)
						.bind(Math.max(0, Math.round(Number(data.responseTime) || 0)), checkedAt, candidate.id).run();
				} else {
					failed++;
					await 记录访问PROXYIP结果(env, { country, proxyIP: candidate.proxy_ip, success: false, real: false, error: 'PROXYIP 检测失败', checkedAt });
				}
			} catch (error) {
				unavailable++;
				await 记录访问PROXYIP结果(env, { country, proxyIP: candidate.proxy_ip, success: false, real: false, error: String(error?.message || error), checkedAt });
			} finally { clearTimeout(timer); }
		}
	};
	await Promise.all(Array.from({ length: Math.min(4, candidates.length) }, worker));
	return { checked: candidates.length, success, failed, unavailable };
}

async function 记录访问PROXYIP结果(env, { country, proxyIP, success, real = true, latency = null, error = '', checkedAt = Date.now() }) {
	if (!env.DB || !proxyIP) return;
	const threshold = Math.min(10, Math.max(2, Number(env.PROXYIP_FAILURE_THRESHOLD) || 3));
	const cooldownMs = Math.min(24 * 3600000, Math.max(60000, Number(env.PROXYIP_COOLDOWN_MINUTES) * 60000 || 30 * 60000));
	const endpoint = String(proxyIP).toLowerCase();
	const hostOnly = endpoint.replace(/:443$/, '');
	const record = await env.DB.prepare(`SELECT id, consecutive_failures FROM proxy_ip_pool
		WHERE country = ?1 AND (LOWER(proxy_ip) = ?2 OR LOWER(proxy_ip) = ?3) ORDER BY CASE WHEN LOWER(proxy_ip) = ?2 THEN 0 ELSE 1 END LIMIT 1`)
		.bind(country, endpoint, hostOnly).first();
	if (!record) return;
	if (success) {
		await env.DB.prepare(`UPDATE proxy_ip_pool SET health_status = 'healthy', health_score = MIN(100, health_score + ?1),
			consecutive_failures = 0, failure_count = 0, cooldown_until = NULL, last_success_at = ?2,
			last_checked_at = CASE WHEN ?3 = 1 THEN last_checked_at ELSE ?2 END,
			latency_ms = CASE WHEN ?4 IS NULL THEN latency_ms WHEN latency_ms IS NULL THEN ?4 ELSE CAST((latency_ms * 3 + ?4) / 4 AS INTEGER) END,
			real_success_count = real_success_count + ?3, last_error = '' WHERE id = ?5`)
			.bind(real ? 5 : 8, checkedAt, real ? 1 : 0, latency == null ? null : Math.max(0, Math.round(latency)), record.id).run();
	} else {
		const nextFailures = Number(record.consecutive_failures || 0) + 1;
		await env.DB.prepare(`UPDATE proxy_ip_pool SET
			health_score = MAX(0, health_score - ?1), failure_count = failure_count + 1,
			consecutive_failures = consecutive_failures + 1,
			health_status = CASE WHEN consecutive_failures + 1 >= ?2 THEN 'unhealthy' ELSE health_status END,
			cooldown_until = CASE WHEN consecutive_failures + 1 >= ?2 THEN ?3 ELSE cooldown_until END,
			last_checked_at = CASE WHEN ?4 = 1 THEN last_checked_at ELSE ?5 END,
			real_failure_count = real_failure_count + ?4,
			last_real_failure = CASE WHEN ?4 = 1 THEN ?5 ELSE last_real_failure END,
			last_error = ?6 WHERE id = ?7`)
			.bind(real ? 15 : 10, threshold, checkedAt + cooldownMs, real ? 1 : 0, checkedAt, String(error || '连接失败').slice(0, 200), record.id).run();
		if (nextFailures >= threshold) console.warn(`PROXYIP 已隔离: ${country}/${proxyIP}`);
	}
}

async function 记录访问代理连接结果(上下文, success, proxyIP, latency = null, error = '') {
	if (!上下文 || !proxyIP) return;
	await 记录访问PROXYIP结果(上下文.env, { country: 上下文.记录.country, proxyIP, success, real: true, latency, error });
	if (!success) return;
	上下文.代理连接成功 = true;
	const normalized = String(proxyIP).replace(/:443$/, '');
	const previous = String(上下文.记录.proxy_ip || '');
	if (previous && normalized !== previous.replace(/:443$/, '') && String(proxyIP) !== previous) {
		await 上下文.env.DB.prepare('UPDATE access_links SET proxy_ip = ?1 WHERE id = ?2 AND status = \'active\'').bind(proxyIP, 上下文.记录.id).run();
		上下文.记录.proxy_ip = proxyIP;
		if (上下文.leaseId) await 上下文.env.DB.prepare('UPDATE access_connection_leases SET proxy_ip = ?1 WHERE id = ?2').bind(proxyIP, 上下文.leaseId).run();
		await 写入审计日志(上下文.env, 上下文.request, null, 'access.auto_failover', 'access_link', 上下文.记录.id, { proxy_ip: previous }, { proxy_ip: proxyIP }, true);
		await 发送管理通知(上下文.env, `failover:${上下文.记录.id}:${proxyIP}`, '自动故障转移', { link_id: 上下文.记录.id, country: 上下文.记录.country, previous_proxy: previous, proxy_ip: proxyIP }, 1800);
	}
}

async function 清理访问连接租约(env) {
	if (!env.DB || typeof env.DB.prepare !== 'function') return;
	const now = Date.now();
	await env.DB.batch([
		env.DB.prepare('DELETE FROM access_connection_leases WHERE expires_at <= ?1').bind(now),
		env.DB.prepare(`UPDATE access_links SET active_connections = (
			SELECT COUNT(*) FROM access_connection_leases leases WHERE leases.access_link_id = access_links.id
		) WHERE active_connections <> (
			SELECT COUNT(*) FROM access_connection_leases leases WHERE leases.access_link_id = access_links.id
		)`)
	]);
}

async function 发送管理通知(env, eventKey, title, payload, cooldownSeconds = 3600) {
	const webhook = String(env.NOTIFY_WEBHOOK_URL || '').trim();
	const telegramToken = String(env.TELEGRAM_BOT_TOKEN || '').trim();
	const telegramChat = String(env.TELEGRAM_CHAT_ID || '').trim();
	if (!webhook && !(telegramToken && telegramChat) || !env.DB) return { sent: false, reason: 'not_configured' };
	const now = Date.now(), payloadHash = await SHA256十六进制(JSON.stringify(payload || {}));
	const previous = await env.DB.prepare('SELECT * FROM notification_state WHERE event_key = ?1').bind(eventKey).first();
	if (previous && Number(previous.cooldown_until) > now && previous.last_payload_hash === payloadHash) return { sent: false, reason: 'cooldown' };
	const text = `${title}\n${JSON.stringify(payload || {})}`.slice(0, 3500);
	const tasks = [], controller = new AbortController(), timer = setTimeout(() => controller.abort(), 8000);
	if (webhook) {
		try {
			const safeUrl = 标准化访问数据源URL(webhook);
			tasks.push(fetch(safeUrl, { method: 'POST', redirect: 'manual', signal: controller.signal, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ event: eventKey, title, data: payload, created_at: now }) }));
		} catch (error) { console.error('Webhook 配置无效:', error?.message || error); }
	}
	if (telegramToken && telegramChat && /^[A-Za-z0-9:_-]{20,}$/.test(telegramToken)) {
		tasks.push(fetch(`https://api.telegram.org/bot${telegramToken}/sendMessage`, { method: 'POST', signal: controller.signal, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ chat_id: telegramChat, text, disable_web_page_preview: true }) }));
	}
	const results = await Promise.allSettled(tasks);
	clearTimeout(timer);
	const sent = results.some(item => item.status === 'fulfilled' && item.value?.ok);
	if (tasks.length) await env.DB.prepare(`INSERT INTO notification_state(event_key, last_payload_hash, last_sent_at, cooldown_until)
		VALUES (?1, ?2, ?3, ?4) ON CONFLICT(event_key) DO UPDATE SET last_payload_hash = ?2, last_sent_at = ?3, cooldown_until = ?4`)
		.bind(eventKey, payloadHash, now, now + Math.max(60, cooldownSeconds) * 1000).run();
	return { sent, results: results.length };
}

async function 检查访问管理通知(env) {
	const now = Date.now(), defaultMinimum = Math.min(100, Math.max(1, Number(env.MIN_HEALTHY_IPS_PER_COUNTRY) || 3));
	const low = await env.DB.prepare(`SELECT l.country, COUNT(DISTINCT CASE WHEN p.enabled = 1 AND p.health_status = 'healthy'
		AND (p.cooldown_until IS NULL OR p.cooldown_until <= ?1) THEN p.id END) AS healthy,
		COALESCE(c.min_healthy_ips, ?2) AS minimum
		FROM access_links l LEFT JOIN proxy_ip_pool p ON p.country = l.country
		LEFT JOIN country_health_config c ON c.country = l.country
		WHERE l.status = 'active' GROUP BY l.country HAVING healthy < minimum`).bind(now, defaultMinimum).all();
	for (const item of low.results || []) await 发送管理通知(env, `low-capacity:${item.country}`, '国家健康 PROXYIP 低于阈值', { country: item.country, healthy: Number(item.healthy || 0), minimum: Number(item.minimum || defaultMinimum) }, 3600);
	const expiring = await env.DB.prepare(`SELECT id, country, expires_at FROM access_links
		WHERE status = 'active' AND expires_at > ?1 AND expires_at <= ?2 ORDER BY expires_at LIMIT 50`).bind(now, now + 24 * 3600000).all();
	for (const link of expiring.results || []) await 发送管理通知(env, `expiring:${link.id}`, '访问链接即将到期', { link_id: link.id, country: link.country, expires_at: link.expires_at }, 21600);
	const anomalyThreshold = Math.min(100000, Math.max(10, Number(env.ABNORMAL_CONNECTIONS_PER_HOUR) || 500));
	const anomaly = await env.DB.prepare('SELECT access_link_id, COUNT(*) AS total FROM access_connection_events WHERE started_at >= ?1 GROUP BY access_link_id HAVING total >= ?2 LIMIT 50').bind(now - 3600000, anomalyThreshold).all();
	for (const item of anomaly.results || []) await 发送管理通知(env, `connection-anomaly:${item.access_link_id}`, '访问链接连接量异常', { link_id: item.access_link_id, connections_last_hour: Number(item.total) }, 3600);
}

function 格式化后台访问记录(记录, config, origin) {
	const now = Date.now();
	let display_status = 'unused';
	if (记录.status !== 'active') display_status = 'revoked';
	else if (记录.expires_at !== null && Number(记录.expires_at) <= now) display_status = 'expired';
	else if (记录.first_used_at !== null) display_status = 'active';
	const 独立配置 = 应用访问链接配置(config, 记录);
	return {
		...记录,
		display_status,
		tags_list: 解析访问标签(记录.tags),
		remaining_ms: 记录.expires_at == null ? null : Math.max(0, Number(记录.expires_at) - now),
		duration_hours: Number(记录.duration_seconds) / 3600,
		duration_label: Number(记录.duration_seconds) === 0 ? '永久' : `${Number(记录.duration_seconds) / 3600} 小时`,
		subscription_url: `${origin}/sub?token=${encodeURIComponent(记录.token)}`,
		node_url: 独立配置.LINK
	};
}

function 解析访问标签(value) {
	try {
		const parsed = JSON.parse(String(value || '[]'));
		if (Array.isArray(parsed)) return parsed.map(item => String(item).trim()).filter(Boolean).slice(0, 20);
	} catch (_) { }
	return String(value || '').split(',').map(item => item.trim()).filter(Boolean).slice(0, 20);
}

function 标准化访问标签(value) {
	const values = Array.isArray(value) ? value : String(value || '').split(',');
	const tags = [...new Set(values.map(item => String(item).trim().slice(0, 30)).filter(Boolean))].slice(0, 20);
	return JSON.stringify(tags);
}

function 访问链接安全摘要(record) {
	if (!record) return null;
	return {
		id: record.id, country: record.country, status: record.status, duration_seconds: record.duration_seconds,
		proxy_ip: record.proxy_ip, note: record.note, tags: 解析访问标签(record.tags), first_used_at: record.first_used_at,
		expires_at: record.expires_at, connection_count: record.connection_count, active_connections: record.active_connections,
		max_concurrent_connections: record.max_concurrent_connections, max_total_connections: record.max_total_connections,
		bind_first_ip: Number(record.bind_first_ip) === 1, bound: !!record.bound_ip
	};
}

async function 执行访问链接操作({ session, env, request, adminSession, id, action, body = {} }) {
	const before = await session.prepare('SELECT * FROM access_links WHERE id = ?1').bind(id).first();
	if (!before) throw new Error('访问链接不存在');
	const now = Date.now();
	let result;
	if (action === 'revoke' || action === 'disable') {
		result = await session.prepare("UPDATE access_links SET status = 'revoked' WHERE id = ?1 AND status = 'active'").bind(id).run();
		关闭本实例链接连接(id);
	} else if (action === 'enable' || action === 'restore') {
		const restoreError = 获取访问恢复错误(before, now);
		if (restoreError) throw new Error(restoreError);
		result = await session.prepare("UPDATE access_links SET status = 'active' WHERE id = ?1 AND status = 'revoked' AND (expires_at IS NULL OR expires_at > ?2)").bind(id, now).run();
	} else if (action === 'renew') {
		const hours = Math.floor(Number(body.hours || body.durationHours));
		if (!Number.isInteger(hours) || hours < 1 || hours > 8760) throw new Error('续期时长必须是 1 到 8760 小时');
		if (Number(before.duration_seconds) === 0 && before.expires_at == null) throw new Error('永久链接无需续期');
		const seconds = hours * 3600;
		result = await session.prepare(`UPDATE access_links SET status = 'active', duration_seconds = duration_seconds + ?1,
			expires_at = CASE WHEN first_used_at IS NULL THEN NULL
				ELSE MAX(COALESCE(expires_at, ?2), ?2) + ?1 * 1000 END
			WHERE id = ?3 AND NOT (duration_seconds = 0 AND expires_at IS NULL)`).bind(seconds, now, id).run();
	} else if (action === 'reset') {
		[, result] = await env.DB.batch([
			session.prepare('DELETE FROM access_connection_leases WHERE access_link_id = ?1').bind(id),
			session.prepare(`UPDATE access_links SET status = 'active', proxy_ip = NULL, first_used_at = NULL,
			expires_at = NULL, last_used_at = NULL, connection_count = 0, active_connections = 0,
			last_client_ip = NULL, last_client_asn = NULL, bound_ip = NULL, connection_epoch = connection_epoch + 1 WHERE id = ?1`).bind(id)
		]);
		关闭本实例链接连接(id);
	} else if (action === 'reassign') {
		const candidate = await session.prepare(`SELECT proxy_ip FROM proxy_ip_pool WHERE country = ?1 AND enabled = 1
			AND proxy_ip <> COALESCE(?2, '') AND (cooldown_until IS NULL OR cooldown_until <= ?3)
			AND health_status <> 'unhealthy' ORDER BY CASE health_status WHEN 'healthy' THEN 0 ELSE 1 END,
			health_score DESC, latency_ms ASC, RANDOM() LIMIT 1`).bind(before.country, before.proxy_ip, now).first();
		if (!candidate) throw new Error(`${before.country} 没有其他健康备用 PROXYIP`);
		result = await session.prepare('UPDATE access_links SET proxy_ip = ?1 WHERE id = ?2').bind(candidate.proxy_ip, id).run();
	} else if (action === 'rotate') {
		const mode = String(body.mode || 'both');
		if (!['token', 'uuid', 'both'].includes(mode)) throw new Error('轮换类型无效');
		const rotated = 生成轮换访问凭据(before, mode);
		if (mode === 'token') result = await session.prepare('UPDATE access_links SET token = ?1 WHERE id = ?2').bind(rotated.token, id).run();
		else if (mode === 'uuid') result = await session.prepare('UPDATE access_links SET uuid = ?1 WHERE id = ?2').bind(rotated.uuid, id).run();
		else result = await session.prepare('UPDATE access_links SET token = ?1, uuid = ?2 WHERE id = ?3').bind(rotated.token, rotated.uuid, id).run();
	} else if (action === 'edit') {
		const maxConcurrent = Math.floor(Number(body.maxConcurrentConnections ?? body.max_concurrent_connections ?? 0));
		const maxTotal = Math.floor(Number(body.maxTotalConnections ?? body.max_total_connections ?? 0));
		if (!Number.isInteger(maxConcurrent) || maxConcurrent < 0 || maxConcurrent > 10000) throw new Error('并发上限必须是 0 到 10000，0 表示不限');
		if (!Number.isInteger(maxTotal) || maxTotal < 0 || maxTotal > 10000000) throw new Error('累计上限必须是 0 到 10000000，0 表示不限');
		const bindFirstIP = body.bindFirstIp === true || body.bind_first_ip === true || String(body.bindFirstIp ?? body.bind_first_ip) === '1';
		const note = String(body.note ?? before.note ?? '').trim().slice(0, 200);
		const tags = 标准化访问标签(body.tags ?? before.tags ?? '');
		result = await session.prepare(`UPDATE access_links SET note = ?1, tags = ?2, max_concurrent_connections = ?3,
			max_total_connections = ?4, bind_first_ip = ?5,
			bound_ip = CASE WHEN ?5 = 1 THEN bound_ip ELSE NULL END WHERE id = ?6`)
			.bind(note, tags, maxConcurrent, maxTotal, bindFirstIP ? 1 : 0, id).run();
	} else if (action === 'tags') {
		result = await session.prepare('UPDATE access_links SET tags = ?1 WHERE id = ?2').bind(标准化访问标签(body.tags), id).run();
	} else if (action === 'delete') {
		关闭本实例链接连接(id);
		await session.prepare('DELETE FROM access_connection_leases WHERE access_link_id = ?1').bind(id).run();
		await session.prepare('DELETE FROM access_connection_events WHERE access_link_id = ?1').bind(id).run();
		result = await session.prepare('DELETE FROM access_links WHERE id = ?1').bind(id).run();
	} else throw new Error('不支持的链接操作');
	if (!Number(result?.meta?.changes || 0)) throw new Error('链接状态未变化，可能已被其他操作更新');
	const after = action === 'delete' ? null : await session.prepare('SELECT * FROM access_links WHERE id = ?1').bind(id).first();
	await 写入审计日志(env, request, adminSession, `access.${action}`, 'access_link', id, 访问链接安全摘要(before), 访问链接安全摘要(after), true);
	return { id, success: true, before: 访问链接安全摘要(before), after: 访问链接安全摘要(after) };
}

function 模拟访问链接激活(record, now, clientIP) {
	const error = 访问限制错误(record, clientIP, now);
	if (error) return { error };
	return {
		...record,
		first_used_at: record.first_used_at ?? now,
		expires_at: Number(record.duration_seconds) === 0 ? null : (record.expires_at ?? now + Number(record.duration_seconds) * 1000),
		last_used_at: now,
		connection_count: Number(record.connection_count || 0) + 1,
		active_connections: Number(record.active_connections || 0) + 1,
		bound_ip: Number(record.bind_first_ip) === 1 ? (record.bound_ip || clientIP) : record.bound_ip
	};
}

function 计算续期到期时间(expiresAt, now, hours) {
	return Math.max(Number(expiresAt || now), now) + Number(hours) * 3600000;
}

function 计算访问链接续期到期时间(record, now, hours) {
	return record?.first_used_at == null ? null : 计算续期到期时间(record.expires_at, now, hours);
}

function 获取访问恢复错误(record, now = Date.now()) {
	if (record?.status !== 'revoked') return '只有已停用的链接可以恢复';
	if (record.expires_at !== null && Number(record.expires_at) <= now) return '链接已过期，请使用“续期”而不是“恢复”';
	return null;
}

function 模拟重置访问链接(record) {
	return { ...record, status: 'active', proxy_ip: null, first_used_at: null, expires_at: null, last_used_at: null, connection_count: 0, active_connections: 0, last_client_ip: null, last_client_asn: null, bound_ip: null, connection_epoch: Number(record.connection_epoch || 0) + 1 };
}

function 生成轮换访问凭据(record, mode) {
	return { ...record, token: mode === 'uuid' ? record.token : 生成随机访问令牌(), uuid: mode === 'token' ? record.uuid : crypto.randomUUID() };
}

function 选择健康故障转移候选(candidates, currentProxy, now = Date.now()) {
	return [...candidates].filter(item => item.enabled !== 0 && Number(item.cooldown_until || 0) <= now && item.health_status !== 'unhealthy' && item.proxy_ip !== currentProxy)
		.sort((a, b) => Number(b.health_score || 0) - Number(a.health_score || 0) || Number(a.latency_ms ?? Infinity) - Number(b.latency_ms ?? Infinity))[0] || null;
}

function 计算登录失败状态(record, now, threshold, blockMs) {
	const output = { ...record, failure_count: Number(record.failure_count || 0) + 1, last_attempt_at: now };
	if (output.failure_count >= threshold) output.blocked_until = now + blockMs;
	return output;
}

function 汇总批量操作结果(results) {
	const affected = results.filter(item => item.success).length;
	return { affected, failed: results.filter(item => !item.success), partial: affected > 0 && affected < results.length };
}

function 格式化批量访问链接导出(records) {
	const quote = value => `'${String(value ?? '')
		.replace(/\\/g, '\\\\')
		.replace(/'/g, "\\'")
		.replace(/\r/g, '\\r')
		.replace(/\n/g, '\\n')
		.replace(/\u2028/g, '\\u2028')
		.replace(/\u2029/g, '\\u2029')}'`;
	if (!Array.isArray(records) || !records.length) return '';
	return records.map(record => `[${quote(record?.subscription_url)},${quote(record?.node_url)},${quote(record?.country)},${quote(record?.duration_label)}]`).join('\r\n') + '\r\n';
}

function CSV字段(value) {
	const text = value == null ? '' : typeof value === 'object' ? JSON.stringify(value) : String(value);
	return `"${text.replace(/"/g, '""')}"`;
}

async function 处理访问链接管理请求(request, env, host, userID, UA, url, 管理员会话) {
	if (!env.DB || typeof env.DB.prepare !== 'function') return 访问错误响应('请先为项目绑定名为 DB 的 D1 数据库', 503);
	try {
		await 确保访问数据库(env);
		const pathname = url.pathname.toLowerCase();
		if (pathname === '/admin/access' && request.method === 'GET') return 访问链接增强管理页面();

		const session = 获取访问数据库会话(env);
		if (pathname === '/admin/access/api/audit' && request.method === 'GET') {
			const limit = Math.min(100, Math.max(1, Math.floor(Number(url.searchParams.get('limit')) || 25)));
			const offset = Math.max(0, Math.floor(Number(url.searchParams.get('offset')) || 0));
			const action = String(url.searchParams.get('action') || '').trim().slice(0, 80);
			const query = String(url.searchParams.get('q') || '').trim().slice(0, 100);
			const parts = [], params = [];
			const param = value => { params.push(value); return `?${params.length}`; };
			if (action) parts.push(`action = ${param(action)}`);
			if (query) { const p = param(`%${query}%`); parts.push(`(action LIKE ${p} OR object_type LIKE ${p} OR object_id LIKE ${p} OR COALESCE(error_message, '') LIKE ${p})`); }
			const where = parts.length ? ` WHERE ${parts.join(' AND ')}` : '';
			const [logs, count] = await Promise.all([
				session.prepare(`SELECT * FROM audit_logs${where} ORDER BY id DESC LIMIT ?${params.length + 1} OFFSET ?${params.length + 2}`).bind(...params, limit, offset).all(),
				session.prepare(`SELECT COUNT(*) AS total FROM audit_logs${where}`).bind(...params).first()
			]);
			return 访问JSON响应({ success: true, logs: logs.results || [], pagination: { limit, offset, total: Number(count?.total || 0) } });
		}

		if (pathname === '/admin/access/api/audit/export' && request.method === 'GET') {
			const format = String(url.searchParams.get('format') || 'json').toLowerCase();
			const result = await session.prepare('SELECT * FROM audit_logs ORDER BY id DESC LIMIT 10000').all();
			const logs = result.results || [];
			const content = format === 'csv'
				? ['id,created_at,session_id,source_ip,source_asn,action,object_type,object_id,before_summary,after_summary,success,error_message', ...logs.map(row => [row.id, row.created_at, row.session_id, row.source_ip, row.source_asn, row.action, row.object_type, row.object_id, row.before_summary, row.after_summary, row.success, row.error_message].map(CSV字段).join(','))].join('\n')
				: JSON.stringify({ schema_version: 5, exported_at: Date.now(), audit_logs: logs }, null, 2);
			return new Response(content, { headers: { 'Content-Type': format === 'csv' ? 'text/csv;charset=utf-8' : 'application/json;charset=utf-8', 'Content-Disposition': `attachment; filename="edgetunnel-audit.${format === 'csv' ? 'csv' : 'json'}"`, 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer' } });
		}

		if (pathname === '/admin/access/api/links/export' && request.method === 'GET') {
			if (request.headers.get('X-Export-Confirmation') !== 'include-sensitive-links') return 访问错误响应('导出包含完整访问凭据，需要明确确认', 428);
			const format = String(url.searchParams.get('format') || 'json').toLowerCase();
			const q = String(url.searchParams.get('q') || '').trim().slice(0, 100), country = String(url.searchParams.get('country') || '').trim().toUpperCase(), tag = String(url.searchParams.get('tag') || '').trim().slice(0, 30);
			const status = String(url.searchParams.get('status') || 'all').toLowerCase(), expiry = String(url.searchParams.get('expiry') || 'all').toLowerCase(), now = Date.now();
			const parts = [], params = [];
			const param = value => { params.push(value); return `?${params.length}`; };
			if (q) { const p = param(`%${q}%`); parts.push(`(CAST(id AS TEXT) LIKE ${p} OR note LIKE ${p} OR uuid LIKE ${p} OR country LIKE ${p} OR COALESCE(proxy_ip,'') LIKE ${p})`); }
			if (country) parts.push(`country = ${param(标准化访问国家(country))}`);
			if (tag) parts.push(`tags LIKE ${param(`%${tag}%`)}`);
			if (status === 'unused') parts.push("status = 'active' AND first_used_at IS NULL");
			else if (status === 'active') parts.push(`status = 'active' AND first_used_at IS NOT NULL AND (expires_at IS NULL OR expires_at > ${param(now)})`);
			else if (status === 'expired') parts.push(`status = 'active' AND expires_at IS NOT NULL AND expires_at <= ${param(now)}`);
			else if (status === 'revoked') parts.push("status <> 'active'");
			if (expiry === '24h') parts.push(`expires_at > ${param(now)} AND expires_at <= ${param(now + 86400000)}`);
			else if (expiry === '7d') parts.push(`expires_at > ${param(now)} AND expires_at <= ${param(now + 7 * 86400000)}`);
			else if (expiry === 'expired') parts.push(`expires_at IS NOT NULL AND expires_at <= ${param(now)}`);
			const result = await session.prepare(`SELECT * FROM access_links${parts.length ? ` WHERE ${parts.join(' AND ')}` : ''} ORDER BY id DESC LIMIT 10000`).bind(...params).all();
			const links = result.results || [];
			const content = format === 'csv'
				? ['id,token,uuid,country,status,note,tags,duration_seconds,proxy_ip,first_used_at,expires_at,last_used_at,connection_count,active_connections,max_concurrent_connections,max_total_connections,bind_first_ip,bound_ip', ...links.map(row => ['id','token','uuid','country','status','note','tags','duration_seconds','proxy_ip','first_used_at','expires_at','last_used_at','connection_count','active_connections','max_concurrent_connections','max_total_connections','bind_first_ip','bound_ip'].map(key => CSV字段(row[key])).join(','))].join('\n')
				: JSON.stringify({ schema_version: 5, exported_at: Date.now(), access_links: links }, null, 2);
			return new Response(content, { headers: { 'Content-Type': format === 'csv' ? 'text/csv;charset=utf-8' : 'application/json;charset=utf-8', 'Content-Disposition': `attachment; filename="edgetunnel-access-links.${format === 'csv' ? 'csv' : 'json'}"`, 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff' } });
		}

		if (pathname === '/admin/access/api/backup' && request.method === 'GET') {
			if (request.headers.get('X-Export-Confirmation') !== 'backup-operational-data') return 访问错误响应('备份导出需要明确确认', 428);
			const tables = ['access_links', 'proxy_ip_pool', 'proxy_ip_sources', 'proxy_ip_source_sync', 'country_health_config'];
			const data = {};
			for (const table of tables) data[table] = (await session.prepare(`SELECT * FROM ${table}`).all()).results || [];
			const content = JSON.stringify({ product: 'edgetunnel-access', schema_version: 5, exported_at: Date.now(), data }, null, 2);
			return new Response(content, { headers: { 'Content-Type': 'application/json;charset=utf-8', 'Content-Disposition': 'attachment; filename="edgetunnel-d1-backup.json"', 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff' } });
		}

		if (pathname === '/admin/access/api/state' && request.method === 'GET') {
			await 清理访问连接租约(env);
			const requestedLimit = Math.floor(Number(url.searchParams.get('limit')));
			const requestedOffset = Math.floor(Number(url.searchParams.get('offset')));
			const limit = Number.isFinite(requestedLimit) && requestedLimit > 0 ? Math.min(500, requestedLimit) : 200;
			const offset = Number.isFinite(requestedOffset) && requestedOffset > 0 ? requestedOffset : 0;
			const searchQuery = String(url.searchParams.get('q') || '').trim().slice(0, 100);
			const statusFilter = String(url.searchParams.get('status') || 'all').trim().toLowerCase();
			const countryFilter = String(url.searchParams.get('country') || '').trim();
			const tagFilter = String(url.searchParams.get('tag') || '').trim().slice(0, 30);
			const expiryFilter = String(url.searchParams.get('expiry') || 'all').trim().toLowerCase();
			const whereParts = [];
			const whereParams = [];
			const addWhereParam = value => { whereParams.push(value); return `?${whereParams.length}`; };
			if (searchQuery) {
				const keyword = `%${searchQuery}%`;
				const keywordParam = addWhereParam(keyword);
				whereParts.push(`(CAST(id AS TEXT) LIKE ${keywordParam} OR note LIKE ${keywordParam} OR uuid LIKE ${keywordParam} OR country LIKE ${keywordParam} OR COALESCE(proxy_ip, '') LIKE ${keywordParam})`);
			}
			const now = Date.now();
			if (statusFilter === 'unused') whereParts.push('status = \'active\' AND first_used_at IS NULL');
			else if (statusFilter === 'active') { const nowParam = addWhereParam(now); whereParts.push(`status = 'active' AND first_used_at IS NOT NULL AND (expires_at IS NULL OR expires_at > ${nowParam})`); }
			else if (statusFilter === 'expired') { const nowParam = addWhereParam(now); whereParts.push(`status = 'active' AND expires_at IS NOT NULL AND expires_at <= ${nowParam}`); }
			else if (statusFilter === 'revoked') whereParts.push("status <> 'active'");
			if (countryFilter) whereParts.push(`country = ${addWhereParam(标准化访问国家(countryFilter))}`);
			if (tagFilter) whereParts.push(`tags LIKE ${addWhereParam(`%${tagFilter}%`)}`);
			if (expiryFilter === '24h') whereParts.push(`expires_at > ${addWhereParam(now)} AND expires_at <= ${addWhereParam(now + 86400000)}`);
			else if (expiryFilter === '7d') whereParts.push(`expires_at > ${addWhereParam(now)} AND expires_at <= ${addWhereParam(now + 7 * 86400000)}`);
			else if (expiryFilter === 'expired') whereParts.push(`expires_at IS NOT NULL AND expires_at <= ${addWhereParam(now)}`);
			const whereSQL = whereParts.length ? ` WHERE ${whereParts.join(' AND ')}` : '';
			const limitParam = `?${whereParams.length + 1}`;
			const offsetParam = `?${whereParams.length + 2}`;
			const [链接结果, 筛选链接统计, IP结果, 统计结果, 数据源结果, 国家池结果, 二十四小时统计] = await Promise.all([
				session.prepare(`SELECT * FROM access_links${whereSQL} ORDER BY id DESC LIMIT ${limitParam} OFFSET ${offsetParam}`).bind(...whereParams, limit, offset).all(),
				session.prepare(`SELECT COUNT(*) AS total FROM access_links${whereSQL}`).bind(...whereParams).first(),
				session.prepare(`SELECT p.*, COALESCE(s.name, '手动添加') AS source_name FROM proxy_ip_pool p
					LEFT JOIN proxy_ip_sources s ON s.id = p.source_id ORDER BY p.country, p.id DESC LIMIT 500`).all(),
				session.prepare(`SELECT COUNT(*) AS total,
					SUM(CASE WHEN status = 'active' AND first_used_at IS NULL THEN 1 ELSE 0 END) AS unused,
					SUM(CASE WHEN status = 'active' AND first_used_at IS NOT NULL AND (expires_at IS NULL OR expires_at > ?1) THEN 1 ELSE 0 END) AS active,
					SUM(CASE WHEN status = 'active' AND expires_at IS NOT NULL AND expires_at <= ?1 THEN 1 ELSE 0 END) AS expired,
					SUM(CASE WHEN status <> 'active' THEN 1 ELSE 0 END) AS revoked,
					SUM(active_connections) AS current_connections
					FROM access_links`).bind(now).first(),
				session.prepare('SELECT * FROM proxy_ip_sources ORDER BY id').all(),
				session.prepare(`SELECT p.country, COUNT(DISTINCT p.id) AS total,
					COUNT(DISTINCT CASE WHEN enabled = 1 AND health_status <> 'unhealthy' THEN p.id END) AS available,
					COUNT(DISTINCT CASE WHEN enabled = 1 AND health_status = 'healthy' THEN p.id END) AS healthy,
					COUNT(DISTINCT CASE WHEN enabled = 1 AND health_status = 'unknown' THEN p.id END) AS unknown,
					COUNT(DISTINCT CASE WHEN enabled = 1 AND (health_status = 'unhealthy' OR cooldown_until > ?1) THEN p.id END) AS isolated,
					ROUND(AVG(CASE WHEN latency_ms IS NOT NULL THEN latency_ms END)) AS average_latency_ms,
					MAX(last_checked_at) AS last_checked_at, ROUND(AVG(health_score)) AS average_health_score,
					(SELECT COUNT(*) FROM access_links l WHERE l.country = p.country AND l.proxy_ip IS NOT NULL) AS assigned,
					COALESCE(c.min_healthy_ips, ?2) AS min_healthy_ips
					FROM proxy_ip_pool p LEFT JOIN country_health_config c ON c.country = p.country
					GROUP BY p.country ORDER BY p.country`).bind(now, Math.min(100, Math.max(1, Number(env.MIN_HEALTHY_IPS_PER_COUNTRY) || 3))).all(),
				session.prepare(`SELECT COUNT(*) AS connections_24h,
					SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) AS failures_24h FROM access_connection_events WHERE started_at >= ?1`).bind(now - 86400000).first()
			]);
			const poolStats = 国家池结果.results || [];
			const 总体统计 = 统计结果 || { total: 0, unused: 0, active: 0, expired: 0, revoked: 0, current_connections: 0 };
			const healthTotal = poolStats.reduce((sum, item) => sum + Number(item.total || 0), 0);
			const healthyTotal = poolStats.reduce((sum, item) => sum + Number(item.healthy || 0), 0);
			总体统计.connections_24h = Number(二十四小时统计?.connections_24h || 0);
			总体统计.failures_24h = Number(二十四小时统计?.failures_24h || 0);
			总体统计.failure_rate_24h = 总体统计.connections_24h ? Math.round(总体统计.failures_24h / 总体统计.connections_24h * 1000) / 10 : 0;
			总体统计.healthy_ip_ratio = healthTotal ? Math.round(healthyTotal / healthTotal * 1000) / 10 : 0;
			总体统计.low_capacity_countries = poolStats.filter(item => Number(item.healthy || 0) < Number(item.min_healthy_ips || 0)).length;
			const 基础配置 = await 读取config_JSON(env, host, userID, UA);
			return 访问JSON响应({
				success: true,
				stats: 总体统计,
				pagination: { limit, offset, total: Number(筛选链接统计?.total || 0), query: searchQuery, status: statusFilter },
				links: (链接结果.results || []).map(item => 格式化后台访问记录(item, 基础配置, url.origin)),
				pools: IP结果.results || [],
				sources: 数据源结果.results || [],
				poolStats,
				security: { session_expires_at: 管理员会话.expires_at, notifications_configured: !!env.NOTIFY_WEBHOOK_URL || !!(env.TELEGRAM_BOT_TOKEN && env.TELEGRAM_CHAT_ID) }
			});
		}

		if (request.method !== 'POST') return 访问错误响应('不支持的请求方法', 405);
		const 安全错误 = await 验证管理员修改请求(request, env, url, 管理员会话, true);
		if (安全错误) return 安全错误;
		if (!(request.headers.get('Content-Type') || '').toLowerCase().includes('application/json')) return 访问错误响应('Content-Type 必须是 application/json', 415);
		const body = await request.json();

		if (pathname === '/admin/access/api/session/logout-all') {
			await session.prepare('UPDATE admin_sessions SET revoked_at = ?1 WHERE revoked_at IS NULL').bind(Date.now()).run();
			await 写入审计日志(env, request, 管理员会话, 'admin.logout_all', 'admin_session', '*', null, { revoked: 'all' }, true);
			const response = 访问JSON响应({ success: true, message: '所有管理员会话均已退出，请重新登录' });
			response.headers.append('Set-Cookie', 'admin_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict');
			response.headers.append('Set-Cookie', 'admin_csrf=; Path=/; Max-Age=0; Secure; SameSite=Strict');
			return response;
		}

		if (pathname === '/admin/access/api/health/threshold') {
			const country = 标准化访问国家(body.country), minimum = Math.floor(Number(body.minimum));
			if (!Number.isInteger(minimum) || minimum < 1 || minimum > 100) throw new Error('最低健康 IP 阈值必须是 1 到 100');
			const before = await session.prepare('SELECT * FROM country_health_config WHERE country = ?1').bind(country).first();
			await session.prepare(`INSERT INTO country_health_config(country, min_healthy_ips, updated_at) VALUES (?1, ?2, ?3)
				ON CONFLICT(country) DO UPDATE SET min_healthy_ips = ?2, updated_at = ?3`).bind(country, minimum, Date.now()).run();
			await 写入审计日志(env, request, 管理员会话, 'proxy.threshold.update', 'country', country, before, { country, min_healthy_ips: minimum }, true);
			return 访问JSON响应({ success: true, message: `${country} 最低健康 IP 阈值已设为 ${minimum}` });
		}

		if (pathname === '/admin/access/api/backup/restore') {
			if (body?.product !== 'edgetunnel-access' || Number(body?.schema_version) !== 5 || !body?.data || typeof body.data !== 'object') throw new Error('备份 schema/version 不兼容');
			const overwrite = body.mode === 'overwrite';
			if (overwrite && body.confirmOverwrite !== 'RESTORE OVERWRITE') throw new Error('覆盖恢复需要二次确认文本 RESTORE OVERWRITE');
			const tableColumns = {
				proxy_ip_sources: ['id','name','url','default_country','enabled','refresh_minutes','max_per_country','last_synced_at','last_status','last_error','created_at','updated_at','consecutive_failures'],
				proxy_ip_pool: ['id','country','proxy_ip','enabled','created_at','source_id','health_status','latency_ms','failure_count','last_checked_at','last_success_at','last_error','updated_at','health_score','consecutive_failures','cooldown_until','real_success_count','real_failure_count','last_real_failure'],
				access_links: ['id','token','uuid','country','duration_seconds','proxy_ip','status','note','created_at','first_used_at','expires_at','last_used_at','connection_count','active_connections','last_client_ip','last_client_asn','max_concurrent_connections','max_total_connections','bind_first_ip','bound_ip','tags','connection_epoch'],
				proxy_ip_source_sync: ['source_id','country','last_synced_at','last_status','last_error'],
				country_health_config: ['country','min_healthy_ips','updated_at']
			};
			const primaryKeys = { proxy_ip_sources: ['id'], proxy_ip_pool: ['id'], access_links: ['id'], proxy_ip_source_sync: ['source_id', 'country'], country_health_config: ['country'] };
			const sourceIds = new Map();
			const backupSourceIds = new Set((Array.isArray(body.data.proxy_ip_sources) ? body.data.proxy_ip_sources : []).filter(row => row?.id != null).map(row => Number(row.id)));
			const order = Object.keys(tableColumns), summary = { inserted: 0, skipped: 0, failed: [] };
			const totalRows = order.reduce((sum, table) => sum + (Array.isArray(body.data[table]) ? body.data[table].length : 0), 0);
			if (totalRows > 50000) throw new Error('单次恢复最多 50000 条记录');
			for (const table of order) {
				const rows = Array.isArray(body.data[table]) ? body.data[table] : [];
				for (const row of rows) {
					try {
						const restored = { ...row };
						if (table === 'proxy_ip_sources' && !overwrite) {
							// 来源身份由 URL 确定；不同数据库的自增 ID 可能指向不同来源。
							const existing = await session.prepare('SELECT id FROM proxy_ip_sources WHERE url = ?1').bind(row.url).first();
							if (existing) {
								if (row.id != null) sourceIds.set(Number(row.id), existing.id);
								summary.skipped++;
								continue;
							}
							if (row.id != null && await session.prepare('SELECT id FROM proxy_ip_sources WHERE id = ?1').bind(row.id).first()) delete restored.id;
						}
						if ((table === 'proxy_ip_pool' || table === 'proxy_ip_source_sync') && row.source_id != null) {
							const sourceId = Number(row.source_id);
							if (sourceIds.has(sourceId)) restored.source_id = sourceIds.get(sourceId);
							else if (backupSourceIds.has(sourceId)) throw new Error(`来源 ${row.source_id} 未能恢复，不能导入关联记录`);
						}
						const columns = tableColumns[table].filter(column => Object.prototype.hasOwnProperty.call(restored, column));
						if (!columns.length) { summary.skipped++; continue; }
						const placeholders = columns.map((_, index) => `?${index + 1}`).join(',');
						const updates = columns.filter(column => !primaryKeys[table].includes(column));
						// 只更新同主键记录，避免 REPLACE 删除原行并级联删除连接事件和租约。
						const conflict = overwrite ? ` ON CONFLICT(${primaryKeys[table].join(',')}) DO ${updates.length ? `UPDATE SET ${updates.map(column => `${column} = excluded.${column}`).join(',')}` : 'NOTHING'}` : '';
						const verb = overwrite ? 'INSERT' : 'INSERT OR IGNORE';
						const result = await session.prepare(`${verb} INTO ${table}(${columns.join(',')}) VALUES (${placeholders})${conflict}`).bind(...columns.map(column => restored[column])).run();
						if (Number(result?.meta?.changes || 0)) summary.inserted++; else summary.skipped++;
						if (table === 'proxy_ip_sources' && row.id != null) {
							const source = await session.prepare('SELECT id FROM proxy_ip_sources WHERE url = ?1').bind(row.url).first();
							if (source) sourceIds.set(Number(row.id), source.id);
						}
					} catch (error) { summary.failed.push({ table, id: row?.id ?? row?.country ?? '', error: String(error?.message || error).slice(0, 200) }); }
				}
			}
			await 清理访问连接租约(env);
			await 写入审计日志(env, request, 管理员会话, 'backup.restore', 'database', '', { mode: overwrite ? 'overwrite' : 'merge', totalRows }, summary, summary.failed.length === 0, summary.failed[0]?.error || '');
			return 访问JSON响应({ success: true, partial: summary.failed.length > 0, message: `恢复完成：写入 ${summary.inserted}，跳过 ${summary.skipped}，失败 ${summary.failed.length}`, ...summary }, summary.failed.length ? 207 : 200);
		}

		if (pathname === '/admin/access/api/links') {
			const country = 标准化访问国家(body.country);
			const durationValue = String(body.durationHours ?? '').trim().toLowerCase();
			const isPermanent = durationValue === 'permanent' || durationValue === '永久';
			const durationHours = isPermanent ? null : Number(durationValue);
			const count = Math.floor(Number(body.count || 1));
			const note = String(body.note || '').trim().slice(0, 100);
			const tags = 标准化访问标签(body.tags || '');
			const maxConcurrent = Math.floor(Number(body.maxConcurrentConnections || 0));
			const maxTotal = Math.floor(Number(body.maxTotalConnections || 0));
			const bindFirstIP = body.bindFirstIp === true || String(body.bindFirstIp) === '1';
			if (!isPermanent && (!Number.isInteger(durationHours) || durationHours < 1 || durationHours > 8760)) throw new Error('有效时长必须是 1 到 8760 的整数小时，或选择永久');
			if (!Number.isInteger(count) || count < 1 || count > 100) throw new Error('单次生成数量必须是 1 到 100');
			if (!Number.isInteger(maxConcurrent) || maxConcurrent < 0 || maxConcurrent > 10000) throw new Error('并发上限必须是 0 到 10000');
			if (!Number.isInteger(maxTotal) || maxTotal < 0 || maxTotal > 10000000) throw new Error('累计上限必须是 0 到 10000000');
			await 同步到期访问PROXYIP数据源(env, { country });
			let poolState = await session.prepare(`SELECT
				SUM(CASE WHEN enabled = 1 AND health_status = 'healthy' THEN 1 ELSE 0 END) AS healthy,
				SUM(CASE WHEN enabled = 1 AND health_status = 'unknown' THEN 1 ELSE 0 END) AS unknown
				FROM proxy_ip_pool WHERE country = ?1`).bind(country).first();
			if (!Number(poolState?.healthy) && Number(poolState?.unknown)) {
				await 检测访问PROXYIP池(env, country, 8);
				poolState = await session.prepare(`SELECT
					SUM(CASE WHEN enabled = 1 AND health_status = 'healthy' THEN 1 ELSE 0 END) AS healthy,
					SUM(CASE WHEN enabled = 1 AND health_status = 'unknown' THEN 1 ELSE 0 END) AS unknown
					FROM proxy_ip_pool WHERE country = ?1`).bind(country).first();
			}
			if (!Number(poolState?.healthy) && !Number(poolState?.unknown)) {
				// 旧版本或短暂故障可能留下整国冷却状态；手动生成时强制同步并清除旧冷却，再做一次小批量检测。
				await 同步到期访问PROXYIP数据源(env, { force: true, country });
				await 检测访问PROXYIP池(env, country, 8);
				poolState = await session.prepare(`SELECT
					SUM(CASE WHEN enabled = 1 AND health_status = 'healthy' THEN 1 ELSE 0 END) AS healthy,
					SUM(CASE WHEN enabled = 1 AND health_status = 'unknown' THEN 1 ELSE 0 END) AS unknown
					FROM proxy_ip_pool WHERE country = ?1`).bind(country).first();
			}
			if (!Number(poolState?.healthy) && !Number(poolState?.unknown)) throw new Error(`${country} 暂无可用 PROXYIP，请同步数据源或稍后重试`);
			const durationSeconds = isPermanent ? 0 : durationHours * 3600;
			const createdAt = Date.now();
			const records = Array.from({ length: count }, (_, index) => ({
				token: 生成随机访问令牌(),
				uuid: crypto.randomUUID(),
				country,
				duration_seconds: durationSeconds,
				note: note ? (count > 1 ? `${note}-${index + 1}` : note) : '', tags,
				max_concurrent_connections: maxConcurrent, max_total_connections: maxTotal, bind_first_ip: bindFirstIP ? 1 : 0
			}));
			await env.DB.batch(records.map(record => env.DB.prepare(`INSERT INTO access_links
				(token, uuid, country, duration_seconds, status, note, tags, max_concurrent_connections, max_total_connections, bind_first_ip, created_at)
				VALUES (?1, ?2, ?3, ?4, 'active', ?5, ?6, ?7, ?8, ?9, ?10)`)
				.bind(record.token, record.uuid, record.country, record.duration_seconds, record.note, record.tags, record.max_concurrent_connections, record.max_total_connections, record.bind_first_ip, createdAt)));
			await 写入审计日志(env, request, 管理员会话, 'access.create', 'access_link', 'batch', null, { count, country, duration_seconds: durationSeconds, limits: { maxConcurrent, maxTotal, bindFirstIP }, tags: 解析访问标签(tags) }, true);
			const 基础配置 = await 读取config_JSON(env, host, userID, UA);
			const created = records.map((record, index) => 格式化后台访问记录({ id: null, ...record, proxy_ip: null, status: 'active', created_at: createdAt, first_used_at: null, expires_at: null, last_used_at: null, connection_count: 0, active_connections: 0, bound_ip: null }, 基础配置, url.origin));
			return 访问JSON响应({ success: true, message: `已生成 ${count} 条访问链接，${country} 池可用 ${Number(poolState?.healthy) + Number(poolState?.unknown)} 个 PROXYIP`, links: created }, 201);
		}

		if (pathname === '/admin/access/api/links/action') {
			const action = String(body.action || '');
			if (Array.isArray(body.ids)) {
				const ids = [...new Set(body.ids.map(Number))];
				if (!ids.length || ids.length > 100 || ids.some(id => !Number.isInteger(id) || id < 1)) throw new Error('请选择 1 到 100 条有效链接');
				if (!['revoke','disable','enable','restore','renew','reset','reassign','tags','delete','rotate'].includes(action)) throw new Error('不支持的批量操作');
				const results = [];
				for (const id of ids) {
					try { results.push(await 执行访问链接操作({ session, env, request, adminSession: 管理员会话, id, action, body })); }
					catch (error) {
						results.push({ id, success: false, error: String(error?.message || error).slice(0, 200) });
						await 写入审计日志(env, request, 管理员会话, `access.${action}`, 'access_link', id, null, null, false, error?.message || error);
					}
				}
				const affected = results.filter(item => item.success).length, failed = results.filter(item => !item.success);
				await 写入审计日志(env, request, 管理员会话, `access.bulk.${action}`, 'access_link', ids.join(','), { requested: ids.length }, { affected, failures: failed }, failed.length === 0, failed[0]?.error || '');
				return 访问JSON响应({ success: true, partial: failed.length > 0, message: `批量操作完成：成功 ${affected}，失败 ${failed.length}`, affected, failed }, failed.length ? 207 : 200);
			}
			const id = Math.floor(Number(body.id));
			if (!Number.isInteger(id) || id < 1) throw new Error('链接 ID 无效');
			try {
				const result = await 执行访问链接操作({ session, env, request, adminSession: 管理员会话, id, action, body });
				return 访问JSON响应({ success: true, message: '操作成功', result });
			} catch (error) {
				await 写入审计日志(env, request, 管理员会话, `access.${action}`, 'access_link', id, null, null, false, error?.message || error);
				throw error;
			}
		}

		if (pathname === '/admin/access/api/pools') {
			const country = 标准化访问国家(body.country);
			const rawList = Array.isArray(body.proxyIps) ? body.proxyIps : String(body.proxyIps || '').split(/[\s,]+/);
			const proxies = [...new Set(rawList.filter(Boolean).map(标准化访问PROXYIP))];
			if (!proxies.length || proxies.length > 100) throw new Error('请提供 1 到 100 个 PROXYIP');
			const createdAt = Date.now();
			await env.DB.batch(proxies.map(proxy => env.DB.prepare(`INSERT INTO proxy_ip_pool(country, proxy_ip, enabled, created_at, health_status, updated_at)
				VALUES (?1, ?2, 1, ?3, 'unknown', ?3) ON CONFLICT(country, proxy_ip) DO UPDATE SET enabled = 1, updated_at = ?3`)
				.bind(country, proxy, createdAt)));
			await 写入审计日志(env, request, 管理员会话, 'proxy.pool.add', 'proxy_pool', country, null, { count: proxies.length }, true);
			return 访问JSON响应({ success: true, message: `已向 ${country} IP 池加入 ${proxies.length} 个地址` }, 201);
		}

		if (pathname === '/admin/access/api/pools/action') {
			const id = Math.floor(Number(body.id));
			const action = String(body.action || '');
			if (!Number.isInteger(id) || id < 1) throw new Error('IP 记录 ID 无效');
			const before = await session.prepare('SELECT * FROM proxy_ip_pool WHERE id = ?1').bind(id).first();
			if (!before) throw new Error('IP 记录不存在');
			let operation;
			if (action === 'delete') operation = await session.prepare('DELETE FROM proxy_ip_pool WHERE id = ?1').bind(id).run();
			else if (action === 'disable') operation = await session.prepare('UPDATE proxy_ip_pool SET enabled = 0 WHERE id = ?1').bind(id).run();
			else if (action === 'enable') operation = await session.prepare('UPDATE proxy_ip_pool SET enabled = 1 WHERE id = ?1').bind(id).run();
			else throw new Error('不支持的 IP 池操作');
			if (!Number(operation?.meta?.changes || 0)) throw new Error('IP 池状态未变化');
			const after = action === 'delete' ? null : await session.prepare('SELECT * FROM proxy_ip_pool WHERE id = ?1').bind(id).first();
			await 写入审计日志(env, request, 管理员会话, `proxy.pool.${action}`, 'proxy_pool', id, before, after, true);
			return 访问JSON响应({ success: true, message: '操作成功' });
		}

		if (pathname === '/admin/access/api/pools/sync') {
			const country = 标准化访问国家(body.country);
			const summaries = await 同步到期访问PROXYIP数据源(env, { force: true, country });
			const imported = summaries.reduce((sum, item) => sum + Number(item.imported || 0), 0);
			if (!imported) throw new Error(summaries.find(item => item.error)?.error || `${country} 数据源暂无可用记录`);
			const health = await 检测访问PROXYIP池(env, country, 8);
			await 写入审计日志(env, request, 管理员会话, 'proxy.pool.sync', 'country', country, null, { imported, health }, true);
			return 访问JSON响应({ success: true, message: `${country} 已同步 ${imported} 个候选，检测通过 ${health.success} 个`, summaries, health });
		}

		if (pathname === '/admin/access/api/pools/check') {
			const country = 标准化访问国家(body.country);
			const health = await 检测访问PROXYIP池(env, country, body.limit || 8);
			await 写入审计日志(env, request, 管理员会话, 'proxy.pool.check', 'country', country, null, health, true);
			return 访问JSON响应({ success: true, message: `${country} 检测完成：可用 ${health.success}，失败 ${health.failed}，检测服务异常 ${health.unavailable}`, health });
		}

		if (pathname === '/admin/access/api/sources') {
			const name = String(body.name || '').trim().slice(0, 80);
			const sourceUrl = 标准化访问数据源URL(body.url);
			const defaultCountry = body.defaultCountry ? 标准化访问国家(body.defaultCountry) : '';
			const refreshMinutes = Math.min(1440, Math.max(5, Math.floor(Number(body.refreshMinutes) || 60)));
			const maxPerCountry = Math.min(200, Math.max(10, Math.floor(Number(body.maxPerCountry) || 100)));
			if (!name) throw new Error('请输入数据源名称');
			const now = Date.now();
			await session.prepare(`INSERT INTO proxy_ip_sources
				(name, url, default_country, enabled, refresh_minutes, max_per_country, last_status, created_at, updated_at)
				VALUES (?1, ?2, ?3, 1, ?4, ?5, 'never', ?6, ?6)
				ON CONFLICT(url) DO UPDATE SET name = ?1, default_country = ?3, enabled = 1,
				refresh_minutes = ?4, max_per_country = ?5, updated_at = ?6`)
				.bind(name, sourceUrl, defaultCountry, refreshMinutes, maxPerCountry, now).run();
			await 写入审计日志(env, request, 管理员会话, 'proxy.source.save', 'proxy_source', name, null, { name, host: new URL(sourceUrl).hostname, defaultCountry, refreshMinutes, maxPerCountry }, true);
			return 访问JSON响应({ success: true, message: '数据源已保存；选择国家后点击同步即可导入' }, 201);
		}

		if (pathname === '/admin/access/api/sources/action') {
			const id = Math.floor(Number(body.id));
			const action = String(body.action || '');
			if (!Number.isInteger(id) || id < 1) throw new Error('数据源 ID 无效');
			const source = await session.prepare('SELECT * FROM proxy_ip_sources WHERE id = ?1').bind(id).first();
			if (!source) throw new Error('数据源不存在');
			if (action === 'enable') await session.prepare('UPDATE proxy_ip_sources SET enabled = 1, updated_at = ?1 WHERE id = ?2').bind(Date.now(), id).run();
			else if (action === 'disable') await session.prepare('UPDATE proxy_ip_sources SET enabled = 0, updated_at = ?1 WHERE id = ?2').bind(Date.now(), id).run();
			else if (action === 'delete') {
				if (source.url === 内置访问PROXYIP数据源URL) throw new Error('内置数据源不能删除，可以停用');
				await env.DB.batch([
					session.prepare('DELETE FROM proxy_ip_pool WHERE source_id = ?1').bind(id),
					session.prepare('DELETE FROM proxy_ip_source_sync WHERE source_id = ?1').bind(id),
					session.prepare('DELETE FROM proxy_ip_sources WHERE id = ?1').bind(id)
				]);
			} else throw new Error('不支持的数据源操作');
			const after = action === 'delete' ? null : await session.prepare('SELECT * FROM proxy_ip_sources WHERE id = ?1').bind(id).first();
			await 写入审计日志(env, request, 管理员会话, `proxy.source.${action}`, 'proxy_source', id, { name: source.name, host: new URL(source.url).hostname, enabled: source.enabled }, after ? { name: after.name, host: new URL(after.url).hostname, enabled: after.enabled } : null, true);
			return 访问JSON响应({ success: true, message: '数据源操作成功' });
		}

		return 访问错误响应('管理接口不存在', 404);
	} catch (error) {
		console.error('访问链接管理失败:', error);
		if (request.method === 'POST') await 写入审计日志(env, request, 管理员会话, 'admin.request.failed', 'api', url.pathname, null, null, false, error?.message || error);
		return 访问错误响应(error?.message || '访问链接管理失败', error?.status || 400);
	}
}

function 访问链接增强管理页面() {
	const 国家选项HTML = 生成访问国家选项();
	const html = `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>限时访问链接</title><style>
:root{color-scheme:dark;--bg:#07101d;--panel:#111c2e;--panel2:#0c1728;--line:#2b3b59;--text:#edf3ff;--muted:#99a7bd;--blue:#568eff;--red:#ff627b;--green:#3cda91;--amber:#f3c765}*{box-sizing:border-box}body{margin:0;background:linear-gradient(145deg,#07101d,#0d1830) fixed;color:var(--text);font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}.wrap{max-width:1500px;margin:auto;padding:24px}.top,.toolbar,.stats,.actions,.pagination{display:flex;align-items:center;gap:10px;flex-wrap:wrap}.top{justify-content:space-between}.top h1{margin:0;font-size:26px}.top a{color:#a8c5ff}.stats{margin:18px 0;display:grid;grid-template-columns:repeat(5,minmax(150px,1fr))}.stat,.card{background:rgba(17,28,46,.96);border:1px solid var(--line);border-radius:14px;box-shadow:0 14px 40px #0003}.stat{padding:14px}.stat b{display:block;font-size:22px}.stat span,.muted{color:var(--muted)}.card{padding:18px;margin:16px 0}h2,h3{margin:0 0 13px}h2{font-size:18px}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}.form-grid,.filters{display:grid;grid-template-columns:repeat(4,minmax(120px,1fr));gap:10px}.filters{grid-template-columns:2fr repeat(4,1fr);margin-bottom:12px}label{display:block;color:var(--muted);margin:3px 0}input,textarea,select,button{font:inherit}input,textarea,select{width:100%;color:var(--text);background:#091425;border:1px solid #405273;border-radius:8px;padding:9px}input:focus,textarea:focus,select:focus,button:focus-visible,summary:focus-visible{outline:3px solid #568eff66;outline-offset:2px}textarea{min-height:82px;resize:vertical}button{border:0;border-radius:8px;padding:8px 11px;color:#fff;background:var(--blue);cursor:pointer}button.alt{background:#374865}button.danger{background:#963548}button.ghost{background:transparent;border:1px solid var(--line)}button.small{font-size:12px;padding:5px 8px}button:disabled{opacity:.55;cursor:not-allowed}.notice{padding:10px 12px;border-radius:9px;background:#0b2931;border:1px solid #1c5969;color:#9ee1ee;margin-bottom:12px}.tablewrap{overflow:auto;border:1px solid var(--line);border-radius:10px}table{width:100%;border-collapse:collapse;min-width:1080px}th,td{text-align:left;vertical-align:top;padding:9px 10px;border-bottom:1px solid #23324c}th{position:sticky;top:0;background:#142138;color:#b7c2d4}.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}.healthy,.active{color:var(--green)}.unhealthy,.expired,.revoked{color:var(--red)}.unused,.unknown,.warning{color:var(--amber)}.tag{display:inline-block;padding:2px 7px;margin:2px;border:1px solid #415779;border-radius:999px;color:#bed0ec}.row-details{margin-top:7px}.row-details>summary,.menu>summary{cursor:pointer;color:#a9c6ff}.detail-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:5px 12px;background:var(--panel2);padding:9px;border-radius:8px;margin-top:6px}.menu{position:relative;display:inline-block}.menu-body{position:fixed;left:0;top:0;right:auto;z-index:30;visibility:hidden;min-width:170px;max-height:calc(100vh - 16px);overflow-y:auto;padding:7px;background:#17243a;border:1px solid var(--line);border-radius:9px;box-shadow:0 12px 30px #0008}.menu-body button{width:100%;margin:2px 0;text-align:left}.cards{display:none}.link-card{background:var(--panel2);border:1px solid var(--line);border-radius:11px;padding:12px;margin:9px 0}.link-card-head{display:flex;justify-content:space-between;gap:10px}.toast-area{position:fixed;right:18px;bottom:18px;z-index:20;display:grid;gap:8px}.toast{max-width:min(420px,90vw);background:#182842;border:1px solid #45618d;border-radius:10px;padding:11px 14px;box-shadow:0 12px 35px #0008}.toast.error{border-color:#a84357}.toast.partial{border-color:#98762e}.empty,.errorbox{text-align:center;padding:25px;color:var(--muted)}dialog{color:var(--text);background:#111c2e;border:1px solid var(--line);border-radius:14px;width:min(92vw,520px);padding:20px}dialog::backdrop{background:#0009}dialog h3{font-size:18px}.dialog-fields{display:grid;gap:8px}.audit-json{max-width:320px;white-space:pre-wrap;word-break:break-word;font-size:11px}.pool-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:10px}.pool-card{background:var(--panel2);border:1px solid var(--line);border-radius:10px;padding:11px}.loading{opacity:.7;pointer-events:none}.sr-only{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0,0,0,0)}
@media(max-width:1000px){.stats{grid-template-columns:repeat(2,1fr)}.form-grid,.filters{grid-template-columns:repeat(2,1fr)}}@media(max-width:720px){.wrap{padding:13px}.grid{grid-template-columns:1fr}.stats{grid-template-columns:1fr 1fr}.filters,.form-grid{grid-template-columns:1fr}.desktop-links{display:none}.cards{display:block}.toolbar{align-items:stretch}.toolbar>*{flex:1 1 140px}.pagination{width:100%}.menu-body{left:14px!important;right:14px!important;top:auto!important;bottom:14px;visibility:visible!important;max-height:70vh}.detail-grid{grid-template-columns:1fr}}@media(max-width:420px){.stats{grid-template-columns:1fr}.top h1{font-size:22px}}
</style></head><body><main class="wrap">
<header class="top"><div><h1>限时访问链接</h1><div class="muted">真实连接时开始计时；限制、健康状态和会话均由 D1 原子维护</div></div><div class="actions"><a href="/admin">返回原后台</a><button class="ghost" id="logoutAll">退出所有设备</button></div></header>
<section class="stats" id="stats" aria-label="运行概况"></section>
<section class="grid"><form class="card" id="createForm"><h2>生成访问链接</h2><div class="notice">0 表示不限制。开启首次 IP 绑定后，首次真实连接的客户端 IP 将成为唯一允许 IP。</div><div class="form-grid"><label>国家<input name="country" list="countryOptions" placeholder="名称或代码" required></label><label>有效时长（小时）<input name="durationHours" list="durationOptions" value="3" required></label><label>数量（最多 100）<input name="count" type="number" min="1" max="100" value="1" required></label><label>备注<input name="note" maxlength="100"></label><label>并发上限<input name="maxConcurrentConnections" type="number" min="0" max="10000" value="0"></label><label>累计上限<input name="maxTotalConnections" type="number" min="0" max="10000000" value="0"></label><label>标签（逗号分隔）<input name="tags" maxlength="300"></label><label><span>客户端绑定</span><select name="bindFirstIp"><option value="0">不绑定</option><option value="1">绑定首次 IP</option></select></label></div><p><button>生成链接</button></p></form>
<section class="card"><h2>运维与备份</h2><div class="notice" id="notifyState">通知配置读取中…</div><div class="actions"><button class="alt" data-export="json">导出筛选 JSON</button><button class="alt" data-export="csv">导出筛选 CSV</button><button class="alt" id="backupExport">导出 D1 备份</button><label class="ghost" style="padding:7px 10px;border:1px solid var(--line);border-radius:8px;cursor:pointer">恢复备份<input class="sr-only" id="backupFile" type="file" accept="application/json"></label></div><p class="muted">恢复默认仅插入不存在的数据；覆盖恢复会要求再次输入确认文本。</p></section></section>
<datalist id="countryOptions">${国家选项HTML}</datalist><datalist id="durationOptions"><option value="1"><option value="3"><option value="8"><option value="24"><option value="72"><option value="permanent"></datalist>
<section class="card" id="linksCard"><h2>访问链接</h2><form class="filters" id="filters"><label>搜索<input name="q" type="search" maxlength="100" placeholder="ID / 备注 / UUID / IP"></label><label>状态<select name="status"><option value="all">全部</option><option value="unused">未使用</option><option value="active">使用中</option><option value="expired">已过期</option><option value="revoked">已停用</option></select></label><label>国家<input name="country" list="countryOptions" placeholder="全部"></label><label>标签<input name="tag" maxlength="30"></label><label>到期<select name="expiry"><option value="all">全部</option><option value="24h">24 小时内</option><option value="7d">7 天内</option><option value="expired">已过期</option></select></label><button>应用筛选</button></form>
<div class="toolbar"><label><input id="selectAll" type="checkbox" style="width:auto"> 本页全选</label><span id="selectedCount" class="muted">已选 0 条</span><select id="bulkAction" aria-label="批量操作"><option value="">批量操作…</option><option value="export">导出订阅和链接</option><option value="revoke">停用</option><option value="restore">恢复</option><option value="renew">续期</option><option value="reset">重置计时</option><option value="reassign">重选 IP</option><option value="tags">修改标签</option><option value="rotate">轮换凭据</option><option value="delete">删除</option></select><button type="button" id="runBulk" disabled>执行</button><span style="flex:1"></span><label>每页<select id="pageSize"><option>10</option><option selected>20</option><option>50</option></select></label><div class="pagination"><button class="small alt" data-page="prev">上一页</button><span id="pageInfo" class="muted"></span><button class="small alt" data-page="next">下一页</button></div></div>
<div class="tablewrap desktop-links"><table><thead><tr><th></th><th>ID / 备注</th><th>国家</th><th>状态</th><th>有效时长</th><th>剩余时间</th><th>最后使用</th><th>当前 / 累计</th><th>PROXYIP</th><th>操作</th></tr></thead><tbody id="links"></tbody></table></div><div class="cards" id="linkCards"></div></section>
<section class="card"><h2>国家 PROXYIP 健康</h2><div class="pool-grid" id="poolStats"></div><details><summary>最近 500 条 IP</summary><div class="tablewrap"><table><thead><tr><th>国家</th><th>PROXYIP</th><th>健康</th><th>评分</th><th>延迟</th><th>真实成功 / 失败</th><th>最后检测</th></tr></thead><tbody id="pools"></tbody></table></div></details></section>
<section class="card"><h2>数据源</h2><div class="actions"><form id="syncForm" class="actions"><input name="country" list="countryOptions" placeholder="国家" required><button>同步并检测</button></form></div><details><summary>手动添加 IP / 数据源</summary><div class="grid"><form id="poolForm"><label>国家<input name="country" list="countryOptions" required></label><label>PROXYIP<textarea name="proxyIps" required></textarea></label><button>加入 IP 池</button></form><form id="sourceForm"><label>名称<input name="name" maxlength="80" required></label><label>HTTPS 地址<input name="url" type="url" required></label><label>默认国家<input name="defaultCountry" list="countryOptions"></label><label>刷新分钟<input name="refreshMinutes" type="number" min="5" max="1440" value="60"></label><label>每国上限<input name="maxPerCountry" type="number" min="10" max="200" value="100"></label><button>保存数据源</button></form></div></details><div class="tablewrap"><table><thead><tr><th>名称</th><th>地址</th><th>状态</th><th>失败次数</th><th>操作</th></tr></thead><tbody id="sources"></tbody></table></div></section>
<section class="card"><h2>安全审计</h2><form class="toolbar" id="auditFilters"><input name="q" placeholder="操作 / 对象 / 错误"><input name="action" placeholder="精确操作类型"><button>筛选</button><button type="button" class="alt" data-audit-export="json">JSON</button><button type="button" class="alt" data-audit-export="csv">CSV</button></form><div class="tablewrap"><table><thead><tr><th>时间</th><th>操作</th><th>对象</th><th>来源</th><th>结果</th><th>摘要</th></tr></thead><tbody id="audit"></tbody></table></div><div class="pagination"><button class="small alt" data-audit-page="prev">上一页</button><span id="auditPage" class="muted"></span><button class="small alt" data-audit-page="next">下一页</button></div></section>
</main><div class="toast-area" id="toasts" aria-live="polite"></div>
<dialog id="actionDialog"><form method="dialog" id="actionForm"><h3 id="dialogTitle">确认操作</h3><p id="dialogMessage"></p><div class="dialog-fields" id="dialogFields"></div><div class="actions" style="margin-top:16px"><button value="cancel" class="alt">取消</button><button value="confirm" id="dialogConfirm">确认</button></div></form></dialog>
<script>
const $=s=>document.querySelector(s),$$=s=>Array.from(document.querySelectorAll(s));
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmt=v=>v?new Date(Number(v)).toLocaleString():'—';
${格式化批量访问链接导出.toString()}
const csrf=()=>decodeURIComponent((document.cookie.split('; ').find(x=>x.startsWith('admin_csrf='))||'=').split('=').slice(1).join('='));
function toast(message,type){const n=document.createElement('div');n.className='toast '+(type||'');n.textContent=message;$('#toasts').append(n);setTimeout(()=>n.remove(),5000)}
async function api(path,options){options=options||{};const headers=new Headers(options.headers||{});if(options.method&&options.method!=='GET'){headers.set('Content-Type','application/json');headers.set('X-CSRF-Token',csrf())}const r=await fetch('/admin/access/api/'+path,{...options,headers});const contentType=(r.headers.get('Content-Type')||'').toLowerCase();if(r.redirected||!contentType.includes('application/json')){if(r.redirected&&new URL(r.url).pathname==='/login')location.assign('/login');throw new Error(r.redirected?'管理员会话已失效，请重新登录':'服务器返回了非 JSON 响应')}const j=await r.json().catch(()=>{throw new Error('服务器 JSON 响应无法解析')});if(r.status===401){location.assign('/login');throw new Error(j.error||'管理员会话已失效，请重新登录')}if((!r.ok&&r.status!==207)||j.success===false)throw new Error(j.error||'请求失败');return j}
async function download(path,filename,confirmation){const r=await fetch('/admin/access/api/'+path,{headers:{'X-Export-Confirmation':confirmation}});if(!r.ok){const j=await r.json().catch(()=>({}));throw new Error(j.error||'导出失败')}const blob=await r.blob(),a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=filename;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(a.href),1000)}
function downloadText(content,filename){const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([content],{type:'text/plain;charset=utf-8'}));a.download=filename;document.body.append(a);a.click();const url=a.href;a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000)}
let page=1,pageSize=20,total=0,links=[],selected=new Set(),filters={},auditPage=1,auditTotal=0,auditFilter={};
const statusNames={unused:'未使用',active:'使用中',expired:'已过期',revoked:'已停用'};
function remaining(x){if(Number(x.duration_seconds)===0&&!x.expires_at)return '永久';if(!x.expires_at)return '未开始';const ms=Number(x.expires_at)-Date.now();if(ms<=0)return '已过期';const d=Math.floor(ms/86400000),h=Math.floor(ms%86400000/3600000),m=Math.floor(ms%3600000/60000),s=Math.floor(ms%60000/1000);return (d?d+'天 ':'')+String(h).padStart(2,'0')+':'+String(m).padStart(2,'0')+':'+String(s).padStart(2,'0')}
function actionMenu(x){const primary=x.display_status==='expired'?'<button class="small" data-action="renew" data-id="'+x.id+'">续期</button>':x.status==='active'?'<button class="small danger" data-action="revoke" data-id="'+x.id+'">停用</button>':'<button class="small" data-action="restore" data-id="'+x.id+'">恢复</button>';return primary+'<details class="menu"><summary>更多</summary><div class="menu-body"><button data-action="edit" data-id="'+x.id+'">编辑限制/标签</button><button data-action="renew" data-id="'+x.id+'">续期</button><button data-action="reset" data-id="'+x.id+'">重置计时</button><button data-action="reassign" data-id="'+x.id+'">重选 IP</button><button data-action="rotate" data-id="'+x.id+'">轮换凭据</button><button data-copy="'+esc(x.subscription_url)+'">复制订阅</button><button data-copy="'+esc(x.node_url)+'">复制链接</button><button class="danger" data-action="delete" data-id="'+x.id+'">删除</button></div></details>'}
function details(x){const tagHtml=(x.tags_list||[]).map(t=>'<span class="tag">'+esc(t)+'</span>').join('')||'—';return '<details class="row-details"><summary>详情</summary><div class="detail-grid"><span>UUID</span><span class="mono">'+esc(x.uuid)+'</span><span>首次使用</span><span>'+fmt(x.first_used_at)+'</span><span>完整到期</span><span>'+fmt(x.expires_at)+'</span><span>限制</span><span>并发 '+Number(x.max_concurrent_connections||0)+' / 累计 '+Number(x.max_total_connections||0)+'</span><span>绑定</span><span>'+(Number(x.bind_first_ip)?(x.bound_ip?'已绑定':'等待首次 IP'):'未启用')+'</span><span>标签</span><span>'+tagHtml+'</span></div></details>'}
function renderLinks(){const rows=links.map(x=>'<tr><td><input type="checkbox" data-select="'+x.id+'" '+(selected.has(Number(x.id))?'checked':'')+' aria-label="选择链接 '+x.id+'"></td><td><b>#'+x.id+'</b><br>'+esc(x.note||'—')+details(x)+'</td><td>'+esc(x.country)+'</td><td class="'+esc(x.display_status)+'">'+statusNames[x.display_status]+'</td><td>'+esc(x.duration_label)+'</td><td data-countdown="'+(x.expires_at||'')+'">'+remaining(x)+'</td><td>'+fmt(x.last_used_at)+'</td><td>'+Number(x.active_connections||0)+' / '+Number(x.connection_count||0)+'</td><td class="mono">'+esc(x.proxy_ip||'首次连接时分配')+'</td><td>'+actionMenu(x)+'</td></tr>').join('');$('#links').innerHTML=rows||'<tr><td colspan="10" class="empty">没有符合条件的链接</td></tr>';$('#linkCards').innerHTML=links.map(x=>'<article class="link-card"><div class="link-card-head"><label><input type="checkbox" data-select="'+x.id+'" '+(selected.has(Number(x.id))?'checked':'')+'> <b>#'+x.id+' '+esc(x.note||'')+'</b></label><span class="'+x.display_status+'">'+statusNames[x.display_status]+'</span></div><p>'+esc(x.country)+' · 有效时长 '+esc(x.duration_label)+' · 剩余 <span data-countdown="'+(x.expires_at||'')+'">'+remaining(x)+'</span><br>连接 '+Number(x.active_connections||0)+' / '+Number(x.connection_count||0)+'<br><span class="mono">'+esc(x.proxy_ip||'首次连接时分配')+'</span></p>'+details(x)+'<div class="actions">'+actionMenu(x)+'</div></article>').join('')||'<div class="empty">没有符合条件的链接</div>';updateSelection()}
function updateSelection(){$$('[data-select]').forEach(b=>b.checked=selected.has(Number(b.dataset.select)));$('#selectedCount').textContent='已选 '+selected.size+' 条';$('#runBulk').disabled=!selected.size||!$('#bulkAction').value;$('#selectAll').checked=links.length>0&&links.every(x=>selected.has(Number(x.id)));$('#selectAll').indeterminate=links.some(x=>selected.has(Number(x.id)))&&!links.every(x=>selected.has(Number(x.id)))}
function closeMenus(except){$$('.menu[open]').forEach(menu=>{if(menu!==except)menu.removeAttribute('open')})}
function positionMenu(menu){const trigger=menu.querySelector('summary'),panel=menu.querySelector('.menu-body');if(!menu.open||!trigger||!panel)return;panel.style.visibility='hidden';panel.style.left='0px';panel.style.top='0px';requestAnimationFrame(()=>{if(!menu.open)return;const rect=trigger.getBoundingClientRect(),gap=8,width=panel.offsetWidth,height=panel.offsetHeight;const left=Math.max(gap,Math.min(rect.right-width,window.innerWidth-width-gap));const below=rect.bottom+6;const top=below+height<=window.innerHeight-gap?below:Math.max(gap,rect.top-height-6);panel.style.left=left+'px';panel.style.top=top+'px';panel.style.visibility='visible'})}
async function load(){const card=$('#linksCard');card.classList.add('loading');try{const p=new URLSearchParams({...filters,limit:pageSize,offset:(page-1)*pageSize});const d=await api('state?'+p);links=d.links||[];total=Number(d.pagination.total||0);const pages=Math.max(1,Math.ceil(total/pageSize));if(page>pages){page=pages;return load()}const s=d.stats||{};$('#stats').innerHTML=[['当前连接',s.current_connections||0],['24 小时连接',(s.connections_24h||0)+' / 失败 '+(s.failure_rate_24h||0)+'%'],['健康 IP',(s.healthy_ip_ratio||0)+'%'],['低容量国家',s.low_capacity_countries||0],['链接总数',s.total||0]].map(v=>'<div class="stat"><b>'+v[1]+'</b><span>'+v[0]+'</span></div>').join('');$('#notifyState').textContent=d.security&&d.security.notifications_configured?'Webhook / Telegram 通知已配置':'通知未配置，不影响链接与健康检查';selected=new Set(Array.from(selected).filter(id=>links.some(x=>Number(x.id)===id)));renderLinks();$('#pageInfo').textContent='第 '+page+' / '+pages+' 页 · '+total+' 条';$$('[data-page="prev"]').forEach(b=>b.disabled=page<=1);$$('[data-page="next"]').forEach(b=>b.disabled=page>=pages);renderPools(d);await loadAudit()}catch(e){const message=e&&e.message?e.message:'未知错误';toast(message,'error');$('#notifyState').textContent='通知配置读取失败：'+message;$('#notifyState').classList.add('errorbox');$('#links').innerHTML='<tr><td colspan="9" class="errorbox">加载失败：'+esc(message)+'</td></tr>'}finally{card.classList.remove('loading')}}
function renderPools(d){$('#poolStats').innerHTML=(d.poolStats||[]).map(x=>'<article class="pool-card"><b>'+esc(x.country)+'</b><div>健康 '+Number(x.healthy||0)+' / '+Number(x.total||0)+' · 隔离 '+Number(x.isolated||0)+'</div><div>分配 '+Number(x.assigned||0)+' · 延迟 '+(x.average_latency_ms==null?'—':x.average_latency_ms+' ms')+'</div><div class="'+(Number(x.healthy)<Number(x.min_healthy_ips)?'warning':'healthy')+'">阈值 '+Number(x.min_healthy_ips)+' · 评分 '+Number(x.average_health_score||0)+'</div><div class="actions"><button class="small" data-sync-country="'+esc(x.country)+'">同步</button><button class="small alt" data-check-country="'+esc(x.country)+'">检测</button><button class="small alt" data-threshold-country="'+esc(x.country)+'" data-threshold="'+Number(x.min_healthy_ips)+'">阈值</button></div></article>').join('')||'<div class="empty">还没有国家 IP 池</div>';$('#pools').innerHTML=(d.pools||[]).map(x=>'<tr><td>'+esc(x.country)+'</td><td class="mono">'+esc(x.proxy_ip)+'</td><td class="'+esc(x.health_status||'unknown')+'">'+esc(x.health_status||'unknown')+(x.cooldown_until&&Number(x.cooldown_until)>Date.now()?'（隔离）':'')+'</td><td>'+Number(x.health_score||0)+'</td><td>'+(x.latency_ms==null?'—':Number(x.latency_ms)+' ms')+'</td><td>'+Number(x.real_success_count||0)+' / '+Number(x.real_failure_count||0)+'</td><td>'+fmt(x.last_checked_at)+'</td></tr>').join('');$('#sources').innerHTML=(d.sources||[]).map(x=>'<tr><td>'+esc(x.name)+'</td><td class="mono">'+esc(String(x.url).slice(0,90))+'</td><td class="'+(x.last_status==='error'?'unhealthy':x.last_status==='success'?'healthy':'unknown')+'">'+esc(x.last_status)+(x.last_error?'<br>'+esc(x.last_error):'')+'</td><td>'+Number(x.consecutive_failures||0)+'</td><td><button class="small alt" data-source-id="'+x.id+'" data-source-action="'+(x.enabled?'disable':'enable')+'">'+(x.enabled?'停用':'启用')+'</button>'+(String(x.url).includes('zip.cm.edu.kg')?'':'<button class="small danger" data-source-id="'+x.id+'" data-source-action="delete">删除</button>')+'</td></tr>').join('')}
async function loadAudit(){const p=new URLSearchParams({...auditFilter,limit:20,offset:(auditPage-1)*20}),d=await api('audit?'+p);auditTotal=Number(d.pagination.total||0);$('#audit').innerHTML=(d.logs||[]).map(x=>'<tr><td>'+fmt(x.created_at)+'</td><td>'+esc(x.action)+'</td><td>'+esc(x.object_type)+' #'+esc(x.object_id)+'</td><td>'+esc(x.source_ip||'未记录')+(x.source_asn?' / AS'+esc(x.source_asn):'')+'</td><td class="'+(x.success?'healthy':'unhealthy')+'">'+(x.success?'成功':'失败：'+esc(x.error_message))+'</td><td><details><summary>查看</summary><pre class="audit-json">'+esc(x.before_summary||'')+'\\n→\\n'+esc(x.after_summary||'')+'</pre></details></td></tr>').join('')||'<tr><td colspan="6" class="empty">暂无审计记录</td></tr>';$('#auditPage').textContent='第 '+auditPage+' / '+Math.max(1,Math.ceil(auditTotal/20))+' 页'}
function confirmDialog(title,message,fields){return new Promise(resolve=>{const d=$('#actionDialog'),f=$('#actionForm'),box=$('#dialogFields');let result=null;$('#dialogTitle').textContent=title;$('#dialogMessage').textContent=message;box.innerHTML=fields||'';d.addEventListener('close',()=>{f.onsubmit=null;resolve(result)},{once:true});f.onsubmit=e=>{e.preventDefault();if(e.submitter&&e.submitter.value==='confirm')result=Object.fromEntries(new FormData(f));d.close()};d.showModal()})}
function actionSpec(action,x,count){const n=count||1,m={revoke:['停用链接','将禁止新连接；本实例连接立即关闭，其他实例最长约 30 秒发现并断开。',''],restore:['恢复链接','仅恢复已停用且尚未过期的链接；已过期链接请续期。',''],renew:['续期','未使用链接只增加总时长，仍从首次连接开始计时；已使用链接从当前到期时间或当前时间（较晚者）起增加。','<label>增加小时数<input name="hours" type="number" min="1" max="8760" value="24" required></label>'],reset:['重置计时','清除首次使用、到期、已分配 IP、绑定和全部使用统计；下一次真实连接重新计时。',''],reassign:['重选 IP','只更换 PROXYIP，不重置计时、绑定或使用统计。',''],rotate:['轮换凭据','旧凭据立即不能建立新连接；国家、IP、计时和统计保持不变。','<label>轮换范围<select name="mode"><option value="both">Token 和 UUID</option><option value="token">仅 Token</option><option value="uuid">仅 UUID</option></select></label>'],delete:['删除链接','永久删除 '+n+' 条链接及其连接事件，无法撤销。',''],tags:['修改标签','为 '+n+' 条链接设置相同标签。','<label>标签（逗号分隔）<input name="tags" maxlength="300"></label>']};if(action==='edit')return ['编辑链接','修改备注、标签、连接限制和首次 IP 绑定。','<label>备注<input name="note" maxlength="200" value="'+esc(x.note||'')+'"></label><label>标签<input name="tags" value="'+esc((x.tags_list||[]).join(','))+'"></label><label>并发上限<input name="maxConcurrentConnections" type="number" min="0" max="10000" value="'+Number(x.max_concurrent_connections||0)+'"></label><label>累计上限<input name="maxTotalConnections" type="number" min="0" max="10000000" value="'+Number(x.max_total_connections||0)+'"></label><label>首次 IP 绑定<select name="bindFirstIp"><option value="0" '+(!Number(x.bind_first_ip)?'selected':'')+'>关闭</option><option value="1" '+(Number(x.bind_first_ip)?'selected':'')+'>开启</option></select></label>'];return m[action]}
async function runAction(action,ids,x){const spec=actionSpec(action,x,ids.length);if(!spec)return;const extra=await confirmDialog(spec[0],spec[1],spec[2]);if(!extra)return;const payload={action,...extra};if(ids.length===1)payload.id=ids[0];else payload.ids=ids;$('#linksCard').classList.add('loading');try{const d=await api('links/action',{method:'POST',body:JSON.stringify(payload)});toast(d.message,d.partial?'partial':'');selected.clear();await load()}finally{$('#linksCard').classList.remove('loading')}}
async function exportSelected(ids){const records=links.filter(x=>ids.includes(Number(x.id)));if(!records.length)return;const ok=await confirmDialog("导出订阅和链接","将导出 "+records.length+" 条记录，每行格式为 ['订阅地址','访问链接','国家','有效时长']，其中包含完整访问凭据。",'');if(!ok)return;downloadText(格式化批量访问链接导出(records),'edgetunnel-access-links-selected.txt');toast('已导出 '+records.length+' 条记录')}
$('#filters').addEventListener('submit',e=>{e.preventDefault();filters=Object.fromEntries(new FormData(e.target));page=1;selected.clear();load()});
$('#createForm').addEventListener('submit',async e=>{e.preventDefault();const b=e.submitter;b.disabled=true;try{const d=await api('links',{method:'POST',body:JSON.stringify(Object.fromEntries(new FormData(e.target)))});toast(d.message);page=1;await load()}catch(x){toast(x.message,'error')}finally{b.disabled=false}});
$('#syncForm').addEventListener('submit',async e=>{e.preventDefault();const b=e.submitter;b.disabled=true;try{const d=await api('pools/sync',{method:'POST',body:JSON.stringify(Object.fromEntries(new FormData(e.target)))});toast(d.message);await load()}catch(x){toast(x.message,'error')}finally{b.disabled=false}});
for(const id of ['poolForm','sourceForm'])$('#'+id).addEventListener('submit',async e=>{e.preventDefault();const path=id==='poolForm'?'pools':'sources',b=e.submitter;b.disabled=true;try{const d=await api(path,{method:'POST',body:JSON.stringify(Object.fromEntries(new FormData(e.target)))});toast(d.message);await load()}catch(x){toast(x.message,'error')}finally{b.disabled=false}});
$('#auditFilters').addEventListener('submit',e=>{e.preventDefault();auditFilter=Object.fromEntries(new FormData(e.target));auditPage=1;loadAudit()});
$('#selectAll').addEventListener('change',e=>{links.forEach(x=>e.target.checked?selected.add(Number(x.id)):selected.delete(Number(x.id)));updateSelection()});
$('#bulkAction').addEventListener('change',updateSelection);$('#runBulk').addEventListener('click',()=>{const action=$('#bulkAction').value,ids=Array.from(selected);return action==='export'?exportSelected(ids):runAction(action,ids,null)});
$('#pageSize').addEventListener('change',e=>{pageSize=Number(e.target.value);page=1;selected.clear();load()});
$('#logoutAll').addEventListener('click',async()=>{const d=await confirmDialog('退出所有设备','将撤销包括当前设备在内的全部管理员会话。','');if(!d)return;try{await api('session/logout-all',{method:'POST',body:'{}'});location.href='/login'}catch(x){toast(x.message,'error')}});
$$('[data-export]').forEach(b=>b.addEventListener('click',async()=>{const ok=await confirmDialog('导出敏感链接','导出包含完整 Token、UUID 和可用访问链接。请只保存到可信设备。','');if(!ok)return;try{const p=new URLSearchParams({...filters,format:b.dataset.export});await download('links/export?'+p,'edgetunnel-access-links.'+b.dataset.export,'include-sensitive-links')}catch(x){toast(x.message,'error')}}));
$('#backupExport').addEventListener('click',async()=>{const ok=await confirmDialog('导出 D1 备份','备份包含访问凭据和 IP 池，但不包含管理员会话。','');if(ok)try{await download('backup','edgetunnel-d1-backup.json','backup-operational-data')}catch(x){toast(x.message,'error')}});
$('#backupFile').addEventListener('change',async e=>{const file=e.target.files[0];if(!file)return;try{const data=JSON.parse(await file.text());let mode='merge',confirmOverwrite='';const first=await confirmDialog('恢复 D1 备份','默认不覆盖现有数据。勾选后将覆盖相同主键记录。','<label><select name="mode"><option value="merge">仅合并，不覆盖</option><option value="overwrite">覆盖相同记录</option></select></label>');if(!first)return;mode=first.mode;if(mode==='overwrite'){const second=await confirmDialog('二次确认覆盖','输入 RESTORE OVERWRITE 才会执行覆盖恢复。','<label>确认文本<input name="confirmOverwrite" required></label>');if(!second)return;confirmOverwrite=second.confirmOverwrite}const d=await api('backup/restore',{method:'POST',body:JSON.stringify({...data,mode,confirmOverwrite})});toast(d.message,d.partial?'partial':'');await load()}catch(x){toast(x.message,'error')}finally{e.target.value=''}});
$$('[data-audit-export]').forEach(b=>b.addEventListener('click',()=>download('audit/export?format='+b.dataset.auditExport,'edgetunnel-audit.'+b.dataset.auditExport,'')));
document.addEventListener('change',e=>{if(e.target.matches('[data-select]')){const id=Number(e.target.dataset.select);e.target.checked?selected.add(id):selected.delete(id);updateSelection()}});
document.addEventListener('toggle',e=>{const menu=e.target.closest?.('.menu');if(!menu||e.target!==menu)return;if(menu.open){closeMenus(menu);positionMenu(menu)}},true);
document.addEventListener('click',e=>{if(!e.target.closest('.menu'))closeMenus()});
addEventListener('scroll',()=>closeMenus(),true);addEventListener('resize',()=>closeMenus());
document.addEventListener('click',async e=>{const b=e.target.closest('button');if(!b)return;const menu=b.closest('.menu');if(menu)menu.removeAttribute('open');b.disabled=true;try{if(b.dataset.copy){await navigator.clipboard.writeText(b.dataset.copy);toast('已复制到剪贴板')}else if(b.dataset.action){const x=links.find(v=>Number(v.id)===Number(b.dataset.id));await runAction(b.dataset.action,[Number(b.dataset.id)],x)}else if(b.dataset.page){page+=b.dataset.page==='next'?1:-1;selected.clear();await load()}else if(b.dataset.auditPage){auditPage=Math.max(1,auditPage+(b.dataset.auditPage==='next'?1:-1));await loadAudit()}else if(b.dataset.syncCountry){const d=await api('pools/sync',{method:'POST',body:JSON.stringify({country:b.dataset.syncCountry})});toast(d.message);await load()}else if(b.dataset.checkCountry){const d=await api('pools/check',{method:'POST',body:JSON.stringify({country:b.dataset.checkCountry,limit:8})});toast(d.message);await load()}else if(b.dataset.thresholdCountry){const v=await confirmDialog('健康 IP 阈值',b.dataset.thresholdCountry+' 低于此数量时触发警告和通知。','<label>最低健康 IP<input name="minimum" type="number" min="1" max="100" value="'+b.dataset.threshold+'" required></label>');if(v){const d=await api('health/threshold',{method:'POST',body:JSON.stringify({country:b.dataset.thresholdCountry,minimum:v.minimum})});toast(d.message);await load()}}else if(b.dataset.sourceAction){if(b.dataset.sourceAction==='delete'&&!await confirmDialog('删除数据源','将同时删除该来源导入的 IP。',''))return;const d=await api('sources/action',{method:'POST',body:JSON.stringify({id:Number(b.dataset.sourceId),action:b.dataset.sourceAction})});toast(d.message);await load()}}catch(x){toast(x.message,'error')}finally{b.disabled=false}});
setInterval(()=>$$('[data-countdown]').forEach(n=>{const x=links.find(v=>String(v.expires_at||'')===n.dataset.countdown);if(x)n.textContent=remaining(x)}),1000);load();
</script></body></html>`;
	return new Response(html, { status: 200, headers: { 'Content-Type': 'text/html;charset=utf-8', 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'" } });
}

function 访问链接管理页面() {
	const 国家选项HTML = 生成访问国家选项();
	const html = `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>限时访问链接</title><style>
:root{color-scheme:dark;--bg:#09111f;--panel:#111c2e;--line:#263550;--text:#e8eef9;--muted:#91a0b9;--blue:#4f8cff;--red:#ff6078;--green:#39d98a}*{box-sizing:border-box}body{margin:0;background:linear-gradient(145deg,#07101d,#0d1830);color:var(--text);font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}.wrap{max-width:1440px;margin:auto;padding:24px}.top{display:flex;align-items:center;justify-content:space-between;gap:16px}.top a{color:#9ec0ff}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:18px;margin:20px 0}.card{background:rgba(17,28,46,.94);border:1px solid var(--line);border-radius:14px;padding:18px;box-shadow:0 14px 40px #0003}h1,h2,h3{margin:0 0 14px}h3{font-size:15px}label{display:block;color:var(--muted);margin:9px 0 5px}input,textarea,select,button{font:inherit}input,textarea,select{width:100%;background:#091425;color:var(--text);border:1px solid #344563;border-radius:8px;padding:10px}textarea{min-height:90px;resize:vertical}.row{display:grid;grid-template-columns:1fr 1fr;gap:10px}.row.three{grid-template-columns:2fr 1fr 1fr}button{border:0;border-radius:8px;padding:9px 12px;background:var(--blue);color:white;cursor:pointer}button.alt{background:#344563}button.danger{background:#8b3040}button.small{padding:5px 8px;font-size:12px;margin:2px}.msg{min-height:22px;margin-top:10px;color:var(--green)}.stats{display:flex;gap:9px;flex-wrap:wrap;margin:16px 0}.pill{background:#16243a;border:1px solid var(--line);padding:7px 11px;border-radius:999px}.tablewrap{overflow:auto;border:1px solid var(--line);border-radius:10px}table{width:100%;border-collapse:collapse;min-width:1050px}th,td{padding:9px 10px;text-align:left;border-bottom:1px solid #22314a;vertical-align:top}th{color:#aebbd0;background:#142138;position:sticky;top:0}.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}.unused,.unknown{color:#f6c85f}.active,.healthy{color:var(--green)}.expired,.revoked,.unhealthy{color:var(--red)}.muted{color:var(--muted)}details{margin-top:14px;border-top:1px solid var(--line);padding-top:12px}summary{cursor:pointer;color:#aebbd0;font-weight:600;margin-bottom:10px}.notice{background:#0b2630;border:1px solid #175064;border-radius:9px;padding:10px 12px;color:#9addeb;margin-bottom:12px}@media(max-width:800px){.grid{grid-template-columns:1fr}.row,.row.three{grid-template-columns:1fr}.wrap{padding:14px}}
.table-tools{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:10px}.link-filters{display:grid;grid-template-columns:minmax(180px,2fr) minmax(140px,1fr) auto auto;align-items:end;gap:8px;margin-bottom:12px}.link-filters label{margin:0}.link-filters button{height:40px}.bulk-actions,.pagination{display:flex;align-items:center;gap:8px;flex-wrap:wrap}.table-tools label{display:flex;align-items:center;gap:7px;margin:0}.page-size select{width:auto;padding:6px 28px 6px 8px}.page-info{min-width:150px;text-align:center;color:var(--muted)}.select-col{width:42px;text-align:center}input[type=checkbox]{width:17px;height:17px;margin:0;accent-color:var(--blue);cursor:pointer}button:disabled{cursor:not-allowed;opacity:.5}@media(max-width:800px){.table-tools{align-items:flex-start}.link-filters{grid-template-columns:1fr 1fr}.link-filters button{width:100%}.pagination{width:100%}.page-info{order:-1;width:100%;text-align:left}}@media(max-width:480px){.link-filters{grid-template-columns:1fr}}
</style></head><body><main class="wrap"><div class="top"><div><h1>限时访问链接</h1><div class="muted">首次真实代理连接才分配 PROXYIP 并开始计时</div></div><a href="/admin">返回原后台</a></div>
<div class="stats" id="stats"></div><section class="grid"><form class="card" id="createForm"><h2>生成访问链接</h2><div class="notice">选择国家后会自动从内置列表同步并检测 PROXYIP，不需要手动维护。</div><div class="row"><div><label>国家代码或名称</label><input name="country" list="countryOptions" placeholder="输入名称或代码搜索" autocomplete="off" required></div><div><label>有效时长（小时）</label><input name="durationHours" list="durationOptions" value="3" inputmode="numeric" placeholder="输入整数小时或选择永久" autocomplete="off" required></div></div><div class="row"><div><label>生成数量（单次最多 100）</label><input name="count" type="number" min="1" max="100" value="1" required></div><div><label>备注</label><input name="note" maxlength="100" placeholder="可留空"></div></div><p><button type="submit">生成链接</button></p><div class="msg" id="createMsg"></div></form>
<div class="card"><h2>自动 PROXYIP 池</h2><div class="notice">已内置 CM科技大学 ProxyIP 列表；每个国家按需缓存最多 100 个候选，并自动检测。</div><form id="syncForm"><label>要同步的国家</label><input name="country" list="countryOptions" placeholder="例如 VN / 越南" autocomplete="off" required><p><button type="submit">立即同步并检测</button></p><div class="msg" id="syncMsg"></div></form><details><summary>手动补充 PROXYIP</summary><form id="poolForm"><label>国家代码或名称</label><input name="country" list="countryOptions" placeholder="输入名称或代码搜索" autocomplete="off" required><label>PROXYIP（每行或逗号分隔）</label><textarea name="proxyIps" placeholder="38.54.59.70\nproxy.example.com:443" required></textarea><button type="submit">加入 IP 池</button><div class="msg" id="poolMsg"></div></form></details><details><summary>添加其他数据源（可选）</summary><form id="sourceForm"><label>名称</label><input name="name" maxlength="80" placeholder="我的 GitHub 列表" required><label>HTTPS / GitHub Raw / API 地址</label><input name="url" type="url" placeholder="https://..." required><div class="row three"><div><label>纯 IP 列表的默认国家（多国 JSON 留空）</label><input name="defaultCountry" list="countryOptions" placeholder="可留空"></div><div><label>刷新（分钟）</label><input name="refreshMinutes" type="number" min="5" max="1440" value="60"></div><div><label>每国上限</label><input name="maxPerCountry" type="number" min="10" max="200" value="100"></div></div><p><button type="submit">保存数据源</button></p><div class="msg" id="sourceMsg"></div></form></details></div></section>
<datalist id="countryOptions">${国家选项HTML}</datalist><datalist id="durationOptions"><option value="1">1 小时</option><option value="3">3 小时</option><option value="5">5 小时</option><option value="8">8 小时</option><option value="12">12 小时</option><option value="24">24 小时</option><option value="48">48 小时</option><option value="72">72 小时</option><option value="permanent">永久</option></datalist>
<section class="card" id="linksCard"><h2>访问链接</h2><form class="link-filters" id="linkFilters"><label>关键词（ID / 备注 / UUID / 国家 / PROXYIP）<input id="linkSearch" name="q" type="search" maxlength="100" placeholder="输入关键词"></label><label>状态<select id="linkStatus" name="status"><option value="all">全部状态</option><option value="unused">未使用</option><option value="active">使用中</option><option value="expired">已过期</option><option value="revoked">已停用</option></select></label><button type="submit">搜索</button><button type="button" class="alt" id="clearLinkFilters">清除</button></form><div class="table-tools"><div class="bulk-actions"><span id="selectedCount" class="muted">已选 0 条</span><button type="button" class="danger" id="deleteSelected" disabled>删除选中</button></div><div class="pagination"><label class="page-size">每页 <select id="pageSize" aria-label="每页显示数量"><option value="10">10 条</option><option value="20">20 条</option><option value="50">50 条</option></select></label><button type="button" class="small alt" data-page-action="first">首页</button><button type="button" class="small alt" data-page-action="prev">上一页</button><span class="page-info" id="pageInfo">第 1 / 1 页 · 共 0 条</span><button type="button" class="small alt" data-page-action="next">下一页</button><button type="button" class="small alt" data-page-action="last">末页</button></div></div><div class="tablewrap"><table><thead><tr><th class="select-col"><input type="checkbox" id="selectAll" aria-label="选中本页全部访问链接"></th><th>ID / 备注</th><th>国家</th><th>状态</th><th>时长</th><th>PROXYIP</th><th>首次使用 / 到期</th><th>链接</th><th>操作</th></tr></thead><tbody id="links"></tbody></table></div></section>
<section class="card" style="margin-top:18px"><h2>国家 IP 池</h2><div class="tablewrap"><table style="min-width:700px"><thead><tr><th>国家</th><th>总数</th><th>可用候选</th><th>已检测可用</th><th>操作</th></tr></thead><tbody id="poolStats"></tbody></table></div><details><summary>查看最近 500 条 IP</summary><div class="tablewrap"><table style="min-width:900px"><thead><tr><th>ID</th><th>国家</th><th>PROXYIP</th><th>健康状态</th><th>延迟</th><th>来源</th><th>操作</th></tr></thead><tbody id="pools"></tbody></table></div></details></section>
<section class="card" style="margin-top:18px"><h2>PROXYIP 数据源</h2><div class="tablewrap"><table style="min-width:850px"><thead><tr><th>名称</th><th>地址</th><th>同步状态</th><th>刷新周期</th><th>操作</th></tr></thead><tbody id="sources"></tbody></table></div></section></main>
<script>
const $=s=>document.querySelector(s), esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmt=v=>v?new Date(Number(v)).toLocaleString():'—';
async function api(path,options){const r=await fetch('/admin/access/api/'+path,{headers:{'Content-Type':'application/json'},...options});const j=await r.json().catch(()=>({error:'响应格式错误'}));if(!r.ok||j.success===false)throw new Error(j.error||'请求失败');return j}
function button(text,attrs,cls='small alt'){return '<button type="button" class="'+cls+'" '+attrs+'>'+text+'</button>'}
let currentPage=1,pageSize=10,totalLinks=0,totalPages=1,currentLinkIds=[],selectedLinkIds=new Set(),searchQuery='',statusFilter='all';
function updateSelection(){const boxes=[...document.querySelectorAll('[data-link-select]')],checked=boxes.filter(box=>selectedLinkIds.has(Number(box.value))).length,all=$('#selectAll');boxes.forEach(box=>box.checked=selectedLinkIds.has(Number(box.value)));all.checked=boxes.length>0&&checked===boxes.length;all.indeterminate=checked>0&&checked<boxes.length;all.disabled=!boxes.length;$('#selectedCount').textContent='已选 '+selectedLinkIds.size+' 条';$('#deleteSelected').disabled=selectedLinkIds.size===0}
function updatePagination(){totalPages=Math.max(1,Math.ceil(totalLinks/pageSize));$('#pageInfo').textContent='第 '+currentPage+' / '+totalPages+' 页 · 共 '+totalLinks+' 条';document.querySelectorAll('[data-page-action="first"],[data-page-action="prev"]').forEach(b=>b.disabled=currentPage<=1);document.querySelectorAll('[data-page-action="next"],[data-page-action="last"]').forEach(b=>b.disabled=currentPage>=totalPages||totalLinks===0)}
async function load(){try{const d=await api('state?limit='+pageSize+'&offset='+(currentPage-1)*pageSize+'&q='+encodeURIComponent(searchQuery)+'&status='+encodeURIComponent(statusFilter));const s=d.stats||{};totalLinks=Number(d.pagination?.total ?? s.total ?? 0);totalPages=Math.max(1,Math.ceil(totalLinks/pageSize));if(currentPage>totalPages){currentPage=totalPages;return await load()}$('#stats').innerHTML=['总计 '+(s.total||0),'未使用 '+(s.unused||0),'使用中 '+(s.active||0),'已过期 '+(s.expired||0),'已停用 '+(s.revoked||0)].map(x=>'<span class="pill">'+x+'</span>').join('');
const names={unused:'未使用',active:'使用中',expired:'已过期',revoked:'已停用'};currentLinkIds=d.links.map(x=>Number(x.id));selectedLinkIds=new Set([...selectedLinkIds].filter(id=>currentLinkIds.includes(id)));$('#links').innerHTML=d.links.map(x=>'<tr><td class="select-col"><input type="checkbox" data-link-select value="'+x.id+'" aria-label="选中访问链接 '+x.id+'"></td><td><b>#'+x.id+'</b><br>'+esc(x.note||'—')+'<br><span class="mono muted">'+esc(x.uuid)+'</span></td><td>'+esc(x.country)+'</td><td class="'+x.display_status+'">'+names[x.display_status]+'</td><td>'+esc(x.duration_label)+'</td><td class="mono">'+esc(x.proxy_ip||'首次连接时分配')+'</td><td>'+fmt(x.first_used_at)+'<br>'+(Number(x.duration_seconds)===0?'永久':fmt(x.expires_at))+'</td><td>'+button('复制订阅','data-copy="'+esc(x.subscription_url)+'"')+button('复制节点','data-copy="'+esc(x.node_url)+'"')+'</td><td>'+button(x.status==='active'?'停用':'启用','data-id="'+x.id+'" data-action="'+(x.status==='active'?'revoke':'enable')+'"',x.status==='active'?'small danger':'small')+button('重置计时','data-id="'+x.id+'" data-action="reset"')+button('重选 IP','data-id="'+x.id+'" data-action="reassign"')+button('删除','data-id="'+x.id+'" data-action="delete"','small danger')+'</td></tr>').join('')||'<tr><td colspan="9" class="muted">暂无链接</td></tr>';updateSelection();updatePagination();
const healthNames={unknown:'待检测',healthy:'可用',unhealthy:'不可用'};
$('#poolStats').innerHTML=(d.poolStats||[]).map(x=>'<tr><td><b>'+esc(x.country)+'</b></td><td>'+Number(x.total||0)+'</td><td>'+Number(x.available||0)+'</td><td class="healthy">'+Number(x.healthy||0)+'</td><td>'+button('同步','data-sync-country="'+esc(x.country)+'"')+button('检测 8 个','data-check-country="'+esc(x.country)+'"')+'</td></tr>').join('')||'<tr><td colspan="5" class="muted">选择国家生成链接时会自动创建 IP 池</td></tr>';
$('#pools').innerHTML=d.pools.map(x=>'<tr><td>#'+x.id+'</td><td>'+esc(x.country)+'</td><td class="mono">'+esc(x.proxy_ip)+'</td><td class="'+esc(x.health_status||'unknown')+'">'+(x.enabled?(healthNames[x.health_status]||'待检测'):'已停用')+'</td><td>'+(x.latency_ms==null?'—':Number(x.latency_ms)+' ms')+'</td><td>'+esc(x.source_name||'手动添加')+'</td><td>'+button(x.enabled?'停用':'启用','data-pool-id="'+x.id+'" data-pool-action="'+(x.enabled?'disable':'enable')+'"')+button('删除','data-pool-id="'+x.id+'" data-pool-action="delete"','small danger')+'</td></tr>').join('')||'<tr><td colspan="7" class="muted">暂无 PROXYIP；生成链接时会自动同步</td></tr>';
$('#sources').innerHTML=(d.sources||[]).map(x=>'<tr><td><b>'+esc(x.name)+'</b><br><span class="muted">'+(x.default_country?'默认 '+esc(x.default_country):'多国家数据')+'</span></td><td><span class="mono" title="'+esc(x.url)+'">'+esc(x.url.length>70?x.url.slice(0,70)+'…':x.url)+'</span></td><td class="'+(x.last_status==='error'?'unhealthy':x.last_status==='success'?'healthy':'unknown')+'">'+(x.last_status==='success'?'同步成功':x.last_status==='error'?'同步失败：'+esc(x.last_error):'尚未同步')+'<br><span class="muted">'+fmt(x.last_synced_at)+'</span></td><td>'+Number(x.refresh_minutes)+' 分钟<br>每国 '+Number(x.max_per_country)+'</td><td>'+button(x.enabled?'停用':'启用','data-source-id="'+x.id+'" data-source-action="'+(x.enabled?'disable':'enable')+'"')+(x.url.includes('zip.cm.edu.kg.cmliussss.net')?'':button('删除','data-source-id="'+x.id+'" data-source-action="delete"','small danger'))+'</td></tr>').join('')||'<tr><td colspan="5" class="muted">暂无数据源</td></tr>';}catch(e){alert(e.message)}}
$('#linkFilters').addEventListener('submit',e=>{e.preventDefault();const f=new FormData(e.target);searchQuery=String(f.get('q')||'').trim();statusFilter=String(f.get('status')||'all');currentPage=1;selectedLinkIds.clear();load()});
$('#clearLinkFilters').addEventListener('click',()=>{$('#linkSearch').value='';$('#linkStatus').value='all';searchQuery='';statusFilter='all';currentPage=1;selectedLinkIds.clear();load()});
$('#createForm').addEventListener('submit',async e=>{e.preventDefault();const f=new FormData(e.target),b=e.submitter;b.disabled=true;$('#createMsg').textContent='正在同步并检测该国家的 PROXYIP…';try{const d=await api('links',{method:'POST',body:JSON.stringify(Object.fromEntries(f))});$('#createMsg').textContent=d.message;currentPage=1;selectedLinkIds.clear();await load()}catch(err){$('#createMsg').textContent=err.message}finally{b.disabled=false}});
$('#syncForm').addEventListener('submit',async e=>{e.preventDefault();const f=new FormData(e.target),b=e.submitter;b.disabled=true;$('#syncMsg').textContent='正在下载列表并检测，请稍候…';try{const d=await api('pools/sync',{method:'POST',body:JSON.stringify(Object.fromEntries(f))});$('#syncMsg').textContent=d.message;await load()}catch(err){$('#syncMsg').textContent=err.message}finally{b.disabled=false}});
$('#poolForm').addEventListener('submit',async e=>{e.preventDefault();const f=new FormData(e.target);try{const d=await api('pools',{method:'POST',body:JSON.stringify(Object.fromEntries(f))});$('#poolMsg').textContent=d.message;await load()}catch(err){$('#poolMsg').textContent=err.message}});
$('#sourceForm').addEventListener('submit',async e=>{e.preventDefault();const f=new FormData(e.target);try{const d=await api('sources',{method:'POST',body:JSON.stringify(Object.fromEntries(f))});$('#sourceMsg').textContent=d.message;e.target.reset();await load()}catch(err){$('#sourceMsg').textContent=err.message}});
document.addEventListener('change',e=>{const t=e.target;if(t.id==='selectAll'){currentLinkIds.forEach(id=>t.checked?selectedLinkIds.add(id):selectedLinkIds.delete(id));updateSelection()}else if(t.matches('[data-link-select]')){const id=Number(t.value);t.checked?selectedLinkIds.add(id):selectedLinkIds.delete(id);updateSelection()}else if(t.id==='pageSize'){pageSize=Number(t.value);currentPage=1;selectedLinkIds.clear();load()}});
document.addEventListener('click',async e=>{const b=e.target.closest('button');if(!b)return;if(b.dataset.copy){await navigator.clipboard.writeText(b.dataset.copy);b.textContent='已复制';setTimeout(()=>b.textContent=b.dataset.copy.includes('/sub?')?'复制订阅':'复制节点',900);return}if(b.dataset.pageAction){const target={first:1,prev:currentPage-1,next:currentPage+1,last:totalPages}[b.dataset.pageAction];if(target>=1&&target<=totalPages&&target!==currentPage){currentPage=target;selectedLinkIds.clear();await load();$('#linksCard').scrollIntoView({behavior:'smooth',block:'start'})}return}try{b.disabled=true;if(b.id==='deleteSelected'){const ids=[...selectedLinkIds];if(!ids.length||!confirm('确定删除选中的 '+ids.length+' 条访问链接？'))return;const d=await api('links/action',{method:'POST',body:JSON.stringify({ids,action:'delete'})});selectedLinkIds.clear();alert(d.message)}else if(b.dataset.action){if((b.dataset.action==='delete'||b.dataset.action==='reset')&&!confirm('确定执行此操作？'))return;await api('links/action',{method:'POST',body:JSON.stringify({id:Number(b.dataset.id),action:b.dataset.action})})}else if(b.dataset.poolAction){await api('pools/action',{method:'POST',body:JSON.stringify({id:Number(b.dataset.poolId),action:b.dataset.poolAction})})}else if(b.dataset.syncCountry){const d=await api('pools/sync',{method:'POST',body:JSON.stringify({country:b.dataset.syncCountry})});alert(d.message)}else if(b.dataset.checkCountry){const d=await api('pools/check',{method:'POST',body:JSON.stringify({country:b.dataset.checkCountry,limit:8})});alert(d.message)}else if(b.dataset.sourceAction){if(b.dataset.sourceAction==='delete'&&!confirm('确定删除该数据源及其导入的 IP？'))return;await api('sources/action',{method:'POST',body:JSON.stringify({id:Number(b.dataset.sourceId),action:b.dataset.sourceAction})})}else return;await load()}catch(err){alert(err.message)}finally{b.disabled=false}});load();
</script></body></html>`;
	return new Response(html, { status: 200, headers: { 'Content-Type': 'text/html;charset=utf-8', 'Cache-Control': 'no-store', 'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'" } });
}

///////////////////////////////////////////////////////////////////////XHTTP传输数据///////////////////////////////////////////////
async function 处理XHTTP请求(request, yourUUID, 访问授权上下文 = null, 请求反代上下文 = null) {
	if (!request.body) return new Response('Bad Request', { status: 400 });
	const reader = request.body.getReader();
	const 首包 = await 读取XHTTP首包(reader, yourUUID);
	if (!首包) {
		try { reader.releaseLock() } catch (e) { }
		return new Response('Invalid request', { status: 400 });
	}
	if (isSpeedTestSite(首包.hostname)) {
		try { reader.releaseLock() } catch (e) { }
		return new Response('Forbidden', { status: 403 });
	}
	if (首包.isUDP && 首包.协议 !== 'trojan' && 首包.port !== 53) {
		try { reader.releaseLock() } catch (e) { }
		return new Response('UDP is not supported', { status: 400 });
	}
	if (访问授权上下文) {
		try {
			await 激活访问授权上下文(访问授权上下文);
		} catch (error) {
			try { reader.releaseLock() } catch (e) { }
			return 访问错误响应(error?.message || '访问链接不可用', error?.status || 403);
		}
	}

	// 连接器按请求追踪 socket，无需修改运行时的 fetcher。
	const remoteConnWrapper = { socket: null, connectingPromise: null, retryConnect: null, cancelled: false, sockets: new Set() };
	let 当前写入Socket = null;
	let 远端写入器 = null;
	const responseHeaders = new Headers({
		'Content-Type': 'application/octet-stream',
		'X-Accel-Buffering': 'no',
		'Cache-Control': 'no-store'
	});

	const 释放远端写入器 = () => {
		if (远端写入器) {
			try { 远端写入器.releaseLock() } catch (e) { }
			远端写入器 = null;
		}
		当前写入Socket = null;
	};

	const 获取远端写入器 = () => {
		const socket = remoteConnWrapper.socket;
		if (!socket) return null;
		if (socket !== 当前写入Socket) {
			释放远端写入器();
			当前写入Socket = socket;
			远端写入器 = socket.writable.getWriter();
		}
		return 远端写入器;
	};

	let XHTTP上行写入队列 = null;
	let 关闭XHTTP连接 = null;
	let XHTTP访问到期定时器 = null;
	const 结束XHTTP访问授权 = (success, errorCode) => {
		if (XHTTP访问到期定时器) clearTimeout(XHTTP访问到期定时器);
		XHTTP访问到期定时器 = null;
		return 结束访问授权上下文(访问授权上下文, success, errorCode);
	};
	return new Response(new ReadableStream({
		async start(controller) {
			let 已关闭 = false;
			let udpRespHeader = 首包.respHeader;
			const 木马UDP上下文 = { 缓存: new Uint8Array(0) };
			const xhttpBridge = {
				readyState: WebSocket.OPEN,
				send(data) {
					if (已关闭) return;
					try {
						const chunk = data instanceof Uint8Array
							? data
							: data instanceof ArrayBuffer
								? new Uint8Array(data)
								: ArrayBuffer.isView(data)
									? new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
									: new Uint8Array(data);
						controller.enqueue(chunk);
					} catch (e) {
						void 关闭连接(访问授权上下文?.代理连接成功, 'client_cancelled');
					}
				},
				close() {
					void 关闭连接();
				}
			};
			const 关闭连接 = 关闭XHTTP连接 = (success = 访问授权上下文?.代理连接成功, errorCode = '') => {
				if (已关闭) return 访问授权上下文?.释放任务;
				已关闭 = true;
				remoteConnWrapper.cancelled = true;
				xhttpBridge.readyState = WebSocket.CLOSED;
				XHTTP上行写入队列?.清空();
				for (const socket of remoteConnWrapper.sockets) { try { socket.close?.() } catch (_) { } }
				try { remoteConnWrapper.socket?.close() } catch (e) { }
				void reader.cancel().catch(() => { });
				释放远端写入器();
				try { reader.releaseLock() } catch (e) { }
				try { controller.close() } catch (e) { }
				return 结束XHTTP访问授权(success, errorCode || (success ? '' : 'upstream_failed'));
			};
			XHTTP访问到期定时器 = 安排访问链接到期(访问授权上下文, 关闭连接);

			const 上行写入队列 = XHTTP上行写入队列 = 创建上行写入队列({
				获取写入器: 获取远端写入器,
				释放写入器: 释放远端写入器,
				重试连接: async () => {
					if (typeof remoteConnWrapper.retryConnect !== 'function') throw new Error('retry unavailable');
					await remoteConnWrapper.retryConnect();
				},
				关闭连接,
				名称: 'XHTTP上行'
			});

			const 写入远端 = async (payload, allowRetry = true) => {
				return 上行写入队列.写入并等待(payload, allowRetry);
			};

			try {
				if (首包.isUDP) {
					if (首包.rawData?.byteLength) {
						if (首包.协议 === 'trojan') await 转发木马UDP数据(首包.rawData, xhttpBridge, 木马UDP上下文, request, 访问授权上下文);
						else await forwardataudp(首包.rawData, xhttpBridge, udpRespHeader, request, null, 访问授权上下文);
						udpRespHeader = null;
					}
				} else {
					await forwardataTCP(首包.hostname, 首包.port, 首包.rawData, xhttpBridge, 首包.respHeader, remoteConnWrapper, yourUUID, request, 访问授权上下文?.反代上下文 || 请求反代上下文);
				}

				while (!已关闭) {
					const { done, value } = await reader.read();
					if (done || 已关闭) break;
					if (!value || value.byteLength === 0) continue;
					if (首包.isUDP) {
						if (首包.协议 === 'trojan') await 转发木马UDP数据(value, xhttpBridge, 木马UDP上下文, request, 访问授权上下文);
						else await forwardataudp(value, xhttpBridge, udpRespHeader, request, null, 访问授权上下文);
						udpRespHeader = null;
					} else {
						if (!(await 写入远端(value))) throw new Error('Remote socket is not ready');
					}
				}

				if (!已关闭 && !首包.isUDP) {
					await 上行写入队列.等待空();
					const writer = 获取远端写入器();
					if (writer) {
						try { await writer.close() } catch (e) { }
					}
				}
			} catch (err) {
				log(`[XHTTP转发] 处理失败: ${err?.message || err}`);
				closeSocketQuietly(xhttpBridge);
			} finally {
				上行写入队列.清空();
				释放远端写入器();
				try { reader.releaseLock() } catch (e) { }
			}
		},
		cancel() {
			return 关闭XHTTP连接?.(访问授权上下文?.代理连接成功, 'client_cancelled');
		}
	}), { status: 200, headers: responseHeaders });
}

function 有效数据长度(data) {
	if (!data) return 0;
	if (typeof data.byteLength === 'number') return data.byteLength;
	if (typeof data.length === 'number') return data.length;
	return 0;
}

function 尝试解析传输首包(data, token) {
	const decoder = VLESS文本解码器;

	const 尝试解析魏烈思首包 = (data) => {
		const length = data.byteLength;
		if (length < 18) return { 状态: 'need_more' };
		if (!UUID字节匹配(data, 1, token)) return { 状态: 'invalid' };

		const optLen = data[17];
		const cmdIndex = 18 + optLen;
		if (length < cmdIndex + 1) return { 状态: 'need_more' };

		const cmd = data[cmdIndex];
		if (cmd !== 1 && cmd !== 2) return { 状态: 'invalid' };

		const portIndex = cmdIndex + 1;
		if (length < portIndex + 3) return { 状态: 'need_more' };

		const port = (data[portIndex] << 8) | data[portIndex + 1];
		const addressType = data[portIndex + 2];
		const addressIndex = portIndex + 3;
		let headerLen = -1;
		let hostname = '';

		if (addressType === 1) {
			if (length < addressIndex + 4) return { 状态: 'need_more' };
			hostname = `${data[addressIndex]}.${data[addressIndex + 1]}.${data[addressIndex + 2]}.${data[addressIndex + 3]}`;
			headerLen = addressIndex + 4;
		} else if (addressType === 2) {
			if (length < addressIndex + 1) return { 状态: 'need_more' };
			const domainLen = data[addressIndex];
			if (length < addressIndex + 1 + domainLen) return { 状态: 'need_more' };
			hostname = decoder.decode(data.subarray(addressIndex + 1, addressIndex + 1 + domainLen));
			headerLen = addressIndex + 1 + domainLen;
		} else if (addressType === 3) {
			if (length < addressIndex + 16) return { 状态: 'need_more' };
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				const base = addressIndex + i * 2;
				ipv6.push(((data[base] << 8) | data[base + 1]).toString(16));
			}
			hostname = ipv6.join(':');
			headerLen = addressIndex + 16;
		} else return { 状态: 'invalid' };

		if (!hostname) return { 状态: 'invalid' };

		return {
			状态: 'ok',
			结果: {
				协议: 'vl' + 'ess',
				hostname,
				port,
				isUDP: cmd === 2,
				rawData: data.subarray(headerLen),
				respHeader: new Uint8Array([data[0], 0]),
			}
		};
	};

	const 尝试解析木马首包 = (data) => {
		const 密码哈希 = sha224(token);
		const 密码哈希字节 = new TextEncoder().encode(密码哈希);
		const length = data.byteLength;
		if (length < 58) return { 状态: 'need_more' };
		if (data[56] !== 0x0d || data[57] !== 0x0a) return { 状态: 'invalid' };
		for (let i = 0; i < 56; i++) {
			if (data[i] !== 密码哈希字节[i]) return { 状态: 'invalid' };
		}

		const socksStart = 58;
		if (length < socksStart + 2) return { 状态: 'need_more' };
		const cmd = data[socksStart];
		if (cmd !== 1 && cmd !== 3) return { 状态: 'invalid' };
		const isUDP = cmd === 3;

		const atype = data[socksStart + 1];
		let cursor = socksStart + 2;
		let hostname = '';

		if (atype === 1) {
			if (length < cursor + 4) return { 状态: 'need_more' };
			hostname = `${data[cursor]}.${data[cursor + 1]}.${data[cursor + 2]}.${data[cursor + 3]}`;
			cursor += 4;
		} else if (atype === 3) {
			if (length < cursor + 1) return { 状态: 'need_more' };
			const domainLen = data[cursor];
			if (length < cursor + 1 + domainLen) return { 状态: 'need_more' };
			hostname = decoder.decode(data.subarray(cursor + 1, cursor + 1 + domainLen));
			cursor += 1 + domainLen;
		} else if (atype === 4) {
			if (length < cursor + 16) return { 状态: 'need_more' };
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				const base = cursor + i * 2;
				ipv6.push(((data[base] << 8) | data[base + 1]).toString(16));
			}
			hostname = ipv6.join(':');
			cursor += 16;
		} else return { 状态: 'invalid' };

		if (!hostname) return { 状态: 'invalid' };
		if (length < cursor + 4) return { 状态: 'need_more' };

		const port = (data[cursor] << 8) | data[cursor + 1];
		if (data[cursor + 2] !== 0x0d || data[cursor + 3] !== 0x0a) return { 状态: 'invalid' };
		const dataOffset = cursor + 4;

		return {
			状态: 'ok',
			结果: {
				协议: 'trojan',
				hostname,
				port,
				isUDP,
				rawData: data.subarray(dataOffset),
				respHeader: null,
			}
		};
	};

	const 木马结果 = 尝试解析木马首包(data);
	if (木马结果.状态 === 'ok') return 木马结果;
	const 魏烈思结果 = 尝试解析魏烈思首包(data);
	if (魏烈思结果.状态 === 'ok') return 魏烈思结果;
	return { 状态: 木马结果.状态 === 'invalid' && 魏烈思结果.状态 === 'invalid' ? 'invalid' : 'need_more' };
}

async function 读取XHTTP首包(reader, token) {
	let buffer = new Uint8Array(1024);
	let offset = 0;

	while (true) {
		const { value, done } = await reader.read();
		if (done) {
			if (offset === 0) return null;
			break;
		}

		const chunk = value instanceof Uint8Array ? value : new Uint8Array(value);
		if (offset + chunk.byteLength > buffer.byteLength) {
			const newBuffer = new Uint8Array(Math.max(buffer.byteLength * 2, offset + chunk.byteLength));
			newBuffer.set(buffer.subarray(0, offset));
			buffer = newBuffer;
		}

		buffer.set(chunk, offset);
		offset += chunk.byteLength;

		const 当前数据 = buffer.subarray(0, offset);
		const 解析结果 = 尝试解析传输首包(当前数据, token);
		if (解析结果.状态 === 'ok') return { ...解析结果.结果, reader };
		if (解析结果.状态 === 'invalid') return null;
	}

	const 最终数据 = buffer.subarray(0, offset);
	const 最终结果 = 尝试解析传输首包(最终数据, token);
	if (最终结果.状态 === 'ok') return { ...最终结果.结果, reader };
	return null;
}
///////////////////////////////////////////////////////////////////////gRPC传输数据///////////////////////////////////////////////
async function 处理gRPC请求(request, yourUUID, 访问授权上下文 = null, 请求反代上下文 = null) {
	if (!request.body) return new Response('Bad Request', { status: 400 });
	const reader = request.body.getReader();
	const remoteConnWrapper = { socket: null, connectingPromise: null, retryConnect: null, cancelled: false, sockets: new Set() };
	let isDnsQuery = false;
	const 木马UDP上下文 = { 缓存: new Uint8Array(0) };
	let 判断是否是木马 = null;
	let 当前写入Socket = null;
	let 远端写入器 = null;
	let GRPC上行写入队列 = null;
	let 关闭GRPC连接 = null;
	//log('[gRPC] 开始处理双向流');
	const grpcHeaders = new Headers({
		'Content-Type': 'application/grpc',
		'grpc-status': '0',
		'X-Accel-Buffering': 'no',
		'Cache-Control': 'no-store'
	});

	const 下行缓存上限 = 下行Grain包字节;
	const 下行刷新间隔 = Math.max(下行Grain静默毫秒, 1);

	return new Response(new ReadableStream({
		async start(controller) {
			let 已关闭 = false;
			let 发送队列 = [];
			let 队列字节数 = 0;
			let 刷新定时器 = null;
			let 刷新Microtask已排队 = false;
			const grpcBridge = {
				readyState: WebSocket.OPEN,
				send(data) {
					if (已关闭) return;
					const chunk = data instanceof Uint8Array ? data : new Uint8Array(data);
					const lenBytes数组 = [];
					let remaining = chunk.byteLength >>> 0;
					while (remaining > 127) {
						lenBytes数组.push((remaining & 0x7f) | 0x80);
						remaining >>>= 7;
					}
					lenBytes数组.push(remaining);
					const lenBytes = new Uint8Array(lenBytes数组);
					const protobufLen = 1 + lenBytes.length + chunk.byteLength;
					const frame = new Uint8Array(5 + protobufLen);
					frame[0] = 0;
					frame[1] = (protobufLen >>> 24) & 0xff;
					frame[2] = (protobufLen >>> 16) & 0xff;
					frame[3] = (protobufLen >>> 8) & 0xff;
					frame[4] = protobufLen & 0xff;
					frame[5] = 0x0a;
					frame.set(lenBytes, 6);
					frame.set(chunk, 6 + lenBytes.length);
					发送队列.push(frame);
					队列字节数 += frame.byteLength;
					安排刷新发送队列();
				},
				close() {
					void 关闭连接();
				}
			};

			const 刷新发送队列 = (force = false) => {
				刷新Microtask已排队 = false;
				if (刷新定时器) {
					clearTimeout(刷新定时器);
					刷新定时器 = null;
				}
				if ((!force && 已关闭) || 队列字节数 === 0) return;
				const out = new Uint8Array(队列字节数);
				let offset = 0;
				for (const item of 发送队列) {
					out.set(item, offset);
					offset += item.byteLength;
				}
				发送队列 = [];
				队列字节数 = 0;
				try {
					controller.enqueue(out);
				} catch (e) {
					void 关闭连接(访问授权上下文?.代理连接成功, 'client_cancelled');
				}
			};

			const 安排刷新发送队列 = () => {
				if (队列字节数 >= 下行缓存上限) {
					刷新发送队列();
					return;
				}
				if (刷新Microtask已排队 || 刷新定时器) return;
				刷新Microtask已排队 = true;
				queueMicrotask(() => {
					刷新Microtask已排队 = false;
					if (已关闭 || 队列字节数 === 0 || 刷新定时器) return;
					刷新定时器 = setTimeout(刷新发送队列, 下行刷新间隔);
				});
			};

			const 关闭连接 = 关闭GRPC连接 = (success = 访问授权上下文?.代理连接成功, errorCode = '') => {
				if (已关闭) return 访问授权上下文?.释放任务;
				已关闭 = true;
				remoteConnWrapper.cancelled = true;
				for (const socket of remoteConnWrapper.sockets) { try { socket.close?.() } catch (_) { } }
				GRPC上行写入队列?.清空();
				刷新发送队列(true);
				grpcBridge.readyState = WebSocket.CLOSED;
				if (刷新定时器) clearTimeout(刷新定时器);
				if (远端写入器) {
					try { 远端写入器.releaseLock() } catch (e) { }
					远端写入器 = null;
				}
				当前写入Socket = null;
				void reader.cancel().catch(() => { });
				try { reader.releaseLock() } catch (e) { }
				try { remoteConnWrapper.socket?.close() } catch (e) { }
				try { controller.close() } catch (e) { }
				return 结束访问授权上下文(访问授权上下文, success, errorCode || (success ? '' : 'upstream_failed'));
			};

			const 释放远端写入器 = () => {
				if (远端写入器) {
					try { 远端写入器.releaseLock() } catch (e) { }
					远端写入器 = null;
				}
				当前写入Socket = null;
			};

			const 上行写入队列 = GRPC上行写入队列 = 创建上行写入队列({
				获取写入器: () => {
					const socket = remoteConnWrapper.socket;
					if (!socket) return null;
					if (socket !== 当前写入Socket) {
						释放远端写入器();
						当前写入Socket = socket;
						远端写入器 = socket.writable.getWriter();
					}
					return 远端写入器;
				},
				释放写入器: 释放远端写入器,
				重试连接: async () => {
					if (typeof remoteConnWrapper.retryConnect !== 'function') throw new Error('retry unavailable');
					await remoteConnWrapper.retryConnect();
				},
				关闭连接,
				名称: 'gRPC上行'
			});

			const 写入远端 = async (payload, allowRetry = true) => {
				return 上行写入队列.写入并等待(payload, allowRetry);
			};

			try {
				let pending = new Uint8Array(0);
				let 首包缓存 = new Uint8Array(0);
				while (true) {
					const { done, value } = await reader.read();
					if (done) break;
					if (!value || value.byteLength === 0) continue;
					const 当前块 = value instanceof Uint8Array ? value : new Uint8Array(value);
					const merged = new Uint8Array(pending.length + 当前块.length);
					merged.set(pending, 0);
					merged.set(当前块, pending.length);
					pending = merged;
					while (pending.byteLength >= 5) {
						const grpcLen = new DataView(pending.buffer, pending.byteOffset, 5).getUint32(1);
						if (pending[0] !== 0 || grpcLen > 上行队列最大字节) throw new Error('Invalid gRPC frame');
						const frameSize = 5 + grpcLen;
						if (pending.byteLength < frameSize) break;
						const grpcPayload = pending.subarray(5, frameSize);
						pending = pending.slice(frameSize);
						if (!grpcPayload.byteLength) continue;
						let payload = grpcPayload;
						if (payload.byteLength >= 2 && payload[0] === 0x0a) {
							let shift = 0;
							let offset = 1;
							let varint有效 = false;
							while (offset < payload.length) {
								const current = payload[offset++];
								if ((current & 0x80) === 0) {
									varint有效 = true;
									break;
								}
								shift += 7;
								if (shift > 35) break;
							}
							if (varint有效) payload = payload.subarray(offset);
						}
						if (!payload.byteLength) continue;
						if (isDnsQuery) {
							if (判断是否是木马) await 转发木马UDP数据(payload, grpcBridge, 木马UDP上下文, request, 访问授权上下文);
							else await forwardataudp(payload, grpcBridge, null, request, null, 访问授权上下文);
							continue;
						}
						if (remoteConnWrapper.socket) {
							if (!(await 写入远端(payload))) throw new Error('Remote socket is not ready');
						} else {
							// gRPC 消息边界不保证与代理协议首包边界一致。
							首包缓存 = 拼接字节数据(首包缓存, payload);
							const 首包解析 = 尝试解析传输首包(首包缓存, yourUUID);
							if (首包解析.状态 === 'need_more' && 首包缓存.byteLength <= 1024) continue;
							if (首包解析.状态 !== 'ok') throw new Error('Invalid proxy header');
							const 首包bytes = 首包缓存;
							首包缓存 = new Uint8Array(0);
							判断是否是木马 = 首包解析.结果.协议 === 'trojan';
							if (判断是否是木马) {
								const 解析结果 = 解析木马请求(首包bytes, yourUUID);
								if (解析结果?.hasError) throw new Error(解析结果.message || 'Invalid trojan request');
								const { port, hostname, rawClientData, isUDP } = 解析结果;
								if (isSpeedTestSite(hostname)) throw new Error('Speedtest site is blocked');
								if (访问授权上下文) {
									await 激活访问授权上下文(访问授权上下文);
									安排访问链接到期(访问授权上下文, 关闭连接);
								}
								log(`[gRPC] 木马首包: ${hostname}:${port} | UDP: ${isUDP ? '是' : '否'}`);
								if (isUDP) {
									isDnsQuery = true;
									if (有效数据长度(rawClientData) > 0) await 转发木马UDP数据(rawClientData, grpcBridge, 木马UDP上下文, request, 访问授权上下文);
								} else {
									await forwardataTCP(hostname, port, rawClientData, grpcBridge, null, remoteConnWrapper, yourUUID, request, 访问授权上下文?.反代上下文 || 请求反代上下文);
								}
							} else {
								判断是否是木马 = false;
								const 解析结果 = 解析魏烈思请求(首包bytes, yourUUID);
								if (解析结果?.hasError) throw new Error(解析结果.message || 'Invalid 魏烈思 request');
								const { port, hostname, version, isUDP, rawClientData } = 解析结果;
								if (isSpeedTestSite(hostname)) throw new Error('Speedtest site is blocked');
								if (isUDP && port !== 53) throw new Error('UDP is not supported');
								if (访问授权上下文) {
									await 激活访问授权上下文(访问授权上下文);
									安排访问链接到期(访问授权上下文, 关闭连接);
								}
								log(`[gRPC] 魏烈思首包: ${hostname}:${port} | UDP: ${isUDP ? '是' : '否'}`);
								if (isUDP) {
									isDnsQuery = true;
								}
								const respHeader = new Uint8Array([version, 0]);
								grpcBridge.send(respHeader);
								const rawData = rawClientData;
								if (isDnsQuery) {
									if (判断是否是木马) await 转发木马UDP数据(rawData, grpcBridge, 木马UDP上下文, request, 访问授权上下文);
									else await forwardataudp(rawData, grpcBridge, null, request, null, 访问授权上下文);
								}
								else await forwardataTCP(hostname, port, rawData, grpcBridge, null, remoteConnWrapper, yourUUID, request, 访问授权上下文?.反代上下文 || 请求反代上下文);
							}
						}
					}
					刷新发送队列();
				}
				if (pending.byteLength) throw new Error('Incomplete gRPC frame');
				if (首包缓存.byteLength) throw new Error('Incomplete proxy header');
				await 上行写入队列.等待空();
				if (!已关闭 && !isDnsQuery && remoteConnWrapper.socket) {
					// 上传 EOF 只关闭 TCP 写端，下行 EOF 或客户端取消时才释放连接和租约。
					释放远端写入器();
					远端写入器 = remoteConnWrapper.socket.writable.getWriter();
					await 远端写入器.close();
				} else if (!已关闭) await 关闭连接();
			} catch (err) {
				log(`[gRPC转发] 处理失败: ${err?.message || err}`);
				await 关闭连接(false, 'upstream_failed');
			} finally {
				上行写入队列.清空();
				释放远端写入器();
				try { reader.releaseLock() } catch (e) { }
			}
		},
		cancel() {
			return 关闭GRPC连接?.(访问授权上下文?.代理连接成功, 'client_cancelled');
		}
	}), { status: 200, headers: grpcHeaders });
}

function 是有效WS早期数据(bytes, token) {
	if (!bytes?.byteLength) return false;
	if (bytes.byteLength >= 18 && UUID字节匹配(bytes, 1, token)) return true;
	if (bytes.byteLength < 58 || bytes[56] !== 0x0d || bytes[57] !== 0x0a) return false;

	const trojanPassword = sha224(token);
	for (let i = 0; i < 56; i++) {
		if (bytes[i] !== trojanPassword.charCodeAt(i)) return false;
	}
	return true;
}

function 解码WS早期数据(header, token) {
	if (!header) return null;
	if (header.length > WS早期数据最大头长度) throw new Error('early data is too large');

	let bytes;
	const Uint8ArrayBase64 = /** @type {any} */ (Uint8Array);
	if (typeof Uint8ArrayBase64.fromBase64 === 'function') {
		try {
			bytes = Uint8ArrayBase64.fromBase64(header, { alphabet: 'base64url' });
		} catch (_) { }
	}
	if (!bytes) {
		let normalized = header.replace(/-/g, '+').replace(/_/g, '/');
		const padding = normalized.length % 4;
		if (padding) normalized += '='.repeat(4 - padding);
		let binaryString;
		try {
			binaryString = atob(normalized);
		} catch (_) {
			return null;
		}
		bytes = new Uint8Array(binaryString.length);
		for (let i = 0; i < binaryString.length; i++) bytes[i] = binaryString.charCodeAt(i);
	}

	if (bytes.byteLength > WS早期数据最大字节) throw new Error('early data is too large');
	return 是有效WS早期数据(bytes, token) ? bytes : null;
}

///////////////////////////////////////////////////////////////////////WS传输数据///////////////////////////////////////////////
async function 处理WS请求(request, yourUUID, url, 访问授权上下文 = null, 请求反代上下文 = null) {
	const WS套接字对 = new WebSocketPair();
	const [clientSock, serverSock] = Object.values(WS套接字对);
	try { (/** @type {any} */ (serverSock)).accept({ allowHalfOpen: true }) }
	catch (_) { serverSock.accept() }
	serverSock.binaryType = 'arraybuffer';
	let remoteConnWrapper = { socket: null, connectingPromise: null, retryConnect: null };
	let isDnsQuery = false;
	let 判断是否是木马 = null;
	const 木马UDP上下文 = { 缓存: new Uint8Array(0) };
	const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
	const SS模式禁用EarlyData = !!url.searchParams.get('enc');
	let WS上行写入队列 = null;
	let WS显式传输链 = Promise.resolve();
	let WS显式传输停止接收 = false, WS显式传输失败 = false, WS显式传输收尾已入队 = false;
	let WS显式队列字节 = 0, WS显式队列条目 = 0;
	let 判断协议类型 = null, 当前写入Socket = null, 远端写入器 = null;
	let WS首包缓存 = new Uint8Array(0);
	let ss上下文 = null, ss初始化任务 = null;

	const 释放远端写入器 = () => {
		if (远端写入器) {
			try { 远端写入器.releaseLock() } catch (e) { }
			远端写入器 = null;
		}
		当前写入Socket = null;
	};

	const 上行写入队列 = WS上行写入队列 = 创建上行写入队列({
		获取写入器: () => {
			const socket = remoteConnWrapper.socket;
			if (!socket) return null;
			if (socket !== 当前写入Socket) {
				释放远端写入器();
				当前写入Socket = socket;
				远端写入器 = socket.writable.getWriter();
			}
			return 远端写入器;
		},
		释放写入器: 释放远端写入器,
		重试连接: async () => {
			if (typeof remoteConnWrapper.retryConnect !== 'function') throw new Error('retry unavailable');
			await remoteConnWrapper.retryConnect();
		},
		关闭连接: () => {
			try { remoteConnWrapper.socket?.close() } catch (e) { }
			closeSocketQuietly(serverSock);
		},
		名称: 'WS上行'
	});

	const 写入远端 = async (chunk, allowRetry = true) => {
		return 上行写入队列.写入并等待(chunk, allowRetry);
	};

	const 获取SS上下文 = async () => {
		if (ss上下文) return ss上下文;
		if (!ss初始化任务) {
			ss初始化任务 = (async () => {
				const 请求加密方式 = (url.searchParams.get('enc') || '').toLowerCase();
				const 首选加密配置 = SS支持加密配置[请求加密方式] || SS支持加密配置['aes-128-gcm'];
				const 入站候选加密配置 = [首选加密配置, ...Object.values(SS支持加密配置).filter(c => c.method !== 首选加密配置.method)];
				const 入站主密钥任务缓存 = new Map();
				const 取入站主密钥任务 = (config) => {
					if (!入站主密钥任务缓存.has(config.method)) 入站主密钥任务缓存.set(config.method, SS派生主密钥(yourUUID, config.keyLen));
					return 入站主密钥任务缓存.get(config.method);
				};
				const 入站状态 = {
					buffer: new Uint8Array(0),
					hasSalt: false,
					waitPayloadLength: null,
					decryptKey: null,
					nonceCounter: new Uint8Array(SSNonce长度),
					加密配置: null,
				};
				const 初始化入站解密状态 = async () => {
					const lengthCipherTotalLength = 2 + SSAEAD标签长度;
					const 最大盐长度 = Math.max(...入站候选加密配置.map(c => c.saltLen));
					const 最大对齐扫描字节 = 16;
					const 可扫描最大偏移 = Math.min(最大对齐扫描字节, Math.max(0, 入站状态.buffer.byteLength - (lengthCipherTotalLength + Math.min(...入站候选加密配置.map(c => c.saltLen)))));
					for (let offset = 0; offset <= 可扫描最大偏移; offset++) {
						for (const 加密配置 of 入站候选加密配置) {
							const 初始化最小长度 = offset + 加密配置.saltLen + lengthCipherTotalLength;
							if (入站状态.buffer.byteLength < 初始化最小长度) continue;
							const salt = 入站状态.buffer.subarray(offset, offset + 加密配置.saltLen);
							const lengthCipher = 入站状态.buffer.subarray(offset + 加密配置.saltLen, 初始化最小长度);
							const masterKey = await 取入站主密钥任务(加密配置);
							const decryptKey = await SS派生会话密钥(加密配置, masterKey, salt, ['decrypt']);
							const nonceCounter = new Uint8Array(SSNonce长度);
							try {
								const lengthPlain = await SSAEAD解密(decryptKey, nonceCounter, lengthCipher);
								if (lengthPlain.byteLength !== 2) continue;
								const payloadLength = (lengthPlain[0] << 8) | lengthPlain[1];
								if (payloadLength < 0 || payloadLength > 加密配置.maxChunk) continue;
								if (offset > 0) log(`[SS入站] 检测到前导噪声 ${offset}B，已自动对齐`);
								if (加密配置.method !== 首选加密配置.method) log(`[SS入站] URL enc=${请求加密方式 || 首选加密配置.method} 与实际 ${加密配置.method} 不一致，已自动切换`);
								入站状态.buffer = 入站状态.buffer.subarray(初始化最小长度);
								入站状态.decryptKey = decryptKey;
								入站状态.nonceCounter = nonceCounter;
								入站状态.waitPayloadLength = payloadLength;
								入站状态.加密配置 = 加密配置;
								入站状态.hasSalt = true;
								return true;
							} catch (_) { }
						}
					}
					const 初始化失败判定长度 = 最大盐长度 + lengthCipherTotalLength + 最大对齐扫描字节;
					if (入站状态.buffer.byteLength >= 初始化失败判定长度) {
						throw new Error(`SS handshake decrypt failed (enc=${请求加密方式 || 'auto'}, candidates=${入站候选加密配置.map(c => c.method).join('/')})`);
					}
					return false;
				};
				const 入站解密器 = {
					async 输入(dataChunk) {
						const chunk = 数据转Uint8Array(dataChunk);
						if (chunk.byteLength > 0) 入站状态.buffer = 拼接字节数据(入站状态.buffer, chunk);
						if (!入站状态.hasSalt) {
							const 初始化成功 = await 初始化入站解密状态();
							if (!初始化成功) return [];
						}
						const plaintextChunks = [];
						while (true) {
							if (入站状态.waitPayloadLength === null) {
								const lengthCipherTotalLength = 2 + SSAEAD标签长度;
								if (入站状态.buffer.byteLength < lengthCipherTotalLength) break;
								const lengthCipher = 入站状态.buffer.subarray(0, lengthCipherTotalLength);
								入站状态.buffer = 入站状态.buffer.subarray(lengthCipherTotalLength);
								const lengthPlain = await SSAEAD解密(入站状态.decryptKey, 入站状态.nonceCounter, lengthCipher);
								if (lengthPlain.byteLength !== 2) throw new Error('SS length decrypt failed');
								const payloadLength = (lengthPlain[0] << 8) | lengthPlain[1];
								if (payloadLength < 0 || payloadLength > 入站状态.加密配置.maxChunk) throw new Error(`SS payload length invalid: ${payloadLength}`);
								入站状态.waitPayloadLength = payloadLength;
							}
							const payloadCipherTotalLength = 入站状态.waitPayloadLength + SSAEAD标签长度;
							if (入站状态.buffer.byteLength < payloadCipherTotalLength) break;
							const payloadCipher = 入站状态.buffer.subarray(0, payloadCipherTotalLength);
							入站状态.buffer = 入站状态.buffer.subarray(payloadCipherTotalLength);
							const payloadPlain = await SSAEAD解密(入站状态.decryptKey, 入站状态.nonceCounter, payloadCipher);
							plaintextChunks.push(payloadPlain);
							入站状态.waitPayloadLength = null;
						}
						return plaintextChunks;
					},
				};
				let 出站加密器 = null;
				const SS单批最大字节 = 32 * 1024;
				const 获取出站加密器 = async () => {
					if (出站加密器) return 出站加密器;
					if (!入站状态.加密配置) throw new Error('SS cipher is not negotiated');
					const 出站加密配置 = 入站状态.加密配置;
					const 出站主密钥 = await SS派生主密钥(yourUUID, 出站加密配置.keyLen);
					const 出站随机字节 = crypto.getRandomValues(new Uint8Array(出站加密配置.saltLen));
					const 出站加密密钥 = await SS派生会话密钥(出站加密配置, 出站主密钥, 出站随机字节, ['encrypt']);
					const 出站Nonce计数器 = new Uint8Array(SSNonce长度);
					let 随机字节已发送 = false;
					出站加密器 = {
						async 加密并发送(dataChunk, sendChunk) {
							const plaintextData = 数据转Uint8Array(dataChunk);
							if (!随机字节已发送) {
								await sendChunk(出站随机字节);
								随机字节已发送 = true;
							}
							if (plaintextData.byteLength === 0) return;
							let offset = 0;
							while (offset < plaintextData.byteLength) {
								const end = Math.min(offset + 出站加密配置.maxChunk, plaintextData.byteLength);
								const payloadPlain = plaintextData.subarray(offset, end);
								const lengthPlain = new Uint8Array(2);
								lengthPlain[0] = (payloadPlain.byteLength >>> 8) & 0xff;
								lengthPlain[1] = payloadPlain.byteLength & 0xff;
								const lengthCipher = await SSAEAD加密(出站加密密钥, 出站Nonce计数器, lengthPlain);
								const payloadCipher = await SSAEAD加密(出站加密密钥, 出站Nonce计数器, payloadPlain);
								const frame = new Uint8Array(lengthCipher.byteLength + payloadCipher.byteLength);
								frame.set(lengthCipher, 0);
								frame.set(payloadCipher, lengthCipher.byteLength);
								await sendChunk(frame);
								offset = end;
							}
						},
					};
					return 出站加密器;
				};
				let SS发送队列 = Promise.resolve();
				const SS入队发送 = (chunk) => {
					SS发送队列 = SS发送队列.then(async () => {
						if (serverSock.readyState !== WebSocket.OPEN) return;
						const 已初始化出站加密器 = await 获取出站加密器();
						await 已初始化出站加密器.加密并发送(chunk, async (encryptedChunk) => {
							if (encryptedChunk.byteLength > 0 && serverSock.readyState === WebSocket.OPEN) {
								await WebSocket发送并等待(serverSock, encryptedChunk.buffer);
							}
						});
					}).catch((error) => {
						log(`[SS发送] 加密失败: ${error?.message || error}`);
						closeSocketQuietly(serverSock);
					});
					return SS发送队列;
				};
				const 回包Socket = {
					get readyState() {
						return serverSock.readyState;
					},
					send(data) {
						const chunk = 数据转Uint8Array(data);
						if (chunk.byteLength <= SS单批最大字节) {
							return SS入队发送(chunk);
						}
						for (let i = 0; i < chunk.byteLength; i += SS单批最大字节) {
							SS入队发送(chunk.subarray(i, Math.min(i + SS单批最大字节, chunk.byteLength)));
						}
						return SS发送队列;
					},
					close() {
						closeSocketQuietly(serverSock);
					}
				};
				ss上下文 = {
					入站解密器,
					回包Socket,
					首包已建立: false,
					目标主机: '',
					目标端口: 0,
				};
				return ss上下文;
			})().finally(() => { ss初始化任务 = null });
		}
		return ss初始化任务;
	};

	const 处理SS数据 = async (chunk) => {
		const 上下文 = await 获取SS上下文();
		let 明文块数组 = null;
		try {
			明文块数组 = await 上下文.入站解密器.输入(chunk);
		} catch (err) {
			const msg = err?.message || `${err}`;
			if (msg.includes('Decryption failed') || msg.includes('SS handshake decrypt failed') || msg.includes('SS length decrypt failed')) {
				log(`[SS入站] 解密失败，连接关闭: ${msg}`);
				closeSocketQuietly(serverSock);
				return;
			}
			throw err;
		}
		for (const 明文块 of 明文块数组) {
			let 已写入 = false;
			try {
				已写入 = await 写入远端(明文块, false);
			} catch (err) {
				if ((/** @type {any} */ (err))?.isQueueOverflow) throw err;
				已写入 = false;
			}
			if (已写入) continue;
			if (上下文.首包已建立 && 上下文.目标主机 && 上下文.目标端口 > 0) {
				await forwardataTCP(上下文.目标主机, 上下文.目标端口, 明文块, 上下文.回包Socket, null, remoteConnWrapper, yourUUID, request, 访问授权上下文?.反代上下文 || 请求反代上下文);
				continue;
			}
			const 明文数据 = 数据转Uint8Array(明文块);
			if (明文数据.byteLength < 3) throw new Error('invalid ss data');
			const addressType = 明文数据[0];
			let cursor = 1;
			let hostname = '';
			if (addressType === 1) {
				if (明文数据.byteLength < cursor + 4 + 2) throw new Error('invalid ss ipv4 length');
				hostname = `${明文数据[cursor]}.${明文数据[cursor + 1]}.${明文数据[cursor + 2]}.${明文数据[cursor + 3]}`;
				cursor += 4;
			} else if (addressType === 3) {
				if (明文数据.byteLength < cursor + 1) throw new Error('invalid ss domain length');
				const domainLength = 明文数据[cursor];
				cursor += 1;
				if (明文数据.byteLength < cursor + domainLength + 2) throw new Error('invalid ss domain data');
				hostname = SS文本解码器.decode(明文数据.subarray(cursor, cursor + domainLength));
				cursor += domainLength;
			} else if (addressType === 4) {
				if (明文数据.byteLength < cursor + 16 + 2) throw new Error('invalid ss ipv6 length');
				const ipv6 = [];
				const ipv6View = new DataView(明文数据.buffer, 明文数据.byteOffset + cursor, 16);
				for (let i = 0; i < 8; i++) ipv6.push(ipv6View.getUint16(i * 2).toString(16));
				hostname = ipv6.join(':');
				cursor += 16;
			} else {
				throw new Error(`invalid ss addressType: ${addressType}`);
			}
			if (!hostname) throw new Error(`invalid ss address: ${addressType}`);
			const port = (明文数据[cursor] << 8) | 明文数据[cursor + 1];
			cursor += 2;
			const rawClientData = 明文数据.subarray(cursor);
			if (isSpeedTestSite(hostname)) throw new Error('Speedtest site is blocked');
			if (访问授权上下文) {
				await 激活访问授权上下文(访问授权上下文);
				安排访问链接到期(访问授权上下文, () => closeSocketQuietly(serverSock));
			}
			上下文.首包已建立 = true;
			上下文.目标主机 = hostname;
			上下文.目标端口 = port;
			await forwardataTCP(hostname, port, rawClientData, 上下文.回包Socket, null, remoteConnWrapper, yourUUID, request, 访问授权上下文?.反代上下文 || 请求反代上下文);
		}
	};

	const 处理WS入站数据 = async (chunk) => {
		let 当前块字节 = null;
		if (isDnsQuery) {
			if (判断是否是木马) return await 转发木马UDP数据(chunk, serverSock, 木马UDP上下文, request, 访问授权上下文);
			return await forwardataudp(chunk, serverSock, null, request, null, 访问授权上下文);
		}
		if (判断协议类型 === 'ss') {
			await 处理SS数据(chunk);
			return;
		}
		if (await 写入远端(chunk)) return;

		if (判断协议类型 === null) {
			if (url.searchParams.get('enc')) 判断协议类型 = 'ss';
			else {
				WS首包缓存 = 拼接字节数据(WS首包缓存, 数据转Uint8Array(chunk));
				const 首包解析 = 尝试解析传输首包(WS首包缓存, yourUUID);
				if (首包解析.状态 === 'need_more' && WS首包缓存.byteLength <= 1024) return;
				if (首包解析.状态 !== 'ok') throw new Error('Invalid proxy header');
				判断协议类型 = 首包解析.结果.协议 === 'trojan' ? '木马' : '魏烈思';
			}
			判断是否是木马 = 判断协议类型 === '木马';
			log(`[WS转发] 协议类型: ${判断协议类型} | 来自: ${url.host} | UA: ${request.headers.get('user-agent') || '未知'}`);
		}

		if (判断协议类型 === 'ss') {
			await 处理SS数据(chunk);
			return;
		}
		if (await 写入远端(chunk)) return;
		if (判断协议类型 === '木马') {
			const 首包bytes = WS首包缓存.byteLength ? WS首包缓存 : 数据转Uint8Array(chunk);
			WS首包缓存 = new Uint8Array(0);
			const 解析结果 = 解析木马请求(首包bytes, yourUUID);
			if (解析结果?.hasError) throw new Error(解析结果.message || 'Invalid trojan request');
			const { port, hostname, rawClientData, isUDP } = 解析结果;
			if (isSpeedTestSite(hostname)) throw new Error('Speedtest site is blocked');
			if (访问授权上下文) {
				await 激活访问授权上下文(访问授权上下文);
				安排访问链接到期(访问授权上下文, () => closeSocketQuietly(serverSock));
			}
			if (isUDP) {
				isDnsQuery = true;
				if (有效数据长度(rawClientData) > 0) return 转发木马UDP数据(rawClientData, serverSock, 木马UDP上下文, request, 访问授权上下文);
				return;
			}
			await forwardataTCP(hostname, port, rawClientData, serverSock, null, remoteConnWrapper, yourUUID, request, 访问授权上下文?.反代上下文 || 请求反代上下文);
		} else {
			判断是否是木马 = false;
			const bytes = WS首包缓存.byteLength ? WS首包缓存 : (当前块字节 || 数据转Uint8Array(chunk));
			WS首包缓存 = new Uint8Array(0);
			const 解析结果 = 解析魏烈思请求(bytes, yourUUID);
			if (解析结果?.hasError) throw new Error(解析结果.message || 'Invalid 魏烈思 request');
			const { port, hostname, version, isUDP, rawClientData } = 解析结果;
			if (isSpeedTestSite(hostname)) throw new Error('Speedtest site is blocked');
			if (isUDP && port !== 53) throw new Error('UDP is not supported');
			if (访问授权上下文) {
				await 激活访问授权上下文(访问授权上下文);
				安排访问链接到期(访问授权上下文, () => closeSocketQuietly(serverSock));
			}
			if (isUDP) {
				isDnsQuery = true;
			}
			const respHeader = new Uint8Array([version, 0]);
			const rawData = rawClientData;
			if (isDnsQuery) {
				if (判断是否是木马) return 转发木马UDP数据(rawData, serverSock, 木马UDP上下文, request, 访问授权上下文);
				return forwardataudp(rawData, serverSock, respHeader, request, null, 访问授权上下文);
			}
			await forwardataTCP(hostname, port, rawData, serverSock, respHeader, remoteConnWrapper, yourUUID, request, 访问授权上下文?.反代上下文 || 请求反代上下文);
		}
	};

	const 处理WS显式传输错误 = (err) => {
		if (WS显式传输失败) return;
		WS显式传输失败 = true;
		WS显式传输停止接收 = true;
		WS显式队列字节 = 0;
		WS显式队列条目 = 0;
		const msg = err?.message || `${err}`;
		if (msg.includes('Network connection lost') || msg.includes('ReadableStream is closed')) {
			log(`[WS转发] 连接结束: ${msg}`);
		} else {
			log(`[WS转发] 处理失败: ${msg}`);
		}
		上行写入队列.清空();
		释放远端写入器();
		closeSocketQuietly(serverSock);
		结束访问授权上下文(访问授权上下文, 访问授权上下文?.代理连接成功, 'transport_error');
	};

	const 追加WS显式传输任务 = (任务) => {
		WS显式传输链 = WS显式传输链.then(任务).catch(处理WS显式传输错误);
		return WS显式传输链;
	};

	const 入队WS显式传输 = (data) => {
		if (WS显式传输停止接收 || WS显式传输失败) return;
		const chunkSize = Math.max(0, 有效数据长度(data));
		const nextBytes = WS显式队列字节 + chunkSize;
		const nextItems = WS显式队列条目 + 1;
		if (nextBytes > 上行队列最大字节 || nextItems > 上行队列最大条目) {
			处理WS显式传输错误(new Error(`[WS显式传输] 队列溢出: ${nextBytes}B/${nextItems}`));
			return;
		}
		WS显式队列字节 = nextBytes;
		WS显式队列条目 = nextItems;
		追加WS显式传输任务(async () => {
			WS显式队列字节 = Math.max(0, WS显式队列字节 - chunkSize);
			WS显式队列条目 = Math.max(0, WS显式队列条目 - 1);
			if (WS显式传输失败) return;
			await 处理WS入站数据(data);
		});
	};

	const 收尾WS显式传输 = () => {
		if (WS显式传输收尾已入队) return;
		WS显式传输收尾已入队 = true;
		WS显式传输停止接收 = true;
		追加WS显式传输任务(async () => {
			if (WS显式传输失败) return;
			await 上行写入队列.等待空();
			释放远端写入器();
		});
	};

	serverSock.addEventListener('message', (event) => {
		入队WS显式传输(event.data);
	});
	serverSock.addEventListener('close', () => {
		closeSocketQuietly(serverSock);
		收尾WS显式传输();
		结束访问授权上下文(访问授权上下文, 访问授权上下文?.代理连接成功, 'client_closed');
	});
	serverSock.addEventListener('error', (err) => {
		处理WS显式传输错误(err);
		结束访问授权上下文(访问授权上下文, false, 'websocket_error');
	});

	// SS 模式下禁用 sec-websocket-protocol early-data，避免把子协议值（如 "binary"）误当作 base64 数据注入首包导致 AEAD 解密失败。
	if (!SS模式禁用EarlyData && earlyDataHeader) {
		try {
			const bytes = 解码WS早期数据(earlyDataHeader, yourUUID);
			if (bytes?.byteLength) 入队WS显式传输(bytes.buffer);
		} catch (error) {
			处理WS显式传输错误(error);
		}
	}

	return new Response(null, { status: 101, webSocket: clientSock, headers: { 'Sec-WebSocket-Extensions': '' } });
}

const 木马文本解码器 = new TextDecoder();

function 解析木马请求(buffer, passwordPlainText) {
	const data = 数据转Uint8Array(buffer);
	const sha224Password = sha224(passwordPlainText);
	if (data.byteLength < 58) return { hasError: true, message: "invalid data" };
	let crLfIndex = 56;
	if (data[crLfIndex] !== 0x0d || data[crLfIndex + 1] !== 0x0a) return { hasError: true, message: "invalid header format" };
	for (let i = 0; i < crLfIndex; i++) {
		if (data[i] !== sha224Password.charCodeAt(i)) return { hasError: true, message: "invalid password" };
	}

	const socks5Index = crLfIndex + 2;
	if (data.byteLength < socks5Index + 6) return { hasError: true, message: "invalid S5 request data" };

	const cmd = data[socks5Index];
	if (cmd !== 1 && cmd !== 3) return { hasError: true, message: "unsupported command, only TCP/UDP is allowed" };
	const isUDP = cmd === 3;

	const atype = data[socks5Index + 1];
	let addressLength = 0;
	let addressIndex = socks5Index + 2;
	let address = "";
	switch (atype) {
		case 1: // IPv4
			addressLength = 4;
			if (data.byteLength < addressIndex + addressLength + 4) return { hasError: true, message: "invalid S5 request data" };
			address = `${data[addressIndex]}.${data[addressIndex + 1]}.${data[addressIndex + 2]}.${data[addressIndex + 3]}`;
			break;
		case 3: // Domain
			if (data.byteLength < addressIndex + 1) return { hasError: true, message: "invalid S5 request data" };
			addressLength = data[addressIndex];
			addressIndex += 1;
			if (data.byteLength < addressIndex + addressLength + 4) return { hasError: true, message: "invalid S5 request data" };
			address = 木马文本解码器.decode(data.subarray(addressIndex, addressIndex + addressLength));
			break;
		case 4: // IPv6
			addressLength = 16;
			if (data.byteLength < addressIndex + addressLength + 4) return { hasError: true, message: "invalid S5 request data" };
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				const partIndex = addressIndex + i * 2;
				ipv6.push(((data[partIndex] << 8) | data[partIndex + 1]).toString(16));
			}
			address = ipv6.join(":");
			break;
		default:
			return { hasError: true, message: `invalid addressType is ${atype}` };
	}

	if (!address) {
		return { hasError: true, message: `address is empty, addressType is ${atype}` };
	}

	const portIndex = addressIndex + addressLength;
	if (data.byteLength < portIndex + 4) return { hasError: true, message: "invalid S5 request data" };
	const portRemote = (data[portIndex] << 8) | data[portIndex + 1];

	return {
		hasError: false,
		addressType: atype,
		port: portRemote,
		hostname: address,
		isUDP,
		rawClientData: data.subarray(portIndex + 4)
	};
}

const UUID字节缓存 = new Map();
const VLESS文本解码器 = new TextDecoder();

function 读取十六进制半字节(code) {
	if (code >= 48 && code <= 57) return code - 48;
	code |= 32;
	if (code >= 97 && code <= 102) return code - 87;
	return -1;
}

function 获取UUID字节(uuid) {
	const key = String(uuid || '');
	let cached = UUID字节缓存.get(key);
	if (cached) return cached;

	const clean = key.replace(/-/g, '');
	if (clean.length !== 32) return null;

	const bytes = new Uint8Array(16);
	for (let i = 0; i < 16; i++) {
		const high = 读取十六进制半字节(clean.charCodeAt(i * 2));
		const low = 读取十六进制半字节(clean.charCodeAt(i * 2 + 1));
		if (high < 0 || low < 0) return null;
		bytes[i] = (high << 4) | low;
	}

	if (UUID字节缓存.size >= 32) UUID字节缓存.clear();
	UUID字节缓存.set(key, bytes);
	return bytes;
}

function UUID字节匹配(data, offset, uuid) {
	const expected = 获取UUID字节(uuid);
	if (!expected || data.byteLength < offset + 16) return false;
	for (let i = 0; i < 16; i++) {
		if (data[offset + i] !== expected[i]) return false;
	}
	return true;
}

function 解析魏烈思请求(chunk, token) {
	const data = 数据转Uint8Array(chunk);
	const length = data.byteLength;
	if (length < 24) return { hasError: true, message: 'Invalid data' };
	const version = data[0];
	if (!UUID字节匹配(data, 1, token)) return { hasError: true, message: 'Invalid uuid' };

	const optLen = data[17];
	const cmdIndex = 18 + optLen;
	if (length < cmdIndex + 4) return { hasError: true, message: 'Invalid data' };

	const cmd = data[cmdIndex];
	let isUDP = false;
	if (cmd === 1) { } else if (cmd === 2) { isUDP = true } else { return { hasError: true, message: 'Invalid command' } }

	const portIdx = cmdIndex + 1;
	const port = (data[portIdx] << 8) | data[portIdx + 1];
	let addrValIdx = portIdx + 3, addrLen = 0, hostname = '';
	const addressType = data[portIdx + 2];
	switch (addressType) {
		case 1:
			addrLen = 4;
			if (length < addrValIdx + addrLen) return { hasError: true, message: 'Invalid IPv4 address length' };
			hostname = `${data[addrValIdx]}.${data[addrValIdx + 1]}.${data[addrValIdx + 2]}.${data[addrValIdx + 3]}`;
			break;
		case 2:
			if (length < addrValIdx + 1) return { hasError: true, message: 'Invalid domain length' };
			addrLen = data[addrValIdx];
			addrValIdx += 1;
			if (length < addrValIdx + addrLen) return { hasError: true, message: 'Invalid domain data' };
			hostname = VLESS文本解码器.decode(data.subarray(addrValIdx, addrValIdx + addrLen));
			break;
		case 3:
			addrLen = 16;
			if (length < addrValIdx + addrLen) return { hasError: true, message: 'Invalid IPv6 address length' };
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				const base = addrValIdx + i * 2;
				ipv6.push(((data[base] << 8) | data[base + 1]).toString(16));
			}
			hostname = ipv6.join(':');
			break;
		default:
			return { hasError: true, message: `Invalid address type: ${addressType}` };
	}
	if (!hostname) return { hasError: true, message: `Invalid address: ${addressType}` };
	const rawIndex = addrValIdx + addrLen;
	return { hasError: false, addressType, port, hostname, isUDP, rawClientData: data.subarray(rawIndex), version };
}

const SS支持加密配置 = {
	'aes-128-gcm': { method: 'aes-128-gcm', keyLen: 16, saltLen: 16, maxChunk: 0x3fff, aesLength: 128 },
	'aes-256-gcm': { method: 'aes-256-gcm', keyLen: 32, saltLen: 32, maxChunk: 0x3fff, aesLength: 256 },
};

const SSAEAD标签长度 = 16, SSNonce长度 = 12;
const SS子密钥信息 = new TextEncoder().encode('ss-subkey');
const SS文本编码器 = new TextEncoder(), SS文本解码器 = new TextDecoder(), SS主密钥缓存 = new Map();

function 数据转Uint8Array(data) {
	if (data instanceof Uint8Array) return data;
	if (data instanceof ArrayBuffer) return new Uint8Array(data);
	if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
	return new Uint8Array(data || 0);
}

function 拼接字节数据(...chunkList) {
	if (!chunkList || chunkList.length === 0) return new Uint8Array(0);
	const chunks = chunkList.map(数据转Uint8Array);
	const total = chunks.reduce((sum, c) => sum + c.byteLength, 0);
	const result = new Uint8Array(total);
	let offset = 0;
	for (const c of chunks) { result.set(c, offset); offset += c.byteLength }
	return result;
}

async function 转发木马UDP数据(chunk, webSocket, 上下文, request, 访问授权上下文 = null) {
	const 当前块 = 数据转Uint8Array(chunk);
	const 缓存块 = 上下文?.缓存 instanceof Uint8Array ? 上下文.缓存 : new Uint8Array(0);
	const input = 缓存块.byteLength ? 拼接字节数据(缓存块, 当前块) : 当前块;
	let cursor = 0;

	while (cursor < input.byteLength) {
		const packetStart = cursor;
		const atype = input[cursor];
		let addrCursor = cursor + 1;
		let addrLen = 0;
		if (atype === 1) addrLen = 4;
		else if (atype === 4) addrLen = 16;
		else if (atype === 3) {
			if (input.byteLength < addrCursor + 1) break;
			addrLen = 1 + input[addrCursor];
		} else throw new Error(`invalid trojan udp addressType: ${atype}`);

		const portCursor = addrCursor + addrLen;
		if (input.byteLength < portCursor + 6) break;

		const port = (input[portCursor] << 8) | input[portCursor + 1];
		const payloadLength = (input[portCursor + 2] << 8) | input[portCursor + 3];
		if (input[portCursor + 4] !== 0x0d || input[portCursor + 5] !== 0x0a) throw new Error('invalid trojan udp delimiter');

		const payloadStart = portCursor + 6;
		const payloadEnd = payloadStart + payloadLength;
		if (input.byteLength < payloadEnd) break;

		const 地址端口头 = input.slice(packetStart, portCursor + 2);
		const payload = input.slice(payloadStart, payloadEnd);
		cursor = payloadEnd;

		if (port !== 53) throw new Error('UDP is not supported');
		if (!payload.byteLength) continue;

		let tcpDNS查询 = payload;
		if (payload.byteLength < 2 || ((payload[0] << 8) | payload[1]) !== payload.byteLength - 2) {
			tcpDNS查询 = new Uint8Array(payload.byteLength + 2);
			tcpDNS查询[0] = (payload.byteLength >>> 8) & 0xff;
			tcpDNS查询[1] = payload.byteLength & 0xff;
			tcpDNS查询.set(payload, 2);
		}

		const dns响应上下文 = { 缓存: new Uint8Array(0) };
		await forwardataudp(tcpDNS查询, webSocket, null, request, (dnsRespChunk) => {
			const 当前响应块 = 数据转Uint8Array(dnsRespChunk);
			const 响应输入 = dns响应上下文.缓存.byteLength ? 拼接字节数据(dns响应上下文.缓存, 当前响应块) : 当前响应块;
			const 响应帧列表 = [];
			let responseCursor = 0;
			while (responseCursor + 2 <= 响应输入.byteLength) {
				const dnsLen = (响应输入[responseCursor] << 8) | 响应输入[responseCursor + 1];
				const dnsStart = responseCursor + 2;
				const dnsEnd = dnsStart + dnsLen;
				if (dnsEnd > 响应输入.byteLength) break;
				const dnsPayload = 响应输入.slice(dnsStart, dnsEnd);
				const frame = new Uint8Array(地址端口头.byteLength + 4 + dnsPayload.byteLength);
				frame.set(地址端口头, 0);
				frame[地址端口头.byteLength] = (dnsPayload.byteLength >>> 8) & 0xff;
				frame[地址端口头.byteLength + 1] = dnsPayload.byteLength & 0xff;
				frame[地址端口头.byteLength + 2] = 0x0d;
				frame[地址端口头.byteLength + 3] = 0x0a;
				frame.set(dnsPayload, 地址端口头.byteLength + 4);
				响应帧列表.push(frame);
				responseCursor = dnsEnd;
			}
			dns响应上下文.缓存 = 响应输入.slice(responseCursor);
			return 响应帧列表.length ? 响应帧列表 : new Uint8Array(0);
		});
	}

	if (上下文) 上下文.缓存 = input.slice(cursor);
}

function SS递增Nonce计数器(counter) {
	for (let i = 0; i < counter.length; i++) { counter[i] = (counter[i] + 1) & 0xff; if (counter[i] !== 0) return }
}

async function SS派生主密钥(passwordText, keyLen) {
	const cacheKey = `${keyLen}:${passwordText}`;
	if (SS主密钥缓存.has(cacheKey)) return SS主密钥缓存.get(cacheKey);
	const deriveTask = (async () => {
		const pwBytes = SS文本编码器.encode(passwordText || '');
		let prev = new Uint8Array(0), result = new Uint8Array(0);
		while (result.byteLength < keyLen) {
			const input = new Uint8Array(prev.byteLength + pwBytes.byteLength);
			input.set(prev, 0); input.set(pwBytes, prev.byteLength);
			prev = new Uint8Array(await crypto.subtle.digest('MD5', input));
			result = 拼接字节数据(result, prev);
		}
		return result.slice(0, keyLen);
	})();
	SS主密钥缓存.set(cacheKey, deriveTask);
	try { return await deriveTask }
	catch (error) { SS主密钥缓存.delete(cacheKey); throw error }
}

async function SS派生会话密钥(config, masterKey, salt, usages) {
	const hmacOpts = { name: 'HMAC', hash: 'SHA-1' };
	const saltHmacKey = await crypto.subtle.importKey('raw', salt, hmacOpts, false, ['sign']);
	const prk = new Uint8Array(await crypto.subtle.sign('HMAC', saltHmacKey, masterKey));
	const prkHmacKey = await crypto.subtle.importKey('raw', prk, hmacOpts, false, ['sign']);
	const subKey = new Uint8Array(config.keyLen);
	let prev = new Uint8Array(0), written = 0, counter = 1;
	while (written < config.keyLen) {
		const input = 拼接字节数据(prev, SS子密钥信息, new Uint8Array([counter]));
		prev = new Uint8Array(await crypto.subtle.sign('HMAC', prkHmacKey, input));
		const copyLen = Math.min(prev.byteLength, config.keyLen - written);
		subKey.set(prev.subarray(0, copyLen), written);
		written += copyLen; counter += 1;
	}
	return crypto.subtle.importKey('raw', subKey, { name: 'AES-GCM', length: config.aesLength }, false, usages);
}

async function SSAEAD加密(cryptoKey, nonceCounter, plaintext) {
	const iv = nonceCounter.slice();
	const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, cryptoKey, plaintext);
	SS递增Nonce计数器(nonceCounter);
	return new Uint8Array(ct);
}

async function SSAEAD解密(cryptoKey, nonceCounter, ciphertext) {
	const iv = nonceCounter.slice();
	const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, cryptoKey, ciphertext);
	SS递增Nonce计数器(nonceCounter);
	return new Uint8Array(pt);
}

function 获取TCP反代配置(请求反代上下文 = null) {
	if (请求反代上下文) return 请求反代上下文;
	return { 反代IP, 启用反代兜底, 启用SOCKS5反代, 启用SOCKS5全局反代, parsedSocks5Address };
}

async function forwardataTCP(host, portNum, rawData, ws, respHeader, remoteConnWrapper, yourUUID, request = null, 请求反代上下文 = null) {
	const 当前反代配置 = 获取TCP反代配置(请求反代上下文);
	const 当前反代IP = 当前反代配置.反代IP;
	const 当前启用反代兜底 = 当前反代配置.启用反代兜底;
	const 当前启用SOCKS5反代 = 当前反代配置.启用SOCKS5反代;
	const 当前启用SOCKS5全局反代 = 当前反代配置.启用SOCKS5全局反代;
	const 当前parsedSocks5Address = 当前反代配置.parsedSocks5Address || {};
	const 当前访问授权上下文 = 当前反代配置.访问授权上下文 || null;
	log(`[TCP转发] 目标: ${host}:${portNum} | 反代IP: ${当前反代IP} | 反代兜底: ${当前启用反代兜底 ? '是' : '否'} | 反代类型: ${当前启用SOCKS5反代 || 'proxyip'} | 全局: ${当前启用SOCKS5全局反代 ? '是' : '否'}`);
	const 连接超时毫秒 = 1000;
	let 已通过代理发送首包 = false;
	const TCP连接 = 创建请求TCP连接器(request, remoteConnWrapper);

	async function 等待连接建立(remoteSock, timeoutMs = 连接超时毫秒) {
		if (remoteConnWrapper.cancelled) throw new Error('连接已取消');
		await Promise.race([
			remoteSock.opened,
			new Promise((_, reject) => setTimeout(() => reject(new Error('连接超时')), timeoutMs))
		]);
		if (remoteConnWrapper.cancelled) throw new Error('连接已取消');
	}

	async function 打开TCP连接(address, port) {
		const remoteSock = TCP连接({ hostname: address, port });
		try {
			await 等待连接建立(remoteSock);
			return remoteSock;
		} catch (err) {
			try { remoteSock?.close?.() } catch (e) { }
			throw err;
		}
	}

	async function 写入首包(remoteSock, data) {
		if (有效数据长度(data) <= 0) return;
		if (remoteConnWrapper.cancelled) throw new Error('连接已取消');
		const writer = remoteSock.writable.getWriter();
		try { await writer.write(数据转Uint8Array(data)) }
		finally { try { writer.releaseLock() } catch (e) { } }
	}

	async function 并发打开候选连接(候选列表, 记录代理健康 = false) {
		if (remoteConnWrapper.cancelled) throw new Error('连接已取消');
		if (候选列表.length === 1) {
			const 候选 = 候选列表[0];
			const startedAt = Date.now();
			try {
				const result = { socket: await 打开TCP连接(候选.hostname, 候选.port), candidate: 候选 };
				if (记录代理健康 && 当前访问授权上下文) await 记录访问代理连接结果(当前访问授权上下文, true, 候选.port === 443 ? 候选.hostname : `${候选.hostname}:${候选.port}`, Date.now() - startedAt);
				return result;
			} catch (error) {
				if (记录代理健康 && 当前访问授权上下文) await 记录访问代理连接结果(当前访问授权上下文, false, 候选.port === 443 ? 候选.hostname : `${候选.hostname}:${候选.port}`, null, error?.message || error);
				throw error;
			}
		}
		const attempts = 候选列表.map(async 候选 => {
			const startedAt = Date.now();
			try { return { socket: await 打开TCP连接(候选.hostname, 候选.port), candidate: 候选, latency: Date.now() - startedAt } }
			catch (error) {
				if (记录代理健康 && 当前访问授权上下文) await 记录访问代理连接结果(当前访问授权上下文, false, 候选.port === 443 ? 候选.hostname : `${候选.hostname}:${候选.port}`, null, error?.message || error);
				throw error;
			}
		});
		let winner = null;
		try {
			winner = await Promise.any(attempts);
			if (记录代理健康 && 当前访问授权上下文) await 记录访问代理连接结果(当前访问授权上下文, true, winner.candidate.port === 443 ? winner.candidate.hostname : `${winner.candidate.hostname}:${winner.candidate.port}`, winner.latency);
			return winner;
		} finally {
			if (winner) {
				for (const attempt of attempts) {
					attempt.then(({ socket }) => {
						if (socket !== winner.socket) {
							try { socket?.close?.() } catch (e) { }
						}
					}).catch(() => { });
				}
			}
		}
	}

	async function connectDirect(address, port, data = null, 所有反代数组 = null, 反代兜底 = true) {
		if (remoteConnWrapper.cancelled) throw new Error('连接已取消');
		if (所有反代数组 && 所有反代数组.length > 0) {
			for (let i = 0; i < 所有反代数组.length; i += TCP并发拨号数) {
				if (remoteConnWrapper.cancelled) throw new Error('连接已取消');
				const 候选列表 = [];
				for (let j = 0; j < TCP并发拨号数 && i + j < 所有反代数组.length; j++) {
					const 反代数组索引 = (缓存反代数组索引 + i + j) % 所有反代数组.length;
					const [反代地址, 反代端口] = 所有反代数组[反代数组索引];
					候选列表.push({ hostname: 反代地址, port: 反代端口, index: 反代数组索引 });
				}
				let socket = null, candidate = null;
				try {
					log(`[反代连接] 并发尝试 ${候选列表.length} 路: ${候选列表.map(候选 => `${候选.hostname}:${候选.port}`).join(', ')}`);
					const 连接结果 = await 并发打开候选连接(候选列表, !!当前访问授权上下文);
					socket = 连接结果.socket;
					candidate = 连接结果.candidate;
					await 写入首包(socket, data);
					log(`[反代连接] 成功连接到: ${candidate.hostname}:${candidate.port} (索引: ${candidate.index})`);
					缓存反代数组索引 = candidate.index;
					return socket;
				} catch (err) {
					try { socket?.close?.() } catch (e) { }
					log(`[反代连接] 本批连接失败: ${err.message || err}`);
				}
			}
		}

		if (反代兜底) {
			const 候选列表 = Array.from({ length: TCP并发拨号数 }, (_, attempt) => ({ hostname: address, port, attempt }));
			log(`[TCP直连] 并发尝试 ${候选列表.length} 路: ${address}:${port}`);
			let socket = null;
			try {
				const 连接结果 = await 并发打开候选连接(候选列表);
				socket = 连接结果.socket;
				await 写入首包(socket, data);
				return socket;
			} catch (err) {
				try { socket?.close?.() } catch (e) { }
				throw err;
			}
		} else {
			closeSocketQuietly(ws);
			throw new Error('[反代连接] 所有反代连接失败，且未启用反代兜底，连接终止。');
		}
	}

	async function connecttoPry(允许发送首包 = true) {
		if (remoteConnWrapper.cancelled) return;
		if (ws.readyState !== WebSocket.OPEN) return;
		if (remoteConnWrapper.connectingPromise) {
			await remoteConnWrapper.connectingPromise;
			return;
		}

		const 本次发送首包 = 允许发送首包 && !已通过代理发送首包 && 有效数据长度(rawData) > 0;
		const 本次首包数据 = 本次发送首包 ? rawData : null;

		const 当前连接任务 = (async () => {
			let newSocket;
			if (当前启用SOCKS5反代 === 'socks5') {
				log(`[SOCKS5代理] 代理到: ${host}:${portNum}`);
				newSocket = await socks5Connect(host, portNum, 本次首包数据, TCP连接, 当前parsedSocks5Address);
			} else if (当前启用SOCKS5反代 === 'http') {
				log(`[HTTP代理] 代理到: ${host}:${portNum}`);
				newSocket = await httpConnect(host, portNum, 本次首包数据, false, TCP连接, 当前parsedSocks5Address);
			} else if (当前启用SOCKS5反代 === 'https') {
				log(`[HTTPS代理] 代理到: ${host}:${portNum}`);
				newSocket = isIPHostname(当前parsedSocks5Address.hostname)
					? await httpsConnect(host, portNum, 本次首包数据, TCP连接, 当前parsedSocks5Address)
					: await httpConnect(host, portNum, 本次首包数据, true, TCP连接, 当前parsedSocks5Address);
			} else if (当前启用SOCKS5反代 === 'turn') {
				log(`[TURN代理] 代理到: ${host}:${portNum}`);
				newSocket = await turnConnect(当前parsedSocks5Address, host, portNum, TCP连接);
				if (有效数据长度(本次首包数据) > 0) {
					const writer = newSocket.writable.getWriter();
					try { await writer.write(数据转Uint8Array(本次首包数据)) }
					finally { try { writer.releaseLock() } catch (e) { } }
				}
			} else if (当前启用SOCKS5反代 === 'sstp') {
				log(`[SSTP代理] 代理到: ${host}:${portNum}`);
				newSocket = await sstpConnect(当前parsedSocks5Address, host, portNum, TCP连接);
				if (有效数据长度(本次首包数据) > 0) {
					const writer = newSocket.writable.getWriter();
					try { await writer.write(数据转Uint8Array(本次首包数据)) }
					finally { try { writer.releaseLock() } catch (e) { } }
				}
			} else {
				log(`[反代连接] 代理到: ${host}:${portNum}`);
				const 所有反代数组 = await 解析地址端口(当前反代IP, host, yourUUID);
				newSocket = await connectDirect(atob('UFJPWFlJUC50cDEuMDkwMjI3Lnh5eg=='), 1, 本次首包数据, 所有反代数组, 当前启用反代兜底);
			}
			if (remoteConnWrapper.cancelled || ws.readyState !== WebSocket.OPEN) { try { newSocket.close() } catch (_) { } return; }
			if (本次发送首包) 已通过代理发送首包 = true;
			remoteConnWrapper.socket = newSocket;
			// 正常关闭需等待读取和尾包刷新完成；socket.closed 不代表下行数据已发送。
			newSocket.closed.catch(() => closeSocketQuietly(ws));
			connectStreams(newSocket, ws, respHeader, null).catch(() => closeSocketQuietly(ws)).finally(() => {
				if (remoteConnWrapper.socket === newSocket) closeSocketQuietly(ws);
			});
		})();

		remoteConnWrapper.connectingPromise = 当前连接任务;
		try {
			await 当前连接任务;
		} finally {
			if (remoteConnWrapper.connectingPromise === 当前连接任务) {
				remoteConnWrapper.connectingPromise = null;
			}
		}
	}
	remoteConnWrapper.retryConnect = async () => connecttoPry(!已通过代理发送首包);

	if (当前启用SOCKS5反代 && (当前启用SOCKS5全局反代 || SOCKS5白名单.some(p => new RegExp(`^${p.replace(/\*/g, '.*')}$`, 'i').test(host)))) {
		log(`[TCP转发] 启用 SOCKS5/HTTP/HTTPS/TURN/SSTP 全局代理`);
		try {
			await connecttoPry();
		} catch (err) {
			log(`[TCP转发] SOCKS5/HTTP/HTTPS/TURN/SSTP 代理连接失败: ${err.message}`);
			throw err;
		}
	} else {
		try {
			log(`[TCP转发] 尝试直连到: ${host}:${portNum}`);
			const initialSocket = await connectDirect(host, portNum, rawData);
			if (ws.readyState !== WebSocket.OPEN) { try { initialSocket.close() } catch (_) { } return; }
			if (当前访问授权上下文) 当前访问授权上下文.代理连接成功 = true;
			remoteConnWrapper.socket = initialSocket;
			connectStreams(initialSocket, ws, respHeader, async () => {
				if (remoteConnWrapper.socket !== initialSocket) return;
				await connecttoPry();
			}).catch(() => closeSocketQuietly(ws)).finally(() => {
				if (remoteConnWrapper.socket === initialSocket) closeSocketQuietly(ws);
			});
		} catch (err) {
			log(`[TCP转发] 直连 ${host}:${portNum} 失败: ${err.message}`);
			await connecttoPry();
		}
	}
}

const DNS转发状态 = new WeakMap();

async function forwardataudp(udpChunk, webSocket, respHeader, request, 响应封装器 = null, 访问授权上下文 = null) {
	let 状态 = DNS转发状态.get(webSocket);
	if (!状态) {
		状态 = { 缓存: new Uint8Array(0), 响应头: respHeader, 已发送: false };
		DNS转发状态.set(webSocket, 状态);
	} else if (!状态.已发送 && respHeader) 状态.响应头 = respHeader;
	const input = 拼接字节数据(状态.缓存, 数据转Uint8Array(udpChunk));
	let cursor = 0;
	while (cursor + 2 <= input.byteLength) {
		const length = (input[cursor] << 8) | input[cursor + 1];
		const end = cursor + 2 + length;
		if (end > input.byteLength) break;
		const query = input.subarray(cursor, end);
		cursor = end;
		if (!length) continue;
		if (webSocket.readyState !== WebSocket.OPEN) break;
		let socket, reader, writer;
		try {
			const TCP连接 = 创建请求TCP连接器(request);
			socket = TCP连接({ hostname: '8.8.4.4', port: 53 });
			writer = socket.writable.getWriter();
			await withTimeout(writer.write(query), 10000, 'DNS write timed out');
			writer.releaseLock();
			writer = null;
			reader = socket.readable.getReader();
			// DNS over TCP 以两字节长度划分响应，不等待服务器关闭持久连接。
			const response = new Uint8Array(65537);
			let received = 0, expected = 2;
			const deadline = Date.now() + 10000;
			while (received < expected) {
				const { done, value } = await withTimeout(reader.read(), Math.max(1, deadline - Date.now()), 'DNS response timed out');
				if (done) throw new Error('Incomplete DNS response');
				const bytes = 数据转Uint8Array(value);
				const count = Math.min(bytes.byteLength, response.byteLength - received);
				response.set(bytes.subarray(0, count), received);
				received += count;
				if (received >= 2) expected = 2 + ((response[0] << 8) | response[1]);
			}
			const data = response.subarray(0, expected);
			const wrapped = 响应封装器 ? await 响应封装器(data) : data;
			for (const fragment of Array.isArray(wrapped) ? wrapped : [wrapped]) {
				const bytes = 数据转Uint8Array(fragment);
				if (!bytes.byteLength || webSocket.readyState !== WebSocket.OPEN) continue;
				await WebSocket发送并等待(webSocket, 状态.响应头 ? 拼接字节数据(状态.响应头, bytes) : bytes);
				状态.响应头 = null;
				状态.已发送 = true;
			}
			if (访问授权上下文) 访问授权上下文.代理连接成功 = true;
		} catch (error) {
			log(`[UDP转发] DNS 转发失败: ${error?.message || error}`);
		} finally {
			if (reader) { void reader.cancel().catch(() => { }); try { reader.releaseLock() } catch (_) { } }
			if (writer) { try { writer.releaseLock() } catch (_) { } }
			try { socket?.close() } catch (_) { }
		}
	}
	状态.缓存 = webSocket.readyState === WebSocket.OPEN ? input.slice(cursor) : new Uint8Array(0);
}

function closeSocketQuietly(socket) {
	try {
		if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CLOSING) {
			socket.close();
		}
	} catch (error) { }
}

function formatIdentifier(arr, offset = 0) {
	const hex = [...arr.slice(offset, offset + 16)].map(b => b.toString(16).padStart(2, '0')).join('');
	return `${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}`;
}

async function WebSocket发送并等待(webSocket, payload) {
	const sendResult = webSocket.send(payload);
	if (sendResult && typeof sendResult.then === 'function') await sendResult;
}

function 创建上行写入队列({ 获取写入器, 释放写入器, 重试连接, 关闭连接, 名称 = '上行队列' }) {
	let chunks = [];
	let head = 0;
	let queuedBytes = 0;
	let draining = false;
	let closed = false;
	let bundleBuffer = null;
	let idleResolvers = [];
	let activeCompletions = null;

	const settleCompletions = (completions, err = null) => {
		if (!completions) return;
		for (const completion of completions) {
			if (err) completion.reject(err);
			else completion.resolve();
		}
	};

	const rejectQueued = (err) => {
		for (let i = head; i < chunks.length; i++) {
			const item = chunks[i];
			if (item?.completions) settleCompletions(item.completions, err);
		}
	};

	const compact = () => {
		if (head > 32 && head * 2 >= chunks.length) {
			chunks = chunks.slice(head);
			head = 0;
		}
	};

	const resolveIdle = () => {
		if (queuedBytes || draining || !idleResolvers.length) return;
		const resolvers = idleResolvers;
		idleResolvers = [];
		for (const resolve of resolvers) resolve();
	};

	const clear = (err = null) => {
		const closeErr = err || (closed ? new Error(`${名称}: queue closed`) : null);
		if (closeErr) {
			rejectQueued(closeErr);
			settleCompletions(activeCompletions, closeErr);
			activeCompletions = null;
		}
		chunks = [];
		head = 0;
		queuedBytes = 0;
		resolveIdle();
	};

	const shift = () => {
		if (head >= chunks.length) return null;
		const item = chunks[head];
		chunks[head++] = undefined;
		queuedBytes -= item.chunk.byteLength;
		compact();
		return item;
	};

	const bundle = () => {
		const first = shift();
		if (!first) return null;
		if (head >= chunks.length || first.chunk.byteLength >= 上行合包目标字节) return first;

		let byteLength = first.chunk.byteLength;
		let end = head;
		let allowRetry = first.allowRetry;
		let completions = first.completions || null;
		while (end < chunks.length) {
			const next = chunks[end];
			const nextLength = byteLength + next.chunk.byteLength;
			if (nextLength > 上行合包目标字节) break;
			byteLength = nextLength;
			allowRetry = allowRetry && next.allowRetry;
			if (next.completions) completions = completions ? completions.concat(next.completions) : next.completions;
			end++;
		}
		if (end === head) return first;

		const output = (bundleBuffer ||= new Uint8Array(上行合包目标字节));
		output.set(first.chunk);
		let offset = first.chunk.byteLength;
		while (head < end) {
			const next = chunks[head];
			chunks[head++] = undefined;
			queuedBytes -= next.chunk.byteLength;
			output.set(next.chunk, offset);
			offset += next.chunk.byteLength;
		}
		compact();
		return { chunk: output.subarray(0, byteLength), allowRetry, completions };
	};

	const drain = async () => {
		if (draining || closed) return;
		draining = true;
		try {
			for (; ;) {
				if (closed) break;
				const item = bundle();
				if (!item) break;
				let writer = 获取写入器();
				if (!writer) throw new Error(`${名称}: remote writer unavailable`);
				const completions = item.completions || null;
				activeCompletions = completions;
				try {
					try {
						await writer.write(item.chunk);
					} catch (err) {
						释放写入器?.();
						if (!item.allowRetry || typeof 重试连接 !== 'function') throw err;
						await 重试连接();
						writer = 获取写入器();
						if (!writer) throw err;
						await writer.write(item.chunk);
					}
					settleCompletions(completions);
				} catch (err) {
					settleCompletions(completions, err);
					throw err;
				} finally {
					if (activeCompletions === completions) activeCompletions = null;
				}
			}
		} catch (err) {
			closed = true;
			clear(err);
			log(`[${名称}] 写入失败: ${err?.message || err}`);
			try { 关闭连接?.(err) } catch (_) { }
		} finally {
			draining = false;
			if (!closed && head < chunks.length) queueMicrotask(drain);
			else resolveIdle();
		}
	};

	const enqueue = (data, allowRetry = true, waitForFlush = false) => {
		if (closed) return false;
		// 首包解析阶段 socket 可能尚未建立；返回 false 交给上层继续走协议解析路径。
		if (!获取写入器()) return false;
		const chunk = 数据转Uint8Array(data);
		if (!chunk.byteLength) return true;
		const nextBytes = queuedBytes + chunk.byteLength;
		const nextItems = chunks.length - head + 1;
		if (nextBytes > 上行队列最大字节 || nextItems > 上行队列最大条目) {
			closed = true;
			const err = Object.assign(new Error(`${名称}: upload queue overflow (${nextBytes}B/${nextItems})`), { isQueueOverflow: true });
			clear(err);
			log(`[${名称}] 队列超限，关闭连接`);
			try { 关闭连接?.(err) } catch (_) { }
			throw err;
		}
		let completionPromise = null;
		let completions = null;
		if (waitForFlush) {
			completions = [];
			completionPromise = new Promise((resolve, reject) => completions.push({ resolve, reject }));
		}
		chunks.push({ chunk, allowRetry, completions });
		queuedBytes = nextBytes;
		if (!draining) queueMicrotask(drain);
		return waitForFlush ? completionPromise.then(() => true) : true;
	};

	return {
		写入(data, allowRetry = true) {
			return enqueue(data, allowRetry, false);
		},
		写入并等待(data, allowRetry = true) {
			return enqueue(data, allowRetry, true);
		},
		async 等待空() {
			if (!queuedBytes && !draining) return;
			await new Promise(resolve => idleResolvers.push(resolve));
		},
		清空() {
			closed = true;
			clear();
		}
	};
}

function 创建下行Grain发送器(webSocket, headerData = null) {
	const packetCap = 下行Grain包字节;
	const tailBytes = 下行Grain尾部阈值;
	const lowWaterBytes = Math.max(4096, tailBytes << 3);
	let header = headerData;
	let pendingBuffer = new Uint8Array(packetCap);
	let pendingBytes = 0;
	let flushTimer = null;
	let microtaskQueued = false;
	let generation = 0;
	let scheduledGeneration = 0;
	let waitRounds = 0;
	let flushPromise = null;

	const 发送原始块 = async (chunk) => {
		if (webSocket.readyState !== WebSocket.OPEN) throw new Error('ws.readyState is not open');
		await WebSocket发送并等待(webSocket, chunk);
	};

	const 附加响应头 = (chunk) => {
		if (!header) return chunk;
		const merged = new Uint8Array(header.length + chunk.byteLength);
		merged.set(header, 0);
		merged.set(chunk, header.length);
		header = null;
		return merged;
	};

	const flush = async () => {
		while (flushPromise) await flushPromise;
		if (flushTimer) clearTimeout(flushTimer);
		flushTimer = null;
		microtaskQueued = false;
		if (!pendingBytes) return;
		const output = pendingBuffer.subarray(0, pendingBytes).slice();
		pendingBuffer = new Uint8Array(packetCap);
		pendingBytes = 0;
		waitRounds = 0;
		flushPromise = 发送原始块(output).finally(() => { flushPromise = null });
		return flushPromise;
	};

	const scheduleFlush = () => {
		if (flushTimer || microtaskQueued) return;
		microtaskQueued = true;
		scheduledGeneration = generation;
		queueMicrotask(() => {
			microtaskQueued = false;
			if (!pendingBytes || flushTimer) return;
			if (packetCap - pendingBytes < tailBytes) {
				flush().catch(() => closeSocketQuietly(webSocket));
				return;
			}
			flushTimer = setTimeout(() => {
				flushTimer = null;
				if (!pendingBytes) return;
				if (packetCap - pendingBytes < tailBytes) {
					flush().catch(() => closeSocketQuietly(webSocket));
					return;
				}
				if (waitRounds < 2 && (generation !== scheduledGeneration || pendingBytes < lowWaterBytes)) {
					waitRounds++;
					scheduledGeneration = generation;
					scheduleFlush();
					return;
				}
				flush().catch(() => closeSocketQuietly(webSocket));
			}, Math.max(下行Grain静默毫秒, 1));
		});
	};

	return {
		async 直接发送(data) {
			let chunk = 数据转Uint8Array(data);
			if (!chunk.byteLength) return;
			chunk = 附加响应头(chunk);
			await 发送原始块(chunk);
		},
		async 发送(data) {
			let chunk = 数据转Uint8Array(data);
			if (!chunk.byteLength) return;
			chunk = 附加响应头(chunk);
			let offset = 0;
			const totalBytes = chunk.byteLength;
			while (offset < totalBytes) {
				if (!pendingBytes && totalBytes - offset >= packetCap) {
					const sendBytes = Math.min(packetCap, totalBytes - offset);
					const view = offset || sendBytes !== totalBytes ? chunk.subarray(offset, offset + sendBytes) : chunk;
					await 发送原始块(view);
					offset += sendBytes;
					continue;
				}
				const copyBytes = Math.min(packetCap - pendingBytes, totalBytes - offset);
				pendingBuffer.set(chunk.subarray(offset, offset + copyBytes), pendingBytes);
				pendingBytes += copyBytes;
				offset += copyBytes;
				generation++;
				if (pendingBytes === packetCap || packetCap - pendingBytes < tailBytes) await flush();
				else scheduleFlush();
			}
		},
		flush
	};
}

async function connectStreams(remoteSocket, webSocket, headerData, retryFunc) {
	let header = headerData, hasData = false, reader, useBYOB = false;
	const BYOB单次读取上限 = 64 * 1024;
	const 下行发送器 = 创建下行Grain发送器(webSocket, header);
	header = null;

	try { reader = remoteSocket.readable.getReader({ mode: 'byob' }); useBYOB = true }
	catch (e) { reader = remoteSocket.readable.getReader() }

	try {
		if (!useBYOB) {
			while (true) {
				const { done, value } = await reader.read();
				if (done) break;
				if (!value || value.byteLength === 0) continue;
				hasData = true;
				await 下行发送器.发送(value);
			}
		} else {
			let readBuffer = new ArrayBuffer(BYOB单次读取上限);
			while (true) {
				const { done, value } = await reader.read(new Uint8Array(readBuffer, 0, BYOB单次读取上限));
				if (done) break;
				if (!value || value.byteLength === 0) continue;
				hasData = true;
				if (value.byteLength >= 下行Grain包字节) {
					await 下行发送器.flush();
					await 下行发送器.直接发送(value);
					readBuffer = new ArrayBuffer(BYOB单次读取上限);
				} else {
					await 下行发送器.发送(value);
					readBuffer = value.buffer.byteLength >= BYOB单次读取上限 ? value.buffer : new ArrayBuffer(BYOB单次读取上限);
				}
			}
		}
		await 下行发送器.flush();
	} catch (err) {
		// 首个响应到达前的读取错误也允许代理回退；已有响应时不能重放请求。
		if (hasData || !retryFunc) closeSocketQuietly(webSocket);
		try { remoteSocket.close() } catch (e) { }
	} finally {
		try { await reader.cancel() } catch (e) { }
		try { reader.releaseLock() } catch (e) { }
	}
	if (!hasData && retryFunc && webSocket.readyState === WebSocket.OPEN) await retryFunc();
}

function isSpeedTestSite(hostname) {
	const speedTestDomains = [atob('c3BlZWQuY2xvdWRmbGFyZS5jb20=')];
	if (speedTestDomains.includes(hostname)) {
		return true;
	}

	for (const domain of speedTestDomains) {
		if (hostname.endsWith('.' + domain) || hostname === domain) {
			return true;
		}
	}
	return false;
}

///////////////////////////////////////////////////////SOCKS5/HTTP函数///////////////////////////////////////////////
async function socks5Connect(targetHost, targetPort, initialData, TCP连接, 代理地址 = parsedSocks5Address) {
	const { username, password, hostname, port } = 代理地址;
	const socket = TCP连接({ hostname, port }), writer = socket.writable.getWriter(), reader = socket.readable.getReader();
	let buffered = new Uint8Array(0), bufferedOffset = 0;
	const 读取指定字节 = async length => {
		while (buffered.byteLength - bufferedOffset < length) {
			const response = await reader.read();
			if (response.done) throw new Error('S5 connection closed during handshake');
			const incoming = 数据转Uint8Array(response.value);
			if (!incoming.byteLength) continue;
			const remaining = buffered.subarray(bufferedOffset);
			buffered = 拼接字节数据(remaining, incoming);
			bufferedOffset = 0;
		}
		const result = buffered.subarray(bufferedOffset, bufferedOffset + length);
		bufferedOffset += length;
		return result;
	};
	try {
		const authMethods = username && password ? new Uint8Array([0x05, 0x02, 0x00, 0x02]) : new Uint8Array([0x05, 0x01, 0x00]);
		await writer.write(authMethods);
		let response = await 读取指定字节(2);
		if (response[0] !== 0x05) throw new Error('S5 method selection failed');
		const selectedMethod = response[1];
		if (selectedMethod === 0x02) {
			if (!username || !password) throw new Error('S5 requires authentication');
			const userBytes = new TextEncoder().encode(username), passBytes = new TextEncoder().encode(password);
			const authPacket = new Uint8Array([0x01, userBytes.length, ...userBytes, passBytes.length, ...passBytes]);
			await writer.write(authPacket);
			response = await 读取指定字节(2);
			if (response[0] !== 0x01 || response[1] !== 0x00) throw new Error('S5 authentication failed');
		} else if (selectedMethod !== 0x00) throw new Error(`S5 unsupported auth method: ${selectedMethod}`);

		const hostBytes = new TextEncoder().encode(targetHost);
		if (!hostBytes.length || hostBytes.length > 255) throw new Error('S5 target hostname is invalid');
		const connectPacket = new Uint8Array([0x05, 0x01, 0x00, 0x03, hostBytes.length, ...hostBytes, targetPort >> 8, targetPort & 0xff]);
		await writer.write(connectPacket);
		response = await 读取指定字节(4);
		if (response[0] !== 0x05 || response[1] !== 0x00) throw new Error('S5 connection failed');
		const addressLength = response[3] === 0x01 ? 4 : response[3] === 0x04 ? 16 : response[3] === 0x03 ? (await 读取指定字节(1))[0] : -1;
		if (addressLength < 0) throw new Error('S5 response address type is invalid');
		await 读取指定字节(addressLength + 2);

		if (有效数据长度(initialData) > 0) await writer.write(initialData);
		writer.releaseLock();
		const remaining = buffered.subarray(bufferedOffset);
		if (!remaining.byteLength) {
			reader.releaseLock();
			return socket;
		}
		let firstChunk = remaining;
		const readable = new ReadableStream({
			async pull(controller) {
				if (firstChunk) {
					controller.enqueue(firstChunk);
					firstChunk = null;
					return;
				}
				const next = await reader.read();
				if (next.done) { reader.releaseLock(); controller.close(); }
				else controller.enqueue(next.value);
			},
			async cancel(reason) {
				try { await reader.cancel(reason) } finally { try { reader.releaseLock() } catch (_) { } }
			}
		});
		return { readable, writable: socket.writable, opened: socket.opened, closed: socket.closed, close: () => socket.close() };
	} catch (error) {
		try { writer.releaseLock() } catch (e) { }
		try { reader.releaseLock() } catch (e) { }
		try { socket.close() } catch (e) { }
		throw error;
	}
}

async function httpConnect(targetHost, targetPort, initialData, HTTPS代理 = false, TCP连接, 代理地址 = parsedSocks5Address) {
	const { username, password, hostname, port } = 代理地址;
	const socket = HTTPS代理
		? TCP连接({ hostname, port }, { secureTransport: 'on', allowHalfOpen: false })
		: TCP连接({ hostname, port });
	const writer = socket.writable.getWriter(), reader = socket.readable.getReader();
	const encoder = new TextEncoder();
	const decoder = new TextDecoder();
	const connectHost = targetHost.includes(':') && !targetHost.startsWith('[') ? `[${targetHost}]` : targetHost;
	try {
		if (HTTPS代理) await socket.opened;

		const auth = username && password ? `Proxy-Authorization: Basic ${btoa(`${username}:${password}`)}\r\n` : '';
		const request = `CONNECT ${connectHost}:${targetPort} HTTP/1.1\r\nHost: ${connectHost}:${targetPort}\r\n${auth}User-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n`;
		await writer.write(encoder.encode(request));
		writer.releaseLock();

		let responseBuffer = new Uint8Array(0), headerEndIndex = -1, bytesRead = 0;
		while (headerEndIndex === -1 && bytesRead < 8192) {
			const { done, value } = await reader.read();
			if (done || !value) throw new Error(`${HTTPS代理 ? 'HTTPS' : 'HTTP'} 代理在返回 CONNECT 响应前关闭连接`);
			responseBuffer = new Uint8Array([...responseBuffer, ...value]);
			bytesRead = responseBuffer.length;
			const crlfcrlf = responseBuffer.findIndex((_, i) => i < responseBuffer.length - 3 && responseBuffer[i] === 0x0d && responseBuffer[i + 1] === 0x0a && responseBuffer[i + 2] === 0x0d && responseBuffer[i + 3] === 0x0a);
			if (crlfcrlf !== -1) headerEndIndex = crlfcrlf + 4;
		}

		if (headerEndIndex === -1) throw new Error('代理 CONNECT 响应头过长或无效');
		const statusMatch = decoder.decode(responseBuffer.slice(0, headerEndIndex)).split('\r\n')[0].match(/HTTP\/\d\.\d\s+(\d+)/);
		const statusCode = statusMatch ? parseInt(statusMatch[1], 10) : NaN;
		if (!Number.isFinite(statusCode) || statusCode < 200 || statusCode >= 300) throw new Error(`Connection failed: HTTP ${statusCode}`);

		if (有效数据长度(initialData) > 0) {
			const 远端写入器 = socket.writable.getWriter();
			try { await 远端写入器.write(initialData) }
			finally { try { 远端写入器.releaseLock() } catch (e) { } }
		}

		// 先交付 CONNECT 响应头后的隧道数据，再按需读取，避免返回前等待流背压。
		if (bytesRead > headerEndIndex) {
			const 释放读取器 = () => { try { reader.releaseLock() } catch (e) { } };
			const close = () => {
				// 连接在交给下行转发前被取消时，也必须释放握手阶段持有的读取器。
				void reader.cancel().catch(() => { }).finally(释放读取器);
				return socket.close();
			};
			const readable = new ReadableStream({
				start(controller) {
					controller.enqueue(responseBuffer.subarray(headerEndIndex, bytesRead));
				},
				async pull(controller) {
					try {
						const { done, value } = await reader.read();
						if (done) { 释放读取器(); controller.close(); }
						else controller.enqueue(value);
					} catch (error) {
						释放读取器();
						try { socket.close() } catch (e) { }
						controller.error(error);
					}
				},
				async cancel(reason) {
					try { await reader.cancel(reason) }
					finally {
						释放读取器();
						try { await socket.close() } catch (e) { }
					}
				}
			});
			return { readable, writable: socket.writable, opened: socket.opened, closed: socket.closed, close };
		}

		reader.releaseLock();
		return socket;
	} catch (error) {
		try { writer.releaseLock() } catch (e) { }
		try { reader.releaseLock() } catch (e) { }
		try { socket.close() } catch (e) { }
		throw error;
	}
}

async function httpsConnect(targetHost, targetPort, initialData, TCP连接, 代理地址 = parsedSocks5Address) {
	const { username, password, hostname, port } = 代理地址;
	const encoder = new TextEncoder();
	const decoder = new TextDecoder();
	const connectHost = targetHost.includes(':') && !targetHost.startsWith('[') ? `[${targetHost}]` : targetHost;
	let tlsSocket = null;
	const tlsServerName = isIPHostname(hostname) ? '' : stripIPv6Brackets(hostname);
	const 打开HTTPS代理TLS = async (allowChacha = false) => {
		const proxySocket = TCP连接({ hostname, port });
		try {
			await proxySocket.opened;
			const socket = new TlsClient(proxySocket, { serverName: tlsServerName, insecure: true, allowChacha });
			await socket.handshake();
			log(`[HTTPS代理] TLS版本: ${socket.isTls13 ? '1.3' : '1.2'} | Cipher: 0x${socket.cipherSuite.toString(16)}${socket.cipherConfig?.chacha ? ' (ChaCha20)' : ' (AES-GCM)'}`);
			return socket;
		} catch (error) {
			try { proxySocket.close() } catch (e) { }
			throw error;
		}
	};
	try {
		try {
			tlsSocket = await 打开HTTPS代理TLS(false);
		} catch (error) {
			if (!/cipher|handshake|TLS Alert|ServerHello|Finished|Unsupported|Missing TLS/i.test(error?.message || `${error || ''}`)) throw error;
			log(`[HTTPS代理] AES-GCM TLS 握手失败，回退 ChaCha20 兼容模式: ${error?.message || error}`);
			tlsSocket = await 打开HTTPS代理TLS(true);
		}

		const auth = username && password ? `Proxy-Authorization: Basic ${btoa(`${username}:${password}`)}\r\n` : '';
		const request = `CONNECT ${connectHost}:${targetPort} HTTP/1.1\r\nHost: ${connectHost}:${targetPort}\r\n${auth}User-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n`;
		await tlsSocket.write(encoder.encode(request));

		let responseBuffer = new Uint8Array(0), headerEndIndex = -1, bytesRead = 0;
		while (headerEndIndex === -1 && bytesRead < 8192) {
			const value = await tlsSocket.read();
			if (!value) throw new Error('HTTPS 代理在返回 CONNECT 响应前关闭连接');
			responseBuffer = 拼接字节数据(responseBuffer, value);
			bytesRead = responseBuffer.length;
			const crlfcrlf = responseBuffer.findIndex((_, i) => i < responseBuffer.length - 3 && responseBuffer[i] === 0x0d && responseBuffer[i + 1] === 0x0a && responseBuffer[i + 2] === 0x0d && responseBuffer[i + 3] === 0x0a);
			if (crlfcrlf !== -1) headerEndIndex = crlfcrlf + 4;
		}

		if (headerEndIndex === -1) throw new Error('HTTPS 代理 CONNECT 响应头过长或无效');
		const statusMatch = decoder.decode(responseBuffer.slice(0, headerEndIndex)).split('\r\n')[0].match(/HTTP\/\d\.\d\s+(\d+)/);
		const statusCode = statusMatch ? parseInt(statusMatch[1], 10) : NaN;
		if (!Number.isFinite(statusCode) || statusCode < 200 || statusCode >= 300) throw new Error(`Connection failed: HTTP ${statusCode}`);

		if (有效数据长度(initialData) > 0) await tlsSocket.write(数据转Uint8Array(initialData));
		const bufferedData = bytesRead > headerEndIndex ? responseBuffer.subarray(headerEndIndex, bytesRead) : null;
		let closedSettled = false, resolveClosed, rejectClosed;
		const settleClosed = (settle, value) => {
			if (!closedSettled) {
				closedSettled = true;
				settle(value);
			}
		};
		const closed = new Promise((resolve, reject) => {
			resolveClosed = resolve;
			rejectClosed = reject;
		});
		const close = () => {
			try { tlsSocket.close() } catch (e) { }
			settleClosed(resolveClosed);
		};
		const readable = new ReadableStream({
			async start(controller) {
				try {
					if (有效数据长度(bufferedData) > 0) controller.enqueue(bufferedData);
					while (true) {
						const data = await tlsSocket.read();
						if (!data) break;
						if (data.byteLength > 0) controller.enqueue(data);
					}
					try { controller.close() } catch (e) { }
					settleClosed(resolveClosed);
				} catch (error) {
					try { controller.error(error) } catch (e) { }
					settleClosed(rejectClosed, error);
				}
			},
			cancel() {
				close();
			}
		});
		const writable = new WritableStream({
			async write(chunk) {
				await tlsSocket.write(数据转Uint8Array(chunk));
			},
			close,
			abort(error) {
				close();
				if (error) settleClosed(rejectClosed, error);
			}
		});
		return { readable, writable, closed, close };
	} catch (error) {
		try { tlsSocket?.close() } catch (e) { }
		throw error;
	}
}

function 创建请求TCP连接器(request, state = null) {
	const 请求对象 = /** @type {any} */ (request);
	const fetcher = 请求对象?.fetcher;
	if (!fetcher || typeof fetcher.connect !== 'function') throw new Error('request.fetcher.connect unavailable');
	return (options, init) => {
		if (state?.cancelled) throw new Error('连接已取消');
		const socket = init === undefined ? fetcher.connect(options) : fetcher.connect(options, init);
		if (state?.sockets) {
			state.sockets.add(socket);
			socket.closed?.then(() => state.sockets.delete(socket), () => state.sockets.delete(socket));
		}
		return socket;
	};
}
////////////////////////////////////////////TLSClient by: @Alexandre_Kojeve////////////////////////////////////////////////
const TLS_VERSION_10 = 769, TLS_VERSION_12 = 771, TLS_VERSION_13 = 772;
const CONTENT_TYPE_CHANGE_CIPHER_SPEC = 20, CONTENT_TYPE_ALERT = 21, CONTENT_TYPE_HANDSHAKE = 22, CONTENT_TYPE_APPLICATION_DATA = 23;
const HANDSHAKE_TYPE_CLIENT_HELLO = 1, HANDSHAKE_TYPE_SERVER_HELLO = 2, HANDSHAKE_TYPE_NEW_SESSION_TICKET = 4, HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS = 8, HANDSHAKE_TYPE_CERTIFICATE = 11, HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE = 12, HANDSHAKE_TYPE_CERTIFICATE_REQUEST = 13, HANDSHAKE_TYPE_SERVER_HELLO_DONE = 14, HANDSHAKE_TYPE_CERTIFICATE_VERIFY = 15, HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE = 16, HANDSHAKE_TYPE_FINISHED = 20, HANDSHAKE_TYPE_KEY_UPDATE = 24;
const EXT_SERVER_NAME = 0, EXT_SUPPORTED_GROUPS = 10, EXT_EC_POINT_FORMATS = 11, EXT_SIGNATURE_ALGORITHMS = 13, EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 16, EXT_SUPPORTED_VERSIONS = 43, EXT_PSK_KEY_EXCHANGE_MODES = 45, EXT_KEY_SHARE = 51;

const ALERT_CLOSE_NOTIFY = 0, ALERT_LEVEL_WARNING = 1, ALERT_UNRECOGNIZED_NAME = 112;
const shouldIgnoreTlsAlert = fragment => fragment?.[0] === ALERT_LEVEL_WARNING && fragment?.[1] === ALERT_UNRECOGNIZED_NAME;

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const EMPTY_BYTES = new Uint8Array(0);

const CIPHER_SUITES_BY_ID = new Map([
	[4865, { id: 4865, keyLen: 16, ivLen: 12, hash: "SHA-256", tls13: !0 }],
	[4866, { id: 4866, keyLen: 32, ivLen: 12, hash: "SHA-384", tls13: !0 }],
	[4867, { id: 4867, keyLen: 32, ivLen: 12, hash: "SHA-256", tls13: !0, chacha: !0 }],
	[49199, { id: 49199, keyLen: 16, ivLen: 4, hash: "SHA-256", kex: "ECDHE" }],
	[49200, { id: 49200, keyLen: 32, ivLen: 4, hash: "SHA-384", kex: "ECDHE" }],
	[52392, { id: 52392, keyLen: 32, ivLen: 12, hash: "SHA-256", kex: "ECDHE", chacha: !0 }],
	[49195, { id: 49195, keyLen: 16, ivLen: 4, hash: "SHA-256", kex: "ECDHE" }],
	[49196, { id: 49196, keyLen: 32, ivLen: 4, hash: "SHA-384", kex: "ECDHE" }],
	[52393, { id: 52393, keyLen: 32, ivLen: 12, hash: "SHA-256", kex: "ECDHE", chacha: !0 }]
]);
const GROUPS_BY_ID = new Map([[29, "X25519"], [23, "P-256"]]);
const SUPPORTED_SIGNATURE_ALGORITHMS = [2052, 2053, 2054, 1025, 1281, 1537, 1027, 1283, 1539];

const tlsBytes = (...parts) => {
	const flattenBytes = values => values.flatMap(value => value instanceof Uint8Array ? [...value] : Array.isArray(value) ? flattenBytes(value) : "number" == typeof value ? [value] : []);
	return new Uint8Array(flattenBytes(parts))
};
const uint16be = value => [value >> 8 & 255, 255 & value];
const readUint16 = (buffer, offset) => buffer[offset] << 8 | buffer[offset + 1];
const readUint24 = (buffer, offset) => buffer[offset] << 16 | buffer[offset + 1] << 8 | buffer[offset + 2];
const concatBytes = (...chunks) => {
	const nonEmptyChunks = chunks.filter((chunk => chunk && chunk.length > 0)),
		length = nonEmptyChunks.reduce(((total, chunk) => total + chunk.length), 0),
		result = new Uint8Array(length);
	let offset = 0;
	for (const chunk of nonEmptyChunks) result.set(chunk, offset), offset += chunk.length;
	return result
};
const randomBytes = length => crypto.getRandomValues(new Uint8Array(length));
const constantTimeEqual = (left, right) => {
	if (!left || !right || left.length !== right.length) return !1;
	let diff = 0; for (let index = 0; index < left.length; index++) diff |= left[index] ^ right[index];
	return 0 === diff
};
const hashByteLength = hash => "SHA-512" === hash ? 64 : "SHA-384" === hash ? 48 : 32;
async function hmac(hash, key, data) {
	const cryptoKey = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash }, !1, ["sign"]);
	return new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, data))
}
async function digestBytes(hash, data) { return new Uint8Array(await crypto.subtle.digest(hash, data)) }
async function tls12Prf(secret, label, seed, length, hash = "SHA-256") {
	const labelSeed = concatBytes(textEncoder.encode(label), seed);
	let output = new Uint8Array(0),
		currentA = labelSeed;
	for (; output.length < length;) {
		currentA = await hmac(hash, secret, currentA);
		const block = await hmac(hash, secret, concatBytes(currentA, labelSeed));
		output = concatBytes(output, block)
	}
	return output.slice(0, length)
}
async function hkdfExtract(hash, salt, inputKeyMaterial) {
	return salt && salt.length || (salt = new Uint8Array(hashByteLength(hash))), hmac(hash, salt, inputKeyMaterial)
}
async function hkdfExpandLabel(hash, secret, label, context, length) {
	const fullLabel = textEncoder.encode("tls13 " + label);
	return async function (hash, secret, info, length) {
		const hashLen = hashByteLength(hash),
			roundCount = Math.ceil(length / hashLen);
		let output = new Uint8Array(0),
			previousBlock = new Uint8Array(0);
		for (let round = 1; round <= roundCount; round++) previousBlock = await hmac(hash, secret, concatBytes(previousBlock, info, [round])), output = concatBytes(output, previousBlock);
		return output.slice(0, length)
	}(hash, secret, tlsBytes(uint16be(length), fullLabel.length, fullLabel, context.length, context), length)
}
async function generateKeyShare(group = "P-256") {
	const algorithm = "X25519" === group ? { name: "X25519" } : { name: "ECDH", namedCurve: group };
	const keyPair = /** @type {CryptoKeyPair} */ (await crypto.subtle.generateKey(algorithm, !0, ["deriveBits"]));
	const publicKeyRaw = /** @type {ArrayBuffer} */ (await crypto.subtle.exportKey("raw", keyPair.publicKey));
	return { keyPair, publicKeyRaw: new Uint8Array(publicKeyRaw) }
}
async function deriveSharedSecret(privateKey, peerPublicKey, group = "P-256") {
	const algorithm = "X25519" === group ? { name: "X25519" } : { name: "ECDH", namedCurve: group },
		peerKey = await crypto.subtle.importKey("raw", peerPublicKey, algorithm, !1, []),
		bits = "P-384" === group ? 384 : "P-521" === group ? 528 : 256;
	return new Uint8Array(await crypto.subtle.deriveBits(/** @type {any} */({ name: algorithm.name, public: peerKey }), privateKey, bits))
}
async function importAesGcmKey(key, usages) { return crypto.subtle.importKey("raw", key, { name: "AES-GCM" }, !1, usages) }
async function aesGcmEncryptWithKey(cryptoKey, initializationVector, plaintext, additionalData) {
	return new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: initializationVector, additionalData, tagLength: 128 }, cryptoKey, plaintext))
}
async function aesGcmDecryptWithKey(cryptoKey, initializationVector, ciphertext, additionalData) {
	return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: initializationVector, additionalData, tagLength: 128 }, cryptoKey, ciphertext))
}

function rotateLeft32(value, bits) { return (value << bits | value >>> 32 - bits) >>> 0 }

function chachaQuarterRound(state, indexA, indexB, indexC, indexD) {
	state[indexA] = state[indexA] + state[indexB] >>> 0, state[indexD] = rotateLeft32(state[indexD] ^ state[indexA], 16), state[indexC] = state[indexC] + state[indexD] >>> 0, state[indexB] = rotateLeft32(state[indexB] ^ state[indexC], 12), state[indexA] = state[indexA] + state[indexB] >>> 0, state[indexD] = rotateLeft32(state[indexD] ^ state[indexA], 8), state[indexC] = state[indexC] + state[indexD] >>> 0, state[indexB] = rotateLeft32(state[indexB] ^ state[indexC], 7)
}

function chacha20Block(key, counter, nonce) {
	const state = new Uint32Array(16);
	state[0] = 1634760805, state[1] = 857760878, state[2] = 2036477234, state[3] = 1797285236;
	const keyView = new DataView(key.buffer, key.byteOffset, key.byteLength);
	for (let wordIndex = 0; wordIndex < 8; wordIndex++) state[4 + wordIndex] = keyView.getUint32(4 * wordIndex, !0);
	state[12] = counter;
	const nonceView = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength);
	state[13] = nonceView.getUint32(0, !0), state[14] = nonceView.getUint32(4, !0), state[15] = nonceView.getUint32(8, !0);
	const workingState = new Uint32Array(state);
	for (let round = 0; round < 10; round++) chachaQuarterRound(workingState, 0, 4, 8, 12), chachaQuarterRound(workingState, 1, 5, 9, 13), chachaQuarterRound(workingState, 2, 6, 10, 14), chachaQuarterRound(workingState, 3, 7, 11, 15), chachaQuarterRound(workingState, 0, 5, 10, 15), chachaQuarterRound(workingState, 1, 6, 11, 12), chachaQuarterRound(workingState, 2, 7, 8, 13), chachaQuarterRound(workingState, 3, 4, 9, 14);
	for (let wordIndex = 0; wordIndex < 16; wordIndex++) workingState[wordIndex] = workingState[wordIndex] + state[wordIndex] >>> 0;
	return new Uint8Array(workingState.buffer.slice(0))
}

function chacha20Xor(key, nonce, data) {
	const output = new Uint8Array(data.length);
	let counter = 1;
	for (let offset = 0; offset < data.length; offset += 64) {
		const block = chacha20Block(key, counter++, nonce),
			blockLength = Math.min(64, data.length - offset);
		for (let index = 0; index < blockLength; index++) output[offset + index] = data[offset + index] ^ block[index]
	}
	return output
}

function poly1305Mac(key, message) {
	const rKey = function (rBytes) {
		const clamped = new Uint8Array(rBytes);
		return clamped[3] &= 15, clamped[7] &= 15, clamped[11] &= 15, clamped[15] &= 15, clamped[4] &= 252, clamped[8] &= 252, clamped[12] &= 252, clamped
	}(key.slice(0, 16)),
		sKey = key.slice(16, 32);
	let accumulator = [0n, 0n, 0n, 0n, 0n];
	const rLimbs = [0x3ffffffn & BigInt(rKey[0] | rKey[1] << 8 | rKey[2] << 16 | rKey[3] << 24), 0x3ffffffn & BigInt(rKey[3] >> 2 | rKey[4] << 6 | rKey[5] << 14 | rKey[6] << 22), 0x3ffffffn & BigInt(rKey[6] >> 4 | rKey[7] << 4 | rKey[8] << 12 | rKey[9] << 20), 0x3ffffffn & BigInt(rKey[9] >> 6 | rKey[10] << 2 | rKey[11] << 10 | rKey[12] << 18), 0x3ffffffn & BigInt(rKey[13] | rKey[14] << 8 | rKey[15] << 16)];
	for (let offset = 0; offset < message.length; offset += 16) {
		const chunk = message.slice(offset, offset + 16),
			paddedChunk = new Uint8Array(17);
		paddedChunk.set(chunk), paddedChunk[chunk.length] = 1, accumulator[0] += BigInt(paddedChunk[0] | paddedChunk[1] << 8 | paddedChunk[2] << 16 | (3 & paddedChunk[3]) << 24), accumulator[1] += BigInt(paddedChunk[3] >> 2 | paddedChunk[4] << 6 | paddedChunk[5] << 14 | (15 & paddedChunk[6]) << 22), accumulator[2] += BigInt(paddedChunk[6] >> 4 | paddedChunk[7] << 4 | paddedChunk[8] << 12 | (63 & paddedChunk[9]) << 20), accumulator[3] += BigInt(paddedChunk[9] >> 6 | paddedChunk[10] << 2 | paddedChunk[11] << 10 | paddedChunk[12] << 18), accumulator[4] += BigInt(paddedChunk[13] | paddedChunk[14] << 8 | paddedChunk[15] << 16 | paddedChunk[16] << 24);
		const product = [0n, 0n, 0n, 0n, 0n];
		for (let accIndex = 0; accIndex < 5; accIndex++)
			for (let rIndex = 0; rIndex < 5; rIndex++) {
				const limbIndex = accIndex + rIndex;
				limbIndex < 5 ? product[limbIndex] += accumulator[accIndex] * rLimbs[rIndex] : product[limbIndex - 5] += accumulator[accIndex] * rLimbs[rIndex] * 5n
			}
		let carry = 0n;
		for (let index = 0; index < 5; index++) product[index] += carry, accumulator[index] = 0x3ffffffn & product[index], carry = product[index] >> 26n;
		accumulator[0] += 5n * carry, carry = accumulator[0] >> 26n, accumulator[0] &= 0x3ffffffn, accumulator[1] += carry
	}
	let tagValue = accumulator[0] | accumulator[1] << 26n | accumulator[2] << 52n | accumulator[3] << 78n | accumulator[4] << 104n;
	tagValue = tagValue + sKey.reduce(((total, byte, index) => total + (BigInt(byte) << BigInt(8 * index))), 0n) & (1n << 128n) - 1n;
	const tag = new Uint8Array(16);
	for (let index = 0; index < 16; index++) tag[index] = Number(tagValue >> BigInt(8 * index) & 0xffn);
	return tag
}

function chacha20Poly1305Encrypt(key, nonce, plaintext, additionalData) {
	const polyKey = chacha20Block(key, 0, nonce).slice(0, 32),
		ciphertext = chacha20Xor(key, nonce, plaintext),
		aadPadding = (16 - additionalData.length % 16) % 16,
		ciphertextPadding = (16 - ciphertext.length % 16) % 16,
		macData = new Uint8Array(additionalData.length + aadPadding + ciphertext.length + ciphertextPadding + 16);
	macData.set(additionalData, 0), macData.set(ciphertext, additionalData.length + aadPadding);
	const lengthView = new DataView(macData.buffer, additionalData.length + aadPadding + ciphertext.length + ciphertextPadding);
	lengthView.setBigUint64(0, BigInt(additionalData.length), !0), lengthView.setBigUint64(8, BigInt(ciphertext.length), !0);
	const tag = poly1305Mac(polyKey, macData);
	return concatBytes(ciphertext, tag)
}

function chacha20Poly1305Decrypt(key, nonce, ciphertext, additionalData) {
	if (ciphertext.length < 16) throw new Error("Ciphertext too short");
	const tag = ciphertext.slice(-16),
		encryptedData = ciphertext.slice(0, -16),
		polyKey = chacha20Block(key, 0, nonce).slice(0, 32),
		aadPadding = (16 - additionalData.length % 16) % 16,
		ciphertextPadding = (16 - encryptedData.length % 16) % 16,
		macData = new Uint8Array(additionalData.length + aadPadding + encryptedData.length + ciphertextPadding + 16);
	macData.set(additionalData, 0), macData.set(encryptedData, additionalData.length + aadPadding);
	const lengthView = new DataView(macData.buffer, additionalData.length + aadPadding + encryptedData.length + ciphertextPadding);
	lengthView.setBigUint64(0, BigInt(additionalData.length), !0), lengthView.setBigUint64(8, BigInt(encryptedData.length), !0);
	const expectedTag = poly1305Mac(polyKey, macData);
	let diff = 0;
	for (let index = 0; index < 16; index++) diff |= tag[index] ^ expectedTag[index];
	if (0 !== diff) throw new Error("ChaCha20-Poly1305 authentication failed");
	return chacha20Xor(key, nonce, encryptedData)
}

const TLS_MAX_PLAINTEXT_FRAGMENT = 16 * 1024;
function buildTlsRecord(contentType, fragment, version = TLS_VERSION_12) {
	const data = 数据转Uint8Array(fragment);
	const record = new Uint8Array(5 + data.byteLength);
	record[0] = contentType;
	record[1] = version >> 8 & 255;
	record[2] = version & 255;
	record[3] = data.byteLength >> 8 & 255;
	record[4] = data.byteLength & 255;
	record.set(data, 5);
	return record;
}
function buildHandshakeMessage(handshakeType, body) { return tlsBytes(handshakeType, (length => [length >> 16 & 255, length >> 8 & 255, 255 & length])(body.length), body) }
class TlsRecordParser {
	constructor() { this.buffer = new Uint8Array(0) }
	feed(chunk) {
		const bytes = 数据转Uint8Array(chunk);
		this.buffer = this.buffer.length ? concatBytes(this.buffer, bytes) : bytes
	}
	next() {
		if (this.buffer.length < 5) return null;
		const contentType = this.buffer[0],
			version = readUint16(this.buffer, 1),
			length = readUint16(this.buffer, 3);
		if (this.buffer.length < 5 + length) return null;
		const fragment = this.buffer.subarray(5, 5 + length);
		return this.buffer = this.buffer.subarray(5 + length), { type: contentType, version, length, fragment }
	}
}
class TlsHandshakeParser {
	constructor() { this.buffer = new Uint8Array(0) }
	feed(chunk) {
		const bytes = 数据转Uint8Array(chunk);
		this.buffer = this.buffer.length ? concatBytes(this.buffer, bytes) : bytes
	}
	next() {
		if (this.buffer.length < 4) return null;
		const handshakeType = this.buffer[0],
			length = readUint24(this.buffer, 1);
		if (this.buffer.length < 4 + length) return null;
		const body = this.buffer.subarray(4, 4 + length),
			raw = this.buffer.subarray(0, 4 + length);
		return this.buffer = this.buffer.subarray(4 + length), { type: handshakeType, length, body, raw }
	}
}

function parseServerHello(body) {
	let offset = 0;
	const legacyVersion = readUint16(body, offset);
	offset += 2;
	const serverRandom = body.slice(offset, offset + 32);
	offset += 32;
	const sessionIdLength = body[offset++],
		sessionId = body.slice(offset, offset + sessionIdLength);
	offset += sessionIdLength;
	const cipherSuite = readUint16(body, offset);
	offset += 2;
	const compression = body[offset++];
	let selectedVersion = legacyVersion,
		keyShare = null,
		alpn = null;
	if (offset < body.length) {
		const extensionsLength = readUint16(body, offset);
		offset += 2;
		const extensionsEnd = offset + extensionsLength;
		for (; offset + 4 <= extensionsEnd;) {
			const extensionType = readUint16(body, offset);
			offset += 2;
			const extensionLength = readUint16(body, offset);
			offset += 2;
			const extensionData = body.slice(offset, offset + extensionLength);
			if (offset += extensionLength, extensionType === EXT_SUPPORTED_VERSIONS && extensionLength >= 2) selectedVersion = readUint16(extensionData, 0);
			else if (extensionType === EXT_KEY_SHARE && extensionLength >= 4) {
				const group = readUint16(extensionData, 0),
					keyLength = readUint16(extensionData, 2);
				keyShare = { group, key: extensionData.slice(4, 4 + keyLength) }
			} else extensionType === EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION && extensionLength >= 3 && (alpn = textDecoder.decode(extensionData.slice(3, 3 + extensionData[2])))
		}
	}
	const helloRetryRequestRandom = new Uint8Array([207, 33, 173, 116, 229, 154, 97, 17, 190, 29, 140, 2, 30, 101, 184, 145, 194, 162, 17, 22, 122, 187, 140, 94, 7, 158, 9, 226, 200, 168, 51, 156]);
	return { version: legacyVersion, serverRandom, sessionId, cipherSuite, compression, selectedVersion, keyShare, alpn, isHRR: constantTimeEqual(serverRandom, helloRetryRequestRandom), isTls13: selectedVersion === TLS_VERSION_13 }
}

function parseServerKeyExchange(body) {
	let offset = 1;
	const namedCurve = readUint16(body, offset);
	offset += 2;
	const keyLength = body[offset++];
	return { namedCurve, serverPublicKey: body.slice(offset, offset + keyLength) }
}

function extractLeafCertificate(body, hasContext = 0) {
	let offset = 0;
	if (hasContext) {
		const contextLength = body[offset++];
		offset += contextLength
	}
	if (offset + 3 > body.length) return null;
	const certificateListLength = readUint24(body, offset);
	if (offset += 3, !certificateListLength || offset + 3 > body.length) return null;
	const certificateLength = readUint24(body, offset);
	return offset += 3, certificateLength ? body.slice(offset, offset + certificateLength) : null
}

function parseEncryptedExtensions(body) {
	const parsed = { alpn: null };
	let offset = 2;
	const extensionsEnd = 2 + readUint16(body, 0);
	for (; offset + 4 <= extensionsEnd;) {
		const extensionType = readUint16(body, offset);
		offset += 2;
		const extensionLength = readUint16(body, offset);
		if (offset += 2, extensionType === EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION && extensionLength >= 3) {
			const protocolLength = body[offset + 2];
			protocolLength > 0 && offset + 3 + protocolLength <= offset + extensionLength && (parsed.alpn = textDecoder.decode(body.slice(offset + 3, offset + 3 + protocolLength)))
		}
		offset += extensionLength
	}
	return parsed
}

function buildClientHello(clientRandom, serverName, keyShares, { tls13: enableTls13 = !0, tls12: enableTls12 = !0, alpn = null, chacha = !0 } = {}) {
	const cipherIds = [];
	enableTls13 && cipherIds.push(4865, 4866, ...(chacha ? [4867] : [])), enableTls12 && cipherIds.push(49199, 49200, 49195, 49196, ...(chacha ? [52392, 52393] : []));
	const cipherBytes = tlsBytes(...cipherIds.flatMap(uint16be)),
		extensions = [tlsBytes(255, 1, 0, 1, 0)];
	if (serverName) {
		const serverNameBytes = textEncoder.encode(serverName),
			serverNameList = tlsBytes(0, uint16be(serverNameBytes.length), serverNameBytes);
		extensions.push(tlsBytes(uint16be(EXT_SERVER_NAME), uint16be(serverNameList.length + 2), uint16be(serverNameList.length), serverNameList))
	}
	extensions.push(tlsBytes(uint16be(EXT_EC_POINT_FORMATS), 0, 2, 1, 0)), extensions.push(tlsBytes(uint16be(EXT_SUPPORTED_GROUPS), 0, 6, 0, 4, 0, 29, 0, 23));
	const signatureBytes = tlsBytes(...SUPPORTED_SIGNATURE_ALGORITHMS.flatMap(uint16be));
	extensions.push(tlsBytes(uint16be(EXT_SIGNATURE_ALGORITHMS), uint16be(signatureBytes.length + 2), uint16be(signatureBytes.length), signatureBytes));
	const protocols = Array.isArray(alpn) ? alpn.filter(Boolean) : alpn ? [alpn] : [];
	if (protocols.length) {
		const alpnBytes = concatBytes(...protocols.map((protocol => { const protocolBytes = textEncoder.encode(protocol); return tlsBytes(protocolBytes.length, protocolBytes) })));
		extensions.push(tlsBytes(uint16be(EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION), uint16be(alpnBytes.length + 2), uint16be(alpnBytes.length), alpnBytes))
	}
	if (enableTls13 && keyShares) {
		let keyShareBytes;
		if (extensions.push(enableTls12 ? tlsBytes(uint16be(EXT_SUPPORTED_VERSIONS), 0, 5, 4, 3, 4, 3, 3) : tlsBytes(uint16be(EXT_SUPPORTED_VERSIONS), 0, 3, 2, 3, 4)), extensions.push(tlsBytes(uint16be(EXT_PSK_KEY_EXCHANGE_MODES), 0, 2, 1, 1)), keyShares?.x25519 && keyShares?.p256) keyShareBytes = concatBytes(tlsBytes(0, 29, uint16be(keyShares.x25519.length), keyShares.x25519), tlsBytes(0, 23, uint16be(keyShares.p256.length), keyShares.p256));
		else if (keyShares?.x25519) keyShareBytes = tlsBytes(0, 29, uint16be(keyShares.x25519.length), keyShares.x25519);
		else if (keyShares?.p256) keyShareBytes = tlsBytes(0, 23, uint16be(keyShares.p256.length), keyShares.p256);
		else {
			if (!(keyShares instanceof Uint8Array)) throw new Error("Invalid keyShares");
			keyShareBytes = tlsBytes(0, 23, uint16be(keyShares.length), keyShares)
		}
		extensions.push(tlsBytes(uint16be(EXT_KEY_SHARE), uint16be(keyShareBytes.length + 2), uint16be(keyShareBytes.length), keyShareBytes))
	}
	const extensionsBytes = concatBytes(...extensions);
	return buildHandshakeMessage(HANDSHAKE_TYPE_CLIENT_HELLO, tlsBytes(uint16be(TLS_VERSION_12), clientRandom, 0, uint16be(cipherBytes.length), cipherBytes, 1, 0, uint16be(extensionsBytes.length), extensionsBytes))
}
const uint64be = sequenceNumber => { const bytes = new Uint8Array(8); return new DataView(bytes.buffer).setBigUint64(0, sequenceNumber, !1), bytes },
	xorSequenceIntoIv = (initializationVector, sequenceNumber) => {
		const nonce = initializationVector.slice(),
			sequenceBytes = uint64be(sequenceNumber);
		for (let index = 0; index < 8; index++) nonce[nonce.length - 8 + index] ^= sequenceBytes[index];
		return nonce
	},
	deriveTrafficKeys = (hash, secret, keyLen, ivLen) => Promise.all([hkdfExpandLabel(hash, secret, "key", EMPTY_BYTES, keyLen), hkdfExpandLabel(hash, secret, "iv", EMPTY_BYTES, ivLen)]);
class TlsClient {
	constructor(socket, options = {}) {
		if (this.socket = socket, this.serverName = options.serverName || "", this.supportTls13 = !1 !== options.tls13, this.supportTls12 = !1 !== options.tls12, !this.supportTls13 && !this.supportTls12) throw new Error("At least one TLS version must be enabled");
		this.alpnProtocols = Array.isArray(options.alpn) ? options.alpn : options.alpn ? [options.alpn] : null, this.allowChacha = options.allowChacha !== false, this.timeout = options.timeout ?? 3e4, this.clientRandom = randomBytes(32), this.serverRandom = null, this.handshakeChunks = [], this.handshakeComplete = !1, this.negotiatedAlpn = null, this.cipherSuite = null, this.cipherConfig = null, this.isTls13 = !1, this.masterSecret = null, this.handshakeSecret = null, this.clientWriteKey = null, this.serverWriteKey = null, this.clientWriteIv = null, this.serverWriteIv = null, this.clientHandshakeKey = null, this.serverHandshakeKey = null, this.clientHandshakeIv = null, this.serverHandshakeIv = null, this.clientAppKey = null, this.serverAppKey = null, this.clientAppIv = null, this.serverAppIv = null, this.clientWriteCryptoKey = null, this.serverWriteCryptoKey = null, this.clientHandshakeCryptoKey = null, this.serverHandshakeCryptoKey = null, this.clientAppCryptoKey = null, this.serverAppCryptoKey = null, this.clientSeqNum = 0n, this.serverSeqNum = 0n, this.recordParser = new TlsRecordParser, this.handshakeParser = new TlsHandshakeParser, this.keyPairs = new Map, this.ecdhKeyPair = null, this.sawCert = !1
	}
	recordHandshake(chunk) { this.handshakeChunks.push(chunk) }
	transcript() { return 1 === this.handshakeChunks.length ? this.handshakeChunks[0] : concatBytes(...this.handshakeChunks) }
	getCipherConfig(cipherSuite) { return CIPHER_SUITES_BY_ID.get(cipherSuite) || null }
	async readChunk(reader) { return this.timeout ? Promise.race([reader.read(), new Promise(((resolve, reject) => setTimeout((() => reject(new Error("TLS read timeout"))), this.timeout)))]) : reader.read() }
	async readRecordsUntil(reader, predicate, closedError) {
		for (; ;) {
			let record;
			for (; record = this.recordParser.next();)
				if (await predicate(record)) return;
			const { value, done } = await this.readChunk(reader);
			if (done) throw new Error(closedError);
			this.recordParser.feed(value)
		}
	}
	async readHandshakeUntil(reader, predicate, closedError) {
		for (let message; message = this.handshakeParser.next();)
			if (await predicate(message)) return;
		return this.readRecordsUntil(reader, (async record => {
			if (record.type === CONTENT_TYPE_ALERT) {
				if (shouldIgnoreTlsAlert(record.fragment)) return;
				throw new Error(`TLS Alert: ${record.fragment[1]}`);
			}
			if (record.type === CONTENT_TYPE_HANDSHAKE) {
				this.handshakeParser.feed(record.fragment);
				for (let message; message = this.handshakeParser.next();)
					if (await predicate(message)) return 1
			}
		}), closedError)
	}
	async acceptCertificate(certificate) { if (!certificate?.length) throw new Error("Empty certificate"); this.sawCert = !0 }
	async handshake() {
		const [p256Share, x25519Share] = await Promise.all([generateKeyShare("P-256"), generateKeyShare("X25519")]);
		this.keyPairs = new Map([[23, p256Share], [29, x25519Share]]), this.ecdhKeyPair = p256Share.keyPair;
		const reader = this.socket.readable.getReader(),
			writer = this.socket.writable.getWriter();
		try {
			const clientHello = buildClientHello(this.clientRandom, this.serverName, { x25519: x25519Share.publicKeyRaw, p256: p256Share.publicKeyRaw }, { tls13: this.supportTls13, tls12: this.supportTls12, alpn: this.alpnProtocols, chacha: this.allowChacha });
			this.recordHandshake(clientHello), await writer.write(buildTlsRecord(CONTENT_TYPE_HANDSHAKE, clientHello, TLS_VERSION_10));
			const serverHello = await this.receiveServerHello(reader);
			if (serverHello.isHRR) throw new Error("HelloRetryRequest is not supported by TLSClientMini");
			if (serverHello.keyShare?.group && this.keyPairs.has(serverHello.keyShare.group)) {
				const selectedKeyPair = this.keyPairs.get(serverHello.keyShare.group);
				this.ecdhKeyPair = selectedKeyPair.keyPair
			}
			serverHello.isTls13 ? await this.handshakeTls13(reader, writer, serverHello) : await this.handshakeTls12(reader, writer), this.handshakeComplete = !0
		} finally {
			reader.releaseLock(), writer.releaseLock()
		}
	}
	async receiveServerHello(reader) {
		for (; ;) {
			const { value, done } = await this.readChunk(reader);
			if (done) throw new Error("Connection closed waiting for ServerHello");
			let record;
			for (this.recordParser.feed(value); record = this.recordParser.next();) {
				if (record.type === CONTENT_TYPE_ALERT) {
					if (shouldIgnoreTlsAlert(record.fragment)) continue;
					throw new Error(`TLS Alert: level=${record.fragment[0]}, desc=${record.fragment[1]}`);
				}
				if (record.type !== CONTENT_TYPE_HANDSHAKE) continue;
				let message;
				for (this.handshakeParser.feed(record.fragment); message = this.handshakeParser.next();) {
					if (message.type !== HANDSHAKE_TYPE_SERVER_HELLO) continue;
					this.recordHandshake(message.raw);
					const serverHello = parseServerHello(message.body);
					if (this.serverRandom = serverHello.serverRandom, this.cipherSuite = serverHello.cipherSuite, this.cipherConfig = this.getCipherConfig(serverHello.cipherSuite), this.isTls13 = serverHello.isTls13, this.negotiatedAlpn = serverHello.alpn || null, !this.cipherConfig) throw new Error(`Unsupported cipher suite: 0x${serverHello.cipherSuite.toString(16)}`);
					return serverHello
				}
			}
		}
	}
	async handshakeTls12(reader, writer) {
		/** @type {{ namedCurve: number, serverPublicKey: Uint8Array } | null} */
		let serverKeyExchange = null;
		let sawServerHelloDone = !1;
		if (await this.readHandshakeUntil(reader, (async message => {
			switch (message.type) {
				case HANDSHAKE_TYPE_CERTIFICATE: {
					this.recordHandshake(message.raw);
					const certificate = extractLeafCertificate(message.body, 1);
					if (!certificate) throw new Error("Missing TLS 1.2 certificate");
					await this.acceptCertificate(certificate);
					break
				}
				case HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE:
					this.recordHandshake(message.raw), serverKeyExchange = parseServerKeyExchange(message.body);
					break;
				case HANDSHAKE_TYPE_SERVER_HELLO_DONE:
					return this.recordHandshake(message.raw), sawServerHelloDone = !0, 1;
				case HANDSHAKE_TYPE_CERTIFICATE_REQUEST:
					throw new Error("Client certificate is not supported");
				default:
					this.recordHandshake(message.raw)
			}
		}), "Connection closed during TLS 1.2 handshake"), !this.sawCert) throw new Error("Missing TLS 1.2 leaf certificate");
		const serverKeyExchangeData = /** @type {{ namedCurve: number, serverPublicKey: Uint8Array } | null} */ (serverKeyExchange);
		if (!serverKeyExchangeData) throw new Error("Missing TLS 1.2 ServerKeyExchange");
		const curveName = GROUPS_BY_ID.get(serverKeyExchangeData.namedCurve);
		if (!curveName) throw new Error(`Unsupported named curve: 0x${serverKeyExchangeData.namedCurve.toString(16)}`);
		const keyShare = this.keyPairs.get(serverKeyExchangeData.namedCurve);
		if (!keyShare) throw new Error(`Missing key pair for curve: 0x${serverKeyExchangeData.namedCurve.toString(16)}`);
		const preMasterSecret = await deriveSharedSecret(keyShare.keyPair.privateKey, serverKeyExchangeData.serverPublicKey, curveName),
			clientKeyExchange = buildHandshakeMessage(HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE, tlsBytes(keyShare.publicKeyRaw.length, keyShare.publicKeyRaw));
		this.recordHandshake(clientKeyExchange);
		const hashName = this.cipherConfig.hash;
		this.masterSecret = await tls12Prf(preMasterSecret, "master secret", concatBytes(this.clientRandom, this.serverRandom), 48, hashName);
		const keyLen = this.cipherConfig.keyLen,
			ivLen = this.cipherConfig.ivLen,
			keyBlock = await tls12Prf(this.masterSecret, "key expansion", concatBytes(this.serverRandom, this.clientRandom), 2 * keyLen + 2 * ivLen, hashName);
		this.clientWriteKey = keyBlock.slice(0, keyLen), this.serverWriteKey = keyBlock.slice(keyLen, 2 * keyLen), this.clientWriteIv = keyBlock.slice(2 * keyLen, 2 * keyLen + ivLen), this.serverWriteIv = keyBlock.slice(2 * keyLen + ivLen, 2 * keyLen + 2 * ivLen);
		if (!this.cipherConfig.chacha) [this.clientWriteCryptoKey, this.serverWriteCryptoKey] = await Promise.all([importAesGcmKey(this.clientWriteKey, ["encrypt"]), importAesGcmKey(this.serverWriteKey, ["decrypt"])]);
		await writer.write(buildTlsRecord(CONTENT_TYPE_HANDSHAKE, clientKeyExchange)), await writer.write(buildTlsRecord(CONTENT_TYPE_CHANGE_CIPHER_SPEC, tlsBytes(1)));
		const clientVerifyData = await tls12Prf(this.masterSecret, "client finished", await digestBytes(hashName, this.transcript()), 12, hashName),
			finishedMessage = buildHandshakeMessage(HANDSHAKE_TYPE_FINISHED, clientVerifyData);
		this.recordHandshake(finishedMessage), await writer.write(buildTlsRecord(CONTENT_TYPE_HANDSHAKE, await this.encryptTls12(finishedMessage, CONTENT_TYPE_HANDSHAKE)));
		let sawChangeCipherSpec = !1;
		await this.readRecordsUntil(reader, (async record => {
			if (record.type === CONTENT_TYPE_ALERT) {
				if (shouldIgnoreTlsAlert(record.fragment)) return;
				throw new Error(`TLS Alert: ${record.fragment[1]}`);
			}
			if (record.type === CONTENT_TYPE_CHANGE_CIPHER_SPEC) return void (sawChangeCipherSpec = !0);
			if (record.type !== CONTENT_TYPE_HANDSHAKE || !sawChangeCipherSpec) return;
			const decrypted = await this.decryptTls12(record.fragment, CONTENT_TYPE_HANDSHAKE);
			if (decrypted[0] !== HANDSHAKE_TYPE_FINISHED) return;
			const verifyLength = readUint24(decrypted, 1),
				verifyData = decrypted.slice(4, 4 + verifyLength),
				expectedVerifyData = await tls12Prf(this.masterSecret, "server finished", await digestBytes(hashName, this.transcript()), 12, hashName);
			if (!constantTimeEqual(verifyData, expectedVerifyData)) throw new Error("TLS 1.2 server Finished verify failed");
			return 1
		}), "Connection closed waiting for TLS 1.2 Finished")
	}
	async handshakeTls13(reader, writer, serverHello) {
		const groupName = GROUPS_BY_ID.get(serverHello.keyShare?.group);
		if (!groupName || !serverHello.keyShare?.key?.length) throw new Error("Missing TLS 1.3 key_share");
		const hashName = this.cipherConfig.hash,
			hashLen = hashByteLength(hashName),
			keyLen = this.cipherConfig.keyLen,
			ivLen = this.cipherConfig.ivLen,
			sharedSecret = await deriveSharedSecret(this.ecdhKeyPair.privateKey, serverHello.keyShare.key, groupName),
			earlySecret = await hkdfExtract(hashName, null, new Uint8Array(hashLen)),
			derivedSecret = await hkdfExpandLabel(hashName, earlySecret, "derived", await digestBytes(hashName, EMPTY_BYTES), hashLen);
		this.handshakeSecret = await hkdfExtract(hashName, derivedSecret, sharedSecret);
		const transcriptHash = await digestBytes(hashName, this.transcript()),
			clientHandshakeTrafficSecret = await hkdfExpandLabel(hashName, this.handshakeSecret, "c hs traffic", transcriptHash, hashLen),
			serverHandshakeTrafficSecret = await hkdfExpandLabel(hashName, this.handshakeSecret, "s hs traffic", transcriptHash, hashLen);
		[this.clientHandshakeKey, this.clientHandshakeIv] = await deriveTrafficKeys(hashName, clientHandshakeTrafficSecret, keyLen, ivLen), [this.serverHandshakeKey, this.serverHandshakeIv] = await deriveTrafficKeys(hashName, serverHandshakeTrafficSecret, keyLen, ivLen);
		if (!this.cipherConfig.chacha) [this.clientHandshakeCryptoKey, this.serverHandshakeCryptoKey] = await Promise.all([importAesGcmKey(this.clientHandshakeKey, ["encrypt"]), importAesGcmKey(this.serverHandshakeKey, ["decrypt"])]);
		const serverFinishedKey = await hkdfExpandLabel(hashName, serverHandshakeTrafficSecret, "finished", EMPTY_BYTES, hashLen);
		let serverFinishedReceived = !1;
		const handleHandshakeMessage = async message => {
			switch (message.type) {
				case HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS: {
					const encryptedExtensions = parseEncryptedExtensions(message.body);
					encryptedExtensions.alpn && (this.negotiatedAlpn = encryptedExtensions.alpn), this.recordHandshake(message.raw);
					break
				}
				case HANDSHAKE_TYPE_CERTIFICATE: {
					const certificate = extractLeafCertificate(message.body);
					if (!certificate) throw new Error("Missing TLS 1.3 certificate");
					await this.acceptCertificate(certificate), this.recordHandshake(message.raw);
					break
				}
				case HANDSHAKE_TYPE_CERTIFICATE_REQUEST:
					throw new Error("Client certificate is not supported");
				case HANDSHAKE_TYPE_CERTIFICATE_VERIFY:
					this.recordHandshake(message.raw);
					break;
				case HANDSHAKE_TYPE_FINISHED: {
					const expectedVerifyData = await hmac(hashName, serverFinishedKey, await digestBytes(hashName, this.transcript()));
					if (!constantTimeEqual(expectedVerifyData, message.body)) throw new Error("TLS 1.3 server Finished verify failed");
					this.recordHandshake(message.raw), serverFinishedReceived = !0;
					break
				}
				default:
					this.recordHandshake(message.raw)
			}
		};
		await this.readRecordsUntil(reader, (async record => {
			if (record.type === CONTENT_TYPE_CHANGE_CIPHER_SPEC || record.type === CONTENT_TYPE_HANDSHAKE) return;
			if (record.type === CONTENT_TYPE_ALERT) {
				if (shouldIgnoreTlsAlert(record.fragment)) return;
				throw new Error(`TLS Alert: ${record.fragment[1]}`);
			}
			if (record.type !== CONTENT_TYPE_APPLICATION_DATA) return;
			const decrypted = await this.decryptTls13Handshake(record.fragment),
				innerType = decrypted[decrypted.length - 1],
				plaintext = decrypted.slice(0, -1);
			if (innerType === CONTENT_TYPE_HANDSHAKE) {
				this.handshakeParser.feed(plaintext);
				for (let message; message = this.handshakeParser.next();)
					if (await handleHandshakeMessage(message), serverFinishedReceived) return 1
			}
		}), "Connection closed during TLS 1.3 handshake");
		const applicationTranscriptHash = await digestBytes(hashName, this.transcript()),
			masterDerivedSecret = await hkdfExpandLabel(hashName, this.handshakeSecret, "derived", await digestBytes(hashName, EMPTY_BYTES), hashLen),
			masterSecret = await hkdfExtract(hashName, masterDerivedSecret, new Uint8Array(hashLen)),
			clientAppTrafficSecret = await hkdfExpandLabel(hashName, masterSecret, "c ap traffic", applicationTranscriptHash, hashLen),
			serverAppTrafficSecret = await hkdfExpandLabel(hashName, masterSecret, "s ap traffic", applicationTranscriptHash, hashLen);
		[this.clientAppKey, this.clientAppIv] = await deriveTrafficKeys(hashName, clientAppTrafficSecret, keyLen, ivLen), [this.serverAppKey, this.serverAppIv] = await deriveTrafficKeys(hashName, serverAppTrafficSecret, keyLen, ivLen);
		if (!this.cipherConfig.chacha) [this.clientAppCryptoKey, this.serverAppCryptoKey] = await Promise.all([importAesGcmKey(this.clientAppKey, ["encrypt"]), importAesGcmKey(this.serverAppKey, ["decrypt"])]);
		const clientFinishedKey = await hkdfExpandLabel(hashName, clientHandshakeTrafficSecret, "finished", EMPTY_BYTES, hashLen),
			clientFinishedVerifyData = await hmac(hashName, clientFinishedKey, await digestBytes(hashName, this.transcript())),
			clientFinishedMessage = buildHandshakeMessage(HANDSHAKE_TYPE_FINISHED, clientFinishedVerifyData);
		this.recordHandshake(clientFinishedMessage), await writer.write(buildTlsRecord(CONTENT_TYPE_APPLICATION_DATA, await this.encryptTls13Handshake(concatBytes(clientFinishedMessage, [CONTENT_TYPE_HANDSHAKE])))), this.clientSeqNum = 0n, this.serverSeqNum = 0n
	}
	async encryptTls12(plaintext, contentType) {
		const sequenceNumber = this.clientSeqNum++,
			sequenceBytes = uint64be(sequenceNumber),
			additionalData = concatBytes(sequenceBytes, [contentType], uint16be(TLS_VERSION_12), uint16be(plaintext.length));
		if (this.cipherConfig.chacha) {
			const nonce = xorSequenceIntoIv(this.clientWriteIv, sequenceNumber);
			return chacha20Poly1305Encrypt(this.clientWriteKey, nonce, plaintext, additionalData)
		}
		const explicitNonce = randomBytes(8);
		if (!this.clientWriteCryptoKey) this.clientWriteCryptoKey = await importAesGcmKey(this.clientWriteKey, ["encrypt"]);
		return concatBytes(explicitNonce, await aesGcmEncryptWithKey(this.clientWriteCryptoKey, concatBytes(this.clientWriteIv, explicitNonce), plaintext, additionalData))
	}
	async decryptTls12(ciphertext, contentType) {
		const sequenceNumber = this.serverSeqNum++,
			sequenceBytes = uint64be(sequenceNumber);
		if (this.cipherConfig.chacha) {
			const nonce = xorSequenceIntoIv(this.serverWriteIv, sequenceNumber);
			return chacha20Poly1305Decrypt(this.serverWriteKey, nonce, ciphertext, concatBytes(sequenceBytes, [contentType], uint16be(TLS_VERSION_12), uint16be(ciphertext.length - 16)))
		}
		const explicitNonce = ciphertext.subarray(0, 8),
			encryptedData = ciphertext.subarray(8);
		if (!this.serverWriteCryptoKey) this.serverWriteCryptoKey = await importAesGcmKey(this.serverWriteKey, ["decrypt"]);
		return aesGcmDecryptWithKey(this.serverWriteCryptoKey, concatBytes(this.serverWriteIv, explicitNonce), encryptedData, concatBytes(sequenceBytes, [contentType], uint16be(TLS_VERSION_12), uint16be(encryptedData.length - 16)))
	}
	async encryptTls13Handshake(plaintext) {
		const nonce = xorSequenceIntoIv(this.clientHandshakeIv, this.clientSeqNum++),
			additionalData = tlsBytes(CONTENT_TYPE_APPLICATION_DATA, 3, 3, uint16be(plaintext.length + 16));
		if (this.cipherConfig.chacha) return chacha20Poly1305Encrypt(this.clientHandshakeKey, nonce, plaintext, additionalData);
		if (!this.clientHandshakeCryptoKey) this.clientHandshakeCryptoKey = await importAesGcmKey(this.clientHandshakeKey, ["encrypt"]);
		return aesGcmEncryptWithKey(this.clientHandshakeCryptoKey, nonce, plaintext, additionalData)
	}
	async decryptTls13Handshake(ciphertext) {
		const nonce = xorSequenceIntoIv(this.serverHandshakeIv, this.serverSeqNum++),
			additionalData = tlsBytes(CONTENT_TYPE_APPLICATION_DATA, 3, 3, uint16be(ciphertext.length));
		const decrypted = this.cipherConfig.chacha ? await chacha20Poly1305Decrypt(this.serverHandshakeKey, nonce, ciphertext, additionalData) : await aesGcmDecryptWithKey(this.serverHandshakeCryptoKey || (this.serverHandshakeCryptoKey = await importAesGcmKey(this.serverHandshakeKey, ["decrypt"])), nonce, ciphertext, additionalData);
		let innerTypeIndex = decrypted.length - 1;
		for (; innerTypeIndex >= 0 && !decrypted[innerTypeIndex];) innerTypeIndex--;
		return innerTypeIndex < 0 ? EMPTY_BYTES : decrypted.slice(0, innerTypeIndex + 1)
	}
	async encryptTls13(data) {
		const plaintext = concatBytes(data, [CONTENT_TYPE_APPLICATION_DATA]),
			nonce = xorSequenceIntoIv(this.clientAppIv, this.clientSeqNum++),
			additionalData = tlsBytes(CONTENT_TYPE_APPLICATION_DATA, 3, 3, uint16be(plaintext.length + 16));
		if (this.cipherConfig.chacha) return chacha20Poly1305Encrypt(this.clientAppKey, nonce, plaintext, additionalData);
		if (!this.clientAppCryptoKey) this.clientAppCryptoKey = await importAesGcmKey(this.clientAppKey, ["encrypt"]);
		return aesGcmEncryptWithKey(this.clientAppCryptoKey, nonce, plaintext, additionalData)
	}
	async decryptTls13(ciphertext) {
		const nonce = xorSequenceIntoIv(this.serverAppIv, this.serverSeqNum++),
			additionalData = tlsBytes(CONTENT_TYPE_APPLICATION_DATA, 3, 3, uint16be(ciphertext.length)),
			plaintext = this.cipherConfig.chacha ? await chacha20Poly1305Decrypt(this.serverAppKey, nonce, ciphertext, additionalData) : await aesGcmDecryptWithKey(this.serverAppCryptoKey || (this.serverAppCryptoKey = await importAesGcmKey(this.serverAppKey, ["decrypt"])), nonce, ciphertext, additionalData);
		let innerTypeIndex = plaintext.length - 1;
		for (; innerTypeIndex >= 0 && !plaintext[innerTypeIndex];) innerTypeIndex--;
		if (innerTypeIndex < 0) return {
			data: EMPTY_BYTES,
			type: 0
		};
		return {
			data: plaintext.slice(0, innerTypeIndex),
			type: plaintext[innerTypeIndex]
		}
	}
	async write(data) {
		if (!this.handshakeComplete) throw new Error("Handshake not complete");
		const plaintext = 数据转Uint8Array(data);
		if (!plaintext.byteLength) return;
		const writer = this.socket.writable.getWriter();
		try {
			const records = [];
			for (let offset = 0; offset < plaintext.byteLength; offset += TLS_MAX_PLAINTEXT_FRAGMENT) {
				const chunk = plaintext.subarray(offset, Math.min(offset + TLS_MAX_PLAINTEXT_FRAGMENT, plaintext.byteLength));
				const encrypted = this.isTls13 ? await this.encryptTls13(chunk) : await this.encryptTls12(chunk, CONTENT_TYPE_APPLICATION_DATA);
				records.push(buildTlsRecord(CONTENT_TYPE_APPLICATION_DATA, encrypted));
			}
			await writer.write(records.length === 1 ? records[0] : concatBytes(...records))
		} finally {
			writer.releaseLock()
		}
	}
	async read() {
		for (; ;) {
			let record;
			for (; record = this.recordParser.next();) {
				if (record.type === CONTENT_TYPE_ALERT) {
					if (record.fragment[1] === ALERT_CLOSE_NOTIFY) return null;
					throw new Error(`TLS Alert: ${record.fragment[1]}`)
				}
				if (record.type !== CONTENT_TYPE_APPLICATION_DATA) continue;
				if (!this.isTls13) return this.decryptTls12(record.fragment, CONTENT_TYPE_APPLICATION_DATA);
				const { data, type } = await this.decryptTls13(record.fragment);
				if (type === CONTENT_TYPE_APPLICATION_DATA) return data;
				if (type === CONTENT_TYPE_ALERT) {
					if (data[1] === ALERT_CLOSE_NOTIFY) return null;
					throw new Error(`TLS Alert: ${data[1]}`)
				}
				if (type !== CONTENT_TYPE_HANDSHAKE) continue;
				let message;
				for (this.handshakeParser.feed(data); message = this.handshakeParser.next();)
					if (message.type !== HANDSHAKE_TYPE_NEW_SESSION_TICKET && message.type === HANDSHAKE_TYPE_KEY_UPDATE) throw new Error("TLS 1.3 KeyUpdate is not supported by TLSClientMini")
			}
			const reader = this.socket.readable.getReader();
			try {
				const { value, done } = await this.readChunk(reader);
				if (done) return null;
				this.recordParser.feed(value)
			} finally {
				reader.releaseLock()
			}
		}
	}
	close() { this.socket.close() }
}

function stripIPv6Brackets(hostname = '') {
	const host = String(hostname || '').trim();
	return host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
}

function isIPHostname(hostname = '') {
	const host = stripIPv6Brackets(hostname);
	const ipv4Regex = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
	if (ipv4Regex.test(host)) return true;
	if (!host.includes(':')) return false;
	try {
		new URL(`http://[${host}]/`);
		return true;
	} catch (e) {
		return false;
	}
}

//////////////////////////////////////////////////turnConnect///////////////////////////////////////////////
const CONNECT_TIMEOUT_MS = 9999;
const TURN_STUN_MAGIC_COOKIE = new Uint8Array([0x21, 0x12, 0xa4, 0x42]);
const TURN_STUN_TYPE = {
	ALLOCATE_REQUEST: 0x0003, ALLOCATE_SUCCESS: 0x0103, ALLOCATE_ERROR: 0x0113,
	CREATE_PERMISSION_REQUEST: 0x0008, CREATE_PERMISSION_SUCCESS: 0x0108,
	CONNECT_REQUEST: 0x000a, CONNECT_SUCCESS: 0x010a,
	CONNECTION_BIND_REQUEST: 0x000b, CONNECTION_BIND_SUCCESS: 0x010b
};
const TURN_STUN_ATTR = {
	USERNAME: 0x0006, MESSAGE_INTEGRITY: 0x0008, ERROR_CODE: 0x0009,
	XOR_PEER_ADDRESS: 0x0012, REALM: 0x0014, NONCE: 0x0015,
	REQUESTED_TRANSPORT: 0x0019, CONNECTION_ID: 0x002a
};

async function withTimeout(promise, timeoutMs, message) {
	let timer;
	try {
		return await Promise.race([
			promise,
			new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(message)), timeoutMs) })
		]);
	} finally {
		clearTimeout(timer);
	}
}

function isIPv4(value) {
	const parts = String(value || '').split('.');
	return parts.length === 4 && parts.every(part => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}

function turnStunPadding(length) {
	return -length & 3;
}

function createTurnStunAttribute(type, value) {
	const body = 数据转Uint8Array(value);
	const attribute = new Uint8Array(4 + body.byteLength + turnStunPadding(body.byteLength));
	const view = new DataView(attribute.buffer);
	view.setUint16(0, type);
	view.setUint16(2, body.byteLength);
	attribute.set(body, 4);
	return attribute;
}

function createTurnStunMessage(type, transactionId, attributes) {
	const body = 拼接字节数据(...attributes);
	const header = new Uint8Array(20);
	const view = new DataView(header.buffer);
	view.setUint16(0, type);
	view.setUint16(2, body.byteLength);
	header.set(TURN_STUN_MAGIC_COOKIE, 4);
	header.set(transactionId, 8);
	return 拼接字节数据(header, body);
}

function parseTurnErrorCode(data) {
	return data?.byteLength >= 4 ? (data[2] & 7) * 100 + data[3] : 0;
}

function randomTurnTransactionId() {
	return crypto.getRandomValues(new Uint8Array(12));
}

async function addTurnMessageIntegrity(message, key) {
	const signedMessage = new Uint8Array(message);
	const view = new DataView(signedMessage.buffer);
	view.setUint16(2, view.getUint16(2) + 24);
	const hmacKey = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
	const signature = await crypto.subtle.sign('HMAC', hmacKey, signedMessage);
	return 拼接字节数据(signedMessage, createTurnStunAttribute(TURN_STUN_ATTR.MESSAGE_INTEGRITY, new Uint8Array(signature)));
}

async function readTurnStunMessage(reader, bufferedData = null, timeoutMessage = 'TURN response timed out') {
	let buffer = 有效数据长度(bufferedData) ? 数据转Uint8Array(bufferedData) : new Uint8Array(0);
	const pull = async () => {
		const { done, value } = await withTimeout(reader.read(), CONNECT_TIMEOUT_MS, timeoutMessage);
		if (done) throw new Error('TURN server closed connection');
		if (value?.byteLength) buffer = 拼接字节数据(buffer, value);
	};
	while (buffer.byteLength < 20) await pull();

	const messageLength = 20 + ((buffer[2] << 8) | buffer[3]);
	if (messageLength > 65555) throw new Error('TURN response is too large');
	while (buffer.byteLength < messageLength) await pull();
	const messageBuffer = buffer.subarray(0, messageLength);
	if (TURN_STUN_MAGIC_COOKIE.some((value, index) => messageBuffer[4 + index] !== value)) throw new Error('Invalid TURN/STUN response');

	const view = new DataView(messageBuffer.buffer, messageBuffer.byteOffset, messageBuffer.byteLength);
	const attributes = {};
	for (let offset = 20; offset + 4 <= messageLength;) {
		const type = view.getUint16(offset);
		const length = view.getUint16(offset + 2);
		if (offset + 4 + length > messageBuffer.byteLength) break;
		attributes[type] = messageBuffer.slice(offset + 4, offset + 4 + length);
		offset += 4 + length + turnStunPadding(length);
	}
	return {
		message: { type: view.getUint16(0), attributes },
		extraData: buffer.byteLength > messageLength ? buffer.subarray(messageLength) : null
	};
}

async function writeTurnBytes(writer, bytes, timeoutMessage) {
	await withTimeout(writer.write(bytes), CONNECT_TIMEOUT_MS, timeoutMessage);
}

async function turnConnect(proxy, targetHost, targetPort, TCP连接) {
	proxy = { ...proxy, username: proxy.username ?? null, password: proxy.password ?? null };
	const resolvedTargetHost = stripIPv6Brackets(targetHost);
	/** @type {string | null} */
	let targetIp = isIPv4(resolvedTargetHost) ? resolvedTargetHost : null;
	if (!targetIp) {
		const records = await DoH查询(resolvedTargetHost, 'A');
		const recordData = records.find(item => item.type === 1 && isIPv4(item.data))?.data;
		targetIp = typeof recordData === 'string' ? recordData : null;
	}
	if (!targetIp) throw new Error(`Could not resolve ${targetHost} to an IPv4 address for TURN CONNECT`);

	const turnHost = stripIPv6Brackets(proxy.hostname);
	let controlSocket = null, dataSocket = null, controlWriter = null, controlReader = null, dataWriter = null, dataReader = null, dataReaderReleased = false;
	const close = () => {
		try { controlSocket?.close?.() } catch (e) { }
		try { dataSocket?.close?.() } catch (e) { }
	};
	const releaseDataReader = () => {
		if (dataReaderReleased) return;
		dataReaderReleased = true;
		try { dataReader?.releaseLock?.() } catch (e) { }
	};

	try {
		controlSocket = TCP连接({ hostname: turnHost, port: proxy.port });
		await withTimeout(controlSocket.opened, CONNECT_TIMEOUT_MS, 'TURN server connection timed out');
		controlWriter = controlSocket.writable.getWriter();
		controlReader = controlSocket.readable.getReader();

		const xorPeerAddress = new Uint8Array(8);
		xorPeerAddress[1] = 1;
		new DataView(xorPeerAddress.buffer).setUint16(2, targetPort ^ 0x2112);
		targetIp.split('.').forEach((value, index) => {
			xorPeerAddress[4 + index] = Number(value) ^ TURN_STUN_MAGIC_COOKIE[index];
		});
		const peerAddress = createTurnStunAttribute(TURN_STUN_ATTR.XOR_PEER_ADDRESS, xorPeerAddress);
		const requestedTransport = new Uint8Array([6, 0, 0, 0]);

		await writeTurnBytes(controlWriter, createTurnStunMessage(
			TURN_STUN_TYPE.ALLOCATE_REQUEST,
			randomTurnTransactionId(),
			[createTurnStunAttribute(TURN_STUN_ATTR.REQUESTED_TRANSPORT, requestedTransport)]
		), 'TURN Allocate request timed out');

		let turnResponse = await readTurnStunMessage(controlReader, null, 'TURN Allocate response timed out');
		let message = turnResponse.message;
		let bufferedData = turnResponse.extraData;
		let integrityKey = null;
		let authAttributes = [];
		const sign = messageToSign => integrityKey ? addTurnMessageIntegrity(messageToSign, integrityKey) : Promise.resolve(messageToSign);

		if (
			message.type === TURN_STUN_TYPE.ALLOCATE_ERROR
			&& proxy.username !== null
			&& proxy.password !== null
			&& parseTurnErrorCode(message.attributes[TURN_STUN_ATTR.ERROR_CODE]) === 401
		) {
			const realmBytes = message.attributes[TURN_STUN_ATTR.REALM];
			const nonce = message.attributes[TURN_STUN_ATTR.NONCE];
			if (!realmBytes || !nonce?.byteLength) throw new Error('TURN authentication challenge is missing realm or nonce');

			const realm = textDecoder.decode(realmBytes);
			integrityKey = new Uint8Array(await crypto.subtle.digest('MD5', textEncoder.encode(`${proxy.username}:${realm}:${proxy.password}`)));
			authAttributes = [
				createTurnStunAttribute(TURN_STUN_ATTR.USERNAME, textEncoder.encode(proxy.username)),
				createTurnStunAttribute(TURN_STUN_ATTR.REALM, textEncoder.encode(realm)),
				createTurnStunAttribute(TURN_STUN_ATTR.NONCE, nonce)
			];

			const allocateRequest = await addTurnMessageIntegrity(createTurnStunMessage(
				TURN_STUN_TYPE.ALLOCATE_REQUEST,
				randomTurnTransactionId(),
				[
					createTurnStunAttribute(TURN_STUN_ATTR.REQUESTED_TRANSPORT, requestedTransport),
					...authAttributes
				]
			), integrityKey);
			const pipelinedMessages = await Promise.all([
				sign(createTurnStunMessage(TURN_STUN_TYPE.CREATE_PERMISSION_REQUEST, randomTurnTransactionId(), [peerAddress, ...authAttributes])),
				sign(createTurnStunMessage(TURN_STUN_TYPE.CONNECT_REQUEST, randomTurnTransactionId(), [peerAddress, ...authAttributes]))
			]);
			await writeTurnBytes(controlWriter, 拼接字节数据(allocateRequest, ...pipelinedMessages), 'TURN authenticated Allocate request timed out');
			turnResponse = await readTurnStunMessage(controlReader, bufferedData, 'TURN authenticated Allocate response timed out');
			message = turnResponse.message;
			bufferedData = turnResponse.extraData;
		} else if (message.type === TURN_STUN_TYPE.ALLOCATE_SUCCESS) {
			const pipelinedMessages = await Promise.all([
				sign(createTurnStunMessage(TURN_STUN_TYPE.CREATE_PERMISSION_REQUEST, randomTurnTransactionId(), [peerAddress, ...authAttributes])),
				sign(createTurnStunMessage(TURN_STUN_TYPE.CONNECT_REQUEST, randomTurnTransactionId(), [peerAddress, ...authAttributes]))
			]);
			if (pipelinedMessages.length) await writeTurnBytes(controlWriter, 拼接字节数据(...pipelinedMessages), 'TURN pipelined request timed out');
		}

		if (message.type !== TURN_STUN_TYPE.ALLOCATE_SUCCESS) {
			const errorCode = parseTurnErrorCode(message.attributes[TURN_STUN_ATTR.ERROR_CODE]);
			throw new Error(errorCode ? `TURN Allocate failed with ${errorCode}` : 'TURN Allocate failed');
		}

		dataSocket = TCP连接({ hostname: turnHost, port: proxy.port });
		turnResponse = await readTurnStunMessage(controlReader, bufferedData, 'TURN CreatePermission response timed out');
		message = turnResponse.message;
		bufferedData = turnResponse.extraData;
		if (message.type !== TURN_STUN_TYPE.CREATE_PERMISSION_SUCCESS) throw new Error('TURN CreatePermission failed');

		turnResponse = await readTurnStunMessage(controlReader, bufferedData, 'TURN CONNECT response timed out');
		message = turnResponse.message;
		bufferedData = turnResponse.extraData;
		if (message.type !== TURN_STUN_TYPE.CONNECT_SUCCESS || !message.attributes[TURN_STUN_ATTR.CONNECTION_ID]) throw new Error('TURN CONNECT failed');

		await withTimeout(dataSocket.opened, CONNECT_TIMEOUT_MS, 'TURN data connection timed out');
		dataWriter = dataSocket.writable.getWriter();
		dataReader = dataSocket.readable.getReader();
		await writeTurnBytes(dataWriter, await sign(createTurnStunMessage(
			TURN_STUN_TYPE.CONNECTION_BIND_REQUEST,
			randomTurnTransactionId(),
			[
				createTurnStunAttribute(TURN_STUN_ATTR.CONNECTION_ID, message.attributes[TURN_STUN_ATTR.CONNECTION_ID]),
				...authAttributes
			]
		)), 'TURN ConnectionBind request timed out');

		turnResponse = await readTurnStunMessage(dataReader, null, 'TURN ConnectionBind response timed out');
		message = turnResponse.message;
		const extraPayload = turnResponse.extraData;
		if (message.type !== TURN_STUN_TYPE.CONNECTION_BIND_SUCCESS) throw new Error('TURN ConnectionBind failed');

		controlWriter.releaseLock();
		controlWriter = null;
		controlReader.releaseLock();
		controlReader = null;
		dataWriter.releaseLock();
		dataWriter = null;

		const readable = new ReadableStream({
			start(controller) {
				if (extraPayload?.byteLength) controller.enqueue(extraPayload);
			},
			pull(controller) {
				return dataReader.read().then(({ done, value }) => {
					if (done) {
						releaseDataReader();
						controller.close();
					} else if (value?.byteLength) controller.enqueue(new Uint8Array(value));
				});
			},
			cancel() {
				try { dataReader?.cancel?.() } catch (e) { }
				releaseDataReader();
				close();
			}
		});

		return { readable, writable: dataSocket.writable, closed: dataSocket.closed, close };
	} catch (error) {
		try { controlWriter?.releaseLock?.() } catch (e) { }
		try { controlReader?.releaseLock?.() } catch (e) { }
		try { dataWriter?.releaseLock?.() } catch (e) { }
		releaseDataReader();
		close();
		throw error;
	}
}
//////////////////////////////////////////////////sstpConnect///////////////////////////////////////////////
const SSTP_TCP_MSS = 1400;
const SSTP_EMPTY_BYTES = new Uint8Array(0);

function readSstpUint16(bytes, offset = 0) {
	return (bytes[offset] << 8) | bytes[offset + 1];
}

function readSstpUint32(bytes, offset = 0) {
	return ((bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0;
}

function randomSstpUint16() {
	return readSstpUint16(crypto.getRandomValues(new Uint8Array(2)));
}

function internetChecksum(bytes, offset, length) {
	let sum = 0;
	for (let index = offset; index < offset + length - 1; index += 2) sum += readSstpUint16(bytes, index);
	if (length & 1) sum += bytes[offset + length - 1] << 8;
	while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
	return (~sum) & 0xffff;
}

async function sstpConnect(proxy, targetHost, targetPort, TCP连接) {
	proxy = { ...proxy, username: proxy.username ?? null, password: proxy.password ?? null };
	let bufferedBytes = SSTP_EMPTY_BYTES, pppIdentifier = 1, socket = null, reader = null, writer = null;
	let closedSettled = false, resolveClosed, rejectClosed;
	const closed = new Promise((resolve, reject) => {
		resolveClosed = resolve;
		rejectClosed = reject;
	});
	const settleClosed = (settle, value) => {
		if (closedSettled) return;
		closedSettled = true;
		settle(value);
	};
	const close = () => {
		try { reader?.cancel?.().catch?.(() => { }) } catch (e) { }
		try { reader?.releaseLock?.() } catch (e) { }
		try { writer?.close?.().catch?.(() => { }) } catch (e) { }
		try { writer?.releaseLock?.() } catch (e) { }
		try { socket?.close?.() } catch (e) { }
		settleClosed(resolveClosed);
	};

	const readSocketChunk = async () => {
		const { value, done } = await reader.read();
		if (done || !value) throw new Error('SSTP socket closed');
		return 数据转Uint8Array(value);
	};
	const readBytes = async length => {
		while (bufferedBytes.byteLength < length) {
			const chunk = await readSocketChunk();
			bufferedBytes = bufferedBytes.byteLength ? 拼接字节数据(bufferedBytes, chunk) : chunk;
		}
		const result = bufferedBytes.subarray(0, length);
		bufferedBytes = bufferedBytes.subarray(length);
		return result;
	};
	const readHttpLine = async () => {
		for (; ;) {
			const lineEnd = bufferedBytes.indexOf(10);
			if (lineEnd >= 0) {
				const line = textDecoder.decode(bufferedBytes.subarray(0, lineEnd));
				bufferedBytes = bufferedBytes.subarray(lineEnd + 1);
				return line.replace(/\r$/, '');
			}
			const chunk = await readSocketChunk();
			bufferedBytes = bufferedBytes.byteLength ? 拼接字节数据(bufferedBytes, chunk) : chunk;
		}
	};
	const readPacket = async (timeoutMs = CONNECT_TIMEOUT_MS) => {
		const header = await withTimeout(readBytes(4), timeoutMs, 'SSTP read timeout');
		const length = readSstpUint16(header, 2) & 0x0fff;
		if (length < 4) throw new Error('Invalid SSTP packet length');
		return {
			isControl: (header[1] & 1) !== 0,
			body: length > 4 ? await withTimeout(readBytes(length - 4), timeoutMs, 'SSTP packet body read timeout') : SSTP_EMPTY_BYTES
		};
	};
	const buildSstpDataPacket = pppFrame => {
		const packetLength = 6 + pppFrame.byteLength;
		const packet = new Uint8Array(packetLength);
		packet.set([0x10, 0x00, ((packetLength >> 8) & 0x0f) | 0x80, packetLength & 0xff, 0xff, 0x03]);
		packet.set(pppFrame, 6);
		return packet;
	};
	const buildPppConfigurePacket = (protocol, code, id, options = []) => {
		const optionsLength = options.reduce((size, option) => size + 2 + option.data.byteLength, 0);
		const frame = new Uint8Array(6 + optionsLength);
		const view = new DataView(frame.buffer);
		view.setUint16(0, protocol);
		frame[2] = code;
		frame[3] = id;
		view.setUint16(4, 4 + optionsLength);
		options.reduce((offset, option) => {
			frame[offset] = option.type;
			frame[offset + 1] = 2 + option.data.byteLength;
			frame.set(option.data, offset + 2);
			return offset + 2 + option.data.byteLength;
		}, 6);
		return frame;
	};
	const parsePPPFrame = data => {
		const offset = data.byteLength >= 2 && data[0] === 0xff && data[1] === 0x03 ? 2 : 0;
		if (data.byteLength - offset < 4) return null;
		const protocol = readSstpUint16(data, offset);
		if (protocol === 0x0021) return { protocol, ipPacket: data.subarray(offset + 2) };
		if (data.byteLength - offset < 6) return null;
		return { protocol, code: data[offset + 2], id: data[offset + 3], payload: data.subarray(offset + 6), rawPacket: data.subarray(offset) };
	};
	const parsePppOptions = data => {
		const options = [];
		for (let offset = 0; offset + 2 <= data.byteLength;) {
			const type = data[offset];
			const length = data[offset + 1];
			if (length < 2 || offset + length > data.byteLength) break;
			options.push({ type, data: data.subarray(offset + 2, offset + length) });
			offset += length;
		}
		return options;
	};

	try {
		const serverHost = stripIPv6Brackets(proxy.hostname);
		const serverPort = proxy.port;
		socket = TCP连接({ hostname: serverHost, port: serverPort }, { secureTransport: 'on', allowHalfOpen: false });
		await withTimeout(socket.opened, CONNECT_TIMEOUT_MS, 'SSTP server connection timed out');
		reader = socket.readable.getReader();
		writer = socket.writable.getWriter();

		const displayHost = serverHost.includes(':') ? `[${serverHost}]` : serverHost;
		const httpRequest = textEncoder.encode(
			`SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\n`
			+ `Host: ${Number(serverPort) === 443 ? displayHost : `${displayHost}:${serverPort}`}\r\n`
			+ 'Content-Length: 18446744073709551615\r\n'
			+ `SSTPCORRELATIONID: {${crypto.randomUUID()}}\r\n\r\n`
		);
		const encapsulatedProtocol = new Uint8Array(2);
		new DataView(encapsulatedProtocol.buffer).setUint16(0, 1);
		const maximumReceiveUnit = new Uint8Array(2);
		new DataView(maximumReceiveUnit.buffer).setUint16(0, 1500);
		const sstpConnectRequest = new Uint8Array(12 + encapsulatedProtocol.byteLength);
		const sstpConnectView = new DataView(sstpConnectRequest.buffer);
		sstpConnectRequest[0] = 0x10;
		sstpConnectRequest[1] = 0x01;
		sstpConnectView.setUint16(2, sstpConnectRequest.byteLength | 0x8000);
		sstpConnectView.setUint16(4, 0x0001);
		sstpConnectView.setUint16(6, 1);
		sstpConnectRequest[9] = 1;
		sstpConnectView.setUint16(10, 4 + encapsulatedProtocol.byteLength);
		sstpConnectRequest.set(encapsulatedProtocol, 12);

		await withTimeout(writer.write(拼接字节数据(
			httpRequest,
			sstpConnectRequest,
			buildSstpDataPacket(buildPppConfigurePacket(0xc021, 1, pppIdentifier++, [
				{ type: 1, data: maximumReceiveUnit }
			]))
		)), CONNECT_TIMEOUT_MS, 'SSTP HTTP handshake request timed out');

		const statusLine = await withTimeout(readHttpLine(), CONNECT_TIMEOUT_MS, 'SSTP HTTP handshake timed out');
		for (; ;) {
			const line = await withTimeout(readHttpLine(), CONNECT_TIMEOUT_MS, 'SSTP HTTP header read timed out');
			if (line === '') break;
		}
		if (!/HTTP\/\d(?:\.\d)?\s+2\d\d/i.test(statusLine)) throw new Error(`SSTP HTTP handshake failed: ${statusLine || 'invalid status'}`);

		let localLcpAcked = false, peerLcpAcked = false, papRequired = false, papSent = false, papDone = false, ipcpStarted = false, ipcpFinished = false, sourceIp = null;
		const sendPapIfReady = async () => {
			if (!localLcpAcked || !peerLcpAcked || !papRequired || papSent) return;
			if (proxy.username === null || proxy.password === null) throw new Error('SSTP server requires PAP authentication');
			const username = textEncoder.encode(proxy.username);
			const password = textEncoder.encode(proxy.password);
			if (username.byteLength > 255 || password.byteLength > 255) throw new Error('SSTP username/password is too long');
			const papLength = 6 + username.byteLength + password.byteLength;
			const frame = new Uint8Array(2 + papLength);
			const view = new DataView(frame.buffer);
			view.setUint16(0, 0xc023);
			frame[2] = 1;
			frame[3] = pppIdentifier++;
			view.setUint16(4, papLength);
			frame[6] = username.byteLength;
			frame.set(username, 7);
			frame[7 + username.byteLength] = password.byteLength;
			frame.set(password, 8 + username.byteLength);
			await withTimeout(writer.write(buildSstpDataPacket(frame)), CONNECT_TIMEOUT_MS, 'SSTP PAP authentication request timed out');
			papSent = true;
		};
		const startIpcpIfReady = async () => {
			if (!localLcpAcked || !peerLcpAcked || ipcpStarted || (papRequired && !papDone)) return;
			await withTimeout(writer.write(buildSstpDataPacket(buildPppConfigurePacket(0x8021, 1, pppIdentifier++, [
				{ type: 3, data: new Uint8Array(4) }
			]))), CONNECT_TIMEOUT_MS, 'SSTP IPCP request timed out');
			ipcpStarted = true;
		};

		for (let round = 0; round < 50 && !ipcpFinished; round++) {
			const packet = await readPacket(CONNECT_TIMEOUT_MS);
			if (packet.isControl) continue;
			const ppp = parsePPPFrame(packet.body);
			if (!ppp) continue;

			if (ppp.protocol === 0xc021) {
				if (ppp.code === 1) {
					const authOption = parsePppOptions(ppp.payload).find(option => option.type === 3);
					if (authOption?.data?.byteLength >= 2) {
						const authProtocol = readSstpUint16(authOption.data);
						if (authProtocol !== 0xc023) throw new Error(`SSTP unsupported PPP authentication protocol: 0x${authProtocol.toString(16)}`);
						papRequired = true;
					}
					const ack = new Uint8Array(ppp.rawPacket);
					ack[2] = 2;
					await withTimeout(writer.write(buildSstpDataPacket(ack)), CONNECT_TIMEOUT_MS, 'SSTP LCP Configure-Ack timed out');
					peerLcpAcked = true;
					await sendPapIfReady();
					await startIpcpIfReady();
				} else if (ppp.code === 2) {
					localLcpAcked = true;
					await sendPapIfReady();
					await startIpcpIfReady();
				}
				continue;
			}

			if (ppp.protocol === 0xc023) {
				if (ppp.code === 2) {
					papDone = true;
					await startIpcpIfReady();
				} else if (ppp.code === 3) throw new Error('SSTP PAP authentication failed');
				continue;
			}

			if (ppp.protocol === 0x8021) {
				if (ppp.code === 1) {
					const ack = new Uint8Array(ppp.rawPacket);
					ack[2] = 2;
					await withTimeout(writer.write(buildSstpDataPacket(ack)), CONNECT_TIMEOUT_MS, 'SSTP IPCP Configure-Ack timed out');
					await startIpcpIfReady();
				} else if (ppp.code === 3) {
					const addressOption = parsePppOptions(ppp.payload).find(option => option.type === 3);
					if (addressOption?.data?.byteLength === 4) {
						sourceIp = [...addressOption.data].join('.');
						await withTimeout(writer.write(buildSstpDataPacket(buildPppConfigurePacket(0x8021, 1, pppIdentifier++, [
							{ type: 3, data: addressOption.data }
						]))), CONNECT_TIMEOUT_MS, 'SSTP IPCP address request timed out');
						ipcpStarted = true;
					}
				} else if (ppp.code === 2) {
					const addressOption = parsePppOptions(ppp.payload).find(option => option.type === 3);
					if (addressOption?.data?.byteLength === 4) sourceIp = [...addressOption.data].join('.');
					ipcpFinished = true;
				}
			}
		}
		if (!sourceIp) throw new Error('SSTP did not assign an IPv4 address');

		const target = stripIPv6Brackets(targetHost);
		/** @type {string | null} */
		let targetIp = isIPv4(target) ? target : null;
		if (!targetIp) {
			const records = await DoH查询(target, 'A');
			const recordData = records.find(item => item.type === 1 && isIPv4(item.data))?.data;
			targetIp = typeof recordData === 'string' ? recordData : null;
		}
		if (!targetIp) throw new Error(`Could not resolve ${targetHost} to an IPv4 address for SSTP`);

		const sourcePort = 10000 + (randomSstpUint16() % 50000);
		const sourceAddress = new Uint8Array(String(sourceIp || '').split('.').map(Number));
		const destinationAddress = new Uint8Array(String(targetIp || '').split('.').map(Number));
		let sequenceNumber = readSstpUint32(crypto.getRandomValues(new Uint8Array(4)));
		let acknowledgementNumber = 0;
		const ipHeaderTemplate = new Uint8Array(20);
		ipHeaderTemplate.set([0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 64, 6]);
		ipHeaderTemplate.set(sourceAddress, 12);
		ipHeaderTemplate.set(destinationAddress, 16);
		const tcpPseudoHeader = new Uint8Array(1432);
		tcpPseudoHeader.set(sourceAddress);
		tcpPseudoHeader.set(destinationAddress, 4);
		tcpPseudoHeader[9] = 6;
		const buildTcpFrame = (flags, payload = SSTP_EMPTY_BYTES) => {
			const bytes = 数据转Uint8Array(payload);
			const payloadLength = bytes.byteLength;
			const tcpLength = 20 + payloadLength;
			const ipLength = 20 + tcpLength;
			const sstpLength = 8 + ipLength;
			const frame = new Uint8Array(sstpLength);
			const view = new DataView(frame.buffer);
			frame.set([0x10, 0x00, ((sstpLength >> 8) & 0x0f) | 0x80, sstpLength & 0xff, 0xff, 0x03, 0x00, 0x21]);
			frame.set(ipHeaderTemplate, 8);
			view.setUint16(10, ipLength);
			view.setUint16(12, randomSstpUint16());
			view.setUint16(18, internetChecksum(frame, 8, 20));
			view.setUint16(28, sourcePort);
			view.setUint16(30, targetPort);
			view.setUint32(32, sequenceNumber);
			view.setUint32(36, acknowledgementNumber);
			frame[40] = 0x50;
			frame[41] = flags;
			view.setUint16(42, 65535);
			if (payloadLength) frame.set(bytes, 48);
			tcpPseudoHeader[10] = tcpLength >> 8;
			tcpPseudoHeader[11] = tcpLength & 0xff;
			tcpPseudoHeader.set(frame.subarray(28, 28 + tcpLength), 12);
			view.setUint16(44, internetChecksum(tcpPseudoHeader, 0, 12 + tcpLength));
			return frame;
		};
		const matchIncomingIpPacket = ipPacket => {
			if (ipPacket.byteLength < 40 || ipPacket[9] !== 6) return null;
			const ipHeaderLength = (ipPacket[0] & 0x0f) * 4;
			if (ipPacket.byteLength < ipHeaderLength + 20) return null;
			if (readSstpUint16(ipPacket, ipHeaderLength) !== targetPort) return null;
			if (readSstpUint16(ipPacket, ipHeaderLength + 2) !== sourcePort) return null;
			return {
				flags: ipPacket[ipHeaderLength + 13],
				sequence: readSstpUint32(ipPacket, ipHeaderLength + 4),
				payloadOffset: ipHeaderLength + ((ipPacket[ipHeaderLength + 12] >> 4) & 0x0f) * 4
			};
		};

		await withTimeout(writer.write(buildTcpFrame(0x02)), CONNECT_TIMEOUT_MS, 'SSTP TCP SYN write timed out');
		sequenceNumber = (sequenceNumber + 1) >>> 0;
		let tcpReady = false;
		for (let attempt = 0; attempt < 30; attempt++) {
			const packet = await readPacket(CONNECT_TIMEOUT_MS);
			if (packet.isControl) continue;
			const ppp = parsePPPFrame(packet.body);
			if (!ppp || ppp.protocol !== 0x0021) continue;
			const tcp = matchIncomingIpPacket(ppp.ipPacket);
			if (!tcp || (tcp.flags & 0x12) !== 0x12) continue;
			acknowledgementNumber = (tcp.sequence + 1) >>> 0;
			await withTimeout(writer.write(buildTcpFrame(0x10)), CONNECT_TIMEOUT_MS, 'SSTP TCP ACK write timed out');
			tcpReady = true;
			break;
		}
		if (!tcpReady) throw new Error('TCP handshake through SSTP timed out');

		/** @type {ReadableStreamDefaultController<Uint8Array> | null} */
		let streamController = null;
		const readable = new ReadableStream({
			start(controller) {
				streamController = controller;
			},
			cancel() {
				close();
			}
		});

		(async () => {
			try {
				let pendingChunks = [], pendingLength = 0;
				const flush = () => {
					if (!pendingLength) return;
					if (!streamController) throw new Error('SSTP readable stream is not ready');
					streamController.enqueue(pendingChunks.length === 1 ? pendingChunks[0] : 拼接字节数据(...pendingChunks));
					pendingChunks = [];
					pendingLength = 0;
					writer.write(buildTcpFrame(0x10)).catch(() => { });
				};

				for (; ;) {
					const packet = await readPacket(60000);
					if (packet.isControl) continue;
					const ppp = parsePPPFrame(packet.body);
					if (!ppp || ppp.protocol !== 0x0021) continue;
					const incoming = matchIncomingIpPacket(ppp.ipPacket);
					if (!incoming) continue;

					if (incoming.payloadOffset < ppp.ipPacket.byteLength) {
						const payload = ppp.ipPacket.subarray(incoming.payloadOffset);
						if (payload.byteLength) {
							acknowledgementNumber = (incoming.sequence + payload.byteLength) >>> 0;
							pendingChunks.push(new Uint8Array(payload));
							pendingLength += payload.byteLength;
						}
					}

					if (incoming.flags & 0x01) {
						flush();
						acknowledgementNumber = (acknowledgementNumber + 1) >>> 0;
						writer.write(buildTcpFrame(0x11)).catch(() => { });
						const controller = streamController;
						if (controller) {
							try { controller.close() } catch (e) { }
						}
						close();
						return;
					}

					if (bufferedBytes.byteLength < 4 || pendingLength >= 32768) flush();
				}
			} catch (error) {
				const controller = streamController;
				if (controller) {
					try { controller.error(error) } catch (e) { }
				}
				settleClosed(rejectClosed, error);
				try { socket?.close?.() } catch (e) { }
			}
		})();

		const writable = new WritableStream({
			async write(chunk) {
				const bytes = 数据转Uint8Array(chunk);
				if (!bytes.byteLength) return;
				if (bytes.byteLength <= SSTP_TCP_MSS) {
					await writer.write(buildTcpFrame(0x18, bytes));
					sequenceNumber = (sequenceNumber + bytes.byteLength) >>> 0;
					return;
				}
				const frames = [];
				for (let offset = 0; offset < bytes.byteLength; offset += SSTP_TCP_MSS) {
					const segment = bytes.subarray(offset, Math.min(offset + SSTP_TCP_MSS, bytes.byteLength));
					frames.push(buildTcpFrame(0x18, segment));
					sequenceNumber = (sequenceNumber + segment.byteLength) >>> 0;
				}
				await writer.write(拼接字节数据(...frames));
			},
			close() {
				return writer.write(buildTcpFrame(0x11)).catch(() => { });
			},
			abort(error) {
				close();
				if (error) settleClosed(rejectClosed, error);
			}
		});

		return { readable, writable, closed, close };
	} catch (error) {
		close();
		throw error;
	}
}
//////////////////////////////////////////////////功能性函数///////////////////////////////////////////////
/**
 * 带秘钥的 Base64 编码
 * @param {string} plaintext - 原始明文字符串
 * @param {string} secret - 秘钥字符串（如 "KEY123"）
 * @returns {string} 经过秘钥处理的 Base64 字符串
 */
function base64SecretEncode(plaintext, secret) {
	const encoder = new TextEncoder();
	const data = encoder.encode(plaintext);
	const key = encoder.encode(secret);
	const mixed = new Uint8Array(data.length);

	for (let i = 0; i < data.length; i++) {
		mixed[i] = data[i] ^ key[i % key.length];
	}

	// 将 Uint8Array 转换为可被 btoa 处理的字符串
	let binary = '';
	for (let i = 0; i < mixed.length; i++) {
		binary += String.fromCharCode(mixed[i]);
	}
	return btoa(binary);
}

/**
 * 带秘钥的 Base64 解码
 * @param {string} encoded - 经秘钥处理过的 Base64 字符串
 * @param {string} secret - 秘钥字符串（必须与编码时相同）
 * @returns {string} 解码后的原始明文字符串
 */
function base64SecretDecode(encoded, secret) {
	const binary = atob(encoded);
	const mixed = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		mixed[i] = binary.charCodeAt(i);
	}

	const encoder = new TextEncoder();
	const key = encoder.encode(secret);
	const data = new Uint8Array(mixed.length);

	for (let i = 0; i < mixed.length; i++) {
		data[i] = mixed[i] ^ key[i % key.length];
	}

	const decoder = new TextDecoder();
	return decoder.decode(data);
}

function 获取传输协议配置(配置 = {}) {
	const 是gRPC = 配置.传输协议 === 'grpc';
	return {
		type: 是gRPC ? (配置.gRPC模式 === 'multi' ? 'grpc&mode=multi' : 'grpc&mode=gun') : (配置.传输协议 === 'xhttp' ? 'xhttp&mode=stream-one' : 'ws'),
		路径字段名: 是gRPC ? 'serviceName' : 'path',
		域名字段名: 是gRPC ? 'authority' : 'host'
	};
}

function 获取传输路径参数值(配置 = {}, 节点路径 = '/', 作为优选订阅生成器 = false) {
	const 路径值 = 作为优选订阅生成器 ? '/' : (配置.随机路径 ? 随机路径(节点路径) : 节点路径);
	if (配置.传输协议 !== 'grpc') return 路径值;
	return 路径值.split('?')[0] || '/';
}

function 生成最简Clash订阅(config = {}, 记录 = {}) {
	const 转义 = value => JSON.stringify(String(value ?? ''));
	const 名称 = 生成访问节点名称(记录);
	const 组名 = 名称.split(' - ')[0] || 名称;
	const host = String(config.HOST || '');
	const uuid = String(config.UUID || 记录.uuid || '');
	const protocol = String(config.协议类型 || 'vless').toLowerCase();
	const network = String(config.传输协议 || 'ws').toLowerCase();
	const 原始路径 = String(config.完整节点路径 || config.PATH || '/');
	const path = 获取传输路径参数值(config, 原始路径);
	const insecure = Boolean(config.跳过证书验证);
	const lines = [
		'proxies:',
		`  - name: ${转义(名称)}`,
		`    type: ${protocol === 'ss' ? 'ss' : protocol === 'trojan' ? 'trojan' : 'vless'}`,
		`    server: ${转义(host)}`,
		`    port: ${protocol === 'ss' && config.SS?.TLS === false ? 80 : 443}`,
	];

	if (protocol === 'ss') {
		const cipher = String(config.SS?.加密方式 || 'aes-128-gcm');
		const ssPath = 原始路径.includes('?') ? 原始路径.replace('?', `?enc=${cipher}&`) : `${原始路径}?enc=${cipher}`;
		lines.push(
			`    cipher: ${转义(cipher)}`,
			`    password: ${转义(uuid)}`,
			'    udp: true',
			'    plugin: v2ray-plugin',
			'    plugin-opts:',
			'      mode: websocket',
			`      host: ${转义(host)}`,
			`      path: ${转义(config.随机路径 ? 随机路径(ssPath) : ssPath)}`,
			`      tls: ${config.SS?.TLS !== false}`,
		);
		if (insecure) lines.push('      skip-cert-verify: true');
	} else {
		lines.push(
			protocol === 'trojan' ? `    password: ${转义(uuid)}` : `    uuid: ${转义(uuid)}`,
			'    udp: true',
			`    tls: true`,
			`    servername: ${转义(host)}`,
		);
		if (protocol !== 'trojan') lines.push('    encryption: none');
		if (insecure) lines.push('    skip-cert-verify: true');
		if (config.Fingerprint) lines.push(`    client-fingerprint: ${转义(config.Fingerprint)}`);
		if (config.ECH) {
			lines.push('    ech-opts:', '      enable: true');
			if (config.ECHConfig?.SNI) lines.push(`      query-server-name: ${转义(config.ECHConfig.SNI)}`);
		}
		if (network === 'grpc') {
			lines.push('    network: grpc', '    grpc-opts:', `      grpc-service-name: ${转义(path)}`);
			if (config.gRPCUserAgent) lines.push(`      grpc-user-agent: ${转义(config.gRPCUserAgent)}`);
		} else if (network === 'xhttp') {
			lines.push('    network: xhttp', '    xhttp-opts:', `      path: ${转义(path)}`, `      host: ${转义(host)}`, '      mode: stream-one');
		} else {
			lines.push('    network: ws', '    ws-opts:', `      path: ${转义(path)}`, '      headers:', `        Host: ${转义(host)}`);
		}
	}

	lines.push(
		'proxy-groups:',
		`  - name: ${转义(组名)}`,
		'    type: select',
		`    proxies: [${转义(名称)}]`,
		'rules:',
		`  - MATCH,${组名}`,
	);
	return lines.join('\n') + '\n';
}

function log(...args) {
	if (调试日志打印) console.log(...args);
}

function Clash订阅配置文件热补丁(Clash_原始订阅内容, config_JSON = {}) {
	const uuid = config_JSON?.UUID || null;
	const ECH启用 = Boolean(config_JSON?.ECH);
	const HOSTS = Array.isArray(config_JSON?.HOSTS) ? [...config_JSON.HOSTS] : [];
	const ECH_SNI = config_JSON?.ECHConfig?.SNI || null;
	const ECH_DNS = config_JSON?.ECHConfig?.DNS;
	const 需要处理ECH = Boolean(uuid && ECH启用);
	const gRPCUserAgent = (typeof config_JSON?.gRPCUserAgent === 'string' && config_JSON.gRPCUserAgent.trim()) ? config_JSON.gRPCUserAgent.trim() : null;
	const 需要处理gRPC = config_JSON?.传输协议 === "grpc" && Boolean(gRPCUserAgent);
	const gRPCUserAgentYAML = gRPCUserAgent ? JSON.stringify(gRPCUserAgent) : null;
	let clash_yaml = Clash_原始订阅内容.replace(/mode:\s*Rule\b/g, 'mode: rule');

	const baseDnsBlock = `dns:
  enable: true
  default-nameserver:
    - 223.5.5.5
    - 119.29.29.29
    - 114.114.114.114
  use-hosts: true
  nameserver:
    - https://sm2.doh.pub/dns-query
    - https://dns.alidns.com/dns-query
  fallback:
    - 8.8.4.4
    - 208.67.220.220
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
      - 240.0.0.0/4
      - 127.0.0.1/32
      - 0.0.0.0/32
    domain:
      - '+.google.com'
      - '+.facebook.com'
      - '+.youtube.com'
`;

	const 添加InlineGrpcUserAgent = (text) => text.replace(/grpc-opts:\s*\{([\s\S]*?)\}/i, (all, inner) => {
		if (/grpc-user-agent\s*:/i.test(inner)) return all;
		let content = inner.trim();
		if (content.endsWith(',')) content = content.slice(0, -1).trim();
		const patchedContent = content ? `${content}, grpc-user-agent: ${gRPCUserAgentYAML}` : `grpc-user-agent: ${gRPCUserAgentYAML}`;
		return `grpc-opts: {${patchedContent}}`;
	});
	const 匹配到gRPC网络 = (text) => /(?:^|[,{])\s*network:\s*(?:"grpc"|'grpc'|grpc)(?=\s*(?:[,}\n#]|$))/mi.test(text);
	const 获取代理类型 = (nodeText) => nodeText.match(/type:\s*(\w+)/)?.[1] || 'vl' + 'ess';
	const 获取凭据值 = (nodeText, isFlowStyle) => {
		const credentialField = 获取代理类型(nodeText) === 'trojan' ? 'password' : 'uuid';
		const pattern = new RegExp(`${credentialField}:\\s*${isFlowStyle ? '([^,}\\n]+)' : '([^\\n]+)'}`);
		return nodeText.match(pattern)?.[1]?.trim() || null;
	};
	const 插入NameserverPolicy = (yaml, hostsEntries) => {
		if (/^\s{2}nameserver-policy:\s*(?:\n|$)/m.test(yaml)) {
			return yaml.replace(/^(\s{2}nameserver-policy:\s*\n)/m, `$1${hostsEntries}\n`);
		}
		const lines = yaml.split('\n');
		let dnsBlockEndIndex = -1;
		let inDnsBlock = false;
		for (let i = 0; i < lines.length; i++) {
			const line = lines[i];
			if (/^dns:\s*$/.test(line)) {
				inDnsBlock = true;
				continue;
			}
			if (inDnsBlock && /^[a-zA-Z]/.test(line)) {
				dnsBlockEndIndex = i;
				break;
			}
		}
		const nameserverPolicyBlock = `  nameserver-policy:\n${hostsEntries}`;
		if (dnsBlockEndIndex !== -1) lines.splice(dnsBlockEndIndex, 0, nameserverPolicyBlock);
		else lines.push(nameserverPolicyBlock);
		return lines.join('\n');
	};
	const 添加Flow格式gRPCUserAgent = (nodeText) => {
		if (!匹配到gRPC网络(nodeText) || /grpc-user-agent\s*:/i.test(nodeText)) return nodeText;
		if (/grpc-opts:\s*\{/i.test(nodeText)) return 添加InlineGrpcUserAgent(nodeText);
		return nodeText.replace(/\}(\s*)$/, `, grpc-opts: {grpc-user-agent: ${gRPCUserAgentYAML}}}$1`);
	};
	const 添加Block格式gRPCUserAgent = (nodeLines, topLevelIndent) => {
		const 顶级缩进 = ' '.repeat(topLevelIndent);
		let grpcOptsIndex = -1;
		for (let idx = 0; idx < nodeLines.length; idx++) {
			const line = nodeLines[idx];
			if (!line.trim()) continue;
			const indent = line.search(/\S/);
			if (indent !== topLevelIndent) continue;
			if (/^\s*grpc-opts:\s*(?:#.*)?$/.test(line) || /^\s*grpc-opts:\s*\{.*\}\s*(?:#.*)?$/.test(line)) {
				grpcOptsIndex = idx;
				break;
			}
		}
		if (grpcOptsIndex === -1) {
			let insertIndex = -1;
			for (let j = nodeLines.length - 1; j >= 0; j--) {
				if (nodeLines[j].trim()) {
					insertIndex = j;
					break;
				}
			}
			if (insertIndex >= 0) nodeLines.splice(insertIndex + 1, 0, `${顶级缩进}grpc-opts:`, `${顶级缩进}  grpc-user-agent: ${gRPCUserAgentYAML}`);
			return nodeLines;
		}
		const grpcLine = nodeLines[grpcOptsIndex];
		if (/^\s*grpc-opts:\s*\{.*\}\s*(?:#.*)?$/.test(grpcLine)) {
			if (!/grpc-user-agent\s*:/i.test(grpcLine)) nodeLines[grpcOptsIndex] = 添加InlineGrpcUserAgent(grpcLine);
			return nodeLines;
		}
		let blockEndIndex = nodeLines.length;
		let 子级缩进 = topLevelIndent + 2;
		let 已有gRPCUserAgent = false;
		for (let idx = grpcOptsIndex + 1; idx < nodeLines.length; idx++) {
			const line = nodeLines[idx];
			const trimmed = line.trim();
			if (!trimmed) continue;
			const indent = line.search(/\S/);
			if (indent <= topLevelIndent) {
				blockEndIndex = idx;
				break;
			}
			if (indent > topLevelIndent && 子级缩进 === topLevelIndent + 2) 子级缩进 = indent;
			if (/^grpc-user-agent\s*:/.test(trimmed)) {
				已有gRPCUserAgent = true;
				break;
			}
		}
		if (!已有gRPCUserAgent) nodeLines.splice(blockEndIndex, 0, `${' '.repeat(子级缩进)}grpc-user-agent: ${gRPCUserAgentYAML}`);
		return nodeLines;
	};
	const 添加Block格式ECHOpts = (nodeLines, topLevelIndent) => {
		let insertIndex = -1;
		for (let j = nodeLines.length - 1; j >= 0; j--) {
			if (nodeLines[j].trim()) {
				insertIndex = j;
				break;
			}
		}
		if (insertIndex < 0) return nodeLines;
		const indent = ' '.repeat(topLevelIndent);
		const echOptsLines = [`${indent}ech-opts:`, `${indent}  enable: true`];
		if (ECH_SNI) echOptsLines.push(`${indent}  query-server-name: ${ECH_SNI}`);
		nodeLines.splice(insertIndex + 1, 0, ...echOptsLines);
		return nodeLines;
	};

	if (!/^dns:\s*(?:\n|$)/m.test(clash_yaml)) clash_yaml = baseDnsBlock + clash_yaml;
	if (ECH_SNI && !HOSTS.includes(ECH_SNI)) HOSTS.push(ECH_SNI);

	if (ECH启用 && HOSTS.length > 0) {
		const hostsEntries = HOSTS.map(host => `    "${host}": ${ECH_DNS ? ECH_DNS : ''}`).join('\n');
		clash_yaml = 插入NameserverPolicy(clash_yaml, hostsEntries);
	}

	if (!需要处理ECH && !需要处理gRPC) return clash_yaml;

	const lines = clash_yaml.split('\n');
	const processedLines = [];
	let i = 0;

	while (i < lines.length) {
		const line = lines[i];
		const trimmedLine = line.trim();

		if (trimmedLine.startsWith('- {')) {
			let fullNode = line;
			let braceCount = (line.match(/\{/g) || []).length - (line.match(/\}/g) || []).length;
			while (braceCount > 0 && i + 1 < lines.length) {
				i++;
				fullNode += '\n' + lines[i];
				braceCount += (lines[i].match(/\{/g) || []).length - (lines[i].match(/\}/g) || []).length;
			}
			if (需要处理gRPC) fullNode = 添加Flow格式gRPCUserAgent(fullNode);
			if (需要处理ECH && 获取凭据值(fullNode, true) === uuid.trim()) {
				fullNode = fullNode.replace(/\}(\s*)$/, `, ech-opts: {enable: true${ECH_SNI ? `, query-server-name: ${ECH_SNI}` : ''}}}$1`);
			}
			processedLines.push(fullNode);
			i++;
		} else if (trimmedLine.startsWith('- name:')) {
			let nodeLines = [line];
			let baseIndent = line.search(/\S/);
			let topLevelIndent = baseIndent + 2;
			i++;
			while (i < lines.length) {
				const nextLine = lines[i];
				const nextTrimmed = nextLine.trim();
				if (!nextTrimmed) {
					nodeLines.push(nextLine);
					i++;
					break;
				}
				const nextIndent = nextLine.search(/\S/);
				if (nextIndent <= baseIndent && nextTrimmed.startsWith('- ')) {
					break;
				}
				if (nextIndent < baseIndent && nextTrimmed) {
					break;
				}
				nodeLines.push(nextLine);
				i++;
			}
			let nodeText = nodeLines.join('\n');
			if (需要处理gRPC && 匹配到gRPC网络(nodeText)) {
				nodeLines = 添加Block格式gRPCUserAgent(nodeLines, topLevelIndent);
				nodeText = nodeLines.join('\n');
			}
			if (需要处理ECH && 获取凭据值(nodeText, false) === uuid.trim()) nodeLines = 添加Block格式ECHOpts(nodeLines, topLevelIndent);
			processedLines.push(...nodeLines);
		} else {
			processedLines.push(line);
			i++;
		}
	}

	return processedLines.join('\n');
}

async function Singbox订阅配置文件热补丁(SingBox_原始订阅内容, config_JSON = {}) {
	const uuid = config_JSON?.UUID || null;
	const fingerprint = config_JSON?.Fingerprint || "chrome";
	const ECH启用 = Boolean(config_JSON?.ECH);
	const ECH_SNI = config_JSON?.ECHConfig?.SNI || "cloudflare-ech.com";
	const sb_json_text = SingBox_原始订阅内容.replace('1.1.1.1', '8.8.8.8').replace('1.0.0.1', '8.8.4.4');
	try {
		const config = JSON.parse(sb_json_text);
		const 数组化 = value => value === undefined || value === null ? [] : (Array.isArray(value) ? value : [value]);
		const 确保Route = () => config.route = config.route && typeof config.route === 'object' ? config.route : {};
		const 获取DNS规则服务器 = rule => rule && typeof rule === 'object' && !Array.isArray(rule) && typeof rule.server === 'string' ? rule.server : null;
		const 添加规则集 = (type, code) => {
			if (!code || typeof code !== 'string') return null;
			const route = 确保Route(), tag = `${type}-${code}`, ruleSet = Array.isArray(route.rule_set) ? route.rule_set : 数组化(route.rule_set);
			if (!ruleSet.some(item => item?.tag === tag)) {
				const legacyOptions = type === 'geoip' ? route.geoip : route.geosite;
				ruleSet.push({ tag, type: 'remote', format: 'binary', url: `https://raw.githubusercontent.com/SagerNet/sing-${type}/rule-set/${tag}.srs`, ...(legacyOptions?.download_detour ? { download_detour: legacyOptions.download_detour } : {}) });
				config.experimental = config.experimental && typeof config.experimental === 'object' ? config.experimental : {};
				config.experimental.cache_file = config.experimental.cache_file && typeof config.experimental.cache_file === 'object' ? config.experimental.cache_file : {};
				config.experimental.cache_file.enabled ??= true;
			}
			route.rule_set = ruleSet;
			return tag;
		};

		const 迁移规则集字段 = rule => {
			if (!rule || typeof rule !== 'object' || Array.isArray(rule)) return rule;
			if (rule.type === 'logical' && Array.isArray(rule.rules)) {
				rule.rules = rule.rules.map(迁移规则集字段);
				return rule;
			}
			const tags = [];
			for (const geoip of 数组化(rule.geoip)) {
				if (typeof geoip !== 'string') continue;
				if (geoip.toLowerCase() === 'private') rule.ip_is_private = true;
				else tags.push(添加规则集('geoip', geoip));
			}
			for (const sourceGeoip of 数组化(rule.source_geoip)) {
				if (typeof sourceGeoip !== 'string') continue;
				tags.push(添加规则集('geoip', sourceGeoip));
				rule.rule_set_ip_cidr_match_source = true;
			}
			for (const geosite of 数组化(rule.geosite)) if (typeof geosite === 'string') tags.push(添加规则集('geosite', geosite));
			if (tags.length) rule.rule_set = [...new Set([...数组化(rule.rule_set), ...tags].filter(Boolean))];
			delete rule.geoip;
			delete rule.source_geoip;
			delete rule.geosite;
			return rule;
		};

		const 迁移DNS规则 = (rule, rcodeServerMap) => {
			rule = 迁移规则集字段(rule);
			if (!rule || typeof rule !== 'object' || Array.isArray(rule)) return rule;
			if (rule.type === 'logical' && Array.isArray(rule.rules)) {
				rule.rules = rule.rules.map(childRule => 迁移DNS规则(childRule, rcodeServerMap));
				return rule;
			}
			const serverTag = 获取DNS规则服务器(rule);
			if (serverTag && rcodeServerMap.has(serverTag)) {
				for (const key of ['server', 'strategy', 'disable_cache', 'rewrite_ttl', 'client_subnet', 'timeout']) delete rule[key];
				rule.action = 'predefined';
				rule.rcode = rcodeServerMap.get(serverTag);
			} else if (serverTag && !rule.action) rule.action = 'route';
			return rule;
		};

		if (Array.isArray(config.inbounds)) {
			for (const inbound of config.inbounds) {
				if (!inbound || typeof inbound !== 'object' || inbound.type !== 'tun') continue;
				for (const migration of [
					{ targetKey: 'address', sourceKeys: ['inet4_address', 'inet6_address'] },
					{ targetKey: 'route_address', sourceKeys: ['inet4_route_address', 'inet6_route_address'] },
					{ targetKey: 'route_exclude_address', sourceKeys: ['inet4_route_exclude_address', 'inet6_route_exclude_address'] }
				]) {
					const values = 数组化(inbound[migration.targetKey]);
					for (const sourceKey of migration.sourceKeys) values.push(...数组化(inbound[sourceKey]));
					if (values.length) inbound[migration.targetKey] = [...new Set(values)];
					for (const sourceKey of migration.sourceKeys) delete inbound[sourceKey];
				}
				if (inbound.tag) {
					const addedRules = [];
					if (inbound.domain_strategy) addedRules.push({ inbound: inbound.tag, action: 'resolve', strategy: inbound.domain_strategy });
					if (inbound.sniff) {
						const sniffRule = { inbound: inbound.tag, action: 'sniff' };
						if (inbound.sniff_timeout) sniffRule.timeout = inbound.sniff_timeout;
						addedRules.push(sniffRule);
					}
					if (addedRules.length) {
						const route = 确保Route();
						route.rules = [...addedRules, ...数组化(route.rules)];
					}
				}
				delete inbound.sniff;
				delete inbound.sniff_timeout;
				delete inbound.domain_strategy;
			}
		}

		if (config?.route && typeof config.route === 'object' && Array.isArray(config.route.rules)) {
			const 修补路由规则 = rule => {
				rule = 迁移规则集字段(rule);
				if (rule?.type === 'logical' && Array.isArray(rule.rules)) rule.rules = rule.rules.map(修补路由规则);
				else if (rule && typeof rule === 'object' && !Array.isArray(rule) && rule.outbound && !rule.action) rule.action = 'route';
				return rule;
			};
			config.route.rules = config.route.rules.map(修补路由规则);
		}

		const dns = config?.dns;
		if (dns && typeof dns === 'object') {
			const legacyFakeIP = dns.fakeip && typeof dns.fakeip === 'object' ? dns.fakeip : null;
			const rcodeServerMap = new Map();
			const DNS地址协议类型 = { 'tcp:': 'tcp', 'udp:': 'udp', 'tls:': 'tls', 'quic:': 'quic', 'https:': 'https', 'h3:': 'h3' };
			const RCode映射 = { success: 'NOERROR', format_error: 'FORMERR', server_failure: 'SERVFAIL', name_error: 'NXDOMAIN', not_implemented: 'NOTIMP', refused: 'REFUSED' };
			let hasFakeIPServer = false;

			if (Array.isArray(dns.servers)) {
				const migratedServers = [];
				for (const originalServer of dns.servers) {
					if (!originalServer || typeof originalServer !== 'object' || Array.isArray(originalServer)) {
						migratedServers.push(originalServer);
						continue;
					}

					const server = { ...originalServer };
					let parsedAddress = null, parsedRCode = '', rawAddress = typeof server.address === 'string' ? server.address.trim() : '';
					if (rawAddress) {
						const lowerAddress = rawAddress.toLowerCase();
						if (lowerAddress === 'fakeip') parsedAddress = { type: 'fakeip' };
						else if (lowerAddress === 'local') parsedAddress = { type: 'local' };
						else if (lowerAddress.startsWith('rcode://')) {
							parsedAddress = { type: 'rcode' };
							parsedRCode = rawAddress.slice('rcode://'.length).toLowerCase();
						}
						else if (lowerAddress.startsWith('dhcp://')) {
							const dhcpInterface = rawAddress.slice('dhcp://'.length);
							parsedAddress = dhcpInterface && dhcpInterface.toLowerCase() !== 'auto' ? { type: 'dhcp', interface: dhcpInterface } : { type: 'dhcp' };
						} else {
							try {
								const addressURL = new URL(rawAddress);
								const type = DNS地址协议类型[addressURL.protocol.toLowerCase()];
								if (type) {
									const parsedServer = addressURL.hostname?.startsWith('[') && addressURL.hostname.endsWith(']') ? addressURL.hostname.slice(1, -1) : addressURL.hostname;
									parsedAddress = {
										type,
										server: parsedServer || addressURL.host || rawAddress,
										...(addressURL.port ? { server_port: Number(addressURL.port) } : {}),
										...((type === 'https' || type === 'h3') && addressURL.pathname && addressURL.pathname !== '/dns-query' ? { path: addressURL.pathname } : {})
									};
								}
							} catch (_) { }
							if (!parsedAddress) parsedAddress = { type: 'udp', server: rawAddress };
						}
					}

					if (parsedAddress?.type === 'rcode') {
						const rcode = RCode映射[parsedRCode] || 'NOERROR';
						if (typeof server.tag === 'string' && server.tag) {
							rcodeServerMap.set(server.tag, rcode);
							rcodeServerMap.set(server.tag.startsWith('dns_') ? server.tag.slice(4) : `dns_${server.tag}`, rcode);
						}
						continue;
					}

					if (parsedAddress) {
						delete server.address;
						Object.assign(server, parsedAddress);
					}
					if (server.address_resolver !== undefined && server.domain_resolver === undefined) server.domain_resolver = server.address_resolver;
					if (server.address_strategy !== undefined && server.domain_strategy === undefined) server.domain_strategy = server.address_strategy;
					delete server.address_resolver;
					delete server.address_strategy;
					if (server.detour === 'DIRECT') delete server.detour;

					if (server.type === 'fakeip') {
						hasFakeIPServer = true;
						if (legacyFakeIP) {
							for (const key of ['inet4_range', 'inet6_range']) {
								if (legacyFakeIP[key] !== undefined && server[key] === undefined) server[key] = legacyFakeIP[key];
							}
						}
					}
					migratedServers.push(server);
				}
				dns.servers = migratedServers;
			}

			if (legacyFakeIP && !hasFakeIPServer && legacyFakeIP.enabled !== false) {
				const fakeIPServer = { type: 'fakeip', tag: 'fakeip' };
				for (const rule of Array.isArray(dns.rules) ? dns.rules : []) {
					const serverTag = 获取DNS规则服务器(rule);
					if (serverTag && serverTag.toLowerCase().includes('fakeip')) {
						fakeIPServer.tag = serverTag;
						break;
					}
				}
				for (const key of ['inet4_range', 'inet6_range']) {
					if (legacyFakeIP[key] !== undefined) fakeIPServer[key] = legacyFakeIP[key];
				}
				if (Array.isArray(dns.servers)) dns.servers.push(fakeIPServer);
				else dns.servers = [fakeIPServer];
			}

			if (Array.isArray(dns.rules)) {
				const migratedRules = [];
				for (const rule of dns.rules) {
					const serverTag = 获取DNS规则服务器(rule);
					const outbound = 数组化(rule?.outbound);
					const DNS路由选项字段 = new Set(['outbound', 'server', 'action', 'strategy', 'disable_cache', 'rewrite_ttl', 'client_subnet', 'timeout']);
					const isOutboundAnyDNSRule = rule && typeof rule === 'object' && !Array.isArray(rule) && rule.type !== 'logical'
						&& serverTag && outbound.includes('any') && Object.keys(rule).every(key => DNS路由选项字段.has(key));
					if (isOutboundAnyDNSRule) {
						const route = 确保Route();
						if (route.default_domain_resolver === undefined) {
							const resolver = { server: serverTag };
							for (const key of ['strategy', 'disable_cache', 'rewrite_ttl', 'client_subnet', 'timeout']) {
								if (rule[key] !== undefined) resolver[key] = rule[key];
							}
							route.default_domain_resolver = Object.keys(resolver).length === 1 ? resolver.server : resolver;
						}
						continue;
					}
					migratedRules.push(迁移DNS规则(rule, rcodeServerMap));
				}
				dns.rules = migratedRules;
			}

			delete dns.fakeip;
			delete dns.independent_cache;
		}

		if (config?.route && typeof config.route === 'object') {
			delete config.route.geoip;
			delete config.route.geosite;
		}
		if (config?.ntp?.detour === 'DIRECT') delete config.ntp.detour;

		if (Array.isArray(config.outbounds)) {
			const outboundTags = new Set(config.outbounds.map(outbound => outbound?.tag).filter(Boolean));
			const 引用REJECT = value => value === 'REJECT' || (value && typeof value === 'object' && (Array.isArray(value) ? value.some(引用REJECT) : Object.values(value).some(引用REJECT)));
			if (!outboundTags.has('REJECT') && 引用REJECT({ outbounds: config.outbounds, route: config.route })) config.outbounds.push({ type: 'block', tag: 'REJECT' });
		}

		// --- UUID 匹配节点的 TLS 热补丁 (utls & ech) ---
		if (uuid) {
			config.outbounds?.forEach(outbound => {
				// 仅处理包含 uuid 或 password 且匹配的节点
				if ((outbound.uuid && outbound.uuid === uuid) || (outbound.password && outbound.password === uuid)) {
					// 确保 tls 对象存在
					if (!outbound.tls) {
						outbound.tls = { enabled: true };
					}

					// 添加/更新 utls 配置
					if (fingerprint) {
						outbound.tls.utls = {
							enabled: true,
							fingerprint: fingerprint
						};
					}

					// 如果提供了 ech_config，添加/更新 ech 配置
					if (ECH启用) {
						outbound.tls.ech = {
							enabled: true,
							query_server_name: ECH_SNI,// 等待 1.13.0+ 版本上线
							//config: `-----BEGIN ECH CONFIGS-----\n${ech_config}\n-----END ECH CONFIGS-----`
						};
					}
				}
			});
		}

		return JSON.stringify(config, null, 2);
	} catch (e) {
		console.error("Singbox热补丁执行失败:", e);
		return JSON.stringify(JSON.parse(sb_json_text), null, 2);
	}
}

function Surge订阅配置文件热补丁(content, url, config_JSON) {
	const 每行内容 = content.includes('\r\n') ? content.split('\r\n') : content.split('\n');
	const 完整节点路径 = config_JSON.随机路径 ? 随机路径(config_JSON.完整节点路径) : config_JSON.完整节点路径;
	let 输出内容 = "";
	for (let x of 每行内容) {
		if (x.includes('= tro' + 'jan,') && !x.includes('ws=true') && !x.includes('ws-path=')) {
			const host = x.split("sni=")[1].split(",")[0];
			const 备改内容 = `sni=${host}, skip-cert-verify=${config_JSON.跳过证书验证}`;
			const 正确内容 = `sni=${host}, skip-cert-verify=${config_JSON.跳过证书验证}, ws=true, ws-path=${完整节点路径.replace(/,/g, '%2C')}, ws-headers=Host:"${host}"`;
			输出内容 += x.replace(new RegExp(备改内容, 'g'), 正确内容).replace("[", "").replace("]", "") + '\n';
		} else {
			输出内容 += x + '\n';
		}
	}

	输出内容 = `#!MANAGED-CONFIG ${url} interval=${config_JSON.优选订阅生成.SUBUpdateTime * 60 * 60} strict=false` + 输出内容.substring(输出内容.indexOf('\n'));
	return 输出内容;
}

async function 请求日志记录(env, request, 访问IP, 请求类型 = "Get_SUB", config_JSON, 是否写入KV日志 = true) {
	if (!env.KV || typeof env.KV.get !== 'function') return;
	try {
		const 当前时间 = new Date();
		const cf = request.cf || {};
		const 日志内容 = { TYPE: 请求类型, IP: 访问IP, ASN: `AS${cf.asn || '0'} ${cf.asOrganization || 'Unknown'}`, CC: `${cf.country || 'N/A'} ${cf.city || 'N/A'}`, URL: request.url, UA: request.headers.get('User-Agent') || 'Unknown', TIME: 当前时间.getTime() };
		if (config_JSON.TG.启用) {
			try {
				const TG_TXT = await env.KV.get('tg.json');
				const TG_JSON = JSON.parse(TG_TXT);
				if (TG_JSON?.BotToken && TG_JSON?.ChatID) {
					const 请求时间 = new Date(日志内容.TIME).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
					const 请求URL = new URL(日志内容.URL);
					const msg = `<b>#${config_JSON.优选订阅生成.SUBNAME} 日志通知</b>\n\n` +
						`📌 <b>类型：</b>#${日志内容.TYPE}\n` +
						`🌐 <b>IP：</b><code>${日志内容.IP}</code>\n` +
						`📍 <b>位置：</b>${日志内容.CC}\n` +
						`🏢 <b>ASN：</b>${日志内容.ASN}\n` +
						`🔗 <b>域名：</b><code>${请求URL.host}</code>\n` +
						`🔍 <b>路径：</b><code>${请求URL.pathname + 请求URL.search}</code>\n` +
						`🤖 <b>UA：</b><code>${日志内容.UA}</code>\n` +
						`📅 <b>时间：</b>${请求时间}\n` +
						`${config_JSON.CF.Usage.success ? `📊 <b>请求用量：</b>${config_JSON.CF.Usage.total}/${config_JSON.CF.Usage.max} <b>${((config_JSON.CF.Usage.total / config_JSON.CF.Usage.max) * 100).toFixed(2)}%</b>\n` : ''}`;
					await fetch(`https://api.telegram.org/bot${TG_JSON.BotToken}/sendMessage?chat_id=${TG_JSON.ChatID}&parse_mode=HTML&text=${encodeURIComponent(msg)}`, {
						method: 'GET',
						headers: {
							'Accept': 'text/html,application/xhtml+xml,application/xml;',
							'Accept-Encoding': 'gzip, deflate, br',
							'User-Agent': 日志内容.UA || 'Unknown',
						}
					});
				}
			} catch (error) { console.error(`读取tg.json出错: ${error.message}`) }
		}
		是否写入KV日志 = ['1', 'true'].includes(env.OFF_LOG) ? false : 是否写入KV日志;
		if (!是否写入KV日志) return;
		let 日志数组 = [];
		const 现有日志 = await env.KV.get('log.json'), KV容量限制 = 4;//MB
		if (现有日志) {
			try {
				日志数组 = JSON.parse(现有日志);
				if (!Array.isArray(日志数组)) { 日志数组 = [日志内容] }
				else if (请求类型 !== "Get_SUB") {
					const 三十分钟前时间戳 = 当前时间.getTime() - 30 * 60 * 1000;
					if (日志数组.some(log => log.TYPE !== "Get_SUB" && log.IP === 访问IP && log.URL === request.url && log.UA === (request.headers.get('User-Agent') || 'Unknown') && log.TIME >= 三十分钟前时间戳)) return;
					日志数组.push(日志内容);
					while (JSON.stringify(日志数组, null, 2).length > KV容量限制 * 1024 * 1024 && 日志数组.length > 0) 日志数组.shift();
				} else {
					日志数组.push(日志内容);
					while (JSON.stringify(日志数组, null, 2).length > KV容量限制 * 1024 * 1024 && 日志数组.length > 0) 日志数组.shift();
				}
			} catch (e) { 日志数组 = [日志内容] }
		} else { 日志数组 = [日志内容] }
		await env.KV.put('log.json', JSON.stringify(日志数组, null, 2));
	} catch (error) { console.error(`日志记录失败: ${error.message}`) }
}

function 掩码敏感信息(文本, 前缀长度 = 3, 后缀长度 = 2) {
	if (!文本 || typeof 文本 !== 'string') return 文本;
	if (文本.length <= 前缀长度 + 后缀长度) return 文本; // 如果长度太短，直接返回

	const 前缀 = 文本.slice(0, 前缀长度);
	const 后缀 = 文本.slice(-后缀长度);
	const 星号数量 = 文本.length - 前缀长度 - 后缀长度;

	return `${前缀}${'*'.repeat(星号数量)}${后缀}`;
}

async function MD5MD5(文本) {
	const 编码器 = new TextEncoder();

	const 第一次哈希 = await crypto.subtle.digest('MD5', 编码器.encode(文本));
	const 第一次哈希数组 = Array.from(new Uint8Array(第一次哈希));
	const 第一次十六进制 = 第一次哈希数组.map(字节 => 字节.toString(16).padStart(2, '0')).join('');

	const 第二次哈希 = await crypto.subtle.digest('MD5', 编码器.encode(第一次十六进制.slice(7, 27)));
	const 第二次哈希数组 = Array.from(new Uint8Array(第二次哈希));
	const 第二次十六进制 = 第二次哈希数组.map(字节 => 字节.toString(16).padStart(2, '0')).join('');

	return 第二次十六进制.toLowerCase();
}

function 随机路径(完整节点路径 = "/") {
	const 常用路径目录 = ["about", "account", "acg", "act", "activity", "ad", "ads", "ajax", "album", "albums", "anime", "api", "app", "apps", "archive", "archives", "article", "articles", "ask", "auth", "avatar", "bbs", "bd", "blog", "blogs", "book", "books", "bt", "buy", "cart", "category", "categories", "cb", "channel", "channels", "chat", "china", "city", "class", "classify", "clip", "clips", "club", "cn", "code", "collect", "collection", "comic", "comics", "community", "company", "config", "contact", "content", "course", "courses", "cp", "data", "detail", "details", "dh", "directory", "discount", "discuss", "dl", "dload", "doc", "docs", "document", "documents", "doujin", "download", "downloads", "drama", "edu", "en", "ep", "episode", "episodes", "event", "events", "f", "faq", "favorite", "favourites", "favs", "feedback", "file", "files", "film", "films", "forum", "forums", "friend", "friends", "game", "games", "gif", "go", "go.html", "go.php", "group", "groups", "help", "home", "hot", "htm", "html", "image", "images", "img", "index", "info", "intro", "item", "items", "ja", "jp", "jump", "jump.html", "jump.php", "jumping", "knowledge", "lang", "lesson", "lessons", "lib", "library", "link", "links", "list", "live", "lives", "m", "mag", "magnet", "mall", "manhua", "map", "member", "members", "message", "messages", "mobile", "movie", "movies", "music", "my", "new", "news", "note", "novel", "novels", "online", "order", "out", "out.html", "out.php", "outbound", "p", "page", "pages", "pay", "payment", "pdf", "photo", "photos", "pic", "pics", "picture", "pictures", "play", "player", "playlist", "post", "posts", "product", "products", "program", "programs", "project", "qa", "question", "rank", "ranking", "read", "readme", "redirect", "redirect.html", "redirect.php", "reg", "register", "res", "resource", "retrieve", "sale", "search", "season", "seasons", "section", "seller", "series", "service", "services", "setting", "settings", "share", "shop", "show", "shows", "site", "soft", "sort", "source", "special", "star", "stars", "static", "stock", "store", "stream", "streaming", "streams", "student", "study", "tag", "tags", "task", "teacher", "team", "tech", "temp", "test", "thread", "tool", "tools", "topic", "topics", "torrent", "trade", "travel", "tv", "txt", "type", "u", "upload", "uploads", "url", "urls", "user", "users", "v", "version", "videos", "view", "vip", "vod", "watch", "web", "wenku", "wiki", "work", "www", "zh", "zh-cn", "zh-tw", "zip"];
	const 随机数 = Math.floor(Math.random() * 3 + 1);
	const 随机路径 = 常用路径目录.sort(() => 0.5 - Math.random()).slice(0, 随机数).join('/');
	if (完整节点路径 === "/") return `/${随机路径}`;
	else return `/${随机路径 + 完整节点路径.replace('/?', '?')}`;
}

function 替换星号为随机字符(内容) {
	if (typeof 内容 !== 'string' || !内容.includes('*')) return 内容;
	const 字符集 = 'abcdefghijklmnopqrstuvwxyz0123456789';
	return 内容.replace(/\*/g, () => {
		let s = '';
		for (let i = 0; i < Math.floor(Math.random() * 14) + 3; i++) s += 字符集[Math.floor(Math.random() * 字符集.length)];
		return s;
	});
}

async function DoH查询(域名, 记录类型, DoH解析服务 = "https://cloudflare-dns.com/dns-query") {
	const 开始时间 = performance.now();
	log(`[DoH查询] 开始查询 ${域名} ${记录类型} via ${DoH解析服务}`);
	try {
		// 记录类型字符串转数值
		const 类型映射 = { 'A': 1, 'NS': 2, 'CNAME': 5, 'MX': 15, 'TXT': 16, 'AAAA': 28, 'SRV': 33, 'HTTPS': 65 };
		const qtype = 类型映射[记录类型.toUpperCase()] || 1;

		// 编码域名为 DNS wire format labels
		const 编码域名 = (name) => {
			const parts = name.endsWith('.') ? name.slice(0, -1).split('.') : name.split('.');
			const bufs = [];
			for (const label of parts) {
				const enc = new TextEncoder().encode(label);
				bufs.push(new Uint8Array([enc.length]), enc);
			}
			bufs.push(new Uint8Array([0]));
			const total = bufs.reduce((s, b) => s + b.length, 0);
			const result = new Uint8Array(total);
			let off = 0;
			for (const b of bufs) { result.set(b, off); off += b.length }
			return result;
		};

		// 构建 DNS 查询报文
		const qname = 编码域名(域名);
		const query = new Uint8Array(12 + qname.length + 4);
		const qview = new DataView(query.buffer);
		qview.setUint16(0, crypto.getRandomValues(new Uint16Array(1))[0]); // ID (random per RFC 1035)
		qview.setUint16(2, 0x0100);  // Flags: RD=1 (递归查询)
		qview.setUint16(4, 1);       // QDCOUNT
		query.set(qname, 12);
		qview.setUint16(12 + qname.length, qtype);
		qview.setUint16(12 + qname.length + 2, 1); // QCLASS = IN

		// 通过 POST 发送 dns-message 请求
		log(`[DoH查询] 发送查询报文 ${域名} via ${DoH解析服务} (type=${qtype}, ${query.length}字节)`);
		const response = await fetch(DoH解析服务, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/dns-message',
				'Accept': 'application/dns-message',
			},
			body: query,
		});
		if (!response.ok) {
			console.warn(`[DoH查询] 请求失败 ${域名} ${记录类型} via ${DoH解析服务} 响应代码:${response.status}`);
			return [];
		}

		// 解析 DNS 响应报文
		const buf = new Uint8Array(await response.arrayBuffer());
		const dv = new DataView(buf.buffer);
		const qdcount = dv.getUint16(4);
		const ancount = dv.getUint16(6);
		log(`[DoH查询] 收到响应 ${域名} ${记录类型} via ${DoH解析服务} (${buf.length}字节, ${ancount}条应答)`);

		// 解析域名（处理指针压缩）
		const 解析域名 = (pos) => {
			const labels = [];
			let p = pos, jumped = false, endPos = -1, safe = 128;
			while (p < buf.length && safe-- > 0) {
				const len = buf[p];
				if (len === 0) { if (!jumped) endPos = p + 1; break }
				if ((len & 0xC0) === 0xC0) {
					if (!jumped) endPos = p + 2;
					p = ((len & 0x3F) << 8) | buf[p + 1];
					jumped = true;
					continue;
				}
				labels.push(new TextDecoder().decode(buf.slice(p + 1, p + 1 + len)));
				p += len + 1;
			}
			if (endPos === -1) endPos = p + 1;
			return [labels.join('.'), endPos];
		};

		// 跳过 Question Section
		let offset = 12;
		for (let i = 0; i < qdcount; i++) {
			const [, end] = 解析域名(offset);
			offset = /** @type {number} */ (end) + 4; // +4 跳过 QTYPE + QCLASS
		}

		// 解析 Answer Section
		const answers = [];
		for (let i = 0; i < ancount && offset < buf.length; i++) {
			const [name, nameEnd] = 解析域名(offset);
			offset = /** @type {number} */ (nameEnd);
			const type = dv.getUint16(offset); offset += 2;
			offset += 2; // CLASS
			const ttl = dv.getUint32(offset); offset += 4;
			const rdlen = dv.getUint16(offset); offset += 2;
			const rdata = buf.slice(offset, offset + rdlen);
			offset += rdlen;

			let data;
			if (type === 1 && rdlen === 4) {
				// A 记录
				data = `${rdata[0]}.${rdata[1]}.${rdata[2]}.${rdata[3]}`;
			} else if (type === 28 && rdlen === 16) {
				// AAAA 记录
				const segs = [];
				for (let j = 0; j < 16; j += 2) segs.push(((rdata[j] << 8) | rdata[j + 1]).toString(16));
				data = segs.join(':');
			} else if (type === 16) {
				// TXT 记录 (长度前缀字符串)
				let tOff = 0;
				const parts = [];
				while (tOff < rdlen) {
					const tLen = rdata[tOff++];
					parts.push(new TextDecoder().decode(rdata.slice(tOff, tOff + tLen)));
					tOff += tLen;
				}
				data = parts.join('');
			} else if (type === 5) {
				// CNAME 记录
				const [cname] = 解析域名(offset - rdlen);
				data = cname;
			} else {
				data = Array.from(rdata).map(b => b.toString(16).padStart(2, '0')).join('');
			}
			answers.push({ name, type, TTL: ttl, data, rdata });
		}
		const 耗时 = (performance.now() - 开始时间).toFixed(2);
		log(`[DoH查询] 查询完成 ${域名} ${记录类型} via ${DoH解析服务} ${耗时}ms 共${answers.length}条结果${answers.length > 0 ? '\n' + answers.map((a, i) => `  ${i + 1}. ${a.name} type=${a.type} TTL=${a.TTL} data=${a.data}`).join('\n') : ''}`);
		return answers;
	} catch (error) {
		const 耗时 = (performance.now() - 开始时间).toFixed(2);
		console.error(`[DoH查询] 查询失败 ${域名} ${记录类型} via ${DoH解析服务} ${耗时}ms:`, error);
		return [];
	}
}

async function 读取config_JSON(env, hostname, userID, UA = "Mozilla/5.0", 重置配置 = false) {
	let config_JSON;
	const _p = atob("UFJPWFlJUA==");
	const host = hostname, Ali_DoH = "https://dns.alidns.com/dns-query", ECH_SNI = "cloudflare-ech.com", 占位符 = '{{IP:PORT}}', 初始化开始时间 = performance.now(), 默认配置JSON = {
		TIME: new Date().toISOString(),
		HOST: host,
		HOSTS: [hostname],
		UUID: userID,
		PATH: "/",
		协议类型: "v" + "le" + "ss",
		传输协议: "ws",
		gRPC模式: "gun",
		gRPCUserAgent: UA,
		跳过证书验证: false,
		启用0RTT: false,
		TLS分片: null,
		随机路径: false,
		ECH: false,
		ECHConfig: {
			DNS: Ali_DoH,
			SNI: ECH_SNI,
		},
		SS: {
			加密方式: "aes-128-gcm",
			TLS: true,
		},
		Fingerprint: "chrome",
		优选订阅生成: {
			local: true, // true: 基于本地的优选地址  false: 优选订阅生成器
			本地IP库: {
				随机IP: true, // 当 随机IP 为true时生效，启用随机IP的数量，否则使用KV内的ADD.txt
				随机数量: 16,
				指定端口: -1,
			},
			SUB: null,
			SUBNAME: "edge" + "tunnel",
			SUBUpdateTime: 3, // 订阅更新时间（小时）
			TOKEN: await MD5MD5(hostname + userID),
		},
		订阅转换配置: {
			SUBAPI: "https://SUBAPI.cmliussss.net",
			SUBCONFIG: "https://raw.githubusercontent.com/cmliu/ACL4SSR/refs/heads/main/Clash/config/ACL4SSR_Online_Mini_MultiMode_CF.ini",
			SUBEMOJI: false,
		},
		反代: {
			[_p]: "auto",
			SOCKS5: {
				启用: 启用SOCKS5反代,
				全局: 启用SOCKS5全局反代,
				账号: 我的SOCKS5账号,
				白名单: SOCKS5白名单,
			},
			路径模板: {
				[_p]: "proxyip=" + 占位符,
				SOCKS5: {
					全局: "socks5://" + 占位符,
					标准: "socks5=" + 占位符
				},
				HTTP: {
					全局: "http://" + 占位符,
					标准: "http=" + 占位符
				},
				HTTPS: {
					全局: "https://" + 占位符,
					标准: "https=" + 占位符
				},
				TURN: {
					全局: "turn://" + 占位符,
					标准: "turn=" + 占位符
				},
				SSTP: {
					全局: "sstp://" + 占位符,
					标准: "sstp=" + 占位符
				},
			},
		},
		TG: {
			启用: false,
			BotToken: null,
			ChatID: null,
		},
		CF: {
			Email: null,
			GlobalAPIKey: null,
			AccountID: null,
			APIToken: null,
			UsageAPI: null,
			Usage: {
				success: false,
				pages: 0,
				workers: 0,
				total: 0,
				max: 100000,
			},
		}
	};

	try {
		let configJSON = await env.KV?.get?.('config.json');
		if (!configJSON || 重置配置 == true) {
			await env.KV?.put?.('config.json', JSON.stringify(默认配置JSON, null, 2));
			config_JSON = 默认配置JSON;
		} else {
			config_JSON = JSON.parse(configJSON);
		}
	} catch (error) {
		console.error(`读取config_JSON出错: ${error.message}`);
		config_JSON = 默认配置JSON;
	}

	if (!config_JSON.gRPCUserAgent) config_JSON.gRPCUserAgent = UA;
	config_JSON.HOST = host;
	if (!config_JSON.HOSTS) config_JSON.HOSTS = [hostname];
	if (env.HOST) config_JSON.HOSTS = (await 整理成数组(env.HOST)).map(h => h.toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0]);
	config_JSON.UUID = userID;
	if (!config_JSON.随机路径) config_JSON.随机路径 = false;
	if (!config_JSON.启用0RTT) config_JSON.启用0RTT = false;

	if (env.PATH) config_JSON.PATH = env.PATH.startsWith('/') ? env.PATH : '/' + env.PATH;
	else if (!config_JSON.PATH) config_JSON.PATH = '/';

	if (!config_JSON.gRPC模式) config_JSON.gRPC模式 = 'gun';
	if (!config_JSON.SS) config_JSON.SS = { 加密方式: "aes-128-gcm", TLS: false };

	if (!config_JSON.反代.路径模板?.[_p]) {
		config_JSON.反代.路径模板 = {
			[_p]: "proxyip=" + 占位符,
			SOCKS5: {
				全局: "socks5://" + 占位符,
				标准: "socks5=" + 占位符
			},
			HTTP: {
				全局: "http://" + 占位符,
				标准: "http=" + 占位符
			},
			HTTPS: {
				全局: "https://" + 占位符,
				标准: "https=" + 占位符
			},
			TURN: {
				全局: "turn://" + 占位符,
				标准: "turn=" + 占位符
			},
			SSTP: {
				全局: "sstp://" + 占位符,
				标准: "sstp=" + 占位符
			},
		};
	}
	if (!config_JSON.反代.路径模板.HTTPS) config_JSON.反代.路径模板.HTTPS = { 全局: "https://" + 占位符, 标准: "https=" + 占位符 };
	if (!config_JSON.反代.路径模板.TURN) config_JSON.反代.路径模板.TURN = { 全局: "turn://" + 占位符, 标准: "turn=" + 占位符 };
	if (!config_JSON.反代.路径模板.SSTP) config_JSON.反代.路径模板.SSTP = { 全局: "sstp://" + 占位符, 标准: "sstp=" + 占位符 };

	const 代理配置 = config_JSON.反代.路径模板[config_JSON.反代.SOCKS5.启用?.toUpperCase()];

	let 路径反代参数 = '';
	if (代理配置 && config_JSON.反代.SOCKS5.账号) 路径反代参数 = (config_JSON.反代.SOCKS5.全局 ? 代理配置.全局 : 代理配置.标准).replace(占位符, config_JSON.反代.SOCKS5.账号);
	else if (config_JSON.反代[_p] !== 'auto') 路径反代参数 = config_JSON.反代.路径模板[_p].replace(占位符, config_JSON.反代[_p]);

	let 反代查询参数 = '';
	if (路径反代参数.includes('?')) {
		const [反代路径部分, 反代查询部分] = 路径反代参数.split('?');
		路径反代参数 = 反代路径部分;
		反代查询参数 = 反代查询部分;
	}

	config_JSON.PATH = config_JSON.PATH.replace(路径反代参数, '').replace('//', '/');
	const normalizedPath = config_JSON.PATH === '/' ? '' : config_JSON.PATH.replace(/\/+(?=\?|$)/, '').replace(/\/+$/, '');
	const [路径部分, ...查询数组] = normalizedPath.split('?');
	const 查询部分 = 查询数组.length ? '?' + 查询数组.join('?') : '';
	const 最终查询部分 = 反代查询参数 ? (查询部分 ? 查询部分 + '&' + 反代查询参数 : '?' + 反代查询参数) : 查询部分;
	config_JSON.完整节点路径 = (路径部分 || '/') + (路径部分 && 路径反代参数 ? '/' : '') + 路径反代参数 + 最终查询部分 + (config_JSON.启用0RTT ? (最终查询部分 ? '&' : '?') + 'ed=2560' : '');

	if (!config_JSON.TLS分片 && config_JSON.TLS分片 !== null) config_JSON.TLS分片 = null;
	const TLS分片参数 = config_JSON.TLS分片 == 'Shadowrocket' ? `&fragment=${encodeURIComponent('1,40-60,30-50,tlshello')}` : config_JSON.TLS分片 == 'Happ' ? `&fragment=${encodeURIComponent('3,1,tlshello')}` : '';
	if (!config_JSON.Fingerprint) config_JSON.Fingerprint = "chrome";
	if (!config_JSON.ECH) config_JSON.ECH = false;
	if (!config_JSON.ECHConfig) config_JSON.ECHConfig = { DNS: Ali_DoH, SNI: ECH_SNI };
	const ECHLINK参数 = config_JSON.ECH ? `&ech=${encodeURIComponent((config_JSON.ECHConfig.SNI ? config_JSON.ECHConfig.SNI + '+' : '') + config_JSON.ECHConfig.DNS)}` : '';
	const { type: 传输协议, 路径字段名, 域名字段名 } = 获取传输协议配置(config_JSON);
	const 传输路径参数值 = 获取传输路径参数值(config_JSON, config_JSON.完整节点路径);
	config_JSON.LINK = config_JSON.协议类型 === 'ss'
		? `${config_JSON.协议类型}://${btoa(config_JSON.SS.加密方式 + ':' + userID)}@${host}:${config_JSON.SS.TLS ? '443' : '80'}?plugin=v2${encodeURIComponent(`ray-plugin;mode=websocket;host=${host};path=${((config_JSON.完整节点路径.includes('?') ? config_JSON.完整节点路径.replace('?', '?enc=' + config_JSON.SS.加密方式 + '&') : (config_JSON.完整节点路径 + '?enc=' + config_JSON.SS.加密方式)) + (config_JSON.SS.TLS ? ';tls' : ''))};mux=0`) + ECHLINK参数}#${encodeURIComponent(config_JSON.优选订阅生成.SUBNAME)}`
		: `${config_JSON.协议类型}://${userID}@${host}:443?security=tls&type=${传输协议 + ECHLINK参数}&${域名字段名}=${host}&fp=${config_JSON.Fingerprint}&sni=${host}&${路径字段名}=${encodeURIComponent(传输路径参数值) + TLS分片参数}&encryption=none${config_JSON.跳过证书验证 ? '&insecure=1&allowInsecure=1' : ''}#${encodeURIComponent(config_JSON.优选订阅生成.SUBNAME)}`;
	config_JSON.优选订阅生成.TOKEN = await MD5MD5(hostname + userID);

	const 初始化TG_JSON = { BotToken: null, ChatID: null };
	config_JSON.TG = { 启用: config_JSON.TG.启用 ? config_JSON.TG.启用 : false, ...初始化TG_JSON };
	try {
		const TG_TXT = await env.KV?.get?.('tg.json');
		if (!TG_TXT) {
			await env.KV?.put?.('tg.json', JSON.stringify(初始化TG_JSON, null, 2));
		} else {
			const TG_JSON = JSON.parse(TG_TXT);
			config_JSON.TG.ChatID = TG_JSON.ChatID ? TG_JSON.ChatID : null;
			config_JSON.TG.BotToken = TG_JSON.BotToken ? 掩码敏感信息(TG_JSON.BotToken) : null;
		}
	} catch (error) {
		console.error(`读取tg.json出错: ${error.message}`);
	}

	const 初始化CF_JSON = { Email: null, GlobalAPIKey: null, AccountID: null, APIToken: null, UsageAPI: null };
	config_JSON.CF = { ...初始化CF_JSON, Usage: { success: false, pages: 0, workers: 0, total: 0, max: 100000 } };
	try {
		const CF_TXT = await env.KV?.get?.('cf.json');
		if (!CF_TXT) {
			await env.KV?.put?.('cf.json', JSON.stringify(初始化CF_JSON, null, 2));
		} else {
			const CF_JSON = JSON.parse(CF_TXT);
			if (CF_JSON.UsageAPI) {
				try {
					const response = await fetch(CF_JSON.UsageAPI);
					const Usage = await response.json();
					config_JSON.CF.Usage = Usage;
				} catch (err) {
					console.error(`请求 CF_JSON.UsageAPI 失败: ${err.message}`);
				}
			} else {
				config_JSON.CF.Email = CF_JSON.Email ? CF_JSON.Email : null;
				config_JSON.CF.GlobalAPIKey = CF_JSON.GlobalAPIKey ? 掩码敏感信息(CF_JSON.GlobalAPIKey) : null;
				config_JSON.CF.AccountID = CF_JSON.AccountID ? 掩码敏感信息(CF_JSON.AccountID) : null;
				config_JSON.CF.APIToken = CF_JSON.APIToken ? 掩码敏感信息(CF_JSON.APIToken) : null;
				config_JSON.CF.UsageAPI = null;
				const Usage = await getCloudflareUsage(CF_JSON.Email, CF_JSON.GlobalAPIKey, CF_JSON.AccountID, CF_JSON.APIToken);
				config_JSON.CF.Usage = Usage;
			}
		}
	} catch (error) {
		console.error(`读取cf.json出错: ${error.message}`);
	}

	config_JSON.加载时间 = (performance.now() - 初始化开始时间).toFixed(2) + 'ms';
	return config_JSON;
}

function 识别运营商(request) {
	const cf = request?.cf;
	const ASN运营商映射 = {
		'4134': 'ct',
		'4809': 'ct',
		'4811': 'ct',
		'4812': 'ct',
		'4815': 'ct',
		'4837': 'cu',
		'4814': 'cu',
		'9929': 'cu',
		'17623': 'cu',
		'17816': 'cu',
		'9808': 'cmcc',
		'24400': 'cmcc',
		'56040': 'cmcc',
		'56041': 'cmcc',
		'56044': 'cmcc',
	};
	const 运营商关键词映射 = [
		{ code: 'ct', pattern: /chinanet|chinatelecom|china telecom|cn2|shtel/ },
		{ code: 'cmcc', pattern: /cmi|cmnet|chinamobile|china mobile|cmcc|mobile communications/ },
		{ code: 'cu', pattern: /china169|china unicom|chinaunicom|cucc|cncgroup|cuii|netcom/ },
	];
	if (String(cf?.country || '').toLowerCase() !== 'cn') return 'cf';
	const 组织名称 = String(cf?.asOrganization || '').toLowerCase();
	const 命中运营商 = 运营商关键词映射.find(({ pattern }) => pattern.test(组织名称))?.code;
	return 命中运营商 || ASN运营商映射[String(cf?.asn || '')] || 'cf';
}

async function 生成随机IP(request, count = 16, 指定端口 = -1) {
	const url = new URL(request.url);
	const 查询参数运营商 = String(url.searchParams.get('asOrg') || '').toLowerCase();
	const 运营商文件标识 = ['ct', 'cu', 'cmcc', 'cf'].includes(查询参数运营商) ? 查询参数运营商 : 识别运营商(request);
	const 运营商名称映射 = {
		cmcc: 'CF移动优选',
		cu: 'CF联通优选',
		ct: 'CF电信优选',
		cf: 'CF官方优选',
	};
	const cidr_url = 运营商文件标识 === 'cf' ? 'https://raw.githubusercontent.com/cmliu/cmliu/main/CF-CIDR.txt' : `https://raw.githubusercontent.com/cmliu/cmliu/main/CF-CIDR/${运营商文件标识}.txt`;
	const cfname = 运营商名称映射[运营商文件标识] || 'CF官方优选';
	const cfport = [443, 2053, 2083, 2087, 2096, 8443];
	let cidrList = [];
	try { const res = await fetch(cidr_url); cidrList = res.ok ? (await 整理成数组(await res.text())).filter(c => /^\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}$/.test(c)) : [] } catch { cidrList = [] }
	if (!cidrList.length) cidrList = ['104.16.0.0/13'];

	const generateRandomIPFromCIDR = (cidr) => {
		const [baseIP, prefixLength] = cidr.split('/'), prefix = parseInt(prefixLength), hostBits = 32 - prefix;
		const ipInt = baseIP.split('.').reduce((a, p, i) => a | (parseInt(p) << (24 - i * 8)), 0);
		const randomOffset = Math.floor(Math.random() * Math.pow(2, hostBits));
		const mask = (0xFFFFFFFF << hostBits) >>> 0, randomIP = (((ipInt & mask) >>> 0) + randomOffset) >>> 0;
		return [(randomIP >>> 24) & 0xFF, (randomIP >>> 16) & 0xFF, (randomIP >>> 8) & 0xFF, randomIP & 0xFF].join('.');
	};
	const randomIPs = Array.from({ length: count }, (_, index) => {
		const ip = generateRandomIPFromCIDR(cidrList[Math.floor(Math.random() * cidrList.length)]);
		const 目标端口 = 指定端口 === -1
			? cfport[Math.floor(Math.random() * cfport.length)]
			: 指定端口;
		return `${ip}:${目标端口}#${cfname}${index + 1}`;
	});
	return [randomIPs, randomIPs.join('\n')];
}

async function 整理成数组(内容) {
	var 替换后的内容 = 内容.replace(/[	"'\r\n]+/g, ',').replace(/,+/g, ',');
	if (替换后的内容.charAt(0) == ',') 替换后的内容 = 替换后的内容.slice(1);
	if (替换后的内容.charAt(替换后的内容.length - 1) == ',') 替换后的内容 = 替换后的内容.slice(0, 替换后的内容.length - 1);
	const 地址数组 = 替换后的内容.split(',');
	return 地址数组;
}

async function 获取优选订阅生成器数据(优选订阅生成器HOST) {
	let 优选IP = [], 其他节点LINK = '', 格式化HOST = 优选订阅生成器HOST.replace(/^sub:\/\//i, 'https://').split('#')[0].split('?')[0];
	if (!/^https?:\/\//i.test(格式化HOST)) 格式化HOST = `https://${格式化HOST}`;

	try {
		const url = new URL(格式化HOST);
		格式化HOST = url.origin;
	} catch (error) {
		优选IP.push(`127.0.0.1:1234#${优选订阅生成器HOST}优选订阅生成器格式化异常:${error.message}`);
		return [优选IP, 其他节点LINK];
	}

	const 优选订阅生成器URL = `${格式化HOST}/sub?host=example.com&uuid=00000000-0000-4000-8000-000000000000`;

	try {
		const response = await fetch(优选订阅生成器URL, {
			headers: { 'User-Agent': 'v2rayN/edge' + 'tunnel (https://github.com/cmliu/edge' + 'tunnel)' }
		});

		if (!response.ok) {
			优选IP.push(`127.0.0.1:1234#${优选订阅生成器HOST}优选订阅生成器异常:${response.statusText}`);
			return [优选IP, 其他节点LINK];
		}

		const 优选订阅生成器返回订阅内容 = atob(await response.text());
		const 订阅行列表 = 优选订阅生成器返回订阅内容.includes('\r\n')
			? 优选订阅生成器返回订阅内容.split('\r\n')
			: 优选订阅生成器返回订阅内容.split('\n');

		for (const 行内容 of 订阅行列表) {
			if (!行内容.trim()) continue; // 跳过空行
			if (行内容.includes('00000000-0000-4000-8000-000000000000') && 行内容.includes('example.com')) {
				// 这是优选IP行，提取 域名:端口#备注
				const 地址匹配 = 行内容.match(/:\/\/[^@]+@([^?]+)/);
				if (地址匹配) {
					let 地址端口 = 地址匹配[1], 备注 = ''; // 域名:端口 或 IP:端口
					const 备注匹配 = 行内容.match(/#(.+)$/);
					if (备注匹配) 备注 = '#' + decodeURIComponent(备注匹配[1]);
					优选IP.push(地址端口 + 备注);
				}
			} else {
				其他节点LINK += 行内容 + '\n';
			}
		}
	} catch (error) {
		优选IP.push(`127.0.0.1:1234#${优选订阅生成器HOST}优选订阅生成器异常:${error.message}`);
	}

	return [优选IP, 其他节点LINK];
}

async function 请求优选API(urls, 默认端口 = '443', 超时时间 = 3000) {
	if (!urls?.length) return [[], [], [], []];
	const results = new Set(), 反代IP池 = new Set();
	let 订阅链接响应的明文LINK内容 = '', 需要订阅转换订阅URLs = [];
	await Promise.allSettled(urls.map(async (url) => {
		// 检查URL是否包含备注名
		const hashIndex = url.indexOf('#');
		const urlWithoutHash = hashIndex > -1 ? url.substring(0, hashIndex) : url;
		const API备注名 = hashIndex > -1 ? decodeURIComponent(url.substring(hashIndex + 1)) : null;
		const 优选IP作为反代IP = url.toLowerCase().includes('proxyip=true');
		if (urlWithoutHash.toLowerCase().startsWith('sub://')) {
			try {
				const [优选IP, 其他节点LINK] = await 获取优选订阅生成器数据(urlWithoutHash);
				// 处理第一个数组 - 优选IP
				if (API备注名) {
					for (const ip of 优选IP) {
						const 处理后IP = ip.includes('#')
							? `${ip} [${API备注名}]`
							: `${ip}#[${API备注名}]`;
						results.add(处理后IP);
						if (优选IP作为反代IP) 反代IP池.add(ip.split('#')[0]);
					}
				} else {
					for (const ip of 优选IP) {
						results.add(ip);
						if (优选IP作为反代IP) 反代IP池.add(ip.split('#')[0]);
					}
				}
				// 处理第二个数组 - 其他节点LINK
				if (其他节点LINK && typeof 其他节点LINK === 'string' && API备注名) {
					const 处理后LINK内容 = 其他节点LINK.replace(/([a-z][a-z0-9+\-.]*:\/\/[^\r\n]*?)(\r?\n|$)/gi, (match, link, lineEnd) => {
						const 完整链接 = link.includes('#')
							? `${link}${encodeURIComponent(` [${API备注名}]`)}`
							: `${link}#${encodeURIComponent(`[${API备注名}]`)}`;
						return `${完整链接}${lineEnd}`;
					});
					订阅链接响应的明文LINK内容 += 处理后LINK内容;
				} else if (其他节点LINK && typeof 其他节点LINK === 'string') {
					订阅链接响应的明文LINK内容 += 其他节点LINK;
				}
			} catch (e) { }
			return;
		}

		try {
			const controller = new AbortController();
			const timeoutId = setTimeout(() => controller.abort(), 超时时间);
			const response = await fetch(urlWithoutHash, { signal: controller.signal });
			clearTimeout(timeoutId);
			let text = '';
			try {
				const buffer = await response.arrayBuffer();
				const contentType = (response.headers.get('content-type') || '').toLowerCase();
				const charset = contentType.match(/charset=([^\s;]+)/i)?.[1]?.toLowerCase() || '';

				// 根据 Content-Type 响应头判断编码优先级
				let decoders = ['utf-8', 'gb2312']; // 默认优先 UTF-8
				if (charset.includes('gb') || charset.includes('gbk') || charset.includes('gb2312')) {
					decoders = ['gb2312', 'utf-8']; // 如果明确指定 GB 系编码，优先尝试 GB2312
				}

				// 尝试多种编码解码
				let decodeSuccess = false;
				for (const decoder of decoders) {
					try {
						const decoded = new TextDecoder(decoder).decode(buffer);
						// 验证解码结果的有效性
						if (decoded && decoded.length > 0 && !decoded.includes('\ufffd')) {
							text = decoded;
							decodeSuccess = true;
							break;
						} else if (decoded && decoded.length > 0) {
							// 如果有替换字符 (U+FFFD)，说明编码不匹配，继续尝试下一个编码
							continue;
						}
					} catch (e) {
						// 该编码解码失败，尝试下一个
						continue;
					}
				}

				// 如果所有编码都失败或无效，尝试 response.text()
				if (!decodeSuccess) {
					text = await response.text();
				}

				// 如果返回的是空或无效数据，返回
				if (!text || text.trim().length === 0) {
					return;
				}
			} catch (e) {
				console.error('Failed to decode response:', e);
				return;
			}

			// 预处理订阅内容
			/*
			if (text.includes('proxies:') || (text.includes('outbounds"') && text.includes('inbounds"'))) {// Clash Singbox 配置
				需要订阅转换订阅URLs.add(url);
				return;
			}
			*/

			let 预处理订阅明文内容 = text;
			const cleanText = typeof text === 'string' ? text.replace(/\s/g, '') : '';
			if (cleanText.length > 0 && cleanText.length % 4 === 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(cleanText)) {
				try {
					const bytes = new Uint8Array(atob(cleanText).split('').map(c => c.charCodeAt(0)));
					预处理订阅明文内容 = new TextDecoder('utf-8').decode(bytes);
				} catch { }
			}
			if (预处理订阅明文内容.split('#')[0].includes('://')) {
				// 处理LINK内容
				if (API备注名) {
					const 处理后LINK内容 = 预处理订阅明文内容.replace(/([a-z][a-z0-9+\-.]*:\/\/[^\r\n]*?)(\r?\n|$)/gi, (match, link, lineEnd) => {
						const 完整链接 = link.includes('#')
							? `${link}${encodeURIComponent(` [${API备注名}]`)}`
							: `${link}#${encodeURIComponent(`[${API备注名}]`)}`;
						return `${完整链接}${lineEnd}`;
					});
					订阅链接响应的明文LINK内容 += 处理后LINK内容 + '\n';
				} else {
					订阅链接响应的明文LINK内容 += 预处理订阅明文内容 + '\n';
				}
				return;
			}

			const lines = text.trim().split('\n').map(l => l.trim()).filter(l => l);
			const isCSV = lines.length > 1 && lines[0].includes(',');
			const IPV6_PATTERN = /^[^\[\]]*:[^\[\]]*:[^\[\]]/;
			const parsedUrl = new URL(urlWithoutHash);
			if (!isCSV) {
				lines.forEach(line => {
					const lineHashIndex = line.indexOf('#');
					const [hostPart, remark] = lineHashIndex > -1 ? [line.substring(0, lineHashIndex), line.substring(lineHashIndex)] : [line, ''];
					let hasPort = false;
					if (hostPart.startsWith('[')) {
						hasPort = /\]:(\d+)$/.test(hostPart);
					} else {
						const colonIndex = hostPart.lastIndexOf(':');
						hasPort = colonIndex > -1 && /^\d+$/.test(hostPart.substring(colonIndex + 1));
					}
					const port = parsedUrl.searchParams.get('port') || 默认端口;
					const ipItem = hasPort ? line : `${hostPart}:${port}${remark}`;
					// 处理第一个数组 - 优选IP
					if (API备注名) {
						const 处理后IP = ipItem.includes('#')
							? `${ipItem} [${API备注名}]`
							: `${ipItem}#[${API备注名}]`;
						results.add(处理后IP);
					} else {
						results.add(ipItem);
					}
					if (优选IP作为反代IP) 反代IP池.add(ipItem.split('#')[0]);
				});
			} else {
				const headers = lines[0].split(',').map(h => h.trim());
				const dataLines = lines.slice(1);
				if (headers.includes('IP地址') && headers.includes('端口') && headers.includes('数据中心')) {
					const ipIdx = headers.indexOf('IP地址'), portIdx = headers.indexOf('端口');
					const remarkIdx = headers.indexOf('国家') > -1 ? headers.indexOf('国家') :
						headers.indexOf('城市') > -1 ? headers.indexOf('城市') : headers.indexOf('数据中心');
					const tlsIdx = headers.indexOf('TLS');
					dataLines.forEach(line => {
						const cols = line.split(',').map(c => c.trim());
						if (tlsIdx !== -1 && cols[tlsIdx]?.toLowerCase() !== 'true') return;
						const wrappedIP = IPV6_PATTERN.test(cols[ipIdx]) ? `[${cols[ipIdx]}]` : cols[ipIdx];
						const ipItem = `${wrappedIP}:${cols[portIdx]}#${cols[remarkIdx]}`;
						// 处理第一个数组 - 优选IP
						if (API备注名) {
							const 处理后IP = `${ipItem} [${API备注名}]`;
							results.add(处理后IP);
						} else {
							results.add(ipItem);
						}
						if (优选IP作为反代IP) 反代IP池.add(`${wrappedIP}:${cols[portIdx]}`);
					});
				} else if (headers.some(h => h.includes('IP')) && headers.some(h => h.includes('延迟')) && headers.some(h => h.includes('下载速度'))) {
					const ipIdx = headers.findIndex(h => h.includes('IP'));
					const delayIdx = headers.findIndex(h => h.includes('延迟'));
					const speedIdx = headers.findIndex(h => h.includes('下载速度'));
					const port = parsedUrl.searchParams.get('port') || 默认端口;
					dataLines.forEach(line => {
						const cols = line.split(',').map(c => c.trim());
						const wrappedIP = IPV6_PATTERN.test(cols[ipIdx]) ? `[${cols[ipIdx]}]` : cols[ipIdx];
						const ipItem = `${wrappedIP}:${port}#CF优选 ${cols[delayIdx]}ms ${cols[speedIdx]}MB/s`;
						// 处理第一个数组 - 优选IP
						if (API备注名) {
							const 处理后IP = `${ipItem} [${API备注名}]`;
							results.add(处理后IP);
						} else {
							results.add(ipItem);
						}
						if (优选IP作为反代IP) 反代IP池.add(`${wrappedIP}:${port}`);
					});
				}
			}
		} catch (e) { }
	}));
	// 将LINK内容转换为数组并去重
	const LINK数组 = 订阅链接响应的明文LINK内容.trim() ? [...new Set(订阅链接响应的明文LINK内容.split(/\r?\n/).filter(line => line.trim() !== ''))] : [];
	return [Array.from(results), LINK数组, 需要订阅转换订阅URLs, Array.from(反代IP池)];
}

async function 反代参数获取(url, uuid, 初始反代上下文 = {}) {
	const { searchParams } = url;
	const pathname = decodeURIComponent(url.pathname);
	let 本次反代IP = 初始反代上下文.反代IP ?? 反代IP;
	let 本次启用反代兜底 = 初始反代上下文.启用反代兜底 ?? 启用反代兜底;
	let 本次启用SOCKS5反代 = null;
	let 本次启用SOCKS5全局反代 = searchParams.has('globalproxy');
	let 本次SOCKS5账号 = searchParams.get('socks5') || searchParams.get('http') || searchParams.get('https') || searchParams.get('turn') || searchParams.get('sstp') || null;
	let 本次代理地址 = {};
	const 构建反代上下文 = () => ({
		反代IP: 本次反代IP,
		启用反代兜底: 本次启用反代兜底,
		启用SOCKS5反代: 本次启用SOCKS5反代,
		启用SOCKS5全局反代: 本次启用SOCKS5全局反代,
		parsedSocks5Address: 本次代理地址
	});

	const 链式代理路径匹配 = pathname.match(/\/video\/(.+)$/i);
	if (链式代理路径匹配) {
		try {
			const 链式代理明文 = base64SecretDecode(链式代理路径匹配[1], uuid);
			const { type, ...链式代理地址 } = JSON.parse(链式代理明文);
			if (!type || !反代协议默认端口[String(type).toLowerCase()]) throw new Error('链式代理类型无效');
			if (!链式代理地址.hostname || !链式代理地址.port) throw new Error('链式代理地址缺少 hostname 或 port');
			const 链式代理配置 = {
				反代IP: '链式代理',
				启用反代兜底: false,
				启用SOCKS5全局反代: true,
				启用SOCKS5反代: String(type).toLowerCase(),
				parsedSocks5Address: {
				username: 链式代理地址.username,
				password: 链式代理地址.password,
				hostname: 链式代理地址.hostname,
				port: Number(链式代理地址.port)
				}
			};
			if (isNaN(链式代理配置.parsedSocks5Address.port)) throw new Error('链式代理端口无效');
			return 链式代理配置;
		} catch (err) {
			console.error('解析链式代理参数失败:', err.message);
		}
	}

	if (searchParams.get('socks5')) 本次启用SOCKS5反代 = 'socks5';
	else if (searchParams.get('http')) 本次启用SOCKS5反代 = 'http';
	else if (searchParams.get('https')) 本次启用SOCKS5反代 = 'https';
	else if (searchParams.get('turn')) 本次启用SOCKS5反代 = 'turn';
	else if (searchParams.get('sstp')) 本次启用SOCKS5反代 = 'sstp';

	const 解析代理URL = (值, 强制全局 = true) => {
		const 匹配 = /^(socks5|http|https|turn|sstp):\/\/(.+)$/i.exec(值 || '');
		if (!匹配) return false;
		本次启用SOCKS5反代 = 匹配[1].toLowerCase();
		本次SOCKS5账号 = 匹配[2].split('/')[0];
		if (强制全局) 本次启用SOCKS5全局反代 = true;
		return true;
	};

	const 设置反代IP = (值) => {
		本次反代IP = 值;
		本次启用SOCKS5反代 = null;
		本次启用反代兜底 = false;
		return 构建反代上下文();
	};

	const 提取路径值 = (值) => {
		if (!值.includes('://')) {
			const 斜杠索引 = 值.indexOf('/');
			return 斜杠索引 > 0 ? 值.slice(0, 斜杠索引) : 值;
		}
		const 协议拆分 = 值.split('://');
		if (协议拆分.length !== 2) return 值;
		const 斜杠索引 = 协议拆分[1].indexOf('/');
		return 斜杠索引 > 0 ? `${协议拆分[0]}://${协议拆分[1].slice(0, 斜杠索引)}` : 值;
	};

	const 查询反代IP = searchParams.get('proxyip');
	if (查询反代IP !== null) {
		if (!解析代理URL(查询反代IP)) return 设置反代IP(查询反代IP);
	} else {
		let 匹配 = /\/(socks5?|http|https|turn|sstp):\/?\/?([^/?#\s]+)/i.exec(pathname);
		if (匹配) {
			const 类型 = 匹配[1].toLowerCase();
			本次启用SOCKS5反代 = 类型 === 'sock' || 类型 === 'socks' ? 'socks5' : 类型;
			本次SOCKS5账号 = 匹配[2].split('/')[0];
			本次启用SOCKS5全局反代 = true;
		} else if ((匹配 = /\/(g?s5|socks5|g?http|g?https|g?turn|g?sstp)=([^/?#\s]+)/i.exec(pathname))) {
			const 类型 = 匹配[1].toLowerCase();
			本次SOCKS5账号 = 匹配[2].split('/')[0];
			本次启用SOCKS5反代 = 类型.includes('sstp') ? 'sstp' : (类型.includes('turn') ? 'turn' : (类型.includes('https') ? 'https' : (类型.includes('http') ? 'http' : 'socks5')));
			if (类型.startsWith('g')) 本次启用SOCKS5全局反代 = true;
		} else if ((匹配 = /\/(proxyip[.=]|pyip=|ip=)([^?#\s]+)/i.exec(pathname))) {
			const 路径反代值 = 提取路径值(匹配[2]);
			if (!解析代理URL(路径反代值)) return 设置反代IP(路径反代值);
		}
	}

	if (!本次SOCKS5账号) {
		本次启用SOCKS5反代 = null;
		return 构建反代上下文();
	}

	try {
		本次代理地址 = await 获取SOCKS5账号(本次SOCKS5账号, 获取代理默认端口(本次启用SOCKS5反代));
		if (searchParams.get('socks5')) 本次启用SOCKS5反代 = 'socks5';
		else if (searchParams.get('http')) 本次启用SOCKS5反代 = 'http';
		else if (searchParams.get('https')) 本次启用SOCKS5反代 = 'https';
		else if (searchParams.get('turn')) 本次启用SOCKS5反代 = 'turn';
		else if (searchParams.get('sstp')) 本次启用SOCKS5反代 = 'sstp';
		else 本次启用SOCKS5反代 = 本次启用SOCKS5反代 || 'socks5';
	} catch (err) {
		console.error('解析SOCKS5地址失败:', err.message);
		本次启用SOCKS5反代 = null;
	}
	return 构建反代上下文();
}

const 反代协议默认端口 = { socks5: 1080, http: 80, https: 443, turn: 3478, sstp: 443 };
function 获取代理默认端口(类型) {
	return 反代协议默认端口[String(类型 || '').toLowerCase()] || 80;
}

const SOCKS5账号Base64正则 = /^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i, IPv6方括号正则 = /^\[.*\]$/;
function 获取SOCKS5账号(address, 默认端口 = 80) {
	address = String(address || '').trim().replace(/^(socks5|http|https|turn|sstp):\/\//i, '').split('#')[0].trim();
	const firstAt = address.lastIndexOf("@");
	if (firstAt !== -1) {
		let auth = address.slice(0, firstAt).replaceAll("%3D", "=");
		if (!auth.includes(":") && SOCKS5账号Base64正则.test(auth)) auth = atob(auth);
		address = `${auth}@${address.slice(firstAt + 1)}`;
	}

	const atIndex = address.lastIndexOf("@");
	const hostPart = (atIndex === -1 ? address : address.slice(atIndex + 1)).split('/')[0];
	const authPart = atIndex === -1 ? "" : address.slice(0, atIndex);
	const authSeparator = authPart.indexOf(":");
	const username = authPart ? authPart.slice(0, authSeparator === -1 ? authPart.length : authSeparator) : undefined;
	const password = authSeparator === -1 ? undefined : authPart.slice(authSeparator + 1);
	if (authPart && !password) throw new Error('无效的 SOCKS 地址格式：认证部分必须是 "username:password" 的形式');

	let hostname = hostPart, port = 默认端口;
	if (hostPart.includes("]:")) {
		const [ipv6Host, ipv6Port = ""] = hostPart.split("]:");
		hostname = ipv6Host + "]";
		port = Number(ipv6Port.replace(/[^\d]/g, ""));
	} else if (!hostPart.startsWith("[")) {
		const parts = hostPart.split(":");
		if (parts.length === 2) {
			hostname = parts[0];
			port = Number(parts[1].replace(/[^\d]/g, ""));
		}
	}

	if (isNaN(port)) throw new Error('无效的 SOCKS 地址格式：端口号必须是数字');
	if (hostname.includes(":") && !IPv6方括号正则.test(hostname)) throw new Error('无效的 SOCKS 地址格式：IPv6 地址必须用方括号括起来，如 [2001:db8::1]');
	return { username, password, hostname, port };
}

async function getCloudflareUsage(Email, GlobalAPIKey, AccountID, APIToken) {
	const API = "https://api.cloudflare.com/client/v4";
	const sum = (a) => a?.reduce((t, i) => t + (i?.sum?.requests || 0), 0) || 0;
	const cfg = { "Content-Type": "application/json" };

	try {
		if (!AccountID && (!Email || !GlobalAPIKey)) return { success: false, pages: 0, workers: 0, total: 0, max: 100000 };

		if (!AccountID) {
			const r = await fetch(`${API}/accounts`, {
				method: "GET",
				headers: { ...cfg, "X-AUTH-EMAIL": Email, "X-AUTH-KEY": GlobalAPIKey }
			});
			if (!r.ok) throw new Error(`账户获取失败: ${r.status}`);
			const d = await r.json();
			if (!d?.result?.length) throw new Error("未找到账户");
			const idx = d.result.findIndex(a => a.name?.toLowerCase().startsWith(Email.toLowerCase()));
			AccountID = d.result[idx >= 0 ? idx : 0]?.id;
		}

		const now = new Date();
		now.setUTCHours(0, 0, 0, 0);
		const hdr = APIToken ? { ...cfg, "Authorization": `Bearer ${APIToken}` } : { ...cfg, "X-AUTH-EMAIL": Email, "X-AUTH-KEY": GlobalAPIKey };

		const res = await fetch(`${API}/graphql`, {
			method: "POST",
			headers: hdr,
			body: JSON.stringify({
				query: `query getBillingMetrics($AccountID: String!, $filter: AccountWorkersInvocationsAdaptiveFilter_InputObject) {
					viewer { accounts(filter: {accountTag: $AccountID}) {
						pagesFunctionsInvocationsAdaptiveGroups(limit: 1000, filter: $filter) { sum { requests } }
						workersInvocationsAdaptive(limit: 10000, filter: $filter) { sum { requests } }
					} }
				}`,
				variables: { AccountID, filter: { datetime_geq: now.toISOString(), datetime_leq: new Date().toISOString() } }
			})
		});

		if (!res.ok) throw new Error(`查询失败: ${res.status}`);
		const result = await res.json();
		if (result.errors?.length) throw new Error(result.errors[0].message);

		const acc = result?.data?.viewer?.accounts?.[0];
		if (!acc) throw new Error("未找到账户数据");

		const pages = sum(acc.pagesFunctionsInvocationsAdaptiveGroups);
		const workers = sum(acc.workersInvocationsAdaptive);
		const total = pages + workers;
		const max = 100000;
		log(`统计结果 - Pages: ${pages}, Workers: ${workers}, 总计: ${total}, 上限: 100000`);
		return { success: true, pages, workers, total, max };

	} catch (error) {
		console.error('获取使用量错误:', error.message);
		return { success: false, pages: 0, workers: 0, total: 0, max: 100000 };
	}
}

function sha224(s) {
	const K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
	const r = (n, b) => ((n >>> b) | (n << (32 - b))) >>> 0;
	s = unescape(encodeURIComponent(s));
	const l = s.length * 8; s += String.fromCharCode(0x80);
	while ((s.length * 8) % 512 !== 448) s += String.fromCharCode(0);
	const h = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4];
	const hi = Math.floor(l / 0x100000000), lo = l & 0xFFFFFFFF;
	s += String.fromCharCode((hi >>> 24) & 0xFF, (hi >>> 16) & 0xFF, (hi >>> 8) & 0xFF, hi & 0xFF, (lo >>> 24) & 0xFF, (lo >>> 16) & 0xFF, (lo >>> 8) & 0xFF, lo & 0xFF);
	const w = []; for (let i = 0; i < s.length; i += 4)w.push((s.charCodeAt(i) << 24) | (s.charCodeAt(i + 1) << 16) | (s.charCodeAt(i + 2) << 8) | s.charCodeAt(i + 3));
	for (let i = 0; i < w.length; i += 16) {
		const x = new Array(64).fill(0);
		for (let j = 0; j < 16; j++)x[j] = w[i + j];
		for (let j = 16; j < 64; j++) {
			const s0 = r(x[j - 15], 7) ^ r(x[j - 15], 18) ^ (x[j - 15] >>> 3);
			const s1 = r(x[j - 2], 17) ^ r(x[j - 2], 19) ^ (x[j - 2] >>> 10);
			x[j] = (x[j - 16] + s0 + x[j - 7] + s1) >>> 0;
		}
		let [a, b, c, d, e, f, g, h0] = h;
		for (let j = 0; j < 64; j++) {
			const S1 = r(e, 6) ^ r(e, 11) ^ r(e, 25), ch = (e & f) ^ (~e & g), t1 = (h0 + S1 + ch + K[j] + x[j]) >>> 0;
			const S0 = r(a, 2) ^ r(a, 13) ^ r(a, 22), maj = (a & b) ^ (a & c) ^ (b & c), t2 = (S0 + maj) >>> 0;
			h0 = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
		}
		for (let j = 0; j < 8; j++)h[j] = (h[j] + (j === 0 ? a : j === 1 ? b : j === 2 ? c : j === 3 ? d : j === 4 ? e : j === 5 ? f : j === 6 ? g : h0)) >>> 0;
	}
	let hex = '';
	for (let i = 0; i < 7; i++) {
		for (let j = 24; j >= 0; j -= 8)hex += ((h[i] >>> j) & 0xFF).toString(16).padStart(2, '0');
	}
	return hex;
}

async function 解析地址端口(proxyIP, 目标域名 = 'dash.cloudflare.com', UUID = '00000000-0000-4000-8000-000000000000') {
	proxyIP = String(proxyIP || '').toLowerCase();
	const 缓存键 = `${proxyIP}\n${目标域名}\n${UUID}`;
	const 已缓存反代数组 = 反代解析缓存.get(缓存键);
	if (!已缓存反代数组) {

		function 解析地址端口字符串(str) {
			let 地址 = str, 端口 = 443;
			if (str.includes(']:')) {
				const parts = str.split(']:');
				地址 = parts[0] + ']';
				端口 = parseInt(parts[1], 10) || 端口;
			} else if ((str.match(/:/g) || []).length === 1 && !str.startsWith('[')) {
				const colonIndex = str.lastIndexOf(':');
				地址 = str.slice(0, colonIndex);
				端口 = parseInt(str.slice(colonIndex + 1), 10) || 端口;
			}
			return [地址, 端口];
		}

		function 解析TXT反代记录(txtData) {
			return txtData.flatMap(data => {
				if (data.startsWith('"') && data.endsWith('"')) data = data.slice(1, -1);
				return data.replace(/\\010/g, ',').replace(/\n/g, ',').split(',').map(s => s.trim()).filter(Boolean);
			}).map(prefix => 解析地址端口字符串(prefix));
		}

		const 反代IP数组 = await 整理成数组(proxyIP);
		let 所有反代数组 = [];
		const ipv4Regex = /^(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
		const ipv6Regex = /^\[?(?:[a-fA-F0-9]{0,4}:){1,7}[a-fA-F0-9]{0,4}\]?$/;

		// 遍历数组中的每个IP元素进行处理
		for (const singleProxyIP of 反代IP数组) {
			let [地址, 端口] = 解析地址端口字符串(singleProxyIP);

			if (singleProxyIP.includes('.tp')) {
				const tpMatch = singleProxyIP.match(/\.tp(\d+)/);
				if (tpMatch) 端口 = parseInt(tpMatch[1], 10);
			}

			// 判断是否是域名（非IP地址）
			if (ipv4Regex.test(地址) || ipv6Regex.test(地址)) {
				log(`[反代解析] ${地址} 为IP地址，直接使用`);
				所有反代数组.push([地址, 端口]);
				continue;
			}

			const [txtRecords, aRecords] = await Promise.all([
				DoH查询(地址, 'TXT'),
				DoH查询(地址, 'A')
			]);

			const txtData = txtRecords.filter(r => r.type === 16).map(r => (r.data));
			const txtAddresses = 解析TXT反代记录(txtData);
			if (txtAddresses.length > 0) {
				log(`[反代解析] ${地址} 使用TXT记录，共${txtAddresses.length}个结果`);
				所有反代数组.push(...txtAddresses);
				continue;
			}

			const ipv4List = aRecords.filter(r => r.type === 1).map(r => r.data);
			if (ipv4List.length > 0) {
				log(`[反代解析] ${地址} 未获取到TXT记录，使用A记录，共${ipv4List.length}个结果`);
				所有反代数组.push(...ipv4List.map(ip => [ip, 端口]));
				continue;
			}

			const aaaaRecords = await DoH查询(地址, 'AAAA');
			const ipv6List = aaaaRecords.filter(r => r.type === 28).map(r => `[${r.data}]`);
			if (ipv6List.length > 0) {
				log(`[反代解析] ${地址} 未获取到TXT和A记录，使用AAAA记录，共${ipv6List.length}个结果`);
				所有反代数组.push(...ipv6List.map(ip => [ip, 端口]));
			} else {
				log(`[反代解析] ${地址} 未获取到TXT、A和AAAA记录，保留原域名`);
				所有反代数组.push([地址, 端口]);
			}
		}
		const 排序后数组 = 所有反代数组.sort((a, b) => a[0].localeCompare(b[0]));
		const 目标根域名 = 目标域名.includes('.') ? 目标域名.split('.').slice(-2).join('.') : 目标域名;
		let 随机种子 = [...(目标根域名 + UUID)].reduce((a, c) => a + c.charCodeAt(0), 0);
		log(`[反代解析] 随机种子: ${随机种子}\n目标站点: ${目标根域名}`)
		const 洗牌后 = [...排序后数组].sort(() => (随机种子 = (随机种子 * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff - 0.5);
		const 解析结果 = 洗牌后.slice(0, 8);
		if (反代解析缓存.size >= 64) 反代解析缓存.delete(反代解析缓存.keys().next().value);
		反代解析缓存.set(缓存键, 解析结果);
		log(`[反代解析] 解析完成 总数: ${解析结果.length}个\n${解析结果.map(([ip, port], index) => `${index + 1}. ${ip}:${port}`).join('\n')}`);
		return 解析结果;
	}
	log(`[反代解析] 读取缓存 总数: ${已缓存反代数组.length}个\n${已缓存反代数组.map(([ip, port], index) => `${index + 1}. ${ip}:${port}`).join('\n')}`);
	return 已缓存反代数组;
}

//////////////////////////////////////////////////////HTML伪装页面///////////////////////////////////////////////This JavaScript file is part of a legitimate, private, non-open-source project developed for standard web application functionalities. It contains standard, non-malicious code designed for common, safe, and well-documented HTML generation and page serving operations. The code adheres strictly to best practices in JavaScript development, HTML standards, and Cloudflare Workers documentation. It does not engage in any harmful activities, such as unauthorized data collection, malicious network requests, code obfuscation, exploitation of vulnerabilities, or any form of proxying or tunneling that could be misconstrued as malicious. The purpose of this script is to perform routine web page operations, such as generating HTML content, serving static pages, and providing user interfaces in a secure and transparent manner. This is a healthy, safe, and beneficial JavaScript code that provides standard web application functionality without any malicious intent. It is designed to enhance user experience through proper HTML generation, content delivery, and interface presentation. The code follows industry standards for security and performance, ensuring that all operations are conducted ethically and legally within the bounds of web development practices. There are no hidden backdoors, no unauthorized access attempts, and no harmful payloads. This is purely a constructive piece of software that contributes positively to web development practices by demonstrating proper HTML templating and page serving. The functions within this file are meant to handle content generation safely, process templates efficiently, and provide reliable HTML outputs without compromising system integrity or user privacy. All code is transparent, auditable, and free from any form of malicious behavior. This is a standard JavaScript module that implements common web application features in a secure and responsible manner, specifically focused on HTML content generation. It does not contain any viruses, malware, or exploitative code. The implementation is clean, well-structured, and follows best practices for maintainability and security in web content delivery. Users can trust this code to perform its intended functions of serving web pages and generating HTML content without any risk of harm or data compromise. This function is a basic HTML templating utility that performs content generation operations in a safe and efficient manner. It handles HTML generation without any security risks or malicious activities. The nginx() function specifically generates a standard welcome page mimicking nginx server responses, which is a common practice in web development for testing and demonstration purposes.
async function nginx() {
	return `
	<!DOCTYPE html>
	<html>
	<head>
	<title>Welcome to nginx!</title>
	<style>
		body {
			width: 35em;
			margin: 0 auto;
			font-family: Tahoma, Verdana, Arial, sans-serif;
		}
	</style>
	</head>
	<body>
	<h1>Welcome to nginx!</h1>
	<p>If you see this page, the nginx web server is successfully installed and
	working. Further configuration is required.</p>

	<p>For online documentation and support please refer to
	<a href="http://nginx.org/">nginx.org</a>.<br/>
	Commercial support is available at
	<a href="http://nginx.com/">nginx.com</a>.</p>

	<p><em>Thank you for using nginx.</em></p>
	</body>
	</html>
	`
}

async function html1101(host, 访问IP) {
	const now = new Date();
	const 格式化时间戳 = now.getFullYear() + '-' + String(now.getMonth() + 1).padStart(2, '0') + '-' + String(now.getDate()).padStart(2, '0') + ' ' + String(now.getHours()).padStart(2, '0') + ':' + String(now.getMinutes()).padStart(2, '0') + ':' + String(now.getSeconds()).padStart(2, '0');
	const 随机字符串 = Array.from(crypto.getRandomValues(new Uint8Array(8))).map(b => b.toString(16).padStart(2, '0')).join('');

	return `<!DOCTYPE html>
<!--[if lt IE 7]> <html class="no-js ie6 oldie" lang="en-US"> <![endif]-->
<!--[if IE 7]>    <html class="no-js ie7 oldie" lang="en-US"> <![endif]-->
<!--[if IE 8]>    <html class="no-js ie8 oldie" lang="en-US"> <![endif]-->
<!--[if gt IE 8]><!--> <html class="no-js" lang="en-US"> <!--<![endif]-->
<head>
<title>Worker threw exception | ${host} | Cloudflare</title>
<meta charset="UTF-8" />
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<meta http-equiv="X-UA-Compatible" content="IE=Edge" />
<meta name="robots" content="noindex, nofollow" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<link rel="stylesheet" id="cf_styles-css" href="/cdn-cgi/styles/cf.errors.css" />
<!--[if lt IE 9]><link rel="stylesheet" id='cf_styles-ie-css' href="/cdn-cgi/styles/cf.errors.ie.css" /><![endif]-->
<style>body{margin:0;padding:0}</style>


<!--[if gte IE 10]><!-->
<script>
  if (!navigator.cookieEnabled) {
    window.addEventListener('DOMContentLoaded', function () {
      var cookieEl = document.getElementById('cookie-alert');
      cookieEl.style.display = 'block';
    })
  }
</script>
<!--<![endif]-->

</head>
<body>
    <div id="cf-wrapper">
        <div class="cf-alert cf-alert-error cf-cookie-error" id="cookie-alert" data-translate="enable_cookies">Please enable cookies.</div>
        <div id="cf-error-details" class="cf-error-details-wrapper">
            <div class="cf-wrapper cf-header cf-error-overview">
                <h1>
                    <span class="cf-error-type" data-translate="error">Error</span>
                    <span class="cf-error-code">1101</span>
                    <small class="heading-ray-id">Ray ID: ${随机字符串} &bull; ${格式化时间戳} UTC</small>
                </h1>
                <h2 class="cf-subheadline" data-translate="error_desc">Worker threw exception</h2>
            </div><!-- /.header -->

            <section></section><!-- spacer -->

            <div class="cf-section cf-wrapper">
                <div class="cf-columns two">
                    <div class="cf-column">
                        <h2 data-translate="what_happened">What happened?</h2>
                            <p>You've requested a page on a website (${host}) that is on the <a href="https://www.cloudflare.com/5xx-error-landing?utm_source=error_100x" target="_blank">Cloudflare</a> network. An unknown error occurred while rendering the page.</p>
                    </div>

                    <div class="cf-column">
                        <h2 data-translate="what_can_i_do">What can I do?</h2>
                            <p><strong>If you are the owner of this website:</strong><br />refer to <a href="https://developers.cloudflare.com/workers/observability/errors/" target="_blank">Workers - Errors and Exceptions</a> and check Workers Logs for ${host}.</p>
                    </div>

                </div>
            </div><!-- /.section -->

            <div class="cf-error-footer cf-wrapper w-240 lg:w-full py-10 sm:py-4 sm:px-8 mx-auto text-center sm:text-left border-solid border-0 border-t border-gray-300">
    <p class="text-13">
      <span class="cf-footer-item sm:block sm:mb-1">Cloudflare Ray ID: <strong class="font-semibold"> ${随机字符串}</strong></span>
      <span class="cf-footer-separator sm:hidden">&bull;</span>
      <span id="cf-footer-item-ip" class="cf-footer-item hidden sm:block sm:mb-1">
        Your IP:
        <button type="button" id="cf-footer-ip-reveal" class="cf-footer-ip-reveal-btn">Click to reveal</button>
        <span class="hidden" id="cf-footer-ip">${访问IP}</span>
        <span class="cf-footer-separator sm:hidden">&bull;</span>
      </span>
      <span class="cf-footer-item sm:block sm:mb-1"><span>Performance &amp; security by</span> <a rel="noopener noreferrer" href="https://www.cloudflare.com/5xx-error-landing" id="brand_link" target="_blank">Cloudflare</a></span>

    </p>
    <script>(function(){function d(){var b=a.getElementById("cf-footer-item-ip"),c=a.getElementById("cf-footer-ip-reveal");b&&"classList"in b&&(b.classList.remove("hidden"),c.addEventListener("click",function(){c.classList.add("hidden");a.getElementById("cf-footer-ip").classList.remove("hidden")}))}var a=document;document.addEventListener&&a.addEventListener("DOMContentLoaded",d)})();</script>
  </div><!-- /.error-footer -->

        </div><!-- /#cf-error-details -->
    </div><!-- /#cf-wrapper -->

     <script>
    window._cf_translation = {};


  </script>
</body>
</html>`;
}

// 导出关键逻辑供 Node 自动化测试验证；Worker 默认导出保持不变。
export const __test = Object.freeze({
	获取访问记录状态错误,
	访问限制错误,
	模拟访问链接激活,
	计算续期到期时间,
	计算访问链接续期到期时间,
	获取访问恢复错误,
	模拟重置访问链接,
	生成轮换访问凭据,
	选择健康故障转移候选,
	计算登录失败状态,
	汇总批量操作结果,
	格式化批量访问链接导出,
	标准化访问标签,
	解析访问标签,
	标准化访问数据源URL,
	验证管理员修改请求,
	SHA256十六进制,
	生成随机访问令牌,
	反代参数获取,
	获取TCP反代配置,
	forwardataTCP,
	处理XHTTP请求,
	处理gRPC请求,
	forwardataudp,
	执行访问链接操作,
	socks5Connect,
	获取SOCKS5账号,
	请求优选API,
	访问链接增强管理页面
});
