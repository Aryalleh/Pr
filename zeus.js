import { connect } from "cloudflare:sockets";
const GLOBAL_TRAFFIC_CACHE = new Map();
const ACTIVE_CONNECTIONS_COUNT = new Map();
const GLOBAL_LAST_ACTIVE_WRITE = new Map();
const GLOBAL_LAST_DB_WRITE = new Map();
const GLOBAL_WRITE_LOCK = new Map();
const DNS_CACHE = new Map();
const USER_REQ_CACHE = new Map();
let GLOBAL_REQ_COUNT = 0;
let GLOBAL_LAST_REQ_WRITE = 0;
const DNS_CACHE_TTL = 5 * 60 * 1000;
const DOH_RESOLVER = "https://cloudflare-dns.com/dns-query";
const UPSTREAM_BUNDLE_TARGET_BYTES = 16 * 1024;
const UPSTREAM_QUEUE_MAX_BYTES = 16 * 1024 * 1024;
const UPSTREAM_QUEUE_MAX_ITEMS = 4096;
const DOWNSTREAM_GRAIN_BYTES = 32 * 1024;
const DOWNSTREAM_GRAIN_TAIL_THRESHOLD = 512;
const DOWNSTREAM_GRAIN_SILENT_MS = 1;
const TCP_CONCURRENCY = 2;
const PRELOAD_RACE_DIAL = true;
export default {
	async fetch(request, env, ctx) {
		trackRequest(env, ctx);
		await DbService.ensureSchema(env.DB);
		const url = new URL(request.url);
		if (Router.isWebSocketUpgrade(request) && url.pathname === "/In_Panel_Rayeghan_Ast_Va_Gheyre_Ghabele_Foroosh") {
			return await Router.handleWebSocket(request, env, ctx);
		}
		if (Router.isSubscriptionPath(url.pathname)) {
			return await Router.handleSubscription(url, env);
		}
		if (url.pathname.startsWith("/api/") || url.pathname === "/locations") {
			return await Router.handleApi(request, url, env, ctx);
		}
		if (url.pathname === "/panel" || url.pathname === "/login") {
			return await Router.handlePanel(request, env);
		}
		if (url.pathname.startsWith("/status/")) {
			return await Router.handleUserStatus(url, env);
		}
		if (url.pathname === "/") {
			return Response.redirect("https://t.me/Aryalleh_dev", 302);
		}
		return new Response(HTML_TEMPLATES.nginx, {
			headers: { "Content-Type": "text/html; charset=utf-8" },
		});
	},
};
const Router = {
	isWebSocketUpgrade(request) {
		const upgradeHeader = (request.headers.get("Upgrade") || "").toLowerCase();
		return upgradeHeader === "websocket";
	},
	isSubscriptionPath(pathname) {
		return pathname.startsWith("/sub/") || pathname.startsWith("/feed/");
	},
	async handleWebSocket(request, env, ctx) {
		try {
			let proxyIP = "proxyip.cmliussss.net";
			let socks5 = "";
			try {
				const proxyRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'proxy_ip'").first();
				if (proxyRow && proxyRow.value) {
					proxyIP = proxyRow.value;
				}
				const socksRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'socks5'").first();
				if (socksRow && socksRow.value) {
					socks5 = socksRow.value;
				}
			} catch (e) {}
			const mockStoredData = { proxy_ip: proxyIP, socks5: socks5 };
			return handleVLESS(env, mockStoredData, ctx, request);
		} catch (e) {
			return new Response("Internal Server Error", { status: 500 });
		}
	},
	async handleSubscription(url, env) {
		const isSubPath = url.pathname.startsWith("/sub/");
		const offset = isSubPath ? 5 : 6;
		let subUser = decodeURIComponent(url.pathname.slice(offset));
		const host = url.hostname;
		try {
			const user = await env.DB.prepare("SELECT * FROM users WHERE username = ? OR uuid = ?").bind(subUser, subUser).first();
			if (!user || user.connection_type !== atob("dmxlc3M=")) {
				return new Response("Not Found", { status: 404 });
			}
			return await SubscriptionService.generateText(user, host);
		} catch (err) {
			return new Response("Error building config: " + err.message, { status: 500 });
		}
	},
	async handlePanel(request, env) {
		const hasPassword = await DbService.getPanelPassword(env.DB);
		if (!hasPassword) {
			return new Response(HTML_TEMPLATES.setup, {
				headers: { "Content-Type": "text/html; charset=utf-8" },
			});
		}
		const authorized = await DbService.verifyApiAuth(request, env);
		if (!authorized) {
			return new Response(HTML_TEMPLATES.login, {
				headers: { "Content-Type": "text/html; charset=utf-8" },
			});
		}
		return new Response(HTML_TEMPLATES.panel, {
			headers: {
				"Content-Type": "text/html; charset=utf-8",
				"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
				Pragma: "no-cache",
				Expires: "0",
			},
		});
	},
	async handleUserStatus(url, env) {
		const username = decodeURIComponent(url.pathname.slice(8));
		if (!username) {
			return new Response("Username is required", { status: 400 });
		}
		try {
			const user = await env.DB.prepare("SELECT * FROM users WHERE username = ? OR uuid = ?").bind(username, username).first();
			if (!user) {
				return new Response("User not found", { status: 404 });
			}
			const userJson = JSON.stringify({
				username: user.username,
				uuid: user.uuid,
				limit_gb: user.limit_gb,
				expiry_days: user.expiry_days,
				used_gb: user.used_gb,
				limit_req: user.limit_req,
				used_req: user.used_req,
				is_active: user.is_active,
				online_count: getActiveIpCount(user.active_ips),
				ip_limit: user.ip_limit,
				created_at: user.created_at,
				tls: user.tls,
				port: user.port,
				ips: user.ips,
				fingerprint: user.fingerprint || "chrome",
			});
			const html = HTML_TEMPLATES.status.replace("/* {{USER_DATA_PLACEHOLDER}} */", `window.statusUser = ${userJson};`);
			return new Response(html, {
				headers: { "Content-Type": "text/html; charset=utf-8" },
			});
		} catch (err) {
			return new Response("Error: " + err.message, { status: 500 });
		}
	},
	async handleApi(request, url, env, ctx) {
		const hasPassword = await DbService.getPanelPassword(env.DB);
		if (url.pathname === "/api/setup-password" && request.method === "POST") {
			if (hasPassword) {
				return new Response(JSON.stringify({ error: "رمز عبور از قبل تعریف شده است" }), {
					status: 400,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
			const { password } = await request.json();
			if (!password || password.length < 4) {
				return new Response(JSON.stringify({ error: "رمز عبور باید حداقل ۴ کاراکتر باشد" }), {
					status: 400,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
			const hashed = await DbService.sha256(password);
			await DbService.setPanelPassword(env.DB, hashed);
			return new Response(JSON.stringify({ success: true }), {
				headers: {
					"Content-Type": "application/json; charset=utf-8",
					"Set-Cookie": "panel_session=" + hashed + "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=31536000",
				},
			});
		}
		if (url.pathname === "/api/login" && request.method === "POST") {
			const { password } = await request.json();
			const hashedInput = await DbService.sha256(password);
			const storedHash = await DbService.getPanelPassword(env.DB);
			if (storedHash === hashedInput) {
				return new Response(JSON.stringify({ success: true }), {
					headers: {
						"Content-Type": "application/json; charset=utf-8",
						"Set-Cookie": "panel_session=" + storedHash + "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=31536000",
					},
				});
			}
			return new Response(JSON.stringify({ error: "رمز عبور اشتباه است" }), {
				status: 401,
				headers: { "Content-Type": "application/json; charset=utf-8" },
			});
		}
		if (url.pathname === "/api/logout" && request.method === "POST") {
			return new Response(JSON.stringify({ success: true }), {
				headers: {
					"Content-Type": "application/json; charset=utf-8",
					"Set-Cookie": "panel_session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; SameSite=Lax",
				},
			});
		}
		if (url.pathname === "/api/recover" && request.method === "POST") {
			const { api_token } = await request.json();
			if (!api_token) {
				return new Response(JSON.stringify({ error: "Token is required" }), {
					status: 400,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
			try {
				const cfRes = await fetch("https://api.cloudflare.com/client/v4/user/tokens/verify", {
					headers: { Authorization: "Bearer " + api_token },
				});
				const cfData = await cfRes.json();
				if (!cfRes.ok || !cfData.success) {
					return new Response(JSON.stringify({ error: "Invalid or expired Cloudflare token" }), {
						status: 401,
						headers: { "Content-Type": "application/json; charset=utf-8" },
					});
				}
				const host = url.hostname;
				let isAuthorized = false;
				if (host.endsWith(".workers.dev")) {
					const parts = host.split(".");
					const targetSubdomain = parts[parts.length - 3];
					const accountsRes = await fetch("https://api.cloudflare.com/client/v4/accounts", {
						headers: { Authorization: "Bearer " + api_token },
					});
					const accountsData = await accountsRes.json();
					if (accountsData.success && accountsData.result) {
						for (const acc of accountsData.result) {
							const subRes = await fetch(`https://api.cloudflare.com/client/v4/accounts/${acc.id}/workers/subdomain`, {
								headers: { Authorization: "Bearer " + api_token },
							});
							const subData = await subRes.json();
							if (subData.success && subData.result && subData.result.subdomain === targetSubdomain) {
								isAuthorized = true;
								break;
							}
						}
					}
				} else {
					const zonesRes = await fetch("https://api.cloudflare.com/client/v4/zones", {
						headers: { Authorization: "Bearer " + api_token },
					});
					const zonesData = await zonesRes.json();
					if (zonesData.success && zonesData.result) {
						for (const zone of zonesData.result) {
							if (host === zone.name || host.endsWith("." + zone.name)) {
								isAuthorized = true;
								break;
							}
						}
					}
				}
				if (!isAuthorized) {
					return new Response(JSON.stringify({ error: "این توکن متعلق به صاحب پنل نیست (ای کــثـــکـــش)" }), {
						status: 403,
						headers: { "Content-Type": "application/json; charset=utf-8" },
					});
				}
				await env.DB.prepare("DELETE FROM settings WHERE key = 'panel_password'").run();
				cachedPanelPassword = null;
				return new Response(JSON.stringify({ success: true }), {
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			} catch (err) {
				return new Response(JSON.stringify({ error: "Cloudflare API connection error" }), {
					status: 500,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
		}
		if (url.pathname === "/api/portal/packages" && request.method === "GET") {
			const { results } = await env.DB.prepare("SELECT * FROM packages WHERE is_active = 1 ORDER BY display_order ASC").all();
			return new Response(JSON.stringify({ ok: true, packages: results || [] }), { headers: { "Content-Type": "application/json" } });
		}
		const portalMatch = url.pathname.match(/^\/api\/portal\/([^/]+)(\/.*)?$/);
		if (portalMatch) {
			const uuid = portalMatch[1];
			const sub = portalMatch[2] || "";
			const user = await env.DB.prepare("SELECT * FROM users WHERE uuid = ? OR username = ?").bind(uuid, uuid).first();
			if (!user) return new Response(JSON.stringify({ ok: false, error: "not found" }), { status: 404, headers: { "Content-Type": "application/json" } });
			if (sub === "" && request.method === "GET") {
				const hasSubscription = Boolean(user.limit_gb) || Boolean(user.expiry_days);
				const totalMb = Number(user.limit_gb || 0) * 1024;
				const usedMb = Number(user.used_gb || 0) * 1024;
				let configText = null;
				if (hasSubscription) {
					try {
						const subResp = await SubscriptionService.generateText(user, url.hostname);
						const decoded = atob((await subResp.text()).trim());
						configText = decoded
							.split("\n")
							.map((l) => l.trim())
							.filter((l) => l.startsWith(atob("dmxlc3M6Ly8=")))
							.join("\n");
					} catch (e) {}
				}
				return new Response(
					JSON.stringify({
						ok: true,
						customer: { name: user.name, phone: user.phone },
						has_subscription: hasSubscription,
						subscription: {
							total_mb: totalMb,
							remaining_mb: Math.max(0, totalMb - usedMb),
							used_pct: totalMb > 0 ? Math.min(100, Math.round((usedMb / totalMb) * 100)) : 0,
							expdate: addDaysIso(user.created_at, user.expiry_days),
							duration_days: user.expiry_days,
							created_at: user.created_at,
							config_text: configText,
						},
					}),
					{ headers: { "Content-Type": "application/json" } },
				);
			}
			if (sub === "/payment" && request.method === "POST") {
				const { package_id } = await request.json().catch(() => ({}));
				const pkg = await env.DB.prepare("SELECT * FROM packages WHERE id = ? AND is_active = 1").bind(package_id).first();
				if (!pkg) return new Response(JSON.stringify({ ok: false, error: "بسته یافت نشد" }), { status: 404, headers: { "Content-Type": "application/json" } });
				const settingsRows = (await env.DB.prepare("SELECT key, value FROM settings").all()).results || [];
				const settings = Object.fromEntries(settingsRows.map((r) => [r.key, r.value]));
				const priceToman = Number(pkg.price_irr || 0);
				const expiresMinutes = 30;
				const expiresAt = new Date(Date.now() + expiresMinutes * 60000).toISOString();
				const payRes = await env.DB
					.prepare("INSERT INTO payments (username, package_id, amount_irr, status, pkg_name, expires_at) VALUES (?,?,?,?,?,?)")
					.bind(user.username, pkg.id, priceToman, "pending", pkg.name, expiresAt)
					.run();
				const paymentId = payRes.meta.last_row_id;
				const methods = {};
				if (settings.payment_tetra_enabled === "1" && settings.tetra_api_key) {
					const orderIdStr = "CRAB-" + paymentId;
					const amountRials = priceToman * 10 + Math.floor(Math.random() * 900) * 10;
					const redirectUrl = (settings.portal_base_url || "") + "/status/" + user.uuid;
					const aryallehBase = settings.aryalleh_base_url || ARYALLEHPAY_BASE;
					const res = await AryallehPay.create(settings.tetra_api_key, {
						orderId: orderIdStr,
						amountRials,
						description: pkg.name,
						expiresMinutes,
						redirectUrl,
						baseUrl: aryallehBase,
					});
					if (res.ok) {
						const fullUrl = res.pay_url && res.pay_url.startsWith("http") ? res.pay_url : aryallehBase + res.pay_url;
						await env.DB.prepare("UPDATE payments SET tetra_pay_token=?, tetra_pay_url=? WHERE id=?").bind(res.pay_token, fullUrl, paymentId).run();
						methods.tetra = { url: fullUrl };
					} else {
						methods.tetra = { error: true };
					}
				}
				return new Response(JSON.stringify({ ok: true, payment_id: paymentId, methods, expires_at: expiresAt }), { headers: { "Content-Type": "application/json" } });
			}
			const statusMatch = sub.match(/^\/payment\/(\d+)\/status$/);
			if (statusMatch && request.method === "GET") {
				const row = await env.DB.prepare("SELECT * FROM payments WHERE id = ? AND username = ?").bind(statusMatch[1], user.username).first();
				if (!row) return new Response(JSON.stringify({ ok: false, error: "not found" }), { status: 404, headers: { "Content-Type": "application/json" } });
				let status = row.status;
				if (status === "pending" && row.expires_at && Date.now() > new Date(row.expires_at).getTime()) {
					status = "expired";
					await env.DB.prepare("UPDATE payments SET status = 'expired' WHERE id = ?").bind(row.id).run();
				}
				return new Response(JSON.stringify({ ok: true, status }), { headers: { "Content-Type": "application/json" } });
			}
			return new Response(JSON.stringify({ ok: false, error: "not found" }), { status: 404, headers: { "Content-Type": "application/json" } });
		}
		if (url.pathname === "/api/payment/callback" && request.method === "POST") {
			const b = await request.json().catch(() => ({}));
			if (b.event !== "payment.confirmed" || !b.order_id) return new Response(JSON.stringify({ ok: true }), { headers: { "Content-Type": "application/json" } });
			const m = String(b.order_id).match(/^CRAB-(\d+)$/);
			if (!m) return new Response(JSON.stringify({ ok: true }), { headers: { "Content-Type": "application/json" } });
			const paymentId = Number(m[1]);
			const payment = await env.DB.prepare("SELECT * FROM payments WHERE id = ?").bind(paymentId).first();
			if (!payment) return new Response(JSON.stringify({ ok: true }), { headers: { "Content-Type": "application/json" } });
			if (payment.tetra_tx_id) return new Response(JSON.stringify({ ok: true, message: "already processed" }), { headers: { "Content-Type": "application/json" } });
			await env.DB.prepare("UPDATE payments SET tetra_tx_id = ?, method = 'tetra' WHERE id = ?").bind(String(b.tx_id || ""), paymentId).run();
			await activateUserPayment(env, payment);
			return new Response(JSON.stringify({ ok: true }), { headers: { "Content-Type": "application/json" } });
		}
		if (url.pathname === "/api/telegram/webhook" && request.method === "POST") {
			const settingsRows = (await env.DB.prepare("SELECT key, value FROM settings").all()).results || [];
			const tgSettings = Object.fromEntries(settingsRows.map((r) => [r.key, r.value]));
			const secretHeader = request.headers.get("X-Telegram-Bot-Api-Secret-Token");
			if (!tgSettings.telegram_bot_token || !tgSettings.telegram_webhook_secret || secretHeader !== tgSettings.telegram_webhook_secret) {
				return new Response("ok");
			}
			const update = await request.json().catch(() => ({}));
			const msg = update.message;
			if (msg && msg.text && msg.text.trim().startsWith("/start")) {
				const chatId = msg.chat.id;
				const fromId = String(msg.from.id);
				const name = msg.from.first_name || msg.from.username || "کاربر";
				if (tgSettings.telegram_gate_channel_id) {
					const memberRes = await Telegram.call(tgSettings.telegram_bot_token, "getChatMember", {
						chat_id: tgSettings.telegram_gate_channel_id,
						user_id: msg.from.id,
					});
					const status = memberRes.result && memberRes.result.status;
					if (!memberRes.ok || !["member", "administrator", "creator"].includes(status)) {
						await Telegram.call(tgSettings.telegram_bot_token, "sendMessage", {
							chat_id: chatId,
							text: "برای استفاده از ربات، اول باید عضو این کانال بشی: " + tgSettings.telegram_gate_channel_id,
						});
						return new Response("ok");
					}
				}
				let user = await env.DB.prepare("SELECT * FROM users WHERE telegram_user_id = ?").bind(fromId).first();
				let isNew = false;
				if (!user) {
					isNew = true;
					const username = "tg" + fromId;
					const uuid = crypto.randomUUID();
					try {
						await env.DB
							.prepare(
								"INSERT INTO users (username, uuid, connection_type, tls, port, fingerprint, ip_limit, used_gb, used_req, created_at, is_active, block_porn, block_ads, frag_len, frag_int, name, telegram_user_id) VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0, ?, 1, 0, 0, '20-30', '1-2', ?, ?)",
							)
							.bind(username, uuid, atob("dmxlc3M="), "tls", 443, "chrome", 0, new Date().toISOString(), name, fromId)
							.run();
					} catch (e) {
						return new Response("ok");
					}
					user = await env.DB.prepare("SELECT * FROM users WHERE telegram_user_id = ?").bind(fromId).first();
				}
				const portalBase = tgSettings.portal_base_url || url.origin;
				const portalUrl = portalBase.replace(/\/$/, "") + "/status/" + user.uuid;
				await Telegram.call(tgSettings.telegram_bot_token, "sendMessage", {
					chat_id: chatId,
					text: (isNew ? "🦀 خوش اومدی!\n\n" : "") + "پورتال شخصی شما:\n" + portalUrl,
				});
				if (isNew && tgSettings.telegram_channel_id) {
					await Telegram.call(tgSettings.telegram_bot_token, "sendMessage", {
						chat_id: tgSettings.telegram_channel_id,
						text: "👤 کاربر جدید از ربات: " + name,
					});
				}
			}
			return new Response("ok");
		}
		const authorized = await DbService.verifyApiAuth(request, env);
		if (!authorized) {
			return new Response(JSON.stringify({ error: "Unauthorized" }), {
				status: 401,
				headers: { "Content-Type": "application/json; charset=utf-8" },
			});
		}
		if (url.pathname === "/api/update-panel" && request.method === "POST") {
			const body = await request.json().catch(() => ({}));
			let currentToken = env.CF_API_TOKEN || body.cf_token;
			let currentAccountId = env.CF_ACCOUNT_ID;

			if (!currentToken) {
				return new Response(JSON.stringify({ error: "TOKEN_REQUIRED" }), { status: 400, headers: { "Content-Type": "application/json" } });
			}

			try {
				if (!currentAccountId) {
					const accRes = await fetch("https://api.cloudflare.com/client/v4/accounts", {
						headers: { Authorization: "Bearer " + currentToken },
					});
					const accData = await accRes.json();
					if (!accData.success || accData.result.length === 0) throw new Error("توکن نامعتبر است یا اکانتی یافت نشد.");
					currentAccountId = accData.result[0].id;
				}

				const githubRes = await fetch("https://raw.githubusercontent.com/IR-NETLIFY/zeus/refs/heads/main/zeus.js?t=" + Date.now() + Math.random(), {
					headers: {
						"Cache-Control": "no-cache, no-store, must-revalidate",
						Pragma: "no-cache",
						Expires: "0",
					},
				});
				if (!githubRes.ok) throw new Error("خطا در دریافت سورس جدید از گیت‌هاب");
				const newCode = await githubRes.text();

				const scriptName = env.WORKER_NAME || url.hostname.split(".")[0];
				const bindingsRes = await fetch(`https://api.cloudflare.com/client/v4/accounts/${currentAccountId}/workers/scripts/${scriptName}/bindings`, {
					headers: { Authorization: "Bearer " + currentToken },
				});
				const bindingsData = await bindingsRes.json();
				if (!bindingsData.success) throw new Error("عدم دسترسی به تنظیمات ورکر. توکن نامعتبر است.");

				const newBindings = [];
				for (const b of bindingsData.result) {
					if (b.type === "d1") {
						newBindings.push({ type: "d1", name: b.name, id: b.database_id || b.id });
					} else if (b.name === "CF_API_TOKEN") {
						newBindings.push({ type: "secret_text", name: "CF_API_TOKEN", text: currentToken });
					} else if (b.name === "CF_ACCOUNT_ID") {
						newBindings.push({ type: "secret_text", name: "CF_ACCOUNT_ID", text: currentAccountId });
					}
				}

				if (!newBindings.some((b) => b.name === "CF_API_TOKEN")) {
					newBindings.push({ type: "secret_text", name: "CF_API_TOKEN", text: currentToken });
				}
				if (!newBindings.some((b) => b.name === "CF_ACCOUNT_ID")) {
					newBindings.push({ type: "secret_text", name: "CF_ACCOUNT_ID", text: currentAccountId });
				}

				const metadata = {
					main_module: "zeus.js",
					compatibility_date: "2024-02-08",
					bindings: newBindings,
				};

				const formData = new FormData();
				formData.append("metadata", new Blob([JSON.stringify(metadata)], { type: "application/json" }));
				formData.append("zeus.js", new Blob([newCode], { type: "application/javascript+module" }), "zeus.js");

				const deployRes = await fetch(`https://api.cloudflare.com/client/v4/accounts/${currentAccountId}/workers/scripts/${scriptName}`, {
					method: "PUT",
					headers: { Authorization: "Bearer " + currentToken },
					body: formData,
				});
				const deployData = await deployRes.json();
				if (!deployData.success) throw new Error("خطا در اعمال آپدیت در کلودفلر.");

				return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
			} catch (err) {
				const errorMsg = err.message + " | در صورت عدم موفقیت، از طریق لینک زیر آپدیت کنید: https://zeus-panel.ir-netlify.workers.dev/";
				return new Response(JSON.stringify({ error: errorMsg }), { status: 500, headers: { "Content-Type": "application/json" } });
			}
		}
		if (url.pathname === "/api/restart-core" && request.method === "POST") {
			let currentToken = env.CF_API_TOKEN;
			let currentAccountId = env.CF_ACCOUNT_ID;

			if (!currentToken || !currentAccountId) {
				return new Response(JSON.stringify({ error: "TOKEN_REQUIRED" }), { status: 400, headers: { "Content-Type": "application/json" } });
			}

			try {
				const githubRes = await fetch("https://raw.githubusercontent.com/IR-NETLIFY/zeus/refs/heads/main/zeus.js?t=" + Date.now(), {
					headers: {
						"Cache-Control": "no-cache, no-store, must-revalidate",
						Pragma: "no-cache",
						Expires: "0",
					},
				});
				if (!githubRes.ok) throw new Error("خطا در دریافت سورس از گیت‌هاب");
				const newCode = await githubRes.text();

				const scriptName = env.WORKER_NAME || url.hostname.split(".")[0];
				const bindingsRes = await fetch(`https://api.cloudflare.com/client/v4/accounts/${currentAccountId}/workers/scripts/${scriptName}/bindings`, {
					headers: { Authorization: "Bearer " + currentToken },
				});
				const bindingsData = await bindingsRes.json();
				if (!bindingsData.success) throw new Error("عدم دسترسی به تنظیمات ورکر");

				const newBindings = [];
				for (const b of bindingsData.result) {
					if (b.type === "d1") {
						newBindings.push({ type: "d1", name: b.name, id: b.database_id || b.id });
					}
				}

				newBindings.push({ type: "secret_text", name: "CF_API_TOKEN", text: currentToken });
				newBindings.push({ type: "secret_text", name: "CF_ACCOUNT_ID", text: currentAccountId });

				const metadata = {
					main_module: "zeus.js",
					compatibility_date: "2024-02-08",
					bindings: newBindings,
				};

				const formData = new FormData();
				formData.append("metadata", new Blob([JSON.stringify(metadata)], { type: "application/json" }));
				formData.append("zeus.js", new Blob([newCode], { type: "application/javascript+module" }), "zeus.js");

				const deployRes = await fetch(`https://api.cloudflare.com/client/v4/accounts/${currentAccountId}/workers/scripts/${scriptName}`, {
					method: "PUT",
					headers: { Authorization: "Bearer " + currentToken },
					body: formData,
				});
				const deployData = await deployRes.json();
				if (!deployData.success) throw new Error("خطا در اعمال ری‌استارت در کلودفلر");

				return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
			} catch (err) {
				return new Response(JSON.stringify({ error: err.message }), { status: 500, headers: { "Content-Type": "application/json" } });
			}
		}
		if (url.pathname === "/api/change-password" && request.method === "POST") {
			const { current_password, new_password } = await request.json();
			if (!current_password || !new_password) {
				return new Response(JSON.stringify({ error: "رمز عبور فعلی و جدید الزامی هستند" }), {
					status: 400,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
			const currentHash = await DbService.sha256(current_password);
			const storedHash = await DbService.getPanelPassword(env.DB);
			if (storedHash && storedHash !== currentHash) {
				return new Response(JSON.stringify({ error: "رمز عبور فعلی اشتباه است" }), {
					status: 401,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
			if (new_password.length < 4) {
				return new Response(JSON.stringify({ error: "رمز عبور جدید باید حداقل ۴ کاراکتر باشد" }), {
					status: 400,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
			const newHash = await DbService.sha256(new_password);
			await DbService.setPanelPassword(env.DB, newHash);
			return new Response(JSON.stringify({ success: true }), {
				headers: {
					"Content-Type": "application/json; charset=utf-8",
					"Set-Cookie": "panel_session=" + newHash + "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=31536000",
				},
			});
		}
		if (url.pathname === "/locations") {
			try {
				const response = await fetch("https://speed.cloudflare.com/locations", {
					headers: { Referer: "https://speed.cloudflare.com/" },
				});
				const data = await response.json();
				return new Response(JSON.stringify(data), {
					headers: { "Content-Type": "application/json; charset=utf-8", "Access-Control-Allow-Origin": "*" },
				});
			} catch (e) {
				return new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { "Content-Type": "application/json" } });
			}
		}
		if (url.pathname === "/api/settings/bulk") {
			if (request.method === "GET") {
				try {
					const { results } = await env.DB.prepare("SELECT * FROM settings").all();
					const settingsObj = {};
					if (results) {
						results.forEach(r => { settingsObj[r.key] = r.value; });
					}
					return new Response(JSON.stringify(settingsObj), { headers: { "Content-Type": "application/json" } });
				} catch (e) {
					return new Response(JSON.stringify({}), { headers: { "Content-Type": "application/json" } });
				}
			}
			if (request.method === "POST") {
				const body = await request.json();
				if (body.settings && typeof body.settings === "object") {
					for (const [k, v] of Object.entries(body.settings)) {
						await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)").bind(k, String(v)).run();
					}
				}
				const result = { success: true };
				if (body.settings && body.settings.telegram_bot_token) {
					try {
						let secretRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'telegram_webhook_secret'").first();
						let secret = secretRow ? secretRow.value : null;
						if (!secret) {
							secret = crypto.randomUUID().replace(/-/g, "");
							await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('telegram_webhook_secret', ?)").bind(secret).run();
						}
						const portalRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'portal_base_url'").first();
						const base = (portalRow && portalRow.value) || url.origin;
						const webhookUrl = base.replace(/\/$/, "") + "/api/telegram/webhook";
						const setRes = await Telegram.call(body.settings.telegram_bot_token, "setWebhook", { url: webhookUrl, secret_token: secret });
						if (setRes.ok) {
							result.webhook_ok = true;
						} else {
							result.webhook_error = setRes.description || "setWebhook failed";
						}
					} catch (e) {
						result.webhook_error = e.message;
					}
				}
				return new Response(JSON.stringify(result), { headers: { "Content-Type": "application/json" } });
			}
		}
		if (url.pathname === "/api/proxy-ip") {
			if (request.method === "POST") {
				const { proxy_ip, iata, socks5 } = await request.json();
				if (proxy_ip) await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('proxy_ip', ?)").bind(proxy_ip).run();
				if (iata !== undefined) await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('proxy_location_iata', ?)").bind(iata).run();
				if (socks5 !== undefined) await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('socks5', ?)").bind(socks5).run();
				return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
			}
			if (request.method === "GET") {
				const rowIp = await env.DB.prepare("SELECT value FROM settings WHERE key = 'proxy_ip'").first();
				const rowIata = await env.DB.prepare("SELECT value FROM settings WHERE key = 'proxy_location_iata'").first();
				const rowSocks = await env.DB.prepare("SELECT value FROM settings WHERE key = 'socks5'").first();
				return new Response(
					JSON.stringify({
						proxy_ip: rowIp ? rowIp.value : "proxyip.cmliussss.net",
						iata: rowIata ? rowIata.value : "",
						socks5: rowSocks ? rowSocks.value : ""
					}),
					{ headers: { "Content-Type": "application/json" } },
				);
			}
		}
		if (url.pathname === "/api/test-proxy" && request.method === "POST") {
			const { proxy } = await request.json();
			if (!proxy) return new Response(JSON.stringify({ error: "پروکسی وارد نشده است" }), { status: 400, headers: { "Content-Type": "application/json" } });
			try {
				let ip = "";
				let workingProxy = proxy;
				if (proxy.includes("t.me/socks") || proxy.includes("tg://socks")) {
					ip = proxy.match(/server=([^&]+)/)?.[1] || "";
				} else {
					let cleanProxy = proxy.replace(/^(socks4|socks5|socks|http|https):\/\//i, '');
					let proxyParts = cleanProxy.split('@');
					ip = (proxyParts.length > 1 ? proxyParts[1] : proxyParts[0]).split(':')[0];
				}
				let country = "UN";
				if (ip) {
					try {
						const geoRes = await fetch(`http://ip-api.com/json/${ip}?fields=countryCode`);
						const geoData = await geoRes.json();
						if (geoData && geoData.countryCode) country = geoData.countryCode;
					} catch (e) {}
				}
				const startTime = Date.now();
				const s = await connectProxy(proxy, "1.1.1.1", 443, null);
				s.close();
				const ping = Date.now() - startTime;
				return new Response(JSON.stringify({ success: true, ping, country }), { headers: { "Content-Type": "application/json" } });
			} catch (e) {
				let msg = e.message;
				if (msg.includes("Stream was cancelled") || msg.includes("network")) msg = "ارتباط با سرور قطع شد (احتمالاً پروکسی مسدود یا خاموش است)";
				else if (msg.includes("timeout") || msg.includes("timed out")) msg = "تایم‌اوت در اتصال (پروکسی در دسترس نیست)";
				else if (msg.includes("Invalid URL") || msg.includes("Invalid format")) msg = "فرمت وارد شده برای پروکسی اشتباه است";
				else if (msg === "err") msg = "خطای نامشخص (ارتباط برقرار نشد)";
				return new Response(JSON.stringify({ error: msg }), { status: 500, headers: { "Content-Type": "application/json" } });
			}
		}
		if (url.pathname.startsWith("/api/users")) {
			const pathParts = url.pathname.split("/");
			const isUserAction = pathParts.length > 3;
			if (isUserAction) {
				const username = decodeURIComponent(pathParts.pop());
				if (request.method === "PUT") {
					const body = await request.json();
					if (body.toggle_only !== undefined) {
						await env.DB.prepare("UPDATE users SET is_active = CASE WHEN is_active = 1 THEN 0 ELSE 1 END WHERE username = ?").bind(username).run();
						return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
					} else if (body.reset_action !== undefined) {
						if (body.reset_action === "volume") {
							await env.DB.prepare("UPDATE users SET used_gb = 0 WHERE username = ?").bind(username).run();
							GLOBAL_TRAFFIC_CACHE.set(username, 0);
						} else if (body.reset_action === "req") {
							await env.DB.prepare("UPDATE users SET used_req = 0 WHERE username = ?").bind(username).run();
							USER_REQ_CACHE.set(username, 0);
						} else if (body.reset_action === "time") {
							await env.DB.prepare("UPDATE users SET created_at = CURRENT_TIMESTAMP WHERE username = ?").bind(username).run();
						}
						return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
					} else {
						const { username: new_username, limit_gb, expiry_days, limit_req, ips, tls, port, fingerprint, ip_limit, block_porn, block_ads, frag_len, frag_int } = body;
						if (new_username && new_username !== username) {
							const existing = await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(new_username).first();
							if (existing) {
								return new Response(JSON.stringify({ error: "این نام کاربری از قبل وجود دارد" }), { status: 400, headers: { "Content-Type": "application/json" } });
							}
							if (GLOBAL_TRAFFIC_CACHE.has(username)) {
								GLOBAL_TRAFFIC_CACHE.set(new_username, GLOBAL_TRAFFIC_CACHE.get(username));
								GLOBAL_TRAFFIC_CACHE.delete(username);
							}
							if (USER_REQ_CACHE.has(username)) {
								USER_REQ_CACHE.set(new_username, USER_REQ_CACHE.get(username));
								USER_REQ_CACHE.delete(username);
							}
							if (ACTIVE_CONNECTIONS_COUNT.has(username)) {
								ACTIVE_CONNECTIONS_COUNT.set(new_username, ACTIVE_CONNECTIONS_COUNT.get(username));
								ACTIVE_CONNECTIONS_COUNT.delete(username);
							}
							if (GLOBAL_LAST_ACTIVE_WRITE.has(username)) {
								GLOBAL_LAST_ACTIVE_WRITE.set(new_username, GLOBAL_LAST_ACTIVE_WRITE.get(username));
								GLOBAL_LAST_ACTIVE_WRITE.delete(username);
							}
						}
						await env.DB.prepare("UPDATE users SET username = ?, limit_gb = ?, expiry_days = ?, limit_req = ?, ips = ?, tls = ?, port = ?, fingerprint = ?, max_connections = ?, ip_limit = ?, block_porn = ?, block_ads = ?, frag_len = ?, frag_int = ? WHERE username = ?")
							.bind(new_username || username, limit_gb ? parseFloat(limit_gb) : null, expiry_days ? parseInt(expiry_days) : null, limit_req ? parseInt(limit_req) : null, ips || null, tls, port, fingerprint || "chrome", ip_limit ? parseInt(ip_limit) : null, ip_limit ? parseInt(ip_limit) : null, block_porn ? 1 : 0, block_ads ? 1 : 0, frag_len !== undefined ? frag_len : "20-30", frag_int !== undefined ? frag_int : "1-2", username)
							.run();
						return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
					}
				}
				if (request.method === "DELETE") {
					await env.DB.prepare("DELETE FROM users WHERE username = ?").bind(username).run();
					return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
				}
			} else {
				if (request.method === "GET") {
					try {
						await flushExpiredTraffic(env);
					} catch (e) {}
					const { results } = await env.DB.prepare("SELECT * FROM users ORDER BY id DESC").all();
					const now = Date.now();
					const enrichedUsers = (results || []).map((user) => ({
						...user,
						is_online: user.last_active && now - user.last_active < 25000 ? 1 : 0,
						online_count: getActiveIpCount(user.active_ips),
					}));
					let cfReqs = { today: 0, total: 0 };
					try {
						const liveCf = await getCfUsage(env);
						const todayStr = new Date().toISOString().split("T")[0];
						const dateRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'req_last_date'").first();
						const totalRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'req_total'").first();
						let dbTotal = totalRow ? parseInt(totalRow.value) || 0 : 0;
						let dbToday = 0;
						if (dateRow && dateRow.value === todayStr) {
							const todayRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'req_today'").first();
							dbToday = todayRow ? parseInt(todayRow.value) || 0 : 0;
						}
						if (liveCf.today > dbToday) {
							dbToday = liveCf.today;
							await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('req_today', ?) ON CONFLICT(key) DO UPDATE SET value = ?").bind(String(dbToday), String(dbToday)).run();
							await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('req_last_date', ?) ON CONFLICT(key) DO UPDATE SET value = ?").bind(todayStr, todayStr).run();
						}
						if (liveCf.total > dbTotal) {
							dbTotal = liveCf.total;
							await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('req_total', ?) ON CONFLICT(key) DO UPDATE SET value = ?").bind(String(dbTotal), String(dbTotal)).run();
						}
						cfReqs.today = dbToday + GLOBAL_REQ_COUNT;
						cfReqs.total = dbTotal + GLOBAL_REQ_COUNT;
					} catch (e) {}
					return new Response(
						JSON.stringify({
							users: enrichedUsers,
							serverTime: now,
							cfRequestsToday: cfReqs.today,
							cfRequestsTotal: cfReqs.total,
						}),
						{
							headers: {
								"Content-Type": "application/json",
								"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
							},
						},
					);
				}
				if (request.method === "POST") {
					const { username, uuid, limit_gb, expiry_days, limit_req, ips, tls, port, fingerprint, ip_limit, used_gb, used_req, created_at, is_active, block_porn, block_ads, frag_len, frag_int } = await request.json();
					if (!username) {
						return new Response(JSON.stringify({ error: "نام کاربری اجباری است" }), { status: 400, headers: { "Content-Type": "application/json" } });
					}
					if (username.length > 32) {
						return new Response(JSON.stringify({ error: "نام کاربری نمی‌تواند بیشتر از ۳۲ کاراکتر باشد" }), { status: 400, headers: { "Content-Type": "application/json" } });
					}
					const finalUuid = uuid || crypto.randomUUID();
					const parsedUsedGb = parseFloat(used_gb);
					const finalUsedGb = !isNaN(parsedUsedGb) ? parsedUsedGb : 0;
					const parsedUsedReq = parseInt(used_req);
					const finalUsedReq = !isNaN(parsedUsedReq) ? parsedUsedReq : 0;
					const finalCreatedAt = created_at || new Date().toISOString();
					const parsedIsActive = parseInt(is_active);
					const finalIsActive = !isNaN(parsedIsActive) ? parsedIsActive : 1;
					try {
						await env.DB.prepare("INSERT INTO users (username, uuid, limit_gb, expiry_days, limit_req, ips, connection_type, tls, port, fingerprint, max_connections, ip_limit, used_gb, used_req, created_at, is_active, block_porn, block_ads, frag_len, frag_int) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
							.bind(username, finalUuid, limit_gb ? parseFloat(limit_gb) : null, expiry_days ? parseInt(expiry_days) : null, limit_req ? parseInt(limit_req) : null, ips || null, atob("dmxlc3M="), tls, port, fingerprint || "chrome", ip_limit ? parseInt(ip_limit) : null, ip_limit ? parseInt(ip_limit) : null, finalUsedGb, finalUsedReq, finalCreatedAt, finalIsActive, block_porn ? 1 : 0, block_ads ? 1 : 0, frag_len !== undefined ? frag_len : "20-30", frag_int !== undefined ? frag_int : "1-2")
							.run();
						return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
					} catch (err) {
						return new Response(JSON.stringify({ error: err.message }), { status: 500, headers: { "Content-Type": "application/json" } });
					}
				}
			}
		}
		if (url.pathname === "/api/packages" && request.method === "GET") {
			const { results } = await env.DB.prepare("SELECT * FROM packages ORDER BY display_order ASC").all();
			return new Response(JSON.stringify({ ok: true, packages: results || [] }), { headers: { "Content-Type": "application/json" } });
		}
		if (url.pathname === "/api/packages/upsert" && request.method === "POST") {
			const b = await request.json().catch(() => ({}));
			if (!b.name) return new Response(JSON.stringify({ ok: false, error: "نام بسته اجباری است" }), { status: 400, headers: { "Content-Type": "application/json" } });
			if (b.id) {
				await env.DB
					.prepare("UPDATE packages SET name=?, traffic_amount=?, traffic_unit=?, price_irr=?, duration_days=?, display_order=?, is_active=? WHERE id=?")
					.bind(b.name, b.traffic_amount || 0, b.traffic_unit || "gb", b.price_irr, b.duration_days || 30, b.display_order || 0, b.is_active ? 1 : 0, b.id)
					.run();
			} else {
				await env.DB
					.prepare("INSERT INTO packages (name, traffic_amount, traffic_unit, price_irr, duration_days, display_order, is_active) VALUES (?,?,?,?,?,?,?)")
					.bind(b.name, b.traffic_amount || 0, b.traffic_unit || "gb", b.price_irr, b.duration_days || 30, b.display_order || 0, b.is_active ? 1 : 0)
					.run();
			}
			return new Response(JSON.stringify({ ok: true }), { headers: { "Content-Type": "application/json" } });
		}
		if (url.pathname === "/api/packages/delete" && request.method === "POST") {
			const { id } = await request.json().catch(() => ({}));
			await env.DB.prepare("DELETE FROM packages WHERE id = ?").bind(id).run();
			return new Response(JSON.stringify({ ok: true }), { headers: { "Content-Type": "application/json" } });
		}
		if (url.pathname === "/api/customers/create" && request.method === "POST") {
			const { name, phone, package_id } = await request.json().catch(() => ({}));
			if (!name || !package_id) return new Response(JSON.stringify({ ok: false, error: "نام و بسته اجباری است" }), { status: 400, headers: { "Content-Type": "application/json" } });
			const pkg = await env.DB.prepare("SELECT * FROM packages WHERE id = ?").bind(package_id).first();
			if (!pkg) return new Response(JSON.stringify({ ok: false, error: "بسته یافت نشد" }), { status: 404, headers: { "Content-Type": "application/json" } });
			const username = "u" + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
			const uuid = crypto.randomUUID();
			const limitGb = toMb(pkg.traffic_amount, pkg.traffic_unit) / 1024;
			try {
				await env.DB
					.prepare(
						"INSERT INTO users (username, uuid, limit_gb, expiry_days, connection_type, tls, port, fingerprint, ip_limit, used_gb, used_req, created_at, is_active, block_porn, block_ads, frag_len, frag_int, name, phone) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, ?, 1, 0, 0, '20-30', '1-2', ?, ?)",
					)
					.bind(username, uuid, limitGb, pkg.duration_days || 30, atob("dmxlc3M="), "tls", 443, "chrome", 0, new Date().toISOString(), name, phone || "")
					.run();
				return new Response(JSON.stringify({ ok: true, username, uuid }), { headers: { "Content-Type": "application/json" } });
			} catch (err) {
				return new Response(JSON.stringify({ ok: false, error: err.message }), { status: 500, headers: { "Content-Type": "application/json" } });
			}
		}
		const extendMatch = url.pathname.match(/^\/api\/users\/([^/]+)\/extend$/);
		if (extendMatch && request.method === "POST") {
			const username = decodeURIComponent(extendMatch[1]);
			const { extra_days, extra_mb } = await request.json().catch(() => ({}));
			const user = await env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(username).first();
			if (!user) return new Response(JSON.stringify({ ok: false, error: "کاربر یافت نشد" }), { status: 404, headers: { "Content-Type": "application/json" } });
			const newLimitGb = Number(user.limit_gb || 0) + Number(extra_mb || 0) / 1024;
			const newExpiryDays = Number(user.expiry_days || 0) + Number(extra_days || 0);
			await env.DB.prepare("UPDATE users SET limit_gb = ?, expiry_days = ? WHERE username = ?").bind(newLimitGb, newExpiryDays, username).run();
			return new Response(JSON.stringify({ ok: true }), { headers: { "Content-Type": "application/json" } });
		}
		if (url.pathname === "/api/usage/monthly" && request.method === "GET") {
			const { results } = await env.DB.prepare("SELECT * FROM monthly_usage ORDER BY month DESC LIMIT 12").all();
			const cf = await getCfUsage(env);
			return new Response(JSON.stringify({ ok: true, months: (results || []).reverse(), cfRequestsToday: cf.today, cfRequestsTotal: cf.total }), { headers: { "Content-Type": "application/json" } });
		}
		if (url.pathname === "/api/payments" && request.method === "GET") {
			const { results } = await env.DB.prepare("SELECT * FROM payments ORDER BY id DESC LIMIT 100").all();
			return new Response(JSON.stringify({ ok: true, payments: results || [] }), { headers: { "Content-Type": "application/json" } });
		}
		if (url.pathname === "/api/payments/approve" && request.method === "POST") {
			const { payment_id } = await request.json().catch(() => ({}));
			const payment = await env.DB.prepare("SELECT * FROM payments WHERE id = ?").bind(payment_id).first();
			if (!payment) return new Response(JSON.stringify({ ok: false, error: "پرداخت یافت نشد" }), { status: 404, headers: { "Content-Type": "application/json" } });
			if (payment.tetra_pay_token && !payment.tetra_tx_id) {
				const payRows = (await env.DB.prepare("SELECT key, value FROM settings WHERE key IN ('tetra_api_key','aryalleh_base_url')").all()).results || [];
				const paySettings = Object.fromEntries(payRows.map((r) => [r.key, r.value]));
				if (paySettings.tetra_api_key) await AryallehPay.manualConfirm(paySettings.tetra_api_key, payment.id, "manual admin approve", paySettings.aryalleh_base_url);
			}
			await activateUserPayment(env, payment);
			return new Response(JSON.stringify({ ok: true }), { headers: { "Content-Type": "application/json" } });
		}
		return new Response(JSON.stringify({ error: "Not Found" }), { status: 404, headers: { "Content-Type": "application/json" } });
	},
};
let schemaEnsured = false;
let cachedPanelPassword = null;
const DbService = {
	async ensureSchema(db) {
		if (schemaEnsured) return;
		try {
			await db
				.prepare(
					`
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT UNIQUE,
          uuid TEXT,
          limit_gb REAL,
          expiry_days INTEGER,
          ips TEXT,
          connection_type TEXT,
          tls TEXT,
          port INTEGER,
          used_gb REAL DEFAULT 0,
          is_active INTEGER DEFAULT 1,
          last_active INTEGER,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
      `,
				)
				.run();
		} catch (e) {}
		try {
			await db.prepare("ALTER TABLE users ADD COLUMN is_active INTEGER DEFAULT 1").run();
		} catch (e) {}
		try {
			await db.prepare("ALTER TABLE users ADD COLUMN last_active INTEGER").run();
		} catch (e) {}
		try {
			await db.prepare("ALTER TABLE users ADD COLUMN fingerprint TEXT DEFAULT 'chrome'").run();
		} catch (e) {}
		try {
			await db.prepare("ALTER TABLE users ADD COLUMN max_connections INTEGER").run();
		} catch (e) {}
		try {
			await db.prepare("ALTER TABLE users ADD COLUMN limit_req INTEGER").run();
		} catch (e) {}
		try {
			await db.prepare("ALTER TABLE users ADD COLUMN used_req INTEGER DEFAULT 0").run();
		} catch (e) {}
		try {
			await db.prepare("ALTER TABLE users ADD COLUMN ip_limit INTEGER DEFAULT NULL").run();
		} catch (e) {}
		try {
			await db.prepare("ALTER TABLE users ADD COLUMN active_ips TEXT DEFAULT NULL").run();
		} catch (e) {}
		try {
			await db.prepare("UPDATE users SET ip_limit = max_connections WHERE ip_limit IS NULL AND max_connections IS NOT NULL").run();
		} catch (e) {}
		try {
			await db.prepare("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)").run();
		} catch (e) {}
		try {
			await db.prepare("ALTER TABLE users ADD COLUMN block_porn INTEGER DEFAULT 0").run();
		} catch (e) {}
		try {
			await db.prepare("ALTER TABLE users ADD COLUMN block_ads INTEGER DEFAULT 0").run();
		} catch (e) {}
		try {
			await db.prepare("ALTER TABLE users ADD COLUMN frag_len TEXT DEFAULT '20-30'").run();
		} catch (e) {}
		try {
			await db.prepare("ALTER TABLE users ADD COLUMN frag_int TEXT DEFAULT '1-2'").run();
		} catch (e) {}
		try {
			await db.prepare("ALTER TABLE users ADD COLUMN name TEXT").run();
		} catch (e) {}
		try {
			await db.prepare("ALTER TABLE users ADD COLUMN phone TEXT").run();
		} catch (e) {}
		try {
			await db.prepare("ALTER TABLE users ADD COLUMN telegram_user_id TEXT").run();
		} catch (e) {}
		try {
			await db
				.prepare(
					`CREATE TABLE IF NOT EXISTS packages (
						id INTEGER PRIMARY KEY AUTOINCREMENT,
						name TEXT NOT NULL,
						traffic_amount INTEGER DEFAULT 0,
						traffic_unit TEXT DEFAULT 'gb',
						price_irr REAL,
						duration_days INTEGER DEFAULT 30,
						display_order INTEGER DEFAULT 0,
						is_active INTEGER DEFAULT 1
					)`,
				)
				.run();
		} catch (e) {}
		try {
			await db
				.prepare(
					`CREATE TABLE IF NOT EXISTS payments (
						id INTEGER PRIMARY KEY AUTOINCREMENT,
						username TEXT NOT NULL,
						package_id INTEGER,
						method TEXT,
						amount_irr REAL,
						status TEXT DEFAULT 'pending',
						card_number TEXT,
						card_owner TEXT,
						tetra_pay_token TEXT,
						tetra_pay_url TEXT,
						tetra_tx_id TEXT,
						pkg_name TEXT,
						expires_at TEXT,
						created_at TEXT DEFAULT CURRENT_TIMESTAMP
					)`,
				)
				.run();
		} catch (e) {}
		try {
			await db
				.prepare(
					`CREATE TABLE IF NOT EXISTS monthly_usage (
						month TEXT PRIMARY KEY,
						traffic_gb REAL DEFAULT 0,
						requests INTEGER DEFAULT 0
					)`,
				)
				.run();
		} catch (e) {}
		schemaEnsured = true;
	},
	async getPanelPassword(db) {
		if (cachedPanelPassword !== null) return cachedPanelPassword;
		try {
			const row = await db.prepare("SELECT value FROM settings WHERE key = 'panel_password'").first();
			cachedPanelPassword = row ? row.value : "";
			return cachedPanelPassword || null;
		} catch (e) {
			return null;
		}
	},
	async setPanelPassword(db, password) {
		await db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('panel_password', ?)").bind(password).run();
		cachedPanelPassword = password;
	},
	async verifyApiAuth(request, env) {
		const storedPasswordHash = await this.getPanelPassword(env.DB);
		if (!storedPasswordHash) return true;
		const cookies = request.headers.get("Cookie") || "";
		const sessionCookie = cookies.split(";").find((c) => c.trim().startsWith("panel_session="));
		if (!sessionCookie) return false;
		const sessionToken = sessionCookie.split("=")[1].trim();
		return sessionToken === storedPasswordHash;
	},
	async sha256(message) {
		const msgBuffer = new TextEncoder().encode(message);
		const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
		const hashArray = Array.from(new Uint8Array(hashBuffer));
		return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
	},
};
const ARYALLEHPAY_BASE = "https://pay.aryalleh.ir";
function toMb(amount, unit) {
	const n = Number(amount) || 0;
	return unit === "mb" ? n : n * 1024;
}
function addDaysIso(fromIso, days) {
	const base = fromIso ? new Date(fromIso) : new Date();
	const d = new Date(base.getTime() + Number(days || 0) * 86400000);
	return d.toISOString().slice(0, 10);
}
const Telegram = {
	async call(token, method, params) {
		try {
			const res = await fetch(`https://api.telegram.org/bot${token}/${method}`, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify(params || {}),
			});
			return await res.json();
		} catch (e) {
			return { ok: false, description: e.message };
		}
	},
};
const AryallehPay = {
	async create(apiKey, { orderId, amountRials, description, expiresMinutes, redirectUrl, baseUrl }) {
		const res = await fetch((baseUrl || ARYALLEHPAY_BASE) + "/api/payment/create", {
			method: "POST",
			headers: { Authorization: "Bearer " + apiKey, "Content-Type": "application/json" },
			body: JSON.stringify({ order_id: orderId, amount_rials: amountRials, description, expires_minutes: expiresMinutes, redirect_url: redirectUrl }),
		});
		const d = await res.json().catch(() => ({}));
		return { ok: res.ok && d.ok, ...d };
	},
	async manualConfirm(apiKey, paymentId, note, baseUrl) {
		const res = await fetch((baseUrl || ARYALLEHPAY_BASE) + "/api/payment/manual-confirm", {
			method: "POST",
			headers: { Authorization: "Bearer " + apiKey, "Content-Type": "application/json" },
			body: JSON.stringify({ payment_id: paymentId, note }),
		});
		const d = await res.json().catch(() => ({}));
		return { ok: res.ok && d.ok, ...d };
	},
};
async function activateUserPayment(env, payment) {
	if (payment.status === "approved") return;
	await env.DB.prepare("UPDATE payments SET status = 'approved' WHERE id = ?").bind(payment.id).run();
	const user = await env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(payment.username).first();
	if (!user) return;
	const pkg = payment.package_id ? await env.DB.prepare("SELECT * FROM packages WHERE id = ?").bind(payment.package_id).first() : null;
	if (!pkg) return;
	const extraGb = toMb(pkg.traffic_amount, pkg.traffic_unit) / 1024;
	const newLimitGb = Number(user.limit_gb || 0) + extraGb;
	const newExpiryDays = Number(user.expiry_days || 0) + Number(pkg.duration_days || 30);
	await env.DB.prepare("UPDATE users SET limit_gb = ?, expiry_days = ? WHERE username = ?").bind(newLimitGb, newExpiryDays, user.username).run();
}
function getActiveIpCount(activeIpsJson) {
	if (!activeIpsJson) return 0;
	try {
		const activeIps = JSON.parse(activeIpsJson);
		const now = Date.now();
		let count = 0;
		for (const [ip, data] of Object.entries(activeIps)) {
			const lastSeen = data && typeof data === "object" ? data.timestamp : data;
			if (now - lastSeen <= 30000) {
				count++;
			}
		}
		return count;
	} catch (e) {
		return 0;
	}
}
const SubscriptionService = {
	async generateText(user, host) {
		let ips = [host];
		if (user.ips) {
			const parsedIps = user.ips
				.split("\n")
				.map((ip) => ip.trim())
				.filter((ip) => ip.length > 0);
			if (parsedIps.length > 0) ips = parsedIps;
		}
		const ports = String(user.port || "443")
			.split(",")
			.map((p) => p.trim())
			.filter((p) => p.length > 0);
		const fp = user.fingerprint || "chrome";
		const links = [];
		const m2 = decodeURIComponent("%F0%9F%9A%80%40CrabVPN%20%DA%A9%D8%A7%D9%86%D8%A7%D9%84%20%D9%85%D8%A7%F0%9F%9A%80");
		links.push(atob("dmxlc3M6Ly8=") + user.uuid + "@0.0.0.0:1?encryption=none&security=none&type=ws&host=" + host + "&path=%2FIn_Panel_Rayeghan_Ast_Va_Gheyre_Ghabele_Foroosh#" + encodeURIComponent(m2));
		let remVol = "Unlimited";
		if (user.limit_gb) {
			let rem = user.limit_gb - (user.used_gb || 0);
			remVol = rem > 0 ? rem.toFixed(2) + "GB" : "0GB";
		}
		let remTime = "Unlimited";
		if (user.expiry_days && user.created_at) {
			const created = new Date(user.created_at);
			const expiryDate = new Date(created.getTime() + user.expiry_days * 24 * 60 * 60 * 1000);
			const diffDays = Math.ceil((expiryDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
			remTime = diffDays > 0 ? diffDays + "Days" : "0Days";
		}
		let remReq = "Unlimited";
		if (user.limit_req) {
			let rem = user.limit_req - (user.used_req || 0);
			remReq = rem > 0 ? rem.toLocaleString() + "Req" : "0Req";
		}
		const infoRemark = "📊 remaining | \u200E" + remVol + " | \u200E" + remTime + " | \u200E" + remReq;
		links.push(atob("dmxlc3M6Ly8=") + user.uuid + "@" + host + ":80?path=%2FIn_Panel_Rayeghan_Ast_Va_Gheyre_Ghabele_Foroosh&security=none&encryption=none&host=" + host + "&fp=" + fp + "&type=ws#" + encodeURIComponent(infoRemark));
		ips.forEach((ip) => {
			ports.forEach((portStr) => {
				const isTlsPort = ["443", "2053", "2083", "2087", "2096", "8443"].includes(portStr);
				const tlsVal = isTlsPort ? "tls" : "none";
				const userFrag = user.frag_len && user.frag_int ? "&fragment=" + user.frag_len + "," + user.frag_int : "";
				const remark = user.username + " | \u200E" + ip + " | \u200E" + portStr;
				links.push(atob("dmxlc3M6Ly8=") + user.uuid + "@" + ip + ":" + portStr + "?path=%2FIn_Panel_Rayeghan_Ast_Va_Gheyre_Ghabele_Foroosh&security=" + tlsVal + "&encryption=none&insecure=0&host=" + host + "&fp=" + fp + "&type=ws&allowInsecure=0&sni=" + host + userFrag + "#" + encodeURIComponent(remark));
			});
		});
		const noise = ["# System Update Feed: OK", "# Sync Code: " + Math.random().toString(36).slice(2, 10), "# Version: 2.10.1", "# Description: Secure Node Configurations", ""].join("\n");
		const plainContent = noise + links.join("\n");
		const subContent = btoa(unescape(encodeURIComponent(plainContent)));
		const downloadBytes = Math.floor((user.used_gb || 0) * 1073741824);
		const totalBytes = user.limit_gb ? Math.floor(user.limit_gb * 1073741824) : 0;
		let expireTimestamp = 0;
		if (user.expiry_days && user.created_at) {
			expireTimestamp = Math.floor((new Date(user.created_at).getTime() + user.expiry_days * 86400000) / 1000);
		}
		const subUserInfo = `upload=0; download=${downloadBytes}; total=${totalBytes}; expire=${expireTimestamp}`;
		return new Response(subContent, {
			headers: {
				"Content-Type": "text/plain; charset=utf-8",
				"Access-Control-Allow-Origin": "*",
				"Cache-Control": "no-store",
				"Subscription-Userinfo": subUserInfo,
			},
		});
	},
};
async function bumpMonthlyUsage(env, deltaGb, deltaReq) {
	if (deltaGb <= 0 && deltaReq <= 0) return;
	try {
		const month = new Date().toISOString().slice(0, 7);
		await env.DB.prepare(
			"INSERT INTO monthly_usage (month, traffic_gb, requests) VALUES (?, ?, ?) ON CONFLICT(month) DO UPDATE SET traffic_gb = traffic_gb + excluded.traffic_gb, requests = requests + excluded.requests",
		)
			.bind(month, deltaGb, deltaReq)
			.run();
	} catch (e) {}
}
async function flushExpiredTraffic(env) {
	const now = Date.now();
	for (const [uname, cachedBytes] of GLOBAL_TRAFFIC_CACHE.entries()) {
		const cachedReqs = USER_REQ_CACHE.get(uname) || 0;
		if (cachedBytes <= 0 && cachedReqs <= 0) continue;
		if (GLOBAL_WRITE_LOCK.get(uname)) continue;
		const lastActive = GLOBAL_LAST_ACTIVE_WRITE.get(uname) || 0;
		const activeCount = ACTIVE_CONNECTIONS_COUNT.get(uname) || 0;
		if (activeCount <= 0 || now - lastActive > 25000) {
			GLOBAL_WRITE_LOCK.set(uname, true);
			const deltaGb = cachedBytes / (1024 * 1024 * 1024);
			try {
				await env.DB.prepare("UPDATE users SET used_gb = used_gb + ?, used_req = used_req + ? WHERE username = ?").bind(deltaGb, cachedReqs, uname).run();
				await bumpMonthlyUsage(env, deltaGb, cachedReqs);
			} catch (e) {
				console.error(e.message);
			} finally {
				GLOBAL_WRITE_LOCK.delete(uname);
				GLOBAL_TRAFFIC_CACHE.delete(uname);
				USER_REQ_CACHE.delete(uname);
				GLOBAL_LAST_ACTIVE_WRITE.delete(uname);
			}
		}
	}
}
async function handleVLESS(env, storedData = null, ctx = null, request = null) {
	const clientIP = request ? request.headers.get("CF-Connecting-IP") || "unknown" : "unknown";
	const socketPair = new WebSocketPair();
	const [clientSock, serverSock] = Object.values(socketPair);
	serverSock.accept();
	serverSock.binaryType = "arraybuffer";
	let username = null;
	let tickCount = 0;
	let validUUID = null;
	let userIpLimit = null;
	let targetDns = "8.8.4.4";
	let targetDoh = "https://cloudflare-dns.com/dns-query";
	function addBytes(bytes) {
		if (bytes <= 0) return;
		if (!username) {
			uncountedBytes += bytes;
			return;
		}
		if (uncountedBytes > 0) {
			bytes += uncountedBytes;
			uncountedBytes = 0;
		}
		let current = GLOBAL_TRAFFIC_CACHE.get(username) || 0;
		GLOBAL_TRAFFIC_CACHE.set(username, current + bytes);
		GLOBAL_LAST_ACTIVE_WRITE.set(username, Date.now());
		if (GLOBAL_WRITE_LOCK.get(username)) return;
		let lastDbWrite = GLOBAL_LAST_DB_WRITE.get(username) || 0;
		let now = Date.now();
		let thresholdBytes = 10 * 1024 * 1024;
		if (current >= thresholdBytes || (current > 0 && now - lastDbWrite > 60000)) {
			GLOBAL_WRITE_LOCK.set(username, true);
			let toCommit = GLOBAL_TRAFFIC_CACHE.get(username) || 0;
			let toCommitReq = USER_REQ_CACHE.get(username) || 0;
			if (toCommit <= 0 && toCommitReq <= 0) {
				GLOBAL_WRITE_LOCK.set(username, false);
				return;
			}
			GLOBAL_TRAFFIC_CACHE.set(username, 0);
			USER_REQ_CACHE.set(username, 0);
			GLOBAL_LAST_DB_WRITE.set(username, now);
			let deltaGb = toCommit / (1024 * 1024 * 1024);
			let writeTask = async () => {
				try {
					await env.DB.prepare("UPDATE users SET used_gb = used_gb + ?, used_req = used_req + ? WHERE username = ?").bind(deltaGb, toCommitReq, username).run();
					await bumpMonthlyUsage(env, deltaGb, toCommitReq);
				} catch (e) {
					console.error(e.message);
				} finally {
					GLOBAL_WRITE_LOCK.set(username, false);
				}
			};
			if (ctx) ctx.waitUntil(writeTask());
			else writeTask();
		}
	}
	let isOfflineSet = false;
	const setOffline = () => {
		if (isOfflineSet) return;
		isOfflineSet = true;
		const uname = username;
		if (!uname) return;
		if (clientIP && clientIP !== "unknown" && validUUID) {
			const removeIpTask = async () => {
				try {
					const user = await env.DB.prepare("SELECT active_ips FROM users WHERE uuid = ?").bind(validUUID).first();
					if (user) {
						console.log(`[setOffline Task] DB active_ips for ${uname}: ${user.active_ips}`);
						let activeIps = JSON.parse(user.active_ips || "{}");
						if (activeIps[clientIP]) {
							if (typeof activeIps[clientIP] === "object") {
								activeIps[clientIP].count = (activeIps[clientIP].count || 1) - 1;
								if (activeIps[clientIP].count <= 0) {
									delete activeIps[clientIP];
								}
							} else {
								delete activeIps[clientIP];
							}
							await env.DB.prepare("UPDATE users SET active_ips = ? WHERE uuid = ?").bind(JSON.stringify(activeIps), validUUID).run();
							console.log(`[setOffline Task] Updated active_ips in DB to: ${JSON.stringify(activeIps)}`);
						} else {
							console.log(`[setOffline Task] IP ${clientIP} not found in user's active_ips`);
						}
					}
				} catch (e) {
					console.error(`[setOffline Task] Error: ${e.message}`);
				}
			};
			if (ctx) ctx.waitUntil(removeIpTask());
			else removeIpTask();
		}
		let activeCount = ACTIVE_CONNECTIONS_COUNT.get(uname) || 1;
		activeCount = activeCount - 1;
		if (activeCount <= 0) {
			ACTIVE_CONNECTIONS_COUNT.delete(uname);
			let cachedBytes = GLOBAL_TRAFFIC_CACHE.get(uname) || 0;
			let cachedReqs = USER_REQ_CACHE.get(uname) || 0;
			if ((cachedBytes > 0 || cachedReqs > 0) && !GLOBAL_WRITE_LOCK.get(uname)) {
				GLOBAL_WRITE_LOCK.set(uname, true);
				const deltaGb = cachedBytes / (1024 * 1024 * 1024);
				const writeTask = async () => {
					try {
						await env.DB.prepare("UPDATE users SET used_gb = used_gb + ?, used_req = used_req + ? WHERE username = ?").bind(deltaGb, cachedReqs, uname).run();
						await bumpMonthlyUsage(env, deltaGb, cachedReqs);
					} catch (e) {
						console.error(e.message);
					} finally {
						GLOBAL_WRITE_LOCK.delete(uname);
						GLOBAL_TRAFFIC_CACHE.delete(uname);
						USER_REQ_CACHE.delete(uname);
						GLOBAL_LAST_ACTIVE_WRITE.delete(uname);
					}
				};
				if (ctx) {
					ctx.waitUntil(writeTask());
				} else {
					writeTask();
				}
			} else {
				GLOBAL_TRAFFIC_CACHE.delete(uname);
				USER_REQ_CACHE.delete(uname);
				GLOBAL_LAST_ACTIVE_WRITE.delete(uname);
				GLOBAL_WRITE_LOCK.delete(uname);
			}
		} else {
			ACTIVE_CONNECTIONS_COUNT.set(uname, activeCount);
		}
	};
	const heartbeat = setInterval(async () => {
		if (serverSock.readyState === WebSocket.OPEN) {
			try {
				serverSock.send(new Uint8Array(0));
				if (!validUUID) return;
				tickCount++;
				if (tickCount >= 1) {
					tickCount = 0;
					const user = await env.DB.prepare("SELECT is_active, limit_gb, used_gb, limit_req, used_req, expiry_days, created_at, ip_limit, active_ips FROM users WHERE uuid = ?").bind(validUUID).first();
					if (user) {
						userIpLimit = user.ip_limit;
					}
					let isExpired = false;
					let isIpLimitExpired = false;
					let updatedActiveIps = null;
					if (!user || user.is_active === 0) {
						isExpired = true;
					} else {
						if (user.limit_gb && user.used_gb >= user.limit_gb) {
							isExpired = true;
						}
						if (user.limit_req && user.used_req + (USER_REQ_CACHE.get(username) || 0) >= user.limit_req) {
							isExpired = true;
						}
						if (user.expiry_days && user.created_at) {
							const created = new Date(user.created_at);
							const expiryDate = new Date(created.getTime() + user.expiry_days * 24 * 60 * 60 * 1000);
							if (new Date() > expiryDate) {
								isExpired = true;
							}
						}
						if (!isExpired && clientIP && clientIP !== "unknown") {
							let activeIps = {};
							try {
								activeIps = JSON.parse(user.active_ips || "{}");
							} catch (e) {}
							const nowTime = Date.now();
							let hasChanges = false;
							for (const [ip, data] of Object.entries(activeIps)) {
								const lastSeen = data && typeof data === "object" ? data.timestamp : data;
								if (nowTime - lastSeen > 30000) {
									delete activeIps[ip];
									hasChanges = true;
								}
							}
							if (!activeIps[clientIP]) {
								isIpLimitExpired = true;
								console.log(`[Heartbeat] IP ${clientIP} expired from active_ips due to inactivity.`);
							} else {
								const sortedIps = Object.keys(activeIps).sort((a, b) => {
									const tA = activeIps[a] && typeof activeIps[a] === "object" ? activeIps[a].timestamp : activeIps[a];
									const tB = activeIps[b] && typeof activeIps[b] === "object" ? activeIps[b].timestamp : activeIps[b];
									return tB - tA;
								});
								const clientIpIndex = sortedIps.indexOf(clientIP);
								if (user.ip_limit && user.ip_limit > 0 && clientIpIndex >= user.ip_limit) {
									isIpLimitExpired = true;
									console.log(`[Heartbeat] IP Limit Exceeded. Client IP index ${clientIpIndex} >= limit ${user.ip_limit}.`);
								}
							}
							if (hasChanges || isIpLimitExpired) {
								updatedActiveIps = JSON.stringify(activeIps);
							}
						}
					}
					if (isExpired) {
						await env.DB.prepare("UPDATE users SET is_active = 0, last_active = 0 WHERE uuid = ?").bind(validUUID).run();
						clearInterval(heartbeat);
						closeSocketQuietly(serverSock);
						return;
					}
					if (isIpLimitExpired) {
						console.log(`[Heartbeat] Terminating socket for user ${username}.`);
						clearInterval(heartbeat);
						closeSocketQuietly(serverSock);
						return;
					}
					const now = Date.now();
					const lastRecorded = GLOBAL_LAST_ACTIVE_WRITE.get(username) || 0;
					if (now - lastRecorded > 120000 || updatedActiveIps !== null) {
						GLOBAL_LAST_ACTIVE_WRITE.set(username, now);
						if (updatedActiveIps !== null) {
							await env.DB.prepare("UPDATE users SET last_active = ?, active_ips = ? WHERE username = ?").bind(now, updatedActiveIps, username).run();
						} else {
							await env.DB.prepare("UPDATE users SET last_active = ? WHERE username = ?").bind(now, username).run();
						}
					}
				}
			} catch (e) {}
		} else {
			clearInterval(heartbeat);
		}
	}, 120000);
	let remoteConnWrapper = { socket: null, connectingPromise: null, retryConnect: null };
	let reqUUID = null;
	let isHeaderParsed = false;
	let isHeaderParsing = false;
	let isDnsQuery = false;
	let chunkBuffer = new Uint8Array(0);
	let uncountedBytes = 0;
	const proxyIP = storedData?.proxy_ip || "proxyip.cmliussss.net";
	let wsChain = Promise.resolve();
	let wsStopped = false,
		wsFailed = false,
		wsFinished = false;
	let wsQueueBytes = 0,
		wsQueueItems = 0;
	let currentSocketWriter = null,
		activeRemoteWriter = null;
	const releaseRemoteWriter = () => {
		if (activeRemoteWriter) {
			try {
				activeRemoteWriter.releaseLock();
			} catch (e) {}
			activeRemoteWriter = null;
		}
		currentSocketWriter = null;
	};
	const getRemoteWriter = () => {
		const s = remoteConnWrapper.socket;
		if (!s) return null;
		if (s !== currentSocketWriter) {
			releaseRemoteWriter();
			currentSocketWriter = s;
			activeRemoteWriter = s.writable.getWriter();
		}
		return activeRemoteWriter;
	};
	const upstreamQueue = createUpstreamQueue({
		getWriter: getRemoteWriter,
		releaseWriter: releaseRemoteWriter,
		retryConnect: async () => {
			if (typeof remoteConnWrapper.retryConnect === "function") {
				await remoteConnWrapper.retryConnect();
			}
		},
		closeConnection: () => {
			try {
				remoteConnWrapper.socket?.close();
			} catch (e) {}
			closeSocketQuietly(serverSock);
		},
		name: "VlessWSQueue",
	});
	const writeToRemote = async (chunk, allowRetry = true) => {
		return upstreamQueue.writeAndAwait(chunk, allowRetry);
	};
	const processWsMessage = async (chunk) => {
		const bytes = chunk.byteLength || 0;
		await addBytes(bytes);
		if (isDnsQuery) {
			await forwardVlessUDP(chunk, serverSock, null, addBytes, targetDns);
			return;
		}
		if (await writeToRemote(chunk)) return;
		if (!isHeaderParsed) {
			chunkBuffer = concatBytes(chunkBuffer, chunk);
			if (chunkBuffer.byteLength < 24) return;
			if (isHeaderParsing) return;
			isHeaderParsing = true;
			reqUUID = extractUUIDFromVless(chunkBuffer);
			if (!reqUUID) {
				serverSock.close();
				return;
			}
			let user = null;
			try {
				user = await env.DB.prepare("SELECT * FROM users WHERE uuid = ?").bind(reqUUID).first();
			} catch (e) {}
			if (isOfflineSet || serverSock.readyState !== WebSocket.OPEN) {
				return;
			}
			if (!user || user.is_active === 0) {
				serverSock.close();
				return;
			}
			if (user.limit_gb && user.used_gb >= user.limit_gb) {
				serverSock.close();
				return;
			}
			if (user.limit_req && user.used_req + (USER_REQ_CACHE.get(user.username) || 0) >= user.limit_req) {
				serverSock.close();
				return;
			}
			if (user.expiry_days && user.created_at) {
				const created = new Date(user.created_at);
				const expiryDate = new Date(created.getTime() + user.expiry_days * 24 * 60 * 60 * 1000);
				if (new Date() > expiryDate) {
					try {
						await env.DB.prepare("UPDATE users SET is_active = 0, last_active = 0 WHERE uuid = ?").bind(reqUUID).run();
					} catch (e) {}
					serverSock.close();
					return;
				}
			}
			userIpLimit = user.ip_limit;
			if (user.block_porn === 1 && user.block_ads === 1) {
				targetDns = "94.140.14.15";
				targetDoh = "https://family.adguard-dns.com/dns-query";
			} else if (user.block_porn === 1) {
				targetDns = "1.1.1.3";
				targetDoh = "https://family.cloudflare-dns.com/dns-query";
			} else if (user.block_ads === 1) {
				targetDns = "94.140.14.14";
				targetDoh = "https://dns.adguard-dns.com/dns-query";
			}
			if (clientIP && clientIP !== "unknown") {
				console.log(`[VLESS Handshake] User: ${user.username}, clientIP: ${clientIP}, active_ips in DB: ${user.active_ips}`);
				let activeIps = {};
				try {
					activeIps = JSON.parse(user.active_ips || "{}");
				} catch (e) {}
				const now = Date.now();
				for (const [ip, data] of Object.entries(activeIps)) {
					const lastSeen = data && typeof data === "object" ? data.timestamp : data;
					if (now - lastSeen > 30000) {
						delete activeIps[ip];
					}
				}
				if (!activeIps[clientIP]) {
					const sortedIps = Object.keys(activeIps).sort((a, b) => {
						const tA = activeIps[a] && typeof activeIps[a] === "object" ? activeIps[a].timestamp : activeIps[a];
						const tB = activeIps[b] && typeof activeIps[b] === "object" ? activeIps[b].timestamp : activeIps[b];
						return tB - tA;
					});
					console.log(`[VLESS Handshake] Non-expired active IPs: ${JSON.stringify(activeIps)}, count: ${sortedIps.length}, limit: ${user.ip_limit}`);
					if (user.ip_limit && user.ip_limit > 0 && sortedIps.length >= user.ip_limit) {
						console.log(`[VLESS Handshake] BLOCKED user ${user.username} because sortedIps.length (${sortedIps.length}) >= limit (${user.ip_limit})`);
						serverSock.close();
						return;
					}
					activeIps[clientIP] = { timestamp: now, count: 1 };
				} else {
					if (typeof activeIps[clientIP] === "object") {
						activeIps[clientIP].timestamp = now;
						activeIps[clientIP].count = (activeIps[clientIP].count || 0) + 1;
					} else {
						activeIps[clientIP] = { timestamp: now, count: 1 };
					}
					console.log(`[VLESS Handshake] Reconnected from same IP: ${clientIP}, count: ${activeIps[clientIP].count}`);
				}
				try {
					await env.DB.prepare("UPDATE users SET active_ips = ?, last_active = ? WHERE uuid = ?").bind(JSON.stringify(activeIps), now, reqUUID).run();
					console.log(`[VLESS Handshake] Successfully updated active_ips to: ${JSON.stringify(activeIps)}`);
				} catch (e) {
					console.error(`[VLESS Handshake] DB Update Error: ${e.message}`);
				}
			}
			validUUID = reqUUID;
			username = user.username;
			isHeaderParsed = true;
			let currentReqs = USER_REQ_CACHE.get(username) || 0;
			USER_REQ_CACHE.set(username, currentReqs + 1);
			let activeCount = ACTIVE_CONNECTIONS_COUNT.get(username) || 0;
			ACTIVE_CONNECTIONS_COUNT.set(username, activeCount + 1);
			if (activeCount === 0) {
				const setOnlineTask = async () => {
					try {
						const now = Date.now();
						GLOBAL_LAST_ACTIVE_WRITE.set(username, now);
						await env.DB.prepare("UPDATE users SET last_active = ? WHERE username = ?").bind(now, username).run();
					} catch (e) {}
				};
				if (ctx) ctx.waitUntil(setOnlineTask());
				else setOnlineTask();
			}
			try {
				let offset = 17;
				const optLen = chunkBuffer[offset++];
				offset += optLen;
				const cmd = chunkBuffer[offset++];
				const port = (chunkBuffer[offset++] << 8) | chunkBuffer[offset++];
				const addrType = chunkBuffer[offset++];
				let addr = "";
				if (addrType === 1) {
					addr = `${chunkBuffer[offset++]}.${chunkBuffer[offset++]}.${chunkBuffer[offset++]}.${chunkBuffer[offset++]}`;
				} else if (addrType === 2) {
					const domainLen = chunkBuffer[offset++];
					addr = new TextDecoder().decode(chunkBuffer.slice(offset, offset + domainLen));
					offset += domainLen;
				} else if (addrType === 3) {
					offset += 16;
					addr = "ipv6-unsupported";
				}
				const rawData = chunkBuffer.slice(offset);
				const respHeader = new Uint8Array([chunkBuffer[0], 0]);
				if (cmd === 2) {
					if (port === 53) {
						isDnsQuery = true;
						await forwardVlessUDP(rawData, serverSock, respHeader, addBytes, targetDns);
					} else {
						serverSock.close();
					}
					return;
				}
				const connectTCP = async (dataPayload = null, useFallback = true) => {
					if (remoteConnWrapper.connectingPromise) {
						await remoteConnWrapper.connectingPromise;
						return;
					}
					const task = (async () => {
						let s = null;
						const socks5 = storedData?.socks5 || "";
						
						if (socks5) {
							s = await connectProxy(socks5, addr, port, dataPayload);
						} else {
							let fHost = proxyIP;
							let fPort = port;
							if (proxyIP && proxyIP.includes(":")) {
								const parts = proxyIP.split(":");
								fHost = parts[0];
								fPort = parseInt(parts[1]) || port;
							}
							const isCustomProxy = proxyIP && proxyIP !== "proxyip.cmliussss.net";

							if (isCustomProxy) {
								try {
									s = await connectDirect(fHost, fPort, dataPayload, targetDoh);
								} catch (err) {
									s = await connectDirect(addr, port, dataPayload, targetDoh);
								}
							} else {
								try {
									s = await connectDirect(addr, port, dataPayload, targetDoh);
								} catch (err) {
									if (useFallback && proxyIP) {
										s = await connectDirect(fHost, fPort, dataPayload, targetDoh);
									} else {
										throw err;
									}
								}
							}
						}
						remoteConnWrapper.socket = s;
						s.closed.catch(() => {}).finally(() => closeSocketQuietly(serverSock));
						connectStreams(s, serverSock, respHeader, null, (b) => {
							addBytes(b);
						});
					})();
					remoteConnWrapper.connectingPromise = task;
					try {
						await task;
					} finally {
						if (remoteConnWrapper.connectingPromise === task) {
							remoteConnWrapper.connectingPromise = null;
						}
					}
				};
				remoteConnWrapper.retryConnect = async () => connectTCP(null, false);
				await connectTCP(rawData, true);
			} catch (e) {
				serverSock.close();
			}
		}
	};
	const handleWsError = (err) => {
		if (wsFailed) return;
		wsFailed = true;
		wsStopped = true;
		wsQueueBytes = 0;
		wsQueueItems = 0;
		upstreamQueue.clear();
		releaseRemoteWriter();
		closeSocketQuietly(serverSock);
		setOffline();
	};
	const pushToChain = (task) => {
		wsChain = wsChain.then(task).catch(handleWsError);
	};
	serverSock.addEventListener("message", (event) => {
		if (wsStopped || wsFailed) return;
		const size = event.data.byteLength || 0;
		const nextBytes = wsQueueBytes + size;
		const nextItems = wsQueueItems + 1;
		if (nextBytes > UPSTREAM_QUEUE_MAX_BYTES || nextItems > UPSTREAM_QUEUE_MAX_ITEMS) {
			handleWsError(new Error("ws queue overflow"));
			return;
		}
		wsQueueBytes = nextBytes;
		wsQueueItems = nextItems;
		pushToChain(async () => {
			wsQueueBytes = Math.max(0, wsQueueBytes - size);
			wsQueueItems = Math.max(0, wsQueueItems - 1);
			if (wsFailed) return;
			await processWsMessage(event.data);
		});
	});
	serverSock.addEventListener("close", () => {
		clearInterval(heartbeat);
		closeSocketQuietly(serverSock);
		setOffline();
		if (wsFinished) return;
		wsFinished = true;
		wsStopped = true;
		pushToChain(async () => {
			if (wsFailed) return;
			await upstreamQueue.awaitEmpty();
			releaseRemoteWriter();
		});
	});
	serverSock.addEventListener("error", (err) => {
		handleWsError(err);
	});
	return new Response(null, { status: 101, webSocket: clientSock });
}
async function getCfUsage(env) {
	if (!env.CF_API_TOKEN || !env.CF_ACCOUNT_ID) return { today: 0, total: 0 };
	try {
		const now = new Date();
		const startOfDay = new Date(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()).toISOString();
		const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000).toISOString();
		const q = `query {
      viewer {
        accounts(filter: {accountTag: "${env.CF_ACCOUNT_ID}"}) {
          today: workersInvocationsAdaptive(limit: 10, filter: {datetime_geq: "${startOfDay}"}) {
            sum { requests }
          }
          total: workersInvocationsAdaptive(limit: 10, filter: {datetime_geq: "${thirtyDaysAgo}"}) {
            sum { requests }
          }
        }
      }
    }`;
		const res = await fetch("https://api.cloudflare.com/client/v4/graphql", {
			method: "POST",
			headers: { Authorization: "Bearer " + env.CF_API_TOKEN, "Content-Type": "application/json" },
			body: JSON.stringify({ query: q }),
		});
		const j = await res.json();
		const acc = j?.data?.viewer?.accounts?.[0];
		const todayReqs = acc?.today?.[0]?.sum?.requests || 0;
		const totalReqs = acc?.total?.[0]?.sum?.requests || todayReqs;
		return { today: todayReqs, total: totalReqs };
	} catch (e) {
		return { today: 0, total: 0 };
	}
}
function isIPv4(value) {
	const parts = String(value || "").split(".");
	return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}
function stripIPv6Brackets(hostname = "") {
	const host = String(hostname || "").trim();
	return host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
}
function isIPHostname(hostname = "") {
	const host = stripIPv6Brackets(hostname);
	if (isIPv4(host)) return true;
	if (!host.includes(":")) return false;
	try {
		new URL(`http://[${host}]/`);
		return true;
	} catch (e) {
		return false;
	}
}
function convertToUint8Array(data) {
	if (data instanceof Uint8Array) return data;
	if (data instanceof ArrayBuffer) return new Uint8Array(data);
	if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
	return new Uint8Array(data || 0);
}
function concatBytes(...chunkList) {
	const chunks = chunkList.map(convertToUint8Array);
	const total = chunks.reduce((sum, c) => sum + c.byteLength, 0);
	const result = new Uint8Array(total);
	let offset = 0;
	for (const c of chunks) {
		result.set(c, offset);
		offset += c.byteLength;
	}
	return result;
}
function closeSocketQuietly(socket) {
	try {
		if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CLOSING) {
			socket.close();
		}
	} catch (e) {}
}
async function dohQuery(domain, recordType, targetDoh = DOH_RESOLVER) {
	const cacheKey = `${domain}:${recordType}:${targetDoh}`;
	if (DNS_CACHE.has(cacheKey)) {
		const cached = DNS_CACHE.get(cacheKey);
		if (Date.now() < cached.expires) return cached.data;
		DNS_CACHE.delete(cacheKey);
	}
	try {
		const typeMap = { A: 1, AAAA: 28 };
		const qtype = typeMap[recordType.toUpperCase()] || 1;
		const encodeDomain = (name) => {
			const parts = name.endsWith(".") ? name.slice(0, -1).split(".") : name.split(".");
			const bufs = [];
			for (const label of parts) {
				const enc = new TextEncoder().encode(label);
				bufs.push(new Uint8Array([enc.length]), enc);
			}
			bufs.push(new Uint8Array([0]));
			return concatBytes(...bufs);
		};
		const qname = encodeDomain(domain);
		const query = new Uint8Array(12 + qname.length + 4);
		const qview = new DataView(query.buffer);
		qview.setUint16(0, crypto.getRandomValues(new Uint16Array(1))[0]);
		qview.setUint16(2, 0x0100);
		qview.setUint16(4, 1);
		query.set(qname, 12);
		qview.setUint16(12 + qname.length, qtype);
		qview.setUint16(12 + qname.length + 2, 1);
		const response = await fetch(targetDoh, {
			method: "POST",
			headers: {
				"Content-Type": "application/dns-message",
				Accept: "application/dns-message",
			},
			body: query,
		});
		if (!response.ok) return [];
		const buf = new Uint8Array(await response.arrayBuffer());
		const dv = new DataView(buf.buffer);
		const qdcount = dv.getUint16(4);
		const ancount = dv.getUint16(6);
		const parseName = (pos) => {
			const labels = [];
			let p = pos,
				jumped = false,
				endPos = -1,
				safe = 128;
			while (p < buf.length && safe-- > 0) {
				const len = buf[p];
				if (len === 0) {
					if (!jumped) endPos = p + 1;
					break;
				}
				if ((len & 0xc0) === 0xc0) {
					if (!jumped) endPos = p + 2;
					p = ((len & 0x3f) << 8) | buf[p + 1];
					jumped = true;
					continue;
				}
				labels.push(new TextDecoder().decode(buf.slice(p + 1, p + 1 + len)));
				p += len + 1;
			}
			if (endPos === -1) endPos = p + 1;
			return [labels.join("."), endPos];
		};
		let offset = 12;
		for (let i = 0; i < qdcount; i++) {
			const [, end] = parseName(offset);
			offset = Number(end) + 4;
		}
		const answers = [];
		for (let i = 0; i < ancount && offset < buf.length; i++) {
			const [name, nameEnd] = parseName(offset);
			offset = Number(nameEnd);
			const type = dv.getUint16(offset);
			offset += 2;
			offset += 2;
			const ttl = dv.getUint32(offset);
			offset += 4;
			const rdlen = dv.getUint16(offset);
			offset += 2;
			const rdata = buf.slice(offset, offset + rdlen);
			offset += rdlen;
			let data;
			if (type === 1 && rdlen === 4) {
				data = `${rdata[0]}.${rdata[1]}.${rdata[2]}.${rdata[3]}`;
			} else if (type === 28 && rdlen === 16) {
				const segs = [];
				for (let j = 0; j < 16; j += 2) segs.push(((rdata[j] << 8) | rdata[j + 1]).toString(16));
				data = segs.join(":");
			} else {
				data = Array.from(rdata)
					.map((b) => b.toString(16).padStart(2, "0"))
					.join("");
			}
			answers.push({ name, type, TTL: ttl, data });
		}
		DNS_CACHE.set(cacheKey, { data: answers, expires: Date.now() + DNS_CACHE_TTL });
		return answers;
	} catch (e) {
		return [];
	}
}
function createUpstreamQueue({ getWriter, releaseWriter, retryConnect, closeConnection, name = "UpstreamQueue" }) {
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
		for (const comp of completions) {
			if (comp) {
				if (err) comp.reject(err);
				else comp.resolve();
			}
		}
	};
	const rejectQueued = (err) => {
		for (let i = head; i < chunks.length; i++) {
			const item = chunks[i];
			if (item && item.completions) settleCompletions(item.completions, err);
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
		const closeErr = err || (closed ? new Error(`${name}: queue closed`) : null);
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
		if (head >= chunks.length || first.chunk.byteLength >= UPSTREAM_BUNDLE_TARGET_BYTES) return first;
		let byteLength = first.chunk.byteLength;
		let end = head;
		let allowRetry = first.allowRetry;
		let completions = first.completions || null;
		while (end < chunks.length) {
			const next = chunks[end];
			const nextLength = byteLength + next.chunk.byteLength;
			if (nextLength > UPSTREAM_BUNDLE_TARGET_BYTES) break;
			byteLength = nextLength;
			allowRetry = allowRetry && next.allowRetry;
			if (next.completions) completions = completions ? completions.concat(next.completions) : next.completions;
			end++;
		}
		if (end === head) return first;
		const output = (bundleBuffer ||= new Uint8Array(UPSTREAM_BUNDLE_TARGET_BYTES));
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
			let batchCount = 0;
			for (;;) {
				if (closed) break;
				const item = bundle();
				if (!item) break;
				let writer = getWriter();
				if (!writer) throw new Error(`${name}: remote writer unavailable`);
				const completions = item.completions || null;
				activeCompletions = completions;
				try {
					try {
						await writer.write(item.chunk);
					} catch (err) {
						releaseWriter?.();
						if (!item.allowRetry || typeof retryConnect !== "function") throw err;
						await retryConnect();
						writer = getWriter();
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
				batchCount++;
				if (batchCount >= 16) {
					await new Promise((resolve) => setTimeout(resolve, 0));
					batchCount = 0;
				}
			}
		} catch (err) {
			closed = true;
			clear(err);
			try {
				closeConnection?.(err);
			} catch (_) {}
		} finally {
			draining = false;
			if (!closed && head < chunks.length) setTimeout(drain, 0);
			else resolveIdle();
		}
	};
	const enqueue = (data, allowRetry = true, waitForFlush = false) => {
		if (closed) return false;
		if (!getWriter()) return false;
		const chunk = convertToUint8Array(data);
		if (!chunk.byteLength) return true;
		const nextBytes = queuedBytes + chunk.byteLength;
		const nextItems = chunks.length - head + 1;
		if (nextBytes > UPSTREAM_QUEUE_MAX_BYTES || nextItems > UPSTREAM_QUEUE_MAX_ITEMS) {
			closed = true;
			const err = Object.assign(new Error(`${name}: upload queue overflow (${nextBytes}B/${nextItems})`), { isQueueOverflow: true });
			clear(err);
			try {
				closeConnection?.(err);
			} catch (_) {}
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
		if (!draining) setTimeout(drain, 0);
		return waitForFlush ? completionPromise.then(() => true) : true;
	};
	return {
		writeAndAwait(data, allowRetry = true) {
			return enqueue(data, allowRetry, true);
		},
		async awaitEmpty() {
			if (!queuedBytes && !draining) return;
			await new Promise((resolve) => idleResolvers.push(resolve));
		},
		clear() {
			closed = true;
			clear();
		},
	};
}
function createDownstreamSender(webSocket, headerData = null) {
	const packetCap = DOWNSTREAM_GRAIN_BYTES;
	const tailBytes = DOWNSTREAM_GRAIN_TAIL_THRESHOLD;
	const lowWaterBytes = Math.max(4096, tailBytes << 3);
	let header = headerData;
	let pendingBuffer = new Uint8Array(packetCap);
	let pendingBytes = 0;
	let flushTimer = null;
	let taskQueued = false;
	let generation = 0;
	let scheduledGeneration = 0;
	let waitRounds = 0;
	let flushPromise = null;
	const sendRawChunk = async (chunk) => {
		if (webSocket.readyState !== WebSocket.OPEN) throw new Error("ws.readyState is not open");
		webSocket.send(chunk);
	};
	const attachResponseHeader = (chunk) => {
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
		taskQueued = false;
		if (!pendingBytes) return;
		const output = pendingBuffer.subarray(0, pendingBytes).slice();
		pendingBuffer = new Uint8Array(packetCap);
		pendingBytes = 0;
		waitRounds = 0;
		flushPromise = sendRawChunk(output).finally(() => {
			flushPromise = null;
		});
		return flushPromise;
	};
	const scheduleFlush = () => {
		if (flushTimer || taskQueued) return;
		taskQueued = true;
		scheduledGeneration = generation;
		setTimeout(() => {
			taskQueued = false;
			if (!pendingBytes || flushTimer) return;
			if (packetCap - pendingBytes < tailBytes) {
				flush().catch(() => closeSocketQuietly(webSocket));
				return;
			}
			flushTimer = setTimeout(
				() => {
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
				},
				Math.max(DOWNSTREAM_GRAIN_SILENT_MS, 1),
			);
		}, 0);
	};
	return {
		async sendDirect(data) {
			let chunk = convertToUint8Array(data);
			if (!chunk.byteLength) return;
			chunk = attachResponseHeader(chunk);
			await sendRawChunk(chunk);
		},
		async send(data) {
			let chunk = convertToUint8Array(data);
			if (!chunk.byteLength) return;
			chunk = attachResponseHeader(chunk);
			let offset = 0;
			const totalBytes = chunk.byteLength;
			while (offset < totalBytes) {
				if (!pendingBytes && totalBytes - offset >= packetCap) {
					const sendBytes = Math.min(packetCap, totalBytes - offset);
					const view = offset || sendBytes !== totalBytes ? chunk.subarray(offset, offset + sendBytes) : chunk;
					await sendRawChunk(view);
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
		flush,
	};
}
async function waitForBackpressure(ws) {
	if (typeof ws.bufferedAmount === "number") {
		let maxAttempts = 150;
		while (ws.bufferedAmount > 256 * 1024 && maxAttempts > 0) {
			if (ws.readyState !== WebSocket.OPEN) break;
			await new Promise((r) => setTimeout(r, 20));
			maxAttempts--;
		}
	}
}
async function connectStreams(remoteSocket, webSocket, headerData, retryFunc, onBytes) {
	let header = headerData,
		hasData = false,
		reader,
		useBYOB = false;
	const BYOB_LIMIT = 64 * 1024;
	const downstreamSender = createDownstreamSender(webSocket, header);
	header = null;
	try {
		reader = remoteSocket.readable.getReader({ mode: "byob" });
		useBYOB = true;
	} catch (e) {
		reader = remoteSocket.readable.getReader();
	}
	try {
		if (!useBYOB) {
			while (true) {
				await waitForBackpressure(webSocket);
				const { done, value } = await reader.read();
				if (done) break;
				if (!value || value.byteLength === 0) continue;
				hasData = true;
				if (typeof onBytes === "function") onBytes(value.byteLength);
				await downstreamSender.send(value);
			}
		} else {
			let readBuffer = new ArrayBuffer(BYOB_LIMIT);
			while (true) {
				await waitForBackpressure(webSocket);
				const { done, value } = await reader.read(new Uint8Array(readBuffer, 0, BYOB_LIMIT));
				if (done) break;
				if (!value || value.byteLength === 0) continue;
				hasData = true;
				if (typeof onBytes === "function") onBytes(value.byteLength);
				if (value.byteLength >= DOWNSTREAM_GRAIN_BYTES) {
					await downstreamSender.flush();
					await downstreamSender.sendDirect(value);
					readBuffer = new ArrayBuffer(BYOB_LIMIT);
				} else {
					await downstreamSender.send(value);
					readBuffer = value.buffer.byteLength >= BYOB_LIMIT ? value.buffer : new ArrayBuffer(BYOB_LIMIT);
				}
			}
		}
		await downstreamSender.flush();
	} catch (err) {
		closeSocketQuietly(webSocket);
	} finally {
		try {
			reader.cancel();
		} catch (e) {}
		try {
			reader.releaseLock();
		} catch (e) {}
	}
	if (!hasData && retryFunc) await retryFunc();
}
async function buildRaceCandidates(address, port, targetDoh) {
	if (!PRELOAD_RACE_DIAL || isIPHostname(address)) return null;
	const [aRecords, aaaaRecords] = await Promise.all([dohQuery(address, "A", targetDoh), dohQuery(address, "AAAA", targetDoh)]);
	const ipv4List = [
		...new Set(
			aRecords.flatMap((r) => {
				return r.type === 1 && typeof r.data === "string" && isIPv4(r.data) ? [r.data] : [];
			}),
		),
	];
	const ipv6List = [
		...new Set(
			aaaaRecords.flatMap((r) => {
				return r.type === 28 && typeof r.data === "string" && isIPHostname(r.data) ? [r.data] : [];
			}),
		),
	];
	const limit = Math.max(1, TCP_CONCURRENCY | 0);
	const ipList = ipv4List.length >= limit ? ipv4List.slice(0, limit) : ipv4List.concat(ipv6List.slice(0, limit - ipv4List.length));
	if (ipList.length === 0) return null;
	return ipList.map((hostname, attempt) => ({ hostname, port, attempt, resolvedFrom: address }));
}
async function connectDirect(address, port, initialData = null, targetDoh = "https://cloudflare-dns.com/dns-query") {
	const raceCandidates = await buildRaceCandidates(address, port, targetDoh);
	const candidates = raceCandidates || Array.from({ length: TCP_CONCURRENCY }, () => ({ hostname: address, port }));
	const openConnection = async (host, prt) => {
		const socket = connect({ hostname: host, port: prt });
		await Promise.race([socket.opened, new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), 1000))]);
		return socket;
	};
	if (candidates.length === 1) {
		const s = await openConnection(candidates[0].hostname, candidates[0].port);
		if (initialData && initialData.byteLength > 0) {
			const w = s.writable.getWriter();
			await w.write(convertToUint8Array(initialData));
			w.releaseLock();
		}
		return s;
	}
	const attempts = candidates.map((c) => openConnection(c.hostname, c.port).then((socket) => ({ socket, candidate: c })));
	let winner = null;
	try {
		winner = await Promise.any(attempts);
		if (initialData && initialData.byteLength > 0) {
			const w = winner.socket.writable.getWriter();
			await w.write(convertToUint8Array(initialData));
			w.releaseLock();
		}
		return winner.socket;
	} finally {
		if (winner) {
			for (const attempt of attempts) {
				attempt
					.then(({ socket }) => {
						if (socket !== winner.socket) {
							try {
								socket.close();
							} catch (e) {}
						}
					})
					.catch(() => {});
			}
		}
	}
}
async function forwardVlessUDP(udpChunk, webSocket, respHeader, onBytes, dnsServer = "8.8.4.4") {
	const requestData = convertToUint8Array(udpChunk);
	try {
		const tcpSocket = connect({ hostname: dnsServer, port: 53 });
		let vlessHeader = respHeader;
		const writer = tcpSocket.writable.getWriter();
		await writer.write(requestData);
		writer.releaseLock();
		await tcpSocket.readable.pipeTo(
			new WritableStream({
				async write(chunk) {
					const response = convertToUint8Array(chunk);
					if (typeof onBytes === "function") onBytes(response.byteLength);
					if (webSocket.readyState !== WebSocket.OPEN) return;
					if (vlessHeader) {
						const merged = new Uint8Array(vlessHeader.length + response.byteLength);
						merged.set(vlessHeader, 0);
						merged.set(response, vlessHeader.length);
						webSocket.send(merged.buffer);
						vlessHeader = null;
					} else {
						webSocket.send(response);
					}
				},
			}),
		);
	} catch (e) {}
}
function extractUUIDFromVless(data) {
	if (data.byteLength < 17) return null;
	const hex = [...data.slice(1, 17)].map((b) => b.toString(16).padStart(2, "0")).join("");
	return `${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}`;
}
function trackRequest(env, ctx) {
	GLOBAL_REQ_COUNT++;
	const now = Date.now();
	if ((now - GLOBAL_LAST_REQ_WRITE > 900000 || GLOBAL_REQ_COUNT > 5000) && GLOBAL_REQ_COUNT > 0) {
		GLOBAL_LAST_REQ_WRITE = now;
		const countToSave = GLOBAL_REQ_COUNT;
		GLOBAL_REQ_COUNT = 0;
		const task = async () => {
			try {
				const today = new Date().toISOString().split("T")[0];
				await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('req_total', ?) ON CONFLICT(key) DO UPDATE SET value = CAST(value AS INTEGER) + ?").bind(String(countToSave), String(countToSave)).run();
				const lastDateRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'req_last_date'").first();
				if (!lastDateRow || lastDateRow.value !== today) {
					await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('req_last_date', ?) ON CONFLICT(key) DO UPDATE SET value = ?").bind(today, today).run();
					await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('req_today', ?) ON CONFLICT(key) DO UPDATE SET value = ?").bind(String(countToSave), String(countToSave)).run();
				} else {
					await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('req_today', ?) ON CONFLICT(key) DO UPDATE SET value = CAST(value AS INTEGER) + ?").bind(String(countToSave), String(countToSave)).run();
				}
			} catch (e) {}
		};
		if (ctx) ctx.waitUntil(task());
		else task();
	}
}
async function connectProxy(proxyStr, destAddr, destPort, initialData) {
	let normalized = proxyStr;
	if (proxyStr.includes("t.me/socks") || proxyStr.includes("tg://socks")) {
		const server = proxyStr.match(/server=([^&]+)/)?.[1];
		const port = proxyStr.match(/port=([^&]+)/)?.[1];
		const user = proxyStr.match(/user=([^&]+)/)?.[1];
		const pass = proxyStr.match(/pass=([^&]+)/)?.[1];
		if (server && port) {
			normalized = user && pass ? `socks5://${user}:${pass}@${server}:${port}` : `socks5://${server}:${port}`;
		}
	}

	const isHttp = normalized.toLowerCase().startsWith('http://') || normalized.toLowerCase().startsWith('https://');
	let cleanStr = normalized.replace(/^(socks4|socks5|socks|http|https):\/\//i, '');
	
	if (isHttp) {
		return await connectHttp(cleanStr, destAddr, destPort, initialData);
	}
	return await connectSocks5(cleanStr, destAddr, destPort, initialData);
}

async function connectSocks5(socksStr, destAddr, destPort, initialData) {
	let user = "", pass = "", host = "", port = 1080;
	let auth = false;
	if (socksStr.includes("@")) {
		const parts = socksStr.split("@");
		const up = parts[0].split(":");
		user = up[0] || ""; pass = up[1] || "";
		auth = true;
		const hp = parts[1].split(":");
		host = hp[0]; port = parseInt(hp[1]) || 1080;
	} else {
		const hp = socksStr.split(":");
		host = hp[0]; port = parseInt(hp[1]) || 1080;
	}

	const socket = connect({ hostname: host, port: port });
	const reader = socket.readable.getReader();
	const writer = socket.writable.getWriter();

	try {
		if (auth) {
			await writer.write(new Uint8Array([0x05, 0x02, 0x00, 0x02]));
		} else {
			await writer.write(new Uint8Array([0x05, 0x01, 0x00]));
		}

		let res = await reader.read();
		if (res.done || !res.value || res.value[0] !== 0x05) throw new Error("پاسخ نامعتبر از سرور (پروکسی SOCKS5 نیست یا خاموش است)");

		const method = res.value[1];
		if (method === 0x02) {
			const uEnc = new TextEncoder().encode(user);
			const pEnc = new TextEncoder().encode(pass);
			const authReq = new Uint8Array(1 + 1 + uEnc.length + 1 + pEnc.length);
			authReq[0] = 0x01;
			authReq[1] = uEnc.length;
			authReq.set(uEnc, 2);
			authReq[2 + uEnc.length] = pEnc.length;
			authReq.set(pEnc, 3 + uEnc.length);
			
			await writer.write(authReq);
			let authRes = await reader.read();
			if (authRes.done || !authRes.value || authRes.value[1] !== 0x00) throw new Error("نام کاربری یا رمز عبور پروکسی اشتباه است");
		}

		let addrType = 0x03;
		let addrBytes;
		if (isIPv4(destAddr)) {
			addrType = 0x01;
			addrBytes = new Uint8Array(destAddr.split('.').map(Number));
		} else {
			const enc = new TextEncoder().encode(destAddr);
			addrBytes = new Uint8Array(1 + enc.length);
			addrBytes[0] = enc.length;
			addrBytes.set(enc, 1);
		}
		
		const req = new Uint8Array(4 + addrBytes.length + 2);
		req[0] = 0x05; req[1] = 0x01; req[2] = 0x00; req[3] = addrType;
		req.set(addrBytes, 4);
		const portOffset = 4 + addrBytes.length;
		req[portOffset] = (destPort >> 8) & 0xFF;
		req[portOffset + 1] = destPort & 0xFF;

		await writer.write(req);
		let connRes = await reader.read();
		if (connRes.done || !connRes.value || connRes.value[1] !== 0x00) throw new Error("پروکسی وصل شد اما دسترسی به اینترنت آزاد ندارد");

		if (initialData && initialData.byteLength > 0) {
			await writer.write(convertToUint8Array(initialData));
		}

		writer.releaseLock();
		reader.releaseLock();
		return socket;
	} catch (e) {
		try { writer.releaseLock(); } catch(err){}
		try { reader.releaseLock(); } catch(err){}
		try { socket.close(); } catch(err){}
		throw e;
	}
}

async function connectHttp(proxyStr, destAddr, destPort, initialData) {
	let user = "", pass = "", host = "", port = 80;
	let auth = false;
	if (proxyStr.includes("@")) {
		const parts = proxyStr.split("@");
		const up = parts[0].split(":");
		user = up[0] || ""; pass = up[1] || "";
		auth = true;
		const hp = parts[1].split(":");
		host = hp[0]; port = parseInt(hp[1]) || 80;
	} else {
		const hp = proxyStr.split(":");
		host = hp[0]; port = parseInt(hp[1]) || 80;
	}

	const socket = connect({ hostname: host, port: port });
	const reader = socket.readable.getReader();
	const writer = socket.writable.getWriter();

	try {
		let req = `CONNECT ${destAddr}:${destPort} HTTP/1.1\r\nHost: ${destAddr}:${destPort}\r\n`;
		if (auth) {
			const authBase64 = btoa(`${user}:${pass}`);
			req += `Proxy-Authorization: Basic ${authBase64}\r\n`;
		}
		req += "\r\n";
		
		await writer.write(new TextEncoder().encode(req));
		
		let resStr = "";
		while (true) {
			const res = await reader.read();
			if (res.done || !res.value) throw new Error("proxy_closed");
			resStr += new TextDecoder().decode(res.value, { stream: true });
			if (resStr.includes("\r\n\r\n")) {
				const match = resStr.match(/^HTTP\/\d\.\d\s+(\d+)/);
				if (match && match[1] === "200") {
					break;
				} else {
					throw new Error("proxy_error_" + (match ? match[1] : "unknown"));
				}
			}
		}
		
		if (initialData && initialData.byteLength > 0) {
			await writer.write(convertToUint8Array(initialData));
		}

		writer.releaseLock();
		reader.releaseLock();
		return socket;
	} catch (e) {
		try { writer.releaseLock(); } catch(err){}
		try { reader.releaseLock(); } catch(err){}
		try { socket.close(); } catch(err){}
		throw e;
	}
}

const HTML_TEMPLATES = {
	nginx: `<!DOCTYPE html>
<html lang="fa" dir="rtl" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>دسترسی به پنل</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css" rel="stylesheet" type="text/css" />
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    fontFamily: { sans: ['Vazirmatn', 'sans-serif'] },
                    colors: { amoled: { bg: '#000000', card: '#080b0f', input: '#0d1117', border: '#1c2330' } }
                }
            }
        }
    </script>
</head>
<body class="bg-gray-50 text-gray-900 dark:bg-amoled-bg dark:text-zinc-100 min-h-screen flex items-center justify-center p-4">
    <div class="w-full max-w-md bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-2xl shadow-xl p-8 text-center flex flex-col items-center gap-4">
        <div class="p-4 bg-blue-50 dark:bg-blue-900/20 text-blue-500 rounded-full mb-2">
            <svg class="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
        </div>
        <h2 class="text-xl font-bold text-gray-900 dark:text-white">ورود به پنل مدیریت</h2>
        <p class="text-sm text-gray-600 dark:text-gray-400 leading-relaxed mt-2">
            برای ورود به پنل، لطفاً عبارت 
            <span class="inline-block px-2 py-1 bg-gray-100 dark:bg-amoled-input border border-gray-200 dark:border-zinc-800 rounded-md font-mono text-blue-500 font-bold mx-1 shadow-sm" dir="ltr">/panel</span> 
            را به انتهای آدرس مرورگر خود اضافه کنید.
        </p>
        <button onclick="window.location.href='/panel'" class="mt-4 w-full py-2.5 bg-transparent border-2 border-emerald-500 text-emerald-600 hover:bg-emerald-500 hover:text-white dark:border-emerald-400 dark:text-emerald-400 dark:hover:bg-emerald-500 dark:hover:text-white font-medium rounded-xl text-sm transition-colors duration-200 shadow-lg font-bold">
            ورود به پنل
        </button>
    </div>
</body>
</html>`,
	setup: "<!DOCTYPE html>\n<html lang=\"fa\" dir=\"rtl\">\n<head>\n<meta charset=\"UTF-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n<title>تعریف رمز عبور پنل</title>\n<link href=\"https://fonts.googleapis.com/css2?family=Vazirmatn:wght@300;400;500;600;700&display=swap\" rel=\"stylesheet\">\n<style>\n:root{--bg:#07090f;--s1:#0d1117;--s2:#161b27;--bd:#252d3d;--acc:#3b82f6;--ac2:#06b6d4;--grn:#10b981;--red:#ef4444;--txt:#e2e8f0;--mut:#64748b;--f:'Vazirmatn',sans-serif}\n*{box-sizing:border-box;margin:0;padding:0}\nbody{background:var(--bg);color:var(--txt);font-family:var(--f);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;background:radial-gradient(ellipse 70% 50% at 50% 0%,#1e3a6a33,transparent)}\n.card{background:var(--s1);border:1px solid var(--bd);border-radius:20px;padding:48px 40px;width:360px;text-align:center}\n.logo{font-size:52px;display:block;margin-bottom:16px;animation:fl 3s ease-in-out infinite}\n@keyframes fl{0%,100%{transform:translateY(0)}50%{transform:translateY(-6px)}}\n.title{font-size:22px;font-weight:700;background:linear-gradient(135deg,var(--acc),var(--ac2));-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:6px}\n.sub{color:var(--mut);font-size:13px;margin-bottom:28px;line-height:1.6}\n.ig{margin-bottom:14px;text-align:right}\n.ig label{display:block;font-size:12px;color:var(--mut);margin-bottom:5px}\n.ig input{width:100%;background:var(--s2);border:1px solid var(--bd);border-radius:8px;padding:11px 13px;color:var(--txt);font-family:var(--f);font-size:14px;outline:none;direction:rtl;text-align:center;transition:border-color .2s}\n.ig input:focus{border-color:var(--acc)}\n.btn{display:flex;align-items:center;justify-content:center;gap:8px;padding:11px 22px;border-radius:8px;border:none;cursor:pointer;font-family:var(--f);font-size:14px;font-weight:600;width:100%;background:var(--acc);color:#fff;transition:all .2s}\n.btn:hover{background:#2563eb;transform:translateY(-1px)}\n.btn:disabled{opacity:.6;cursor:default;transform:none}\n.tw{position:fixed;bottom:22px;left:50%;transform:translateX(-50%);z-index:999;display:flex;flex-direction:column;gap:7px;align-items:center}\n.toast{background:var(--s2);border:1px solid var(--bd);border-radius:9px;padding:11px 18px;font-size:13px;font-weight:500}\n.toast.ok{border-color:#10b98138;color:var(--grn)}.toast.err{border-color:#ef444438;color:var(--red)}\n</style>\n</head>\n<body>\n<div class=\"card\">\n  <span class=\"logo\">🦀</span>\n  <div class=\"title\">CrabVPN Admin</div>\n  <div class=\"sub\">این اولین ورود شما به پنل مدیریت است.<br>لطفاً رمز عبور خود را تعیین کنید.</div>\n  <form onsubmit=\"handleSetup(event)\">\n    <div class=\"ig\"><label>رمز عبور</label><input type=\"password\" id=\"password\" required minlength=\"4\"></div>\n    <div class=\"ig\"><label>تکرار رمز عبور</label><input type=\"password\" id=\"confirm-password\" required minlength=\"4\"></div>\n    <button type=\"submit\" id=\"submit-btn\" class=\"btn\">ثبت و ورود</button>\n  </form>\n</div>\n<div class=\"tw\" id=\"tw\"></div>\n<script>\nfunction toast(m, type) {\n  type = type || 'ok';\n  var e = document.createElement('div');\n  e.className = 'toast ' + type;\n  e.textContent = m;\n  document.getElementById('tw').appendChild(e);\n  setTimeout(function () { e.remove(); }, 3200);\n}\nasync function handleSetup(event) {\n  event.preventDefault();\n  var password = document.getElementById('password').value;\n  var confirmPassword = document.getElementById('confirm-password').value;\n  var btn = document.getElementById('submit-btn');\n  if (password !== confirmPassword) {\n    toast('رمز عبور و تکرار آن مطابقت ندارند', 'err');\n    return;\n  }\n  btn.disabled = true;\n  btn.textContent = 'در حال ثبت...';\n  try {\n    var res = await fetch('/api/setup-password', {\n      method: 'POST',\n      headers: { 'Content-Type': 'application/json' },\n      body: JSON.stringify({ password: password }),\n    });\n    var data = await res.json();\n    if (res.ok && data.success) {\n      toast('رمز عبور با موفقیت تنظیم شد');\n      setTimeout(function () { window.location.reload(); }, 1200);\n    } else {\n      toast('خطا: ' + (data.error || 'عملیات ناموفق بود'), 'err');\n      btn.disabled = false;\n      btn.textContent = 'ثبت و ورود';\n    }\n  } catch (err) {\n    toast('خطا در ارتباط با سرور', 'err');\n    btn.disabled = false;\n    btn.textContent = 'ثبت و ورود';\n  }\n}\n</script>\n</body>\n</html>\n",

	login: "<!DOCTYPE html>\n<html lang=\"fa\" dir=\"rtl\">\n<head>\n<meta charset=\"UTF-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n<title>ورود به پنل مدیریت</title>\n<link href=\"https://fonts.googleapis.com/css2?family=Vazirmatn:wght@300;400;500;600;700&display=swap\" rel=\"stylesheet\">\n<style>\n:root{--bg:#07090f;--s1:#0d1117;--s2:#161b27;--bd:#252d3d;--acc:#3b82f6;--ac2:#06b6d4;--grn:#10b981;--red:#ef4444;--ylw:#f59e0b;--txt:#e2e8f0;--mut:#64748b;--f:'Vazirmatn',sans-serif}\n*{box-sizing:border-box;margin:0;padding:0}\nbody{background:var(--bg);color:var(--txt);font-family:var(--f);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;background:radial-gradient(ellipse 70% 50% at 50% 0%,#1e3a6a33,transparent)}\n.card{background:var(--s1);border:1px solid var(--bd);border-radius:20px;padding:48px 40px;width:360px;text-align:center}\n.logo{font-size:52px;display:block;margin-bottom:16px;animation:fl 3s ease-in-out infinite}\n@keyframes fl{0%,100%{transform:translateY(0)}50%{transform:translateY(-6px)}}\n.title{font-size:22px;font-weight:700;background:linear-gradient(135deg,var(--acc),var(--ac2));-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:6px}\n.sub{color:var(--mut);font-size:13px;margin-bottom:28px}\n.ig{margin-bottom:14px;text-align:right}\n.ig label{display:block;font-size:12px;color:var(--mut);margin-bottom:5px}\n.ig input{width:100%;background:var(--s2);border:1px solid var(--bd);border-radius:8px;padding:11px 13px;color:var(--txt);font-family:var(--f);font-size:14px;outline:none;direction:rtl;text-align:center;transition:border-color .2s}\n.ig input:focus{border-color:var(--acc)}\n.btn{display:flex;align-items:center;justify-content:center;gap:8px;padding:11px 22px;border-radius:8px;border:none;cursor:pointer;font-family:var(--f);font-size:14px;font-weight:600;width:100%;transition:all .2s}\n.btn-p{background:var(--acc);color:#fff}\n.btn-p:hover{background:#2563eb;transform:translateY(-1px)}\n.btn-r{background:#ef444418;color:var(--red);border:1px solid #ef444435}.btn-r:hover{background:#ef444428}\n.btn-g{background:#10b98118;color:var(--grn);border:1px solid #10b98135}.btn-g:hover{background:#10b98128}\n.btn:disabled{opacity:.6;cursor:default;transform:none}\n.link-btn{background:none;border:none;color:var(--acc);font-family:var(--f);font-size:12px;cursor:pointer;margin-top:16px}\n.link-btn:hover{text-decoration:underline}\n.hidden{display:none}\n.notice{margin-bottom:20px;padding:12px 14px;border-radius:10px;border:1px solid #f59e0b30;background:#f59e0b08;font-size:12px;line-height:1.7;color:var(--ylw);text-align:right}\n.notice a{display:flex;align-items:center;justify-content:center;gap:6px;margin-top:10px;padding:8px;border-radius:8px;border:1px solid #10b98135;background:#10b98118;color:var(--grn);text-decoration:none;font-weight:600}\n.row{display:flex;gap:8px;margin-top:14px}\n.row .btn{width:auto;flex:1}\n.tw{position:fixed;bottom:22px;left:50%;transform:translateX(-50%);z-index:999;display:flex;flex-direction:column;gap:7px;align-items:center}\n.toast{background:var(--s2);border:1px solid var(--bd);border-radius:9px;padding:11px 18px;font-size:13px;font-weight:500}\n.toast.ok{border-color:#10b98138;color:var(--grn)}.toast.err{border-color:#ef444438;color:var(--red)}\n</style>\n</head>\n<body>\n<div class=\"card\">\n  <span class=\"logo\">🦀</span>\n  <div class=\"title\">CrabVPN Admin</div>\n  <div class=\"sub\">پنل مدیریت</div>\n\n  <div id=\"login-section\">\n    <form onsubmit=\"handleLogin(event)\">\n      <div class=\"ig\"><label>رمز عبور</label><input type=\"password\" id=\"password\" required></div>\n      <button type=\"submit\" id=\"submit-btn\" class=\"btn btn-p\">ورود</button>\n    </form>\n    <button class=\"link-btn\" onclick=\"toggleRecovery(true)\">بازیابی رمز پنل</button>\n  </div>\n\n  <div id=\"recovery-section\" class=\"hidden\">\n    <div class=\"notice\">\n      برای احراز هویت و اثبات مالکیت پنل، از طریق دکمه زیر وارد کلودفلر شوید و توکن دریافتی را در کادر زیر وارد کنید.\n      <a href=\"https://dash.cloudflare.com/profile/api-tokens?permissionGroupKeys=%5B%7B%22key%22%3A%22workers_scripts%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22workers_kv_storage%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22d1%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22account_settings%22%2C%22type%22%3A%22read%22%7D%2C%7B%22key%22%3A%22workers_subdomain%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22account_analytics%22%2C%22type%22%3A%22read%22%7D%5D&accountId=*&zoneId=all&name=Zeus-Deployer-Token\" target=\"_blank\">دریافت توکن</a>\n    </div>\n    <form onsubmit=\"handleRecovery(event)\">\n      <div class=\"ig\"><input type=\"password\" id=\"api-token\" placeholder=\"توکن را وارد کنید\" required style=\"direction:ltr\"></div>\n      <div class=\"row\">\n        <button type=\"button\" onclick=\"toggleRecovery(false)\" class=\"btn btn-r\">انصراف</button>\n        <button type=\"submit\" id=\"recover-btn\" class=\"btn btn-g\">بازیابی رمز پنل</button>\n      </div>\n    </form>\n  </div>\n</div>\n<div class=\"tw\" id=\"tw\"></div>\n<script>\nfunction toast(m, type) {\n  type = type || 'ok';\n  var e = document.createElement('div');\n  e.className = 'toast ' + type;\n  e.textContent = m;\n  document.getElementById('tw').appendChild(e);\n  setTimeout(function () { e.remove(); }, 3200);\n}\nasync function handleLogin(event) {\n  event.preventDefault();\n  var password = document.getElementById('password').value;\n  var btn = document.getElementById('submit-btn');\n  btn.disabled = true;\n  try {\n    var res = await fetch('/api/login', {\n      method: 'POST',\n      headers: { 'Content-Type': 'application/json' },\n      body: JSON.stringify({ password: password }),\n    });\n    var data = await res.json();\n    if (res.ok && data.success) {\n      window.location.reload();\n    } else {\n      toast('رمز عبور اشتباه است', 'err');\n      btn.disabled = false;\n    }\n  } catch (err) {\n    toast('خطا در ارتباط با سرور', 'err');\n    btn.disabled = false;\n  }\n}\nfunction toggleRecovery(show) {\n  document.getElementById('login-section').classList.toggle('hidden', show);\n  document.getElementById('recovery-section').classList.toggle('hidden', !show);\n}\nasync function handleRecovery(event) {\n  event.preventDefault();\n  var apiToken = document.getElementById('api-token').value;\n  var btn = document.getElementById('recover-btn');\n  btn.disabled = true;\n  btn.textContent = 'در حال بررسی...';\n  try {\n    var res = await fetch('/api/recover', {\n      method: 'POST',\n      headers: { 'Content-Type': 'application/json' },\n      body: JSON.stringify({ api_token: apiToken }),\n    });\n    var data = await res.json();\n    if (res.ok && data.success) {\n      toast('رمز عبور با موفقیت حذف شد');\n      setTimeout(function () { window.location.reload(); }, 1200);\n    } else {\n      toast(data.error || 'خطا در تایید اطلاعات', 'err');\n      btn.disabled = false;\n      btn.textContent = 'بازیابی رمز پنل';\n    }\n  } catch (err) {\n    toast('خطا در ارتباط با سرور', 'err');\n    btn.disabled = false;\n    btn.textContent = 'بازیابی رمز پنل';\n  }\n}\n</script>\n</body>\n</html>\n",

	panel: "<!DOCTYPE html>\n<html lang=\"fa\" dir=\"rtl\">\n<head>\n<meta charset=\"UTF-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n<title>CrabVPN Admin</title>\n<link href=\"https://fonts.googleapis.com/css2?family=Vazirmatn:wght@300;400;500;600;700&display=swap\" rel=\"stylesheet\">\n<script src=\"https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js\"></script>\n<style>\n:root{--bg:#07090f;--s1:#0d1117;--s2:#161b27;--s3:#1e2535;--bd:#252d3d;--acc:#3b82f6;--ac2:#06b6d4;--grn:#10b981;--red:#ef4444;--ylw:#f59e0b;--pur:#8b5cf6;--txt:#e2e8f0;--mut:#64748b;--r:10px;--f:'Vazirmatn',sans-serif}\n*{box-sizing:border-box;margin:0;padding:0}\nbody{background:var(--bg);color:var(--txt);font-family:var(--f);font-size:14px;min-height:100vh}\n.btn{display:inline-flex;align-items:center;gap:8px;padding:11px 22px;border-radius:8px;border:none;cursor:pointer;font-family:var(--f);font-size:14px;font-weight:600;transition:all .2s}\n.btn-p{background:var(--acc);color:#fff}\n.btn-p:hover{background:#2563eb;transform:translateY(-1px)}\n.btn-sm{padding:6px 13px;font-size:12px;border-radius:6px}\n.btn-g{background:#10b98118;color:var(--grn);border:1px solid #10b98135}.btn-g:hover{background:#10b98128}\n.btn-y{background:#f59e0b18;color:var(--ylw);border:1px solid #f59e0b35}.btn-y:hover{background:#f59e0b28}\n.btn-r{background:#ef444418;color:var(--red);border:1px solid #ef444435}.btn-r:hover{background:#ef444428}\n.btn-2{background:var(--s2);color:var(--mut);border:1px solid var(--bd)}.btn-2:hover{color:var(--txt)}\n#app{min-height:100vh}\n.sidebar{position:fixed;top:0;right:0;width:220px;height:100vh;background:var(--s1);border-left:1px solid var(--bd);display:flex;flex-direction:column;padding:24px 0;z-index:100}\n.slg{padding:0 20px 24px;border-bottom:1px solid var(--bd);display:flex;align-items:center;gap:10px}\n.slg span:first-child{font-size:28px}\n.sl-t{font-size:16px;font-weight:700}\n.sl-s{font-size:11px;color:var(--mut)}\n.nav{padding:14px 10px;flex:1}\n.ni{display:flex;align-items:center;gap:9px;padding:9px 12px;border-radius:8px;cursor:pointer;color:var(--mut);font-size:13px;font-weight:500;transition:all .15s;margin-bottom:3px}\n.ni:hover{background:var(--s2);color:var(--txt)}\n.ni.active{background:#3b82f615;color:var(--acc)}\n.ni-ico{font-size:16px}\n.sf{padding:14px 20px 0;border-top:1px solid var(--bd);display:flex;flex-direction:column;gap:8px}\n.obadge{display:inline-flex;align-items:center;gap:5px;background:#10b98112;color:var(--grn);border:1px solid #10b98130;border-radius:20px;padding:3px 10px;font-size:12px;font-weight:600}\n.dot{width:7px;height:7px;border-radius:50%;background:var(--grn);animation:pulse 1.5s infinite}\n@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}\n.main{margin-right:220px;padding:26px 30px;min-height:100vh}\n.page{display:none;animation:fi .25s ease}.page.active{display:block}\n@keyframes fi{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}\n.ph{display:flex;align-items:center;justify-content:space-between;margin-bottom:4px}\n.pt{font-size:22px;font-weight:700}\n.ps{color:var(--mut);font-size:13px;margin-bottom:24px}\n.sg{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:14px;margin-bottom:24px}\n.sc{background:var(--s1);border:1px solid var(--bd);border-radius:var(--r);padding:18px;position:relative;overflow:hidden;transition:border-color .2s}\n.sc:hover{border-color:var(--s3)}\n.sc::before{content:'';position:absolute;top:0;left:0;right:0;height:2px}\n.sc.blue::before{background:var(--acc)}.sc.grn::before{background:var(--grn)}.sc.ylw::before{background:var(--ylw)}.sc.cyn::before{background:var(--ac2)}\n.si{font-size:20px;margin-bottom:10px}\n.sv{font-size:26px;font-weight:700;line-height:1;margin-bottom:5px}\n.sl{color:var(--mut);font-size:12px}\n.cg{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:24px}\n.cc{background:var(--s1);border:1px solid var(--bd);border-radius:var(--r);padding:18px}\n.cc h3{font-size:13px;font-weight:600;color:var(--mut);margin-bottom:14px}\n.card{background:var(--s1);border:1px solid var(--bd);border-radius:var(--r);overflow:hidden;margin-bottom:18px}\n.tbl-wrap{overflow-x:auto;-webkit-overflow-scrolling:touch}\n.ch{padding:14px 18px;border-bottom:1px solid var(--bd);display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap}\n.ch h3{font-size:14px;font-weight:600}\ntable{width:100%;border-collapse:collapse}\nth{padding:11px 14px;text-align:right;font-size:11px;font-weight:600;color:var(--mut);border-bottom:1px solid var(--bd);background:var(--s2);text-transform:uppercase;letter-spacing:.5px}\ntd{padding:12px 14px;border-bottom:1px solid #ffffff06;font-size:13px;vertical-align:middle}\ntr:last-child td{border-bottom:none}\ntr:hover td{background:#ffffff02}\n.badge{display:inline-flex;align-items:center;gap:4px;padding:2px 9px;border-radius:20px;font-size:11px;font-weight:600}\n.b-g{background:#10b98112;color:var(--grn)}.b-r{background:#ef444412;color:var(--red)}.b-y{background:#f59e0b12;color:var(--ylw)}.b-b{background:#3b82f612;color:var(--acc)}.b-m{background:#ffffff0c;color:var(--mut)}\n.tb{min-width:130px}.tbb{height:5px;background:var(--s2);border-radius:3px;overflow:hidden;margin-top:3px}.tbf{height:100%;border-radius:3px;transition:width .4s}\n.tbt{font-size:11px;color:var(--mut)}\n.mo{position:fixed;inset:0;background:#00000088;backdrop-filter:blur(4px);z-index:200;display:none;align-items:center;justify-content:center}\n.mo.open{display:flex}\n.mbox{background:var(--s1);border:1px solid var(--bd);border-radius:14px;padding:26px;width:480px;max-height:90vh;overflow-y:auto;animation:min .2s ease}\n@keyframes min{from{opacity:0;transform:scale(.95)}to{opacity:1;transform:scale(1)}}\n.mbox h3{font-size:16px;font-weight:700;margin-bottom:18px}\n.mf{display:flex;gap:10px;margin-top:18px;flex-direction:row-reverse}\n.g2{display:grid;grid-template-columns:1fr 1fr;gap:12px}\n.g3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px}\n.ig{margin-bottom:14px;text-align:right}\n.ig label{display:block;font-size:12px;color:var(--mut);margin-bottom:5px}\n.ig input,.ig select{width:100%;background:var(--s2);border:1px solid var(--bd);border-radius:8px;padding:11px 13px;color:var(--txt);font-family:var(--f);font-size:14px;outline:none;direction:rtl;transition:border-color .2s}\n.ig input:focus,.ig select:focus{border-color:var(--acc)}\n.tw{position:fixed;bottom:22px;left:50%;transform:translateX(-50%);z-index:999;display:flex;flex-direction:column;gap:7px;align-items:center}\n.toast{background:var(--s2);border:1px solid var(--bd);border-radius:9px;padding:11px 18px;font-size:13px;font-weight:500;animation:ti .25s ease}\n.toast.ok{border-color:#10b98138;color:var(--grn)}.toast.err{border-color:#ef444438;color:var(--red)}\n@keyframes ti{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}\n.load{display:flex;align-items:center;justify-content:center;padding:50px;color:var(--mut);gap:10px}\n.spin{width:18px;height:18px;border:2px solid var(--bd);border-top-color:var(--acc);border-radius:50%;animation:sp .7s linear infinite}\n@keyframes sp{to{transform:rotate(360deg)}}\n.empty{padding:36px;text-align:center;color:var(--mut);font-size:13px}\n.ts{position:relative;display:inline-block;width:44px;height:24px;flex-shrink:0}\n.ts input{opacity:0;width:0;height:0}\n.tsl{position:absolute;cursor:pointer;inset:0;background:var(--s2);border:1px solid var(--bd);border-radius:34px;transition:.3s}\n.tsl:before{content:'';position:absolute;height:16px;width:16px;left:3px;bottom:3px;background:var(--mut);border-radius:50%;transition:.3s}\n.ts input:checked+.tsl{background:#10b98122;border-color:var(--grn)}.ts input:checked+.tsl:before{transform:translateX(20px);background:var(--grn)}\n.search-inp{background:var(--s2);border:1px solid var(--bd);border-radius:7px;padding:7px 12px;color:var(--txt);font-family:var(--f);font-size:13px;width:190px;outline:none;text-align:right;direction:rtl}\n.search-inp:focus{border-color:var(--acc)}\n.rb{background:var(--s2);border:1px solid var(--bd);border-radius:7px;padding:6px 11px;color:var(--mut);cursor:pointer;font-family:var(--f);font-size:12px;display:flex;align-items:center;gap:5px;transition:all .15s}\n.rb:hover{color:var(--txt)}.rb.sp svg{animation:sp .7s linear infinite}\n@media(max-width:860px){.sidebar{width:56px}.sl-t,.sl-s,.ni span:last-child{display:none}.main{margin-right:56px;padding:18px}.cg{grid-template-columns:1fr}}\n</style>\n</head>\n<body>\n<div id=\"app\">\n  <div class=\"sidebar\">\n    <div class=\"slg\"><span>🦀</span><div><div class=\"sl-t\">CrabVPN</div><div class=\"sl-s\">Admin Panel</div></div></div>\n    <nav class=\"nav\">\n      <div class=\"ni active\" onclick=\"pg('overview',this)\"><span class=\"ni-ico\">📊</span><span>داشبورد</span></div>\n      <div class=\"ni\" onclick=\"pg('users',this)\"><span class=\"ni-ico\">👥</span><span>کاربران</span></div>\n      <div class=\"ni\" onclick=\"pg('packages',this)\"><span class=\"ni-ico\">📦</span><span>بسته‌ها</span></div>\n      <div class=\"ni\" onclick=\"pg('payments',this)\"><span class=\"ni-ico\">💳</span><span>پرداخت‌ها</span></div>\n      <div class=\"ni\" onclick=\"pg('settings',this)\"><span class=\"ni-ico\">⚙️</span><span>تنظیمات</span></div>\n    </nav>\n    <div class=\"sf\">\n      <div class=\"obadge\"><div class=\"dot\"></div><span id=\"total-online\">۰</span> آنلاین</div>\n      <button class=\"btn btn-2 btn-sm\" style=\"width:100%;justify-content:center\" onclick=\"doLogout()\">خروج</button>\n    </div>\n  </div>\n\n  <div class=\"main\">\n    <!-- OVERVIEW -->\n    <div class=\"page active\" id=\"page-overview\">\n      <div class=\"ph\"><div class=\"pt\">داشبورد</div>\n        <button class=\"rb\" id=\"rfbtn\" onclick=\"loadAll()\">\n          <svg width=\"13\" height=\"13\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><path d=\"M1 4v6h6M23 20v-6h-6\"/><path d=\"M20.49 9A9 9 0 0 0 5.64 5.64L1 10m22 4l-4.64 4.36A9 9 0 0 1 3.51 15\"/></svg>\n          بروزرسانی\n        </button>\n      </div>\n      <div class=\"ps\" id=\"lupd\">در حال بارگذاری...</div>\n      <div class=\"sg\">\n        <div class=\"sc blue\"><div class=\"si\">💰</div><div class=\"sv\" id=\"s-rev\">—</div><div class=\"sl\">درآمد کل (تومان)</div></div>\n        <div class=\"sc cyn\"><div class=\"si\">📅</div><div class=\"sv\" id=\"s-mon\">—</div><div class=\"sl\">این ماه (تومان)</div></div>\n        <div class=\"sc grn\"><div class=\"si\">👤</div><div class=\"sv\" id=\"s-cus\">—</div><div class=\"sl\">کل کاربران</div></div>\n        <div class=\"sc ylw\"><div class=\"si\">✅</div><div class=\"sv\" id=\"s-ord\">—</div><div class=\"sl\">اشتراک فعال</div></div>\n        <div class=\"sc blue\"><div class=\"si\">📡</div><div class=\"sv\" id=\"s-cf-today\">—</div><div class=\"sl\">درخواست Cloudflare (امروز)</div></div>\n        <div class=\"sc cyn\"><div class=\"si\">🌐</div><div class=\"sv\" id=\"s-cf-total\">—</div><div class=\"sl\">درخواست Cloudflare (۳۰ روز)</div></div>\n      </div>\n      <div class=\"cg\">\n        <div class=\"cc\"><h3>درآمد ماهانه (تومان)</h3><canvas id=\"ch-mon\" height=\"200\"></canvas></div>\n        <div class=\"cc\"><h3>۳۰ روز اخیر</h3><canvas id=\"ch-day\" height=\"200\"></canvas></div>\n        <div class=\"cc\"><h3>مصرف حجم ماهانه (GB)</h3><canvas id=\"ch-traf\" height=\"200\"></canvas></div>\n        <div class=\"cc\"><h3>درخواست‌های ماهانه</h3><canvas id=\"ch-req\" height=\"200\"></canvas></div>\n      </div>\n    </div>\n\n    <!-- USERS -->\n    <div class=\"page\" id=\"page-users\">\n      <div class=\"ph\"><div class=\"pt\">کاربران</div>\n        <button class=\"btn btn-sm btn-g\" onclick=\"openAddCustomer()\">➕ کاربر جدید</button>\n      </div>\n      <div class=\"ps\">وضعیت اشتراک و مصرف همه کاربران</div>\n      <div class=\"card\">\n        <div class=\"ch\">\n          <h3>لیست کاربران</h3>\n          <input class=\"search-inp\" id=\"user-q\" type=\"text\" placeholder=\"🔍 جستجو...\" oninput=\"applyUserFilter()\">\n        </div>\n        <div id=\"users-wrap\"><div class=\"load\"><div class=\"spin\"></div>در حال بارگذاری...</div></div>\n      </div>\n    </div>\n\n    <!-- PACKAGES -->\n    <div class=\"page\" id=\"page-packages\">\n      <div class=\"ph\"><div class=\"pt\">بسته‌ها</div>\n        <button class=\"btn btn-sm btn-g\" onclick=\"openAddPkg()\">➕ بسته جدید</button>\n      </div>\n      <div class=\"ps\">بسته‌های حجم/قیمت که کاربران و پورتال ازشون استفاده می‌کنن</div>\n      <div class=\"card\"><div id=\"pkgs-wrap\"><div class=\"load\"><div class=\"spin\"></div>در حال بارگذاری...</div></div></div>\n    </div>\n\n    <!-- PAYMENTS -->\n    <div class=\"page\" id=\"page-payments\">\n      <div class=\"pt\">پرداخت‌ها</div>\n      <div class=\"ps\">مدیریت پرداخت‌ها و تأیید دستی</div>\n      <div class=\"card\">\n        <div class=\"ch\"><h3>آخرین ۱۰۰ پرداخت</h3></div>\n        <div id=\"pay-wrap\"><div class=\"load\"><div class=\"spin\"></div>در حال بارگذاری...</div></div>\n      </div>\n    </div>\n\n    <!-- SETTINGS -->\n    <div class=\"page\" id=\"page-settings\">\n      <div class=\"pt\">تنظیمات</div>\n      <div class=\"ps\">آدرس پورتال و روش‌های پرداخت</div>\n\n      <div class=\"card\" style=\"padding:16px;margin-bottom:14px\">\n        <div style=\"font-weight:600;margin-bottom:16px;font-size:15px\">🌐 آدرس پورتال (دامنه)</div>\n        <div style=\"font-size:12px;color:var(--mut);margin-bottom:8px\">آدرس عمومی این ورکر — برای لینک پورتال و Callback درگاه پرداخت.</div>\n        <div style=\"display:flex;gap:8px;margin-bottom:10px\">\n          <input id=\"gset-portal-url\" class=\"search-inp\" style=\"flex:1;direction:ltr\" placeholder=\"https://your-worker.workers.dev\">\n          <button class=\"btn btn-sm btn-g\" onclick=\"savePortalURL()\">ذخیره</button>\n        </div>\n        <div style=\"background:var(--s2);border:1px solid var(--bd);border-radius:8px;padding:10px 12px\">\n          <div style=\"font-size:11px;color:var(--mut);margin-bottom:4px\">🔗 آدرس Callback فعلی (برای AryallehPay):</div>\n          <code id=\"gset-callback-url\" style=\"direction:ltr;font-size:12px;word-break:break-all;color:var(--ac2)\">در حال بارگذاری...</code>\n        </div>\n      </div>\n\n      <div class=\"card\" style=\"padding:16px\">\n        <div style=\"font-weight:600;margin-bottom:16px;font-size:15px\">💳 درگاه پرداخت (AryallehPay)</div>\n\n        <div style=\"display:flex;align-items:center;justify-content:space-between;gap:12px;padding-bottom:12px;border-bottom:1px solid var(--bd)\">\n          <div>\n            <div style=\"font-weight:500\">⚡ فعال بودن درگاه</div>\n            <div style=\"font-size:12px;color:var(--mut);margin-top:3px\">پرداخت آنلاین از طریق AryallehPay — تایید خودکار پس از پرداخت</div>\n          </div>\n          <label class=\"ts\"><input type=\"checkbox\" id=\"gset-tetra-en\" onchange=\"setGlobalSetting('payment_tetra_enabled',this.checked)\"><span class=\"tsl\"></span></label>\n        </div>\n        <div style=\"padding-top:12px\">\n          <div style=\"font-weight:500;margin-bottom:6px\">🔑 API Key درگاه AryallehPay</div>\n          <div style=\"display:flex;gap:8px;margin-bottom:10px\">\n            <input id=\"gset-tetra-key\" class=\"search-inp\" style=\"flex:1;direction:ltr\" type=\"password\" placeholder=\"api key را اینجا وارد کنید...\">\n            <button class=\"btn btn-sm btn-g\" onclick=\"saveTetraKey()\">ذخیره</button>\n          </div>\n          <div style=\"font-weight:500;margin-bottom:6px\">🌐 آدرس پایه AryallehPay</div>\n          <div style=\"display:flex;gap:8px;margin-bottom:10px\">\n            <input id=\"gset-aryalleh-url\" class=\"search-inp\" style=\"flex:1;direction:ltr\" placeholder=\"https://pay.aryalleh.ir\">\n            <button class=\"btn btn-sm btn-g\" onclick=\"saveAryallehUrl()\">ذخیره</button>\n          </div>\n          <div style=\"background:var(--s2);border:1px solid var(--bd);border-radius:8px;padding:10px 12px\">\n            <div style=\"font-size:11px;color:var(--mut);margin-bottom:4px\">آدرس Callback — در پنل AryallehPay وارد کنید:</div>\n            <code id=\"tetra-callback-url\" style=\"direction:ltr;font-size:12px;word-break:break-all;color:var(--ac2)\"></code>\n          </div>\n        </div>\n      </div>\n\n      <div class=\"card\" style=\"padding:16px;margin-top:14px\">\n        <div style=\"font-weight:600;margin-bottom:16px;font-size:15px\">🤖 ربات تلگرام</div>\n        <div style=\"font-size:12px;color:var(--mut);margin-bottom:12px\">وقتی توکن رو ذخیره کنی، webhook ربات خودکار روی این ورکر تنظیم می‌شه.</div>\n        <div style=\"margin-bottom:14px\">\n          <div style=\"font-weight:500;margin-bottom:6px\">🔑 توکن ربات (Bot Token)</div>\n          <div style=\"display:flex;gap:8px\">\n            <input id=\"gset-bot-token\" class=\"search-inp\" style=\"flex:1;direction:ltr\" type=\"password\" placeholder=\"123456789:ABC...\">\n            <button class=\"btn btn-sm btn-g\" onclick=\"saveBotToken()\">ذخیره</button>\n          </div>\n        </div>\n        <div style=\"margin-bottom:14px\">\n          <div style=\"font-weight:500;margin-bottom:6px\">📢 کانال اطلاع‌رسانی ادمین (اختیاری)</div>\n          <div style=\"font-size:12px;color:var(--mut);margin-bottom:6px\">هر ثبت‌نام جدید از ربات، این‌جا اعلام می‌شه.</div>\n          <div style=\"display:flex;gap:8px\">\n            <input id=\"gset-channel-id\" class=\"search-inp\" style=\"flex:1;direction:ltr\" placeholder=\"@channel یا -100123456789\">\n            <button class=\"btn btn-sm btn-g\" onclick=\"saveChannelId()\">ذخیره</button>\n          </div>\n        </div>\n        <div>\n          <div style=\"font-weight:500;margin-bottom:6px\">🔒 کانال عضویت اجباری (اختیاری)</div>\n          <div style=\"font-size:12px;color:var(--mut);margin-bottom:6px\">کاربر باید عضو این کانال باشه تا ربات جواب بده. ربات باید ادمین این کانال باشه.</div>\n          <div style=\"display:flex;gap:8px\">\n            <input id=\"gset-gate-channel-id\" class=\"search-inp\" style=\"flex:1;direction:ltr\" placeholder=\"@channel یا -100123456789\">\n            <button class=\"btn btn-sm btn-g\" onclick=\"saveGateChannelId()\">ذخیره</button>\n          </div>\n        </div>\n      </div>\n    </div>\n  </div>\n</div>\n\n<!-- Modal: Add Customer -->\n<div class=\"mo\" id=\"m-cust\">\n<div class=\"mbox\">\n  <h3>➕ کاربر جدید</h3>\n  <div class=\"ig\"><label>نام</label><input id=\"mc-name\" placeholder=\"نام مشتری\"></div>\n  <div class=\"ig\"><label>شماره تماس</label><input id=\"mc-phone\" placeholder=\"0912...\" dir=\"ltr\"></div>\n  <div class=\"ig\"><label>بسته</label><select id=\"mc-pkg\"></select></div>\n  <div class=\"mf\">\n    <button class=\"btn btn-p\" style=\"width:auto\" onclick=\"submitCustomer()\">ساخت کاربر</button>\n    <button class=\"btn btn-2\" onclick=\"cm('m-cust')\">لغو</button>\n  </div>\n</div></div>\n\n<!-- Modal: Add Traffic -->\n<div class=\"mo\" id=\"m-traf\">\n<div class=\"mbox\">\n  <h3>➕ افزایش حجم</h3>\n  <div class=\"ig\"><label>یوزرنیم</label><input id=\"mt-user\" readonly style=\"opacity:.7\"></div>\n  <div class=\"ig\"><label>مقدار (GB)</label><input type=\"number\" id=\"mt-val\" value=\"5\" min=\"1\"></div>\n  <div class=\"mf\">\n    <button class=\"btn btn-p\" style=\"width:auto\" onclick=\"submitTraffic()\">تأیید</button>\n    <button class=\"btn btn-2\" onclick=\"cm('m-traf')\">لغو</button>\n  </div>\n</div></div>\n\n<!-- Modal: Extend duration -->\n<div class=\"mo\" id=\"m-ext\">\n<div class=\"mbox\">\n  <h3>⏳ تمدید دستی</h3>\n  <div class=\"ig\"><label>یوزرنیم</label><input id=\"me-user\" readonly style=\"opacity:.7\"></div>\n  <div class=\"ig\"><label>روز اضافه</label><input type=\"number\" id=\"me-days\" value=\"30\" min=\"1\"></div>\n  <div class=\"mf\">\n    <button class=\"btn btn-p\" style=\"width:auto\" onclick=\"submitExtend()\">اعمال</button>\n    <button class=\"btn btn-2\" onclick=\"cm('m-ext')\">لغو</button>\n  </div>\n</div></div>\n\n<!-- Modal: Add/Edit Package -->\n<div class=\"mo\" id=\"m-pkg\">\n<div class=\"mbox\">\n  <h3 id=\"m-pkg-title\">📦 بسته جدید</h3>\n  <input type=\"hidden\" id=\"mp-id\">\n  <div class=\"ig\"><label>نام بسته</label><input id=\"mp-name\" placeholder=\"5GB\"></div>\n  <div class=\"g3\">\n    <div class=\"ig\"><label>حجم</label><input type=\"number\" id=\"mp-traf\" min=\"0\" value=\"1\"></div>\n    <div class=\"ig\"><label>واحد</label><select id=\"mp-unit\"><option value=\"gb\">GB</option><option value=\"mb\">MB</option></select></div>\n    <div class=\"ig\"><label>قیمت (تومان)</label><input type=\"number\" id=\"mp-price\" min=\"0\" step=\"1000\" placeholder=\"50000\"></div>\n  </div>\n  <div class=\"g2\">\n    <div class=\"ig\"><label>⏳ مدت زمان (روز)</label><input type=\"number\" id=\"mp-days\" min=\"1\" max=\"3650\" value=\"30\"></div>\n    <div class=\"ig\"><label>ترتیب نمایش</label><input type=\"number\" id=\"mp-ord\" value=\"0\"></div>\n  </div>\n  <label style=\"display:flex;align-items:center;gap:8px;cursor:pointer;margin-bottom:14px\">\n    <label class=\"ts\"><input type=\"checkbox\" id=\"mp-active\" checked><span class=\"tsl\"></span></label>بسته فعال باشد\n  </label>\n  <div class=\"mf\">\n    <button class=\"btn btn-p\" style=\"width:auto\" onclick=\"submitPkg()\">ذخیره</button>\n    <button class=\"btn btn-2\" onclick=\"cm('m-pkg')\">لغو</button>\n  </div>\n</div></div>\n\n<div class=\"tw\" id=\"tw\"></div>\n\n<script>\nlet _D = { users: [], packages: [], payments: [], monthlyUsage: [], cfRequestsToday: 0, cfRequestsTotal: 0 };\nlet _CM = null, _CD = null, _CT = null, _CR = null;\n\nfunction toast(m, type) { type = type || 'ok'; var e = document.createElement('div'); e.className = 'toast ' + type; e.textContent = (type === 'ok' ? '✅ ' : '❌ ') + m; document.getElementById('tw').appendChild(e); setTimeout(function () { e.remove(); }, 3200); }\nfunction cm(id) { document.getElementById(id).classList.remove('open'); }\nfunction om(id) { document.getElementById(id).classList.add('open'); }\nfunction fIRR(n, s) { if (n == null || n === '') return '—'; var v = Number(n); if (isNaN(v)) return '—'; if (s && v >= 1e6) return (v / 1e6).toFixed(1) + 'M'; if (s && v >= 1e3) return (v / 1e3).toFixed(0) + 'K'; return v.toLocaleString('fa-IR', { maximumFractionDigits: 0 }); }\nfunction fN(n) { return String(n).replace(/\\d/g, function (d) { return '۰۱۲۳۴۵۶۷۸۹'[d]; }); }\n\nfunction pg(n, el) {\n  var pages = document.querySelectorAll('.page');\n  for (var i = 0; i < pages.length; i++) pages[i].classList.remove('active');\n  var navs = document.querySelectorAll('.ni');\n  for (var j = 0; j < navs.length; j++) navs[j].classList.remove('active');\n  document.getElementById('page-' + n).classList.add('active');\n  if (el) el.classList.add('active');\n}\n\nfunction doLogout() {\n  fetch('/api/logout', { method: 'POST' }).then(function () { location.href = '/panel'; });\n}\n\nasync function loadAll() {\n  var btn = document.getElementById('rfbtn');\n  btn.classList.add('sp');\n  try {\n    var r = await fetch('/api/users');\n    if (r.status === 401) { location.href = '/panel'; return; }\n    var d = await r.json();\n    _D.users = d.users || [];\n    var pr = await fetch('/api/packages');\n    var pd = await pr.json();\n    _D.packages = pd.packages || [];\n    var payr = await fetch('/api/payments');\n    var payd = await payr.json();\n    _D.payments = payd.payments || [];\n    var ur = await fetch('/api/usage/monthly');\n    var ud = await ur.json();\n    _D.monthlyUsage = ud.months || [];\n    _D.cfRequestsToday = ud.cfRequestsToday || 0;\n    _D.cfRequestsTotal = ud.cfRequestsTotal || 0;\n    renderOverview();\n    renderUsers();\n    renderPackages();\n    renderPayments();\n    loadSettings();\n    document.getElementById('lupd').textContent = 'آخرین بروزرسانی: ' + new Date().toLocaleTimeString('fa-IR');\n  } catch (e) {\n    toast('خطا: ' + e.message, 'err');\n  } finally {\n    btn.classList.remove('sp');\n  }\n}\n\nfunction cOpts() {\n  return { responsive: true, plugins: { legend: { display: false } }, scales: { x: { grid: { color: '#1e2535' }, ticks: { color: '#64748b', font: { family: 'Vazirmatn', size: 11 } } }, y: { grid: { color: '#1e2535' }, ticks: { color: '#64748b', font: { family: 'Vazirmatn', size: 11 } } } } };\n}\n\n// ── OVERVIEW ──────────────────────────────────────────────────────────────────\nfunction renderOverview() {\n  var approved = _D.payments.filter(function (p) { return p.status === 'approved'; });\n  var totalRev = approved.reduce(function (a, p) { return a + Number(p.amount_irr || 0); }, 0);\n  var monthKey = new Date().toISOString().slice(0, 7);\n  var monthRev = approved.filter(function (p) { return (p.created_at || '').slice(0, 7) === monthKey; }).reduce(function (a, p) { return a + Number(p.amount_irr || 0); }, 0);\n  document.getElementById('s-rev').textContent = fIRR(totalRev, true);\n  document.getElementById('s-mon').textContent = fIRR(monthRev, true);\n  document.getElementById('s-cus').textContent = fN(_D.users.length);\n  document.getElementById('s-ord').textContent = fN(_D.users.filter(function (u) { return u.is_active; }).length);\n  var online = _D.users.filter(function (u) { return u.is_online; }).length;\n  document.getElementById('total-online').textContent = fN(online);\n  document.getElementById('s-cf-today').textContent = fIRR(_D.cfRequestsToday, true);\n  document.getElementById('s-cf-total').textContent = fIRR(_D.cfRequestsTotal, true);\n\n  var byMonth = {};\n  approved.forEach(function (p) { var k = (p.created_at || '').slice(0, 7); byMonth[k] = (byMonth[k] || 0) + Number(p.amount_irr || 0); });\n  var monthKeys = Object.keys(byMonth).sort().slice(-6);\n  if (typeof Chart !== 'undefined') {\n    try {\n      if (_CM) _CM.destroy();\n      _CM = new Chart(document.getElementById('ch-mon'), { type: 'bar', data: { labels: monthKeys, datasets: [{ label: 'تومان', data: monthKeys.map(function (k) { return byMonth[k]; }), backgroundColor: '#3b82f628', borderColor: '#3b82f6', borderWidth: 2, borderRadius: 5 }] }, options: cOpts() });\n      var byDay = {};\n      approved.forEach(function (p) { var k = (p.created_at || '').slice(0, 10); byDay[k] = (byDay[k] || 0) + Number(p.amount_irr || 0); });\n      var dayKeys = Object.keys(byDay).sort().slice(-30);\n      if (_CD) _CD.destroy();\n      _CD = new Chart(document.getElementById('ch-day'), { type: 'line', data: { labels: dayKeys.map(function (k) { return k.slice(5); }), datasets: [{ label: 'تومان', data: dayKeys.map(function (k) { return byDay[k]; }), borderColor: '#06b6d4', backgroundColor: '#06b6d412', fill: true, tension: .4, pointRadius: 3 }] }, options: cOpts() });\n      var muKeys = _D.monthlyUsage.map(function (m) { return m.month; });\n      if (_CT) _CT.destroy();\n      _CT = new Chart(document.getElementById('ch-traf'), { type: 'bar', data: { labels: muKeys, datasets: [{ label: 'GB', data: _D.monthlyUsage.map(function (m) { return Number(m.traffic_gb || 0).toFixed(2); }), backgroundColor: '#10b98128', borderColor: '#10b981', borderWidth: 2, borderRadius: 5 }] }, options: cOpts() });\n      if (_CR) _CR.destroy();\n      _CR = new Chart(document.getElementById('ch-req'), { type: 'line', data: { labels: muKeys, datasets: [{ label: 'درخواست', data: _D.monthlyUsage.map(function (m) { return m.requests || 0; }), borderColor: '#8b5cf6', backgroundColor: '#8b5cf612', fill: true, tension: .4, pointRadius: 3 }] }, options: cOpts() });\n    } catch (e) {}\n  }\n}\n\n// ── USERS ─────────────────────────────────────────────────────────────────────\nfunction renderUsers() { applyUserFilter(); }\nfunction applyUserFilter() {\n  var q = (document.getElementById('user-q').value || '').toLowerCase();\n  var list = _D.users;\n  if (q) list = list.filter(function (u) { return (u.name || '').toLowerCase().indexOf(q) >= 0 || (u.username || '').toLowerCase().indexOf(q) >= 0 || (u.phone || '').toLowerCase().indexOf(q) >= 0; });\n  var wrap = document.getElementById('users-wrap');\n  if (!list.length) { wrap.innerHTML = '<div class=\"empty\">کاربری یافت نشد</div>'; return; }\n  var rows = list.map(function (u) {\n    var tot = Number(u.limit_gb || 0) * 1024, used = Number(u.used_gb || 0) * 1024;\n    var pct = tot > 0 ? Math.min(100, Math.round(used / tot * 100)) : 0;\n    var bc = pct > 85 ? 'var(--red)' : pct > 60 ? 'var(--ylw)' : 'var(--grn)';\n    var tf = tot < 1024 ? (Math.max(0, tot - used)).toFixed(0) + ' / ' + tot.toFixed(0) + ' MB' : ((Math.max(0, tot - used)) / 1024).toFixed(2) + ' / ' + (tot / 1024).toFixed(2) + ' GB';\n    return '<tr>' +\n      '<td><b>' + (u.name || '—') + '</b><br><span style=\"font-size:11px;color:var(--mut)\">' + (u.phone || '—') + '</span></td>' +\n      '<td><code style=\"background:var(--s2);padding:2px 6px;border-radius:4px;font-size:11px\">' + u.username + '</code></td>' +\n      '<td class=\"tb\"><div class=\"tbt\">' + tf + ' (' + pct + '%)</div><div class=\"tbb\"><div class=\"tbf\" style=\"width:' + pct + '%;background:' + bc + '\"></div></div></td>' +\n      '<td><span class=\"badge b-b\">' + (u.expiry_days || 0) + ' روز</span></td>' +\n      '<td>' + (u.is_online ? '<span class=\"badge b-g\">آنلاین</span>' : '<span class=\"badge b-m\">آفلاین</span>') + '</td>' +\n      '<td><a href=\"/status/' + u.uuid + '\" target=\"_blank\" class=\"badge b-b\" style=\"cursor:pointer\">🔗 پورتال</a></td>' +\n      '<td style=\"display:flex;gap:4px\">' +\n      '<button class=\"btn btn-sm btn-y\" onclick=\"openTraf(\\'' + u.username + '\\')\">➕</button>' +\n      '<button class=\"btn btn-sm btn-g\" onclick=\"openExtend(\\'' + u.username + '\\')\">⏳</button>' +\n      '</td></tr>';\n  }).join('');\n  wrap.innerHTML = '<div class=\"tbl-wrap\"><table><thead><tr><th>کاربر</th><th>یوزرنیم</th><th>مصرف</th><th>مدت</th><th>وضعیت</th><th>پورتال</th><th>عملیات</th></tr></thead><tbody>' + rows + '</tbody></table></div>';\n}\n\nasync function openAddCustomer() {\n  document.getElementById('mc-name').value = '';\n  document.getElementById('mc-phone').value = '';\n  var sel = document.getElementById('mc-pkg');\n  sel.innerHTML = _D.packages.filter(function (p) { return p.is_active; }).map(function (p) { return '<option value=\"' + p.id + '\">' + p.name + ' — ' + p.traffic_amount + p.traffic_unit.toUpperCase() + ' / ' + p.duration_days + 'روز</option>'; }).join('') || '<option value=\"\">بسته‌ای نیست</option>';\n  om('m-cust');\n}\nasync function submitCustomer() {\n  var name = document.getElementById('mc-name').value.trim();\n  var phone = document.getElementById('mc-phone').value.trim();\n  var package_id = parseInt(document.getElementById('mc-pkg').value);\n  if (!name || !package_id) { toast('نام و بسته اجباری است', 'err'); return; }\n  try {\n    var r = await fetch('/api/customers/create', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: name, phone: phone, package_id: package_id }) });\n    var d = await r.json();\n    if (!d.ok) throw new Error(d.error);\n    toast('کاربر ساخته شد');\n    cm('m-cust');\n    loadAll();\n    window.open('/status/' + d.uuid, '_blank');\n  } catch (e) { toast(e.message, 'err'); }\n}\n\nfunction openTraf(username) { document.getElementById('mt-user').value = username; document.getElementById('mt-val').value = '5'; om('m-traf'); }\nasync function submitTraffic() {\n  var u = document.getElementById('mt-user').value;\n  var gb = parseFloat(document.getElementById('mt-val').value);\n  if (!gb || gb <= 0) { toast('مقدار نامعتبر', 'err'); return; }\n  try {\n    var r = await fetch('/api/users/' + encodeURIComponent(u) + '/extend', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ extra_mb: gb * 1024 }) });\n    var d = await r.json();\n    if (!d.ok) throw new Error(d.error);\n    toast(gb + 'GB به ' + u + ' اضافه شد');\n    cm('m-traf');\n    loadAll();\n  } catch (e) { toast(e.message, 'err'); }\n}\n\nfunction openExtend(username) { document.getElementById('me-user').value = username; document.getElementById('me-days').value = '30'; om('m-ext'); }\nasync function submitExtend() {\n  var u = document.getElementById('me-user').value;\n  var days = parseInt(document.getElementById('me-days').value);\n  if (!days || days <= 0) { toast('مقدار نامعتبر', 'err'); return; }\n  try {\n    var r = await fetch('/api/users/' + encodeURIComponent(u) + '/extend', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ extra_days: days }) });\n    var d = await r.json();\n    if (!d.ok) throw new Error(d.error);\n    toast(days + ' روز به ' + u + ' اضافه شد');\n    cm('m-ext');\n    loadAll();\n  } catch (e) { toast(e.message, 'err'); }\n}\n\n// ── PACKAGES ──────────────────────────────────────────────────────────────────\nfunction renderPackages() {\n  var wrap = document.getElementById('pkgs-wrap');\n  var pkgs = _D.packages.slice().sort(function (a, b) { return a.display_order - b.display_order; });\n  if (!pkgs.length) { wrap.innerHTML = '<div class=\"empty\">بسته‌ای تعریف نشده</div>'; return; }\n  var rows = pkgs.map(function (p) {\n    return '<tr>' +\n      '<td><b>' + p.name + '</b></td>' +\n      '<td><span class=\"badge b-m\">' + p.traffic_amount + ' ' + p.traffic_unit.toUpperCase() + '</span></td>' +\n      '<td><span class=\"badge b-b\">⏳ ' + (p.duration_days || 30) + ' روز</span></td>' +\n      '<td>' + (p.price_irr != null ? '<span class=\"badge b-g\">' + Number(p.price_irr).toLocaleString('fa-IR', { maximumFractionDigits: 0 }) + ' T</span>' : '<span class=\"badge b-y\">دستی</span>') + '</td>' +\n      '<td>' + (p.is_active ? '<span class=\"badge b-g\">فعال</span>' : '<span class=\"badge b-r\">غیرفعال</span>') + '</td>' +\n      '<td style=\"display:flex;gap:6px\">' +\n      '<button class=\"btn btn-sm btn-y\" onclick=\\'openEditPkg(' + JSON.stringify(JSON.stringify(p)) + ')\\'>✏️</button>' +\n      '<button class=\"btn btn-sm btn-r\" onclick=\"delPkg(' + p.id + ',\\'' + p.name + '\\')\">🗑</button>' +\n      '</td></tr>';\n  }).join('');\n  wrap.innerHTML = '<div class=\"tbl-wrap\"><table><thead><tr><th>نام</th><th>حجم</th><th>مدت</th><th>قیمت</th><th>وضعیت</th><th>عملیات</th></tr></thead><tbody>' + rows + '</tbody></table></div>';\n}\nfunction openAddPkg() {\n  document.getElementById('m-pkg-title').textContent = '📦 بسته جدید';\n  document.getElementById('mp-id').value = '';\n  document.getElementById('mp-name').value = '';\n  document.getElementById('mp-traf').value = '1';\n  document.getElementById('mp-unit').value = 'gb';\n  document.getElementById('mp-price').value = '';\n  document.getElementById('mp-days').value = '30';\n  document.getElementById('mp-ord').value = '0';\n  document.getElementById('mp-active').checked = true;\n  om('m-pkg');\n}\nfunction openEditPkg(js) {\n  var p = JSON.parse(js);\n  document.getElementById('m-pkg-title').textContent = '✏️ ویرایش بسته';\n  document.getElementById('mp-id').value = p.id;\n  document.getElementById('mp-name').value = p.name;\n  document.getElementById('mp-traf').value = p.traffic_amount;\n  document.getElementById('mp-unit').value = p.traffic_unit || 'gb';\n  document.getElementById('mp-price').value = p.price_irr != null ? p.price_irr : '';\n  document.getElementById('mp-days').value = p.duration_days || 30;\n  document.getElementById('mp-ord').value = p.display_order;\n  document.getElementById('mp-active').checked = !!p.is_active;\n  om('m-pkg');\n}\nasync function submitPkg() {\n  var prRaw = document.getElementById('mp-price').value.trim();\n  var d = { id: document.getElementById('mp-id').value || null, name: document.getElementById('mp-name').value.trim(), traffic_amount: parseInt(document.getElementById('mp-traf').value) || 0, traffic_unit: document.getElementById('mp-unit').value, price_irr: prRaw === '' ? null : parseFloat(prRaw), duration_days: parseInt(document.getElementById('mp-days').value) || 30, display_order: parseInt(document.getElementById('mp-ord').value) || 0, is_active: document.getElementById('mp-active').checked };\n  if (!d.name) { toast('نام بسته اجباری است', 'err'); return; }\n  try {\n    var r = await fetch('/api/packages/upsert', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(d) });\n    var x = await r.json();\n    if (!x.ok) throw new Error(x.error);\n    toast('بسته ذخیره شد');\n    cm('m-pkg');\n    loadAll();\n  } catch (e) { toast(e.message, 'err'); }\n}\nasync function delPkg(id, name) {\n  if (!confirm('حذف بسته «' + name + '»؟')) return;\n  try {\n    var r = await fetch('/api/packages/delete', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id: id }) });\n    var d = await r.json();\n    if (!d.ok) throw new Error(d.error);\n    toast('بسته حذف شد');\n    loadAll();\n  } catch (e) { toast(e.message, 'err'); }\n}\n\n// ── PAYMENTS ──────────────────────────────────────────────────────────────────\nfunction renderPayments() {\n  var wrap = document.getElementById('pay-wrap');\n  var list = _D.payments;\n  if (!list.length) { wrap.innerHTML = '<div class=\"empty\">پرداختی نیست</div>'; return; }\n  var rows = list.map(function (p) {\n    var sb;\n    if (p.status === 'approved') sb = '<span class=\"badge b-g\">تأیید</span>';\n    else if (p.status === 'expired') sb = '<span class=\"badge b-r\">منقضی</span>';\n    else sb = '<span class=\"badge b-y\">' + p.status + '</span>';\n    return '<tr>' +\n      '<td><b>#' + p.id + '</b></td>' +\n      '<td><code>' + p.username + '</code></td>' +\n      '<td><span class=\"badge b-m\">' + (p.pkg_name || '—') + '</span></td>' +\n      '<td><b>' + (p.amount_irr ? Number(p.amount_irr).toLocaleString('fa-IR', { maximumFractionDigits: 0 }) + ' T' : '—') + '</b></td>' +\n      '<td>' + sb + '</td>' +\n      '<td style=\"font-size:11px;color:var(--mut)\">' + (p.created_at || '').slice(0, 16) + '</td>' +\n      '<td>' + (p.status === 'pending' ? '<button class=\"btn btn-sm btn-g\" onclick=\"approvePay(' + p.id + ',this)\">✅ تأیید</button>' : '') + '</td>' +\n      '</tr>';\n  }).join('');\n  wrap.innerHTML = '<div class=\"tbl-wrap\"><table><thead><tr><th>#</th><th>کاربر</th><th>بسته</th><th>مبلغ</th><th>وضعیت</th><th>تاریخ</th><th>عملیات</th></tr></thead><tbody>' + rows + '</tbody></table></div>';\n}\nasync function approvePay(id, btn) {\n  btn.disabled = true; btn.textContent = '...';\n  try {\n    var r = await fetch('/api/payments/approve', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ payment_id: id }) });\n    var d = await r.json();\n    if (!d.ok) throw new Error(d.error);\n    toast('پرداخت #' + id + ' تأیید شد');\n    loadAll();\n  } catch (e) { toast(e.message, 'err'); btn.disabled = false; btn.textContent = '✅ تأیید'; }\n}\n\n// ── SETTINGS ──────────────────────────────────────────────────────────────────\nasync function loadSettings() {\n  try {\n    var r = await fetch('/api/settings/bulk');\n    var s = await r.json();\n    s = s || {};\n    document.getElementById('gset-tetra-en').checked = s.payment_tetra_enabled === '1' || s.payment_tetra_enabled === true;\n    if (s.tetra_api_key) document.getElementById('gset-tetra-key').placeholder = '(ذخیره شده)';\n    document.getElementById('gset-aryalleh-url').value = s.aryalleh_base_url || '';\n    document.getElementById('gset-portal-url').value = s.portal_base_url || '';\n    document.getElementById('gset-callback-url').textContent = (s.portal_base_url || '') + '/api/payment/callback';\n    document.getElementById('tetra-callback-url').textContent = (s.portal_base_url || '') + '/api/payment/callback';\n    if (s.telegram_bot_token) document.getElementById('gset-bot-token').placeholder = '(ذخیره شده)';\n    document.getElementById('gset-channel-id').value = s.telegram_channel_id || '';\n    document.getElementById('gset-gate-channel-id').value = s.telegram_gate_channel_id || '';\n  } catch (e) {}\n}\nasync function setGlobalSetting(key, val) {\n  var settings = {}; settings[key] = val ? '1' : '0';\n  try {\n    var r = await fetch('/api/settings/bulk', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ settings: settings }) });\n    var d = await r.json();\n    if (d && d.error) throw new Error(d.error);\n    toast(key + ' → ' + (val ? 'on' : 'off'));\n  } catch (e) { toast(e.message, 'err'); }\n}\nasync function savePortalURL() {\n  var url = document.getElementById('gset-portal-url').value.trim();\n  if (!url) { toast('آدرس نمی‌تواند خالی باشد', 'err'); return; }\n  try {\n    await fetch('/api/settings/bulk', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ settings: { portal_base_url: url } }) });\n    document.getElementById('gset-callback-url').textContent = url + '/api/payment/callback';\n    document.getElementById('tetra-callback-url').textContent = url + '/api/payment/callback';\n    toast('آدرس پورتال ذخیره شد');\n  } catch (e) { toast(e.message, 'err'); }\n}\nasync function saveTetraKey() {\n  var key = document.getElementById('gset-tetra-key').value.trim();\n  if (!key) { toast('API Key خالی است', 'err'); return; }\n  try {\n    await fetch('/api/settings/bulk', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ settings: { tetra_api_key: key } }) });\n    document.getElementById('gset-tetra-key').value = '';\n    document.getElementById('gset-tetra-key').placeholder = '(ذخیره شده)';\n    toast('API Key AryallehPay ذخیره شد');\n  } catch (e) { toast(e.message, 'err'); }\n}\nasync function saveAryallehUrl() {\n  var url = document.getElementById('gset-aryalleh-url').value.trim();\n  if (!url) { toast('آدرس خالی است', 'err'); return; }\n  try {\n    await fetch('/api/settings/bulk', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ settings: { aryalleh_base_url: url } }) });\n    toast('آدرس AryallehPay ذخیره شد');\n  } catch (e) { toast(e.message, 'err'); }\n}\nasync function saveBotToken() {\n  var token = document.getElementById('gset-bot-token').value.trim();\n  if (!token) { toast('توکن خالی است', 'err'); return; }\n  try {\n    var r = await fetch('/api/settings/bulk', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ settings: { telegram_bot_token: token } }) });\n    var d = await r.json();\n    document.getElementById('gset-bot-token').value = '';\n    document.getElementById('gset-bot-token').placeholder = '(ذخیره شده)';\n    if (d && d.webhook_ok) toast('توکن ذخیره شد و webhook فعال شد');\n    else if (d && d.webhook_error) toast('توکن ذخیره شد ولی webhook فعال نشد: ' + d.webhook_error, 'err');\n    else toast('توکن ربات ذخیره شد');\n  } catch (e) { toast(e.message, 'err'); }\n}\nasync function saveChannelId() {\n  var id = document.getElementById('gset-channel-id').value.trim();\n  if (!id) { toast('شناسه خالی است', 'err'); return; }\n  try {\n    await fetch('/api/settings/bulk', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ settings: { telegram_channel_id: id } }) });\n    toast('شناسه کانال ذخیره شد');\n  } catch (e) { toast(e.message, 'err'); }\n}\nasync function saveGateChannelId() {\n  var id = document.getElementById('gset-gate-channel-id').value.trim();\n  try {\n    await fetch('/api/settings/bulk', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ settings: { telegram_gate_channel_id: id } }) });\n    toast('شناسه کانال عضویت اجباری ذخیره شد');\n  } catch (e) { toast(e.message, 'err'); }\n}\n\ndocument.querySelectorAll('.mo').forEach(function (el) { el.addEventListener('click', function (e) { if (e.target === el) el.classList.remove('open'); }); });\nsetInterval(loadAll, 90000);\nloadAll();\n</script>\n</body>\n</html>\n",
	status: "<!DOCTYPE html>\n<html lang=\"fa\" dir=\"rtl\">\n<head>\n<meta charset=\"UTF-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n<title>CrabVPN — پورتال شخصی</title>\n<link href=\"https://fonts.googleapis.com/css2?family=Vazirmatn:wght@300;400;500;600;700&display=swap\" rel=\"stylesheet\">\n<script src=\"https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js\"></script>\n<style>\n:root{--bg:#06080e;--s1:#0c0f18;--s2:#12172240;--bd:#1a2035;--acc:#38bdf8;--ac2:#818cf8;--grn:#34d399;--red:#f87171;--ylw:#fbbf24;--txt:#e2e8f0;--mut:#64748b;--f:'Vazirmatn',sans-serif}\n*{box-sizing:border-box;margin:0;padding:0}\nbody{background:var(--bg);color:var(--txt);font-family:var(--f);min-height:100vh;overflow-x:hidden}\nbody::before{content:'';position:fixed;inset:0;background-image:linear-gradient(rgba(56,189,248,.03) 1px,transparent 1px),linear-gradient(90deg,rgba(56,189,248,.03) 1px,transparent 1px);background-size:40px 40px;pointer-events:none;z-index:0}\n.wrap{position:relative;z-index:1;max-width:520px;margin:0 auto;padding:32px 20px}\n.top{text-align:center;margin-bottom:40px}\n.crab{font-size:52px;display:block;margin-bottom:12px;filter:drop-shadow(0 0 20px #38bdf855);animation:fl 4s ease-in-out infinite}\n@keyframes fl{0%,100%{transform:translateY(0) rotate(-3deg)}50%{transform:translateY(-8px) rotate(3deg)}}\n.title{font-size:28px;font-weight:700;background:linear-gradient(135deg,var(--acc),var(--ac2));-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:6px}\n.sub-name{font-size:16px;color:var(--mut);margin-bottom:4px}\n.sub-phone{font-size:13px;color:var(--bd);background:var(--s1);border:1px solid var(--bd);border-radius:8px;padding:4px 12px;display:inline-block}\n.sub-card{background:linear-gradient(135deg,var(--s1) 0%,#0d1220 100%);border:1px solid var(--bd);border-radius:16px;padding:22px;margin-bottom:14px;position:relative;overflow:hidden}\n.sub-card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,var(--acc),var(--ac2))}\n.pkg-badge{background:linear-gradient(135deg,#38bdf820,#818cf820);border:1px solid #38bdf830;color:var(--acc);border-radius:20px;padding:3px 12px;font-size:12px;font-weight:600;display:inline-block;margin-bottom:16px}\n.tbar-wrap{margin-bottom:16px}\n.tbar-labels{display:flex;justify-content:space-between;font-size:12px;color:var(--mut);margin-bottom:6px}\n.tbar-bg{height:8px;background:#1a2035;border-radius:4px;overflow:hidden}\n.tbar-fill{height:100%;border-radius:4px;transition:width .8s ease;background:linear-gradient(90deg,var(--grn),var(--acc))}\n.tbar-fill.warn{background:linear-gradient(90deg,var(--ylw),#f97316)}\n.tbar-fill.danger{background:linear-gradient(90deg,var(--red),#dc2626)}\n.tbar-pct{font-size:12px;color:var(--mut);margin-top:4px;text-align:left}\n.info-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:16px}\n.info-item{background:var(--bd)30;border:1px solid var(--bd);border-radius:10px;padding:10px 13px}\n.info-lbl{font-size:11px;color:var(--mut);margin-bottom:3px}\n.info-val{font-size:14px;font-weight:600}\n.cfg-wrap{background:#00000040;border:1px solid var(--bd);border-radius:10px;padding:12px 14px;margin-top:10px}\n.cfg-lbl{font-size:11px;color:var(--mut);margin-bottom:6px}\n.cfg-box{font-family:monospace;font-size:11px;word-break:break-all;color:#94a3b8;line-height:1.5;background:transparent;border:none;width:100%;outline:none;resize:none;direction:ltr;cursor:pointer}\n.copy-btn{display:inline-flex;align-items:center;gap:5px;padding:5px 12px;border-radius:6px;border:1px solid var(--bd);background:transparent;color:var(--acc);font-family:var(--f);font-size:12px;cursor:pointer;margin-top:6px;transition:all .2s}\n.copy-btn:hover{background:#38bdf815;border-color:#38bdf840}\n.copy-btn.copied{color:var(--grn);border-color:#34d39940}\n.add-btn{display:flex;align-items:center;justify-content:center;gap:6px;width:100%;margin-top:14px;padding:10px;border-radius:10px;border:1px solid #38bdf840;background:linear-gradient(135deg,#38bdf810,#818cf810);color:var(--acc);font-family:var(--f);font-size:14px;font-weight:600;cursor:pointer;transition:all .2s}\n.add-btn:hover{background:linear-gradient(135deg,#38bdf825,#818cf825);border-color:#38bdf870;transform:translateY(-1px)}\n.ref-btn{display:flex;align-items:center;justify-content:center;gap:5px;width:100%;margin-top:8px;padding:8px;border-radius:8px;border:1px solid var(--bd);background:transparent;color:var(--mut);font-family:var(--f);font-size:12px;cursor:pointer;transition:all .2s}\n.ref-btn:hover{color:var(--acc);border-color:#38bdf840}\n.ref-btn.loading{opacity:.6;pointer-events:none}\n.renew-blocked{margin-top:14px;padding:11px 14px;border-radius:10px;border:1px solid #fbbf2430;background:#fbbf2408;display:flex;align-items:flex-start;gap:8px;font-size:12px;color:#fbbf24;line-height:1.5}\n.empty-box,.err-box{text-align:center;padding:60px 20px;color:var(--mut)}\n.loading{text-align:center;padding:80px 20px}\n.spin{width:36px;height:36px;border:3px solid var(--bd);border-top-color:var(--acc);border-radius:50%;animation:sp .8s linear infinite;margin:0 auto 16px}\n@keyframes sp{to{transform:rotate(360deg)}}\n.footer{text-align:center;margin-top:48px;padding-top:24px;border-top:1px solid var(--bd);color:var(--mut);font-size:12px}\n.modal-overlay{position:fixed;inset:0;background:#00000090;backdrop-filter:blur(4px);z-index:100;display:flex;align-items:center;justify-content:center;padding:20px}\n.modal-box{background:linear-gradient(135deg,#0d1220,#0c0f18);border:1px solid var(--bd);border-radius:20px;padding:28px 24px;width:100%;max-width:420px;max-height:90vh;overflow-y:auto;position:relative}\n.modal-hd{font-size:18px;font-weight:700;margin-bottom:20px;text-align:center}\n.modal-close-x{position:absolute;top:16px;left:16px;background:transparent;border:none;color:var(--mut);font-size:20px;cursor:pointer;line-height:1;padding:4px 8px;border-radius:6px;transition:color .2s}\n.modal-close-x:hover{color:var(--txt)}\n.pkg-item{display:flex;align-items:center;justify-content:space-between;padding:14px 16px;border:1px solid var(--bd);border-radius:12px;margin-bottom:8px;cursor:pointer;transition:all .2s;background:#ffffff05}\n.pkg-item:hover{border-color:#38bdf860;background:#38bdf810}\n.pkg-item-name{font-size:15px;font-weight:600}\n.pkg-item-info{font-size:12px;color:var(--mut);margin-top:3px}\n.pkg-item-price{font-size:14px;font-weight:700;color:var(--acc);text-align:left;white-space:nowrap}\n.pay-timer{text-align:center;font-size:36px;font-weight:700;letter-spacing:4px;color:var(--acc);margin-bottom:6px;font-family:monospace}\n.pay-timer.warn{color:var(--ylw)}\n.pay-timer.danger{color:var(--red)}\n.pay-expire-lbl{text-align:center;font-size:12px;color:var(--mut);margin-bottom:20px}\n.pay-method-tabs{display:flex;gap:6px;margin-bottom:16px;flex-wrap:wrap}\n.pay-tab{flex:1;min-width:80px;padding:8px 4px;border:1px solid var(--bd);border-radius:8px;background:transparent;color:var(--mut);font-family:var(--f);font-size:12px;cursor:pointer;text-align:center;transition:all .2s}\n.pay-tab.active{border-color:#38bdf870;color:var(--acc);background:#38bdf810}\n.pay-section{display:none}\n.pay-section.visible{display:block}\n.copy-field-wrap{background:#00000050;border:1px solid var(--bd);border-radius:10px;padding:12px 14px;margin-bottom:10px}\n.copy-field-lbl{font-size:11px;color:var(--mut);margin-bottom:6px}\n.copy-field-val{font-size:18px;font-weight:700;color:var(--txt);direction:ltr;text-align:left;margin-bottom:4px;word-break:break-all}\n.copy-field-val.mono{font-family:monospace;font-size:14px;letter-spacing:2px}\n.copy-field-btn{display:inline-flex;align-items:center;gap:4px;padding:4px 10px;border-radius:6px;border:1px solid var(--bd);background:transparent;color:var(--acc);font-family:var(--f);font-size:11px;cursor:pointer;transition:all .2s}\n.copy-field-btn:hover{background:#38bdf815}\n.copy-field-btn.copied{color:var(--grn)}\n.amount-note{font-size:11px;color:var(--ylw);background:#fbbf2410;border:1px solid #fbbf2430;border-radius:8px;padding:8px 12px;margin-top:8px}\n.pay-status-area{text-align:center;padding:10px;font-size:13px;color:var(--mut);margin-top:8px}\n.success-overlay{position:absolute;inset:0;background:#0c0f18ee;border-radius:20px;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:12px;z-index:10}\n.success-ico{font-size:64px;animation:pop .4s ease-out}\n@keyframes pop{0%{transform:scale(0)}80%{transform:scale(1.15)}100%{transform:scale(1)}}\n.success-txt{font-size:22px;font-weight:700;color:var(--grn)}\n.success-sub{font-size:13px;color:var(--mut)}\n.tetra-link-btn{display:flex;align-items:center;justify-content:center;gap:8px;width:100%;padding:14px;border-radius:12px;border:1px solid #818cf840;background:linear-gradient(135deg,#818cf820,#6366f120);color:var(--ac2);font-family:var(--f);font-size:15px;font-weight:600;cursor:pointer;text-decoration:none;transition:all .2s;margin-bottom:10px}\n.tetra-link-btn:hover{background:linear-gradient(135deg,#818cf835,#6366f135)}\n.method-note{font-size:12px;color:var(--mut);text-align:center;margin-top:6px}\n.cancel-btn{width:100%;margin-top:14px;padding:10px;border-radius:10px;border:1px solid #f8717130;background:transparent;color:var(--red);font-family:var(--f);font-size:13px;cursor:pointer;transition:all .2s}\n.cancel-btn:hover{background:#f8717110}\n</style>\n</head>\n<body>\n<div class=\"wrap\">\n  <div class=\"top\">\n    <span class=\"crab\">🦀</span>\n    <div class=\"title\">CrabVPN</div>\n    <div class=\"sub-name\">پورتال شخصی</div>\n  </div>\n  <div id=\"content\">\n    <div class=\"loading\">\n      <div class=\"spin\"></div>\n      <div style=\"color:var(--mut);font-size:14px\">در حال بارگذاری...</div>\n    </div>\n  </div>\n  <div class=\"footer\">CrabVPN © — این لینک فقط مال شماست، به کسی ندهید.</div>\n</div>\n\n<div id=\"pkg-modal\" class=\"modal-overlay\" style=\"display:none\" onclick=\"if(event.target===this)closeModal('pkg-modal')\">\n  <div class=\"modal-box\">\n    <button class=\"modal-close-x\" onclick=\"closeModal('pkg-modal')\">✕</button>\n    <div class=\"modal-hd\">📦 انتخاب پکیج</div>\n    <div id=\"pkg-list\"><div class=\"loading\"><div class=\"spin\"></div></div></div>\n  </div>\n</div>\n\n<div id=\"pay-modal\" class=\"modal-overlay\" style=\"display:none\">\n  <div class=\"modal-box\" style=\"position:relative\">\n    <button class=\"modal-close-x\" onclick=\"cancelPayment()\">✕</button>\n    <div class=\"modal-hd\">💳 پرداخت</div>\n    <div id=\"pay-timer\" class=\"pay-timer\">--:--</div>\n    <div class=\"pay-expire-lbl\">زمان باقی‌مانده برای پرداخت</div>\n    <div id=\"pay-method-tabs\" class=\"pay-method-tabs\"></div>\n    <div id=\"pay-sections\"></div>\n    <div id=\"pay-status\" class=\"pay-status-area\">⏳ در انتظار تأیید پرداخت...</div>\n    <button class=\"cancel-btn\" onclick=\"cancelPayment()\">انصراف از پرداخت</button>\n    <div id=\"success-overlay\" class=\"success-overlay\" style=\"display:none\">\n      <div class=\"success-ico\">✅</div>\n      <div class=\"success-txt\">تایید شد!</div>\n      <div class=\"success-sub\">پرداخت شما با موفقیت تأیید شد.</div>\n      <div id=\"success-countdown\" style=\"font-size:12px;color:var(--mut)\"></div>\n    </div>\n  </div>\n</div>\n\n<script>\nconst uuid = location.pathname.split('/').pop();\nlet _pollTimer = null;\nlet _countdownTimer = null;\nlet _successShown = false;\n\nasync function load() {\n  try {\n    const r = await fetch(`/api/portal/${uuid}`);\n    const d = await r.json();\n    if (!d.ok) {\n      document.getElementById('content').innerHTML = `<div class=\"err-box\"><div style=\"font-size:48px;margin-bottom:16px\">🔒</div><div style=\"font-size:18px;margin-bottom:8px\">لینک نامعتبر</div><div style=\"font-size:13px\">این پورتال وجود ندارد یا منقضی شده</div></div>`;\n      return;\n    }\n    render(d);\n  } catch(e) {\n    document.getElementById('content').innerHTML = `<div class=\"err-box\"><div style=\"font-size:48px;margin-bottom:16px\">⚠️</div><div>خطای اتصال</div></div>`;\n  }\n}\n\nfunction fmb(mb) {\n  if (mb < 1024) return `${Math.round(mb).toLocaleString('fa-IR')} MB`;\n  return `${(mb/1024).toLocaleString('fa-IR',{minimumFractionDigits:2,maximumFractionDigits:2})} GB`;\n}\n\nfunction render(d) {\n  const c = d.customer;\n  const s = d.subscription;\n\n  let html = `\n    <div style=\"text-align:center;margin-bottom:24px\">\n      <div class=\"sub-name\">خوش آمدی${c.name ? ('، <b>' + c.name + '</b>') : ''}</div>\n      ${c.phone ? `<div class=\"sub-phone\">${c.phone}</div>` : ''}\n    </div>`;\n\n  if (!d.has_subscription) {\n    html += `<div class=\"sub-card\" style=\"text-align:center;padding:36px 22px\">\n      <div style=\"font-size:48px;margin-bottom:14px\">📦</div>\n      <div style=\"font-size:16px;font-weight:600;margin-bottom:8px\">هنوز بسته‌ای نداری</div>\n      <div style=\"font-size:13px;color:var(--mut);margin-bottom:18px\">اولین بسته‌ت رو انتخاب کن تا اشتراکت فعال بشه</div>\n      <button class=\"add-btn\" onclick=\"openAddTraffic()\">📦 انتخاب بسته</button>\n    </div>`;\n    document.getElementById('content').innerHTML = html;\n    return;\n  }\n\n  const pct = s.used_pct || 0;\n  const fillClass = pct > 85 ? 'danger' : pct > 60 ? 'warn' : '';\n  const expStr = s.expdate && s.expdate !== '—' ? s.expdate : 'بدون محدودیت';\n  let daysLeft = '—';\n  if (s.expdate) {\n    try {\n      const diff = Math.ceil((new Date(s.expdate) - new Date()) / 86400000);\n      daysLeft = diff >= 0 ? `${diff.toLocaleString('fa-IR')} روز` : '⛔ منقضی';\n    } catch(e) {}\n  }\n\n  const cfgHtml = s.config_text\n    ? `<div class=\"cfg-wrap\">\n         <div class=\"cfg-lbl\">📲 کانفیگ VLESS (تپ برای کپی)</div>\n         <textarea class=\"cfg-box\" rows=\"2\" readonly id=\"cfg-npv\" onclick=\"copyEl('cfg-npv','cbtn-npv')\">${s.config_text}</textarea>\n         <button class=\"copy-btn\" id=\"cbtn-npv\" onclick=\"copyEl('cfg-npv','cbtn-npv')\">📋 کپی</button>\n         <div id=\"qr-npv\" style=\"display:flex;justify-content:center;margin-top:12px;padding:12px;background:#fff;border-radius:10px\"></div>\n       </div>`\n    : '';\n\n  html += `<div class=\"sub-card\">\n    <div class=\"pkg-badge\">${s.pkg_name || 'اشتراک'}</div>\n    <div class=\"tbar-wrap\">\n      <div class=\"tbar-labels\">\n        <span id=\"lbl-remain\">باقی‌مانده: <b>${fmb(s.remaining_mb)}</b></span>\n        <span id=\"lbl-total\">کل: <b>${fmb(s.total_mb)}</b></span>\n      </div>\n      <div class=\"tbar-bg\">\n        <div class=\"tbar-fill ${fillClass}\" id=\"fill\" style=\"width:${pct}%\"></div>\n      </div>\n      <div class=\"tbar-pct\" id=\"lbl-pct\">${pct.toLocaleString('fa-IR')}٪ مصرف شده</div>\n    </div>\n    <div class=\"info-grid\">\n      <div class=\"info-item\">\n        <div class=\"info-lbl\">⏳ زمان باقی‌مانده</div>\n        <div class=\"info-val\" id=\"days-val\">${daysLeft}</div>\n      </div>\n      <div class=\"info-item\">\n        <div class=\"info-lbl\">📅 تاریخ انقضا</div>\n        <div class=\"info-val\" id=\"exp-val\">${expStr}</div>\n      </div>\n      <div class=\"info-item\">\n        <div class=\"info-lbl\">🕐 تاریخ خرید</div>\n        <div class=\"info-val\" style=\"font-size:12px\">${(s.created_at||'').slice(0,10)}</div>\n      </div>\n      <div class=\"info-item\">\n        <div class=\"info-lbl\">📊 مصرف</div>\n        <div class=\"info-val\">${pct.toLocaleString('fa-IR')}٪</div>\n      </div>\n    </div>\n    ${cfgHtml}\n    <div id=\"renew-area\">\n      <button class=\"add-btn\" onclick=\"openAddTraffic()\">➕ افزودن حجم / تمدید</button>\n    </div>\n  </div>`;\n\n  document.getElementById('content').innerHTML = html;\n\n  if (s.config_text && window.QRCode) {\n    new QRCode(document.getElementById('qr-npv'), {text: s.config_text, width: 200, height: 200,\n      colorDark: \"#000\", colorLight: \"#fff\", correctLevel: QRCode.CorrectLevel.M});\n  }\n\n}\n\nfunction copyEl(elId, btnId) {\n  const el  = document.getElementById(elId);\n  const btn = document.getElementById(btnId);\n  navigator.clipboard.writeText(el.value).then(() => {\n    const orig = btn.textContent;\n    btn.textContent = '✅ کپی شد!';\n    btn.classList.add('copied');\n    setTimeout(() => { btn.textContent = orig; btn.classList.remove('copied'); }, 2000);\n  });\n}\n\nasync function openAddTraffic() {\n  document.getElementById('pkg-list').innerHTML = '<div class=\"loading\"><div class=\"spin\"></div></div>';\n  document.getElementById('pkg-modal').style.display = 'flex';\n  try {\n    const r = await fetch(`/api/portal/packages`);\n    const d = await r.json();\n    if (!d.ok || !d.packages.length) {\n      document.getElementById('pkg-list').innerHTML = '<div style=\"text-align:center;color:var(--mut);padding:20px\">بسته‌ای موجود نیست</div>';\n      return;\n    }\n    let html = '';\n    d.packages.forEach(p => {\n      const price = p.price_irr ? `${Number(p.price_irr).toLocaleString('fa')} تومان` : 'دستی';\n      const traffic = p.traffic_unit === 'gb' ? `${p.traffic_amount} GB` : `${p.traffic_amount} MB`;\n      html += `<div class=\"pkg-item\" onclick=\"selectPackage(${p.id})\">\n        <div>\n          <div class=\"pkg-item-name\">${p.name}</div>\n          <div class=\"pkg-item-info\">حجم: ${traffic}</div>\n        </div>\n        <div class=\"pkg-item-price\">${price}</div>\n      </div>`;\n    });\n    document.getElementById('pkg-list').innerHTML = html;\n  } catch(e) {\n    document.getElementById('pkg-list').innerHTML = '<div style=\"text-align:center;color:var(--red);padding:20px\">خطای اتصال</div>';\n  }\n}\n\nasync function selectPackage(packageId) {\n  closeModal('pkg-modal');\n  document.getElementById('pay-modal').style.display = 'flex';\n  document.getElementById('pay-timer').textContent = '--:--';\n  document.getElementById('pay-timer').className = 'pay-timer';\n  document.getElementById('pay-method-tabs').innerHTML = '';\n  document.getElementById('pay-sections').innerHTML = '<div class=\"loading\"><div class=\"spin\"></div></div>';\n  document.getElementById('pay-status').textContent = '⏳ در حال آماده‌سازی...';\n  document.getElementById('success-overlay').style.display = 'none';\n  _successShown = false;\n\n  try {\n    const r = await fetch(`/api/portal/${uuid}/payment`, {\n      method: 'POST',\n      headers: {'Content-Type': 'application/json'},\n      body: JSON.stringify({package_id: packageId}),\n    });\n    const d = await r.json();\n    if (!d.ok) {\n      document.getElementById('pay-sections').innerHTML = `<div style=\"text-align:center;color:var(--red);padding:20px\">${d.error || 'خطا'}</div>`;\n      return;\n    }\n    renderPaymentModal(d);\n    startCountdown(d.expires_at);\n    startPolling(d.payment_id);\n  } catch(e) {\n    document.getElementById('pay-sections').innerHTML = '<div style=\"text-align:center;color:var(--red);padding:20px\">خطای اتصال</div>';\n  }\n}\n\nfunction renderPaymentModal(d) {\n  const methods = Object.keys(d.methods || {});\n  const tabsEl  = document.getElementById('pay-method-tabs');\n  const secEl   = document.getElementById('pay-sections');\n  const labels = {tetra: '⚡ آنلاین'};\n\n  tabsEl.innerHTML = '';\n  if (methods.length > 1) {\n    methods.forEach(m => {\n      const btn = document.createElement('button');\n      btn.className = 'pay-tab';\n      btn.textContent = labels[m] || m;\n      btn.onclick = () => showTab(m);\n      btn.id = `tab-${m}`;\n      tabsEl.appendChild(btn);\n    });\n  }\n\n  let sectionsHtml = '';\n  if (d.methods.tetra) {\n    const t = d.methods.tetra;\n    const hasUrl = t.url && !t.error;\n    sectionsHtml += `<div id=\"sec-tetra\" class=\"pay-section\">\n      ${hasUrl\n        ? `<a class=\"tetra-link-btn\" href=\"${t.url}\" target=\"_blank\">⚡ پرداخت آنلاین</a>\n           <div class=\"method-note\">بعد از پرداخت آنلاین به این صفحه برگردید</div>`\n        : `<div style=\"text-align:center;color:var(--red);padding:16px;font-size:13px\">⚠️ درگاه آنلاین موقتاً در دسترس نیست</div>`\n      }\n    </div>`;\n  }\n  secEl.innerHTML = sectionsHtml;\n  if (methods.length > 0) showTab(methods[0]);\n  document.getElementById('pay-status').textContent = '⏳ در انتظار تأیید پرداخت...';\n}\n\nfunction showTab(method) {\n  document.querySelectorAll('.pay-section').forEach(el => el.classList.remove('visible'));\n  document.querySelectorAll('.pay-tab').forEach(el => el.classList.remove('active'));\n  const sec = document.getElementById(`sec-${method}`);\n  if (sec) sec.classList.add('visible');\n  const tab = document.getElementById(`tab-${method}`);\n  if (tab) tab.classList.add('active');\n}\n\nfunction startCountdown(expiresAt) {\n  if (_countdownTimer) clearInterval(_countdownTimer);\n  const expMs = new Date(expiresAt).getTime();\n  function tick() {\n    const rem = Math.max(0, Math.floor((expMs - Date.now()) / 1000));\n    const mm = String(Math.floor(rem / 60)).padStart(2, '0');\n    const ss = String(rem % 60).padStart(2, '0');\n    const el = document.getElementById('pay-timer');\n    if (!el) { clearInterval(_countdownTimer); return; }\n    el.textContent = `${mm}:${ss}`;\n    el.className = 'pay-timer' + (rem < 60 ? ' danger' : rem < 180 ? ' warn' : '');\n    if (rem <= 0) {\n      clearInterval(_countdownTimer);\n      document.getElementById('pay-status').textContent = '⛔ مهلت پرداخت منقضی شد.';\n    }\n  }\n  tick();\n  _countdownTimer = setInterval(tick, 1000);\n}\n\nfunction startPolling(paymentId) {\n  if (_pollTimer) clearInterval(_pollTimer);\n  _pollTimer = setInterval(() => pollStatus(paymentId), 3000);\n}\n\nasync function pollStatus(paymentId) {\n  try {\n    const r = await fetch(`/api/portal/${uuid}/payment/${paymentId}/status`);\n    const d = await r.json();\n    if (!d.ok) return;\n    if (d.status === 'approved') {\n      stopPolling();\n      showSuccess();\n    } else if (d.status === 'expired') {\n      stopPolling();\n      if (_countdownTimer) clearInterval(_countdownTimer);\n      document.getElementById('pay-status').textContent = '⛔ مهلت پرداخت منقضی شد.';\n    }\n  } catch(e) {}\n}\n\nfunction stopPolling() {\n  if (_pollTimer) { clearInterval(_pollTimer); _pollTimer = null; }\n}\n\nfunction showSuccess() {\n  if (_successShown) return;\n  _successShown = true;\n  if (_countdownTimer) { clearInterval(_countdownTimer); _countdownTimer = null; }\n  const overlay = document.getElementById('success-overlay');\n  overlay.style.display = 'flex';\n  let sec = 10;\n  const cntEl = document.getElementById('success-countdown');\n  cntEl.textContent = `بسته می‌شود در ${sec} ثانیه`;\n  const t = setInterval(() => {\n    sec--;\n    if (sec <= 0) { clearInterval(t); closeModal('pay-modal'); load(); return; }\n    cntEl.textContent = `بسته می‌شود در ${sec} ثانیه`;\n  }, 1000);\n}\n\nfunction closeModal(id) {\n  document.getElementById(id).style.display = 'none';\n}\n\nfunction cancelPayment() {\n  stopPolling();\n  if (_countdownTimer) { clearInterval(_countdownTimer); _countdownTimer = null; }\n  _successShown = false;\n  document.getElementById('pay-modal').style.display = 'none';\n}\n\ndocument.querySelectorAll('.modal-overlay').forEach(el=>el.addEventListener('click',e=>{if(e.target===el)el.style.display='none'}));\nload();\n</script>\n</body>\n</html>\n",
};
