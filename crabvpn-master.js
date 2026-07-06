import { DASHBOARD_HTML, PORTAL_HTML } from "./pages.generated.js";

const SESSION_DAYS = 7;
const OTP_TTL_MS = 5 * 60 * 1000;
const ARYALLEHPAY_BASE = "https://pay.aryalleh.ir";

const Utils = {
	async sha256(message) {
		const buf = new TextEncoder().encode(message);
		const hash = await crypto.subtle.digest("SHA-256", buf);
		return Array.from(new Uint8Array(hash)).map((b) => b.toString(16).padStart(2, "0")).join("");
	},
	randomHex(bytes = 32) {
		const arr = new Uint8Array(bytes);
		crypto.getRandomValues(arr);
		return Array.from(arr).map((b) => b.toString(16).padStart(2, "0")).join("");
	},
	randomOtp() {
		return String(Math.floor(100000 + Math.random() * 900000));
	},
	json(obj, status = 200) {
		return new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json; charset=utf-8" } });
	},
	html(str, status = 200) {
		return new Response(str, { status, headers: { "Content-Type": "text/html; charset=utf-8" } });
	},
	toMb(amount, unit) {
		const n = Number(amount) || 0;
		return unit === "mb" ? n : n * 1024;
	},
	addDaysIso(fromIso, days) {
		const base = fromIso ? new Date(fromIso) : new Date();
		const d = new Date(base.getTime() + Number(days || 0) * 86400000);
		return d.toISOString().slice(0, 10);
	},
	nowIso() {
		return new Date().toISOString();
	},
	uuid() {
		return crypto.randomUUID();
	},
};

const DbService = {
	async ensureSchema(db) {
		const stmts = [
			`CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)`,
			`CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, created_at TEXT, expires_at TEXT)`,
			`CREATE TABLE IF NOT EXISTS servers (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				name TEXT NOT NULL,
				flag TEXT DEFAULT '🌍',
				location TEXT,
				server_type TEXT DEFAULT 'ssh',
				xpanel_url TEXT NOT NULL,
				xpanel_token TEXT,
				ssh_host TEXT DEFAULT '127.0.0.1',
				ssh_port INTEGER DEFAULT 22,
				xpanel_username TEXT,
				xpanel_password TEXT,
				xpanel_inbound_id INTEGER DEFAULT 1,
				xpanel_webbasepath TEXT DEFAULT '/',
				display_order INTEGER DEFAULT 0,
				sales_open INTEGER DEFAULT 1,
				renewal_open INTEGER DEFAULT 1,
				free_trial INTEGER DEFAULT 0,
				is_active INTEGER DEFAULT 1,
				created_at TEXT DEFAULT CURRENT_TIMESTAMP
			)`,
			`CREATE TABLE IF NOT EXISTS packages (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				server_id INTEGER NOT NULL,
				name TEXT NOT NULL,
				traffic_amount INTEGER DEFAULT 0,
				traffic_unit TEXT DEFAULT 'gb',
				price_irr REAL,
				duration_days INTEGER DEFAULT 30,
				display_order INTEGER DEFAULT 0,
				is_active INTEGER DEFAULT 1
			)`,
			`CREATE TABLE IF NOT EXISTS customers (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				name TEXT,
				phone TEXT,
				portal_token TEXT UNIQUE NOT NULL,
				created_at TEXT DEFAULT CURRENT_TIMESTAMP
			)`,
			`CREATE TABLE IF NOT EXISTS orders (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				customer_id INTEGER NOT NULL,
				server_id INTEGER NOT NULL,
				package_id INTEGER,
				xpanel_user TEXT NOT NULL,
				xpanel_uuid TEXT,
				total_mb INTEGER DEFAULT 0,
				used_mb INTEGER DEFAULT 0,
				duration_days INTEGER DEFAULT 30,
				expdate TEXT,
				is_active INTEGER DEFAULT 1,
				created_at TEXT DEFAULT CURRENT_TIMESTAMP
			)`,
			`CREATE TABLE IF NOT EXISTS payments (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				order_id INTEGER,
				server_id INTEGER,
				package_id INTEGER,
				method TEXT,
				amount_irr REAL,
				status TEXT DEFAULT 'pending',
				card_number TEXT,
				card_owner TEXT,
				tetra_pay_token TEXT,
				tetra_pay_url TEXT,
				tetra_tx_id TEXT,
				payer_name TEXT,
				full_name TEXT,
				telegram_username TEXT,
				pkg_name TEXT,
				expires_at TEXT,
				created_at TEXT DEFAULT CURRENT_TIMESTAMP
			)`,
		];
		for (const s of stmts) {
			try {
				await db.prepare(s).run();
			} catch (e) {}
		}
	},
	async getSetting(db, key) {
		const row = await db.prepare("SELECT value FROM settings WHERE key = ?").bind(key).first();
		return row ? row.value : null;
	},
	async getAllSettings(db) {
		const { results } = await db.prepare("SELECT key, value FROM settings").all();
		const out = {};
		for (const r of results || []) out[r.key] = r.value;
		return out;
	},
	async setSetting(db, key, value) {
		await db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)").bind(key, String(value)).run();
	},
	async createSession(db, token) {
		const expiresAt = new Date(Date.now() + SESSION_DAYS * 86400000).toISOString();
		await db.prepare("INSERT INTO sessions (token, created_at, expires_at) VALUES (?, ?, ?)").bind(token, Utils.nowIso(), expiresAt).run();
	},
	async validateSession(db, token) {
		if (!token) return false;
		const row = await db.prepare("SELECT expires_at FROM sessions WHERE token = ?").bind(token).first();
		if (!row) return false;
		return new Date(row.expires_at).getTime() > Date.now();
	},
};

// ── Server communication layer ──────────────────────────────────────────────
// Both clients expose: createAccount, addTraffic, extendDays, getStats, testConnection

function SshPanelClient(server) {
	const base = server.xpanel_url.replace(/\/$/, "");
	async function cookie() {
		return "panel_session=" + (await Utils.sha256(server.xpanel_token || ""));
	}
	async function listUsers() {
		const res = await fetch(base + "/api/users", { headers: { Cookie: await cookie() } });
		if (!res.ok) throw new Error("xpanel list failed: " + res.status);
		return res.json();
	}
	async function findUser(username) {
		const list = await listUsers();
		const arr = Array.isArray(list) ? list : list.results || list.users || [];
		return arr.find((u) => u.username === username) || null;
	}
	return {
		async createAccount({ username, totalMb, durationDays }) {
			const uuid = Utils.uuid();
			const body = {
				username,
				uuid,
				limit_gb: (Number(totalMb) || 0) / 1024,
				expiry_days: Number(durationDays) || 30,
				limit_req: 0,
				ips: 0,
				connection_type: "vless",
				tls: "tls",
				port: 443,
				fingerprint: "chrome",
				max_connections: 0,
				ip_limit: 0,
				used_gb: 0,
				used_req: 0,
				created_at: Utils.nowIso(),
				is_active: 1,
				block_porn: 0,
				block_ads: 0,
				frag_len: "20-30",
				frag_int: "1-2",
			};
			const res = await fetch(base + "/api/users", {
				method: "POST",
				headers: { "Content-Type": "application/json", Cookie: await cookie() },
				body: JSON.stringify(body),
			});
			const d = await res.json().catch(() => ({}));
			if (!res.ok || d.error) throw new Error(d.error || "create failed");
			return { xpanelUser: username, xpanelUuid: uuid };
		},
		async addTraffic(username, extraMb) {
			const u = await findUser(username);
			if (!u) throw new Error("user not found on server");
			const newLimitGb = Number(u.limit_gb || 0) + Number(extraMb || 0) / 1024;
			const res = await fetch(base + "/api/users/" + encodeURIComponent(username), {
				method: "PUT",
				headers: { "Content-Type": "application/json", Cookie: await cookie() },
				body: JSON.stringify({ username, limit_gb: newLimitGb, expiry_days: u.expiry_days, ips: u.ips, tls: u.tls, port: u.port, fingerprint: u.fingerprint, ip_limit: u.ip_limit, block_porn: u.block_porn, block_ads: u.block_ads, frag_len: u.frag_len, frag_int: u.frag_int }),
			});
			const d = await res.json().catch(() => ({}));
			if (!res.ok || d.error) throw new Error(d.error || "traffic update failed");
		},
		async extendDays(username, extraDays) {
			const u = await findUser(username);
			if (!u) throw new Error("user not found on server");
			const newExpiryDays = Number(u.expiry_days || 0) + Number(extraDays || 0);
			const res = await fetch(base + "/api/users/" + encodeURIComponent(username), {
				method: "PUT",
				headers: { "Content-Type": "application/json", Cookie: await cookie() },
				body: JSON.stringify({ username, limit_gb: u.limit_gb, expiry_days: newExpiryDays, ips: u.ips, tls: u.tls, port: u.port, fingerprint: u.fingerprint, ip_limit: u.ip_limit, block_porn: u.block_porn, block_ads: u.block_ads, frag_len: u.frag_len, frag_int: u.frag_int }),
			});
			const d = await res.json().catch(() => ({}));
			if (!res.ok || d.error) throw new Error(d.error || "extend failed");
		},
		async getStats(username) {
			const u = await findUser(username);
			if (!u) return null;
			return {
				usedMb: Number(u.used_gb || 0) * 1024,
				totalMb: Number(u.limit_gb || 0) * 1024,
				expdate: Utils.addDaysIso(u.created_at, u.expiry_days),
			};
		},
		async testConnection() {
			const start = Date.now();
			try {
				await listUsers();
				return { connected: true, latencyMs: Date.now() - start };
			} catch (e) {
				return { connected: false, error: e.message };
			}
		},
	};
}

function XrayPanelClient(server) {
	const base = server.xpanel_url.replace(/\/$/, "") + (server.xpanel_webbasepath && server.xpanel_webbasepath !== "/" ? server.xpanel_webbasepath.replace(/\/$/, "") : "");
	const inboundId = server.xpanel_inbound_id || 1;
	async function login() {
		const res = await fetch(base + "/login", {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({ username: server.xpanel_username || "", password: server.xpanel_password || "" }),
		});
		const setCookie = res.headers.get("Set-Cookie");
		if (!res.ok || !setCookie) throw new Error("3x-ui login failed");
		return setCookie.split(";")[0];
	}
	async function getInbound(cookie) {
		const res = await fetch(base + "/panel/api/inbounds/list", { headers: { Cookie: cookie } });
		const d = await res.json().catch(() => ({}));
		if (!res.ok || !d.success) throw new Error("3x-ui list inbounds failed");
		return (d.obj || []).find((x) => x.id === Number(inboundId));
	}
	function parseClients(inbound) {
		try {
			return JSON.parse(inbound.settings).clients || [];
		} catch (e) {
			return [];
		}
	}
	return {
		async createAccount({ username, totalMb, durationDays }) {
			const cookie = await login();
			const uuid = Utils.uuid();
			const client = {
				id: uuid,
				email: username,
				enable: true,
				totalGB: 0,
				total: Math.round((Number(totalMb) || 0) * 1024 * 1024),
				expiryTime: Date.now() + (Number(durationDays) || 30) * 86400000,
				limitIp: 0,
			};
			const res = await fetch(base + "/panel/api/inbounds/addClient", {
				method: "POST",
				headers: { "Content-Type": "application/json", Cookie: cookie },
				body: JSON.stringify({ id: Number(inboundId), settings: JSON.stringify({ clients: [client] }) }),
			});
			const d = await res.json().catch(() => ({}));
			if (!res.ok || !d.success) throw new Error(d.msg || "3x-ui create client failed");
			return { xpanelUser: username, xpanelUuid: uuid };
		},
		async addTraffic(username, extraMb) {
			const cookie = await login();
			const inbound = await getInbound(cookie);
			const clients = parseClients(inbound);
			const c = clients.find((x) => x.email === username);
			if (!c) throw new Error("client not found on server");
			c.total = Number(c.total || 0) + Math.round((Number(extraMb) || 0) * 1024 * 1024);
			const res = await fetch(base + "/panel/api/inbounds/updateClient/" + c.id, {
				method: "POST",
				headers: { "Content-Type": "application/json", Cookie: cookie },
				body: JSON.stringify({ id: Number(inboundId), settings: JSON.stringify({ clients: [c] }) }),
			});
			const d = await res.json().catch(() => ({}));
			if (!res.ok || !d.success) throw new Error(d.msg || "3x-ui traffic update failed");
		},
		async extendDays(username, extraDays) {
			const cookie = await login();
			const inbound = await getInbound(cookie);
			const clients = parseClients(inbound);
			const c = clients.find((x) => x.email === username);
			if (!c) throw new Error("client not found on server");
			const base_ts = c.expiryTime && c.expiryTime > 0 ? c.expiryTime : Date.now();
			c.expiryTime = base_ts + (Number(extraDays) || 0) * 86400000;
			const res = await fetch(base + "/panel/api/inbounds/updateClient/" + c.id, {
				method: "POST",
				headers: { "Content-Type": "application/json", Cookie: cookie },
				body: JSON.stringify({ id: Number(inboundId), settings: JSON.stringify({ clients: [c] }) }),
			});
			const d = await res.json().catch(() => ({}));
			if (!res.ok || !d.success) throw new Error(d.msg || "3x-ui extend failed");
		},
		async getStats(username) {
			const cookie = await login();
			const inbound = await getInbound(cookie);
			if (!inbound) return null;
			const clients = parseClients(inbound);
			const c = clients.find((x) => x.email === username);
			const stat = (inbound.clientStats || []).find((x) => x.email === username);
			if (!c && !stat) return null;
			const usedMb = stat ? (Number(stat.up || 0) + Number(stat.down || 0)) / 1024 / 1024 : 0;
			const totalMb = c && c.total ? Number(c.total) / 1024 / 1024 : 0;
			const expdate = c && c.expiryTime ? new Date(c.expiryTime).toISOString().slice(0, 10) : null;
			return { usedMb, totalMb, expdate };
		},
		async testConnection() {
			const start = Date.now();
			try {
				const cookie = await login();
				await getInbound(cookie);
				return { connected: true, latencyMs: Date.now() - start };
			} catch (e) {
				return { connected: false, error: e.message };
			}
		},
	};
}

function getPanelClient(server) {
	return server.server_type === "xray" ? XrayPanelClient(server) : SshPanelClient(server);
}

// ── AryallehPay gateway client ───────────────────────────────────────────────

const AryallehPay = {
	async create(apiKey, { orderId, amountRials, description, expiresMinutes, redirectUrl }) {
		const res = await fetch(ARYALLEHPAY_BASE + "/api/payment/create", {
			method: "POST",
			headers: { Authorization: "Bearer " + apiKey, "Content-Type": "application/json" },
			body: JSON.stringify({ order_id: orderId, amount_rials: amountRials, description, expires_minutes: expiresMinutes, redirect_url: redirectUrl }),
		});
		const d = await res.json().catch(() => ({}));
		return { ok: res.ok && d.ok, ...d };
	},
	async status(apiKey, orderId) {
		const res = await fetch(ARYALLEHPAY_BASE + "/api/payment/status/" + encodeURIComponent(orderId), {
			headers: { Authorization: "Bearer " + apiKey },
		});
		const d = await res.json().catch(() => ({}));
		return { ok: res.ok && d.ok, ...d };
	},
	async manualConfirm(apiKey, paymentId, note) {
		const res = await fetch(ARYALLEHPAY_BASE + "/api/payment/manual-confirm", {
			method: "POST",
			headers: { Authorization: "Bearer " + apiKey, "Content-Type": "application/json" },
			body: JSON.stringify({ payment_id: paymentId, note }),
		});
		const d = await res.json().catch(() => ({}));
		return { ok: res.ok && d.ok, ...d };
	},
};

// ── Payment activation (shared by admin approve / sms match / aryallehpay callback) ──

async function activatePayment(db, env, payment) {
	if (payment.status === "approved") return;
	await db.prepare("UPDATE payments SET status = 'approved' WHERE id = ?").bind(payment.id).run();
	if (!payment.order_id) return;
	const order = await db.prepare("SELECT * FROM orders WHERE id = ?").bind(payment.order_id).first();
	if (!order) return;
	const pkg = payment.package_id ? await db.prepare("SELECT * FROM packages WHERE id = ?").bind(payment.package_id).first() : null;
	const extraMb = pkg ? Utils.toMb(pkg.traffic_amount, pkg.traffic_unit) : 0;
	const extraDays = pkg ? Number(pkg.duration_days || 30) : 30;
	const server = await db.prepare("SELECT * FROM servers WHERE id = ?").bind(order.server_id).first();
	if (server) {
		const client = getPanelClient(server);
		try {
			if (extraMb) await client.addTraffic(order.xpanel_user, extraMb);
			if (extraDays) await client.extendDays(order.xpanel_user, extraDays);
		} catch (e) {}
	}
	await db
		.prepare("UPDATE orders SET total_mb = total_mb + ?, duration_days = duration_days + ?, expdate = ?, package_id = COALESCE(?, package_id) WHERE id = ?")
		.bind(extraMb, extraDays, Utils.addDaysIso(order.expdate || order.created_at, extraDays), payment.package_id || null, order.id)
		.run();
}

function parseBankSmsAmountRials(message) {
	const m = String(message || "").match(/([\d,]{4,})\s*ریال/);
	if (!m) return null;
	return parseInt(m[1].replace(/,/g, ""), 10);
}

// ── Auth routes ──────────────────────────────────────────────────────────────

const AuthRoutes = {
	async otp(request, env, db) {
		const { secret } = await request.json().catch(() => ({}));
		if (!secret || String(secret).length < 4) return Utils.json({ ok: false, error: "کلمه عبور نامعتبر" }, 400);
		const stored = await DbService.getSetting(db, "admin_password_hash");
		const inputHash = await Utils.sha256(secret);
		if (!stored) {
			await DbService.setSetting(db, "admin_password_hash", inputHash);
		} else if (stored !== inputHash) {
			return Utils.json({ ok: false, error: "کلمه عبور اشتباه است" }, 401);
		}
		const code = Utils.randomOtp();
		await DbService.setSetting(db, "pending_otp", code + ":" + (Date.now() + OTP_TTL_MS));
		if (env.BOT_TOKEN && env.ADMIN_CHAT_ID) {
			try {
				await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/sendMessage`, {
					method: "POST",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify({ chat_id: env.ADMIN_CHAT_ID, text: `کد ورود پنل: ${code}` }),
				});
			} catch (e) {}
		}
		return Utils.json({ ok: true });
	},
	async login(request, db) {
		const { otp } = await request.json().catch(() => ({}));
		const stored = await DbService.getSetting(db, "pending_otp");
		if (!stored) return Utils.json({ ok: false, error: "کدی درخواست نشده" }, 400);
		const [code, expiresAt] = stored.split(":");
		if (Date.now() > Number(expiresAt)) return Utils.json({ ok: false, error: "کد منقضی شده" }, 400);
		if (String(otp).trim() !== code) return Utils.json({ ok: false, error: "کد اشتباه است" }, 401);
		const token = Utils.randomHex(32);
		await DbService.createSession(db, token);
		await db.prepare("DELETE FROM settings WHERE key = 'pending_otp'").run();
		return Utils.json({ ok: true, token });
	},
};

async function requireAdminToken(request, url, db) {
	let token = url.searchParams.get("token");
	if (!token && request.method !== "GET") {
		try {
			const clone = request.clone();
			const b = await clone.json();
			token = b.token;
		} catch (e) {}
	}
	return DbService.validateSession(db, token);
}

// ── Admin routes ─────────────────────────────────────────────────────────────

const AdminRoutes = {
	async data(url, db) {
		const servers = (await db.prepare("SELECT * FROM servers ORDER BY display_order ASC").all()).results || [];
		const totalsRow = await db
			.prepare("SELECT COUNT(DISTINCT customer_id) as total_customers, COUNT(*) as active_orders FROM orders WHERE is_active = 1")
			.first();
		const revRow = await db.prepare("SELECT COALESCE(SUM(amount_irr),0) as total FROM payments WHERE status = 'approved'").first();
		const monthRow = await db
			.prepare("SELECT COALESCE(SUM(amount_irr),0) as total FROM payments WHERE status = 'approved' AND strftime('%Y-%m', created_at) = strftime('%Y-%m','now')")
			.first();
		const monthly = (await db
			.prepare(
				"SELECT strftime('%Y-%m', created_at) as month, SUM(amount_irr) as revenue FROM payments WHERE status='approved' GROUP BY month ORDER BY month DESC LIMIT 6",
			)
			.all()).results || [];
		const daily = (await db
			.prepare(
				"SELECT date(created_at) as day, SUM(amount_irr) as revenue FROM payments WHERE status='approved' AND created_at >= date('now','-30 day') GROUP BY day ORDER BY day DESC",
			)
			.all()).results || [];
		const users = (await db
			.prepare(
				`SELECT o.id as order_id, o.server_id, o.xpanel_user, o.total_mb, o.used_mb, o.expdate, o.created_at,
					c.name, c.phone, c.portal_token,
					s.flag as server_flag, s.name as server_name,
					p.name as pkg
				 FROM orders o
				 JOIN customers c ON c.id = o.customer_id
				 LEFT JOIN servers s ON s.id = o.server_id
				 LEFT JOIN packages p ON p.id = o.package_id
				 ORDER BY o.id DESC`,
			)
			.all()).results || [];
		for (const u of users) u.remaining_mb = Math.max(0, Number(u.total_mb || 0) - Number(u.used_mb || 0));
		const pending = (await db
			.prepare(
				`SELECT pay.*, o.server_id as ord_server_id FROM payments pay LEFT JOIN orders o ON o.id = pay.order_id ORDER BY pay.id DESC LIMIT 100`,
			)
			.all()).results || [];
		const onlineCounts = {};
		for (const s of servers) onlineCounts[s.id] = 0;
		return Utils.json({
			ok: true,
			totals: { total_revenue: revRow.total, this_month_revenue: monthRow.total, total_customers: totalsRow.total_customers, active_orders: totalsRow.active_orders },
			online_counts: onlineCounts,
			monthly,
			daily,
			servers,
			users,
			pending,
		});
	},

	async settingsGet(db) {
		const s = await DbService.getAllSettings(db);
		delete s.admin_password_hash;
		delete s.pending_otp;
		return Utils.json({ ok: true, settings: s });
	},
	async settingsSet(request, db) {
		const { key, value } = await request.json();
		if (!key) return Utils.json({ ok: false, error: "key الزامی است" }, 400);
		await DbService.setSetting(db, key, typeof value === "boolean" ? (value ? "1" : "0") : value);
		return Utils.json({ ok: true });
	},

	async serversUpsert(request, db) {
		const b = await request.json();
		if (!b.name || !b.xpanel_url) return Utils.json({ ok: false, error: "نام و Panel URL اجباری است" }, 400);
		let configsUpdated = 0;
		if (b.id) {
			const prev = await db.prepare("SELECT ssh_host FROM servers WHERE id = ?").bind(b.id).first();
			if (prev && prev.ssh_host !== b.ssh_host) {
				const cnt = await db.prepare("SELECT COUNT(*) as c FROM orders WHERE server_id = ?").bind(b.id).first();
				configsUpdated = cnt ? cnt.c : 0;
			}
			await db
				.prepare(
					`UPDATE servers SET name=?, flag=?, location=?, server_type=?, xpanel_url=?, xpanel_token=?, ssh_host=?, ssh_port=?, xpanel_username=?, xpanel_password=?, xpanel_inbound_id=?, xpanel_webbasepath=?, display_order=?, sales_open=?, renewal_open=?, free_trial=?, is_active=? WHERE id=?`,
				)
				.bind(
					b.name, b.flag || "🌍", b.location || "", b.server_type || "ssh", b.xpanel_url, b.xpanel_token || "", b.ssh_host || "127.0.0.1", b.ssh_port || 22,
					b.xpanel_username || "", b.xpanel_password || "", b.xpanel_inbound_id || 1, b.xpanel_webbasepath || "/", b.display_order || 0,
					b.sales_open ? 1 : 0, b.renewal_open ? 1 : 0, b.free_trial ? 1 : 0, b.is_active ? 1 : 0, b.id,
				)
				.run();
		} else {
			await db
				.prepare(
					`INSERT INTO servers (name, flag, location, server_type, xpanel_url, xpanel_token, ssh_host, ssh_port, xpanel_username, xpanel_password, xpanel_inbound_id, xpanel_webbasepath, display_order, sales_open, renewal_open, free_trial, is_active)
					 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
				)
				.bind(
					b.name, b.flag || "🌍", b.location || "", b.server_type || "ssh", b.xpanel_url, b.xpanel_token || "", b.ssh_host || "127.0.0.1", b.ssh_port || 22,
					b.xpanel_username || "", b.xpanel_password || "", b.xpanel_inbound_id || 1, b.xpanel_webbasepath || "/", b.display_order || 0,
					b.sales_open ? 1 : 0, b.renewal_open ? 1 : 0, b.free_trial ? 1 : 0, b.is_active ? 1 : 0,
				)
				.run();
		}
		return Utils.json({ ok: true, configs_updated: configsUpdated });
	},
	async serversDelete(request, db) {
		const { id } = await request.json();
		const cnt = await db.prepare("SELECT COUNT(*) as c FROM orders WHERE server_id = ? AND is_active = 1").bind(id).first();
		if (cnt && cnt.c > 0) return Utils.json({ ok: false, error: "این سرور اشتراک فعال دارد" }, 400);
		await db.prepare("DELETE FROM servers WHERE id = ?").bind(id).run();
		return Utils.json({ ok: true });
	},
	async serversToggle(request, db) {
		const { server_id, key, value } = await request.json();
		const allowed = ["sales_open", "renewal_open", "free_trial", "is_active"];
		if (!allowed.includes(key)) return Utils.json({ ok: false, error: "invalid key" }, 400);
		await db.prepare(`UPDATE servers SET ${key} = ? WHERE id = ?`).bind(value ? 1 : 0, server_id).run();
		return Utils.json({ ok: true });
	},
	async serversTestConnection(request, db) {
		const { server_id } = await request.json();
		const server = await db.prepare("SELECT * FROM servers WHERE id = ?").bind(server_id).first();
		if (!server) return Utils.json({ ok: false, error: "سرور یافت نشد" }, 404);
		const r = await getPanelClient(server).testConnection();
		return Utils.json({ ok: true, connected: r.connected, latency_ms: r.latencyMs, error: r.error });
	},

	async packagesList(url, db) {
		const serverId = url.searchParams.get("server_id");
		const rows = (await db.prepare("SELECT * FROM packages WHERE server_id = ? ORDER BY display_order ASC").bind(serverId).all()).results || [];
		return Utils.json({ ok: true, packages: rows });
	},
	async packagesUpsert(request, db) {
		const b = await request.json();
		if (!b.name || !b.server_id) return Utils.json({ ok: false, error: "نام بسته و سرور اجباری است" }, 400);
		if (b.id) {
			await db
				.prepare("UPDATE packages SET name=?, traffic_amount=?, traffic_unit=?, price_irr=?, duration_days=?, display_order=?, is_active=? WHERE id=?")
				.bind(b.name, b.traffic_amount || 0, b.traffic_unit || "gb", b.price_irr, b.duration_days || 30, b.display_order || 0, b.is_active ? 1 : 0, b.id)
				.run();
		} else {
			await db
				.prepare("INSERT INTO packages (server_id, name, traffic_amount, traffic_unit, price_irr, duration_days, display_order, is_active) VALUES (?,?,?,?,?,?,?,?)")
				.bind(b.server_id, b.name, b.traffic_amount || 0, b.traffic_unit || "gb", b.price_irr, b.duration_days || 30, b.display_order || 0, b.is_active ? 1 : 0)
				.run();
		}
		return Utils.json({ ok: true });
	},
	async packagesDelete(request, db) {
		const { id } = await request.json();
		await db.prepare("DELETE FROM packages WHERE id = ?").bind(id).run();
		return Utils.json({ ok: true });
	},

	async traffic(request, db) {
		const { server_id, username, traffic, unit } = await request.json();
		const server = await db.prepare("SELECT * FROM servers WHERE id = ?").bind(server_id).first();
		const order = await db.prepare("SELECT * FROM orders WHERE server_id = ? AND xpanel_user = ?").bind(server_id, username).first();
		if (!server || !order) return Utils.json({ ok: false, error: "کاربر یافت نشد" }, 404);
		const mb = Utils.toMb(traffic, unit);
		try {
			await getPanelClient(server).addTraffic(username, mb);
		} catch (e) {
			return Utils.json({ ok: false, error: e.message }, 500);
		}
		await db.prepare("UPDATE orders SET total_mb = total_mb + ? WHERE id = ?").bind(mb, order.id).run();
		return Utils.json({ ok: true });
	},

	async approve(request, env, db) {
		const { payment_id } = await request.json();
		const payment = await db.prepare("SELECT * FROM payments WHERE id = ?").bind(payment_id).first();
		if (!payment) return Utils.json({ ok: false, error: "پرداخت یافت نشد" }, 404);
		if (payment.tetra_pay_token && !payment.tetra_tx_id) {
			const apiKey = await DbService.getSetting(db, "tetra_api_key");
			if (apiKey) await AryallehPay.manualConfirm(apiKey, payment.id, "manual admin approve");
		}
		await activatePayment(db, env, payment);
		return Utils.json({ ok: true });
	},

	async customersCreate(request, env, db) {
		const b = await request.json();
		if (!b.name || !b.server_id || !b.package_id) return Utils.json({ ok: false, error: "نام، سرور و بسته اجباری است" }, 400);
		const server = await db.prepare("SELECT * FROM servers WHERE id = ?").bind(b.server_id).first();
		const pkg = await db.prepare("SELECT * FROM packages WHERE id = ?").bind(b.package_id).first();
		if (!server || !pkg) return Utils.json({ ok: false, error: "سرور یا بسته یافت نشد" }, 404);
		const portalToken = Utils.randomHex(16);
		const custRes = await db.prepare("INSERT INTO customers (name, phone, portal_token) VALUES (?,?,?)").bind(b.name, b.phone || "", portalToken).run();
		const customerId = custRes.meta.last_row_id;
		const xpanelUser = "u" + customerId + "_" + Utils.randomHex(3);
		const totalMb = Utils.toMb(pkg.traffic_amount, pkg.traffic_unit);
		let xpanelUuid = null;
		try {
			const created = await getPanelClient(server).createAccount({ username: xpanelUser, totalMb, durationDays: pkg.duration_days });
			xpanelUuid = created.xpanelUuid;
		} catch (e) {
			return Utils.json({ ok: false, error: "خطا در ساخت اکانت روی سرور: " + e.message }, 500);
		}
		const expdate = Utils.addDaysIso(null, pkg.duration_days);
		await db
			.prepare("INSERT INTO orders (customer_id, server_id, package_id, xpanel_user, xpanel_uuid, total_mb, used_mb, duration_days, expdate, is_active) VALUES (?,?,?,?,?,?,0,?,?,1)")
			.bind(customerId, b.server_id, b.package_id, xpanelUser, xpanelUuid, totalMb, pkg.duration_days, expdate)
			.run();
		return Utils.json({ ok: true, portal_token: portalToken });
	},
	async ordersExtend(request, env, db) {
		const { order_id, extra_days, extra_traffic_mb } = await request.json();
		const order = await db.prepare("SELECT * FROM orders WHERE id = ?").bind(order_id).first();
		if (!order) return Utils.json({ ok: false, error: "سفارش یافت نشد" }, 404);
		const server = await db.prepare("SELECT * FROM servers WHERE id = ?").bind(order.server_id).first();
		if (!server) return Utils.json({ ok: false, error: "سرور یافت نشد" }, 404);
		const client = getPanelClient(server);
		try {
			if (extra_traffic_mb) await client.addTraffic(order.xpanel_user, extra_traffic_mb);
			if (extra_days) await client.extendDays(order.xpanel_user, extra_days);
		} catch (e) {
			return Utils.json({ ok: false, error: e.message }, 500);
		}
		await db
			.prepare("UPDATE orders SET total_mb = total_mb + ?, expdate = ? WHERE id = ?")
			.bind(extra_traffic_mb || 0, Utils.addDaysIso(order.expdate || order.created_at, extra_days || 0), order.id)
			.run();
		return Utils.json({ ok: true });
	},
};

// ── Portal routes ────────────────────────────────────────────────────────────

const PortalRoutes = {
	async get(token, db) {
		const customer = await db.prepare("SELECT * FROM customers WHERE portal_token = ?").bind(token).first();
		if (!customer) return Utils.json({ ok: false, error: "not found" }, 404);
		const configHidden = (await DbService.getSetting(db, "link_enabled")) === "1";
		const orders = (await db
			.prepare(
				`SELECT o.*, s.flag as server_flag, s.name as server_name, s.location as server_location, p.name as pkg_name
				 FROM orders o LEFT JOIN servers s ON s.id = o.server_id LEFT JOIN packages p ON p.id = o.package_id
				 WHERE o.customer_id = ? AND o.is_active = 1 ORDER BY o.id DESC`,
			)
			.bind(customer.id)
			.all()).results || [];
		const subscriptions = orders.map((o) => {
			const total = Number(o.total_mb || 0);
			const used = Number(o.used_mb || 0);
			return {
				order_id: o.id,
				server_id: o.server_id,
				server_flag: o.server_flag,
				server_name: o.server_name,
				server_location: o.server_location,
				pkg_name: o.pkg_name,
				duration_days: o.duration_days,
				total_mb: total,
				remaining_mb: Math.max(0, total - used),
				used_pct: total > 0 ? Math.min(100, Math.round((used / total) * 100)) : 0,
				expdate: o.expdate,
				created_at: o.created_at,
				config_text: configHidden ? null : "vless://" + o.xpanel_uuid + "@" + o.xpanel_user + "?config=pending",
				config_netmod: null,
			};
		});
		return Utils.json({ ok: true, customer: { name: customer.name, phone: customer.phone }, subscriptions, config_hidden: configHidden });
	},

	async packages(token, serverId, db) {
		const customer = await db.prepare("SELECT id FROM customers WHERE portal_token = ?").bind(token).first();
		if (!customer) return Utils.json({ ok: false, error: "not found" }, 404);
		const rows = (await db.prepare("SELECT * FROM packages WHERE server_id = ? AND is_active = 1 ORDER BY display_order ASC").bind(serverId).all()).results || [];
		return Utils.json({ ok: true, packages: rows });
	},

	async createPayment(token, request, env, db) {
		const customer = await db.prepare("SELECT id FROM customers WHERE portal_token = ?").bind(token).first();
		if (!customer) return Utils.json({ ok: false, error: "not found" }, 404);
		const { order_id, package_id } = await request.json();
		const order = await db.prepare("SELECT * FROM orders WHERE id = ? AND customer_id = ?").bind(order_id, customer.id).first();
		const pkg = await db.prepare("SELECT * FROM packages WHERE id = ?").bind(package_id).first();
		if (!order || !pkg) return Utils.json({ ok: false, error: "سفارش یا بسته یافت نشد" }, 404);
		const settings = await DbService.getAllSettings(db);
		const priceToman = Number(pkg.price_irr || 0);
		const expiresMinutes = 30;
		const expiresAt = new Date(Date.now() + expiresMinutes * 60000).toISOString();

		const payRes = await db
			.prepare("INSERT INTO payments (order_id, server_id, package_id, amount_irr, status, pkg_name, expires_at) VALUES (?,?,?,?,?,?,?)")
			.bind(order.id, order.server_id, pkg.id, priceToman, "pending", pkg.name, expiresAt)
			.run();
		const paymentId = payRes.meta.last_row_id;

		const methods = {};
		if (settings.payment_card_enabled === "1" && settings.card_number) {
			const offset = 100 + Math.floor(Math.random() * 900);
			const smsAmount = priceToman + offset;
			await db.prepare("UPDATE payments SET card_number=?, card_owner=?, amount_irr=? WHERE id=?").bind(settings.card_number, settings.card_owner || "", smsAmount, paymentId).run();
			methods.card = { card_number: settings.card_number, card_owner: settings.card_owner || "", sms_amount: smsAmount };
		}
		if (settings.payment_tetra_enabled === "1" && settings.tetra_api_key) {
			const orderIdStr = "CRABVPN-" + paymentId;
			const amountRials = priceToman * 10 + Math.floor(Math.random() * 900) * 10;
			const redirectUrl = (settings.portal_base_url || "") + "/portal/" + token;
			const callbackUrl = (settings.portal_base_url || "") + "/api/payment/callback";
			const res = await AryallehPay.create(settings.tetra_api_key, {
				orderId: orderIdStr,
				amountRials,
				description: pkg.name,
				expiresMinutes,
				redirectUrl,
			});
			if (res.ok) {
				const fullUrl = res.pay_url && res.pay_url.startsWith("http") ? res.pay_url : ARYALLEHPAY_BASE + res.pay_url;
				await db.prepare("UPDATE payments SET tetra_pay_token=?, tetra_pay_url=? WHERE id=?").bind(res.pay_token, fullUrl, paymentId).run();
				methods.tetra = { url: fullUrl };
			} else {
				methods.tetra = { error: true };
			}
		}
		return Utils.json({ ok: true, payment_id: paymentId, methods, expires_at: expiresAt });
	},

	async paymentStatus(token, paymentId, db) {
		const row = await db
			.prepare(
				`SELECT pay.* FROM payments pay
				 JOIN orders o ON o.id = pay.order_id
				 JOIN customers c ON c.id = o.customer_id
				 WHERE pay.id = ? AND c.portal_token = ?`,
			)
			.bind(paymentId, token)
			.first();
		if (!row) return Utils.json({ ok: false, error: "not found" }, 404);
		let status = row.status;
		if (status === "pending" && row.expires_at && Date.now() > new Date(row.expires_at).getTime()) {
			status = "expired";
			await db.prepare("UPDATE payments SET status = 'expired' WHERE id = ?").bind(row.id).run();
		}
		return Utils.json({ ok: true, status });
	},

	async stats(token, orderId, db) {
		const order = await db
			.prepare(`SELECT o.* FROM orders o JOIN customers c ON c.id = o.customer_id WHERE o.id = ? AND c.portal_token = ?`)
			.bind(orderId, token)
			.first();
		if (!order) return Utils.json({ ok: false, error: "not found" }, 404);
		const server = await db.prepare("SELECT * FROM servers WHERE id = ?").bind(order.server_id).first();
		if (server) {
			try {
				const stats = await getPanelClient(server).getStats(order.xpanel_user);
				if (stats) {
					await db.prepare("UPDATE orders SET used_mb = ? WHERE id = ?").bind(stats.usedMb, order.id).run();
					order.used_mb = stats.usedMb;
					if (stats.expdate) order.expdate = stats.expdate;
				}
			} catch (e) {}
		}
		const total = Number(order.total_mb || 0);
		const used = Number(order.used_mb || 0);
		return Utils.json({
			ok: true,
			used_pct: total > 0 ? Math.min(100, Math.round((used / total) * 100)) : 0,
			remaining_mb: Math.max(0, total - used),
			total_mb: total,
			expdate: order.expdate,
		});
	},
};

// ── Payment gateway webhooks ─────────────────────────────────────────────────

const PaymentWebhooks = {
	async sms(url, env, db) {
		const msg = url.searchParams.get("msg") || "";
		const amount = parseBankSmsAmountRials(msg);
		if (!amount) return Utils.json({ ok: true, parsed: false });
		const payment = await db.prepare("SELECT * FROM payments WHERE card_number IS NOT NULL AND status='pending' AND amount_irr = ?").bind(amount).first();
		if (!payment) return Utils.json({ ok: true, parsed: true, matched: false, amount });
		await db.prepare("UPDATE payments SET method = 'card' WHERE id = ?").bind(payment.id).run();
		await activatePayment(db, env, payment);
		return Utils.json({ ok: true, parsed: true, matched: true, amount, payment_id: payment.id });
	},
	async callback(request, env, db) {
		const b = await request.json().catch(() => ({}));
		if (b.event !== "payment.confirmed" || !b.order_id) return Utils.json({ ok: true });
		const m = String(b.order_id).match(/^CRABVPN-(\d+)$/);
		if (!m) return Utils.json({ ok: true });
		const paymentId = Number(m[1]);
		const payment = await db.prepare("SELECT * FROM payments WHERE id = ?").bind(paymentId).first();
		if (!payment) return Utils.json({ ok: true });
		if (payment.tetra_tx_id) return Utils.json({ ok: true, message: "already processed" });
		await db.prepare("UPDATE payments SET tetra_tx_id = ?, method = 'tetra' WHERE id = ?").bind(String(b.tx_id || ""), paymentId).run();
		await activatePayment(db, env, payment);
		return Utils.json({ ok: true });
	},
};

// ── Main router ──────────────────────────────────────────────────────────────

async function handleApi(request, url, env, db) {
	const path = url.pathname;
	const method = request.method;

	if (path === "/api/auth/otp" && method === "POST") return AuthRoutes.otp(request, env, db);
	if (path === "/api/auth/login" && method === "POST") return AuthRoutes.login(request, db);

	if (path === "/api/sms" && method === "GET") return PaymentWebhooks.sms(url, env, db);
	if (path === "/api/payment/callback" && method === "POST") return PaymentWebhooks.callback(request, env, db);

	const portalMatch = path.match(/^\/api\/portal\/([^/]+)(\/.*)?$/);
	if (portalMatch) {
		const token = portalMatch[1];
		const sub = portalMatch[2] || "";
		if (sub === "" && method === "GET") return PortalRoutes.get(token, db);
		let m;
		if ((m = sub.match(/^\/packages\/(\d+)$/)) && method === "GET") return PortalRoutes.packages(token, m[1], db);
		if (sub === "/payment" && method === "POST") return PortalRoutes.createPayment(token, request, env, db);
		if ((m = sub.match(/^\/payment\/(\d+)\/status$/)) && method === "GET") return PortalRoutes.paymentStatus(token, m[1], db);
		if ((m = sub.match(/^\/stats\/(\d+)$/)) && method === "GET") return PortalRoutes.stats(token, m[1], db);
		return Utils.json({ ok: false, error: "not found" }, 404);
	}

	if (path.startsWith("/api/admin/")) {
		if (!(await requireAdminToken(request, url, db))) return Utils.json({ ok: false, error: "Unauthorized" }, 401);
		if (path === "/api/admin/data" && method === "GET") return AdminRoutes.data(url, db);
		if (path === "/api/admin/settings" && method === "GET") return AdminRoutes.settingsGet(db);
		if (path === "/api/admin/settings/set" && method === "POST") return AdminRoutes.settingsSet(request, db);
		if (path === "/api/admin/servers/upsert" && method === "POST") return AdminRoutes.serversUpsert(request, db);
		if (path === "/api/admin/servers/delete" && method === "POST") return AdminRoutes.serversDelete(request, db);
		if (path === "/api/admin/servers/toggle" && method === "POST") return AdminRoutes.serversToggle(request, db);
		if (path === "/api/admin/servers/test_connection" && method === "POST") return AdminRoutes.serversTestConnection(request, db);
		if (path === "/api/admin/packages" && method === "GET") return AdminRoutes.packagesList(url, db);
		if (path === "/api/admin/packages/upsert" && method === "POST") return AdminRoutes.packagesUpsert(request, db);
		if (path === "/api/admin/packages/delete" && method === "POST") return AdminRoutes.packagesDelete(request, db);
		if (path === "/api/admin/traffic" && method === "POST") return AdminRoutes.traffic(request, db);
		if (path === "/api/admin/approve" && method === "POST") return AdminRoutes.approve(request, env, db);
		if (path === "/api/admin/customers/create" && method === "POST") return AdminRoutes.customersCreate(request, env, db);
		if (path === "/api/admin/orders/extend" && method === "POST") return AdminRoutes.ordersExtend(request, env, db);
		return Utils.json({ ok: false, error: "not found" }, 404);
	}

	return Utils.json({ ok: false, error: "not found" }, 404);
}

export default {
	async fetch(request, env) {
		await DbService.ensureSchema(env.DB);
		const url = new URL(request.url);

		if (url.pathname.startsWith("/api/")) {
			try {
				return await handleApi(request, url, env, env.DB);
			} catch (e) {
				return Utils.json({ ok: false, error: e.message || "internal error" }, 500);
			}
		}

		const portalPageMatch = url.pathname.match(/^\/portal\/([^/]+)$/);
		if (portalPageMatch) return Utils.html(PORTAL_HTML);

		if (url.pathname === "/" || url.pathname === "/admin") return Utils.html(DASHBOARD_HTML);

		return new Response("Not found", { status: 404 });
	},
};
