const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function loadLocalEnv() {
    const envFile = path.join(__dirname, '.env');
    if (!fs.existsSync(envFile)) return;
    for (const line of fs.readFileSync(envFile, 'utf8').split(/\r?\n/)) {
        const match = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
        if (!match || process.env[match[1]]) continue;
        process.env[match[1]] = match[2].replace(/^['"]|['"]$/g, '');
    }
}

loadLocalEnv();

const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, 'data');
const DB_FILE = path.join(DATA_DIR, 'cyberpay.json');
const VEXAPAY_BASE_URL = process.env.VEXAPAY_BASE_URL || 'https://vexapay.site/api/v1';
const VEXAPAY_CLIENT_ID = process.env.VEXAPAY_CLIENT_ID || '';
const VEXAPAY_CLIENT_SECRET = process.env.VEXAPAY_CLIENT_SECRET || '';
const VEXAPAY_WEBHOOK_SECRET = process.env.VEXAPAY_WEBHOOK_SECRET || '';
const hasGatewayCredentials = Boolean(VEXAPAY_CLIENT_ID && VEXAPAY_CLIENT_SECRET);
const sessions = new Map();
const rateLimits = new Map();
const SESSION_TTL = 8 * 60 * 60 * 1000;
const MAX_BODY_SIZE = 256 * 1024;
const isProduction = process.env.NODE_ENV === 'production';

if (isProduction) {
    throw new Error('CyberPay não pode iniciar em produção enquanto usa banco JSON e sessões em memória. Configure armazenamento e sessões persistentes antes do deploy.');
}

const seed = {
    admin: { email: 'hfsx67325@gmail.com', passwordHash: 'scrypt$dfa120295fd77f6c76b895b4f444355e$c1b4b73fcea2f921ae1bc3a39f3e6201d3ee2677dfe72367acf148d689332943' },
    users: [
        { id: 'usr_demo', name: 'Teste CyberPay', email: 'teste2@cyberpay.dev', phone: '(11) 99999-9999', passwordHash: hashPassword('SenhaTeste123!'), plan: 'Vendedor Pro', status: 'active', balance: 12846.72, createdAt: new Date().toISOString() }
    ],
    plans: {
        'Vendedor Pro': { percent: 3, fixed: 1.5, withdrawalFee: 1.75, med: true },
        Ghost: { percent: 8, fixed: 1, withdrawalFee: 1.5, med: false },
        Enterprise: { percent: 0, fixed: 0, withdrawalFee: 0, med: true }
    },
    withdrawals: [
        { id: 'wd_8A21', userId: 'usr_demo', value: 8200, destination: 'Banco •••• 4821', risk: 'low', status: 'pending', createdAt: new Date().toISOString() },
        { id: 'wd_8A18', userId: 'usr_demo', value: 4600, destination: 'USDT · BEP20', risk: 'high', status: 'pending', createdAt: new Date().toISOString() }
    ],
    notices: [],
    partners: [],
    audit: [],
    webhookEvents: [],
    gatewayCharges: [
        { id: 'chg_seed_001', clientTransactionId: 'chg_seed_001', amount: 249.9, description: 'Pedido #1048', status: 'paid', createdAt: new Date(Date.now() - 1000 * 60 * 35).toISOString() },
        { id: 'chg_seed_002', clientTransactionId: 'chg_seed_002', amount: 89, description: 'Pedido #1047', status: 'paid', createdAt: new Date(Date.now() - 1000 * 60 * 90).toISOString() }
    ],
    gatewayTransfers: [
        { id: 'tr_seed_001', amount: 500, description: 'Transferência interna', status: 'completed', type: 'internal', createdAt: new Date(Date.now() - 1000 * 60 * 240).toISOString() }
    ],
    gatewayVisits: [
        { id: crypto.randomUUID(), route: '/api/gateway/charges', method: 'POST', ip: '189.20.14.102', at: new Date(Date.now() - 5 * 60 * 1000).toISOString() },
        { id: crypto.randomUUID(), route: '/api/gateway/transfers/balance', method: 'GET', ip: '162.214.10.9', at: new Date(Date.now() - 18 * 60 * 1000).toISOString() },
        { id: crypto.randomUUID(), route: '/api/gateway/fees', method: 'GET', ip: '179.26.16.27', at: new Date(Date.now() - 35 * 60 * 1000).toISOString() }
    ],
    settings: { payoutMode: 'manual', automaticLimit: 2000 }
};

function legacyHash(value) {
    return crypto.createHash('sha256').update(String(value)).digest('hex');
}

function hashPassword(value) {
    const salt = crypto.randomBytes(16);
    const key = crypto.scryptSync(String(value), salt, 32);
    return `scrypt$${salt.toString('hex')}$${key.toString('hex')}`;
}

function verifyPassword(value, stored) {
    if (!stored) return false;
    if (stored.startsWith('scrypt$')) {
        const [, saltHex, keyHex] = stored.split('$');
        try {
            const actual = crypto.scryptSync(String(value), Buffer.from(saltHex, 'hex'), 32);
            const expected = Buffer.from(keyHex, 'hex');
            return expected.length === actual.length && crypto.timingSafeEqual(actual, expected);
        } catch { return false; }
    }
    const actual = Buffer.from(legacyHash(value), 'hex');
    const expected = Buffer.from(stored, 'hex');
    return expected.length === actual.length && crypto.timingSafeEqual(actual, expected);
}

function validEmail(value) {
    return typeof value === 'string' && value.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function validCpf(value) {
    const cpf = String(value || '').replace(/\D/g, '');
    if (cpf.length !== 11 || /^(\d)\1{10}$/.test(cpf)) return false;
    const digit = (length) => {
        const sum = cpf.slice(0, length).split('').reduce((total, number, index) => total + Number(number) * (length + 1 - index), 0);
        const remainder = (sum * 10) % 11;
        return remainder === 10 ? 0 : remainder;
    };
    return digit(9) === Number(cpf[9]) && digit(10) === Number(cpf[10]);
}

function ensureDatabase() {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    if (!fs.existsSync(DB_FILE)) saveDb(seed);
}

function loadDb() {
    ensureDatabase();
    const db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    db.admin ||= seed.admin;
    db.plans = {
        ...seed.plans,
        ...(db.plans || {})
    };
    for (const [name, plan] of Object.entries(seed.plans)) {
        db.plans[name] = { ...plan, ...(db.plans[name] || {}) };
    }
    db.users ||= [];
    const demoUser = db.users.find(user => user.id === 'usr_demo');
    if (demoUser) demoUser.withdrawalPasswordHash ||= undefined;
    db.gatewayCharges ||= [];
    db.gatewayTransfers ||= [];
    db.gatewayVisits ||= [];
    db.webhookEvents ||= [];
    db.audit ||= [];
    db.notices ||= [];
    db.partners ||= [];
    db.settings ||= { payoutMode: 'manual', automaticLimit: 2000 };
    return db;
}

function saveDb(db) {
    fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2), 'utf8');
}

function json(res, status, payload) {
    const headers = securityHeaders({ 'Content-Type': 'application/json; charset=utf-8' });
    const allowedOrigin = process.env.ALLOWED_ORIGIN;
    if (allowedOrigin) {
        headers['Access-Control-Allow-Origin'] = allowedOrigin;
        headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, Idempotency-Key, X-CyberPay-Signature, X-VexaPay-Signature, X-VexaPay-Event';
        headers['Access-Control-Allow-Methods'] = 'GET, POST, PATCH, OPTIONS';
        headers.Vary = 'Origin';
    }
    res.writeHead(status, headers);
    res.end(JSON.stringify(payload));
}

function securityHeaders(headers = {}) {
    return { ...headers, 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer', 'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https:; frame-ancestors 'none'" };
}

function readRawBody(req) {
    return new Promise((resolve, reject) => {
        let body = '';
        req.on('data', chunk => { body += chunk; if (Buffer.byteLength(body) > MAX_BODY_SIZE) reject(new Error('Corpo da requisição muito grande')); });
        req.on('end', () => resolve(body));
        req.on('error', reject);
    });
}

async function readBody(req) {
    const raw = await readRawBody(req);
    try { return raw ? JSON.parse(raw) : {}; } catch { throw new Error('JSON inválido'); }
}

function tokenFor(user) {
    const token = crypto.randomBytes(32).toString('hex');
    sessions.set(token, { userId: user.id, role: user.role || 'customer', expiresAt: Date.now() + SESSION_TTL });
    return token;
}

function auth(req, requiredRole) {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : '';
    const session = sessions.get(token);
    if (session && session.expiresAt <= Date.now()) sessions.delete(token);
    if (!session || (requiredRole && session.role !== requiredRole)) return null;
    return session;
}

function checkRateLimit(req, key, limit, windowMs) {
    if (process.env.NODE_ENV === 'test') return true;
    const now = Date.now();
    const id = `${key}:${req.socket.remoteAddress || 'unknown'}`;
    if (rateLimits.size > 10000) {
        for (const [entry, value] of rateLimits) if (value.resetAt <= now) rateLimits.delete(entry);
        if (rateLimits.size > 10000) return false;
    }
    const current = rateLimits.get(id);
    if (!current || current.resetAt <= now) { rateLimits.set(id, { count: 1, resetAt: now + windowMs }); return true; }
    current.count += 1;
    return current.count <= limit;
}

function audit(db, action, actor = 'system') {
    db.audit.unshift({ id: crypto.randomUUID(), action, actor, at: new Date().toISOString() });
    db.audit = db.audit.slice(0, 500);
}

async function callVexaPay(path, method = 'GET', body = undefined) {
    if (!hasGatewayCredentials) return { ok: false, status: 503, error: 'Credenciais VexaPay não configuradas no servidor' };
    const headers = {
        Accept: 'application/json',
        'Content-Type': 'application/json',
        Authorization: `Bearer ${VEXAPAY_CLIENT_SECRET}`,
        'X-Client-Id': VEXAPAY_CLIENT_ID
    };
    try {
        const response = await fetch(`${VEXAPAY_BASE_URL}${path}`, {
            method,
            headers,
            body: body === undefined ? undefined : JSON.stringify(body),
            signal: AbortSignal.timeout(30000)
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) {
            return { ok: false, status: response.status, error: payload.message || payload.error || 'Erro da VexaPay' };
        }
        return { ok: true, status: response.status, data: payload };
    } catch (error) {
        return { ok: false, status: 502, error: 'Falha de conexão com a VexaPay' };
    }
}

function gatewaySummary(db) {
    const transactions = [...(db.gatewayCharges || []), ...(db.gatewayTransfers || [])].sort((a, b) => new Date(b.createdAt || b.at || 0) - new Date(a.createdAt || a.at || 0));
    const totalReceita = (db.gatewayCharges || []).reduce((sum, item) => sum + Number(item.amount ?? item.transaction?.amount ?? 0), 0);
    const totalTransferencias = (db.gatewayTransfers || []).reduce((sum, item) => sum + Number(item.amount ?? item.transaction?.amount ?? 0), 0);
    const uniqueVisitors = new Set((db.gatewayVisits || []).map(visit => visit.ip || 'unknown')).size;
    return {
        totalCharges: (db.gatewayCharges || []).length,
        totalTransfers: (db.gatewayTransfers || []).length,
        totalVolume: Number((totalReceita + totalTransferencias).toFixed(2)),
        availableBalance: Number((db.users || []).reduce((sum, user) => sum + Number(user.balance || 0), 0).toFixed(2)),
        uptime: '99.98%',
        uniqueVisitors,
        conversion: '96.4%',
        transactions: transactions.slice(0, 8)
    };
}

function recordGatewayVisit(db, route, method) {
    db.gatewayVisits = db.gatewayVisits || [];
    db.gatewayVisits.unshift({
        id: crypto.randomUUID(),
        route,
        method,
        ip: 'local-client',
        at: new Date().toISOString()
    });
    db.gatewayVisits = db.gatewayVisits.slice(0, 100);
}

function serveStatic(req, res) {
    if (!['GET', 'HEAD'].includes(req.method)) return json(res, 405, { error: 'Método não permitido' });
    let requested;
    try { requested = decodeURIComponent(new URL(req.url, 'http://localhost').pathname); }
    catch { return json(res, 400, { error: 'Caminho inválido' }); }
    const safePath = requested === '/' ? '/index.html' : requested === '/loginadmin' ? '/login.html' : requested;
    const publicFiles = new Set([
        '/index.html', '/admin.html', '/dashboard.html', '/login.html', '/register.html',
        '/client-security.js', '/cyberpay-brand.svg', '/cyberpay-character.svg',
        '/cyberpay-logo.svg', '/parceiro-cyberbuy.jpg', '/parceiro-divulga.jpg',
        '/parceiro-infostore.png'
    ]);
    if (!publicFiles.has(safePath)) return json(res, 404, { error: 'Arquivo não encontrado' });
    const file = path.normalize(path.join(ROOT, safePath));
    if ((file !== ROOT && !file.startsWith(`${ROOT}${path.sep}`)) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) return json(res, 404, { error: 'Arquivo não encontrado' });
    const extension = path.extname(file).toLowerCase();
    const types = {
        '.html': 'text/html; charset=utf-8',
        '.js': 'text/javascript; charset=utf-8',
        '.css': 'text/css; charset=utf-8',
        '.json': 'application/json; charset=utf-8',
        '.svg': 'image/svg+xml',
        '.jpg': 'image/jpeg',
        '.jpeg': 'image/jpeg',
        '.png': 'image/png',
        '.webp': 'image/webp',
        '.ico': 'image/x-icon'
    };
    res.writeHead(200, securityHeaders({ 'Content-Type': types[extension] || 'application/octet-stream' }));
    fs.createReadStream(file).pipe(res);
}

async function api(req, res) {
    const url = new URL(req.url, 'http://localhost');
    const db = loadDb();

    if (req.method === 'GET' && url.pathname === '/api/public/config') {
        const plans = Object.entries(db.plans || {}).map(([name, plan]) => ({
            name,
            percent: Number(plan.percent) || 0,
            fixed: Number(plan.fixed) || 0,
            withdrawalFee: Number(plan.withdrawalFee) || 0
        }));
        return json(res, 200, {
            plans,
            support: { phone: '11925988460', whatsapp: 'https://wa.me/5511925988460' },
            features: { pix: true, api: hasGatewayCredentials, webhooks: Boolean(VEXAPAY_WEBHOOK_SECRET) }
        });
    }
    if (req.method === 'OPTIONS') return json(res, 204, {});

    if (req.method === 'POST' && url.pathname === '/api/webhooks/vexapay') {
        if (!VEXAPAY_WEBHOOK_SECRET) return json(res, 503, { error: 'Webhook Secret VexaPay não configurado' });
        const rawBody = await readRawBody(req);
        const received = String(req.headers['x-vexapay-signature'] || '');
        const expected = crypto.createHmac('sha256', VEXAPAY_WEBHOOK_SECRET).update(rawBody).digest('hex');
        const receivedBuffer = Buffer.from(received, 'hex');
        const expectedBuffer = Buffer.from(expected, 'hex');
        if (receivedBuffer.length !== expectedBuffer.length || !crypto.timingSafeEqual(expectedBuffer, receivedBuffer)) return json(res, 401, { error: 'Assinatura VexaPay inválida' });
        let event;
        try { event = rawBody ? JSON.parse(rawBody) : {}; } catch { return json(res, 400, { error: 'JSON inválido' }); }
        if (!['pix.charge.paid', 'pix.charge.cancelled', 'pix.payout.paid', 'pix.payout.cancelled'].includes(event.event)) return json(res, 400, { error: 'Evento VexaPay inválido' });
        if (req.headers['x-vexapay-event'] && req.headers['x-vexapay-event'] !== event.event) return json(res, 400, { error: 'Evento VexaPay inconsistente' });
        const isCharge = String(event.event || '').startsWith('pix.charge.');
        const transactionId = isCharge ? event.charge_id : event.payout_id;
        const transactions = isCharge ? db.gatewayCharges : db.gatewayTransfers;
        const transaction = transactions.find(item => item.id === transactionId);
        if (!transaction) return json(res, 200, { received: true, processed: false });
        transaction.status = event.status || (event.event.endsWith('.paid') ? 'paid' : 'cancelled');
        transaction.updatedAt = event.occurred_at || new Date().toISOString();
        if (transaction.status === 'paid') transaction.paidAt = transaction.updatedAt;
        saveDb(db);
        return json(res, 200, { received: true, processed: true });
    }

    if (url.pathname.startsWith('/api/gateway')) {
        recordGatewayVisit(db, url.pathname, req.method);
        const customerSession = auth(req);
        const gatewayAdminSession = auth(req, 'admin');
        if (req.method === 'GET' && url.pathname === '/api/gateway/overview') {
            if (customerSession) {
                const user = db.users.find(item => item.id === customerSession.userId);
                const ownCharges = (db.gatewayCharges || []).filter(item => item.userId === customerSession.userId);
                const ownTransfers = (db.gatewayTransfers || []).filter(item => item.userId === customerSession.userId);
                const totalReceita = ownCharges.reduce((sum, item) => sum + Number(item.amount ?? item.transaction?.amount ?? 0), 0);
                const totalTransferencias = ownTransfers.reduce((sum, item) => sum + Number(item.amount ?? item.transaction?.amount ?? 0), 0);
                const monthStart = new Date();
                monthStart.setDate(1);
                monthStart.setHours(0, 0, 0, 0);
                const paidCharges = ownCharges.filter(item => item.status === 'paid');
                const paidThisMonth = paidCharges.filter(item => new Date(item.paidAt || item.updatedAt || item.createdAt || 0) >= monthStart);
                const plan = db.plans?.[user?.plan] || {};
                const feesThisMonth = paidThisMonth.reduce((sum, item) => sum + Number(item.amount ?? item.transaction?.amount ?? 0) * (Number(plan.percent) || 0) / 100 + (Number(plan.fixed) || 0), 0);
                const allTransactions = [...ownCharges, ...ownTransfers].sort((a, b) => new Date(b.createdAt || b.at || 0) - new Date(a.createdAt || a.at || 0));
                return json(res, 200, {
                    summary: {
                        totalCharges: ownCharges.length,
                        totalTransfers: ownTransfers.length,
                        totalVolume: Number((totalReceita + totalTransferencias).toFixed(2)),
                        availableBalance: Number((user?.balance ?? 0).toFixed(2)),
                        receivedThisMonth: Number(paidThisMonth.reduce((sum, item) => sum + Number(item.amount ?? item.transaction?.amount ?? 0), 0).toFixed(2)),
                        feesThisMonth: Number(feesThisMonth.toFixed(2)),
                        paidCharges: paidCharges.length,
                        pendingCharges: ownCharges.filter(item => item.status === 'pending' || item.status === 'waiting_payment').length,
                        uptime: '99.98%',
                        uniqueVisitors: 1,
                        conversion: '96.4%',
                        transactions: allTransactions.slice(0, 8)
                    },
                    users: db.users.length,
                    gatewayVisits: (db.gatewayVisits || []).slice(0, 10),
                    transactions: allTransactions.slice(0, 100),
                    credentials: { baseUrl: VEXAPAY_BASE_URL, authMode: 'Bearer + X-Client-Id' },
                    apiStatus: 'online',
                    apiMessage: 'API VexaPay configurada no servidor',
                    recentCharges: ownCharges.slice(0, 5),
                    recentTransfers: ownTransfers.slice(0, 5)
                });
            }
            const summary = gatewaySummary(db);
            return json(res, 200, {
                summary,
                users: db.users.length,
                gatewayVisits: (db.gatewayVisits || []).slice(0, 10),
                transactions: summary.transactions,
                credentials: { clientId: VEXAPAY_CLIENT_ID, baseUrl: VEXAPAY_BASE_URL, authMode: 'Bearer + X-Client-Id' },
                    apiStatus: hasGatewayCredentials ? 'configured' : 'offline',
                    apiMessage: hasGatewayCredentials ? 'Credenciais VexaPay configuradas; a API não oferece rota de health check.' : 'Configure as credenciais VexaPay no servidor.',
                recentCharges: (db.gatewayCharges || []).slice(0, 5),
                recentTransfers: (db.gatewayTransfers || []).slice(0, 5)
            });
        }

        if (req.method === 'GET' && url.pathname === '/api/gateway/fees') {
            return json(res, 501, { error: 'A API VexaPay não documenta um endpoint de consulta de taxas' });
        }

        if (req.method === 'GET' && url.pathname === '/api/gateway/charges') {
            if (!customerSession) return json(res, 401, { error: 'Autenticação obrigatória para consultar cobranças' });
            return json(res, 200, { items: (db.gatewayCharges || []).filter(item => item.userId === customerSession.userId).slice(0, 20) });
        }

        const chargeMatch = url.pathname.match(/^\/api\/gateway\/charges\/([^/]+)$/);
        if (req.method === 'GET' && chargeMatch) {
            if (!customerSession) return json(res, 401, { error: 'Autenticação obrigatória para consultar cobrança' });
            const charge = db.gatewayCharges.find(item => item.id === decodeURIComponent(chargeMatch[1]) && item.userId === customerSession.userId);
            if (!charge) return json(res, 404, { error: 'Cobrança não encontrada' });
            const external = await callVexaPay(`/charges/${encodeURIComponent(charge.id)}`);
            if (!external.ok) return json(res, external.status, { error: external.error, gatewayStatus: external.status });
            Object.assign(charge, external.data, { userId: customerSession.userId, source: 'vexapay' });
            saveDb(db);
            return json(res, 200, charge);
        }

        if (req.method === 'POST' && url.pathname === '/api/gateway/charges') {
            if (!customerSession) return json(res, 401, { error: 'Autenticação obrigatória para criar cobrança' });
            const body = await readBody(req);
            const amount = Number(body.amount ?? 0);
            if (!Number.isFinite(amount) || amount < 1 || !Number.isInteger(amount * 100)) return json(res, 422, { error: 'O valor mínimo é R$ 1,00 e deve ter no máximo duas casas decimais' });
            const description = String(body.description || '').trim();
            const payer = body.payer && typeof body.payer === 'object' ? body.payer : {};
            const payerName = String(payer.name || '').trim();
            const payerDocument = String(payer.document || '').replace(/\D/g, '');
            const externalId = String(body.external_id || `cyberpay-${customerSession.userId}-${crypto.randomUUID()}`).trim();
            if (!externalId || externalId.length > 120) return json(res, 422, { error: 'external_id deve ter até 120 caracteres' });
            const requestBody = { amount, external_id: externalId };
            if (description) requestBody.description = description;
            if (payerName || payerDocument) {
                requestBody.payer = {};
                if (payerName) requestBody.payer.name = payerName;
                if (payerDocument) requestBody.payer.document = payerDocument;
            }
            let external = await callVexaPay('/charges', 'POST', requestBody);
            if (external.ok) {
                if (external.status === 200 && external.data.id && !external.data.pix_copy_paste) {
                    const existing = await callVexaPay(`/charges/${encodeURIComponent(external.data.id)}`);
                    if (existing.ok) external = { ...external, data: { ...existing.data, ...external.data } };
                }
                const transaction = external.data;
                const charge = {
                    ...transaction,
                    id: transaction.id,
                    clientTransactionId: transaction.external_id || externalId,
                    amount: Number(transaction.amount ?? amount),
                    description: transaction.description || description,
                    copyPaste: transaction.pix_copy_paste || null,
                    qrCode: transaction.qr_code_base64 || null,
                    status: transaction.status || 'pending',
                    createdAt: transaction.created_at || new Date().toISOString(),
                    userId: customerSession.userId,
                    source: 'vexapay'
                };
                db.gatewayCharges.unshift(charge);
                db.gatewayCharges = db.gatewayCharges.slice(0, 100);
                saveDb(db);
                return json(res, external.status, charge);
            }
            return json(res, external.status, { error: external.error, gatewayStatus: external.status });
        }

        if (req.method === 'GET' && url.pathname === '/api/gateway/transfers') {
            if (!customerSession) return json(res, 401, { error: 'Autenticação obrigatória para consultar transferências' });
            return json(res, 200, { items: (db.gatewayTransfers || []).filter(item => item.userId === customerSession.userId).slice(0, 20) });
        }

        const payoutMatch = url.pathname.match(/^\/api\/gateway\/payouts\/([^/]+)$/);
        if (req.method === 'GET' && payoutMatch) {
            if (!gatewayAdminSession) return json(res, 403, { error: 'Acesso administrativo obrigatório para consultar saques da conta VexaPay' });
            const payout = db.gatewayTransfers.find(item => item.id === decodeURIComponent(payoutMatch[1]));
            if (!payout) return json(res, 404, { error: 'Saque não encontrado' });
            const external = await callVexaPay(`/payouts/${encodeURIComponent(payout.id)}`);
            if (!external.ok) return json(res, external.status, { error: external.error, gatewayStatus: external.status });
            Object.assign(payout, external.data, { userId: customerSession.userId, source: 'vexapay' });
            saveDb(db);
            return json(res, 200, payout);
        }

        if (req.method === 'POST' && ['/api/gateway/payouts', '/api/gateway/transfers'].includes(url.pathname)) {
            if (!gatewayAdminSession) return json(res, 403, { error: 'Acesso administrativo obrigatório para enviar saques da conta VexaPay' });
            const body = await readBody(req);
            const amount = Number(body.amount ?? 0);
            const pixKey = String(body.pix_key || body.pixKey || '').trim();
            const pixKeyType = String(body.pix_key_type || body.pixKeyType || '').trim().toLowerCase();
            if (!Number.isFinite(amount) || amount < 1 || !Number.isInteger(amount * 100)) return json(res, 422, { error: 'O valor mínimo do saque é R$ 1,00 e deve ter no máximo duas casas decimais' });
            if (!pixKey || !['cpf', 'cnpj', 'email', 'telefone', 'aleatoria'].includes(pixKeyType)) return json(res, 422, { error: 'Informe uma chave Pix e um tipo válido' });
            const externalId = String(body.external_id || `cyberpay-${customerSession.userId}-${crypto.randomUUID()}`).trim();
            if (!externalId || externalId.length > 120) return json(res, 422, { error: 'external_id deve ter até 120 caracteres' });
            const external = await callVexaPay('/payouts', 'POST', { amount, pix_key: pixKey, pix_key_type: pixKeyType, external_id: externalId });
            if (external.ok) {
                const persistedTransfer = { ...external.data, clientTransactionId: external.data.external_id || externalId, createdAt: external.data.created_at || new Date().toISOString(), userId: gatewayAdminSession.userId, source: 'vexapay', type: 'payout', destination: pixKey };
                db.gatewayTransfers.unshift(persistedTransfer);
                db.gatewayTransfers = db.gatewayTransfers.slice(0, 100);
                saveDb(db);
                return json(res, external.status, persistedTransfer);
            }
            return json(res, external.status, { error: external.error, gatewayStatus: external.status });
        }

        if (req.method === 'GET' && url.pathname === '/api/gateway/balance') {
            return json(res, 501, { error: 'A API VexaPay não documenta endpoint de saldo' });
        }

        return json(res, 404, { error: 'Endpoint da gateway não encontrado' });
    }

    if (req.method === 'POST' && url.pathname === '/api/webhooks/cyberpay') {
        if (!checkRateLimit(req, 'webhook', 60, 60 * 1000)) return json(res, 429, { error: 'Muitas requisições' });
        const rawBody = await readRawBody(req);
        let body;
        try { body = rawBody ? JSON.parse(rawBody) : {}; } catch { return json(res, 400, { error: 'JSON inválido' }); }
        const idempotencyKey = req.headers['idempotency-key'];
        if (!idempotencyKey) return json(res, 400, { error: 'Idempotency-Key obrigatório' });
        if (db.webhookEvents.some(event => event.idempotencyKey === idempotencyKey)) return json(res, 200, { accepted: true, duplicate: true });
        const signature = req.headers['x-cyberpay-signature'] || '';
        const secret = process.env.CYBERPAY_WEBHOOK_SECRET;
        if (!secret) return json(res, 503, { error: 'Webhook não configurado' });
        const expected = crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
        const provided = Buffer.from(String(signature), 'utf8');
        const expectedBuffer = Buffer.from(expected, 'utf8');
        if (provided.length !== expectedBuffer.length || !crypto.timingSafeEqual(provided, expectedBuffer)) return json(res, 401, { error: 'Assinatura inválida' });
        db.webhookEvents.unshift({ id: crypto.randomUUID(), idempotencyKey, event: body.event || 'unknown', receivedAt: new Date().toISOString() });
        db.webhookEvents = db.webhookEvents.slice(0, 1000);
        audit(db, `Webhook recebido: ${body.event || 'unknown'}`, 'webhook');
        saveDb(db);
        return json(res, 202, { accepted: true, duplicate: false });
    }

    if (req.method === 'POST' && url.pathname === '/api/auth/login') {
        if (!checkRateLimit(req, 'login', 5, 15 * 60 * 1000)) return json(res, 429, { error: 'Muitas tentativas. Tente novamente mais tarde.' });
        const body = await readBody(req);
        const email = String(body.email || '').trim().toLowerCase();
        const user = db.users.find(item => item.email.toLowerCase() === email && verifyPassword(body.password, item.passwordHash));
        if (!user || user.status === 'blocked') return json(res, 401, { error: 'Credenciais inválidas ou conta bloqueada' });
        if (user.status === 'pending') return json(res, 403, { error: 'Sua conta está aguardando aprovação de um administrador' });
        if (!user.passwordHash.startsWith('scrypt$')) user.passwordHash = hashPassword(body.password);
        const token = tokenFor(user);
        audit(db, `Login realizado: ${user.email}`, user.email);
        saveDb(db);
        return json(res, 200, { token, user: { ...user, passwordHash: undefined } });
    }

    if (req.method === 'POST' && url.pathname === '/api/auth/admin-login') {
        if (!checkRateLimit(req, 'admin-login', 5, 15 * 60 * 1000)) return json(res, 429, { error: 'Muitas tentativas. Tente novamente mais tarde.' });
        const body = await readBody(req);
        const email = String(body.email || '').trim().toLowerCase();
        if (email !== db.admin.email.toLowerCase() || !verifyPassword(body.password, db.admin.passwordHash)) return json(res, 401, { error: 'Credenciais administrativas inválidas' });
        const token = tokenFor({ id: 'admin', role: 'admin' });
        audit(db, `Login administrativo realizado: ${db.admin.email}`, db.admin.email);
        saveDb(db);
        return json(res, 200, { token, user: { email: db.admin.email, role: 'admin' } });
    }

    if (req.method === 'POST' && url.pathname === '/api/auth/register') {
        if (!checkRateLimit(req, 'register', 5, 60 * 60 * 1000)) return json(res, 429, { error: 'Muitas tentativas. Tente novamente mais tarde.' });
        const body = await readBody(req);
        const cpf = String(body.cpf || '').replace(/\D/g, '');
        const withdrawalPassword = String(body.withdrawalPassword || '');
        const name = String(body.name || '').trim();
        const email = String(body.email || '').trim().toLowerCase();
        const password = String(body.password || '');
        if (name.length < 2 || name.length > 120 || !validEmail(email) || password.length < 10 || password.length > 128 || !validCpf(cpf) || withdrawalPassword.length < 6 || withdrawalPassword.length > 128) return json(res, 400, { error: 'Nome, e-mail, CPF, senha de acesso e senha de saque válidos são obrigatórios' });
        if (!Object.hasOwn(db.plans, body.plan || 'Vendedor Pro')) return json(res, 400, { error: 'Plano inválido' });
        if (db.users.some(item => item.email.toLowerCase() === email)) return json(res, 409, { error: 'E-mail já cadastrado' });
        if (db.users.some(item => item.cpf === cpf)) return json(res, 409, { error: 'CPF já cadastrado' });
        const user = { id: `usr_${crypto.randomBytes(4).toString('hex')}`, name: body.name, email: body.email, cpf, phone: body.phone || '', passwordHash: hashPassword(body.password), withdrawalPasswordHash: hashPassword(withdrawalPassword), plan: body.plan || 'Vendedor Pro', status: 'pending', balance: 0, createdAt: new Date().toISOString() };
        db.users.push(user); audit(db, `Usuário criado: ${user.email}`, user.email); saveDb(db);
        return json(res, 201, { user: safeUser(user) });
    }

    const customerSession = auth(req);
    const adminSession = auth(req, 'admin');
    if (url.pathname.startsWith('/api/admin')) {
        if (req.method === 'POST' && url.pathname === '/api/admin/seed-session') {
            if (isProduction || process.env.ENABLE_DEV_ADMIN !== 'true') return json(res, 404, { error: 'Rota não encontrada' });
            return json(res, 200, { token: tokenFor({ id: 'admin', role: 'admin' }) });
        }
        if (!adminSession) return json(res, 403, { error: 'Acesso administrativo obrigatório' });
        if (req.method === 'GET' && url.pathname === '/api/admin/overview') return json(res, 200, {
            users: db.users.map(safeUser),
            withdrawals: db.withdrawals,
            plans: db.plans,
            notices: db.notices,
            partners: db.partners,
            settings: db.settings,
            gatewaySummary: gatewaySummary(db),
            gatewayVisits: (db.gatewayVisits || []).slice(0, 20),
            gatewayCredentials: {
                clientId: VEXAPAY_CLIENT_ID,
                clientSecretConfigured: Boolean(VEXAPAY_CLIENT_SECRET),
                webhookSecretConfigured: Boolean(VEXAPAY_WEBHOOK_SECRET),
                baseUrl: VEXAPAY_BASE_URL,
                authMode: 'Bearer + X-Client-Id'
            }
        });
        if (req.method === 'POST' && url.pathname === '/api/admin/gateway/test') {
            return json(res, hasGatewayCredentials ? 200 : 503, {
                ok: hasGatewayCredentials,
                status: hasGatewayCredentials ? 'configured' : 503,
                message: hasGatewayCredentials ? 'Credenciais VexaPay configuradas. A API não documenta health check; a conexão real é validada ao criar ou consultar uma operação.' : 'Configure VEXAPAY_CLIENT_ID e VEXAPAY_CLIENT_SECRET no servidor.'
            });
        }
        if (req.method === 'POST' && url.pathname === '/api/admin/notices') { const body = await readBody(req); const notice = { id: crypto.randomUUID(), title: body.title, text: body.text, type: body.type || 'Informativo', audience: body.audience || 'Todos os usuários', createdAt: new Date().toISOString() }; db.notices.unshift(notice); audit(db, `Aviso publicado: ${notice.title}`, 'admin'); saveDb(db); return json(res, 201, notice); }
        if (req.method === 'POST' && url.pathname === '/api/admin/partners') { const body = await readBody(req); const partner = { id: crypto.randomUUID(), name: body.name, description: body.description, type: body.type || 'Integração', link: body.link || '', createdAt: new Date().toISOString() }; db.partners.unshift(partner); audit(db, `Parceria adicionada: ${partner.name}`, 'admin'); saveDb(db); return json(res, 201, partner); }
        if (req.method === 'PATCH' && url.pathname === '/api/admin/settings') {
            const body = await readBody(req);
            const allowedModes = ['manual', 'automatic'];
            const automaticLimit = Number(body.automaticLimit ?? db.settings.automaticLimit);
            if (!allowedModes.includes(body.payoutMode ?? db.settings.payoutMode) || !Number.isFinite(automaticLimit) || automaticLimit < 0 || automaticLimit > 1000000) return json(res, 400, { error: 'Configuração operacional inválida' });
            db.settings = { ...db.settings, payoutMode: body.payoutMode ?? db.settings.payoutMode, automaticLimit };
            audit(db, 'Regras operacionais atualizadas', 'admin'); saveDb(db); return json(res, 200, db.settings);
        }
        const withdrawalMatch = url.pathname.match(/^\/api\/admin\/withdrawals\/([^/]+)$/);
        if (req.method === 'PATCH' && withdrawalMatch) { const body = await readBody(req); const item = db.withdrawals.find(withdrawal => withdrawal.id === withdrawalMatch[1]); if (!item) return json(res, 404, { error: 'Saque não encontrado' }); if (!['approved', 'blocked', 'rejected'].includes(body.status)) return json(res, 400, { error: 'Status de saque inválido' }); item.status = body.status; item.decisionReason = body.reason || ''; item.decidedAt = new Date().toISOString(); audit(db, `Saque ${item.id}: ${item.status} · ${item.decisionReason}`, 'admin'); saveDb(db); return json(res, 200, item); }
        const userMatch = url.pathname.match(/^\/api\/admin\/users\/([^/]+)$/);
        if (userMatch) {
            const user = db.users.find(item => item.id === userMatch[1]);
            if (!user) return json(res, 404, { error: 'Usuário não encontrado' });
            if (req.method === 'PATCH') {
                const body = await readBody(req);
                const updates = {};
                if (body.name !== undefined) {
                    const name = String(body.name).trim();
                    if (name.length < 2 || name.length > 120) return json(res, 400, { error: 'Nome deve ter entre 2 e 120 caracteres' });
                    updates.name = name;
                }
                if (body.email !== undefined) {
                    const email = String(body.email).trim().toLowerCase();
                    if (!validEmail(email)) return json(res, 400, { error: 'E-mail inválido' });
                    if (db.users.some(item => item.id !== user.id && item.email.toLowerCase() === email)) return json(res, 409, { error: 'E-mail já cadastrado' });
                    updates.email = email;
                }
                if (body.phone !== undefined) updates.phone = String(body.phone).trim().slice(0, 30);
                if (body.plan !== undefined) {
                    if (!Object.hasOwn(db.plans, String(body.plan))) return json(res, 400, { error: 'Plano inválido' });
                    updates.plan = String(body.plan);
                }
                if (body.status !== undefined) {
                    if (!['active', 'pending', 'blocked'].includes(body.status)) return json(res, 400, { error: 'Status de usuário inválido' });
                    updates.status = body.status;
                }
                if (body.balance !== undefined) {
                    const balance = Number(body.balance);
                    if (!Number.isFinite(balance) || balance < 0 || balance > 1000000000 || Math.round(balance * 100) !== balance * 100) return json(res, 400, { error: 'Saldo inválido' });
                    updates.balance = balance;
                }
                if (body.password !== undefined && body.password !== '') {
                    const password = String(body.password);
                    if (password.length < 10 || password.length > 128) return json(res, 400, { error: 'A senha deve ter entre 10 e 128 caracteres' });
                    updates.passwordHash = hashPassword(password);
                }
                Object.assign(user, updates);
                audit(db, `Cliente atualizado (saldo/plano/status): ${user.email}`, 'admin');
                saveDb(db);
                return json(res, 200, safeUser(user));
            }
            if (req.method === 'DELETE') {
                db.users = db.users.filter(item => item.id !== userMatch[1]);
                audit(db, `Cliente removido pelo admin: ${user.email}`, 'admin');
                saveDb(db);
                return json(res, 200, { success: true });
            }
        }
        const planMatch = url.pathname.match(/^\/api\/admin\/plans\/(.+)$/);
        if (req.method === 'POST' && url.pathname === '/api/admin/plans') {
            const body = await readBody(req);
            if (!body.name || body.percent === undefined) return json(res, 400, { error: 'Nome e percentual são obrigatórios' });
            const name = String(body.name).trim();
            const planData = {
                percent: Number(body.percent),
                fixed: Number(body.fixed ?? 0),
                withdrawalFee: Number(body.withdrawalFee ?? 0),
                med: Boolean(body.med)
            };
            if (!Number.isFinite(planData.percent) || !Number.isFinite(planData.fixed) || !Number.isFinite(planData.withdrawalFee)) return json(res, 400, { error: 'Taxas inválidas para o plano' });
            db.plans[name] = planData;
            audit(db, `Plano configurado: ${name}`, 'admin');
            saveDb(db);
            return json(res, 200, db.plans[name]);
        }
        if (planMatch && req.method === 'PATCH') {
            const originalName = decodeURIComponent(planMatch[1]);
            const body = await readBody(req);
            const targetName = String(body.name || originalName).trim();
            if (!targetName || body.percent === undefined) return json(res, 400, { error: 'Nome e percentual são obrigatórios' });
            const planData = {
                percent: Number(body.percent ?? db.plans[originalName]?.percent ?? 0),
                fixed: Number(body.fixed ?? db.plans[originalName]?.fixed ?? 0),
                withdrawalFee: Number(body.withdrawalFee ?? db.plans[originalName]?.withdrawalFee ?? 0),
                med: body.med ?? db.plans[originalName]?.med ?? false
            };
            if (!Number.isFinite(planData.percent) || !Number.isFinite(planData.fixed) || !Number.isFinite(planData.withdrawalFee)) return json(res, 400, { error: 'Taxas inválidas para o plano' });
            if (originalName !== targetName && db.plans[originalName]) delete db.plans[originalName];
            db.plans[targetName] = { percent: planData.percent, fixed: planData.fixed, withdrawalFee: planData.withdrawalFee, med: Boolean(planData.med) };
            audit(db, `Plano atualizado: ${targetName}`, 'admin');
            saveDb(db);
            return json(res, 200, db.plans[targetName]);
        }
        if (planMatch && req.method === 'DELETE') {
            const name = decodeURIComponent(planMatch[1]);
            if (!db.plans[name]) return json(res, 404, { error: 'Plano não encontrado' });
            delete db.plans[name];
            audit(db, `Plano removido: ${name}`, 'admin');
            saveDb(db);
            return json(res, 200, { success: true, deleted: name });
        }
        if (req.method === 'GET' && url.pathname === '/api/admin/audit') return json(res, 200, db.audit);
        return json(res, 404, { error: 'Rota admin não encontrada' });
    }

    if (!customerSession) return json(res, 401, { error: 'Autenticação obrigatória' });
    const user = db.users.find(item => item.id === customerSession.userId);
    if (req.method === 'GET' && url.pathname === '/api/withdrawals') {
        const items = (db.withdrawals || []).filter(item => item.userId === user.id).sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));
        return json(res, 200, { items });
    }
    if (req.method === 'POST' && url.pathname === '/api/auth/withdrawal-password') {
        const body = await readBody(req);
        const password = String(body.password || '');
        if (password.length < 6 || password.length > 128) return json(res, 400, { error: 'A senha de saque deve ter entre 6 e 128 caracteres' });
        if (body.confirmPassword !== undefined && password !== String(body.confirmPassword)) return json(res, 400, { error: 'As senhas de saque não coincidem' });
        user.withdrawalPasswordHash = hashPassword(password);
        audit(db, `Senha de saque configurada: ${user.email}`, user.email);
        saveDb(db);
        return json(res, 200, { configured: true });
    }
    if (req.method === 'POST' && url.pathname === '/api/withdrawals') {
        if (!user.withdrawalPasswordHash) return json(res, 400, { error: 'Configure uma senha de saque antes de solicitar um saque' });
        const body = await readBody(req);
        const password = String(body.password || '');
        const value = Number(body.value);
        const destination = String(body.destination || '').trim();
        if (!verifyPassword(password, user.withdrawalPasswordHash)) return json(res, 401, { error: 'Senha de saque inválida' });
        if (!Number.isFinite(value) || value <= 0 || !destination) return json(res, 400, { error: 'Informe um valor e um destino válidos' });
        const withdrawal = { id: `wd_${crypto.randomBytes(4).toString('hex')}`, userId: user.id, value, destination, risk: 'low', status: 'pending', createdAt: new Date().toISOString() };
        db.withdrawals.unshift(withdrawal);
        audit(db, `Saque solicitado: ${withdrawal.id}`, user.email);
        saveDb(db);
        return json(res, 201, withdrawal);
    }
    if (req.method === 'GET' && url.pathname === '/api/me') return json(res, 200, { user: safeUser(user), notices: db.notices, partners: db.partners, settings: db.settings, plans: db.plans });
    if (req.method === 'GET' && url.pathname === '/api/notifications') return json(res, 200, db.audit.filter(item => item.actor === user.email).slice(0, 50));
    return json(res, 404, { error: 'Rota não encontrada' });
}

function safeUser(user) { const { passwordHash, withdrawalPasswordHash, ...safe } = user; return { ...safe, withdrawalPasswordConfigured: Boolean(withdrawalPasswordHash) }; }

ensureDatabase();
async function requestHandler(req, res) {
    try { if (req.url.startsWith('/api/')) await api(req, res); else serveStatic(req, res); }
    catch (error) { console.error(error); json(res, error.message === 'Corpo da requisição muito grande' ? 413 : 500, { error: isProduction ? 'Erro interno do servidor' : error.message }); }
}

if (require.main === module) {
    http.createServer(requestHandler).listen(PORT, () => console.log(`CyberPay em http://localhost:${PORT}`));
}

module.exports = requestHandler;
