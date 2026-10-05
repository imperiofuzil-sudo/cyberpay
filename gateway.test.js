const { test, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const { escapeHTML, safeHttpUrl, parseJSON } = require('./client-security');
process.env.NODE_ENV = 'test';
process.env.VEXAPAY_BASE_URL = 'https://vexapay.test/api/v1';
process.env.VEXAPAY_CLIENT_ID = 'ci_test_gateway';
process.env.VEXAPAY_CLIENT_SECRET = 'cs_test_gateway';
process.env.VEXAPAY_WEBHOOK_SECRET = 'test-webhook-secret';
process.env.ENABLE_DEV_ADMIN = 'true';
const databasePath = './data/cyberpay.json';
const originalDatabase = fs.readFileSync(databasePath, 'utf8');
after(() => fs.writeFileSync(databasePath, originalDatabase));
const nativeFetch = global.fetch;
const providerCharges = new Map();
const providerPayouts = new Map();
const providerRequests = [];
global.fetch = async (resource, options = {}) => {
  const url = String(resource);
  if (!url.startsWith(process.env.VEXAPAY_BASE_URL)) return nativeFetch(resource, options);
  const route = url.slice(process.env.VEXAPAY_BASE_URL.length);
  const method = options.method || 'GET';
  const body = options.body ? JSON.parse(options.body) : {};
  providerRequests.push({ route, method, headers: options.headers || {}, body });
  const response = (status, payload) => new Response(JSON.stringify(payload), { status, headers: { 'Content-Type': 'application/json' } });
  if (method === 'POST' && route === '/charges') {
    const charge = { id: `ch_test_${providerCharges.size + 1}`, external_id: body.external_id, status: 'pending', amount: body.amount, pix_copy_paste: '000201PIX_TEST', qr_code_base64: null, created_at: new Date().toISOString() };
    providerCharges.set(charge.id, charge);
    return response(201, charge);
  }
  if (method === 'POST' && route === '/payouts') {
    const payout = { id: `po_test_${providerPayouts.size + 1}`, external_id: body.external_id, status: 'pending', amount: body.amount, created_at: new Date().toISOString() };
    providerPayouts.set(payout.id, payout);
    return response(201, payout);
  }
  const chargeMatch = route.match(/^\/charges\/(.+)$/);
  if (method === 'GET' && chargeMatch) return providerCharges.has(chargeMatch[1]) ? response(200, providerCharges.get(chargeMatch[1])) : response(404, { error: 'not_found', message: 'Cobrança não encontrada' });
  const payoutMatch = route.match(/^\/payouts\/(.+)$/);
  if (method === 'GET' && payoutMatch) return providerPayouts.has(payoutMatch[1]) ? response(200, providerPayouts.get(payoutMatch[1])) : response(404, { error: 'not_found', message: 'Saque não encontrado' });
  return response(404, { error: 'not_found', message: 'Rota não encontrada' });
};
const requestHandler = require('./server');

test('helpers de segurança escapam HTML e rejeitam URLs executáveis', () => {
  assert.equal(escapeHTML(`<script "x">'&</script>`), '&lt;script &quot;x&quot;&gt;&#39;&amp;&lt;/script&gt;');
  assert.equal(safeHttpUrl('javascript:alert(1)'), '');
  assert.equal(safeHttpUrl('https://example.com/path'), 'https://example.com/path');
  assert.deepEqual(parseJSON('{invalid', { fallback: true }), { fallback: true });
});

test('servidor estático não expõe segredos, banco, configuração nem código do servidor', async () => {
  await withServer(async (port) => {
    for (const pathname of ['/.env', '/server.js', '/data/cyberpay.json', '/package.json', '/.vercel/project.json']) {
      const response = await fetch('http://127.0.0.1:' + port + pathname);
      assert.equal(response.status, 404, pathname);
    }
    const home = await fetch('http://127.0.0.1:' + port + '/');
    assert.equal(home.status, 200);
    assert.match(home.headers.get('content-type'), /text\/html/);
  });
});

test('login administrativo autentica e concede acesso ao painel', async () => {
  const original = fs.readFileSync(databasePath, 'utf8');
  const db = JSON.parse(original);
  const password = 'AdminTest123!';
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, 32);
  db.admin.passwordHash = `scrypt$${salt.toString('hex')}$${hash.toString('hex')}`;
  fs.writeFileSync(databasePath, JSON.stringify(db, null, 2));

  try {
    await withServer(async (port) => {
      const response = await fetch(`http://127.0.0.1:${port}/api/auth/admin-login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: db.admin.email, password }),
      });
      assert.equal(response.status, 200);
      const payload = await response.json();
      assert.equal(payload.user.role, 'admin');
      const overview = await fetch(`http://127.0.0.1:${port}/api/admin/overview`, {
        headers: { Authorization: `Bearer ${payload.token}` },
      });
      assert.equal(overview.status, 200);
    });
  } finally {
    fs.writeFileSync(databasePath, original);
  }
});

test('produção falha fechada enquanto usa armazenamento local', () => {
  const result = spawnSync(process.execPath, ['-e', "require('./server')"], {
    cwd: process.cwd(),
    env: { ...process.env, NODE_ENV: 'production' },
    encoding: 'utf8',
  });

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /banco JSON e sessões em memória/);
});

async function withServer(testFn) {
  const server = http.createServer(requestHandler);
  await new Promise((resolve) => server.listen(0, resolve));
  const { port } = server.address();

  try {
    await testFn(port);
  } finally {
    await new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
  }
}

async function login(port, email, password) {
  const response = await fetch(`http://127.0.0.1:${port}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  assert.equal(response.status, 200);
  return (await response.json()).token;
}

test('GET /api/gateway/overview returns dashboard summary', async () => {
  await withServer(async (port) => {
    const response = await fetch(`http://127.0.0.1:${port}/api/gateway/overview`);
    assert.equal(response.status, 200);

    const data = await response.json();
    assert.ok(data.summary);
    assert.ok(Array.isArray(data.transactions));
    assert.ok(data.users >= 1);
  });
});

test('planos base configurados com taxas desejadas e Ghost sem MED', async () => {
  const db = JSON.parse(fs.readFileSync(databasePath, 'utf8'));
  assert.equal(db.plans['Vendedor Pro'].percent, 3);
  assert.equal(db.plans['Vendedor Pro'].fixed, 1.5);
  assert.equal(db.plans['Vendedor Pro'].withdrawalFee, 1.75);
  assert.equal(db.plans['Vendedor Pro'].med, true);
  assert.equal(db.plans.Ghost.fixed, 1);
  assert.equal(db.plans.Ghost.med, false);
});

test('POST /api/gateway/charges accepts amount and returns a charge object', async () => {
  await withServer(async (port) => {
    const token = await login(port, 'teste2@cyberpay.dev', 'SenhaTeste123!');
    const response = await fetch(`http://127.0.0.1:${port}/api/gateway/charges`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ amount: 50, description: 'Pedido #123', payer: { name: 'Maria da Silva', document: '529.982.247-25' } }),
    });

    assert.equal(response.status, 201);
    const data = await response.json();
    assert.equal(data.status, 'pending');
    assert.equal(data.copyPaste, '000201PIX_TEST');
    assert.ok(data.clientTransactionId);
    assert.ok(data.amount >= 50);
    const upstreamRequest = providerRequests.at(-1);
    assert.equal(upstreamRequest.headers.Authorization, 'Bearer cs_test_gateway');
    assert.equal(upstreamRequest.headers['X-Client-Id'], 'ci_test_gateway');
    assert.equal(upstreamRequest.body.payer.document, '52998224725');
    const query = await fetch(`http://127.0.0.1:${port}/api/gateway/charges/${data.id}`, { headers: { Authorization: `Bearer ${token}` } });
    assert.equal(query.status, 200);
    assert.equal((await query.json()).status, 'pending');
  });
});

test('POST /api/gateway/payouts envia e consulta saque VexaPay', async () => {
  await withServer(async (port) => {
    const adminSession = await fetch(`http://127.0.0.1:${port}/api/admin/seed-session`, { method: 'POST' });
    const token = (await adminSession.json()).token;
    const response = await fetch(`http://127.0.0.1:${port}/api/gateway/payouts`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ amount: 1, pix_key: 'financeiro@example.com', pix_key_type: 'email', external_id: 'saque-teste-1' }),
    });
    assert.equal(response.status, 201);
    const payout = await response.json();
    assert.match(payout.id, /^po_test_/);
    assert.equal(payout.status, 'pending');
    const query = await fetch(`http://127.0.0.1:${port}/api/gateway/payouts/${payout.id}`, { headers: { Authorization: `Bearer ${token}` } });
    assert.equal(query.status, 200);
    assert.equal((await query.json()).status, 'pending');
  });
});

test('cliente nao autenticado como admin nao pode sacar do saldo VexaPay compartilhado', async () => {
  await withServer(async (port) => {
    const token = await login(port, 'teste2@cyberpay.dev', 'SenhaTeste123!');
    const response = await fetch(`http://127.0.0.1:${port}/api/gateway/payouts`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ amount: 1, pix_key: 'financeiro@example.com', pix_key_type: 'email' }),
    });
    assert.equal(response.status, 403);
  });
});

test('webhook VexaPay valida assinatura e atualiza o status da cobranca', async () => {
  await withServer(async (port) => {
    const token = await login(port, 'teste2@cyberpay.dev', 'SenhaTeste123!');
    const chargeResponse = await fetch(`http://127.0.0.1:${port}/api/gateway/charges`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ amount: 1, payer: { name: 'Maria da Silva', document: '52998224725' } }),
    });
    const charge = await chargeResponse.json();
    const body = JSON.stringify({ event: 'pix.charge.paid', charge_id: charge.id, status: 'paid', occurred_at: new Date().toISOString() });
    const signature = crypto.createHmac('sha256', process.env.VEXAPAY_WEBHOOK_SECRET).update(body).digest('hex');
    const invalid = await fetch(`http://127.0.0.1:${port}/api/webhooks/vexapay`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-VexaPay-Signature': 'invalid' }, body });
    assert.equal(invalid.status, 401);
    const webhook = await fetch(`http://127.0.0.1:${port}/api/webhooks/vexapay`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-VexaPay-Event': 'pix.charge.paid', 'X-VexaPay-Signature': signature }, body });
    assert.equal(webhook.status, 200);
    assert.equal((await webhook.json()).processed, true);
    const list = await fetch(`http://127.0.0.1:${port}/api/gateway/charges`, { headers: { Authorization: `Bearer ${token}` } });
    const items = (await list.json()).items;
    assert.equal(items.find(item => item.id === charge.id).status, 'paid');
  });
});

test('duas contas autenticadas podem gerar cobranças isoladas', async () => {
  await withServer(async (port) => {
    const email = `teste-${Date.now()}@cyberpay.dev`;
    const cpf = '11144477735';
    const registerResponse = await fetch(`http://127.0.0.1:${port}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'Conta de Teste 2', email, cpf, password: 'SenhaTeste456!', withdrawalPassword: 'Saque456!', plan: 'Ghost' }),
    });
    assert.equal(registerResponse.status, 201);
    const registeredUser = (await registerResponse.json()).user;

    const pendingLogin = await fetch(`http://127.0.0.1:${port}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: 'SenhaTeste456!' }),
    });
    assert.equal(pendingLogin.status, 403);

    const devSession = await fetch(`http://127.0.0.1:${port}/api/admin/seed-session`, { method: 'POST' });
    const adminToken = (await devSession.json()).token;
    const approval = await fetch(`http://127.0.0.1:${port}/api/admin/users/${registeredUser.id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
      body: JSON.stringify({ status: 'active' }),
    });
    assert.equal(approval.status, 200);

    const firstToken = await login(port, 'teste2@cyberpay.dev', 'SenhaTeste123!');
    const secondToken = await login(port, email, 'SenhaTeste456!');
    const headers = token => ({ 'Content-Type': 'application/json', Authorization: `Bearer ${token}` });
    const payer = { name: 'Maria da Silva', document: '52998224725' };
    const firstResponse = await fetch(`http://127.0.0.1:${port}/api/gateway/charges`, { method: 'POST', headers: headers(firstToken), body: JSON.stringify({ amount: 10, description: 'Conta 1', payer }) });
    const secondResponse = await fetch(`http://127.0.0.1:${port}/api/gateway/charges`, { method: 'POST', headers: headers(secondToken), body: JSON.stringify({ amount: 11, description: 'Conta 2', payer }) });
    assert.equal(firstResponse.status, 201);
    assert.equal(secondResponse.status, 201);
    assert.notEqual((await firstResponse.json()).userId, (await secondResponse.json()).userId);
  });
});

test('admin consegue criar, editar e remover um plano customizado', async () => {
  await withServer(async (port) => {
    const devSession = await fetch(`http://127.0.0.1:${port}/api/admin/seed-session`, { method: 'POST' });
    const adminToken = (await devSession.json()).token;

    const createResponse = await fetch(`http://127.0.0.1:${port}/api/admin/plans`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
      body: JSON.stringify({ name: 'Premium', percent: 4.5, fixed: 1.2, med: true }),
    });
    assert.equal(createResponse.status, 200);

    const patchResponse = await fetch(`http://127.0.0.1:${port}/api/admin/plans/Premium`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
      body: JSON.stringify({ percent: 6.5, fixed: 2.0, med: false }),
    });
    assert.equal(patchResponse.status, 200);
    const updatedPlan = await patchResponse.json();
    assert.equal(updatedPlan.percent, 6.5);
    assert.equal(updatedPlan.fixed, 2.0);
    assert.equal(updatedPlan.med, false);

    const deleteResponse = await fetch(`http://127.0.0.1:${port}/api/admin/plans/Premium`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    assert.equal(deleteResponse.status, 200);

    const overviewResponse = await fetch(`http://127.0.0.1:${port}/api/admin/overview`, {
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    assert.equal(overviewResponse.status, 200);
    const overview = await overviewResponse.json();
    assert.equal(Boolean(overview.plans.Premium), false);
  });
});

test('cliente só vê suas próprias cobranças e transferências da gateway', async () => {
  await withServer(async (port) => {
    const token = await login(port, 'teste2@cyberpay.dev', 'SenhaTeste123!');
    const meResponse = await fetch(`http://127.0.0.1:${port}/api/me`, { headers: { Authorization: `Bearer ${token}` } });
    assert.equal(meResponse.status, 200);
    const me = await meResponse.json();
    const dbPath = './data/cyberpay.json';
    const originalDb = fs.readFileSync(dbPath, 'utf8');
    const db = JSON.parse(originalDb);
    db.gatewayCharges.unshift({
      id: `forbidden_${Date.now()}`,
      clientTransactionId: `forbidden_${Date.now()}`,
      amount: 321,
      description: 'Cobrança de outro cliente',
      status: 'pending',
      userId: 'usr_outra_conta',
      createdAt: new Date().toISOString(),
    });
    db.gatewayTransfers.unshift({
      id: `tr_${Date.now()}`,
      type: 'internal',
      amount: 150,
      description: 'Transferência de outro cliente',
      status: 'completed',
      userId: 'usr_outra_conta',
      destination: 'outra@conta.com',
      createdAt: new Date().toISOString(),
    });
    fs.writeFileSync(dbPath, JSON.stringify(db, null, 2));

    try {
      const chargeResponse = await fetch(`http://127.0.0.1:${port}/api/gateway/charges`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      assert.equal(chargeResponse.status, 200);
      const chargeData = await chargeResponse.json();
      assert.ok(chargeData.items.every(item => item.userId === me.user.id));

      const transferResponse = await fetch(`http://127.0.0.1:${port}/api/gateway/transfers`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      assert.equal(transferResponse.status, 200);
      const transferData = await transferResponse.json();
      assert.ok(transferData.items.every(item => item.userId === me.user.id));
    } finally {
      fs.writeFileSync(dbPath, originalDb);
    }
  });
});

test('mutação da gateway sem sessão é rejeitada', async () => {
  await withServer(async (port) => {
    const response = await fetch(`http://127.0.0.1:${port}/api/gateway/charges`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ amount: 1 }),
    });
    assert.equal(response.status, 401);
  });
});

test('nome, CPF e descrição deixam de ser obrigatórios para cobrança VexaPay', async () => {
  await withServer(async (port) => {
    const token = await login(port, 'teste2@cyberpay.dev', 'SenhaTeste123!');
    const response = await fetch(`http://127.0.0.1:${port}/api/gateway/charges`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ amount: 1 }),
    });
    assert.equal(response.status, 201);
    const payload = await response.json();
    assert.equal(payload.status, 'pending');
    assert.ok(payload.id);
  });
});
