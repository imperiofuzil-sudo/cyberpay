# CyberPay Gateway

## Executar localmente

```powershell
npm start
```

Configure a VexaPay copiando `.env.example` para `.env` e preenchendo `VEXAPAY_CLIENT_ID`, `VEXAPAY_CLIENT_SECRET` e `VEXAPAY_WEBHOOK_SECRET`. O arquivo `.env` é ignorado pelo Git. Cobranças e saques são encaminhados à API real da VexaPay; erros não geram operações locais fictícias. Mesmo no sandbox, a documentação alerta que a infraestrutura Pix é real.

Abra `http://localhost:3000/` no navegador. Use `http://localhost:3000/login.html` para o login e `http://localhost:3000/admin.html` para o painel administrativo. As telas devem ser acessadas pelo servidor local para que as chamadas `/api` funcionem.

O projeto é local e não possui configuração de deploy. Os dados de desenvolvimento ficam em `data/cyberpay.json`.

## Variáveis de segurança

Para testar o webhook localmente, defina `CYBERPAY_WEBHOOK_SECRET` com um segredo forte. A rota `POST /api/admin/seed-session` fica desativada por padrão; para desenvolvimento local, habilite explicitamente `ENABLE_DEV_ADMIN=true`.

As senhas novas usam `scrypt`, as sessões expiram em 8 horas, e login, cadastro e webhook possuem rate limiting. Usuários antigos com hash SHA-256 são atualizados para `scrypt` no próximo login bem-sucedido.

O login administrativo e o login de cliente usam e-mail e senha. O login de cliente demo é `teste2@cyberpay.dev` com senha `SenhaTeste123!`.

## API local

- `POST /api/auth/register`: cria uma conta.
- `POST /api/auth/login`: autentica uma conta e retorna um token de sessão.
- `POST /api/auth/admin-login`: autentica o operador administrativo e retorna um token com papel `admin`.
- `GET /api/public/config`: publica apenas os nomes e tarifas dos planos disponíveis e o contato oficial de suporte, para sincronizar site e cadastro.
- `GET /api/me`: retorna dados do cliente, avisos, parcerias e regras operacionais.
- `GET /api/withdrawals`: lista somente os saques pertencentes à conta autenticada.
- `GET /api/gateway/overview`: retorna saldo, métricas de cobrança e histórico da conta autenticada.
- `GET /api/notifications`: retorna a auditoria associada ao cliente.
- `POST /api/admin/seed-session`: cria uma sessão admin apenas para desenvolvimento local, quando `ENABLE_DEV_ADMIN=true`.
- `GET /api/admin/overview`: retorna usuários, saques, planos, avisos, parcerias e configurações.
- `POST /api/admin/gateway/test`: verifica se as credenciais VexaPay estão configuradas; a VexaPay não documenta endpoint de health check.
- `PATCH /api/admin/withdrawals/:id`: libera, bloqueia ou recusa um saque com motivo.
- `PATCH /api/admin/users/:id`: altera nome, e-mail, telefone, plano ou status.
- `PATCH /api/admin/settings`: altera modo manual/automático e limite automático.
- `POST /api/admin/notices`: publica avisos para o painel dos clientes.
- `POST /api/admin/partners`: publica parceiros para o painel dos clientes.
- `GET /api/admin/audit`: consulta o log administrativo.
- `POST /api/webhooks/cyberpay`: webhook interno CyberPay, assinado com `X-CyberPay-Signature` e `Idempotency-Key`.
- `POST /api/webhooks/vexapay`: valida `X-VexaPay-Signature` sobre o corpo bruto e atualiza cobrança/saque armazenado.

As rotas locais de cobrança exigem sessão de cliente CyberPay (`Authorization: Bearer <token>`). `POST /api/gateway/charges` recebe `amount`, `payer.name`, `payer.document`, e opcionalmente `description` e `external_id`. Consulte via `GET /api/gateway/charges/:id`. Saques usam o saldo compartilhado da única conta VexaPay configurada e, por isso, `POST /api/gateway/payouts` e `GET /api/gateway/payouts/:id` exigem sessão administrativa; clientes não podem movimentar esse saldo. O POST recebe `amount`, `pix_key`, `pix_key_type` e opcionalmente `external_id`. `POST /api/gateway/transfers` permanece como alias legado protegido da mesma forma.

As chamadas servidor-a-servidor usam `Authorization: Bearer <VEXAPAY_CLIENT_SECRET>` e `X-Client-Id: <VEXAPAY_CLIENT_ID>`. A cobrança retorna o código `copyPaste` e, se disponível, `qrCode` em base64. Um payout pode retornar `201` ou `202` (análise manual). Consulte [VEXAPAY_API.md](VEXAPAY_API.md) para o contrato completo.

## Testes

`npm test` usa um mock HTTP local para validar cobranças, saques e consultas; os testes não chamam a VexaPay e não movimentam dinheiro. Uma validação real requer credenciais VexaPay, dados válidos de pagador/chave PIX e autorização explícita para o valor, pois a documentação informa que o PIX pode ser processado em infraestrutura real.

## Limites do ambiente local

A API usa um arquivo JSON e sessões em memória para facilitar testes. Antes de movimentar dinheiro real, substitua esse armazenamento por PostgreSQL ou outro banco transacional, remova `seed-session`, use sessões/refresh tokens seguros, aplique RBAC, rate limiting, validação de schema, cofre de segredos, logs imutáveis e integração oficial com PSP/Banco Central. Também será necessário implementar ledger de dupla entrada, idempotência, webhooks assinados, KYC/KYB, antifraude, MED e conciliação financeira.

## Publicação do domínio

No servidor de produção, configure `NODE_ENV=production`, `VEXAPAY_BASE_URL`, `VEXAPAY_CLIENT_ID`, `VEXAPAY_CLIENT_SECRET` e `VEXAPAY_WEBHOOK_SECRET` como variáveis protegidas. Nunca coloque segredos em HTML, JavaScript público ou repositório. Use HTTPS, desative `ENABLE_DEV_ADMIN` e encaminhe `/api` ao processo Node.
