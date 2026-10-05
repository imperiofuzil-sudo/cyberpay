# VexaPay PIX API

API base: `https://vexapay.site/api/v1`  
Formato: JSON UTF-8. A integracao local deste projeto funciona como proxy e mantem as credenciais somente no backend.

## Credenciais e ambiente

Crie uma integracao no painel VexaPay e configure no servidor:

```env
VEXAPAY_BASE_URL=https://vexapay.site/api/v1
VEXAPAY_CLIENT_ID=ci_...
VEXAPAY_CLIENT_SECRET=cs_...
VEXAPAY_WEBHOOK_SECRET=...
```

Cada requisicao direta a VexaPay usa `Authorization: Bearer SEU_CLIENT_SECRET`, `X-Client-Id: SEU_CLIENT_ID` e, em POST, `Content-Type: application/json`. Nunca envie Client Secret ao navegador. A API usa a mesma URL em sandbox e producao; a documentacao alerta que o PIX pode passar pela infraestrutura real mesmo em sandbox. Use valores baixos.

## Criar cobranca

`POST /charges`

```json
{
  "amount": 1.00,
  "external_id": "pedido-123",
  "payer": { "name": "Maria da Silva", "document": "52998224725" },
  "description": "Pedido 123"
}
```

`amount` minimo R$ 1,00; `payer.name` e CPF valido em `payer.document` sao obrigatorios. `external_id` e recomendado e aceita ate 120 caracteres. A resposta `201` inclui `id` (`ch_...`), `status`, `pix_copy_paste` e `qr_code_base64` (pode ser `null`). Para exibir novamente uma cobranca deduplicada, consulte `GET /charges/{id}`.

## Consultar cobranca

`GET /charges/{id}` retorna status `pending`, `paid` ou `cancelled`; `paid_at` e `null` enquanto pendente. A consulta pode confirmar o pagamento diretamente no provedor, servindo de contingencia ao webhook.

## Criar saque PIX

`POST /payouts`

```json
{
  "amount": 1.00,
  "pix_key": "financeiro@empresa.com",
  "pix_key_type": "email",
  "external_id": "saque-987"
}
```

`pix_key_type` deve ser `cpf`, `cnpj`, `email`, `telefone` ou `aleatoria`. O valor minimo e R$ 1,00 (algumas contas exigem R$ 5,00). A chave deve corresponder ao tipo. Sucesso pode ser `201` ou `202`; `202` significa encaminhado para analise manual e deve continuar sendo consultado. O recebedor recebe exatamente `amount`, e a taxa e debitada adicionalmente do saldo. O saldo precisa cobrir valor e taxa.

`GET /payouts/{id}` retorna `pending`, `paid` ou `cancelled`. Saques pendentes recentes podem impedir nova solicitacao por 30 segundos. Se falhar, o valor reservado retorna ao saldo.

## Eventos webhook

Configure uma URL HTTPS no painel. Esta aplicacao recebe em `POST /api/webhooks/vexapay`, desde que esse caminho esteja publicado com HTTPS e `VEXAPAY_WEBHOOK_SECRET` corresponda ao segredo da integracao.

Eventos: `pix.charge.paid`, `pix.charge.cancelled`, `pix.payout.paid` e `pix.payout.cancelled`. A VexaPay envia `X-VexaPay-Event` e `X-VexaPay-Signature`. A assinatura e HMAC-SHA256 hexadecimal do corpo bruto; a rota valida a assinatura em tempo constante antes de atualizar a operacao.

A VexaPay envia o webhook uma vez, sem reenvio automatico. Responda rapidamente e trate eventos de forma idempotente. Consulte a cobranca ou saque pendente periodicamente para reconciliar eventos ausentes.

## Rotas deste projeto

As rotas locais de cobranca usam sessao de cliente CyberPay (`Authorization: Bearer <token>`). As rotas locais de saque exigem sessao administrativa: as credenciais VexaPay sao globais e ainda nao ha saldo/ledger segregado por usuario, portanto clientes nao podem sacar do saldo compartilhado. O servidor adiciona as credenciais VexaPay e nunca as entrega ao frontend.

| Rota local | Funcao |
|---|---|
| `POST /api/gateway/charges` | Cria cobranca; corpo `amount`, `payer: { name, document }`, `description?`, `external_id?`. |
| `GET /api/gateway/charges` | Lista cobrancas da sessao. |
| `GET /api/gateway/charges/{id}` | Consulta cobranca pertencente a sessao. |
| `POST /api/gateway/payouts` | Admin envia saque; corpo `amount`, `pix_key`, `pix_key_type`, `external_id?`. |
| `GET /api/gateway/payouts/{id}` | Admin consulta saque da conta VexaPay. |
| `GET /api/gateway/transfers` | Lista saques da sessao autenticada. |

A rota legada `POST /api/gateway/transfers` continua aceita como alias de `POST /api/gateway/payouts` e agora exige os campos de saque PIX documentados acima. O saque do dashboard que cria solicitações internas CyberPay em `/api/withdrawals` continua sendo uma fila de análise própria e nao envia dinheiro pela VexaPay.

## Erros e repeticao

Erros VexaPay usam `{ "error": "codigo", "message": "descricao" }`. Codigos comuns: `400 invalid_json`, `401 unauthorized`, `403 production_not_approved` ou `account_unavailable`, `404 not_found`, `422 invalid_amount`, `invalid_document`, `invalid_payer`, `fee_exceeds_amount`, `invalid_pix_key` ou `internal_error`, `502 gateway_error` e `503 gateway_disabled`.

Use um `external_id` unico por pedido/saque. Em timeout, falha de rede ou erro `500`, `502` ou `503`, repita com o mesmo identificador; a VexaPay retorna a operacao existente em vez de duplicar. A resposta de cobranca duplicada pode nao conter o copia-e-cola, entao faca GET pela cobranca retornada.

## Testes

`npm test` usa um mock HTTP e nao movimenta valores nem chama a VexaPay. Testes reais de cobranca ou saque exigem autorizacao explicita para um valor e uma chave PIX de destino, pois podem transferir dinheiro real.