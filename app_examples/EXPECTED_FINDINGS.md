# Falhas propositais em `vulnerable_app.py`

Este arquivo serve como "gabarito" para avaliar o scanner (Bandit + agente de IA).

| # | Falha | Onde | Esperado de |
|---|-------|------|-------------|
| 1 | Credenciais hardcoded (`SECRET_KEY`, `DB_PASSWORD`) | topo do arquivo | Bandit |
| 2 | Hash fraco (MD5) para senhas e token | `login` | Bandit |
| 3 | SQL Injection (f-string na query) | `login`, `search_users` | Bandit |
| 4 | Serviço exposto em `0.0.0.0` | bloco `__main__` | Bandit |
| 5 | Senha registrada em log | `login` | IA |
| 6 | Sem rate limiting no login (força bruta / ATO) | `login` | IA |
| 7 | Token previsível (md5 de e-mail + chave fixa) | `login` | IA |
| 8 | IDOR: qualquer pessoa lê qualquer pedido | `get_order` | IA |
| 9 | Bypass de pagamento: preço vindo do cliente, quantidade negativa, cupom sem limite de uso, pedido marcado como pago sem gateway | `checkout` | IA |
| 10 | Sem autenticação nos endpoints | todos | IA |

Obs.: os itens "Bandit" são os esperados; confirme rodando `bandit -r app_examples/`.
