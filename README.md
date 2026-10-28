# AI-First DevSecOps Pipeline & Threat Scanner

![GitHub Actions](https://img.shields.io/badge/GitHub_Actions-2088FF?style=for-the-badge&logo=githubactions&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![OpenAI](https://img.shields.io/badge/OpenAI_API-412991?style=for-the-badge&logo=openai&logoColor=white)

Projeto de estudo que simula uma esteira de **DevSecOps para o ecossistema de foodtech e delivery**. A ideia é unir ferramentas tradicionais de análise estática (SAST) a um agente de IA capaz de apontar falhas de **lógica de negócio** que scanners convencionais costumam perder, como sequestro de contas de entregadores (*Account Takeover*), fraudes no checkout e endpoints sensíveis sem proteção.

> *Projeto independente, inspirado em cenários comuns de plataformas de delivery de alta escala.*

---

## Arquitetura da Esteira

```
[ Commit / Pull Request ]
          │
          ├──► 1. Linting & SAST estático (Bandit)
          │
          ├──► 2. Agente de IA SecOps (LLM + saída estruturada)
          │        └─► Analisa regras de negócio (ex.: ATO, ausência de rate limit)
          │
          └──► 3. Bloqueio de merge + relatório SARIF no GitHub
```

---

## Diferenciais

- **AI-First Security:** respostas estruturadas (Pydantic/JSON) reduzem falsos positivos e permitem gerar sugestões de correção direto nos Pull Requests.
- **Cenários de delivery:** o código é avaliado contra falhas típicas de plataformas de alta escala:
  - Tentativas de *Account Takeover* (ATO) em logins de parceiros/entregadores
  - Ausência de *rate limiting* em endpoints críticos em horários de pico
  - Vazamento de credenciais e *bypass* de pagamento no checkout
- **Segurança em camadas:** combina o determinismo do **Bandit** com a análise contextual da **IA**.

---

## Roadmap

- [x] Definição da arquitetura e dos cenários de risco
- [x] Aplicação de exemplo com vulnerabilidades propositais (`app_examples/`)
- [x] Integração com Bandit (saída em JSON)
- [x] Agente de IA com saída estruturada (`sast_scan.py`)
- [x] Workflow no GitHub Actions com bloqueio de merge
- [x] Relatório SARIF na aba Security do GitHub

---

## Como executar localmente

1. **Clone o repositório e crie o ambiente virtual:**
   ```bash
   git clone https://github.com/Carolina-Lins/Delivery-DevSecOps.git
   cd Delivery-DevSecOps
   python -m venv .venv
   ```
   Ative o ambiente: `.venv\Scripts\activate` (Windows) ou `source .venv/bin/activate` (Mac/Linux).

2. **Instale as dependências:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Rode o Bandit e gere o relatório em JSON:**
   ```bash
   python -m bandit -r app_examples -f json -o reports/bandit_report.json
   ```

4. **Configure a chave da OpenAI e rode o agente de IA:**
   ```bash
   # Mac/Linux
   export OPENAI_API_KEY="sua-chave-aqui"
   # Windows (PowerShell)
   $env:OPENAI_API_KEY="sua-chave-aqui"

   python sast_scan.py --target app_examples --bandit-report reports/bandit_report.json --output reports/ai_report.json --provider openai
   ```
   Para ver o que seria enviado à IA sem gastar nada, adicione `--dry-run`.

O script termina com código de erro quando encontra falha de severidade HIGH ou maior. É isso que bloqueia o merge no pipeline.

### No GitHub Actions

Cadastre o secret `OPENAI_API_KEY` em **Settings → Secrets and variables → Actions**. Sem ele, a etapa da IA é pulada e o restante do pipeline continua funcionando.

> **Atenção:** `app_examples/` é vulnerável de propósito. Nunca publique esse código em produção.

---

## Exemplo de saída da IA

```json
{
  "file": "app_examples/vulnerable_app.py",
  "vulnerability_type": "Account Takeover (ATO)",
  "severity": "HIGH",
  "line_number": 56,
  "description": "Endpoint de login sem limite de tentativas, permitindo brute force.",
  "suggested_fix": "Adicionar um mecanismo de rate limiting para limitar tentativas de login."
}
```

---

## Resultados

Testes feitos no app de exemplo, que tem 10 falhas propositais (gabarito em `app_examples/EXPECTED_FINDINGS.md`):

| Falha | Bandit | Agente de IA |
|-------|:------:|:------------:|
| Credenciais fixas no código | Sim | Não aplicável |
| Hash MD5 fraco | Sim | Não aplicável |
| SQL Injection | Sim | Não aplicável |
| Serviço exposto em `0.0.0.0` | Sim | Não aplicável |
| Senha registrada em log | Não | Sim |
| Login sem rate limit (ATO) | Não | Sim |
| IDOR em `/orders/{id}` | Não | Sim |
| Bypass no checkout | Não | Parcial |
| Endpoints sem autenticação | Não | Parcial |
| Token previsível | Não | Não |

**Leitura dos resultados**
- O **Bandit** encontrou 9 ocorrências, todas de *padrão de código*, e nenhuma falha de regra de negócio.
- O **agente de IA** encontrou de 4 a 5 achados por execução, concentrados em lógica de negócio e controle de acesso.
- Uma falha (token previsível) escapou das duas camadas.

**Limitações conhecidas**
- A IA **não é determinística**: o resultado varia entre execuções (5 achados em um teste e 4 no pipeline).
- Os números de linha citados podem ser imprecisos. A validação com Pydantic garante o *formato* da resposta, não a sua *correção*.
- Por isso o projeto usa camadas (SAST + IA) e não substitui a revisão humana.

---

## Autora

**Carolina Lins**
Estudante de Segurança da Informação (CESAR School) · Recife, PE
[LinkedIn](https://www.linkedin.com/in/maria-carolina-lins) · [GitHub](https://github.com/Carolina-Lins)