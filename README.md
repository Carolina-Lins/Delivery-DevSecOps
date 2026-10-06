# AI-First DevSecOps Pipeline & Threat Scanner

![GitHub Actions](https://img.shields.io/badge/GitHub_Actions-2088FF?style=for-the-badge&logo=githubactions&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![OpenAI](https://img.shields.io/badge/OpenAI_API-412991?style=for-the-badge&logo=openai&logoColor=white)
![Status](https://img.shields.io/badge/status-em_desenvolvimento-yellow?style=for-the-badge)

Projeto de estudo que simula uma esteira de *DevSecOps para o ecossistema de foodtech e delivery. A ideia é unir ferramentas tradicionais de análise estática (SAST) a um agente de IA capaz de apontar falhas de **lógica de negócio* que scanners convencionais costumam perder, como sequestro de contas de entregadores (Account Takeover), fraudes no checkout e endpoints sensíveis sem proteção.

> *Status:* em desenvolvimento. Veja o [roadmap](#roadmap) para o que já está pronto e o que vem a seguir.
>
> Projeto independente, inspirado em cenários comuns de plataformas de delivery de alta escala.

---

## Arquitetura da Esteira


[ Commit / Pull Request ]
          │
          ├──► 1. Linting & SAST estático (Bandit)
          │
          ├──► 2. Agente de IA SecOps (LLM + saída estruturada)
          │        └─► Analisa regras de negócio (ex.: ATO, ausência de rate limit)
          │
          └──► 3. Bloqueio de merge + relatório SARIF no GitHub


---

## Diferenciais

- *AI-First Security:* respostas estruturadas (Pydantic/JSON) reduzem falsos positivos e permitem gerar sugestões de correção direto nos Pull Requests.
- *Cenários de delivery:* o código é avaliado contra falhas típicas de plataformas de alta escala:
  - Tentativas de Account Takeover (ATO) em logins de parceiros/entregadores
  - Ausência de rate limiting em endpoints críticos em horários de pico
  - Vazamento de credenciais e bypass de pagamento no checkout
- *Segurança em camadas:* combina o determinismo do *Bandit* com a análise contextual da *IA*.

---

## Roadmap

- [x] Definição da arquitetura e dos cenários de risco
- [ ] Aplicação de exemplo com vulnerabilidades propositais (app_examples/)
- [ ] Integração com Bandit (saída em JSON)
- [ ] Agente de IA com saída estruturada (sast_scan.py)
- [ ] Workflow no GitHub Actions com bloqueio de merge
- [ ] Geração de relatório SARIF
- [ ] Demo em vídeo/GIF

---

## Como executar localmente

> *Atenção:* os passos abaixo descrevem o uso planejado; os scripts serão adicionados conforme o roadmap avança.

1. *Clone o repositório:*
   bash
   git clone https://github.com/Carolina-Lins/Delivery-DevSecOps.git
   cd Delivery-DevSecOps
   

2. *Instale as dependências e configure a API:*
   bash
   pip install -r requirements.txt
   export OPENAI_API_KEY="sua-chave-aqui"
   

3. *Rode o scanner:*
   bash
   python sast_scan.py --target ./app_examples/
   

---

## Exemplo de saída esperada da IA

json
{
  "vulnerability_type": "Business Logic / Rate Limiting Missing",
  "severity": "HIGH",
  "line_number": 42,
  "description": "O endpoint de autenticação do entregador não possui limitação de taxa, permitindo ataques de força bruta durante horários de pico.",
  "suggested_fix": "Implemente um rate limiter baseado em Redis com limite de 5 requisições por minuto por IP."
}


---

## Autora

*Maria Carolina Lins de Oliveira*
Estudante de Segurança da Informação (CESAR School) · Recife, PE
[LinkedIn](https://www.linkedin.com/in/maria-carolina-lins) · [GitHub](https://github.com/Carolina-Lins)
