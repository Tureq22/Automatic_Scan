# Scanner Automatizado de Vulnerabilidades em CI/CD (DevSecOps Core)

Pipeline de segurança que executa análise estática de código (SAST, via **Bandit**), análise de dependências (SCA, via **pip-audit** e **Trivy**) e detecção de segredos, consolida tudo em um relatório JSON e **falha a build automaticamente** quando encontra vulnerabilidades acima do limiar configurado.

## Arquitetura

```
push/PR ──> GitHub Actions ──> security_scan.py
                                   ├── Bandit     (SAST: código Python inseguro)
                                   ├── pip-audit  (SCA: CVEs em dependências)
                                   └── Trivy      (SCA + secrets + filesystem)
                                        │
                                        ▼
                            security_report.json
                                        │
                          exit 0 (passa) / exit 1 (bloqueia merge)
```

## Estrutura do projeto

```
devsecops-scanner/
├── .github/workflows/security.yml   # Pipeline do GitHub Actions
├── scanner/security_scan.py         # Orquestrador (o coração do projeto)
├── app/vulnerable_example.py        # Código vulnerável para demonstração
├── requirements.txt                 # Inclui dependência vulnerável de propósito
└── README.md
```

## Passo a passo

### Fase 1 — Ambiente local

1. Instale o Python 3.11+ e crie o ambiente virtual:
   ```bash
   python -m venv venv
   source venv/bin/activate        # Windows: venv\Scripts\activate
   ```
2. Instale as ferramentas de análise:
   ```bash
   pip install bandit pip-audit
   ```
3. Instale o Trivy (opcional localmente, obrigatório entender):
   ```bash
   # Linux
   curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
   # macOS
   brew install trivy
   # Windows
   choco install trivy
   ```

### Fase 2 — Entender cada ferramenta isoladamente

Antes de automatizar, rode cada uma na mão e leia o JSON de saída. Isso é o que diferencia quem entende do projeto de quem só copiou código:

```bash
bandit -r app/ -f json | python -m json.tool
pip-audit -r requirements.txt -f json | python -m json.tool
trivy fs --format json --scanners vuln,secret .
```

Observe os campos que o `security_scan.py` extrai: `issue_severity`, `test_id` e `filename` no Bandit; `vulns`, `fix_versions` no pip-audit; `Severity`, `VulnerabilityID` no Trivy.

### Fase 3 — Rodar o scanner localmente

```bash
python scanner/security_scan.py --path . --fail-on HIGH --report security_report.json
echo $?   # deve retornar 1 (build falhou por causa do código vulnerável)
```

Teste as variações:
```bash
python scanner/security_scan.py --fail-on CRITICAL      # limiar mais permissivo
python scanner/security_scan.py --skip trivy            # pular uma ferramenta
```

### Fase 4 — Subir para o GitHub e ativar a pipeline

1. Crie um repositório no GitHub e envie o projeto:
   ```bash
   git init
   git add .
   git commit -m "feat: scanner de vulnerabilidades DevSecOps"
   git branch -M main
   git remote add origin https://github.com/SEU_USUARIO/devsecops-scanner.git
   git push -u origin main
   ```
2. Vá na aba **Actions** do repositório: o workflow `Security Scan (DevSecOps)` roda automaticamente e deve **falhar** (vermelho) — esse é o comportamento esperado, provando que o portão de segurança funciona.
3. Baixe o artefato `security-report` na página da execução para ver o JSON completo.

### Fase 5 — Demonstrar o ciclo completo (a parte que impressiona)

1. Crie uma branch de correção:
   ```bash
   git checkout -b fix/vulnerabilidades
   ```
2. Corrija as vulnerabilidades: atualize o `requirements.txt` (`requests>=2.32.0`, `flask>=3.0.0`) e corrija/remova o `app/vulnerable_example.py` (use queries parametrizadas, `hashlib.sha256`, `shell=False`, `verify=True`, senha via variável de ambiente).
3. Abra um Pull Request e veja a pipeline passar (verde). Screenshot do antes/depois é ouro para o portfólio.
4. Em **Settings > Branches > Branch protection rules**, exija que o check `SAST + SCA Scan` passe antes de permitir merge na `main`. Agora nenhum código vulnerável entra no repositório.

## Decisões de design (para explicar em entrevista)

- **pip-audit em vez de Safety**: usa a base de dados OSV (Google) e o PyPI Advisory Database, não exige chave de API e é mantido pela PyPA. O Safety passou a exigir conta para uso completo. O script aceita trocar facilmente.
- **Normalização de severidade**: cada ferramenta usa escalas diferentes (Bandit usa LOW/MEDIUM/HIGH; Trivy inclui CRITICAL e UNKNOWN). O scanner unifica tudo antes de decidir.
- **Exit codes como contrato**: o GitHub Actions só precisa do código de saída — `0` passa, `1` bloqueia. Isso torna o script portável para GitLab CI, Jenkins ou qualquer CI.
- **`if: always()` no upload**: o relatório é publicado mesmo quando a build falha, que é exatamente quando ele é mais necessário.
- **Postura conservadora no SCA**: CVE em dependência sem severidade explícita é tratada como HIGH.

## Extensões possíveis

Gitleaks dedicado para secrets, Semgrep para regras SAST customizadas, comentário automático no PR com o resumo (via `actions/github-script`), suporte a `--format sarif` para integrar com a aba Security do GitHub, e versão para GitLab CI (`.gitlab-ci.yml`).
