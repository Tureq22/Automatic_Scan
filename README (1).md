# Scanner Automatizado de Vulnerabilidades em CI/CD

**Português** | [English](README.en.md)

![Security Scan](https://github.com/SEU_USUARIO/SEU_REPO/actions/workflows/security.yml/badge.svg)

Portão de segurança automatizado para pipelines CI/CD. Um orquestrador em Python executa análise estática de código (SAST, via **Bandit**), análise de dependências (SCA, via **pip-audit** e **Trivy**) e detecção de segredos, consolida os resultados em um relatório JSON unificado e **falha a build** quando encontra vulnerabilidades acima do limiar configurado — impedindo que código inseguro chegue à branch principal.

## Arquitetura

```
push / pull request
        │
        ▼
  GitHub Actions ──> security_scan.py
                          ├── Bandit     (SAST: padrões inseguros no código Python)
                          ├── pip-audit  (SCA: CVEs em dependências, base OSV)
                          └── Trivy      (SCA + secrets + filesystem)
                               │
                               ▼
                    normalização de severidade
                               │
                               ▼
                     security_report.json
                               │
                 exit 0 (aprova) │ exit 1 (bloqueia o merge)
```

O contrato entre o script e o CI é apenas o **exit code**, o que torna o scanner portável para GitLab CI, Jenkins ou qualquer outra plataforma sem alteração de código.

| Exit code | Significado |
|-----------|-------------|
| `0` | Nenhuma vulnerabilidade acima do limiar — build aprovada |
| `1` | Vulnerabilidades bloqueantes encontradas — build falha |
| `2` | Erro na execução das ferramentas |

## Estrutura do projeto

```
.
├── .github/workflows/security.yml   # Pipeline do GitHub Actions
├── scanner/security_scan.py         # Orquestrador (o coração do projeto)
├── requirements.txt                 # Dependências da aplicação
├── .gitignore
└── README.md
```

> O arquivo `app/vulnerable_example.py`, com vulnerabilidades propositais, existe apenas na branch de demonstração `demo/vulnerabilidades`. A branch `main` é mantida limpa.

## Uso

### Instalação

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install bandit pip-audit
```

Trivy (opcional localmente, usado na pipeline):

```bash
# Linux
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
# macOS
brew install trivy
# Windows
choco install trivy
```

### Execução

```bash
python scanner/security_scan.py --path . --fail-on HIGH --report security_report.json
```

| Argumento | Padrão | Descrição |
|-----------|--------|-----------|
| `--path` | `.` | Diretório do projeto a analisar |
| `--fail-on` | `HIGH` | Severidade mínima que falha a build: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `--report` | `security_report.json` | Caminho do relatório JSON de saída |
| `--skip` | — | Ferramentas a pular: `bandit`, `pip-audit`, `trivy` |

### Ferramentas isoladas

Útil para depurar: se a ferramenta funciona sozinha, o problema está no orquestrador.

```bash
bandit -r . -f json
pip-audit -r requirements.txt -f json --no-deps
trivy fs --format json --scanners vuln,secret .
```

## Exemplo de saída

Rodando contra a branch de demonstração, com `requests==2.19.1`, `flask==0.12.3` e código vulnerável:

```
============================================================
RESUMO DA ANÁLISE DE SEGURANÇA
============================================================
 CRITICAL: 0
 HIGH: 29
 MEDIUM: 2
 LOW: 5
 Total: 36
 Limiar de falha (--fail-on): HIGH
============================================================

Vulnerabilidades bloqueantes:
 [HIGH] (bandit) B602 - subprocess_popen_with_shell_equals_true -> ./app/vulnerable_example.py:23
 [HIGH] (bandit) B324 - hashlib -> ./app/vulnerable_example.py:28
 [HIGH] (pip-audit) PYSEC-2023-74 - requests 2.19.1 vulneravel -> requests
 ...

BUILD FALHOU: 29 vulnerabilidade(s) >= HIGH encontrada(s).
```

Cada achado do pip-audit inclui o campo `fix_versions`, indicando para qual versão atualizar:

```json
{
  "tool": "pip-audit",
  "type": "SCA",
  "severity": "HIGH",
  "id": "PYSEC-2023-74",
  "package": "requests",
  "installed_version": "2.19.1",
  "fix_versions": ["2.31.0"]
}
```

## Integração com o GitHub

O workflow roda em todo `push` e `pull_request` para a `main`, além de permitir execução manual pela aba Actions. O relatório é publicado como artefato com `if: always()`, garantindo que fique disponível justamente quando a build falha.

Para transformar o check em obstáculo real ao merge, ative a proteção de branch em **Settings → Branches → Add branch ruleset**, exigindo o status check `SAST + SCA Scan` como obrigatório. Sem essa configuração o workflow ainda roda e reporta, mas o botão de merge continua liberado.

## Decisões de design

**pip-audit em vez de Safety.** Consulta a base OSV e o PyPI Advisory Database, não exige chave de API e é mantido pela PyPA. O Safety passou a exigir conta para uso completo.

**Normalização de severidade.** Cada ferramenta usa uma escala própria — o Bandit trabalha com `LOW`/`MEDIUM`/`HIGH`, o Trivy acrescenta `CRITICAL` e `UNKNOWN`, e o pip-audit não expõe severidade. O scanner unifica tudo em uma escala única antes de comparar com o limiar, e trata CVE sem severidade explícita como `HIGH` por postura conservadora.

**Exit code como contrato.** O CI não precisa entender o formato do relatório: `0` aprova, `1` bloqueia. Isso desacopla o scanner da plataforma.

**Tolerância a ferramentas ausentes.** Se uma ferramenta não está instalada, o scanner avisa e segue com as demais em vez de quebrar a pipeline inteira.

## Extensões possíveis

Saída em formato SARIF para integrar com a aba Security do GitHub, comentário automático no PR com o resumo via `actions/github-script`, Semgrep para regras SAST customizadas, Gitleaks dedicado a segredos, e um `.gitlab-ci.yml` equivalente.

## Licença

MIT
