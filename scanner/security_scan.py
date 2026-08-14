#!/usr/bin/env python3
"""
security_scan.py - Scanner automatizado de vulnerabilidades para Ci/CD pipelines.
==================================================================================
Orquestra ferramentas de SAST (Bandit) e SCA (pip-audit/Safety e Trivy),
consolidando os resultados em JSON e falha a build (exit code 1) se vulnerabilidades forem encontradas.

Uso:
    python scanner/security_scan.py --path . --fail-on HIGH --report report.json
    
Exit codes:
    0 - Nenhuma vulnerabilidade encontrada
    1 - Vulnerabilidades encontradas (de acordo com o nível de falha especificado)
    2 - Erro ao executar o scanner
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone

SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# Cores ANSI para o log da pipeline
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
BOLD = "\033[1m"
RESET = "\033[0m"

#Utilities

def run_command(cmd: list[str]) -> tuple[int, str, str]:
    """Executa um comando no shell e retorna o código de saída, stdout e stderr."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,  # Timeout de 10 minutos
        )
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        return 127, "", f"Comando não encontrado: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", f"Timeout expirado para o comando: {' '.join(cmd)}"

def tool_available(name: str) -> bool:
    return shutil.which(name) is not None

def normalize_severity(raw: str) -> str:
    """Normaliza a severidade de diferentes ferramentas para um padrão unico"""
    raw = (raw or "").upper() .strip()
    mapping = {
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH",
        "MODERATE": "MEDIUM",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
        "UNKNOWN": "LOW",
        "UNDEFINED": "LOW",
        "INFO": "LOW",
    }
    return mapping.get(raw, "LOW")

# SAST - Bandit (busca por padrões de código inseguros em Python)

def run_bandit(target_path: str) -> list[dict]:
    """Roda o Bandit e retorna uma lista de finding normalizados"""
    print(f"{BOLD} [1/3] Executando Bandit (SAST) . . .{RESET}")

    if not tool_available("bandit"):
        print(f"{YELLOW}Bandit não instalado - pulando (pip install bandit).{RESET}")
        return []

    code, stdout, stderr = run_command(
        ["bandit", "-r", target_path, "-f", "json", "-q",
         "--exclude", "./venv,./.venv,./node_modules,./.git"]
    )

    # Bandit retorna 1 quando encontra issues - isso é esperado, não é erro
    if code not in (0, 1):
        print(f"{RED} Erro ao executar Bandit: {stderr}{RESET}")
        return []

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        print(f"{RED} Falha ao interpretar JSON do Bandit{RESET}")
        return []

    findings = []
    for issue in data.get("results", []):
        findings.append({
            "tool": "bandit",
            "type": "SAST",
            "severity": normalize_severity(issue.get("issue_severity")),
            "confidence": issue.get("issue_confidence"),
            "id": issue.get("test_id"),
            "title": issue.get("test_name"),
            "description": issue.get("issue_text"),
            "file": issue.get("filename"),
            "line": issue.get("line_number"),
            "cwe": (issue.get("issue_cwe") or {}).get("id"),
            "more_info": issue.get("more_info"),
        })

    print(f" Bandit find {len(findings)} issue(s)")
    return findings

# SCA - pip-audit (busca por vulnerabilidades em dependências Python / CVEs conhecidas)

def run_pip_audit(target_path: str) -> list[dict]:
    """Roda o pip-audit contra o requirements.txt e normaliza os resultados"""

    print(f"{BOLD} [2/3] Executando pip-audit (SCA - dependências) . . .{RESET}")

    if not tool_available("pip-audit"):
        print(f"{YELLOW} pip-audit não instalado - pulando (pip install pip-audit).{RESET}")
        return []

    req_file = os.path.join(target_path, "requirements.txt")
    if not os.path.exists(req_file):
        print(f"{YELLOW} requirements.txt não encontrado em {target_path} - pulando pip-audit.{RESET}")
        return []

    code, stdout, stderr = run_command(
        ["pip-audit", "-r", req_file, "-f", "json", "--disable-pip"]
    )

    if code not in (0, 1):
        print(f"{RED} Erro ao executar pip-audit: {stderr}{RESET}")
        return []

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        print(f"{RED} Falha ao interpretar JSON do pip-audit{RESET}")
        return []

    findings = []
    for dep in data.get("dependencies", []):
        for vuln in dep.get("vulns", []):
            findings.append({
                "tool": "pip-audit",
                "type": "SCA",
                "severity": "HIGH",
                "id": vuln.get("id"),
                "title": f"{dep.get('name')} {dep.get('version')} vulneravel",
                "description": (vuln.get("description") or "")[:300],
                "package": dep.get("name"),
                "installed_version": dep.get("version"),
                "fix_versions": vuln.get("fix_versions, []"),
                "aliases": vuln.get("aliases", []),
            })

    print(f" pip-audit find {len(findings)} issue(s)")
    return findings


# SCA/Container - Trivy (filesystem, dependencias e segredos)

def run_trivy(target_path: str) -> list[dict]:
    """Roda o Trivy em modo filesystem e normaliza os resultados"""
    print(f"{BOLD} [3/3] Executando Trivy (SCA/secrets/filesystem) . . .{RESET}")

    if not tool_available("trivy"):
        print(f"{YELLOW} Trivy não instalado - pulando (ver README para instalação).{RESET}")
        return []

    code, stdout, stderr = run_command(
        ["trivy", "fs", "--format", "json", "--quiet",
         "--scanners", "vuln,secret", target_path]
    )

    if code not in (0, 1):
        print(f"{RED} Erro ao executar Trivy: {stderr}{RESET}")
        return []

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        print(f"{RED} Falha ao interpretar JSON do Trivy{RESET}")
        return []

    findings = []
    for result in data.get("Results", []) or []:
        # Vulnerabilidades em dependências
        for vuln in result.get("Vulnerabilities", []) or []:
            findings.append({
                "tool": "trivy",
                "type": "SCA",
                "severity": normalize_severity(vuln.get("Severity")),
                "id": vuln.get("VulnerabilityID"),
                "title": vuln.get("Title") or vuln.get("VulnerabilityID"),
                "description": (vuln.get("Description") or "")[:300],
                "package": vuln.get("PkgName"),
                "installed_version": vuln.get("InstalledVersion"),
                "fixed_version": vuln.get("FixedVersion"),
                "target": result.get("Target"),
            })

        # Segredos vazados no código (chaves de API, senhas, tokens)
        for secret in result.get("Secrets", []) or []:
            findings.append({
                "tool": "trivy",
                "type": "SECRET",
                "severity": normalize_severity(secret.get("Severity")),
                "id": secret.get("RuleID"),
                "title": secret.get("Title"),
                "description": "Possivel segredo/credencial exposto no código",
                "file": secret.get("Target"),
                "line": secret.get("StartLine"),
            })

    print(f" Truvy encontrou {len(findings)} issue(s)")
    return findings

# Consolidação, relatório e decisão de build

def summarize(findings: list[dict]) -> dict:
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        summary[f["severity"]] = summary.get(f["severity"], 0) + 1
        return summary

def print_summary(findings: list[dict], summary: dict, fail_on: str) -> None:
    print(f"\n{BOLD}{'=' * 60}{RESET}")
    print(f"{BOLD}RESUMO DA ANÁLISE DE SEGURANÇA{RESET}")
    print(f"{'=' * 60}")
    print(f" {RED}CRITICAL: {summary['CRITICAL']}{RESET}")
    print(f" {RED}HIGH: {summary['HIGH']}{RESET}")
    print(f" {YELLOW}MEDIUM: {summary['MEDIUM']}{RESET}")
    print(f" LOW: {summary['LOW']}")
    print(f" Total: {len(findings)}")
    print(f" Limiar de falha (--fail-on): {fail_on}")
    print(f"{'=' * 60}\n")

    #Lista as vulnerabilidades acima do limiar para facilitar o debug no CI
    threshold = SEVERITY_ORDER[fail_on]
    blocking = [f for f in findings if SEVERITY_ORDER[f["severity"]] >= threshold]
    if blocking:
        print(f"{BOLD}{RED}Vulnerabilidaes bloqueantes:{RESET}")
        for f in blocking:
            location = f.get("file") or f.get("package") or f.gt("target") or "-"
            line = f":{f['line']}" if f.get("line") else ""
            print(f" [{f['severity']}] ({f['tool']}) {f.get('id,' '-')}"
                  f"- {f.get('title', '-')} -> {location}{line}")
        print()

def write_report(findings: list[dict], summary: dict, output: str, fail_on: str, passed: bool) -> None:
    report = {
        "scan_date": datetime.now(timezone.utc). isoformat(),
        "fail_on_threshold": fail_on,
        "passed": passed,
        "summary": summary,
        "total_findings": len(findings),
        "findings": findings,
    }
    with open(output, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(f"Relatorio salvo em: {output}")