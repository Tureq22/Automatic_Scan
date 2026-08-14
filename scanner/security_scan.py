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
