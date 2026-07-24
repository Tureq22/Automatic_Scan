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

def tool_available(name; str) -> bool:
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