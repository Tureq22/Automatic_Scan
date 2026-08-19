"""
vulnerable_example.py - Código PROPOSITALMENTE vulnerável para demonstração.
Use este arquivo para provar que o scanner detecta e bloqueia a build.
NUNCA use estes padrões em produção.
Depois de demonstrar, corrija ou delete este arquivo para ver a build passar.
"""

import hashlib
import pickle
import subprocess

import requests


def buscar_usuario(user_input: str):
    """B608: concatenação direta em SQL -> SQL Injection."""
    query = "SELECT * FROM users WHERE name = '" + user_input + "'"
    return query


def executar_comando(comando_usuario: str):
    """B602: shell=True com input do usuário -> Command Injection."""
    return subprocess.call(comando_usuario, shell=True)


def gerar_hash_senha(senha: str) -> str:
    """B324: MD5 é criptograficamente quebrado para senhas."""
    return hashlib.md5(senha.encode()).hexdigest()


def carregar_dados(dados_serializados: bytes):
    """B301: pickle com dados não confiáveis -> execução de código arbitrário."""
    return pickle.loads(dados_serializados)


def chamar_api_interna(url: str):
    """B501: verify=False desabilita a validação do certificado TLS."""
    return requests.get(url, verify=False, timeout=10)


# B105: senha hardcoded no código (também detectado como secret pelo Trivy)
DB_PASSWORD = "super_secret_password_123"
