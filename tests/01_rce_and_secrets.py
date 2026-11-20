"""
Тест 1: Классические уязвимости Python (детектируются и AST-анализатором, и LLM).
Ожидаемые находки AST:
- CWE-798: захардкоженные секреты (DB_PASSWORD, JWT_SECRET)
- CWE-78: инъекция команд через os.system и subprocess.Popen(..., shell=True)
- CWE-502: небезопасная десериализация pickle.loads и yaml.load
- CWE-327: использование устаревшего MD5
"""
import os
import yaml
import pickle
import hashlib
import subprocess

DB_PASSWORD = "SuperSecretProdPassword2026!"
JWT_SECRET = "jwt_private_signing_key_9912"


def hash_user_token(token: str) -> str:
    return hashlib.md5(token.encode("utf-8")).hexdigest()


def run_backup(target_dir: str):
    os.system(f"tar -czf backup.tar.gz {target_dir}")
    subprocess.Popen("echo Backup finished for " + target_dir, shell=True)


def load_user_state(raw_bytes: bytes, yaml_config: str):
    state = pickle.loads(raw_bytes)
    config = yaml.load(yaml_config)
    return state, config
