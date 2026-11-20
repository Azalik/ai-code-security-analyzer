"""
Тест 3: Эталонный безопасный код (проверка на отсутствие ложных срабатываний).
Ожидаемый результат:
- AST: 0 уязвимостей
- LLM: Низкий уровень риска, подтверждение корректности практик безопасности.
"""
import os
import json
import hmac
import hashlib
import sqlite3
import subprocess
from pathlib import Path


def get_api_secret() -> str:
    secret = os.getenv("APP_API_SECRET")
    if not secret:
        raise RuntimeError("Переменная окружения APP_API_SECRET не задана")
    return secret


def verify_webhook_signature(payload: bytes, signature: str, secret: str) -> bool:
    expected = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def ping_trusted_host(hostname: str) -> int:
    allowed_hosts = {"8.8.8.8", "1.1.1.1"}
    if hostname not in allowed_hosts:
        raise ValueError("Недопустимый хост")
    result = subprocess.run(["ping", "-c", "1", hostname], check=True, capture_output=True)
    return result.returncode


def get_user_by_id(db_path: str, user_id: int):
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, role FROM users WHERE id = ?", (user_id,))
        return cursor.fetchone()


def read_safe_report(base_dir: str, filename: str) -> str:
    base = Path(base_dir).resolve()
    target = (base / filename).resolve()
    if base not in target.parents:
        raise PermissionError("Попытка выхода за пределы рабочей директории")
    return target.read_text(encoding="utf-8")
