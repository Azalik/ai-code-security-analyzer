"""
Тест 2: Скрытые логические и контекстные уязвимости (AST находит 0 проблем, выявляет только LLM).
Содержит:
1. IDOR (Broken Access Control, CWE-639) — эндпоинт возвращает чужие платежные данные без проверки current_user_id.
2. SSRF (Server-Side Request Forgery, CWE-918) — запрос на произвольный URL от пользователя.
3. Path Traversal (CWE-22) — чтение произвольного файла по имени из запроса.
"""
import os
import sqlite3
import urllib.request


def get_invoice_details(current_user_id: int, invoice_id: int):
    conn = sqlite3.connect("billing.db")
    cursor = conn.cursor()
    # Запрос параметризован (SQLi нет), но отсутствует проверка: WHERE id = ? AND owner_id = ?
    cursor.execute("SELECT id, card_last4, amount, address FROM invoices WHERE id = ?", (invoice_id,))
    return cursor.fetchone()


def fetch_webhook_preview(user_provided_url: str) -> str:
    # Пользователь может передать http://169.254.169.254/latest/meta-data/ или http://127.0.0.1:8080/admin
    with urllib.request.urlopen(user_provided_url, timeout=5) as response:
        return response.read(2048).decode("utf-8", errors="replace")


def download_user_report(filename: str) -> str:
    # Пользователь может передать "../../.env" или "/etc/passwd"
    base_dir = "/var/app/reports"
    full_path = os.path.join(base_dir, filename)
    with open(full_path, "r", encoding="utf-8") as f:
        return f.read()
