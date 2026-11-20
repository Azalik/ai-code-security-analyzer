-- Тест 4: Уязвимый SQL-скрипт для демонстрации сигнатурного анализатора + LLM

-- 1. Динамическая конкатенация пользовательского ввода (CWE-89)
SELECT id, email, balance FROM users WHERE username = '" + user_login + "' AND status = 'active';

-- 2. Классический вектор обхода аутентификации (OR 1=1)
SELECT * FROM sessions WHERE token = '' OR 1=1 --';

-- 3. Извлечение конфиденциальных данных через UNION SELECT
SELECT title, body FROM news WHERE id = 10 UNION SELECT username, password_hash FROM admin_users;

-- 4. Неконтролируемая деструктивная DDL-операция
DROP TABLE audit_logs;
