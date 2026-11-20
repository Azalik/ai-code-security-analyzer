import os
import ast
import re
import json
import ssl
import hashlib
import urllib.request
import urllib.error
from datetime import datetime
import streamlit as st

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# --- КОНФИГУРАЦИЯ СТРАНИЦЫ ---
st.set_page_config(
    page_title="AI Code Security Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- CSS-ЗАЩИТА ОТ ПЕРЕПОЛНЕНИЯ КОНТЕЙНЕРОВ ---
st.markdown("""
<style>
    [data-testid="stVerticalBlockBorderWrapper"] {
        overflow-x: auto;
    }
    [data-testid="stMarkdownContainer"] table {
        width: 100%;
        display: block;
        overflow-x: auto;
    }
    [data-testid="stMarkdownContainer"] pre {
        overflow-x: auto;
    }
</style>
""", unsafe_allow_html=True)

# --- ПРИМЕРЫ УЯЗВИМОГО КОДА ДЛЯ БЫСТРОГО ТЕСТА И ДЕМОНСТРАЦИИ ---
CODE_SAMPLES = {
    "Свой код (пусто)": {
        "lang": "Python",
        "code": ""
    },
    "Python: RCE + Утечка токена + MD5": {
        "lang": "Python",
        "code": (
            "import os\n"
            "import hashlib\n"
            "import pickle\n\n"
            "API_SECRET_KEY = 'sk-live-9876543210secret'\n\n"
            "def run_diagnostics(user_host, raw_session):\n"
            "    # Уязвимость OS Command Injection\n"
            "    os.system('ping -c 1 ' + user_host)\n"
            "    # Небезопасная десериализация\n"
            "    session = pickle.loads(raw_session)\n"
            "    # Слабое хеширование\n"
            "    token_hash = hashlib.md5(API_SECRET_KEY.encode()).hexdigest()\n"
            "    return session, token_hash\n"
        )
    },
    "Python: SQL-инъекция через f-строку": {
        "lang": "Python",
        "code": (
            "import sqlite3\n\n"
            "def get_user_profile(user_id):\n"
            "    conn = sqlite3.connect('app.db')\n"
            "    cursor = conn.cursor()\n"
            "    # Уязвимость SQL Injection\n"
            "    query = f\"SELECT id, username, role FROM users WHERE id = '{user_id}'\"\n"
            "    cursor.execute(query)\n"
            "    return cursor.fetchone()\n"
        )
    },
    "SQL: Небезопасный динамический запрос": {
        "lang": "SQL",
        "code": (
            "-- Пример запроса с конкатенацией пользовательского ввода\n"
            "SELECT * FROM accounts WHERE login = '" + "' + user_input + '" + "' AND active = 1;\n"
            "-- Тестовый пейлоад злоумышленника:\n"
            "SELECT * FROM accounts WHERE login = 'admin' OR 1=1 --' AND active = 1;\n"
        )
    }
}


# --- УНИВЕРСАЛЬНЫЙ HTTP-КЛИЕНТ БЕЗ ЗАВИСИМОСТИ ОТ ПРОКСИ WINDOWS ---
def clean_api_url(raw_url):
    url = raw_url.strip().lstrip("[")
    if "](" in url:
        url = url.split("](")[1].replace(")", "")
    return url.rstrip("]")


def send_http_json(url, api_key, payload=None, skip_ssl_verify=False, timeout=30):
    clean_key = api_key.strip()
    if not clean_key.isascii():
        return None, "В API-ключе есть русские буквы или недопустимые символы (например, точки ••••). Нажмите на глаз 👁️ и вставьте чистый ключ."

    safe_url = clean_api_url(url)
    headers = {
        "Authorization": f"Bearer {clean_key}",
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    }
    data_bytes = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(safe_url, data=data_bytes, headers=headers, method="POST" if payload else "GET")

    handlers = [urllib.request.ProxyHandler({})]
    if skip_ssl_verify and safe_url.startswith("https://"):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=ctx))

    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8")), None
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")
        return None, f"HTTP {e.code}: {err_body}"
    except Exception as e:
        return None, f"{e} (URL: {safe_url})"


# --- АВТОЗАГРУЗКА ДОСТУПНЫХ МОДЕЛЕЙ ИЗ API (С ИЗОЛИРОВАННЫМ КЭШЕМ СЕССИИ) ---
def fetch_available_models(provider_name, api_key, base_url, skip_ssl_verify):
    if not api_key or not api_key.strip():
        return [], "Введите API-ключ для загрузки списка моделей."

    if "models_cache" not in st.session_state:
        st.session_state["models_cache"] = {}

    key_hash = hashlib.sha256(api_key.strip().encode("utf-8")).hexdigest()[:16]
    cache_id = f"{provider_name}|{base_url.strip()}|{key_hash}|{skip_ssl_verify}"

    if cache_id in st.session_state["models_cache"]:
        return st.session_state["models_cache"][cache_id]

    root_url = base_url.strip().rstrip("/")
    target_url = f"{root_url}/models"

    data, err = send_http_json(target_url, api_key, payload=None, skip_ssl_verify=skip_ssl_verify, timeout=15)
    if err:
        return [], err

    raw_ids = [m["id"] for m in data.get("data", []) if "id" in m]

    excluded_keywords = ('whisper', 'tts', 'orpheus', 'guard', 'embed', 'moderation', 'dall-e', 'allam')
    text_models = [
        m_id for m_id in raw_ids
        if not any(bad in m_id.lower() for bad in excluded_keywords)
    ]

    if provider_name == "OpenRouter (Бесплатно)":
        free_models = [m_id for m_id in text_models if ":free" in m_id]
        if free_models:
            text_models = free_models

    def model_priority(name):
        n = name.lower()
        if "120b" in n or "70b" in n:
            return (0, n)
        if "qwen" in n or "coder" in n or "deepseek" in n or "gpt-4" in n:
            return (1, n)
        return (2, n)

    text_models.sort(key=model_priority)
    result = (text_models, None)
    st.session_state["models_cache"][cache_id] = result
    return result


# --- ДВИЖОК 1: СТАТИЧЕСКИЙ AST-АНАЛИЗАТОР (PYTHON) ---
def analyze_python_ast(source_code):
    findings = []
    try:
        tree = ast.parse(source_code)
    except SyntaxError as e:
        return [{
            "line": e.lineno or 1,
            "severity": "Ошибка синтаксиса",
            "title": "SyntaxError в коде Python",
            "desc": f"Не удалось построить AST-дерево: {e.msg}. Проверьте скобки, отступы или выбранный язык."
        }]

    sensitive_vars = {
        'password', 'passwd', 'pwd', 'secret',
        'api_key', 'apikey', 'token', 'auth_token', 'private_key'
    }

    for node in ast.walk(tree):
        # 1. Проверка вызовов функций и методов
        if isinstance(node, ast.Call):
            line = getattr(node, 'lineno', '?')

            # Прямые вызовы: eval(), exec()
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
                if func_name in ['eval', 'exec']:
                    findings.append({
                        "line": line,
                        "severity": "Критическая",
                        "title": f"Вызов опасной функции {func_name}()",
                        "desc": "Динамическое исполнение строк позволяет выполнить произвольный код (CWE-95 / RCE)."
                    })

            # Вызовы методов модулей: os.system(), pickle.loads() и т.д.
            elif isinstance(node.func, ast.Attribute):
                attr_name = node.func.attr

                if isinstance(node.func.value, ast.Name):
                    mod_name = node.func.value.id

                    if mod_name == 'os' and attr_name in ['system', 'popen', 'execl', 'execle', 'execlp', 'execv', 'execve']:
                        findings.append({
                            "line": line,
                            "severity": "Критическая",
                            "title": f"OS Command Injection: os.{attr_name}()",
                            "desc": "Прямой вызов системной оболочки. При попадании пользовательских данных ведет к захвату сервера (CWE-78)."
                        })

                    elif mod_name == 'subprocess':
                        has_shell_true = any(
                            kw.arg == 'shell' and isinstance(kw.value, ast.Constant) and kw.value.value is True
                            for kw in node.keywords
                        )
                        if has_shell_true:
                            findings.append({
                                "line": line,
                                "severity": "Высокая",
                                "title": f"subprocess.{attr_name}() с параметром shell=True",
                                "desc": "Использование shell=True делает вызов уязвимым к инъекции команд (CWE-78)."
                            })
                        else:
                            findings.append({
                                "line": line,
                                "severity": "Средняя",
                                "title": f"Использование модуля subprocess.{attr_name}()",
                                "desc": "Убедитесь, что аргументы передаются списком, а не формируются из непроверенного ввода."
                            })

                    elif mod_name == 'pickle' and attr_name in ['loads', 'load']:
                        findings.append({
                            "line": line,
                            "severity": "Критическая",
                            "title": f"Небезопасная десериализация: pickle.{attr_name}()",
                            "desc": "Десериализация недоверенных данных через pickle ведет к удаленному выполнению кода (CWE-502)."
                        })

                    elif mod_name == 'yaml' and attr_name == 'load':
                        has_safe_loader = any(
                            kw.arg == 'Loader' and isinstance(kw.value, ast.Attribute) and kw.value.attr == 'SafeLoader'
                            for kw in node.keywords
                        )
                        if not has_safe_loader:
                            findings.append({
                                "line": line,
                                "severity": "Высокая",
                                "title": "Небезопасный вызов yaml.load()",
                                "desc": "Используйте yaml.safe_load() вместо стандартного load() для защиты от выполнения кода (CWE-502)."
                            })

                    elif mod_name == 'hashlib' and attr_name in ['md5', 'sha1']:
                        findings.append({
                            "line": line,
                            "severity": "Средняя",
                            "title": f"Слабый криптографический алгоритм: {attr_name.upper()}",
                            "desc": "Алгоритм подвержен коллизиям. Для паролей используйте bcrypt/Argon2, для хешей — SHA-256 (CWE-327)."
                        })

                # Проверка cursor.execute(f"...")
                if attr_name in ['execute', 'executemany'] and node.args:
                    first_arg = node.args[0]
                    if isinstance(first_arg, ast.JoinedStr):
                        findings.append({
                            "line": line,
                            "severity": "Критическая",
                            "title": "Потенциальная SQL-инъекция (f-строка в execute)",
                            "desc": "Формирование SQL-запроса через f-строку. Используйте параметризованные запросы (?, %s) (CWE-89)."
                        })

        # 2. Поиск захардкоженных секретов в переменных
        elif isinstance(node, ast.Assign):
            line = getattr(node, 'lineno', '?')
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str) and len(node.value.value.strip()) > 0:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        var_name = target.id.lower()
                        if any(key in var_name for key in sensitive_vars):
                            findings.append({
                                "line": line,
                                "severity": "Высокая",
                                "title": f"Утечка секрета в коде (переменная '{target.id}')",
                                "desc": "Ключи и пароли не должны храниться в исходном коде. Перенесите их в переменные окружения (.env) (CWE-798)."
                            })

    return findings


# --- ДВИЖОК 2: СИГНАТУРНЫЙ АНАЛИЗАТОР (SQL) ---
def analyze_sql_static(source_code):
    findings = []
    lines = source_code.splitlines()

    patterns = [
        (r"(\+\s*[a-zA-Z_][a-zA-Z0-9_]*|[a-zA-Z_][a-zA-Z0-9_]*\s*\+)", "Критическая", "Конкатенация строк в SQL-запросе", "Обнаружено склеивание строк через '+', что указывает на риск SQL-инъекции (CWE-89)."),
        (r"(?i)\bOR\s+1\s*=\s*1\b", "Критическая", "Признак SQL-инъекции (OR 1=1)", "Обнаружена классическая тавтология для обхода аутентификации или фильтрации."),
        (r"(?i)\bUNION\s+ALL\s+SELECT\b|\bUNION\s+SELECT\b", "Высокая", "Использование UNION SELECT", "Проверьте, не является ли конструкция вектором извлечения данных из соседних таблиц."),
        (r"(?i)\bDROP\s+TABLE\b|\bTRUNCATE\s+TABLE\b", "Высокая", "Деструктивная DDL-команда (DROP/TRUNCATE)", "Операция полного удаления таблицы/данных. Убедитесь в наличии строгих прав доступа.")
    ]

    for idx, line_text in enumerate(lines, start=1):
        for regex, sev, title, desc in patterns:
            if re.search(regex, line_text):
                findings.append({
                    "line": idx,
                    "severity": sev,
                    "title": title,
                    "desc": desc
                })

    return findings


# --- ДВИЖОК 3: ГЕНЕРАТИВНЫЙ ИИ-АУДИТ (LLM) ---
def get_ai_security_review(source_code, language, static_findings, api_key, model, base_url, skip_ssl_verify=False):
    if not api_key or not api_key.strip() or not model:
        return "⚠️ **Модель или API-ключ не выбраны.** Глубокий ИИ-аудит пропущен — показаны только результаты локального статического анализатора.", ""

    if static_findings:
        static_summary = "\n".join(
            f"- [Строка {item['line']}] ({item['severity']}) {item['title']}: {item['desc']}"
            for item in static_findings
        )
    else:
        static_summary = "Локальный статический анализатор не выявил базовых сигнатурных уязвимостей."

    prompt_template = """Ты ведущий эксперт по безопасной разработке (AppSec) и аудиту кода.
Проведи аудит безопасности следующего кода на языке {lang} по стандартам OWASP Top 10 и CWE.

Результаты предварительного статического анализа:
{static_info}

Анализируемый код:
{code}

Сформируй отчет строго по следующей структуре:
1. **Итоговый уровень риска**: (Низкий / Средний / Высокий / Критический) и краткое обоснование в 1-2 предложения.
2. **Разбор уязвимостей**: маркированным списком подтверди каждую находку статического анализатора (строка, CWE, суть) и опиши скрытые логические уязвимости, если они есть. НЕ используй Markdown-таблицы.
3. **Рекомендации по исправлению**: краткий список внесенных изменений.

В самом конце ответа приведи полностью исправленный, рабочий и безопасный вариант кода внутри ОДНОГО блока ```{lang_lower} ... ``` без дополнительного текста после него."""

    prompt = prompt_template.format(
        lang=language,
        lang_lower=language.lower(),
        static_info=static_summary,
        code=source_code
    )

    chat_url = f"{base_url.strip().rstrip('/')}/chat/completions"
    payload = {
        "model": model.strip(),
        "messages": [
            {"role": "system", "content": "Ты старший AppSec-инженер. Пиши лаконично, без повторов и без таблиц. Исправленный код всегда оборачивай в единый блок ```."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.15
    }

    resp_json, err = send_http_json(chat_url, api_key, payload=payload, skip_ssl_verify=skip_ssl_verify, timeout=60)
    if err:
        return f"❌ **Ошибка при обращении к LLM:**\n\n`{err}`", ""

    try:
        raw_text = resp_json["choices"][0]["message"]["content"] or ""
    except (KeyError, IndexError):
        return f"❌ **Неожиданный формат ответа от API:** `{resp_json}`", ""

    # Берем последний блок кода ```...``` как финальный патч
    code_matches = list(re.finditer(r"```[a-zA-Z0-9_-]*\s*\n(.*?)```", raw_text, re.DOTALL))
    if code_matches:
        last_match = code_matches[-1]
        patched_code = last_match.group(1).strip()
        audit_text = (raw_text[:last_match.start()] + "\n" + raw_text[last_match.end():]).strip()
        audit_text = re.sub(r"(#+\s*|\*\*)?(Исправленный|Безопасный).*?:\s*$", "", audit_text, flags=re.IGNORECASE).strip()
    else:
        audit_text = raw_text.strip()
        patched_code = ""

    return audit_text, patched_code


# --- БОКОВАЯ ПАНЕЛЬ (НАСТРОЙКИ) ---
with st.sidebar:
    st.header("⚙️ Настройки анализатора")

    language = st.selectbox(
        "Язык исходного кода:",
        ["Python", "SQL"],
        help="Для Python используется AST-парсер, для SQL — сигнатурный анализатор."
    )

    st.markdown("---")
    provider = st.radio(
        "Провайдер ИИ (LLM):",
        [
            "Groq (Бесплатно)",
            "OpenRouter (Бесплатно)",
            "Локальная Ollama",
            "OpenAI API"
        ],
        help="Список доступных моделей подтягивается автоматически после ввода ключа (или из .env)."
    )

    if provider == "Groq (Бесплатно)":
        user_credential = st.text_input(
            "Groq API Key:",
            value=os.getenv("GROQ_API_KEY", ""),
            type="password",
            placeholder="gsk_...",
            help="Бесплатный ключ создается на console.groq.com/keys"
        )
        base_url = "https" + "://api.groq.com/openai/v1"
        fallback_models = ["openai/gpt-oss-120b", "openai/gpt-oss-20b"]

    elif provider == "OpenRouter (Бесплатно)":
        user_credential = st.text_input(
            "OpenRouter API Key:",
            value=os.getenv("OPENROUTER_API_KEY", ""),
            type="password",
            placeholder="sk-or-v1-...",
            help="Бесплатный ключ создается на openrouter.ai/keys"
        )
        base_url = "https" + "://openrouter.ai/api/v1"
        fallback_models = ["openrouter/free", "qwen/qwen3-coder:free"]

    elif provider == "Локальная Ollama":
        user_credential = "ollama"
        base_url = st.text_input("Адрес сервера Ollama:", value="http" + "://localhost:11434/v1")
        fallback_models = ["qwen2.5-coder:7b", "deepseek-coder"]

    else:
        user_credential = st.text_input(
            "OpenAI API Key:",
            value=os.getenv("OPENAI_API_KEY", ""),
            type="password",
            placeholder="sk-...",
            help="Ключ используется только в рамках текущей сессии."
        )
        base_url = "https" + "://api.openai.com/v1"
        fallback_models = ["gpt-4o-mini", "gpt-4o"]

    skip_ssl = st.checkbox(
        "Отключить строгую проверку SSL",
        value=False,
        help="Включите, если антивирус (например, Kaspersky) проверяет HTTPS-трафик и блокирует сертификаты."
    )

    # Динамическая загрузка списка моделей
    col_m1, col_m2 = st.columns([4, 1])
    with col_m2:
        if st.button("🔄", help="Обновить список моделей из API"):
            st.session_state["models_cache"] = {}

    loaded_models, fetch_err = fetch_available_models(provider, user_credential, base_url, skip_ssl)

    with col_m1:
        if loaded_models:
            st.caption(f"✅ Загружено моделей: {len(loaded_models)}")
            options = loaded_models + ["Ввести ID модели вручную..."]
            selected_opt = st.selectbox("Выберите модель:", options, label_visibility="collapsed")
        else:
            if user_credential and provider != "Локальная Ollama":
                st.caption("⚠️ Выбран резерв (не удалось загрузить список):")
            elif provider == "Локальная Ollama":
                st.caption("⚠️ Ollama не запущена (указан резерв):")
            else:
                st.caption("Введите ключ для загрузки моделей:")
            options = fallback_models + ["Ввести ID модели вручную..."]
            selected_opt = st.selectbox("Резервный список:", options, label_visibility="collapsed")

    if selected_opt == "Ввести ID модели вручную...":
        model_choice = st.text_input("ID модели:", value=fallback_models[0])
    else:
        model_choice = selected_opt

    if fetch_err and user_credential and provider != "Локальная Ollama":
        with st.expander("Детали подключения к API"):
            st.error(fetch_err)

    st.markdown("---")
    st.markdown("### 🛡️ О проекте")
    st.info(
        "Гибридный SAST + LLM анализатор кода.\n\n"
        "1. **AST / Regex** мгновенно находит опасные конструкции и точные номера строк.\n"
        "2. **LLM** проверяет контекст, отсеивает ложные срабатывания и генерирует безопасный патч."
    )


# --- ОСНОВНОЙ ЭКРАН ---
st.title("🛡️ Умный анализатор безопасности кода")
st.caption("Гибридный аудит уязвимостей на базе абстрактных синтаксических деревьев (AST) и генеративного ИИ")

# Панель выбора пресета и загрузки файла
top_col1, top_col2 = st.columns([1.2, 1])

with top_col1:
    selected_sample = st.selectbox(
        "🧪 Загрузить тестовый пример уязвимости:",
        list(CODE_SAMPLES.keys())
    )

with top_col2:
    uploaded_file = st.file_uploader(
        "📂 Или загрузите файл с кодом (.py / .sql):",
        type=["py", "sql"]
    )

# Определение начального текста в редакторе
if uploaded_file is not None:
    initial_code = uploaded_file.read().decode("utf-8", errors="replace")
    if uploaded_file.name.endswith(".sql"):
        language = "SQL"
else:
    initial_code = CODE_SAMPLES[selected_sample]["code"]
    if selected_sample != "Свой код (пусто)":
        language = CODE_SAMPLES[selected_sample]["lang"]

code_input = st.text_area(
    f"Исходный код ({language}):",
    value=initial_code,
    height=230,
    placeholder="Вставьте сюда исходный код для проверки на уязвимости..."
)

run_btn = st.button("🚀 Запустить полный аудит безопасности", type="primary", use_container_width=True)

# --- ОБРАБОТКА И ВЫВОД РЕЗУЛЬТАТОВ ---
if run_btn:
    if not code_input.strip():
        st.warning("⚠️ Поле с кодом пустое. Введите код, выберите тестовый пример или загрузите файл.")
    else:
        # 1. Запуск статического анализа
        if language == "Python":
            static_results = analyze_python_ast(code_input)
        else:
            static_results = analyze_sql_static(code_input)

        # 2. Запуск ИИ-аудита
        with st.spinner(f"Выполняется статический разбор и ИИ-аудит ({provider} / {model_choice})..."):
            ai_audit_text, ai_patched_code = get_ai_security_review(
                code_input, language, static_results, user_credential, model_choice, base_url, skip_ssl
            )

        st.markdown("---")

        # Верхняя панель метрик
        m1, m2, m3 = st.columns(3)
        lines_count = len(code_input.splitlines())
        issues_count = len(static_results)
        critical_count = sum(1 for i in static_results if i["severity"] == "Критическая")

        m1.metric("Строк кода проверено", lines_count)
        m2.metric("Находок статического анализа", issues_count, delta=f"{critical_count} крит." if critical_count else "0 крит.", delta_color="inverse")
        m3.metric("Статус ИИ-аудита", f"Готово ({model_choice})" if user_credential else "Пропущен (нет ключа)")

        st.markdown("### 📊 Результаты проверки")

        # Две колонки: слева статический анализ, справа ИИ
        res_col1, res_col2 = st.columns([1, 1.45], gap="medium")

        with res_col1:
            st.subheader(f"🔍 Статический анализ ({'AST' if language == 'Python' else 'Regex'})")
            if static_results:
                for item in static_results:
                    badge = "🔴" if item["severity"] == "Критическая" else ("🟠" if item["severity"] == "Высокая" else "🟡")
                    with st.container(border=True):
                        st.markdown(f"**{badge} [Строка {item['line']}] {item['title']}**")
                        st.caption(f"Критичность: {item['severity']}")
                        st.write(item["desc"])
            else:
                st.success("✅ Базовых уязвимостей по сигнатурам не обнаружено. Проверьте отчет ИИ на наличие скрытых логических багов.")

        with res_col2:
            st.subheader("🤖 Контекстный аудит и безопасный патч (LLM)")
            tab_audit, tab_patch = st.tabs(["📋 Выводы и разбор", "🛠️ Безопасный код (Патч)"])

            with tab_audit:
                with st.container(border=True):
                    st.markdown(ai_audit_text)

            with tab_patch:
                if ai_patched_code:
                    st.code(ai_patched_code, language=language.lower())
                else:
                    st.info("Модель не вернула отдельный блок кода. Проверьте вкладку «Выводы и разбор».")

        # Вкладка с исходником
        with st.expander("📄 Посмотреть проанализированный исходный код"):
            st.code(code_input, language=language.lower())

        # Генерация итогового Markdown-отчета для скачивания
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
        md_report = "# Отчет об аудите безопасности кода\n\n"
        md_report += f"- **Дата проверки:** {timestamp}\n"
        md_report += f"- **Язык:** {language}\n"
        md_report += f"- **Провайдер / Модель:** {provider} / {model_choice if user_credential else 'Не использовалась'}\n\n"
        md_report += "## 1. Результаты статического анализа\n\n"
        if static_results:
            for item in static_results:
                md_report += f"- **[Строка {item['line']}] ({item['severity']}) {item['title']}**: {item['desc']}\n"
        else:
            md_report += "- Базовых сигнатурных уязвимостей не обнаружено.\n"

        md_report += f"\n## 2. ИИ-аудит и разбор уязвимостей\n\n{ai_audit_text}\n"
        if ai_patched_code:
            md_report += f"\n## 3. Исправленный безопасный код\n\n```{language.lower()}\n{ai_patched_code}\n```\n"

        st.download_button(
            label="📥 Скачать полный отчет об аудите (.md)",
            data=md_report,
            file_name=f"security_audit_{datetime.now().strftime('%Y%m%d_%H%M')}.md",
            mime="text/markdown",
            use_container_width=True
        )