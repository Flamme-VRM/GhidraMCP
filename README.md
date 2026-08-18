# Ghidra MCP

**v3** — интеграция Ghidra с MCP (Model Context Protocol) для автоматизации реверс-инжиниринга через ИИ-агентов (opencode, Claude и др.).

## Архитектура

Сервис состоит из двух компонентов:

```
┌──────────────┐   stdio    ┌──────────────────┐   HTTP + Token   ┌──────────────┐
│  ИИ-агент    │ ─────────▶ │ mcp_server.py    │ ───────────────▶ │  Ghidra      │
│  (opencode)  │ ◀───────── │ (FastMCP, venv)  │ ◀─────────────── │  (порт 13337)│
└──────────────┘            └──────────────────┘                  └──────────────┘
```

1. **`ghidra_mcp_server.py`** — скрипт **PyGhidra** (`@runtime PyGhidra`), запускается внутри Ghidra (Script Manager). Поднимает HTTP-сервер на `127.0.0.1:13337` с токен-авторизацией (`X-MCP-Token`) и выполняет операции с текущей программой: декомпиляция, дизассемблирование, поиск функций/строк/XREF-ов/импортов, переименование, комментарии.

2. **`mcp_server.py`** — MCP-сервер (stdio) на базе `FastMCP`. Проксирует вызовы инструментов агента на HTTP-сервер Ghidra.

## Установка

### 1. Python-зависимости (для mcp_server.py)

```bash
python -m venv venv
venv\Scripts\activate          # Windows
pip install "mcp>=1.24,<2.0" httpx
```

> **Важно:** пакет `mcp` должен оставаться в ветке 1.x — в 2.x отсутствует модуль `mcp.server.fastmcp`. Не выполняй `pip install -U mcp` без ограничения версии.

### 2. PyGhidra

Скрипт Ghidra работает на рантайме **PyGhidra** (не Jython):

```bash
pip install pyghidra
# затем настрой в Ghidra: Edit → Preferences → PyGhidra → Install
```

Проверка: в Script Manager'е у скриптов PyGhidra должен быть бейдж PyGhidra.

### 3. Скрипт в Ghidra

1. Открой Ghidra с загруженной программой (CodeBrowser).
2. **Window → Script Manager** (или `Alt+9`).
3. **Manage Script Directories** → добавь папку проекта.
4. Выбери `ghidra_mcp_server.py` (рантайм PyGhidra) и нажми **Run** ▶.
5. В консоли Ghidra появится `[GhidraMCP] Server started on http://127.0.0.1:13337`.

Проверка: `GET http://127.0.0.1:13337/health` → `{"status": "ok", "program": "<имя>"}`.

### 4. Подключение к opencode

Добавь в `~/.config/opencode/opencode.json`:

```json
{
  "mcp": {
    "ghidra": {
      "type": "local",
      "command": [
        "C:\\path\\to\\GhidraMCP\\venv\\Scripts\\python.exe",
        "C:\\path\\to\\GhidraMCP\\mcp_server.py"
      ],
      "enabled": true
    }
  }
}
```

## Инструменты (v3)

### Чтение

| Инструмент | Аргументы | Назначение |
|---|---|---|
| `get_program_info` | — | Инфо: формат, архитектура, image base, кол-во функций |
| `list_functions` | `query`, `limit`, `offset` | Список функций, фильтр по подстроке |
| `get_function` | `name`, `address` | Метаданные + декомпилированный C-код |
| `get_current_function` | — | Декомпиляция функции под курсором |
| `get_disassembly` | `address`, `count` | Листинг ассемблера от адреса |
| `get_xrefs_to` | `address`, `limit` | Ссылки на адрес |
| `get_strings` | `filter_text`, `limit` | Строки программы |
| `get_imports` | `query`, `limit` | Импорты (внешние функции) |
| `get_memory_blocks` | — | Карта памяти |

### Запись

| Инструмент | Аргументы | Назначение |
|---|---|---|
| `rename_function` | `old_name`, `new_name` | Переименование функции |
| `rename_symbol` | `old_name`, `new_name`, `function_name` | Переименование символа (опц. в области функции) |
| `add_comment` | `address`, `comment`, `comment_type`, `append` | Комментарий PRE/POST/EOL/PLATE/REPEATABLE |

## Требования

- Ghidra 10.x+ с установленным PyGhidra
- Python 3.10+
- `mcp` 1.x + `httpx` в venv

## Ограничения

- Инструменты работают только с текущей открытой программой в Ghidra.
- `get_current_function` зависит от позиции курсора в GUI.
- Изменения применяются сразу и сохраняются в проект Ghidra (Ctrl+S).
- Токен `ghidra_secret_v3` захардкожен по умолчанию с обеих сторон.

## История версий

- **v3** — рантайм PyGhidra, токен-авторизация, 12 инструментов (`get_function`, `get_disassembly`, `get_memory_blocks` и др.)
- **v2** — Jython, 11 инструментов, `GET /health`
- **v1** — Jython, 3 инструмента (декомпиляция под курсором, переименование переменной, комментарий)