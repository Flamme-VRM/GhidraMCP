# Ghidra MCP

**v0.1** — интеграция Ghidra с MCP (Model Context Protocol) для автоматизации реверс-инжиниринга через ИИ-агентов (opencode, Claude и др.).

## Архитектура

Сервис состоит из двух компонентов:

```
┌──────────────┐   stdio    ┌──────────────────┐   HTTP    ┌──────────────┐
│  ИИ-агент    │ ─────────▶ │ mcp_server.py    │ ────────▶ │  Ghidra      │
│  (opencode)  │ ◀───────── │ (FastMCP, venv)  │ ◀──────── │  (порт 13337)│
└──────────────┘            └──────────────────┘           └──────────────┘
```

1. **`ghidra_mcp_server.py`** — Jython-скрипт, запускается внутри Ghidra (Script Manager). Поднимает HTTP-сервер на `127.0.0.1:13337` и выполняет операции с текущей программой: декомпиляция, переименование, комментарии.

2. **`mcp_server.py`** — MCP-сервер (stdio) на базе `FastMCP`. Проксирует вызовы инструментов агента на HTTP-сервер Ghidra.

## Установка

### 1. Python-зависимости (для mcp_server.py)

```bash
python -m venv venv
venv\Scripts\activate          # Windows
pip install fastmcp httpx
```

### 2. Скрипт в Ghidra

1. Открой Ghidra с загруженной программой (CodeBrowser).
2. **Window → Script Manager** (или `Alt+9`).
3. **Manage Script Directories** → добавь папку проекта.
4. Выбери `ghidra_mcp_server.py` и нажми **Run** ▶.
5. В консоли Ghidra появится `[GhidraMCP] Server started on port 13337`.

### 3. Подключение к opencode

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

## Инструменты (v0.1)

| Инструмент | Аргументы | Назначение |
|---|---|---|
| `get_current_function` | — | Декомпилированный C-код функции под курсором в Ghidra |
| `rename_variable` | `func_name`, `old_name`, `new_name` | Переименование переменной (`param_1` → осмысленное имя) |
| `add_comment` | `address`, `comment` | Добавление PRE-комментария по hex-адресу (`0x0040105a`) |

## Требования

- Ghidra 10.x+ (Jython-скрипт)
- Python 3.10+
- `fastmcp` + `httpx` в venv

## Ограничения

- Инструменты работают только с текущей открытой программой в Ghidra.
- `get_current_function` зависит от позиции курсора в GUI.
- Изменения применяются сразу и сохраняются в проект Ghidra (Ctrl+S).

## Планы

- Декомпиляция по имени/адресу функции
- Поиск функций, строк, XREF-ов
- Переименование функций и задание сигнатур