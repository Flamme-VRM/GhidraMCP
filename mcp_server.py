import os
import json
from typing import Optional

import httpx

from mcp.server.fastmcp import FastMCP


GHIDRA_URL = os.environ.get("GHIDRA_MCP_URL", "http://127.0.0.1:13337")
GHIDRA_TOKEN = os.environ.get("GHIDRA_MCP_TOKEN", "")

mcp = FastMCP("Ghidra v0.2")


def _headers():
    headers = {
        "Content-Type": "application/json",
    }
    if GHIDRA_TOKEN:
        headers["X-MCP-Token"] = GHIDRA_TOKEN
    return headers


async def ghidra_post(endpoint: str, payload: Optional[dict] = None) -> dict:
    url = GHIDRA_URL.rstrip("/") + endpoint

    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.post(
                url,
                json=payload or {},
                headers=_headers(),
            )

            try:
                return response.json()
            except Exception:
                return {
                    "error": f"HTTP {response.status_code}: {response.text[:1000]}"
                }
    except Exception as e:
        return {
            "error": str(e),
        }


def as_text(result: dict) -> str:
    if isinstance(result, dict) and "error" in result:
        return f"ERROR: {result['error']}"

    return json.dumps(result, indent=2, ensure_ascii=False)


@mcp.tool()
async def get_program_info() -> str:
    """
    Возвращает общую информацию о текущей программе в Ghidra:
    имя файла, архитектуру, компилятор, image base, memory blocks,
    количество функций.
    """
    result = await ghidra_post("/get_program_info")
    return as_text(result)


@mcp.tool()
async def list_functions(query: str = "", limit: int = 100, offset: int = 0) -> str:
    """
    Возвращает список функций из Ghidra.

    Args:
        query: Фильтр по подстроке имени функции.
        limit: Сколько функций вернуть.
        offset: Сколько функций пропустить.
    """
    result = await ghidra_post(
        "/list_functions",
        {
            "query": query,
            "limit": limit,
            "offset": offset,
        },
    )
    return as_text(result)


@mcp.tool()
async def get_function_by_name(name: str) -> str:
    """
    Ищет функцию по имени и возвращает её метаданные.

    Args:
        name: Имя функции или его часть.
    """
    result = await ghidra_post(
        "/get_function_by_name",
        {
            "name": name,
        },
    )
    return as_text(result)


@mcp.tool()
async def get_decompiled_function(name: str = "", address: str = "") -> str:
    """
    Возвращает декомпилированный C-код функции.

    Можно передать либо имя функции, либо адрес.
    Если ничего не передать, будет использована текущая функция в Ghidra.

    Args:
        name: Имя функции.
        address: Адрес функции в hex, например 0x00401000.
    """
    result = await ghidra_post(
        "/get_decompiled_function",
        {
            "name": name,
            "address": address,
        },
    )
    return as_text(result)


@mcp.tool()
async def get_current_function() -> str:
    """
    Возвращает декомпилированный C-код функции,
    которая сейчас выбрана в Ghidra.
    """
    result = await ghidra_post("/get_current_function")
    return as_text(result)


@mcp.tool()
async def get_xrefs_to(address: str, limit: int = 100) -> str:
    """
    Возвращает xrefs на указанный адрес.

    Args:
        address: Адрес в hex, например 0x00401000.
        limit: Максимальное количество xrefs.
    """
    result = await ghidra_post(
        "/get_xrefs_to",
        {
            "address": address,
            "limit": limit,
        },
    )
    return as_text(result)


@mcp.tool()
async def get_strings(filter_text: str = "", limit: int = 200) -> str:
    """
    Возвращает строки из программы.

    Args:
        filter_text: Фильтр по подстроке.
        limit: Максимальное количество строк.
    """
    result = await ghidra_post(
        "/get_strings",
        {
            "filter": filter_text,
            "limit": limit,
        },
    )
    return as_text(result)


@mcp.tool()
async def get_imports(query: str = "", limit: int = 200) -> str:
    """
    Возвращает импорты программы.

    Args:
        query: Фильтр по имени импорта или библиотеки.
        limit: Максимальное количество результатов.
    """
    result = await ghidra_post(
        "/get_imports",
        {
            "query": query,
            "limit": limit,
        },
    )
    return as_text(result)


@mcp.tool()
async def rename_function(old_name: str, new_name: str) -> str:
    """
    Переименовывает функцию в Ghidra.

    Args:
        old_name: Текущее имя функции.
        new_name: Новое имя функции.
    """
    result = await ghidra_post(
        "/rename_function",
        {
            "old_name": old_name,
            "new_name": new_name,
        },
    )
    return as_text(result)


@mcp.tool()
async def rename_symbol(function_name: str, old_name: str, new_name: str) -> str:
    """
    Переименовывает символ/переменную в Ghidra.

    Если function_name указан, поиск символа ограничивается этой функцией.

    Args:
        function_name: Имя функции, где находится символ. Может быть пустым.
        old_name: Текущее имя символа.
        new_name: Новое имя символа.
    """
    result = await ghidra_post(
        "/rename_symbol",
        {
            "function_name": function_name,
            "old_name": old_name,
            "new_name": new_name,
        },
    )
    return as_text(result)


@mcp.tool()
async def add_comment(
    address: str,
    comment: str,
    comment_type: str = "PRE",
    append: bool = False,
) -> str:
    """
    Добавляет комментарий к адресу в Ghidra.

    Args:
        address: Адрес в hex, например 0x00401000.
        comment: Текст комментария.
        comment_type: PRE, POST, EOL, PLATE или REPEATABLE.
        append: Если True, комментарий добавляется к существующему.
    """
    result = await ghidra_post(
        "/add_comment",
        {
            "address": address,
            "comment": comment,
            "comment_type": comment_type,
            "append": append,
        },
    )
    return as_text(result)


if __name__ == "__main__":
    mcp.run()