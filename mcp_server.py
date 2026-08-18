"""
Ghidra MCP Server v3 — MCP side
Python 3, Ghidra 12.1.2, PyGhidra

Requires: pip install -U mcp httpx
"""
import os
import json
from dataclasses import dataclass
from typing import Optional

import httpx
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations

# ==================== CONFIG ====================

GHIDRA_URL = os.environ.get("GHIDRA_MCP_URL", "http://127.0.0.1:13337")
GHIDRA_TOKEN = os.environ.get("GHIDRA_MCP_TOKEN", "ghidra_secret_v3")

# ==================== MCP SERVER ====================

mcp = FastMCP(
    name="Ghidra v3",
    mask_error_details=True,  # Скрываем внутренние ошибки от клиента
)

# ==================== HTTP CLIENT ====================


async def ghidra_post(endpoint: str, payload: Optional[dict] = None) -> dict:
    """Отправляет POST-запрос к Ghidra HTTP-серверу."""
    url = GHIDRA_URL.rstrip("/") + endpoint
    headers = {"X-MCP-Token": GHIDRA_TOKEN}

    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(url, json=payload or {}, headers=headers)

            if resp.status_code == 401:
                raise ToolError("Unauthorized: invalid GHIDRA_MCP_TOKEN")

            if resp.status_code == 404:
                raise ToolError(f"Endpoint not found: {endpoint}")

            data = resp.json()

            if isinstance(data, dict) and "error" in data:
                raise ToolError(data["error"])

            return data

    except httpx.ConnectError:
        raise ToolError(
            f"Cannot connect to Ghidra at {GHIDRA_URL}. "
            "Make sure the Ghidra MCP script is running."
        )
    except httpx.TimeoutException:
        raise ToolError("Ghidra server timed out (120s)")
    except ToolError:
        raise
    except Exception as e:
        raise ToolError(f"Unexpected error: {e}")


# ==================== DATA MODELS ====================


@dataclass
class FunctionInfo:
    """Метаданные функции."""
    name: str
    address: str
    signature: str
    calling_convention: str
    parameter_count: int
    parameters: list[str]
    c_code: Optional[str]


@dataclass
class ProgramInfo:
    """Информация о программе."""
    name: str
    path: str
    format: str
    language: Optional[str]
    compiler: Optional[str]
    image_base: str
    function_count: int
    memory_blocks: list[dict]


@dataclass
class XrefInfo:
    """Перекрёстная ссылка."""
    from_address: str
    ref_type: str


@dataclass
class StringInfo:
    """Строка в бинарнике."""
    address: str
    string: str


@dataclass
class ImportInfo:
    """Импортированная функция."""
    name: str
    library: str
    address: Optional[str]


@dataclass
class MemoryBlock:
    """Блок памяти."""
    name: str
    start: str
    end: str
    size: int
    read: bool
    write: bool
    execute: bool


@dataclass
class MutationResult:
    """Результат мутирующей операции."""
    status: str
    message: str


# ==================== READ-ONLY TOOLS ====================


@mcp.tool(
    annotations=ToolAnnotations(
        title="Get Program Info",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    )
)
async def get_program_info() -> ProgramInfo:
    """Returns program metadata: name, format, architecture, image base, memory blocks, function count."""
    data = await ghidra_post("/get_program_info")

    blocks = [
        MemoryBlock(
            name=b.get("name", ""),
            start=b.get("start", ""),
            end=b.get("end", ""),
            size=b.get("size", 0),
            read=b.get("read", False),
            write=b.get("write", False),
            execute=b.get("execute", False),
        )
        for b in data.get("memory_blocks", [])
    ]

    return ProgramInfo(
        name=data.get("name", ""),
        path=data.get("path", ""),
        format=data.get("format", ""),
        language=data.get("language"),
        compiler=data.get("compiler"),
        image_base=data.get("image_base", ""),
        function_count=data.get("function_count", 0),
        memory_blocks=[vars(b) for b in blocks],
    )


@mcp.tool(
    annotations=ToolAnnotations(
        title="List Functions",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    )
)
async def list_functions(
    query: str = "",
    limit: int = 100,
    offset: int = 0,
) -> dict:
    """Lists functions in the program with optional name filter.

    Args:
        query: Substring filter for function names (case-insensitive).
        limit: Maximum number of results (default 100, max 500).
        offset: Number of results to skip.
    """
    limit = max(1, min(limit, 500))
    offset = max(0, offset)

    data = await ghidra_post("/list_functions", {
        "query": query,
        "limit": limit,
        "offset": offset,
    })
    return data


@mcp.tool(
    annotations=ToolAnnotations(
        title="Get Function",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    )
)
async def get_function(
    name: str = "",
    address: str = "",
) -> FunctionInfo:
    """Gets function metadata and decompiled C code by name or address.

    Args:
        name: Function name (e.g. 'main', 'FUN_00401000').
        address: Function address in hex (e.g. '0x00401000').
    """
    if not name and not address:
        raise ToolError("Provide either 'name' or 'address'")

    data = await ghidra_post("/get_function", {
        "name": name,
        "address": address,
    })

    return FunctionInfo(
        name=data.get("name", ""),
        address=data.get("address", ""),
        signature=data.get("signature", ""),
        calling_convention=data.get("calling_convention", ""),
        parameter_count=data.get("parameter_count", 0),
        parameters=data.get("parameters", []),
        c_code=data.get("c_code"),
    )


@mcp.tool(
    annotations=ToolAnnotations(
        title="Get Current Function",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    )
)
async def get_current_function() -> FunctionInfo:
    """Gets the decompiled C code of the function currently selected in Ghidra's GUI."""
    data = await ghidra_post("/get_current_function")

    return FunctionInfo(
        name=data.get("name", ""),
        address=data.get("address", ""),
        signature="",
        calling_convention="",
        parameter_count=0,
        parameters=[],
        c_code=data.get("c_code"),
    )


@mcp.tool(
    annotations=ToolAnnotations(
        title="Get Disassembly",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    )
)
async def get_disassembly(
    address: str,
    count: int = 20,
) -> dict:
    """Gets disassembly listing starting from an address.

    Args:
        address: Start address in hex (e.g. '0x00401000').
        count: Number of instructions to return (max 100).
    """
    count = max(1, min(count, 100))

    data = await ghidra_post("/get_disassembly", {
        "address": address,
        "count": count,
    })
    return data


@mcp.tool(
    annotations=ToolAnnotations(
        title="Get Xrefs To",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    )
)
async def get_xrefs_to(
    address: str,
    limit: int = 100,
) -> dict:
    """Gets cross-references TO an address (who calls/references it).

    Args:
        address: Target address in hex (e.g. '0x00401000').
        limit: Maximum number of xrefs to return.
    """
    limit = max(1, min(limit, 500))

    data = await ghidra_post("/get_xrefs_to", {
        "address": address,
        "limit": limit,
    })
    return data


@mcp.tool(
    annotations=ToolAnnotations(
        title="Get Strings",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    )
)
async def get_strings(
    filter_text: str = "",
    limit: int = 200,
) -> dict:
    """Gets defined strings from the program.

    Args:
        filter_text: Filter strings containing this substring (case-insensitive).
        limit: Maximum number of strings to return.
    """
    limit = max(1, min(limit, 1000))

    data = await ghidra_post("/get_strings", {
        "filter": filter_text,
        "limit": limit,
    })
    return data


@mcp.tool(
    annotations=ToolAnnotations(
        title="Get Imports",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    )
)
async def get_imports(
    query: str = "",
    limit: int = 200,
) -> dict:
    """Gets imported external functions (API calls).

    Args:
        query: Filter by function name or library name.
        limit: Maximum number of imports to return.
    """
    limit = max(1, min(limit, 1000))

    data = await ghidra_post("/get_imports", {
        "query": query,
        "limit": limit,
    })
    return data


@mcp.tool(
    annotations=ToolAnnotations(
        title="Get Memory Blocks",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    )
)
async def get_memory_blocks() -> dict:
    """Returns memory block layout: segments, permissions, sizes."""
    data = await ghidra_post("/get_memory_blocks")
    return data


# ==================== MUTATING TOOLS ====================


@mcp.tool(
    annotations=ToolAnnotations(
        title="Rename Function",
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=False,
        openWorldHint=False,
    )
)
async def rename_function(
    old_name: str,
    new_name: str,
) -> MutationResult:
    """Renames a function in Ghidra's database.

    Args:
        old_name: Current function name (e.g. 'FUN_00401000').
        new_name: New meaningful name (e.g. 'decrypt_password').
    """
    if not old_name or not new_name:
        raise ToolError("Both 'old_name' and 'new_name' are required")

    data = await ghidra_post("/rename_function", {
        "old_name": old_name,
        "new_name": new_name,
    })

    return MutationResult(
        status=data.get("status", "unknown"),
        message=f"Function renamed to '{new_name}'",
    )


@mcp.tool(
    annotations=ToolAnnotations(
        title="Rename Symbol",
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=False,
        openWorldHint=False,
    )
)
async def rename_symbol(
    old_name: str,
    new_name: str,
    function_name: str = "",
) -> MutationResult:
    """Renames a symbol/variable in Ghidra. Optionally scoped to a specific function.

    Args:
        old_name: Current symbol name (e.g. 'param_1', 'local_10').
        new_name: New meaningful name (e.g. 'user_buffer').
        function_name: Optional function to scope the search.
    """
    if not old_name or not new_name:
        raise ToolError("Both 'old_name' and 'new_name' are required")

    data = await ghidra_post("/rename_symbol", {
        "old_name": old_name,
        "new_name": new_name,
        "function_name": function_name,
    })

    return MutationResult(
        status=data.get("status", "unknown"),
        message=f"Symbol '{old_name}' renamed to '{new_name}'",
    )


@mcp.tool(
    annotations=ToolAnnotations(
        title="Add Comment",
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    )
)
async def add_comment(
    address: str,
    comment: str,
    comment_type: str = "PRE",
    append: bool = False,
) -> MutationResult:
    """Adds a comment at an address in Ghidra.

    Args:
        address: Address in hex (e.g. '0x00401000').
        comment: Comment text.
        comment_type: PRE, POST, EOL, PLATE, or REPEATABLE.
        append: If True, appends to existing comment instead of replacing.
    """
    if not address or not comment:
        raise ToolError("Both 'address' and 'comment' are required")

    valid_types = {"PRE", "POST", "EOL", "PLATE", "REPEATABLE"}
    if comment_type.upper() not in valid_types:
        raise ToolError(f"Invalid comment_type. Must be one of: {valid_types}")

    data = await ghidra_post("/add_comment", {
        "address": address,
        "comment": comment,
        "comment_type": comment_type.upper(),
        "append": append,
    })

    return MutationResult(
        status=data.get("status", "unknown"),
        message=f"Comment added at {address}",
    )


# ==================== ENTRY POINT ====================

if __name__ == "__main__":
    mcp.run()