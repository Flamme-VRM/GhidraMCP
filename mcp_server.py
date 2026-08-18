"""
Ghidra MCP Server v3 — MCP side
Requires: pip install -U mcp httpx
"""
import os
import json
from typing import Optional

import httpx
from mcp.server.fastmcp import FastMCP

GHIDRA_URL = os.environ.get("GHIDRA_MCP_URL", "http://127.0.0.1:13337")
GHIDRA_TOKEN = os.environ.get("GHIDRA_MCP_TOKEN", "ghidra_secret_v3")

mcp = FastMCP("Ghidra v3")


async def ghidra_post(endpoint: str, payload: Optional[dict] = None) -> dict:
    url = GHIDRA_URL.rstrip("/") + endpoint
    headers = {"X-MCP-Token": GHIDRA_TOKEN}
    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(url, json=payload or {}, headers=headers)
            return resp.json()
    except Exception as e:
        return {"error": str(e)}


def fmt(result) -> str:
    if isinstance(result, dict) and "error" in result:
        return f"ERROR: {result['error']}"
    return json.dumps(result, indent=2, ensure_ascii=False)


# ==================== READ-ONLY TOOLS ====================

@mcp.tool(annotations={"readOnlyHint": True})
async def get_program_info() -> str:
    """Returns program info: name, format, architecture, image base, memory blocks, function count."""
    result = await ghidra_post("/get_program_info")
    return fmt(result)


@mcp.tool(annotations={"readOnlyHint": True})
async def list_functions(query: str = "", limit: int = 100, offset: int = 0) -> str:
    """Lists functions in the program. Filter by substring.
    
    Args:
        query: Substring filter for function names.
        limit: Max results (default 100, max 500).
        offset: Skip N results.
    """
    result = await ghidra_post("/list_functions", {
        "query": query,
        "limit": limit,
        "offset": offset,
    })
    return fmt(result)


@mcp.tool(annotations={"readOnlyHint": True})
async def get_function(name: str = "", address: str = "") -> str:
    """Gets function metadata and decompiled C code by name or address.
    
    Args:
        name: Function name (e.g. 'main' or 'FUN_00401000').
        address: Function address in hex (e.g. '0x00401000').
    """
    result = await ghidra_post("/get_function", {
        "name": name,
        "address": address,
    })
    return fmt(result)


@mcp.tool(annotations={"readOnlyHint": True})
async def get_current_function() -> str:
    """Gets the decompiled C code of the function currently selected in Ghidra."""
    result = await ghidra_post("/get_current_function")
    return fmt(result)


@mcp.tool(annotations={"readOnlyHint": True})
async def get_disassembly(address: str, count: int = 20) -> str:
    """Gets disassembly listing starting from an address.
    
    Args:
        address: Start address in hex (e.g. '0x00401000').
        count: Number of instructions to return (max 100).
    """
    result = await ghidra_post("/get_disassembly", {
        "address": address,
        "count": count,
    })
    return fmt(result)


@mcp.tool(annotations={"readOnlyHint": True})
async def get_xrefs_to(address: str, limit: int = 100) -> str:
    """Gets cross-references TO an address (who calls/references it).
    
    Args:
        address: Target address in hex.
        limit: Max xrefs to return.
    """
    result = await ghidra_post("/get_xrefs_to", {
        "address": address,
        "limit": limit,
    })
    return fmt(result)


@mcp.tool(annotations={"readOnlyHint": True})
async def get_strings(filter_text: str = "", limit: int = 200) -> str:
    """Gets defined strings from the program.
    
    Args:
        filter_text: Filter strings containing this substring.
        limit: Max strings to return.
    """
    result = await ghidra_post("/get_strings", {
        "filter": filter_text,
        "limit": limit,
    })
    return fmt(result)


@mcp.tool(annotations={"readOnlyHint": True})
async def get_imports(query: str = "", limit: int = 200) -> str:
    """Gets imported functions (external API calls).
    
    Args:
        query: Filter by function name or library name.
        limit: Max imports to return.
    """
    result = await ghidra_post("/get_imports", {
        "query": query,
        "limit": limit,
    })
    return fmt(result)


@mcp.tool(annotations={"readOnlyHint": True})
async def get_memory_blocks() -> str:
    """Returns memory block layout (segments, permissions, sizes)."""
    result = await ghidra_post("/get_memory_blocks")
    return fmt(result)


# ==================== MUTATING TOOLS ====================

@mcp.tool()
async def rename_function(old_name: str, new_name: str) -> str:
    """Renames a function in Ghidra. USE WITH CAUTION.
    
    Args:
        old_name: Current function name.
        new_name: New meaningful name.
    """
    result = await ghidra_post("/rename_function", {
        "old_name": old_name,
        "new_name": new_name,
    })
    return fmt(result)


@mcp.tool()
async def rename_symbol(old_name: str, new_name: str, function_name: str = "") -> str:
    """Renames a symbol/variable in Ghidra. Optionally scoped to a function.
    
    Args:
        old_name: Current symbol name (e.g. 'param_1', 'local_10').
        new_name: New meaningful name.
        function_name: Optional function to scope the search.
    """
    result = await ghidra_post("/rename_symbol", {
        "old_name": old_name,
        "new_name": new_name,
        "function_name": function_name,
    })
    return fmt(result)


@mcp.tool()
async def add_comment(address: str, comment: str, comment_type: str = "PRE", append: bool = False) -> str:
    """Adds a comment at an address in Ghidra.
    
    Args:
        address: Address in hex (e.g. '0x00401000').
        comment: Comment text.
        comment_type: PRE, POST, EOL, PLATE, or REPEATABLE.
        append: If True, appends to existing comment instead of replacing.
    """
    result = await ghidra_post("/add_comment", {
        "address": address,
        "comment": comment,
        "comment_type": comment_type,
        "append": append,
    })
    return fmt(result)


if __name__ == "__main__":
    mcp.run()