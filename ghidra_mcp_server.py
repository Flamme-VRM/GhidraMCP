# @category MCP
# @name Ghidra MCP Server v3 (PyGhidra)
# @runtime PyGhidra

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import threading
import traceback

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import SourceType

HOST = '127.0.0.1'
PORT = 13337
EXPECTED_TOKEN = 'ghidra_secret_v3'

COMMENT_TYPES = {
    'PRE': CodeUnit.PRE_COMMENT,
    'POST': CodeUnit.POST_COMMENT,
    'EOL': CodeUnit.EOL_COMMENT,
    'PLATE': CodeUnit.PLATE_COMMENT,
    'REPEATABLE': CodeUnit.REPEATABLE_COMMENT,
}


def log(msg):
    print(f"[GhidraMCP] {msg}")


def parse_address(value):
    if not value:
        return None
    value = str(value).strip()
    af = currentProgram.getAddressFactory()
    try:
        addr = af.getAddress(value)
        if addr is not None:
            return addr
    except Exception:
        pass
    try:
        v = value.lower().removeprefix('0x')
        return af.getDefaultAddressSpace().getAddress(int(v, 16))
    except Exception:
        return None


def get_current_address():
    try:
        return state.getCurrentAddress()
    except Exception:
        pass
    try:
        return currentAddress
    except Exception:
        return None


def decompile_function(func):
    if func is None:
        return None
    decomp = DecompInterface()
    decomp.openProgram(currentProgram)
    try:
        res = decomp.decompileFunction(func, 60, monitor)
        if res is not None and res.decompileCompleted():
            df = res.getDecompiledFunction()
            if df is not None:
                return df.getC()
    finally:
        try:
            decomp.dispose()
        except Exception:
            pass
    return None


def get_function_by_name(name):
    fm = currentProgram.getFunctionManager()
    for f in fm.getFunctions(True):
        if f.getName() == name:
            return f
    return None


def get_function_at(addr):
    fm = currentProgram.getFunctionManager()
    f = fm.getFunctionAt(addr)
    if f is not None:
        return f
    return fm.getFunctionContaining(addr)


class GhidraMCPHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        log(fmt % args)

    def _authorized(self):
        if not EXPECTED_TOKEN:
            return True
        token = self.headers.get('X-MCP-Token', '')
        return token == EXPECTED_TOKEN

    def _read_json(self):
        length = int(self.headers.get('Content-Length', 0))
        if length <= 0:
            return {}
        body = self.rfile.read(length)
        if not body:
            return {}
        return json.loads(body.decode('utf-8'))

    def _send_json(self, obj, status=200):
        try:
            payload = json.dumps(obj, ensure_ascii=False)
        except Exception as e:
            payload = json.dumps({'error': f'serialization failed: {e}'})
        data = payload.encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == '/health':
            return self._send_json({
                'status': 'ok',
                'program': currentProgram.getName(),
            })
        return self._send_json({'error': 'use POST'}, 405)

    def do_POST(self):
        if not self._authorized():
            return self._send_json({'error': 'unauthorized'}, 401)

        try:
            payload = self._read_json()
        except Exception:
            return self._send_json({'error': 'bad json'}, 400)

        try:
            self._route(payload)
        except Exception as e:
            log(f"ERROR:\n{traceback.format_exc()}")
            self._send_json({'error': str(e)}, 500)

    def _route(self, payload):
        path = self.path

        # ===== READ-ONLY =====
        if path == '/get_program_info':
            return self._handle_program_info()

        elif path == '/list_functions':
            return self._handle_list_functions(payload)

        elif path == '/get_function':
            return self._handle_get_function(payload)

        elif path == '/get_current_function':
            return self._handle_current_function()

        elif path == '/get_disassembly':
            return self._handle_disassembly(payload)

        elif path == '/get_xrefs_to':
            return self._handle_xrefs(payload)

        elif path == '/get_strings':
            return self._handle_strings(payload)

        elif path == '/get_imports':
            return self._handle_imports(payload)

        elif path == '/get_memory_blocks':
            return self._handle_memory_blocks()

        # ===== MUTATING =====
        elif path == '/rename_function':
            return self._handle_rename_function(payload)

        elif path == '/rename_symbol':
            return self._handle_rename_symbol(payload)

        elif path == '/add_comment':
            return self._handle_add_comment(payload)

        else:
            return self._send_json({'error': f'unknown endpoint: {path}'}, 404)

    # ==================== READ-ONLY ====================

    def _handle_program_info(self):
        p = currentProgram
        fm = p.getFunctionManager()
        mem = p.getMemory()

        blocks = []
        try:
            for b in mem.getBlocks():
                blocks.append({
                    'name': str(b.getName()),
                    'start': str(b.getStart()),
                    'end': str(b.getEnd()),
                    'size': int(b.getSize()),
                    'read': bool(b.isRead()),
                    'write': bool(b.isWrite()),
                    'execute': bool(b.isExecute()),
                })
        except Exception:
            pass

        lang = None
        try:
            lang = str(p.getLanguageID())
        except Exception:
            pass

        compiler = None
        try:
            compiler = str(p.getCompilerSpec().getCompilerSpecID())
        except Exception:
            pass

        self._send_json({
            'name': str(p.getName()),
            'path': str(p.getExecutablePath()),
            'format': str(p.getExecutableFormat()),
            'language': lang,
            'compiler': compiler,
            'image_base': str(p.getImageBase()),
            'function_count': int(fm.getFunctionCount()),
            'memory_blocks': blocks,
        })

    def _handle_list_functions(self, payload):
        query = str(payload.get('query', '')).lower()
        limit = min(int(payload.get('limit', 100)), 500)
        offset = max(int(payload.get('offset', 0)), 0)

        fm = currentProgram.getFunctionManager()
        items = []
        seen = 0
        has_more = False

        for f in fm.getFunctions(True):
            name = str(f.getName())
            if query and query not in name.lower():
                continue
            if seen < offset:
                seen += 1
                continue
            if len(items) < limit:
                items.append({
                    'name': name,
                    'address': str(f.getEntryPoint()),
                    'signature': str(f.getSignature()),
                })
            else:
                has_more = True
                break

        self._send_json({
            'functions': items,
            'count': len(items),
            'has_more': has_more,
        })

    def _handle_get_function(self, payload):
        name = payload.get('name', '')
        address = payload.get('address', '')

        func = None
        if address:
            addr = parse_address(address)
            if addr:
                func = get_function_at(addr)
        elif name:
            func = get_function_by_name(name)

        if func is None:
            return self._send_json({'error': 'function not found'}, 404)

        code = decompile_function(func)
        params = []
        try:
            for p in func.getParameters():
                params.append(str(p))
        except Exception:
            pass

        self._send_json({
            'name': str(func.getName()),
            'address': str(func.getEntryPoint()),
            'signature': str(func.getSignature()),
            'calling_convention': str(func.getCallingConventionName()),
            'parameters': params,
            'parameter_count': int(func.getParameterCount()),
            'c_code': code,
        })

    def _handle_current_function(self):
        addr = get_current_address()
        if addr is None:
            return self._send_json({'error': 'no current address'})

        func = get_function_at(addr)
        if func is None:
            return self._send_json({'error': 'no function at current address'})

        code = decompile_function(func)
        self._send_json({
            'name': str(func.getName()),
            'address': str(func.getEntryPoint()),
            'c_code': code,
        })

    def _handle_disassembly(self, payload):
        address = payload.get('address', '')
        count = min(int(payload.get('count', 20)), 100)

        addr = parse_address(address)
        if addr is None:
            return self._send_json({'error': 'invalid address'})

        listing = currentProgram.getListing()
        lines = []
        current = addr

        for _ in range(count):
            try:
                cu = listing.getCodeUnitAt(current)
                if cu is None:
                    break
                lines.append(f"{current}: {cu.toString()}")
                nxt = cu.getMaxAddress().add(1)
                if nxt is None:
                    break
                current = nxt
            except Exception:
                break

        self._send_json({
            'address': str(addr),
            'disassembly': lines,
            'count': len(lines),
        })

    def _handle_xrefs(self, payload):
        address = payload.get('address', '')
        limit = min(int(payload.get('limit', 100)), 500)

        addr = parse_address(address)
        if addr is None:
            return self._send_json({'error': 'invalid address'})

        ref_mgr = currentProgram.getReferenceManager()
        items = []

        try:
            refs = ref_mgr.getReferencesTo(addr)
            for ref in refs:
                items.append({
                    'from': str(ref.getFromAddress()),
                    'type': str(ref.getReferenceType().getName()),
                })
                if len(items) >= limit:
                    break
        except Exception as e:
            return self._send_json({'error': str(e)})

        self._send_json({
            'address': str(addr),
            'xrefs_to': items,
            'count': len(items),
        })

    def _handle_strings(self, payload):
        filter_text = str(payload.get('filter', '')).lower()
        limit = min(int(payload.get('limit', 200)), 1000)

        listing = currentProgram.getListing()
        items = []

        for data in listing.getDefinedData(True):
            try:
                if not data.hasStringValue():
                    continue
                val = str(data.getValue())
                if not val:
                    continue
                if filter_text and filter_text not in val.lower():
                    continue
                items.append({
                    'address': str(data.getAddress()),
                    'string': val,
                })
                if len(items) >= limit:
                    break
            except Exception:
                continue

        self._send_json({
            'strings': items,
            'count': len(items),
        })

    def _handle_imports(self, payload):
        query = str(payload.get('query', '')).lower()
        limit = min(int(payload.get('limit', 200)), 1000)

        items = []
        fm = currentProgram.getFunctionManager()

        try:
            for ext in fm.getExternalFunctions():
                name = str(ext.getName())
                lib = str(ext.getLibraryName())
                if query and query not in name.lower() and query not in lib.lower():
                    continue
                addr = None
                try:
                    addr = str(ext.getAddress())
                except Exception:
                    pass
                items.append({
                    'name': name,
                    'library': lib,
                    'address': addr,
                })
                if len(items) >= limit:
                    break
        except Exception:
            pass

        self._send_json({
            'imports': items,
            'count': len(items),
        })

    def _handle_memory_blocks(self):
        mem = currentProgram.getMemory()
        blocks = []
        try:
            for b in mem.getBlocks():
                blocks.append({
                    'name': str(b.getName()),
                    'start': str(b.getStart()),
                    'end': str(b.getEnd()),
                    'size': int(b.getSize()),
                    'read': bool(b.isRead()),
                    'write': bool(b.isWrite()),
                    'execute': bool(b.isExecute()),
                })
        except Exception:
            pass
        self._send_json({'memory_blocks': blocks})

    # ==================== MUTATING ====================

    def _handle_rename_function(self, payload):
        old_name = str(payload.get('old_name', ''))
        new_name = str(payload.get('new_name', ''))

        if not old_name or not new_name:
            return self._send_json({'error': 'old_name and new_name required'}, 400)

        func = get_function_by_name(old_name)
        if func is None:
            return self._send_json({'error': 'function not found'}, 404)

        tx = currentProgram.startTransaction("MCP rename function")
        try:
            func.setName(new_name, SourceType.USER_DEFINED)
            currentProgram.endTransaction(tx, True)
            self._send_json({'status': 'success', 'new_name': new_name})
        except Exception as e:
            currentProgram.endTransaction(tx, False)
            self._send_json({'error': str(e)}, 500)

    def _handle_rename_symbol(self, payload):
        old_name = str(payload.get('old_name', ''))
        new_name = str(payload.get('new_name', ''))
        func_name = str(payload.get('function_name', ''))

        if not old_name or not new_name:
            return self._send_json({'error': 'old_name and new_name required'}, 400)

        st = currentProgram.getSymbolTable()
        candidates = []

        try:
            for sym in st.getSymbols(old_name):
                candidates.append(sym)
        except Exception:
            pass

        if not candidates:
            return self._send_json({'error': 'symbol not found'}, 404)

        if func_name:
            func = get_function_by_name(func_name)
            if func:
                filtered = []
                for sym in candidates:
                    try:
                        if func.getBody().contains(sym.getAddress()):
                            filtered.append(sym)
                    except Exception:
                        pass
                candidates = filtered

        if not candidates:
            return self._send_json({'error': 'symbol not found in function'}, 404)

        if len(candidates) > 1 and not func_name:
            return self._send_json({
                'error': 'multiple symbols found, specify function_name',
                'count': len(candidates),
            }, 400)

        tx = currentProgram.startTransaction("MCP rename symbol")
        renamed = []
        try:
            for sym in candidates:
                sym.setName(new_name, SourceType.USER_DEFINED)
                renamed.append(str(sym.getAddress()))
            currentProgram.endTransaction(tx, True)
            self._send_json({'status': 'success', 'renamed_addresses': renamed})
        except Exception as e:
            currentProgram.endTransaction(tx, False)
            self._send_json({'error': str(e)}, 500)

    def _handle_add_comment(self, payload):
        address = payload.get('address', '')
        comment = str(payload.get('comment', ''))
        ctype_name = str(payload.get('comment_type', 'PRE')).upper()
        append = bool(payload.get('append', False))

        addr = parse_address(address)
        if addr is None:
            return self._send_json({'error': 'invalid address'}, 400)
        if not comment:
            return self._send_json({'error': 'comment required'}, 400)

        ctype = COMMENT_TYPES.get(ctype_name, CodeUnit.PRE_COMMENT)
        listing = currentProgram.getListing()

        tx = currentProgram.startTransaction("MCP add comment")
        try:
            final = comment
            if append:
                try:
                    old = listing.getComment(addr, ctype)
                    if old:
                        final = str(old) + '\n' + comment
                except Exception:
                    pass
            listing.setComment(addr, ctype, final)
            currentProgram.endTransaction(tx, True)
            self._send_json({'status': 'success', 'address': str(addr)})
        except Exception as e:
            currentProgram.endTransaction(tx, False)
            self._send_json({'error': str(e)}, 500)


# ==================== SERVER START ====================

def run_server():
    server = HTTPServer((HOST, PORT), GhidraMCPHandler)
    log(f"Server started on http://{HOST}:{PORT}")
    log(f"Token: {EXPECTED_TOKEN}")
    server.serve_forever()

thread = threading.Thread(target=run_server, daemon=True)
thread.start()
log("MCP Server thread launched.")