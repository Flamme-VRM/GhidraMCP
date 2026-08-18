# @category MCP
# @name Ghidra MCP Server v0.2
# @runtime Jython

from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import json
import threading
import traceback

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import SourceType

HOST = '127.0.0.1'
PORT = 13337

# Если хочешь защиту, задай токен, например:
# EXPECTED_TOKEN = 'secret123'
# Если пусто — сервер работает без токена.
EXPECTED_TOKEN = ''

COMMENT_TYPES = {
    'PRE': CodeUnit.PRE_COMMENT,
    'POST': CodeUnit.POST_COMMENT,
    'EOL': CodeUnit.EOL_COMMENT,
    'PLATE': CodeUnit.PLATE_COMMENT,
    'REPEATABLE': CodeUnit.REPEATABLE_COMMENT,
}


def log(msg):
    try:
        println("[GhidraMCP] %s" % msg)
    except:
        print("[GhidraMCP] %s" % msg)


def safe_text(x):
    if x is None:
        return None
    try:
        return unicode(x)
    except:
        pass
    try:
        return str(x)
    except:
        return repr(x)


def to_jsonable(x):
    if x is None:
        return None

    if isinstance(x, (str, unicode)):
        return x

    if isinstance(x, bool):
        return x

    if isinstance(x, (int, long, float)):
        return x

    if isinstance(x, (list, tuple)):
        return [to_jsonable(v) for v in x]

    if isinstance(x, dict):
        out = {}
        for k, v in x.items():
            out[to_jsonable(k)] = to_jsonable(v)
        return out

    return safe_text(x)


def parse_address(value):
    if not value:
        return None

    value = safe_text(value).strip()
    if not value:
        return None

    af = currentProgram.getAddressFactory()

    try:
        addr = af.getAddress(value)
        if addr is not None:
            return addr
    except:
        pass

    try:
        v = value.lower()
        if v.startswith('0x'):
            v = v[2:]
        return af.getDefaultAddressSpace().getAddress(int(v, 16))
    except:
        return None


def get_current_address():
    try:
        return state.getCurrentAddress()
    except:
        pass

    try:
        return currentAddress
    except:
        return None


def function_info(f):
    if f is None:
        return None

    params = []
    try:
        for p in f.getParameters():
            params.append(safe_text(p))
    except:
        pass

    comment = None
    try:
        comment = safe_text(f.getComment())
    except:
        pass

    return {
        'name': safe_text(f.getName()),
        'address': str(f.getEntryPoint()),
        'signature': safe_text(f.getSignature()),
        'calling_convention': safe_text(f.getCallingConventionName()),
        'parameter_count': int(f.getParameterCount()),
        'parameters': params,
        'comment': comment,
    }


def find_functions_by_name(name):
    name = safe_text(name)
    if not name:
        return []

    lower_name = name.lower()
    fm = currentProgram.getFunctionManager()

    exact = []
    partial = []

    for f in fm.getFunctions(True):
        fname = safe_text(f.getName()) or ''
        if fname == name:
            exact.append(f)
        elif lower_name in fname.lower():
            partial.append(f)

    if exact:
        return exact

    return partial


def get_function_at_or_containing(addr):
    if addr is None:
        return None

    fm = currentProgram.getFunctionManager()

    try:
        f = fm.getFunctionAt(addr)
        if f is not None:
            return f
    except:
        pass

    try:
        return fm.getFunctionContaining(addr)
    except:
        return None


def decompile_function(f):
    if f is None:
        return None

    decomp = DecompInterface()
    decomp.openProgram(currentProgram)

    try:
        res = decomp.decompileFunction(f, 60, monitor)
        if res is None:
            return None

        ok = False
        try:
            ok = res.decompileCompleted()
        except:
            try:
                ok = res.getDecompiledFunction() is not None
            except:
                ok = False

        if ok:
            dec_func = res.getDecompiledFunction()
            if dec_func is not None:
                return safe_text(dec_func.getC())
    finally:
        try:
            decomp.dispose()
        except:
            pass

    return None


def get_program_info():
    p = currentProgram
    fm = p.getFunctionManager()
    mem = p.getMemory()

    blocks = []
    try:
        for b in mem.getBlocks():
            blocks.append({
                'name': safe_text(b.getName()),
                'start': str(b.getStart()),
                'end': str(b.getEnd()),
                'size': int(b.getSize()),
                'read': bool(b.isRead()),
                'write': bool(b.isWrite()),
                'execute': bool(b.isExecute()),
            })
    except Exception as e:
        log("get_memory_blocks failed: %s" % e)

    lang = None
    try:
        lang = safe_text(p.getLanguageID())
    except:
        pass

    if lang is None:
        try:
            lang = safe_text(p.getLanguage().getId())
        except:
            pass

    compiler = None
    try:
        compiler = safe_text(p.getCompilerSpec().getCompilerSpecID())
    except:
        pass

    info = {
        'name': safe_text(p.getName()),
        'executable_path': safe_text(p.getExecutablePath()),
        'executable_format': safe_text(p.getExecutableFormat()),
        'language': lang,
        'compiler': compiler,
        'image_base': str(p.getImageBase()),
        'min_address': str(p.getMinAddress()),
        'max_address': str(p.getMaxAddress()),
        'function_count': int(fm.getFunctionCount()),
        'memory_blocks': blocks,
    }

    return info


def list_functions(query='', limit=100, offset=0):
    try:
        limit = int(limit or 100)
    except:
        limit = 100

    try:
        offset = int(offset or 0)
    except:
        offset = 0

    limit = max(1, min(limit, 500))
    offset = max(0, offset)

    query = safe_text(query) or ''
    query = query.lower()

    fm = currentProgram.getFunctionManager()
    items = []
    seen = 0
    has_more = False

    for f in fm.getFunctions(True):
        name = safe_text(f.getName()) or ''

        if query and query not in name.lower():
            continue

        if seen < offset:
            seen += 1
            continue

        if len(items) < limit:
            items.append({
                'name': name,
                'address': str(f.getEntryPoint()),
            })
        else:
            has_more = True
            break

    return {
        'functions': items,
        'has_more': has_more,
        'limit': limit,
        'offset': offset,
    }


def get_function_by_name(name):
    funcs = find_functions_by_name(name)
    if not funcs:
        return {'error': 'function not found'}

    matches = []
    for f in funcs[:20]:
        matches.append({
            'name': safe_text(f.getName()),
            'address': str(f.getEntryPoint()),
        })

    return {
        'function': function_info(funcs[0]),
        'match_count': len(funcs),
        'matches': matches,
    }


def get_decompiled_function(name=None, address=None):
    f = None
    fm = currentProgram.getFunctionManager()

    if address:
        addr = parse_address(address)
        if addr is None:
            return {'error': 'invalid address'}
        f = get_function_at_or_containing(addr)

    elif name:
        funcs = find_functions_by_name(name)
        if funcs:
            f = funcs[0]

    else:
        addr = get_current_address()
        if addr is not None:
            f = get_function_at_or_containing(addr)

    if f is None:
        return {'error': 'function not found'}

    code = decompile_function(f)
    if code is None:
        return {
            'error': 'decompilation failed',
            'function': function_info(f),
        }

    return {
        'function': function_info(f),
        'c_code': code,
    }


def get_current_function():
    return get_decompiled_function()


def get_xrefs_to(address_str, limit=100):
    try:
        limit = int(limit or 100)
    except:
        limit = 100

    limit = max(1, min(limit, 1000))

    addr = parse_address(address_str)
    if addr is None:
        return {'error': 'invalid address'}

    ref_mgr = currentProgram.getReferenceManager()
    items = []

    try:
        refs = ref_mgr.getReferencesTo(addr)
        for ref in refs:
            from_addr = ref.getFromAddress()
            ref_type = ref.getReferenceType()

            items.append({
                'from': str(from_addr),
                'type': safe_text(ref_type.getName()) if ref_type is not None else None,
            })

            if len(items) >= limit:
                break
    except Exception as e:
        return {'error': str(e)}

    return {
        'address': str(addr),
        'xrefs_to': items,
        'count': len(items),
        'limit': limit,
    }


def get_strings(filter_text='', limit=200):
    try:
        limit = int(limit or 200)
    except:
        limit = 200

    limit = max(1, min(limit, 1000))

    filter_text = safe_text(filter_text) or ''
    filter_text = filter_text.lower()

    listing = currentProgram.getListing()
    items = []

    for data in listing.getDefinedData(True):
        try:
            has_string = False
            try:
                has_string = data.hasStringValue()
            except:
                has_string = False

            if not has_string:
                continue

            val = data.getValue()
            if val is None:
                continue

            s = safe_text(val)
            if not s:
                continue

            if filter_text and filter_text not in s.lower():
                continue

            item = {
                'address': str(data.getAddress()),
                'string': s,
            }

            try:
                item['data_type'] = safe_text(data.getDataType().getName())
            except:
                pass

            items.append(item)

            if len(items) >= limit:
                break

        except Exception:
            continue

    return {
        'strings': items,
        'count': len(items),
        'limit': limit,
    }


def get_imports(query='', limit=200):
    try:
        limit = int(limit or 200)
    except:
        limit = 200

    limit = max(1, min(limit, 1000))

    query = safe_text(query) or ''
    query = query.lower()

    items = []
    fm = currentProgram.getFunctionManager()

    # Основной путь: external functions
    try:
        for ext in fm.getExternalFunctions():
            name = safe_text(ext.getName()) or ''
            lib = safe_text(ext.getLibraryName()) or ''

            if query and query not in name.lower() and query not in lib.lower():
                continue

            addr = None
            try:
                addr = str(ext.getAddress())
            except:
                pass

            items.append({
                'name': name,
                'library': lib,
                'address': addr,
                'source': 'external_function',
            })

            if len(items) >= limit:
                return {
                    'imports': items,
                    'count': len(items),
                    'has_more': True,
                }
    except Exception as e:
        log("getExternalFunctions failed: %s" % e)

    # Fallback: внешние символы
    try:
        st = currentProgram.getSymbolTable()
        for sym in st.getAllSymbols(True):
            try:
                if not sym.isExternal():
                    continue

                name = safe_text(sym.getName()) or ''
                if query and query not in name.lower():
                    continue

                addr = str(sym.getAddress())

                ns = None
                try:
                    ns = safe_text(sym.getParentNamespace().getName())
                except:
                    try:
                        ns = safe_text(sym.getNamespace().getName())
                    except:
                        ns = None

                items.append({
                    'name': name,
                    'library': ns,
                    'address': addr,
                    'source': 'symbol',
                })

                if len(items) >= limit:
                    break

            except Exception:
                continue
    except Exception as e:
        log("symbol fallback failed: %s" % e)

    return {
        'imports': items,
        'count': len(items),
        'has_more': False,
    }


def rename_function(old_name, new_name):
    old_name = safe_text(old_name)
    new_name = safe_text(new_name)

    if not old_name or not new_name:
        return {'error': 'old_name and new_name are required'}

    funcs = find_functions_by_name(old_name)

    if not funcs:
        return {'error': 'function not found'}

    if len(funcs) != 1:
        matches = []
        for f in funcs[:20]:
            matches.append({
                'name': safe_text(f.getName()),
                'address': str(f.getEntryPoint()),
            })
        return {
            'error': 'ambiguous function name',
            'matches': matches,
        }

    f = funcs[0]
    tx = currentProgram.startTransaction('MCP rename function')

    try:
        f.setName(new_name, SourceType.USER_DEFINED)
        currentProgram.endTransaction(tx, True)
        return {
            'status': 'success',
            'function': function_info(f),
        }
    except Exception as e:
        currentProgram.endTransaction(tx, False)
        return {'error': str(e)}


def rename_symbol(function_name, old_name, new_name):
    old_name = safe_text(old_name)
    new_name = safe_text(new_name)
    function_name = safe_text(function_name)

    if not old_name or not new_name:
        return {'error': 'old_name and new_name are required'}

    f = None
    if function_name:
        funcs = find_functions_by_name(function_name)
        if not funcs:
            return {'error': 'function not found'}
        f = funcs[0]

    st = currentProgram.getSymbolTable()
    symbols = []

    try:
        symbols = list(st.getSymbols(old_name))
    except Exception as e:
        log("getSymbols(name) failed: %s" % e)
        symbols = []

    if not symbols:
        try:
            for sym in st.getAllSymbols(True):
                if safe_text(sym.getName()) == old_name:
                    symbols.append(sym)
        except Exception as e:
            log("getAllSymbols fallback failed: %s" % e)

    candidates = []

    for sym in symbols:
        if f is not None:
            try:
                if not f.getBody().contains(sym.getAddress()):
                    continue
            except:
                pass
        candidates.append(sym)

    if not candidates:
        return {'error': 'symbol not found'}

    # Если функция не указана и символов несколько, лучше не трогать все подряд.
    if f is None and len(candidates) > 1:
        return {
            'error': 'multiple global symbols found; specify function_name',
            'count': len(candidates),
        }

    tx = currentProgram.startTransaction('MCP rename symbol')
    renamed = []

    try:
        for sym in candidates:
            sym.setName(new_name, SourceType.USER_DEFINED)
            renamed.append({
                'old_name': old_name,
                'new_name': new_name,
                'address': str(sym.getAddress()),
            })

        currentProgram.endTransaction(tx, True)

        return {
            'status': 'success',
            'renamed': renamed,
        }
    except Exception as e:
        currentProgram.endTransaction(tx, False)
        return {'error': str(e)}


def add_comment(address_str, comment, comment_type='PRE', append=False):
    addr = parse_address(address_str)
    if addr is None:
        return {'error': 'invalid address'}

    comment = safe_text(comment)
    if comment is None:
        return {'error': 'comment is required'}

    ctype_name = safe_text(comment_type) or 'PRE'
    ctype = COMMENT_TYPES.get(ctype_name.upper(), CodeUnit.PRE_COMMENT)

    listing = currentProgram.getListing()
    tx = currentProgram.startTransaction('MCP add comment')

    try:
        final_comment = comment

        if append:
            try:
                old = listing.getComment(addr, ctype)
                if old:
                    final_comment = safe_text(old) + u'\n' + comment
            except:
                pass

        listing.setComment(addr, ctype, final_comment)
        currentProgram.endTransaction(tx, True)

        return {
            'status': 'success',
            'address': str(addr),
            'comment_type': ctype_name.upper(),
        }
    except Exception as e:
        currentProgram.endTransaction(tx, False)
        return {'error': str(e)}


class GhidraMCPHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        try:
            log(format % args)
        except:
            pass

    def _get_header(self, name, default=None):
        try:
            return self.headers.getheader(name, default)
        except:
            try:
                return self.headers.get(name, default)
            except:
                return default

    def _authorized(self):
        if not EXPECTED_TOKEN:
            return True

        token = self._get_header('X-MCP-Token', '')
        return token == EXPECTED_TOKEN

    def _read_json(self):
        length = self._get_header('content-length', 0)
        try:
            length = int(length or 0)
        except:
            length = 0

        if length <= 0:
            return {}

        body = self.rfile.read(length)
        if not body:
            return {}

        return json.loads(body.decode('utf-8'))

    def _send_json(self, obj, status=200):
        try:
            payload = json.dumps(to_jsonable(obj))
        except Exception:
            payload = json.dumps({
                'error': 'serialization failed',
                'object_repr': safe_text(obj),
            })

        data = payload.encode('utf-8')

        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == '/health':
            return self._send_json({'status': 'ok'})

        return self._send_json({'error': 'use POST'}, status=405)

    def do_POST(self):
        if not self._authorized():
            return self._send_json({'error': 'unauthorized'}, status=401)

        try:
            payload = self._read_json()
        except Exception:
            return self._send_json({'error': 'bad json'}, status=400)

        try:
            if self.path == '/get_program_info':
                return self._send_json(get_program_info())

            elif self.path == '/list_functions':
                return self._send_json(list_functions(
                    payload.get('query', ''),
                    payload.get('limit', 100),
                    payload.get('offset', 0),
                ))

            elif self.path == '/get_function_by_name':
                return self._send_json(get_function_by_name(
                    payload.get('name', ''),
                ))

            elif self.path == '/get_decompiled_function':
                return self._send_json(get_decompiled_function(
                    payload.get('name', None),
                    payload.get('address', None),
                ))

            elif self.path == '/get_current_function':
                return self._send_json(get_current_function())

            elif self.path == '/get_xrefs_to':
                return self._send_json(get_xrefs_to(
                    payload.get('address', ''),
                    payload.get('limit', 100),
                ))

            elif self.path == '/get_strings':
                return self._send_json(get_strings(
                    payload.get('filter', ''),
                    payload.get('limit', 200),
                ))

            elif self.path == '/get_imports':
                return self._send_json(get_imports(
                    payload.get('query', ''),
                    payload.get('limit', 200),
                ))

            elif self.path == '/rename_function':
                return self._send_json(rename_function(
                    payload.get('old_name', ''),
                    payload.get('new_name', ''),
                ))

            elif self.path == '/rename_symbol':
                return self._send_json(rename_symbol(
                    payload.get('function_name', ''),
                    payload.get('old_name', ''),
                    payload.get('new_name', ''),
                ))

            elif self.path == '/add_comment':
                return self._send_json(add_comment(
                    payload.get('address', ''),
                    payload.get('comment', ''),
                    payload.get('comment_type', 'PRE'),
                    bool(payload.get('append', False)),
                ))

            else:
                return self._send_json({'error': 'unknown endpoint'}, status=404)

        except Exception as e:
            log("request failed:\n%s" % traceback.format_exc())
            return self._send_json({'error': str(e)}, status=500)


class ReusableHTTPServer(HTTPServer):
    allow_reuse_address = True


try:
    server = ReusableHTTPServer((HOST, PORT), GhidraMCPHandler)
    log("Starting server on http://%s:%d" % (HOST, PORT))

    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()

except Exception as e:
    log("Failed to start MCP server: %s" % e)
    log(traceback.format_exc())