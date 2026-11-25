# -*- coding: utf-8 -*-
"""Small bounded JSON codec for the stripped P011 Python 3.5 runtime.

The inspected firmware omits the standard-library json package. This module
Encoder reused from the project's reporting helper; parser below is new.
It is not installed into system Python. No third-party imports or eval.
"""
import re

def dumps(value, ensure_ascii=True, indent=None, sort_keys=False):
    if indent is not None and (not isinstance(indent, int) or not 0 <= indent <= 8):
        raise ValueError('indent must be None or an integer between 0 and 8')
    active = set()
    escapes = {'"': '\\"', '\\': '\\\\', '\b': '\\b', '\f': '\\f',
               '\n': '\\n', '\r': '\\r', '\t': '\\t'}

    def quoted(text):
        parts = ['"']
        for c in text:
            n = ord(c)
            if c in escapes:
                parts.append(escapes[c])
            elif n < 32 or 0xD800 <= n <= 0xDFFF or (ensure_ascii and n > 126):
                if n <= 0xFFFF:
                    parts.append('\\u%04x' % n)
                else:
                    n -= 0x10000
                    parts.append('\\u%04x\\u%04x' % (0xD800 + (n >> 10), 0xDC00 + (n & 1023)))
            else:
                parts.append(c)
        parts.append('"')
        return ''.join(parts)

    def encode(item, depth):
        if depth > 40:
            raise ValueError('report nesting limit exceeded')
        if item is None:
            return 'null'
        if item is True:
            return 'true'
        if item is False:
            return 'false'
        if isinstance(item, str):
            return quoted(item)
        if isinstance(item, int):
            return str(item)
        if isinstance(item, float):
            if item != item or item in (float('inf'), -float('inf')):
                raise ValueError('non-finite report value')
            return repr(item)
        if not isinstance(item, (dict, list, tuple)):
            raise TypeError('unsupported report type: ' + type(item).__name__)
        marker = id(item)
        if marker in active:
            raise ValueError('circular report value')
        active.add(marker)
        try:
            if isinstance(item, dict):
                keys = list(item.keys())
                if not all(isinstance(k, str) for k in keys):
                    raise TypeError('report dictionary keys must be strings')
                if sort_keys:
                    keys.sort()
                content = [quoted(k) + ': ' + encode(item[k], depth + 1) for k in keys]
                left, right = '{', '}'
            else:
                content = [encode(x, depth + 1) for x in item]
                left, right = '[', ']'
            if not content:
                return left + right
            if indent is None:
                return left + ', '.join(content) + right
            pad = ' ' * (indent * (depth + 1))
            return left + '\n' + pad + (',\n' + pad).join(content) + '\n' + ' ' * (indent * depth) + right
        finally:
            active.remove(marker)

    return encode(value, 0)


def loads(text):
    """Strict JSON, duplicate keys rejected, bounded depth/nodes/input.

    No object hooks, NaN/Infinity, trailing commas, unpaired surrogates or eval.
    Protocol modules apply their own tighter semantic and byte limits.
    """
    if not isinstance(text, str) or len(text) > 131072:
        raise ValueError('JSON input limit')
    position = [0]
    nodes = [0]
    number = re.compile(r'-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?')
    escapes = {'"':'"', '\\':'\\', '/':'/', 'b':'\b', 'f':'\f', 'n':'\n', 'r':'\r', 't':'\t'}

    def whitespace():
        while position[0] < len(text) and text[position[0]] in ' \r\n\t':
            position[0] += 1

    def string():
        position[0] += 1
        result = []
        while position[0] < len(text):
            char = text[position[0]]
            position[0] += 1
            if char == '"':
                return ''.join(result)
            if ord(char) < 32 or 0xD800 <= ord(char) <= 0xDFFF:
                raise ValueError('Invalid JSON character')
            if char != '\\':
                result.append(char)
                continue
            if position[0] >= len(text):
                break
            escape = text[position[0]]
            position[0] += 1
            if escape in escapes:
                result.append(escapes[escape])
                continue
            if escape != 'u':
                raise ValueError('Invalid JSON escape')
            raw = text[position[0]:position[0]+4]
            if len(raw) != 4 or re.match(r'^[0-9a-fA-F]{4}$', raw) is None:
                raise ValueError('Invalid JSON unicode escape')
            position[0] += 4
            code = int(raw, 16)
            if 0xD800 <= code <= 0xDBFF:
                if text[position[0]:position[0]+2] != '\\u':
                    raise ValueError('Unpaired JSON surrogate')
                raw = text[position[0]+2:position[0]+6]
                if len(raw) != 4 or re.match(r'^[0-9a-fA-F]{4}$', raw) is None:
                    raise ValueError('Invalid JSON surrogate')
                low = int(raw,16)
                if not 0xDC00 <= low <= 0xDFFF:
                    raise ValueError('Invalid JSON surrogate')
                position[0] += 6
                code = 0x10000 + ((code-0xD800)<<10) + low-0xDC00
            elif 0xDC00 <= code <= 0xDFFF:
                raise ValueError('Unpaired JSON surrogate')
            result.append(chr(code))
        raise ValueError('Unterminated JSON string')

    def value(depth):
        whitespace()
        nodes[0] += 1
        if depth > 24 or nodes[0] > 8192 or position[0] >= len(text):
            raise ValueError('JSON structure limit')
        char = text[position[0]]
        if char == '"':
            return string()
        if char in '[{':
            position[0] += 1
            whitespace()
            end = ']' if char == '[' else '}'
            result = [] if char == '[' else {}
            if position[0] < len(text) and text[position[0]] == end:
                position[0] += 1
                return result
            while True:
                whitespace()
                if char == '{':
                    if position[0] >= len(text) or text[position[0]] != '"':
                        raise ValueError('JSON object key required')
                    key = string()
                    if key in result:
                        raise ValueError('Duplicate JSON key')
                    whitespace()
                    if position[0] >= len(text) or text[position[0]] != ':':
                        raise ValueError('JSON colon required')
                    position[0] += 1
                    result[key] = value(depth+1)
                else:
                    result.append(value(depth+1))
                whitespace()
                if position[0] >= len(text):
                    raise ValueError('Unterminated JSON collection')
                separator = text[position[0]]
                position[0] += 1
                if separator == end:
                    return result
                if separator != ',':
                    raise ValueError('JSON comma required')
        for literal, output in [('null',None),('true',True),('false',False)]:
            if text.startswith(literal,position[0]):
                position[0] += len(literal)
                return output
        match = number.match(text,position[0])
        if not match or len(match.group()) > 128:
            raise ValueError('Invalid JSON value')
        position[0] = match.end()
        raw = match.group()
        output = float(raw) if any(c in raw for c in '.eE') else int(raw)
        if isinstance(output,float) and (output != output or output in (float('inf'),-float('inf'))):
            raise ValueError('Non-finite JSON number')
        return output

    result = value(0)
    whitespace()
    if position[0] != len(text):
        raise ValueError('Trailing JSON content')
    return result

