"""Bounded lexical hints from public JavaScript. No JavaScript evaluation.

Only complete literal imports and simple literal GET request declarations are eligible for
HTTP discovery. Other paths remain observations; variable expressions, request
bodies, credentials and template strings are never interpreted.
"""
import re

PARSER_VERSION = 1
MAX_REFERENCES = 16
MAX_SOURCE = 8 * 1024 * 1024
MAX_TOKENS = 100000
# Strings/comments are tokenized together so strings inside comments are ignored.
TOKEN = re.compile(r'''(?P<comment>//[^\n]*|/\*[\s\S]*?(?:\*/|$))|(?P<string>"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')|(?P<template>`(?:\\.|[^`\\])*(?:`|$))|(?P<regex>/(?:\\.|[^/\\\r\n])+/[dgimsuvy]*)|(?P<word>[A-Za-z_$][\w$]*)|(?P<invalid>['"`])|(?P<punct>[^\s])''')


def references(source, diagnostics=None):
    """Return bounded literal URL hints, with syntax-based execution eligibility."""
    tokens = []
    if diagnostics is not None and len(source) > MAX_SOURCE:
        diagnostics['source_limit'] = True
    for match in TOKEN.finditer(source[:MAX_SOURCE]):
        if match.lastgroup == 'invalid':
            break
        if match.lastgroup != 'comment':
            tokens.append((match.lastgroup, match.group()))
            if len(tokens) >= MAX_TOKENS:
                if diagnostics is not None:
                    diagnostics['token_limit'] = True
                break
    result = []

    def literal(index):
        if not 0 <= index < len(tokens) or tokens[index][0] != 'string':
            return None
        value = tokens[index][1][1:-1]
        # Do not decode escaped strings or partial expressions as destinations.
        if '\\' in value or not 1 <= len(value) <= 300:
            return None
        return value

    def add(index, kind, method=None, eligible=False, base='document'):
        value = literal(index)
        if value is None:
            return
        if not (value.startswith(('/', './', '../', 'http://', 'https://'))
                or value.lower().endswith(('.js', '.css'))):
            return
        entry = {'href': value, 'kind': kind, 'method': method,
                 'eligible': eligible, 'base': base}
        if entry not in result and len(result) < MAX_REFERENCES:
            result.append(entry)

    values = [t[1] for t in tokens]
    # Eligible references first so unrelated literals cannot starve the queue.
    for i, (_, value) in enumerate(tokens):
        if value == 'import' and (i == 0 or values[i-1] != '.'):
            if i + 1 < len(tokens) and tokens[i+1][0] == 'string':
                if i + 2 == len(tokens) or values[i+2] == ';':
                    add(i+1, 'module_import', eligible=True, base='script')
            elif values[i+1:i+2] == ['('] and i + 3 < len(tokens) and values[i+3] == ')':
                add(i+2, 'module_import', eligible=True, base='script')
            else:
                for j in range(i+1, min(len(tokens)-1, i+24)):
                    if values[j] == ';':
                        break
                    if values[j] == 'from' and literal(j+1):
                        if j+2 == len(tokens) or values[j+2] == ';':
                            add(j+1, 'module_import', eligible=True, base='script')
                        break
        if value == 'fetch' and (i == 0 or values[i-1] != '.') and values[i+1:i+2] == ['(']:
            if i+3 < len(tokens) and values[i+3] == ')':
                add(i+2, 'fetch', method='GET', eligible=True)
            elif (i+9 < len(tokens) and values[i+3:i+6] == [',', '{', 'method']
                  and values[i+6] == ':' and values[i+8:i+10] == ['}', ')']):
                method = literal(i+7)
                if method in ('GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD'):
                    add(i+2, 'fetch', method=method, eligible=method == 'GET')
        if (value == 'Ext' and (i == 0 or values[i-1] != '.')
                and values[i:i+7] == ['Ext', '.', 'Ajax', '.', 'request', '(', '{']):
            # Accept only a flat, complete {url: literal, method: literal}.
            # Configurations with params, headers or executable values stay hints.
            config = {}
            j = i + 7
            valid = True
            for _ in range(2):
                if j + 2 >= len(tokens):
                    valid = False
                    break
                key = literal(j) if tokens[j][0] == 'string' else values[j]
                if key not in ('url', 'method') or key in config or values[j+1] != ':' or literal(j+2) is None:
                    valid = False
                    break
                config[key] = j+2
                j += 3
                if len(config) == 1:
                    if values[j:j+1] != [',']:
                        valid = False
                        break
                    j += 1
            if valid and set(config) == {'url','method'} and values[j:j+2] == ['}', ')']:
                method = literal(config['method'])
                if method in ('GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD'):
                    add(config['url'], 'ext_ajax', method=method, eligible=method == 'GET')
    for i, token in enumerate(tokens):
        if token[0] != 'string':
            continue
        # A string next to + is a fragment, not a complete observed URL.
        if (i and values[i-1] == '+') or (i+1 < len(tokens) and values[i+1] == '+'):
            continue
        if any(entry['href'] == literal(i) for entry in result):
            continue
        add(i, 'url_literal')
    return result
