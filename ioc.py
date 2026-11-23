#!/usr/bin/env python3
"""Extract possible indicators from text offline, with defanged display by default."""

import argparse
import ipaddress
import json
import re
import sys
from urllib.parse import urlsplit

MAX_BYTES = 2 * 1024 * 1024
MAX_ITEMS = 5000
URL = re.compile(r'\b(?:https?|hxxps?)://[^\s<>"\x00-\x1f]+', re.I)
DOMAIN_TEXT = r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})'
DOMAIN = re.compile(r'(?<![\w@.-])' + DOMAIN_TEXT + r'(?![\w-]|\.[a-z0-9])', re.I)
EMAIL = re.compile(r'(?<![\w.+-])[a-z0-9.!#$%&\x27*+/=?^_`{|}~-]+@' + DOMAIN_TEXT + r'(?![\w-]|\.[a-z0-9])', re.I)
IPV4 = re.compile(r'(?<![\w.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![\w.])')
IPV6 = re.compile(r'(?<![\w:])(?:[a-f0-9]{0,4}:){2,}[a-f0-9:.]*(?![\w:])', re.I)
HASH = re.compile(r'(?<![a-z0-9])(?:[a-f0-9]{128}|[a-f0-9]{96}|[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})(?![a-z0-9])', re.I)


class IOCError(ValueError):
    pass


def refang(text):
    """Only common punctuation substitutions, not arbitrary decoding."""
    text = text.replace('[.]', '.').replace('(.)', '.').replace('[@]', '@')
    return re.sub(r'\bhxxp(s?)://', r'http\1://', text, flags=re.I)


def defang(value, kind):
    if kind == 'url':
        value = re.sub(r'^http(s?)://', r'hxxp\1://', value, flags=re.I)
    if kind in ('url', 'domain', 'email', 'ipv4', 'ipv6'):
        value = value.replace('.', '[.]').replace('@', '[@]')
    if kind == 'ipv6':
        value = value.replace(':', '[:]')
    return value


def extract(text, raw=False):
    if not isinstance(text, str) or len(text.encode('utf-8')) > MAX_BYTES:
        raise IOCError('Input must be text no larger than 2 MiB')
    source = refang(text)
    found = {k: set() for k in ['url', 'domain', 'email', 'ipv4', 'ipv6', 'hash']}
    def add(kind, value):
        if value in found[kind]:
            return
        if sum(len(v) for v in found.values()) >= MAX_ITEMS:
            raise IOCError('More than 5000 unique candidates; split the input')
        found[kind].add(value)

    for match in URL.finditer(source):
        value = match[0].rstrip('.,;!?)\'')
        try:
            p = urlsplit(value)
            if not p.hostname or p.username is not None or p.password is not None:
                continue
            _ = p.port
            if p.scheme.lower() not in ('http', 'https'):
                continue
        except ValueError:
            continue
        add('url', value)
    for match in EMAIL.finditer(source):
        local, domain = match[0].rsplit('@', 1)
        add('email', local + '@' + domain.lower())
        add('domain', domain.lower())
    for match in DOMAIN.finditer(source):
        add('domain', match[0].lower())
    for regex, kind, version in [(IPV4, 'ipv4', 4), (IPV6, 'ipv6', 6)]:
        for match in regex.finditer(source):
            value = match[0].rstrip('.')
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                continue
            if address.version == version:
                add(kind, str(address))
    for match in HASH.finditer(source):
        add('hash', match[0].lower())
    results = {k: [v if raw else defang(v, k) for v in sorted(values)] for k, values in found.items()}
    return {'indicators': results, 'counts': {k: len(v) for k, v in results.items()},
            'total': sum(len(v) for v in results.values()), 'defanged': not raw,
            'note': 'Candidates only, not confirmed threats. No lookups or network requests were made.'}


def safe_text(value):
    return ''.join(c if c.isprintable() else '\\x' + format(ord(c), '02x') for c in value)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('file', nargs='?', help='UTF-8 input file, or stdin when omitted')
    parser.add_argument('--raw', action='store_true', help='Keep active URLs and addresses (default: defanged)')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)
    try:
        if args.file:
            with open(args.file, 'rb') as handle:
                data = handle.read(MAX_BYTES + 1)
        else:
            data = sys.stdin.buffer.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise IOCError('Input exceeds 2 MiB')
        text = data.decode('utf-8')
        result = extract(text, args.raw)
    except (OSError, UnicodeError, IOCError) as exc:
        message = str(exc) if isinstance(exc, IOCError) else 'Could not read input as UTF-8 text'
        if args.json: print(json.dumps({'error': message}))
        else: print('ioc: ' + message, file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result, ensure_ascii=True, indent=2))
    else:
        print(result['note'])
        for kind, values in result['indicators'].items():
            if values:
                print(kind + ':')
                for value in values: print('  ' + safe_text(value))
        print(f"Total: {result['total']} unique candidates across categories")
    return 0 if result['total'] else 1


if __name__ == '__main__':
    sys.exit(main())
