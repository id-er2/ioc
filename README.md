# ioc

Extract possible indicators from UTF-8 text, offline. Python 3.9 or newer,
standard library only. No DNS lookups, uploads, reputation checks or
network requests.

## Usage

```
git clone https://github.com/id-er2/ioc.git
cd ioc
python3 ioc.py notes.txt
python3 ioc.py notes.txt --json
cat notes.txt | python3 ioc.py
```

The default output is defanged to reduce accidental clicks. Use `--raw`
only when you need active values for another local tool:

```
python3 ioc.py notes.txt --raw --json
```

Supported candidate categories:

- HTTP/HTTPS URLs, including common `hxxp` defanging
- ASCII domain names, including punycode spellings
- Common ASCII email address forms
- IPv4 and IPv6 addresses, validated with `ipaddress`
- Hex strings of 32, 40, 64, 96 or 128 characters, reported as hash
  candidates without guessing which algorithm produced them

Values are deduplicated within each category and sorted. One value can
contribute to more than one category: a URL and its hostname are useful
separate candidates. Domain names and hashes are lowercased, email
local-part case is preserved, and IPs use canonical notation.

Common `[.]`, `(.)`, `[@]` and `hxxp(s)://` substitutions are recognized.
No arbitrary URL decoding, HTML decoding or recursive decoding is done.
Default display replaces dots with `[.]`, email `@` with `[@]`, URL
schemes with `hxxp(s)`, and standalone IPv6 colons with `[:]`.

Example input:

```
Investigate hxxps://sub.example[.]com/path and 192[.]0[.]2[.]1.
Contact: analyst@example.org
```

The JSON result has `indicators`, `counts`, `total`, `defanged` and a
plain warning in `note`. `total` counts unique candidates across
categories, not unique incidents or confirmed threats.

## Limits and caveats

An extracted indicator is not evidence of malicious activity. This is a
pattern matcher for triage notes, not a full parser for every URL, email,
log format or obfuscation. It can miss unusual forms and include harmless
text such as a filename that resembles a domain. Domain endings are
syntactic, not checked against the public suffix list or live DNS.
Unicode domains should be supplied in punycode for extraction.

Trailing sentence punctuation is trimmed from URL candidates, which can
also trim legitimate URL characters such as a closing parenthesis.
URLs with embedded credentials or malformed ports are not included in
the URL category. Their other visible substrings may still match other
categories. This is not a secret redactor. Do not use it to make private
logs safe to share, and do not paste secrets into a chat bot.

Input is limited to 2 MiB and 5,000 unique candidates across categories.
On either limit the tool returns an error instead of a silent partial
result. No files or maps are written. Your terminal and shell can retain
input paths and output.

## Exit codes

- `0`: at least one candidate found
- `1`: no candidates found
- `2`: unreadable input, invalid UTF-8 or a limit exceeded

With `--json`, runtime errors contain an `error` field. CLI argument
syntax errors use argparse's usual usage output.

## Tests

```
python3 -m unittest -v test_ioc
```

Tests use documentation addresses and synthetic text. They cover
extraction, common defanging, deduplication, IPv6, hash boundaries, input
limits, JSON, files and exit codes. The suite makes no network requests.

## License

MIT. See [LICENSE](LICENSE).
