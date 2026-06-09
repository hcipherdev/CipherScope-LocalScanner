# CipherScope Local Scanner

A read-only command-line tool for local post-quantum cryptography (PQC)
migration inventory. It inspects selected local TLS endpoints, certificate and
key files, SSH configuration, common TLS configuration files, locally
installed crypto/runtime libraries, and optionally active Docker containers.

## Design Principles

- Does not upload results or call external APIs.
- Does not print or store private key material.
- Does not make destructive changes.
- Does not declare a system fully ready for post-quantum migration.
- Reports a **Migration Priority** score, not a security grade.

## Prerequisites

- Python 3.11 or later.
- A local Python environment with `pip`.
- Optional:
  - Docker CLI for `--docker`.
  - Windows PDF export: Microsoft Edge, Google Chrome, or Chromium.
  - macOS PDF export: Swift toolchain with WebKit support.

Windows support is package-first, not `.exe`-first. The scanner still depends
on local runtimes and platform backends such as Docker, OpenSSH, and the PDF
renderer.

## Installation

### Windows

```powershell
py -m pip install -e ".[dev]"
```

After installation, use either the console script or module form:

```powershell
cipherscope-local --help
cipherscope-local scan --help
py -m CipherScope_local.scanner --help
py -m CipherScope_local.scanner scan --help
```

### macOS and Linux

```bash
python -m pip install -e ".[dev]"
```

After installation:

```bash
cipherscope-local --help
cipherscope-local scan --help
python -m CipherScope_local.scanner --help
python -m CipherScope_local.scanner scan --help
```

## Quick Start

### Windows

Scan a local TLS endpoint and print JSON:

```powershell
py -m CipherScope_local.scanner scan --target localhost --ports 443 --format json
```

Scan local certificate, key, and configuration paths:

```powershell
py -m CipherScope_local.scanner scan `
  --path C:\ProgramData\ssh `
  --path $env:USERPROFILE\.ssh `
  --format html `
  --output report.html
```

Generate a PDF report:

```powershell
py -m CipherScope_local.scanner scan `
  --target localhost `
  --ports 443,8443 `
  --path C:\ProgramData\ssh `
  --path $env:USERPROFILE\.ssh `
  --format pdf `
  --output report.pdf
```

Scan Docker containers (running only):

```powershell
py -m CipherScope_local.scanner scan `
  --docker `
  --format html `
  --output docker-report.html
```

### macOS and Linux

Scan a local TLS endpoint and print JSON:

```bash
python -m CipherScope_local.scanner scan --target localhost --ports 443 --format json
```

Scan certificate and key paths, output HTML:

```bash
python -m CipherScope_local.scanner scan --path /etc --path /usr/local/etc --format html --output report.html
```

Generate a PDF report:

```bash
python -m CipherScope_local.scanner scan \
  --target localhost \
  --ports 443,8443 \
  --path /etc \
  --path ~/.ssh \
  --format pdf \
  --output report.pdf
```

Scan a CIDR range:

```bash
python -m CipherScope_local.scanner scan --network 192.168.1.0/24 --ports 443,8443 --max-hosts 256
```

Scan Docker containers (running only):

```bash
python -m CipherScope_local.scanner scan --docker --format html --output docker-report.html
```

## What It Scans

| Category | Source | Trigger |
|----------|--------|---------|
| TLS certificates | Live endpoint handshake | `--target` or `--network` |
| File certificates and keys | `.pem`, `.crt`, `.cer`, `.key`, `.p12`, `.pfx`, `.jks` | `--path` |
| Configuration files | Crypto terms in `.conf`, `.yaml`, `.json`, `.toml`, and related configs | `--path` |
| SSH keys and config | Platform-native OpenSSH locations and Windows PuTTY registry data | Always (disable with `--no-ssh`) |
| Installed libraries | OpenSSL, BoringSSL, Java, Python, Go, Node.js | Always (disable with `--no-libraries`) |
| Docker containers | Running container crypto inventory | `--docker` |

## CLI Reference

```text
cipherscope-local scan [OPTIONS]

Options:
  --target HOST         TLS host to scan (for example localhost)
  --network CIDR        CIDR range to scan
  --ports PORTS         Comma-separated TLS ports (default: 443)
  --path PATH           Path to scan for certs, keys, and config (repeatable)
  --docker              Scan running Docker containers only
  --no-ssh              Disable SSH scanning
  --no-libraries        Disable library version scanning
  --format FORMAT       json | markdown | html | pdf (default: json)
  --output FILE         Write report to file instead of stdout
  --timeout SECONDS     Socket/command timeout (default: 3.0)
  --max-files N         Max files per scanner (default: 5000)
  --max-hosts N         Max network hosts (default: 256)
```

At least one of `--target`, `--network`, `--path`, or `--docker` is required.

## Report Formats

- **JSON** - machine-readable, suitable for CI pipelines
- **Markdown** - human-readable summary
- **HTML** - styled report with collapsible sections
- **PDF** - print-ready version of the HTML report

## Migration Priority Score

The score (0-100) reflects **migration priority**, not security risk. It
measures how much classical cryptography inventory exists that needs PQC
migration planning.

- Category caps prevent one noisy category from dominating.
- Diminishing returns apply to repeated findings in the same category.
- PQC-ready dependencies reduce the score.

## Running Tests

```bash
python -m pip install -e ".[dev]"
python -m pytest CipherScope_local/test_local_scanner.py CipherScope_local/test_local_reports_cli.py -q
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
