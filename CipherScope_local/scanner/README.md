# CipherScope Local Scanner

`cipherscope-local` is a read-only command-line scanner for local
post-quantum cryptography migration inventory work. It inspects selected local
TLS endpoints, certificate and key files, SSH configuration, common TLS
configuration files, locally installed crypto/runtime libraries, and optionally
active Docker containers.

The scanner is intentionally local-first:

- It does not upload results.
- It does not call external APIs.
- It does not print or store private key material.
- It does not make destructive changes.
- It does not declare a system fully ready for post-quantum migration.

## Prerequisites

- Python 3.11 or later.
- A local Python environment with `pip`.
- Optional:
  - Docker CLI for `--docker`.
  - Windows PDF export: Microsoft Edge, Google Chrome, or Chromium.
  - macOS PDF export: Swift toolchain with WebKit support.

Windows support is package-first, not `.exe`-first. That is the recommended
default because the scanner still depends on local runtimes and platform
backends such as Docker, OpenSSH, and the PDF renderer. A standalone `.exe`
could be added later as a packaging layer, but it is not the primary
compatibility path.

## Windows Installation

From PowerShell at the repository root:

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

If you are working inside an activated virtual environment, `python -m` also
works:

```powershell
python -m CipherScope_local.scanner scan --help
```

## macOS Installation

From the repository root:

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

## Windows Usage

Scan a local TLS endpoint and print JSON:

```powershell
py -m CipherScope_local.scanner scan --target localhost --ports 443 --format json
```

Scan multiple local TLS ports and write Markdown:

```powershell
py -m CipherScope_local.scanner scan --target localhost --ports 443,8443,9443 --format markdown
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

Scan a local project tree with explicit bounds:

```powershell
py -m CipherScope_local.scanner scan `
  --path $env:USERPROFILE\projects `
  --max-files 1000 `
  --timeout 2 `
  --format json `
  --output local-scan.json
```

Scan active Docker containers without starting stopped containers:

```powershell
py -m CipherScope_local.scanner scan `
  --docker `
  --format html `
  --output docker-report.html
```

Windows SSH coverage includes:

- `%USERPROFILE%\.ssh\*.pub`
- `%USERPROFILE%\.ssh\known_hosts`
- `%ProgramData%\ssh\*.pub`
- `%ProgramData%\ssh\sshd_config`
- PuTTY host keys from `HKCU\Software\SimonTatham\PuTTY\SshHostKeys`
- PuTTY saved sessions from `HKCU\Software\SimonTatham\PuTTY\Sessions`

PuTTY session scans report configured SSH session evidence and referenced key
file paths when present, but they do not read `.ppk` private key contents or
inspect Pageant memory.

## macOS Usage

Scan a local TLS endpoint and print JSON:

```bash
python -m CipherScope_local.scanner scan --target localhost --ports 443 --format json
```

Scan multiple local TLS ports:

```bash
python -m CipherScope_local.scanner scan --target localhost --ports 443,8443,9443 --format markdown
```

Scan local certificate, key, and configuration paths:

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

Scan a small internal CIDR range:

```bash
python -m CipherScope_local.scanner scan --network 192.168.1.0/24 --ports 443,8443 --max-hosts 256
```

Scan a combination of network and local paths:

```bash
python -m CipherScope_local.scanner scan \
  --target localhost \
  --ports 443,8443 \
  --path /etc \
  --path ~/.ssh \
  --format html \
  --output report.html
```

Scan a broader local scope:

```bash
python -m CipherScope_local.scanner scan \
  --target localhost \
  --ports 443,8443,9443 \
  --path /etc \
  --path /usr/local/etc \
  --path ~/.ssh \
  --path ~/projects \
  --format html \
  --output report.html
```

Useful bounds:

```bash
python -m CipherScope_local.scanner scan \
  --path ~/projects \
  --max-files 1000 \
  --timeout 2 \
  --format json \
  --output local-scan.json
```

Scan active Docker containers without starting stopped containers:

```bash
python -m CipherScope_local.scanner scan \
  --docker \
  --format html \
  --output docker-report.html
```

Combine Docker scanning with local file scanning:

```bash
python -m CipherScope_local.scanner scan \
  --docker \
  --path /etc \
  --format html \
  --output report.html
```

## What It Scans

### TLS Endpoints

The TLS scanner connects to `--target` and each selected port, or to each host
generated from `--network` and `--max-hosts`. It disables certificate trust
verification only so it can inspect self-signed and private certificates.

Captured evidence includes:

- TLS protocol version.
- Certificate subject and issuer.
- Certificate expiration.
- Certificate public key algorithm and size.
- Certificate signature algorithm.

RSA, ECDSA, Ed25519, Ed448, DSA, X25519, and related classical algorithms are
classified as `quantum-vulnerable` for migration planning.

### File System Certificates And Keys

The file scanner walks only paths supplied with `--path`. It looks for:

- `.pem`
- `.crt`
- `.cer`
- `.key`
- `.p12`
- `.pfx`
- `.jks`

PEM/DER certificates and unencrypted private keys are parsed with
`cryptography`. Private key contents are never included in evidence. PKCS#12,
PFX, and JKS files are detected but not opened in v1; they are reported as
`unknown` with a recommendation for manual inspection by the owning application
team.

The scanner skips symlinks by default, caps traversal with `--max-files`, and
skips oversized files.

### SSH

The SSH scanner inspects platform-native OpenSSH locations and, on Windows,
selected PuTTY registry data.

It detects SSH RSA, ECDSA, and Ed25519 key algorithms and reports them as
`quantum-vulnerable` for long-term migration planning. It records key type and
location only, not key material.

### Configuration Files

The configuration scanner searches selected `--path` trees for common TLS and
crypto strings, including:

- `RSA`
- `ECDSA`
- `Ed25519`
- `X25519`
- `secp256r1`
- `prime256v1`
- `secp384r1`
- `Diffie-Hellman`
- `dhparam`
- `ssl_certificate`
- `ssl_certificate_key`
- `SSLCertificateFile`
- `SSLCertificateKeyFile`
- `ssl_ecdh_curve`

Each match records the path, line number, matched term, a short line excerpt,
and a remediation recommendation.

### Libraries And Runtimes

The library scanner runs safe local commands with a timeout:

- `openssl version -a`
- `bssl version`
- `java -version`
- `<current-python> --version`
- `<current-python> -c "import cryptography; print(cryptography.__version__)"`
- `go version`
- `node --version`

Missing commands are reported as `unknown`, not fatal errors. Output containing
markers such as `oqsprovider`, `ML-KEM`, `Kyber`, `ML-DSA`, `Dilithium`,
`Falcon`, or `SPHINCS` is classified as `PQC-ready dependency found`.

### Docker

The Docker scanner runs only when `--docker` is supplied. It scans active
containers returned by `docker ps` and does not inspect stopped containers or
image filesystems.

The scanner uses read-only Docker CLI inspection:

- `docker ps --format '{{json .}}'`
- `docker inspect <container_id>`
- `docker exec <container_id> sh -lc '<version probe>'`

It never runs `docker start`, `docker run`, `docker pull`, `docker cp`, or any
container mutation command. If Docker is missing, stopped, or unavailable, the
report records an `unknown` informational finding and the rest of the scan
continues.

## Report Format Notes

The scanner supports four output formats:

- `json`: deterministic machine-readable report.
- `markdown`: human-readable text report.
- `html`: styled report using the same visual language as the CipherScope web
  report.
- `pdf`: rendered from the local HTML report so it shares the same visual
  style.

Without `--output`, the report is printed to stdout. With `--output`, it is
written to the requested file.

PDF prerequisites are platform-specific:

- Windows: installed Microsoft Edge, Google Chrome, or Chromium.
- macOS: local Swift toolchain with WebKit support.

## Report Fields

Each finding has this model:

```json
{
  "id": "stable finding id",
  "category": "tls_certificate",
  "asset": "localhost:443",
  "location": "localhost:443",
  "algorithm": "RSA-2048",
  "key_size": 2048,
  "status": "quantum-vulnerable",
  "severity": "high",
  "evidence": {
    "tls_version": "TLSv1.3"
  },
  "recommendation": "Inventory this certificate for PQC migration planning."
}
```

### Status Values

- `quantum-vulnerable`: Classical public-key cryptography relevant to
  post-quantum migration planning was found.
- `migration-limited`: A dependency or runtime may limit future PQC migration
  until upgraded or reviewed.
- `hybrid-capable`: Hybrid post-quantum and classical capability was detected.
- `PQC-ready dependency found`: A local dependency exposes PQC-related markers.
- `unknown`: The scanner found relevant material but could not classify it.

### Severity Values

- `critical`: Highest-priority finding.
- `high`: Strong migration concern, such as private key material being present
  on disk or a network-facing classical certificate.
- `medium`: Relevant migration finding that should be tracked and remediated.
- `low`: Lower-priority migration limitation or dependency tracking item.
- `info`: Informational evidence or unknown/missing command result.

## Risk Score

The report score is a `0` to `100` migration-priority score, not a security
grade.

The scorer adds points for findings such as:

- Classical TLS certificates.
- Classical SSH keys or SSH host key algorithms.
- Classical private keys on disk.
- Hardcoded classical crypto terms in config files.
- Migration-limited runtimes.
- Unknown cryptographic stores that require manual inspection.

The scorer subtracts a small capped amount for `hybrid-capable` or
`PQC-ready dependency found` evidence. This credit is deliberately limited
because one PQC-capable library does not prove every service uses it.

The `Why this score?` section contains the exact score factors used for the
report.

## HTML Report Styling

The local HTML report renderer lives in
`CipherScope_local/scanner/reports/html.py`. It inlines
`cipherscope/static/styles.css` and uses the existing website report classes:

- `report-shell`
- `report-head`
- `status-panel`
- `finding-section`
- `finding`
- `eyebrow`

It does not include `_google_tag.html`, external assets, or telemetry snippets.
Keep that separation intact: hosted web reports may use web analytics, but local
reports should remain self-contained.

## Developer Notes

Main modules:

- `CipherScope_local/scanner/cli.py`: argparse command surface and output
  dispatch.
- `CipherScope_local/scanner/runner.py`: scanner orchestration and scan
  metadata.
- `CipherScope_local/scanner/models.py`: Pydantic report and finding models.
- `CipherScope_local/scanner/scanners/*.py`: focused scanner implementations.
- `CipherScope_local/scanner/reports/*.py`: JSON, Markdown, HTML, PDF, and
  scoring logic.
- `CipherScope_local/scanner/templates/report.html`: local HTML report template.

The local scanner intentionally uses its own model instead of reusing the
remote-domain `cipherscope.scanners.models.ScanResult`. Local machine findings
have different assets, categories, privacy concerns, and report sections.

When adding new scanners:

- Keep scanners read-only.
- Add bounded traversal, command timeouts, and size limits.
- Do not follow symlinks unless there is a deliberate reason and a test.
- Return `LocalFinding` objects; do not print from scanner modules.
- Put private or secret material behind redacted metadata only.
- Add tests before implementation.
- Preserve deterministic JSON output where practical.

When adding shell scripts, start the file with purpose and usage instructions.

## Tests

Run the local scanner tests:

```bash
pytest CipherScope_local/test_local_scanner.py CipherScope_local/test_local_reports_cli.py -q
```

On Windows, the equivalent is:

```powershell
py -m pytest CipherScope_local/test_local_scanner.py CipherScope_local/test_local_reports_cli.py -q
```

Some environments sandbox loopback socket binding. The TLS scanner tests start
temporary local TLS servers, so they may need permission to bind `127.0.0.1`.

The current test coverage checks:

- Local score factors and counts.
- Docker active-container scan behavior.
- Docker safety constraints for non-mutating CLI calls.
- TLS certificate algorithm detection.
- File certificate/key/store detection.
- Private key redaction.
- OpenSSH key and `sshd_config` detection.
- Windows PuTTY host key and saved-session detection.
- Config line-number evidence.
- Library command handling.
- JSON, Markdown, HTML, and PDF report dispatch.
- CLI output behavior and module entrypoint execution.

## Known Platform Limits

- Docker scanning covers active containers only. It does not start stopped
  containers or scan image filesystems.
- Docker runtime probes still use `sh -lc`. Linux containers work best; Windows
  containers are reported as `unknown` unless they expose a compatible shell.
- PKCS#12, PFX, and JKS parsing is detection-only in v1.
- SSH private key parsing is intentionally conservative.
- Network scanning is explicit only through `--network` and capped by
  `--max-hosts`.
- Linux does not currently have a dedicated PDF backend in this scanner.
- Library version classification is intentionally simple and should be expanded
  as platform support evolves.
