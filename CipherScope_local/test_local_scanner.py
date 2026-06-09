from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json
import ssl
import subprocess
import threading
from pathlib import Path
from socketserver import BaseRequestHandler, TCPServer

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from CipherScope_local.scanner.models import LocalSeverity, LocalStatus
from CipherScope_local.scanner.reports.score import score_findings
from CipherScope_local.scanner.scanners.config import scan_config_paths
from CipherScope_local.scanner.scanners.docker import scan_docker
from CipherScope_local.scanner.scanners.files import scan_file_paths
from CipherScope_local.scanner.scanners import libraries as library_scanner
from CipherScope_local.scanner.scanners.libraries import scan_libraries
from CipherScope_local.scanner.scanners.ssh import scan_ssh_paths
from CipherScope_local.scanner.scanners.tls import scan_tls_endpoint


def test_score_findings_explains_risk_and_caps_pqc_credit() -> None:
    findings = [
        _finding(
            finding_id="tls-localhost-443-rsa",
            category="tls",
            asset="localhost:443",
            location="localhost:443",
            algorithm="RSA",
            status=LocalStatus.QUANTUM_VULNERABLE,
            severity=LocalSeverity.HIGH,
        ),
        _finding(
            finding_id="openssl-oqs",
            category="libraries",
            asset="openssl",
            location="openssl version",
            algorithm="ML-KEM",
            status=LocalStatus.PQC_READY_DEPENDENCY_FOUND,
            severity=LocalSeverity.INFO,
        ),
    ]

    scored = score_findings(findings)

    assert 1 <= scored.score <= 100
    assert scored.counts_by_status == {
        "PQC-ready dependency found": 1,
        "quantum-vulnerable": 1,
    }
    assert scored.counts_by_severity == {"high": 1, "info": 1}
    assert any("TLS" in factor.reason for factor in scored.score_factors)
    assert any(factor.points < 0 for factor in scored.score_factors)
    assert "quantum safe" not in scored.summary.lower()


def test_config_scanner_reports_terms_with_line_numbers(tmp_path: Path) -> None:
    config = tmp_path / "nginx.conf"
    config.write_text(
        "\n".join(
            [
                "server {",
                "  ssl_certificate /etc/ssl/example.crt;",
                "  ssl_ecdh_curve prime256v1;",
                "}",
            ]
        ),
        encoding="utf-8",
    )

    findings = scan_config_paths([tmp_path], max_files=10)

    matched = {(finding.evidence["matched_term"], finding.location) for finding in findings}
    assert ("ssl_certificate", f"{config}:2") in matched
    assert ("prime256v1", f"{config}:3") in matched
    assert all(finding.status == LocalStatus.QUANTUM_VULNERABLE for finding in findings)


def test_config_scanner_does_not_match_algorithm_terms_inside_ordinary_words(
    tmp_path: Path,
) -> None:
    config = tmp_path / "services"
    config.write_text(
        "\n".join(
            [
                "univ-appserver 1233/tcp # Universal App Server",
                "ice-router 4063/tcp # Ice Firewall Traversal Service",
                "rsa-service enabled",
                "ssl_certificate /etc/ssl/example.crt;",
            ]
        ),
        encoding="utf-8",
    )

    findings = scan_config_paths([config], max_files=10)

    matched_terms = [finding.evidence["matched_term"] for finding in findings]
    assert matched_terms == ["RSA", "ssl_certificate"]


def test_file_scanner_detects_certificates_keys_and_protected_stores_without_key_material(
    tmp_path: Path,
) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = _self_signed_cert(private_key, hashes.SHA256())
    cert_path = tmp_path / "service.crt"
    key_path = tmp_path / "service.key"
    store_path = tmp_path / "keystore.p12"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_bytes = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    key_path.write_bytes(key_bytes)
    store_path.write_bytes(b"not a real encrypted store")

    findings = scan_file_paths([tmp_path], max_files=20)

    certificate = next(finding for finding in findings if finding.location == str(cert_path))
    private = next(finding for finding in findings if finding.location == str(key_path))
    store = next(finding for finding in findings if finding.location == str(store_path))
    serialized_evidence = "\n".join(str(finding.evidence) for finding in findings)

    assert certificate.algorithm == "RSA-2048"
    assert certificate.status == LocalStatus.QUANTUM_VULNERABLE
    assert private.algorithm == "RSA-2048"
    assert private.severity == LocalSeverity.HIGH
    assert store.status == LocalStatus.UNKNOWN
    assert "BEGIN RSA PRIVATE KEY" not in serialized_evidence
    assert "PRIVATE KEY" not in serialized_evidence


def test_ssh_scanner_detects_public_keys_and_sshd_algorithms(tmp_path: Path) -> None:
    user_ssh = tmp_path / "home" / ".ssh"
    system_ssh = tmp_path / "etc" / "ssh"
    user_ssh.mkdir(parents=True)
    system_ssh.mkdir(parents=True)
    (user_ssh / "id_ed25519.pub").write_text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA test\n")
    (system_ssh / "sshd_config").write_text(
        "HostKeyAlgorithms ssh-rsa,ecdsa-sha2-nistp256\n",
        encoding="utf-8",
    )

    findings = scan_ssh_paths(user_ssh_dir=user_ssh, system_ssh_dir=system_ssh)

    assert any(finding.algorithm == "Ed25519" for finding in findings)
    assert any(finding.algorithm == "RSA" for finding in findings)
    assert any(finding.algorithm == "ECDSA" for finding in findings)
    assert all("AAAA" not in str(finding.evidence) for finding in findings)


def test_ssh_scanner_supports_windows_openssh_paths(tmp_path: Path) -> None:
    user_ssh = tmp_path / "Users" / "Alice" / ".ssh"
    system_ssh = tmp_path / "ProgramData" / "ssh"
    user_ssh.mkdir(parents=True)
    system_ssh.mkdir(parents=True)
    (user_ssh / "known_hosts").write_text("github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA\n")
    (system_ssh / "ssh_host_rsa_key.pub").write_text("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ test\n")
    (system_ssh / "sshd_config").write_text(
        "HostKeyAlgorithms ssh-rsa,ecdsa-sha2-nistp256\n",
        encoding="utf-8",
    )

    findings = scan_ssh_paths(
        user_ssh_dir=user_ssh,
        system_ssh_dir=system_ssh,
        platform="win32",
        putty_registry_reader=lambda: ([], []),
    )

    assert any(finding.location.endswith("known_hosts:1") for finding in findings)
    assert any(finding.location.endswith("ssh_host_rsa_key.pub") for finding in findings)
    assert any(finding.location.endswith("sshd_config:1") for finding in findings)


def test_ssh_scanner_reads_putty_host_keys() -> None:
    findings = scan_ssh_paths(
        user_ssh_dir=Path("missing-user"),
        system_ssh_dir=Path("missing-system"),
        platform="win32",
        putty_registry_reader=lambda: (
            [{"name": "rsa2@22:legacy.example.com", "value": "0x01,0x02"}],
            [],
        ),
    )

    putty_finding = next(finding for finding in findings if finding.evidence["source"] == "putty-host-key")
    assert putty_finding.asset == "legacy.example.com"
    assert putty_finding.algorithm == "RSA"
    assert "SshHostKeys" in putty_finding.location


def test_ssh_scanner_reads_putty_sessions_with_referenced_key_files() -> None:
    findings = scan_ssh_paths(
        user_ssh_dir=Path("missing-user"),
        system_ssh_dir=Path("missing-system"),
        platform="win32",
        putty_registry_reader=lambda: (
            [],
            [
                {
                    "session_name": "Prod SSH",
                    "host_name": "prod.example.com",
                    "protocol": "ssh",
                    "port_number": "22",
                    "public_key_file": r"C:\Keys\prod.ppk",
                }
            ],
        ),
    )

    session_finding = next(finding for finding in findings if finding.evidence["source"] == "putty-session")
    assert session_finding.asset == "Prod SSH"
    assert session_finding.status == LocalStatus.UNKNOWN
    assert session_finding.evidence["public_key_file"] == r"C:\Keys\prod.ppk"
    assert "Sessions" in session_finding.location


def test_library_scanner_marks_missing_tools_unknown_and_oqs_dependency_found(monkeypatch) -> None:
    def fake_run(command, **kwargs):
        executable = command[0]
        if executable == "openssl":
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="OpenSSL 3.5.0 oqsprovider ML-KEM enabled\n",
                stderr="",
            )
        raise FileNotFoundError(executable)

    monkeypatch.setattr(subprocess, "run", fake_run)

    findings = scan_libraries(timeout=0.1)

    openssl = next(finding for finding in findings if finding.asset == "OpenSSL")
    missing = [finding for finding in findings if finding.status == LocalStatus.UNKNOWN]
    assert openssl.status == LocalStatus.PQC_READY_DEPENDENCY_FOUND
    assert openssl.severity == LocalSeverity.INFO
    assert missing


def test_library_scanner_uses_current_interpreter_for_python_probes(monkeypatch) -> None:
    commands = []
    expected_python = r"C:\Python311\python.exe"

    def fake_run(command, **kwargs):
        commands.append(command)
        if command[0] == expected_python:
            output = "3.11.9" if command[1] == "--version" else "42.0.0"
            return subprocess.CompletedProcess(command, 0, stdout=output, stderr="")
        raise FileNotFoundError(command[0])

    monkeypatch.setattr(library_scanner.sys, "executable", expected_python)
    monkeypatch.setattr(subprocess, "run", fake_run)

    findings = scan_libraries(timeout=0.1)

    assert any(
        finding.asset == "Python" and finding.location.startswith(expected_python)
        for finding in findings
    )
    assert any(
        finding.asset == "Python cryptography" and finding.location.startswith(expected_python)
        for finding in findings
    )
    assert [command[0] for command in commands if command[0] == expected_python] == [
        expected_python,
        expected_python,
    ]


def test_docker_scanner_uses_running_containers_only_and_reports_pqc_dependency(
    monkeypatch,
) -> None:
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        if command[:2] == ["docker", "ps"]:
            assert "-a" not in command
            ps_output = {
                "ID": "abc123",
                "Names": "web",
                "Image": "nginx:latest",
                "Status": "Up 5 minutes",
                "Ports": "0.0.0.0:443->443/tcp",
            }
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=f"{json.dumps(ps_output)}\n",
                stderr="",
            )
        if command[:2] == ["docker", "inspect"]:
            inspect_output = [
                {
                    "Id": "abc123",
                    "Name": "/web",
                    "Config": {"Image": "nginx:latest"},
                    "State": {"Status": "running"},
                    "NetworkSettings": {"Ports": {"443/tcp": [{"HostPort": "443"}]}},
                }
            ]
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=f"{json.dumps(inspect_output)}\n",
                stderr="",
            )
        if command[:3] == ["docker", "exec", "abc123"]:
            probe = " ".join(command)
            if "openssl version -a" in probe:
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout="OpenSSL 3.5.0 oqsprovider ML-KEM enabled\n",
                    stderr="",
                )
            return subprocess.CompletedProcess(command, 127, stdout="", stderr="not found\n")
        raise AssertionError(f"unexpected command: {command}")

    monkeypatch.setattr(subprocess, "run", fake_run)

    findings = scan_docker(timeout=0.1)

    assert not any(
        command[:2] in {
            ("docker", "start"),
            ("docker", "run"),
            ("docker", "pull"),
            ("docker", "cp"),
        }
        for command in map(tuple, calls)
    )
    assert any(finding.category == "docker_container" for finding in findings)
    pqc = next(
        finding
        for finding in findings
        if finding.status == LocalStatus.PQC_READY_DEPENDENCY_FOUND
    )
    assert pqc.asset == "container:web:nginx:latest"
    assert pqc.category == "docker_library"


def test_docker_scanner_missing_docker_is_non_fatal(monkeypatch) -> None:
    def fake_run(command, **kwargs):
        raise FileNotFoundError(command[0])

    monkeypatch.setattr(subprocess, "run", fake_run)

    findings = scan_docker(timeout=0.1)

    assert len(findings) == 1
    assert findings[0].category == "docker"
    assert findings[0].status == LocalStatus.UNKNOWN
    assert findings[0].severity == LocalSeverity.INFO


def test_tls_scanner_extracts_certificate_algorithm_without_verifying_trust(tmp_path: Path) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = _self_signed_cert(private_key, hashes.SHA256())
    cert_path = tmp_path / "localhost.crt"
    key_path = tmp_path / "localhost.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )

    server, thread = _start_tls_server(cert_path, key_path)
    try:
        host, port = server.server_address
        findings = scan_tls_endpoint(str(host), int(port), timeout=2.0)
    finally:
        server.shutdown()
        thread.join(timeout=2)

    cert_finding = next(finding for finding in findings if finding.category == "tls_certificate")
    assert cert_finding.algorithm == "RSA-2048"
    assert cert_finding.status == LocalStatus.QUANTUM_VULNERABLE
    assert cert_finding.evidence["tls_version"].startswith("TLS")


def test_tls_scanner_classifies_ecdsa_certificate_as_quantum_vulnerable(tmp_path: Path) -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    cert = _self_signed_cert(private_key, hashes.SHA256())
    cert_path = tmp_path / "localhost-ecdsa.crt"
    key_path = tmp_path / "localhost-ecdsa.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )

    server, thread = _start_tls_server(cert_path, key_path)
    try:
        host, port = server.server_address
        findings = scan_tls_endpoint(str(host), int(port), timeout=2.0)
    finally:
        server.shutdown()
        thread.join(timeout=2)

    cert_finding = next(finding for finding in findings if finding.category == "tls_certificate")
    assert cert_finding.algorithm == "ECDSA secp256r1"
    assert cert_finding.status == LocalStatus.QUANTUM_VULNERABLE


def _finding(**overrides):
    from CipherScope_local.scanner.models import LocalFinding

    values = {
        "id": "test",
        "category": "test",
        "asset": "asset",
        "location": "location",
        "algorithm": "RSA",
        "key_size": None,
        "status": LocalStatus.QUANTUM_VULNERABLE,
        "severity": LocalSeverity.MEDIUM,
        "evidence": {"source": "test"},
        "recommendation": "Plan a PQC migration path.",
    }
    values.update(overrides)
    return LocalFinding(**values)


def _self_signed_cert(private_key, algorithm):
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ]
    )
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(private_key, algorithm)
    )


class _TLSHandler(BaseRequestHandler):
    def handle(self) -> None:
        try:
            self.request.recv(1)
        except OSError:
            pass


def _start_tls_server(cert_path: Path, key_path: Path):
    class ReusableTCPServer(TCPServer):
        allow_reuse_address = True

    server = ReusableTCPServer(("127.0.0.1", 0), _TLSHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread
