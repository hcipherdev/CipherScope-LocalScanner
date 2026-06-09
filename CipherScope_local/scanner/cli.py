from __future__ import annotations

import argparse
import sys
from pathlib import Path

from CipherScope_local.scanner.models import LocalScanOptions, LocalScanReport
from CipherScope_local.scanner.reports.html import render_html_report
from CipherScope_local.scanner.reports.json import render_json_report
from CipherScope_local.scanner.reports.markdown import render_markdown_report
from CipherScope_local.scanner.reports.pdf import render_pdf_report
from CipherScope_local.scanner.runner import paths_from_strings, run_local_scan


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "handler"):
        parser.print_help(sys.stderr)
        return 2
    return args.handler(args)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cipherscope-local",
        description="Read-only local PQC migration scanner.",
    )
    subcommands = parser.add_subparsers(dest="command")
    scan = subcommands.add_parser("scan", help="Scan local endpoints, files, SSH, and libraries.")
    scan.add_argument("--target", help="TLS host to scan, for example localhost.")
    scan.add_argument("--network", help="CIDR range to scan. Only used when explicitly provided.")
    scan.add_argument(
        "--ports",
        default="443",
        help="Comma-separated TLS ports to inspect. Default: 443.",
    )
    scan.add_argument(
        "--path",
        action="append",
        default=[],
        help="Path to scan for certificates, keys, and configuration. May be repeated.",
    )
    scan.add_argument(
        "--format",
        choices=("json", "markdown", "html", "pdf"),
        default="json",
        help="Report format. Default: json.",
    )
    scan.add_argument("--output", help="Write report to this file instead of stdout.")
    scan.add_argument(
        "--timeout",
        type=float,
        default=3.0,
        help="Socket/command timeout in seconds.",
    )
    scan.add_argument("--max-files", type=int, default=5000, help="Maximum files per scanner.")
    scan.add_argument("--max-hosts", type=int, default=256, help="Maximum network hosts to scan.")
    scan.add_argument(
        "--docker",
        action="store_true",
        help="Scan running Docker containers only; does not start stopped containers.",
    )
    scan.add_argument(
        "--no-ssh",
        action="store_true",
        help="Disable SSH key and configuration scanning.",
    )
    scan.add_argument(
        "--no-libraries",
        action="store_true",
        help="Disable installed crypto library scanning.",
    )
    scan.set_defaults(handler=_handle_scan)
    return parser


def _handle_scan(args: argparse.Namespace) -> int:
    try:
        ports = _parse_ports(args.ports)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    if not args.target and not args.network and not args.path and not args.docker:
        print(
            "scan requires at least one of --target, --network, --path, or --docker",
            file=sys.stderr,
        )
        return 2

    options = LocalScanOptions(
        target=args.target,
        network=args.network,
        ports=ports,
        paths=paths_from_strings(args.path),
        timeout=args.timeout,
        max_files=args.max_files,
        max_hosts=args.max_hosts,
        docker=args.docker,
        ssh=not args.no_ssh,
        libraries=not args.no_libraries,
    )
    report = run_local_scan(options)
    rendered = render_report(report, args.format)
    if args.output:
        _write_output(Path(args.output), rendered)
    else:
        _write_stdout(rendered)
    return 0


def render_report(report: LocalScanReport, report_format: str) -> str | bytes:
    if report_format == "json":
        return render_json_report(report)
    if report_format == "markdown":
        return render_markdown_report(report)
    if report_format == "html":
        return render_html_report(report)
    if report_format == "pdf":
        return render_pdf_report(report)
    raise ValueError(f"Unsupported report format: {report_format}")


def _write_output(path: Path, rendered: str | bytes) -> None:
    if isinstance(rendered, bytes):
        path.write_bytes(rendered)
        return
    path.write_text(rendered, encoding="utf-8")


def _write_stdout(rendered: str | bytes) -> None:
    if isinstance(rendered, bytes):
        sys.stdout.buffer.write(rendered)
        return
    print(rendered, end="")


def _parse_ports(value: str) -> list[int]:
    ports: list[int] = []
    for raw in value.split(","):
        raw = raw.strip()
        if not raw:
            continue
        try:
            port = int(raw)
        except ValueError as exc:
            raise ValueError(f"invalid port: {raw}") from exc
        if port < 1 or port > 65535:
            raise ValueError(f"invalid port: {raw}")
        ports.append(port)
    if not ports:
        raise ValueError("at least one port is required")
    return ports
