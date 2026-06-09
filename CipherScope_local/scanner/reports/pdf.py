from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from CipherScope_local.scanner.models import LocalScanReport
from CipherScope_local.scanner.reports.html import render_html_report


SWIFT_PDF_RENDERER = r"""
import AppKit
import Foundation
import PDFKit
import WebKit

final class NavigationDelegate: NSObject, WKNavigationDelegate {
    var onFinish: (() -> Void)?
    var onFail: ((Error) -> Void)?

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        onFinish?()
    }

    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        onFail?(error)
    }

    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        onFail?(error)
    }
}

enum RenderError: Error {
    case invalidArguments
    case invalidPageMetrics
    case invalidPDFPage
    case missingPDFData
    case writeFailed
    case timedOut
}

let arguments = CommandLine.arguments
guard arguments.count == 3 else {
    throw RenderError.invalidArguments
}

let htmlURL = URL(fileURLWithPath: arguments[1])
let pdfURL = URL(fileURLWithPath: arguments[2])

let application = NSApplication.shared
application.setActivationPolicy(.accessory)
application.finishLaunching()
let configuration = WKWebViewConfiguration()
configuration.websiteDataStore = .nonPersistent()
let pageWidth = 794.0
let pageHeight = 1123.0
let webView = WKWebView(
    frame: CGRect(x: 0, y: 0, width: pageWidth, height: pageHeight),
    configuration: configuration
)
let window = NSWindow(
    contentRect: webView.frame,
    styleMask: [.borderless],
    backing: .buffered,
    defer: false
)
window.contentView = webView
let delegate = NavigationDelegate()
webView.navigationDelegate = delegate

var renderError: Error?
var completed = false

delegate.onFinish = {
    webView.evaluateJavaScript(
        "({ width: Math.max(document.body.scrollWidth, document.documentElement.scrollWidth), height: Math.max(document.body.scrollHeight, document.documentElement.scrollHeight) })"
    ) { result, error in
        if let error {
            renderError = error
            completed = true
            return
        }

        guard
            let metrics = result as? [String: Any],
            let width = metrics["width"] as? Double,
            let height = metrics["height"] as? Double,
            width > 0,
            height > 0
        else {
            renderError = RenderError.invalidPageMetrics
            completed = true
            return
        }

        let mergedDocument = PDFDocument()
        let pageCount = max(1, Int(ceil(height / pageHeight)))

        func renderPage(index: Int) {
            if index >= pageCount {
                guard let data = mergedDocument.dataRepresentation() else {
                    renderError = RenderError.missingPDFData
                    completed = true
                    return
                }
                do {
                    try data.write(to: pdfURL)
                } catch {
                    renderError = RenderError.writeFailed
                }
                completed = true
                return
            }

            let configuration = WKPDFConfiguration()
            configuration.rect = CGRect(
                x: 0,
                y: Double(index) * pageHeight,
                width: pageWidth,
                height: pageHeight
            )

            webView.createPDF(configuration: configuration) { result in
                switch result {
                case .success(let data):
                    guard
                        let document = PDFDocument(data: data),
                        let page = document.page(at: 0)
                    else {
                        renderError = RenderError.invalidPDFPage
                        completed = true
                        return
                    }
                    mergedDocument.insert(page, at: mergedDocument.pageCount)
                    renderPage(index: index + 1)
                case .failure(let error):
                    renderError = error
                    completed = true
                }
            }
        }

        renderPage(index: 0)
    }
}

delegate.onFail = { error in
    renderError = error
    completed = true
}

DispatchQueue.main.async {
    webView.loadFileURL(htmlURL, allowingReadAccessTo: htmlURL.deletingLastPathComponent())
}

DispatchQueue.main.asyncAfter(deadline: .now() + 20) {
    if completed {
        return
    }
    renderError = RenderError.timedOut
    completed = true
}

while !completed {
    RunLoop.main.run(mode: .default, before: Date(timeIntervalSinceNow: 0.1))
}

if let renderError {
    fputs("Failed to render PDF: \(renderError)\n", stderr)
    exit(1)
}
"""


def render_pdf_report(report: LocalScanReport) -> bytes:
    html = render_html_report(report, output_profile="pdf")
    return render_pdf_bytes(html)


def render_pdf_bytes(html: str) -> bytes:
    if sys.platform == "darwin":
        return _render_pdf_bytes_macos(html)
    if sys.platform.startswith("win"):
        return _render_pdf_bytes_windows(html)
    raise RuntimeError(
        "PDF output is supported on macOS with the Swift toolchain or on Windows "
        "with Microsoft Edge, Google Chrome, or Chromium."
    )


def _render_pdf_bytes_macos(html: str) -> bytes:
    with tempfile.TemporaryDirectory(prefix="cipherscope-local-pdf-") as temp_dir:
        temp_path = Path(temp_dir)
        html_path = temp_path / "report.html"
        pdf_path = temp_path / "report.pdf"
        swift_path = temp_path / "render.swift"
        module_cache_path = temp_path / "swift-module-cache"
        html_path.write_text(html, encoding="utf-8")
        swift_path.write_text(SWIFT_PDF_RENDERER, encoding="utf-8")
        module_cache_path.mkdir()

        try:
            completed = subprocess.run(
                [
                    "swift",
                    "-module-cache-path",
                    str(module_cache_path),
                    str(swift_path),
                    str(html_path),
                    str(pdf_path),
                ],
                check=True,
                capture_output=True,
                text=True,
                env=_swift_renderer_env(temp_path),
            )
        except FileNotFoundError as exc:
            raise RuntimeError(
                "PDF output requires the Swift toolchain (`swift`) on macOS."
            ) from exc
        except subprocess.CalledProcessError as exc:
            stderr = (exc.stderr or "").strip()
            message = stderr or "unknown Swift/WebKit renderer failure"
            raise RuntimeError(f"Failed to render PDF report: {message}") from exc

        if completed.stderr.strip():
            # Swift can emit non-fatal Xcode path warnings in some environments.
            # Ignore stderr if the PDF file was produced successfully.
            pass

        if not pdf_path.exists() or pdf_path.stat().st_size == 0:
            raise RuntimeError(
                "Failed to render PDF report: renderer did not create a usable PDF."
            )

        return pdf_path.read_bytes()


def _render_pdf_bytes_windows(html: str) -> bytes:
    browser_path = _find_windows_browser()
    if browser_path is None:
        raise RuntimeError(
            "PDF output on Windows requires Microsoft Edge, Google Chrome, or Chromium "
            "installed locally."
        )

    with tempfile.TemporaryDirectory(prefix="cipherscope-local-pdf-") as temp_dir:
        temp_path = Path(temp_dir)
        html_path = temp_path / "report.html"
        pdf_path = temp_path / "report.pdf"
        profile_path = temp_path / "browser-profile"
        html_path.write_text(html, encoding="utf-8")
        profile_path.mkdir()

        command = [
            str(browser_path),
            "--headless",
            "--disable-gpu",
            "--no-first-run",
            "--no-default-browser-check",
            "--allow-file-access-from-files",
            f"--user-data-dir={profile_path}",
            f"--print-to-pdf={pdf_path}",
            html_path.resolve().as_uri(),
        ]
        try:
            completed = subprocess.run(
                command,
                check=True,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as exc:
            stderr = (exc.stderr or "").strip()
            message = stderr or "unknown Chromium renderer failure"
            raise RuntimeError(f"Failed to render PDF report: {message}") from exc

        if completed.stderr.strip():
            pass

        if not pdf_path.exists() or pdf_path.stat().st_size == 0:
            raise RuntimeError(
                "Failed to render PDF report: renderer did not create a usable PDF."
            )

        return pdf_path.read_bytes()


def _swift_renderer_env(temp_path: Path) -> dict[str, str]:
    env = os.environ.copy()
    home_path = temp_path / "swift-home"
    home_path.mkdir()
    for relative_path in (
        "Library/Caches",
        "Library/WebKit",
        ".cache",
    ):
        (home_path / relative_path).mkdir(parents=True, exist_ok=True)
    env["HOME"] = str(home_path)
    env["XDG_CACHE_HOME"] = str(home_path / ".cache")
    env["CFFIXED_USER_HOME"] = str(home_path)
    return env


def _find_windows_browser() -> Path | None:
    for candidate in ("msedge", "chrome", "chromium"):
        resolved = shutil.which(candidate)
        if resolved:
            return Path(resolved)

    program_files_roots = [
        os.environ.get("ProgramFiles"),
        os.environ.get("ProgramFiles(x86)"),
    ]
    fallback_paths = [
        Path(root) / "Microsoft" / "Edge" / "Application" / "msedge.exe"
        for root in program_files_roots
        if root
    ] + [
        Path(root) / "Google" / "Chrome" / "Application" / "chrome.exe"
        for root in program_files_roots
        if root
    ] + [
        Path(root) / "Chromium" / "Application" / "chrome.exe"
        for root in program_files_roots
        if root
    ] + [
        Path(root) / "Chromium" / "Application" / "chromium.exe"
        for root in program_files_roots
        if root
    ]
    for candidate in fallback_paths:
        if candidate.exists():
            return candidate
    return None
