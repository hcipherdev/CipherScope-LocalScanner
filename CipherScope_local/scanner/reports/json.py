from __future__ import annotations

import json

from CipherScope_local.scanner.models import LocalScanReport


def render_json_report(report: LocalScanReport) -> str:
    return json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"
