import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List
from .case import FuzzResult

_TEMPLATE = Path(__file__).resolve().parents[1] / "ui" / "static" / "index.html"
_EMBED_SLOT = "/*EMBED_START*/null/*EMBED_END*/"


class JsonReporter:
    def __init__(self, meta: Dict[str, Any] = None):
        self.results: List[FuzzResult] = []
        self.meta: Dict[str, Any] = dict(meta or {})
        self.meta.setdefault("generated_at", datetime.now(timezone.utc).isoformat(timespec="seconds"))

    def record(self, result: FuzzResult):
        # One campaign can run several protocols; the report owns the global order.
        result.index = len(self.results)
        self.results.append(result)

    def summary(self) -> Dict[str, Any]:
        summary: Dict[str, Any] = {"total": len(self.results), "by_status": {}, "by_layer": {}, "by_protocol": {}}
        for r in self.results:
            summary["by_status"][r.status] = summary["by_status"].get(r.status, 0) + 1
            for key, value in (("by_layer", r.layer), ("by_protocol", r.protocol)):
                bucket = summary[key].setdefault(value, {})
                bucket[r.status] = bucket.get(r.status, 0) + 1
        return summary

    def to_dict(self) -> Dict[str, Any]:
        return {
            "meta": self.meta,
            "summary": self.summary(),
            "results": [r.__dict__ for r in self.results],
        }

    def write(self, output_path: str):
        Path(output_path).write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")

    def write_html(self, output_path: str):
        Path(output_path).write_text(render_html(self.to_dict()), encoding="utf-8")


def render_html(report: Dict[str, Any]) -> str:
    """Self-contained HTML report: the console UI with this report embedded."""
    template = _TEMPLATE.read_text(encoding="utf-8")
    if _EMBED_SLOT not in template:
        raise RuntimeError("ui/static/index.html is missing the report embed slot")
    data = json.dumps(report).replace("</", "<\\/").replace("<!--", "<\\!--")
    # U+2028/2029 are valid in JSON but were line terminators in older JS.
    data = data.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    return template.replace(_EMBED_SLOT, data)


# Kept for callers that import the old name.
HtmlReporter = JsonReporter
