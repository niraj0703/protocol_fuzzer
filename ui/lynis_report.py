"""Standalone, self-contained HTML audit report for a Lynis snapshot (or a
before/after pair). Kept separate from ui/static/index.html: that page shows
fuzz campaign results, this shows a host security audit, and the two have
different shapes (no cases, no bytes, no mutations).
"""
import html
import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional

_CSS = """
:root{color-scheme:light dark;--bg:#EEF2F3;--panel:#F6F8F9;--field:#FFFFFF;--ink:#17262E;--ink2:#4A5C66;
--rule:#C3CDD2;--accent:#0B6477;--good:#2F8F5B;--warn:#D9822B;--bad:#C62F2F;--sans:"Segoe UI",system-ui,Arial,sans-serif;
--mono:ui-monospace,"SF Mono",Menlo,Consolas,monospace}
@media (prefers-color-scheme:dark){:root{--bg:#12191D;--panel:#1A242A;--field:#0F171B;--ink:#E4ECEF;--ink2:#A3B4BC;
--rule:#34444D;--accent:#5CC0D6;--good:#4FBF83;--warn:#E0A75E;--bad:#FF7D7D}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.55 var(--sans)}
header{padding:20px 28px;background:var(--panel);border-bottom:1px solid var(--rule)}
header h1{margin:0;font-size:18px;font-weight:650}
header p{margin:4px 0 0;color:var(--ink2);font-size:13px}
main{max-width:980px;margin:0 auto;padding:24px 20px 60px;display:grid;gap:20px}
.pane{background:var(--panel);border:1px solid var(--rule);border-radius:6px;padding:18px 20px}
.score-row{display:flex;align-items:baseline;gap:18px;flex-wrap:wrap}
.score{font-size:42px;font-weight:700;font-variant-numeric:tabular-nums}
.score small{font-size:16px;font-weight:500;color:var(--ink2)}
.delta{font-size:15px;font-weight:600;padding:2px 10px;border-radius:12px}
.delta.up{color:var(--good);background:color-mix(in srgb,var(--good) 15%,transparent)}
.delta.down{color:var(--bad);background:color-mix(in srgb,var(--bad) 15%,transparent)}
.delta.flat{color:var(--ink2);background:var(--field)}
dl.kv{display:grid;grid-template-columns:max-content 1fr;gap:3px 14px;margin:14px 0 0;font-size:13px}
dl.kv dt{color:var(--ink2)} dl.kv dd{margin:0}
h2{font-size:15px;font-weight:650;margin:0 0 10px}
.count{font-weight:400;color:var(--ink2)}
ul.findings{list-style:none;margin:0;padding:0;display:grid;gap:8px}
ul.findings li{background:var(--field);border:1px solid var(--rule);border-radius:4px;padding:9px 12px}
ul.findings li.new{border-left:3px solid var(--warn)}
ul.findings li.resolved{border-left:3px solid var(--good);color:var(--ink2)}
.fid{font-family:var(--mono);font-size:12px;color:var(--accent);font-weight:600}
.fdesc{margin-top:2px}
.empty{color:var(--ink2);font-size:13px}
.badge{display:inline-block;font-size:11px;font-weight:700;letter-spacing:.02em;text-transform:uppercase;
padding:1px 7px;border-radius:3px;background:var(--warn);color:#1B1200;margin-left:8px;vertical-align:middle}
.badge.resolved{background:var(--good);color:#06200F}
footer{max-width:980px;margin:0 auto;padding:0 20px 40px;color:var(--ink2);font-size:12px}
"""


def _esc(s: Any) -> str:
    return html.escape(str(s if s is not None else ""))


def _delta_html(delta: Optional[int]) -> str:
    if delta is None:
        return ""
    cls = "up" if delta > 0 else "down" if delta < 0 else "flat"
    sign = "+" if delta > 0 else ""
    return f'<span class="delta {cls}">{sign}{delta}</span>'


def _finding_list(entries, cls="") -> str:
    if not entries:
        return '<p class="empty">None.</p>'
    items = "".join(
        f'<li class="{cls}"><span class="fid">{_esc(e.get("id", "?"))}</span>'
        f'<div class="fdesc">{_esc(e.get("description", ""))}</div></li>'
        for e in entries
    )
    return f'<ul class="findings">{items}</ul>'


def render_single(report: Dict[str, Any], generated_at: Optional[str] = None) -> str:
    """Report page for one audit() snapshot (no baseline to compare against)."""
    idx = report.get("hardening_index")
    kv = "".join(
        f"<dt>{_esc(k)}</dt><dd>{_esc(report.get(k))}</dd>"
        for k in ("lynis_version", "os_fullname", "hostname") if report.get(k)
    )
    return _page("Lynis host audit", generated_at, f"""
      <section class="pane">
        <div class="score-row"><span class="score">{idx if idx is not None else '?'}<small> / 100</small></span></div>
        <dl class="kv">{kv}</dl>
      </section>
      <section class="pane">
        <h2>Warnings <span class="count">({len(report.get('warnings', []))})</span></h2>
        {_finding_list(report.get('warnings', []))}
      </section>
      <section class="pane">
        <h2>Suggestions <span class="count">({len(report.get('suggestions', []))})</span></h2>
        {_finding_list(report.get('suggestions', []))}
      </section>
    """)


def render_diff(before: Dict[str, Any], after: Dict[str, Any], diff: Dict[str, Any],
                generated_at: Optional[str] = None) -> str:
    """Report page comparing a baseline and a follow-up audit() snapshot."""
    idx = after.get("hardening_index")
    kv = "".join(
        f"<dt>{_esc(k)}</dt><dd>{_esc(after.get(k))}</dd>"
        for k in ("lynis_version", "os_fullname", "hostname") if after.get(k)
    )
    return _page("Lynis host audit: before and after", generated_at, f"""
      <section class="pane">
        <div class="score-row">
          <span class="score">{diff.get('hardening_index_before', '?')} &rarr; {idx if idx is not None else '?'}<small> / 100</small></span>
          {_delta_html(diff.get('hardening_index_delta'))}
        </div>
        <dl class="kv">{kv}</dl>
      </section>
      <section class="pane">
        <h2>New warnings <span class="count">({len(diff.get('new_warnings', []))})</span></h2>
        {_finding_list(diff.get('new_warnings', []), 'new')}
      </section>
      <section class="pane">
        <h2>Resolved warnings <span class="count">({len(diff.get('resolved_warnings', []))})</span></h2>
        {_finding_list(diff.get('resolved_warnings', []), 'resolved')}
      </section>
      <section class="pane">
        <h2>New suggestions <span class="count">({len(diff.get('new_suggestions', []))})</span></h2>
        {_finding_list(diff.get('new_suggestions', []), 'new')}
      </section>
      <section class="pane">
        <h2>All current warnings <span class="count">({len(after.get('warnings', []))})</span></h2>
        {_finding_list(after.get('warnings', []))}
      </section>
      <section class="pane">
        <h2>All current suggestions <span class="count">({len(after.get('suggestions', []))})</span></h2>
        {_finding_list(after.get('suggestions', []))}
      </section>
    """)


def _page(title: str, generated_at: Optional[str], body: str) -> str:
    when = generated_at or datetime.now(timezone.utc).isoformat(timespec="seconds")
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        f"<title>{_esc(title)}</title><style>{_CSS}</style></head><body>"
        f"<header><h1>{_esc(title)}</h1><p>{_esc(when)}</p></header>"
        f"<main>{body}</main>"
        f"<footer>Generated by Lynis (<a href=\"https://cisofy.com/lynis/\">cisofy.com/lynis</a>) "
        "and the protocol fuzzer framework's audit report writer.</footer>"
        "</body></html>"
    )
