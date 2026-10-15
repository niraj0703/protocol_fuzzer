"""Campaign file loading and validation.

Uses PyYAML when it is installed. Otherwise a small parser handles the subset
used by configs/campaigns/*.yaml: nested maps, lists of scalars, comments.
JSON files work too.
"""
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .oracles import KNOWN_ORACLES


class ConfigError(ValueError):
    pass


def _scalar(text: str) -> Any:
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1]
    low = text.lower()
    if low in ("true", "false"):
        return low == "true"
    if low in ("null", "~", ""):
        return None
    for cast in (int, float):
        try:
            return cast(text)
        except ValueError:
            pass
    return text


def _strip_comment(line: str) -> str:
    if line.lstrip().startswith("#"):
        return ""
    idx = line.find(" #")
    return line[:idx] if idx != -1 else line


def parse_simple_yaml(text: str) -> Any:
    lines: List[Tuple[int, str]] = []
    for raw in text.splitlines():
        raw = _strip_comment(raw).rstrip()
        if raw.strip():
            lines.append((len(raw) - len(raw.lstrip(" ")), raw.strip()))
    if not lines:
        return {}
    node, pos = _block(lines, 0, lines[0][0])
    if pos != len(lines):
        raise ConfigError(f"unexpected content near: {lines[pos][1]!r}")
    return node


def _block(lines, pos, indent):
    if lines[pos][1].startswith("- "):
        items = []
        while pos < len(lines) and lines[pos][0] == indent and lines[pos][1].startswith("- "):
            item = lines[pos][1][2:].strip()
            if ": " in item or item.endswith(":"):
                raise ConfigError(f"lists of maps are not supported by the built-in parser: {item!r}")
            items.append(_scalar(item))
            pos += 1
        return items, pos
    mapping = {}
    while pos < len(lines) and lines[pos][0] == indent and not lines[pos][1].startswith("- "):
        key, sep, rest = lines[pos][1].partition(":")
        if not sep:
            raise ConfigError(f"expected 'key: value', got {lines[pos][1]!r}")
        key, rest = key.strip(), rest.strip()
        pos += 1
        if rest:
            mapping[key] = _scalar(rest)
        elif pos < len(lines) and (lines[pos][0] > indent or (lines[pos][0] == indent and lines[pos][1].startswith("- "))):
            mapping[key], pos = _block(lines, pos, lines[pos][0])
        else:
            mapping[key] = None
    return mapping, pos


def load_campaign(path: str) -> Dict[str, Any]:
    p = Path(path)
    if not p.is_file():
        raise ConfigError(f"campaign file not found: {path}")
    text = p.read_text(encoding="utf-8")
    if p.suffix.lower() == ".json":
        data = json.loads(text)
    else:
        try:
            import yaml  # type: ignore
            data = yaml.safe_load(text)
        except ImportError:
            data = parse_simple_yaml(text)
    return validate_campaign(data)


def validate_campaign(data: Any) -> Dict[str, Any]:
    """Return a normalized campaign dict or raise ConfigError."""
    from protocols.registry import PROTOCOLS, LAYER_IDS  # local import avoids a cycle

    if not isinstance(data, dict):
        raise ConfigError("campaign file must contain a mapping at the top level")
    mode = data.get("mode", "dry-run")
    if mode not in ("dry-run", "live"):
        raise ConfigError("mode must be 'dry-run' or 'live'")
    max_cases = data.get("max_cases", 40)
    if not isinstance(max_cases, int) or isinstance(max_cases, bool) or not 1 <= max_cases <= 100000:
        raise ConfigError("max_cases must be an integer between 1 and 100000")

    protocols: List[str] = []
    layers = data.get("layers") or {}
    if not isinstance(layers, dict) or not layers:
        raise ConfigError("layers must list at least one layer")
    for layer, spec in layers.items():
        if layer not in LAYER_IDS:
            raise ConfigError(f"unknown layer {layer!r}; expected one of {sorted(LAYER_IDS)}")
        spec = spec or {}
        if not spec.get("enabled", True):
            continue
        for pid in spec.get("protocols") or []:
            if pid not in PROTOCOLS:
                raise ConfigError(f"unknown protocol {pid!r}; expected one of {sorted(PROTOCOLS)}")
            if PROTOCOLS[pid].layer != layer:
                raise ConfigError(f"protocol {pid!r} belongs to layer {PROTOCOLS[pid].layer!r}, not {layer!r}")
            if pid not in protocols:
                protocols.append(pid)
    if not protocols:
        raise ConfigError("no protocols are enabled")

    targets = _validate_targets(data.get("targets") or {}, PROTOCOLS)
    if mode == "live" and not any(p in targets for p in protocols):
        raise ConfigError("live mode needs a target for at least one enabled protocol")

    oracles = data.get("oracles") or []
    bad = [o for o in oracles if o not in KNOWN_ORACLES]
    if bad:
        raise ConfigError(f"unknown oracles {bad}; expected a subset of {list(KNOWN_ORACLES)}")
    report = data.get("report") or {}
    return {
        "name": str(data.get("name") or "campaign"),
        "mode": mode,
        "max_cases": max_cases,
        "rate_limit_pps": data.get("rate_limit_pps", 0) or 0,
        "protocols": protocols,
        "targets": targets,
        "oracles": list(oracles),
        "report": {
            "format": report.get("format", "json"),
            "save_payload_hex": bool(report.get("save_payload_hex", True)),
            "save_reproducer": bool(report.get("save_reproducer", True)),
        },
    }


def _validate_targets(raw: Any, protocols) -> Dict[str, Dict[str, Any]]:
    if not isinstance(raw, dict):
        raise ConfigError("targets must be a mapping of protocol id to target settings")
    out: Dict[str, Dict[str, Any]] = {}
    for pid, spec in raw.items():
        if pid not in protocols:
            raise ConfigError(f"targets: unknown protocol {pid!r}")
        spec = spec or {}
        host, port, transport = spec.get("host"), spec.get("port"), spec.get("transport")
        if not isinstance(host, str) or not host:
            raise ConfigError(f"targets.{pid}.host is required")
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise ConfigError(f"targets.{pid}.port must be 1-65535")
        if transport not in ("udp", "tcp"):
            raise ConfigError(f"targets.{pid}.transport must be 'udp' or 'tcp' (raw sockets are not implemented)")
        out[pid] = {"host": host, "port": port, "transport": transport,
                    "timeout": float(spec.get("timeout", 2.0)), "process": spec.get("process"),
                    "allow_public": bool(spec.get("allow_public", False))}
    return out
