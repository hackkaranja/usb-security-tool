from __future__ import annotations

import json
import urllib.error
import urllib.request


VT_BASE_URL = "https://www.virustotal.com/api/v3/files/"


def lookup_file_hash(sha256_hash: str, api_key: str, timeout_seconds: float = 4.0) -> dict:
    """
    Query VirusTotal file report by SHA-256 hash.

    Safe behavior:
    - Never uploads content.
    - Returns structured status for caller-side policy decisions.
    """
    digest = (sha256_hash or "").strip().lower()
    key = (api_key or "").strip()
    if not digest:
        return {"ok": False, "status": "invalid", "error": "missing hash"}
    if not key:
        return {"ok": False, "status": "disabled", "error": "missing api key"}

    req = urllib.request.Request(f"{VT_BASE_URL}{digest}")
    req.add_header("x-apikey", key)
    req.add_header("accept", "application/json")

    try:
        with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as http_err:
        if http_err.code == 404:
            return {"ok": True, "status": "not_found", "hash": digest}
        if http_err.code == 429:
            return {"ok": False, "status": "rate_limited", "error": "rate limited"}
        return {
            "ok": False,
            "status": "http_error",
            "error": f"http {http_err.code}",
        }
    except Exception as exc:
        return {"ok": False, "status": "network_error", "error": str(exc)}

    attrs = ((payload or {}).get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    malicious = int(stats.get("malicious") or 0)
    suspicious = int(stats.get("suspicious") or 0)
    harmless = int(stats.get("harmless") or 0)
    undetected = int(stats.get("undetected") or 0)
    timeout_count = int(stats.get("timeout") or 0)
    total_engines = malicious + suspicious + harmless + undetected + timeout_count

    return {
        "ok": True,
        "status": "found",
        "hash": digest,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "timeout": timeout_count,
        "total_engines": total_engines,
        "raw_stats": stats,
    }
