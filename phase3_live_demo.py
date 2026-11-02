# =============================================================================
# PHASE 3: LIVE STATIC DEMO + THREAT INTELLIGENCE
#   APK  ->  Androguard parsing  ->  215 Drebin features  ->  saved Phase-1 model
#        ->  verdict + SHAP evidence
#   APK  ->  embedded IPs / domains  ->  AbuseIPDB reputation lookup
#
# Needs:  pip install "androguard>=4" requests shap xgboost scikit-learn joblib pandas
# Safe:   the APK is only READ (like opening a zip). It is never installed or run.
# =============================================================================
import os
import re
import socket
import ipaddress
import logging
import math
import collections
import warnings
import numpy as np
import pandas as pd
import joblib
import tldextract
from pathlib import Path

# ---------------------------------------------------------------------------
# In-memory thread-safe TTL cache for threat-intelligence lookups (AbuseIPDB & URLhaus)
# ---------------------------------------------------------------------------
import threading as _threading
import time as _time

_TI_CACHE = {}
_TI_CACHE_LOCK = _threading.Lock()
_TI_CACHE_TTL = 86400.0  # 24 hours


def _ti_cache_get(key: str):
    with _TI_CACHE_LOCK:
        entry = _TI_CACHE.get(key)
        if entry is None:
            return None
        val, ts = entry
        if _time.monotonic() - ts > _TI_CACHE_TTL:
            _TI_CACHE.pop(key, None)
            return None
        return dict(val) if isinstance(val, dict) else val


def _ti_cache_set(key: str, val) -> None:
    with _TI_CACHE_LOCK:
        _TI_CACHE[key] = (dict(val) if isinstance(val, dict) else val, _time.monotonic())


def _ti_cache_clear() -> None:
    with _TI_CACHE_LOCK:
        _TI_CACHE.clear()

warnings.filterwarnings("ignore")
logging.disable(logging.CRITICAL)
try:                                   # androguard logs a lot through loguru
    from loguru import logger
    logger.remove()
except Exception:
    pass

# Load root .env file if present
_DOTENV_PATH = Path(__file__).resolve().parent / ".env"
try:
    from dotenv import load_dotenv
    if _DOTENV_PATH.is_file():
        load_dotenv(dotenv_path=_DOTENV_PATH, override=False)
except ImportError:
    if _DOTENV_PATH.is_file():
        try:
            with open(_DOTENV_PATH, "r", encoding="utf-8") as _f:
                for _line in _f:
                    _line = _line.strip()
                    if _line and not _line.startswith("#") and "=" in _line:
                        _k, _v = _line.split("=", 1)
                        _k, _v = _k.strip(), _v.strip().strip("'\"")
                        if _k and _k not in os.environ:
                            os.environ[_k] = _v
        except Exception:
            pass

# -----------------------------------------------------------------------------
# >>> SETTINGS <<<
# -----------------------------------------------------------------------------
STATIC_MODEL_PATH = "static_outputs/static_model.joblib"   # saved by phase1_static.py
ABUSE_API = "https://api.abuseipdb.com/api/v2"
MALICIOUS_THRESHOLD = 50       # AbuseIPDB confidence score >= 50 counts as "malicious IP"
ENTROPY_THRESHOLD = 3.4        # Shannon entropy > 3.4 flags DGA candidate domain label
URLHAUS_API_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/host/"
_TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())

# --- Feature groups of the Drebin-215 dataset (used to decide HOW to look for each feature)
INTENT_FEATURES = {
    "android.intent.action.BOOT_COMPLETED", "android.intent.action.PACKAGE_REPLACED",
    "android.intent.action.SEND_MULTIPLE", "android.intent.action.TIME_SET",
    "android.intent.action.PACKAGE_REMOVED", "android.intent.action.TIMEZONE_CHANGED",
    "android.intent.action.ACTION_POWER_DISCONNECTED", "android.intent.action.PACKAGE_ADDED",
    "android.intent.action.ACTION_SHUTDOWN", "android.intent.action.PACKAGE_DATA_CLEARED",
    "android.intent.action.PACKAGE_CHANGED", "android.intent.action.NEW_OUTGOING_CALL",
    "android.intent.action.SENDTO", "android.intent.action.CALL", "android.intent.action.SCREEN_ON",
    "android.intent.action.BATTERY_OKAY", "android.intent.action.PACKAGE_RESTARTED",
    "android.intent.action.CALL_BUTTON", "android.intent.action.SCREEN_OFF", "intent.action.RUN",
    "android.intent.action.SET_WALLPAPER", "android.intent.action.BATTERY_LOW",
    "android.intent.action.ACTION_POWER_CONNECTED"}
COMMAND_FEATURES = {"mount", "chmod", "remount", "chown", "/system/bin", "/system/app"}

# Hosts that appear in almost every app and say nothing about maliciousness
IGNORED_HOST_SUFFIXES = (
    "schemas.android.com", "w3.org", "xmlpull.org", "apache.org", "android.com", "google.com",
    "googleapis.com", "gstatic.com", "googleusercontent.com", "mozilla.org", "example.com",
    "example.org", "oracle.com", "sun.com", "xml.org")


# =============================================================================
# 1. READ THE APK
# =============================================================================
def extract_apk_info(apk_path):
    """Read an APK (never executes it) and collect what the feature matcher needs."""
    try:
        from androguard.core.apk import APK
        from androguard.core.dex import DEX
    except ImportError as e:
        raise ImportError('Androguard 4.x is required:  pip install "androguard>=4"') from e

    try:
        apk = APK(apk_path)
        if not apk.is_valid_APK():
            raise ValueError("not a valid APK")
    except Exception as e:
        raise ValueError(f"'{os.path.basename(apk_path)}' could not be read as an APK ({e}).") from e
    permissions = {p.split(".")[-1] for p in apk.get_permissions()}
    try:
        version_name = apk.get_androidversion_name() or ""
    except Exception:
        version_name = ""

    actions, manifest_strings = set(), []
    xml = apk.get_android_manifest_xml()
    ns = "{http://schemas.android.com/apk/res/android}"
    if xml is not None:
        for el in xml.iter():
            for v in el.attrib.values():
                manifest_strings.append(str(v))
            if el.tag == "action":
                name = el.attrib.get(ns + "name") or el.attrib.get("name")
                if name:
                    actions.add(name)

    method_refs, type_descs, strings = set(), set(), []
    n_dex = 0
    for raw in apk.get_all_dex():
        n_dex += 1
        dex = DEX(raw)
        for m in dex.get_methods():                       # every method defined OR referenced
            method_refs.add((m.get_class_name(), m.get_name()))
        for s in dex.get_strings():                       # string table: constants + type names
            strings.append(s)
            t = s.lstrip("[")
            if t.startswith("L") and t.endswith(";") and "/" in t:
                type_descs.add(t)
    for cls, _ in method_refs:
        type_descs.add(cls.lstrip("["))

    try:
        app_name = apk.get_app_name()
    except Exception:
        app_name = ""
    return {"path": apk_path, "package": apk.get_package() or "?", "app_name": app_name,
            "version_name": version_name, "n_dex": n_dex,
            "permissions": permissions, "actions": actions, "method_refs": method_refs,
            "type_descs": type_descs, "strings": strings, "manifest_strings": manifest_strings}


# =============================================================================
# 2. MATCH THE 215 DREBIN FEATURES
# =============================================================================
def _simple_name(desc):
    return desc.rstrip(";").split("/")[-1]


def _command_present(feature, strings):
    if feature.startswith("/"):
        return any(feature in s for s in strings)
    pat = re.compile(rf"(?<![A-Za-z0-9_]){re.escape(feature)}(?![A-Za-z0-9_])")
    return any(pat.search(s) for s in strings if len(s) < 300 and not s.startswith("L"))


def _api_present(feature, info):
    refs, types = info["method_refs"], info["type_descs"]
    if feature == "android.intent.action.SEND":                       # string constant / manifest action
        return feature in info["actions"] or feature in set(info["strings"])
    if feature.startswith("L") and "." in feature:                    # e.g. Ljava.lang.Class.getMethods
        head, last = feature[1:].rsplit(".", 1)
        if last[:1].islower():                                        # method reference
            return ("L" + head.replace(".", "/") + ";", last) in refs
        return "L" + feature[1:].replace(".", "/") + ";" in types     # class reference
    if "." in feature and feature[0].isupper() and feature.count(".") == 1:   # e.g. Runtime.exec
        cls, meth = feature.split(".")
        meth = "<init>" if meth == "init" else meth
        return any(n == meth and _simple_name(c) == cls for c, n in refs)
    if "." in feature:                                                # e.g. android.os.Binder
        return "L" + feature.replace(".", "/") + ";" in types
    if feature[:1].isupper():                                         # e.g. ClassLoader, IBinder
        return any(_simple_name(t) == feature for t in types)
    return any(n == feature for _, n in refs)                         # e.g. transact, bindService


def build_feature_vector(info, feature_names):
    """Return a 1 x 215 DataFrame of 0/1 flags (same column order the model was trained on)."""
    present = {}
    strings = info["strings"]
    for f in feature_names:
        if f in COMMAND_FEATURES:
            ok = _command_present(f, strings)
        elif f in INTENT_FEATURES:
            ok = any(a == f or a.endswith("." + f) for a in info["actions"]) if f.startswith("intent.") \
                else f in info["actions"]
        elif re.fullmatch(r"[A-Z][A-Z_]+", f):                        # permissions (and SET_ALARM etc.)
            ok = f in info["permissions"]
        else:
            ok = _api_present(f, info)
        present[f] = int(bool(ok))
    return pd.DataFrame([present], columns=feature_names)


# =============================================================================
# 3. STATIC PREDICTION + SHAP EVIDENCE
# =============================================================================
_MODEL_CACHE = {}


def load_static_model(path=STATIC_MODEL_PATH):
    if path not in _MODEL_CACHE:
        import shap
        bundle = joblib.load(path)
        bundle["explainer"] = shap.TreeExplainer(bundle["xgb"])
        _MODEL_CACHE[path] = bundle
    return _MODEL_CACHE[path]


def predict_static(row, bundle, top_n=8, n_dex=None):
    p_rf = bundle["rf"].predict_proba(row)[:, 1]
    p_xgb = bundle["xgb"].predict_proba(row)[:, 1]
    prob = float((p_rf + p_xgb)[0] / 2)                               # same fusion as Phase 1
    sv = np.asarray(bundle["explainer"].shap_values(row))[0]
    order = np.argsort(-np.abs(sv))[:top_n]
    evidence = [{"feature": row.columns[i], "present": bool(row.iloc[0, i]), "shap": float(sv[i])}
                for i in order]
    shap_map = {str(row.columns[i]): float(sv[i]) for i in range(len(row.columns))}

    n_active = int(row.sum(axis=1).iloc[0]) if hasattr(row, "sum") else 0
    verdict_reason = None
    if n_dex is not None and n_dex == 0:
        verdict = "UNKNOWN"
        verdict_reason = "APK contains no compiled DEX code (n_dex=0); static classification cannot be determined reliably."
    elif n_active == 0:
        verdict = "UNKNOWN"
        verdict_reason = "All 215 static features are zero (n_active_features=0); APK may be packed, encrypted, or non-functional. Verdict cannot be determined as BENIGN."
    else:
        verdict = "MALWARE" if prob >= 0.5 else "BENIGN"

    return {
        "prob_malware": prob,
        "verdict": verdict,
        "verdict_reason": verdict_reason,
        "reason": verdict_reason,
        "evidence": evidence,
        "shap_map": shap_map,
        "shap_source": "XGBoost component of ensemble",
        "shap_note": "SHAP values represent local feature attributions for the XGBoost component. The ensemble prediction averages Random Forest and XGBoost outputs.",
        "n_dex": n_dex,
        "n_active_features": n_active,
    }


# =============================================================================
# 4. THREAT INTELLIGENCE: EXTRACT INDICATORS FROM THE APK
# =============================================================================
_URL_HOST = re.compile(r"(?:https?|ftp|wss?)://([^/\s:?#\"'<>@]+)(?::\d+)?", re.I)
_BARE_IP = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})(?::\d{1,5})?")
_DOMAIN = re.compile(r"^(?:[a-z0-9-]+\.)+[a-z]{2,}$")


def extract_indicators(strings):
    """Find public IPs (IPv4 and IPv6) and domain names embedded in an app's strings.
    Returns (ips, domains, n_ignored): dicts of indicator -> example string."""
    ips, domains, ignored = {}, {}, 0
    for s in strings:
        s = s.strip()
        if not s or len(s) > 2000:
            continue
        hosts = []
        # Check if bare string is an IP address
        try:
            bare_parsed = ipaddress.ip_address(s.strip("[]"))
            if bare_parsed.is_global and not (bare_parsed.is_multicast or bare_parsed.is_private or bare_parsed.is_loopback or bare_parsed.is_reserved):
                ips.setdefault(str(bare_parsed), s[:90])
                continue
        except ValueError:
            pass

        m = _BARE_IP.fullmatch(s)
        if m:
            hosts.append(m.group(1))
        hosts += [h.lower() for h in _URL_HOST.findall(s)]
        for h in hosts:
            try:
                ip = ipaddress.ip_address(h.strip("[]"))
            except ValueError:
                ip = None
            if ip is not None:
                if ip.is_global and not (ip.is_multicast or ip.is_private or ip.is_loopback or ip.is_reserved):
                    ips.setdefault(str(ip), s[:90])
                continue
            if _DOMAIN.match(h):
                if h.endswith(IGNORED_HOST_SUFFIXES):
                    ignored += 1
                else:
                    domains.setdefault(h, s[:90])
    return ips, domains, ignored


def resolve_domain(host, timeout=3.0):
    """Optional: DNS-resolve a domain to public IPs (this is a live DNS query from YOUR machine)."""
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        resolved_ips = []
        for a in socket.gethostbyname_ex(host)[2]:
            try:
                ip_obj = ipaddress.ip_address(a)
                if ip_obj.is_global and not (ip_obj.is_multicast or ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved):
                    resolved_ips.append(str(ip_obj))
            except ValueError:
                continue
        return sorted(set(resolved_ips))
    except Exception:
        return []
    finally:
        socket.setdefaulttimeout(old)


# =============================================================================
# 5. THREAT INTELLIGENCE: ABUSEIPDB LOOKUP
# =============================================================================
def check_ip(ip, api_key, max_age_days=90, timeout=15, http_get=None):
    """Ask AbuseIPDB about one IP. `http_get` lets tests inject a fake response."""
    # Pre-validate IP address
    try:
        parsed_ip = ipaddress.ip_address(ip.strip("[]"))
    except ValueError:
        raise ValueError(f"AbuseIPDB could not accept '{ip}' as an IP address.")

    if not parsed_ip.is_global or parsed_ip.is_multicast or parsed_ip.is_private or parsed_ip.is_loopback or parsed_ip.is_reserved:
        return {
            "ip": ip,
            "abuse_score": 0,
            "total_reports": 0,
            "country": None,
            "isp": None,
            "domain": None,
            "usage_type": None,
            "last_reported": None,
            "status": "skipped_private",
            "error": "IP is in a private, loopback, or reserved range.",
        }

    cached = _ti_cache_get(f"abuseipdb:{ip}")
    if cached is not None:
        return dict(cached)

    if http_get is None:
        import requests
        http_get = requests.get

    r = http_get(f"{ABUSE_API}/check", headers={"Key": api_key, "Accept": "application/json"},
                 params={"ipAddress": ip, "maxAgeInDays": max_age_days}, timeout=timeout)
    if r.status_code == 429:
        raise RuntimeError("AbuseIPDB rate limit reached (free plan: about 1,000 checks per day).")
    if r.status_code in (401, 403):
        raise RuntimeError("AbuseIPDB rejected the API key. Check that it was copied correctly.")
    if r.status_code == 422:
        raise ValueError(f"AbuseIPDB could not accept '{ip}' as an IP address.")
    r.raise_for_status()
    d = r.json()["data"]
    res = {
        "ip": ip,
        "abuse_score": int(d.get("abuseConfidenceScore", 0)),
        "total_reports": int(d.get("totalReports", 0)),
        "country": d.get("countryCode"),
        "isp": d.get("isp"),
        "domain": d.get("domain"),
        "usage_type": d.get("usageType"),
        "last_reported": d.get("lastReportedAt"),
        "status": "checked",
        "error": None,
    }
    _ti_cache_set(f"abuseipdb:{ip}", res)
    return res


def get_known_bad_ips(api_key, n=3, http_get=None):
    """Ask AbuseIPDB's blacklist for IPs it is 100% confident are abusive (for validation tests).
    The blacklist endpoint has a small daily quota on the free plan, so use it sparingly."""
    if http_get is None:
        import requests
        http_get = requests.get
    r = http_get(f"{ABUSE_API}/blacklist", headers={"Key": api_key, "Accept": "application/json"},
                 params={"confidenceMinimum": 100, "limit": n}, timeout=20)
    r.raise_for_status()
    return [row["ipAddress"] for row in r.json()["data"]][:n]


def risk_level(max_score):
    if max_score is None:
        return "none (no indicators checked)"
    return "HIGH" if max_score >= 75 else "MEDIUM" if max_score >= 25 else "LOW"


def threat_intel_features(results):
    """Summarise lookup results into the 3 threat-intelligence features."""
    scores = [r["abuse_score"] for r in results if r.get("abuse_score") is not None and r.get("status") == "checked"]
    mx = max(scores) if scores else None
    return {"max_abuse_score": mx if mx is not None else 0,
            "malicious_ip_count": sum(s >= MALICIOUS_THRESHOLD for s in scores),
            "network_risk": risk_level(mx)}


def validate_lookup(api_key, extra_ips=(), http_get=None):
    """Validation of the AbuseIPDB mechanism: harmless control IPs should score low,
    known-bad IPs from the AbuseIPDB blacklist should score high."""
    rows = []
    for ip, expect in [("8.8.8.8", "LOW (Google DNS)"), ("1.1.1.1", "LOW (Cloudflare DNS)")]:
        r = check_ip(ip, api_key, http_get=http_get); r["expected"] = expect; rows.append(r)
    try:
        for ip in get_known_bad_ips(api_key, 3, http_get=http_get):
            r = check_ip(ip, api_key, http_get=http_get); r["expected"] = "HIGH (blacklisted)"; rows.append(r)
    except Exception as e:
        print(f"(Could not fetch blacklist sample: {e}. Add a bad IP yourself via extra_ips.)")
    for ip in extra_ips:
        r = check_ip(ip, api_key, http_get=http_get); r["expected"] = "your choice"; rows.append(r)
    df = pd.DataFrame(rows)[["ip", "abuse_score", "total_reports", "country", "isp", "expected"]]
    print(df.to_string(index=False))
    return df


# =============================================================================
# 5b. URLHAUS THREAT INTELLIGENCE (abuse.ch)
# =============================================================================
def check_urlhaus_host(host, auth_key=None, timeout=10, http_post=None):
    cached = _ti_cache_get(f"urlhaus:{host}")
    if cached is not None:
        return cached
    """Query URLhaus API for a host (domain or IP).

    POST https://urlhaus-api.abuse.ch/v1/host/ with form field host=<domain or IP>
    and header Auth-Key read from env ABUSECH_AUTH_KEY or passed auth_key.

    Returns:
      - LISTED (with url_count): query_status == "ok"
      - NOT_LISTED: query_status == "no_results"
      - UNAVAILABLE: no key, timeout, HTTP error, or any other query_status.

    Critical safety rules:
      - An error must NEVER be reported as not listed or clean.
      - Timeout is 10 seconds.
      - Never print, log, store or export the key.
    """
    key = auth_key or os.environ.get("ABUSECH_AUTH_KEY")
    if not key or not str(key).strip():
        return {
            "status": "UNAVAILABLE",
            "host": host,
            "error": "No Auth-Key provided or configured in ABUSECH_AUTH_KEY environment variable",
        }

    headers = {"Auth-Key": str(key).strip()}
    data = {"host": host}

    if http_post is None:
        import requests
        http_post = requests.post

    try:
        r = http_post(URLHAUS_API_ENDPOINT, data=data, headers=headers, timeout=timeout)
    except Exception as exc:
        return {
            "status": "UNAVAILABLE",
            "host": host,
            "error": f"Request failed: {exc}",
        }

    if r.status_code != 200:
        return {
            "status": "UNAVAILABLE",
            "host": host,
            "error": f"HTTP {r.status_code}",
        }

    try:
        body = r.json()
    except Exception as exc:
        return {
            "status": "UNAVAILABLE",
            "host": host,
            "error": f"JSON decode failed: {exc}",
        }

    query_status = body.get("query_status")
    if query_status == "ok":
        raw_count = body.get("url_count")
        url_count = int(raw_count if raw_count is not None else len(body.get("urls") or []))
        res = {
            "status": "LISTED",
            "host": host,
            "url_count": url_count,
            "urlhaus_reference": body.get("urlhaus_reference"),
        }
        _ti_cache_set(f"urlhaus:{host}", res)
        return res
    elif query_status == "no_results":
        res = {
            "status": "NOT_LISTED",
            "host": host,
            "url_count": 0,
        }
        _ti_cache_set(f"urlhaus:{host}", res)
        return res
    else:
        # Any other query_status (e.g. no_auth, invalid_host, error) MUST be reported as UNAVAILABLE
        return {
            "status": "UNAVAILABLE",
            "host": host,
            "error": f"URLhaus query status: {query_status}",
        }


# =============================================================================
# 5c. SHANNON ENTROPY OF REGISTRABLE DOMAIN LABEL
# =============================================================================
def calculate_domain_entropy(domain_or_url):
    """Calculate Shannon entropy of the registrable domain label using tldextract in offline mode.

    Returns: label, entropy (rounded to 3 decimals), and flag = entropy > 3.4.

    Theoretical note:
    The maximum Shannon entropy for a string with k distinct characters is log2(k).
    For k = 10 distinct characters: log2(10) ≈ 3.3219 bits < 3.4.
    Therefore, labels with fewer than 11 distinct characters cannot exceed 3.4.
    At least 11 distinct characters are mathematically required to exceed the 3.4 threshold.
    """
    try:
        ext = _TLD_EXTRACTOR(domain_or_url)
        label = ext.domain
    except Exception:
        label = domain_or_url.split(".")[0] if "." in domain_or_url else domain_or_url

    if not label:
        return {
            "domain": domain_or_url,
            "label": "",
            "entropy": 0.0,
            "flag": False,
        }

    counts = collections.Counter(label)
    n = len(label)
    entropy = -sum((c / n) * math.log2(c / n) for c in counts.values())
    entropy_rounded = round(entropy, 3)
    flag = bool(entropy_rounded > ENTROPY_THRESHOLD)

    return {
        "domain": domain_or_url,
        "label": label,
        "entropy": entropy_rounded,
        "flag": flag,
    }


# =============================================================================
# 5d. MITRE ATT&CK CANDIDATE MAPPING (RULE-BASED)
# =============================================================================
def extract_attack_candidates(info, row=None, domain_entropy=None):
    """Rule-based MITRE ATT&CK candidate mapping. Always labelled 'candidate'.

    Mappings:
      - SEND_SMS or RECEIVE_SMS permission -> T1582 SMS Control
      - READ_SMS permission -> T1636.004 Protected User Data: SMS Messages
      - DexClassLoader reference -> T1407 Download New Code at Runtime
      - entropy-flagged domain -> T1637.001 Dynamic Resolution: DGA

    Negative rules:
      - Do NOT map su/chmod strings or a bare embedded IP to any technique.
      - Never invent data.
      - Store the exact evidence string.
    """
    candidates = []

    # Collect declared permissions
    perms = set()
    if info and "permissions" in info:
        perms.update(info["permissions"])
    if row is not None and hasattr(row, "columns"):
        for p in ["SEND_SMS", "RECEIVE_SMS", "READ_SMS"]:
            if p in row.columns and row.iloc[0][p] == 1:
                perms.add(p)

    # 1. SEND_SMS or RECEIVE_SMS permission -> T1582 SMS Control
    sms_control_ev = []
    if any(p.endswith("SEND_SMS") or p == "SEND_SMS" for p in perms):
        sms_control_ev.append("Declared permission: SEND_SMS")
    if any(p.endswith("RECEIVE_SMS") or p == "RECEIVE_SMS" for p in perms):
        sms_control_ev.append("Declared permission: RECEIVE_SMS")
    if sms_control_ev:
        candidates.append({
            "technique_id": "T1582",
            "technique_name": "SMS Control",
            "label": "candidate",
            "type": "heuristic / candidate",
            "evidence": "; ".join(sms_control_ev),
        })

    # 2. READ_SMS permission -> T1636.004 Protected User Data: SMS Messages
    if any(p.endswith("READ_SMS") or p == "READ_SMS" for p in perms):
        candidates.append({
            "technique_id": "T1636.004",
            "technique_name": "Protected User Data: SMS Messages",
            "label": "candidate",
            "type": "heuristic / candidate",
            "evidence": "Declared permission: READ_SMS",
        })

    # 3. DexClassLoader reference -> T1407 Download New Code at Runtime
    dexclass_ev = None
    if info:
        # Check string table
        for s in info.get("strings", []):
            if "DexClassLoader" in s:
                dexclass_ev = f"DEX string reference: {s}"
                break
        # Check type descriptors
        if not dexclass_ev:
            for t in info.get("type_descs", []):
                if "DexClassLoader" in t:
                    dexclass_ev = f"Class reference: {t}"
                    break
        # Check method references
        if not dexclass_ev:
            for cls, m in info.get("method_refs", []):
                if "DexClassLoader" in cls:
                    dexclass_ev = f"Method reference: {cls}->{m}"
                    break
    if not dexclass_ev and row is not None and hasattr(row, "columns"):
        for c in row.columns:
            if "DexClassLoader" in str(c) and row.iloc[0][c] == 1:
                dexclass_ev = f"Drebin feature present: {c}"
                break
    if dexclass_ev:
        candidates.append({
            "technique_id": "T1407",
            "technique_name": "Download New Code at Runtime",
            "label": "candidate",
            "type": "heuristic / candidate",
            "evidence": dexclass_ev,
        })

    # 4. entropy-flagged domain -> T1637.001 Dynamic Resolution: DGA
    if domain_entropy:
        for item in domain_entropy:
            if item.get("flag"):
                candidates.append({
                    "technique_id": "T1637.001",
                    "technique_name": "Dynamic Resolution: DGA",
                    "label": "candidate",
                    "type": "heuristic / candidate",
                    "evidence": f"Domain '{item.get('domain')}' (label '{item.get('label')}') has Shannon entropy {item.get('entropy'):.3f} > 3.4",
                })

    return candidates


# =============================================================================
# 6. FULL ANALYSIS OF ONE APK
# =============================================================================
def analyze_apk(apk_path, abuse_key=None, urlhaus_key=None, resolve_domains=False,
                model_path=STATIC_MODEL_PATH, top_n=8, verbose=True,
                http_get=None, http_post=None):
    info = extract_apk_info(apk_path)
    bundle = load_static_model(model_path)
    row = build_feature_vector(info, bundle["feature_names"])
    static = predict_static(row, bundle, top_n=top_n, n_dex=info.get("n_dex", 0))

    candidates = [x for x in info["strings"] + info["manifest_strings"]
                  if x.strip() != info["version_name"]]            # a version like 2.12.9.2 is not an IP
    ips, domains, n_ignored = extract_indicators(candidates)
    resolved = {}
    if resolve_domains:
        for d in domains:
            for ip in resolve_domain(d):
                resolved.setdefault(ip, d)
    lookups, lookup_error = [], None
    if abuse_key:
        unique_ips = []
        seen_ips = set()
        for ip in list(ips) + [i for i in resolved if i not in ips]:
            if ip not in seen_ips:
                seen_ips.add(ip)
                unique_ips.append(ip)

        for ip in unique_ips:
            try:
                res = check_ip(ip, abuse_key, http_get=http_get)
                res["source"] = ips.get(ip, f"resolved from {resolved.get(ip)}")
                lookups.append(res)
            except RuntimeError as e:
                # Fatal authentication or rate limit errors
                lookup_error = str(e)
                lookups.append({
                    "ip": ip,
                    "abuse_score": None,
                    "total_reports": 0,
                    "country": None,
                    "isp": None,
                    "domain": None,
                    "usage_type": None,
                    "last_reported": None,
                    "status": "failed",
                    "error": str(e),
                    "source": ips.get(ip, f"resolved from {resolved.get(ip)}"),
                })
                break
            except Exception as e:
                # Non-fatal error for specific IP
                lookups.append({
                    "ip": ip,
                    "abuse_score": None,
                    "total_reports": 0,
                    "country": None,
                    "isp": None,
                    "domain": None,
                    "usage_type": None,
                    "last_reported": None,
                    "status": "failed",
                    "error": str(e),
                    "source": ips.get(ip, f"resolved from {resolved.get(ip)}"),
                })

    ti = threat_intel_features(lookups) if abuse_key and not lookup_error else None

    # Feature 2: Registrable domain label Shannon entropy (offline tldextract)
    domain_entropy = [calculate_domain_entropy(d) for d in sorted(domains.keys())]

    # Feature 3: MITRE ATT&CK candidates (rule-based, always labelled candidate)
    attack_candidates = extract_attack_candidates(info, row=row, domain_entropy=domain_entropy)

    # Feature 1: URLhaus lookups (POST https://urlhaus-api.abuse.ch/v1/host/)
    urlhaus_results = []
    effective_urlhaus_key = urlhaus_key or os.environ.get("ABUSECH_AUTH_KEY")
    all_hosts = []
    seen_hosts = set()
    for host in list(ips.keys()) + list(domains.keys()):
        if host not in seen_hosts:
            seen_hosts.add(host)
            all_hosts.append(host)

    for host in all_hosts:
        if effective_urlhaus_key:
            try:
                res = check_urlhaus_host(host, auth_key=effective_urlhaus_key, timeout=10, http_post=http_post)
            except Exception as e:
                res = {
                    "status": "UNAVAILABLE",
                    "host": host,
                    "url_count": 0,
                    "error": f"URLhaus query error: {e}",
                }
        else:
            res = {
                "status": "UNAVAILABLE",
                "host": host,
                "url_count": 0,
                "error": "URLhaus lookup not queried: No Auth-Key provided or configured in ABUSECH_AUTH_KEY environment variable",
            }
        urlhaus_results.append(res)

    if not urlhaus_results:
        urlhaus_results.append({
            "status": "UNAVAILABLE",
            "host": "none",
            "url_count": 0,
            "error": "No embedded IP or domain hosts found in APK to query",
        })

    n_dex = int(info.get("n_dex", 0))
    n_active_features = int(row.sum(axis=1).iloc[0])

    result = {
        "info": info,
        "features": row,
        "static": static,
        "n_dex": n_dex,
        "n_active_features": n_active_features,
        "ips": ips,
        "domains": domains,
        "resolved": resolved,
        "lookups": lookups,
        "threat_features": ti,
        "lookup_error": lookup_error,
        "urlhaus": urlhaus_results,
        "domain_entropy": domain_entropy,
        "attack_candidates": attack_candidates,
    }
    if verbose:
        print_report(result, n_ignored, bool(abuse_key), resolve_domains)
    return result


def print_report(r, n_ignored, used_key, resolved_domains):
    info, st, row = r["info"], r["static"], r["features"]
    line = "=" * 66
    cats = {"permissions": 0, "intents": 0, "commands": 0, "API calls": 0}
    for f in row.columns[row.iloc[0] == 1]:
        k = "commands" if f in COMMAND_FEATURES else "intents" if f in INTENT_FEATURES else \
            "permissions" if re.fullmatch(r"[A-Z][A-Z_]+", f) else "API calls"
        cats[k] += 1
    print(line); print("APK ANALYSIS REPORT"); print(line)
    print(f"File: {os.path.basename(info['path'])}   Package: {info['package']}")
    if info["n_dex"] == 0:
        print("\n!! WARNING: this APK contains no compiled code (no .dex), so almost every feature is 0")
        print("   and the verdict below is NOT meaningful.")
    print("\n[1] STATIC ANALYSIS (Random Forest + XGBoost, trained on Drebin-215)")
    print(f"    Verdict            : {st['verdict']}   (malware probability {st['prob_malware']:.1%})")
    print(f"    Features detected  : {int(row.sum(axis=1).iloc[0])} of {row.shape[1]}  "
          f"({cats['permissions']} permissions, {cats['intents']} intents, "
          f"{cats['API calls']} API calls, {cats['commands']} commands)")
    print("    Top evidence (SHAP; + pushes toward MALWARE, - toward BENIGN):")
    for e in st["evidence"]:
        print(f"      {e['feature'][:44]:44s} {'present' if e['present'] else 'absent ':7s} {e['shap']:+.3f}")
    print("\n[2] THREAT INTELLIGENCE (indicators embedded in the app, checked on AbuseIPDB)")
    print(f"    Embedded public IPs: {len(r['ips'])}   |   domains: {len(r['domains'])}   "
          f"(ignored {n_ignored} common-infrastructure hosts)")
    for ip, ctx in list(r["ips"].items())[:10]:
        note = "  (standalone string, may be a version number)" if ctx.strip() == ip else ""
        print(f"      IP     {ip:16s} found in: {ctx}{note}")
    for d, ctx in list(r["domains"].items())[:10]:
        print(f"      domain {d:32s} found in: {ctx}")
    if r["domains"] and not resolved_domains:
        print("      (domains were NOT resolved to IPs; set resolve_domains=True to include them)")
    if not used_key:
        print("    AbuseIPDB lookup skipped (no API key given).")
    elif r["lookup_error"]:
        print(f"    AbuseIPDB lookup problem: {r['lookup_error']}")
    elif not r["lookups"]:
        print("    Nothing to look up (no public IPs found), so the network risk is unknown, not 'safe'.")
    else:
        for x in r["lookups"]:
            print(f"      {x['ip']:16s} abuse score {x['abuse_score']:3d}  reports {x['total_reports']:4d}  "
                  f"{x['country'] or '?'}  {x['isp'] or ''}")
        t = r["threat_features"]
        print(f"    Max abuse score {t['max_abuse_score']}  |  malicious IPs {t['malicious_ip_count']}  "
              f"|  network risk {t['network_risk']}")

    if r.get("domain_entropy"):
        print("\n[3] DOMAIN SHANNON ENTROPY (heuristic / candidate, threshold > 3.4)")
        for item in r["domain_entropy"][:10]:
            flag_str = "[FLAGGED DGA CANDIDATE]" if item.get("flag") else "normal"
            print(f"      domain: {item.get('domain'):30s} label: {item.get('label'):16s} entropy: {item.get('entropy'):.3f} ({flag_str})")

    if r.get("attack_candidates"):
        print("\n[4] MITRE ATT&CK CANDIDATES (heuristic / candidate)")
        for ac in r["attack_candidates"]:
            print(f"      [{ac['technique_id']}] {ac['technique_name']} (candidate) - {ac['evidence']}")

    if r.get("urlhaus"):
        print("\n[5] URLHAUS THREAT INTELLIGENCE (abuse.ch, heuristic / candidate)")
        for uh in r["urlhaus"]:
            print(f"      host: {uh.get('host'):25s} status: {uh.get('status')} (urls: {uh.get('url_count', 0)})")

    print("\nNOTE: embedded indicators are read from the app's code, not captured from live traffic.")
    print("      Some API/command features are matched by code search, so results approximate the benchmark.")
    print(line)


# =============================================================================
# 6b. HELPER FOR THE JUPYTER UPLOAD BUTTON (works with ipywidgets 7 and 8)
# =============================================================================
def save_uploaded_apk(widget_value, folder=None):
    """Write the file chosen in an ipywidgets FileUpload to disk and return its path."""
    import tempfile
    items = list(widget_value.values()) if isinstance(widget_value, dict) else list(widget_value)
    if not items:
        raise ValueError("No file was uploaded.")
    item = items[0]
    name = item.get("name") or item.get("metadata", {}).get("name") or "uploaded.apk"
    path = os.path.join(folder or tempfile.gettempdir(), os.path.basename(name))
    with open(path, "wb") as f:
        f.write(bytes(item["content"]))
    return path


# =============================================================================
# 7. COMMAND LINE:  python phase3_live_demo.py my_app.apk
# =============================================================================
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("usage: python phase3_live_demo.py path/to/app.apk")
        sys.exit(1)
    analyze_apk(
        sys.argv[1],
        abuse_key=os.environ.get("ABUSEIPDB_API_KEY") or os.environ.get("ABUSEIPDB_KEY"),
        urlhaus_key=os.environ.get("ABUSECH_AUTH_KEY"),
    )
