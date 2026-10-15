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
import warnings
import numpy as np
import pandas as pd
import joblib

warnings.filterwarnings("ignore")
logging.disable(logging.CRITICAL)
try:                                   # androguard logs a lot through loguru
    from loguru import logger
    logger.remove()
except Exception:
    pass

# -----------------------------------------------------------------------------
# >>> SETTINGS <<<
# -----------------------------------------------------------------------------
STATIC_MODEL_PATH = "static_outputs/static_model.joblib"   # saved by phase1_static.py
ABUSE_API = "https://api.abuseipdb.com/api/v2"
MALICIOUS_THRESHOLD = 50       # AbuseIPDB confidence score >= 50 counts as "malicious IP"

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


def predict_static(row, bundle, top_n=8):
    p_rf = bundle["rf"].predict_proba(row)[:, 1]
    p_xgb = bundle["xgb"].predict_proba(row)[:, 1]
    prob = float((p_rf + p_xgb)[0] / 2)                               # same fusion as Phase 1
    sv = np.asarray(bundle["explainer"].shap_values(row))[0]
    order = np.argsort(-np.abs(sv))[:top_n]
    evidence = [{"feature": row.columns[i], "present": bool(row.iloc[0, i]), "shap": float(sv[i])}
                for i in order]
    return {"prob_malware": prob, "verdict": "MALWARE" if prob >= 0.5 else "BENIGN", "evidence": evidence}


# =============================================================================
# 4. THREAT INTELLIGENCE: EXTRACT INDICATORS FROM THE APK
# =============================================================================
_URL_HOST = re.compile(r"(?:https?|ftp|wss?)://([^/\s:?#\"'<>@]+)(?::\d+)?", re.I)
_BARE_IP = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})(?::\d{1,5})?")
_DOMAIN = re.compile(r"^(?:[a-z0-9-]+\.)+[a-z]{2,}$")


def extract_indicators(strings):
    """Find public IPs and domain names embedded in an app's strings.
    Returns (ips, domains, n_ignored): dicts of indicator -> example string."""
    ips, domains, ignored = {}, {}, 0
    for s in strings:
        s = s.strip()
        if not s or len(s) > 2000:
            continue
        hosts = []
        m = _BARE_IP.fullmatch(s)
        if m:
            hosts.append(m.group(1))
        hosts += [h.lower() for h in _URL_HOST.findall(s)]
        for h in hosts:
            try:
                ip = ipaddress.ip_address(h)
            except ValueError:
                ip = None
            if ip is not None:
                if ip.is_global and not ip.is_multicast:              # drops 10.x, 192.168.x, 127.x, 0.0.0.0 ...
                    ips.setdefault(h, s[:90])
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
        return sorted({a for a in socket.gethostbyname_ex(host)[2] if ipaddress.ip_address(a).is_global})
    except Exception:
        return []
    finally:
        socket.setdefaulttimeout(old)


# =============================================================================
# 5. THREAT INTELLIGENCE: ABUSEIPDB LOOKUP
# =============================================================================
def check_ip(ip, api_key, max_age_days=90, timeout=15, http_get=None):
    """Ask AbuseIPDB about one IP. `http_get` lets tests inject a fake response."""
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
    return {"ip": ip, "abuse_score": int(d.get("abuseConfidenceScore", 0)),
            "total_reports": int(d.get("totalReports", 0)), "country": d.get("countryCode"),
            "isp": d.get("isp"), "domain": d.get("domain"), "usage_type": d.get("usageType"),
            "last_reported": d.get("lastReportedAt")}


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
    scores = [r["abuse_score"] for r in results]
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
# 6. FULL ANALYSIS OF ONE APK
# =============================================================================
def analyze_apk(apk_path, abuse_key=None, resolve_domains=False, model_path=STATIC_MODEL_PATH,
                top_n=8, verbose=True, http_get=None):
    info = extract_apk_info(apk_path)
    bundle = load_static_model(model_path)
    row = build_feature_vector(info, bundle["feature_names"])
    static = predict_static(row, bundle, top_n=top_n)

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
        try:
            for ip in list(ips) + [i for i in resolved if i not in ips]:
                res = check_ip(ip, abuse_key, http_get=http_get)
                res["source"] = ips.get(ip, f"resolved from {resolved.get(ip)}")
                lookups.append(res)
        except Exception as e:
            lookup_error = str(e)
    ti = threat_intel_features(lookups) if abuse_key and not lookup_error else None

    result = {"info": info, "features": row, "static": static, "ips": ips, "domains": domains,
              "resolved": resolved, "lookups": lookups, "threat_features": ti, "lookup_error": lookup_error}
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
    analyze_apk(sys.argv[1], abuse_key=os.environ.get("ABUSEIPDB_KEY"))