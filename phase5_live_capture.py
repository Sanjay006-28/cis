# =============================================================================
# PHASE 5: LIVE DYNAMIC ANALYSIS  (Android emulator + adb + strace)
#   1. check_setup()          -> tells you what your emulator can/can't do (run this FIRST)
#   2. capture_syscalls(apk)  -> installs the app, launches it, simulates taps with `monkey`,
#                                counts its system calls with `strace -c`
#   3. analyze_dynamic(apk)   -> capture + convert to the model's 139 syscall features + prediction
#
# SAFETY: this RUNS the app. Use only an emulator (never a real phone), with no personal accounts,
#         and prefer a fresh emulator snapshot for unknown or suspicious apps.
# HONESTY: the model was trained on CICMalDroid2020 (a different Android version / CPU / run length).
#          A live prediction is a demonstration of the pipeline, NOT a validated result.
# =============================================================================
import os
import re
import sys
import time
import shutil
import subprocess
import logging
import warnings
import joblib
import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")
logging.disable(logging.CRITICAL)
try:                                  # Androguard prints a lot of debug text through loguru
    from loguru import logger
    logger.remove()
except Exception:
    pass

# -----------------------------------------------------------------------------
# >>> SETTINGS <<<
# -----------------------------------------------------------------------------
BUNDLE_PATH = "dynamic_outputs_v2/dynamic_model.joblib"     # saved by phase2_dynamic_v2.py
REMOTE_OUT = "/data/local/tmp/strace_out.txt"
REMOTE_STRACE = "/data/local/tmp/strace"                    # where you push strace if the image has none

# strace reports names of the CPU it runs on; the training data used 32-bit ARM names.
# This maps the common differences to the CICMalDroid2020 139-feature vocabulary.
# Anything not listed or with no in-vocabulary target remains unmapped.
#
# Semantic Classification:
# 1. Exact Architecture / ABI Adaptations (identical userland operation, adjusting for 32/64-bit width, LFS offsets, or ARM calling convention):
#    - fstatfs -> fstatfs64, statfs -> statfs64 (64-bit filesystem statistics struct adaptation)
#    - fstat -> fstat64, stat -> stat64, lstat -> lstat64 (64-bit file status struct adaptation)
#    - mmap -> mmap2, lseek -> _llseek, select -> _newselect, fcntl -> fcntl64, ftruncate -> ftruncate64 (64-bit offset & ABI adaptations)
#    - getuid/geteuid/getgid/getegid/setuid/setgid -> *32 (32-bit UID/GID credential adaptations)
#    - cacheflush -> __arm_nr_cacheflush, set_tls -> __arm_nr_set_tls (ARM-specific architecture syscall numbers)
# 2. Approximate Behavioral Groupings (differing signatures, signal masks, or directory-relative *at scopes grouped to closest training counterpart):
#    - ppoll -> poll (adds nanosecond precision and atomic sigmask; grouped by shared I/O event polling function)
#    - epoll_pwait -> epoll_wait (adds sigmask parameter for atomic unmasking; grouped by epoll wait function)
#    - newfstatat / fstatat64 -> fstat64 (directory-relative stat taking dirfd and AT_SYMLINK_NOFOLLOW; grouped to stat family)
#    - openat -> open (POSIX *at directory-relative file open with flags relative to dirfd)
#    - readlinkat -> readlink (POSIX *at symbolic link target inspection relative to dirfd)
#    - fchmodat -> chmod (POSIX *at file mode change by pathname relative to dirfd)
#    - mkdirat -> mkdir (POSIX *at directory creation relative to dirfd)
#    - unlinkat -> unlink (POSIX *at file removal; in modern kernels also handles rmdir when AT_REMOVEDIR flag is passed)
#    - renameat / renameat2 -> rename (POSIX *at file move/rename; renameat2 adds exchange/noreplace flags)
# Note: 'sendfile' and 'truncate64' are not in the 139-feature training vocabulary;
# unmapped calls remain in unmapped_counts without silent feature meaning changes.
ALIASES = {
    "mmap": "mmap2", "lseek": "_llseek", "fstat": "fstat64", "stat": "stat64", "lstat": "lstat64",
    "select": "_newselect", "fcntl": "fcntl64", "getuid": "getuid32", "geteuid": "geteuid32",
    "getgid": "getgid32", "getegid": "getegid32", "setuid": "setuid32", "setgid": "setgid32",
    "openat": "open", "cacheflush": "__arm_nr_cacheflush", "set_tls": "__arm_nr_set_tls",
    "ftruncate": "ftruncate64",
    "newfstatat": "fstat64", "fstatat64": "fstat64", "epoll_pwait": "epoll_wait",
    # Modern Android 14 / x86_64 system call compatibility mappings
    "ppoll": "poll",
    "fstatfs": "fstatfs64",
    "statfs": "statfs64",
    "readlinkat": "readlink",
    "fchmodat": "chmod",
    "mkdirat": "mkdir",
    "unlinkat": "unlink",
    "renameat": "rename",
    "renameat2": "rename",
}

_DYNAMIC_BUNDLE_CACHE = {}
_DYNAMIC_SHAP_CACHE = {}


def get_dynamic_bundle(bundle_path=BUNDLE_PATH):
    """Load and cache the dynamic model bundle in memory."""
    if bundle_path not in _DYNAMIC_BUNDLE_CACHE:
        _DYNAMIC_BUNDLE_CACHE[bundle_path] = joblib.load(bundle_path)
    return _DYNAMIC_BUNDLE_CACHE[bundle_path]


def get_dynamic_explainer(bundle_path=BUNDLE_PATH):
    """Reuse initialized SHAP TreeExplainer for the shares model."""
    if bundle_path not in _DYNAMIC_SHAP_CACHE:
        import shap
        b = get_dynamic_bundle(bundle_path)
        _DYNAMIC_SHAP_CACHE[bundle_path] = shap.TreeExplainer(b["xgb_share"])
    return _DYNAMIC_SHAP_CACHE[bundle_path]


# =============================================================================
# adb helpers
# =============================================================================
def find_adb():
    if os.environ.get("ADB_PATH"):
        return os.environ["ADB_PATH"]
    exe = shutil.which("adb")
    if exe:
        return exe
    name = "adb.exe" if os.name == "nt" else "adb"
    bases = [os.environ.get("ANDROID_HOME"), os.environ.get("ANDROID_SDK_ROOT"),
             os.path.join(os.environ.get("LOCALAPPDATA", ""), "Android", "Sdk")]
    for b in bases:
        if b and os.path.exists(os.path.join(b, "platform-tools", name)):
            return os.path.join(b, "platform-tools", name)
    return None


def _adb_cmd(args, device=None):
    exe = find_adb()
    if not exe:
        raise RuntimeError("adb was not found. Install Android Studio (it includes platform-tools) "
                           "or add the platform-tools folder to your PATH.")
    return [exe] + (["-s", device] if device else []) + list(args)


def adb(*args, timeout=60, device=None):
    """Run an adb command, return (exit_code, stdout, stderr)."""
    r = subprocess.run(_adb_cmd(args, device), capture_output=True, text=True, timeout=timeout)
    return r.returncode, (r.stdout or "").strip(), (r.stderr or "").strip()


def sh(command, **kw):
    return adb("shell", command, **kw)


def list_devices():
    _, out, _ = adb("devices")
    return [ln.split()[0] for ln in out.splitlines()[1:] if ln.strip() and ln.split()[-1] == "device"]


def find_strace(device=None):
    """Return the path of a working strace on the device, or None."""
    for cand in ["strace", REMOTE_STRACE, "/system/xbin/strace", "/system/bin/strace"]:
        code, out, _ = sh(f"{cand} -V 2>&1 | head -1", device=device)
        if "strace" in out.lower() and "not found" not in out.lower() and "inaccessible" not in out.lower():
            return cand
    return None


# =============================================================================
# 1. SETUP CHECK
# =============================================================================
def check_setup(device=None):
    ok = True

    def line(good, text):
        print(("  [OK]   " if good else "  [FAIL] ") + text)
        return good

    print("PHASE 5 SETUP CHECK\n")
    if not line(find_adb() is not None, f"adb found: {find_adb()}"):
        print("\n  -> Install Android Studio (includes platform-tools), or add platform-tools to PATH.")
        return {"ready": False, "step": "adb"}
    devs = list_devices()
    if not line(len(devs) > 0, f"emulator/device connected: {devs or 'none'}"):
        print("\n  -> Start an emulator first (Android Studio > Device Manager > Play), wait until the home screen shows,")
        print("     then run this check again.")
        return {"ready": False, "step": "device"}
    device = device or devs[0]
    if len(devs) > 1:
        print(f"  note: several devices found {devs}; using {device}. Pass device='...' to choose.")
    if not any(device.startswith(p) for p in ("emulator-", "127.0.0.1", "localhost")):
        print(f"  WARNING: '{device}' does not look like an emulator. Do NOT run unknown apps on a real phone.")

    props = {k: sh(f"getprop {k}", device=device)[1] for k in
             ["ro.build.version.release", "ro.build.version.sdk", "ro.product.cpu.abi", "ro.build.type", "ro.kernel.qemu"]}
    print(f"  info:  Android {props['ro.build.version.release']} (API {props['ro.build.version.sdk']}), "
          f"CPU {props['ro.product.cpu.abi']}, build type '{props['ro.build.type']}'")

    adb("root", device=device); time.sleep(1.5)
    code, out, _ = sh("id", device=device)
    is_root = "uid=0" in out
    ok &= line(is_root, f"root access via `adb root`: {out[:40] if out else 'no answer'}")
    if not is_root:
        print("\n  -> `adb root` only works on emulator images named 'Google APIs' (NOT 'Google Play').")
        print("     Create a new virtual device in Android Studio using a 'Google APIs' system image.")

    strace = find_strace(device)
    ok &= line(strace is not None, f"strace on the device: {strace or 'not found'}")
    if strace is None:
        print(f"\n  -> This emulator image has no strace. You must push one built for CPU '{props['ro.product.cpu.abi']}':")
        print(f"       adb push strace {REMOTE_STRACE}")
        print(f"       adb shell chmod 755 {REMOTE_STRACE}")
        print("     (a static strace binary for that CPU is needed; tell Claude the CPU and Android version above.)")

    mk = sh("which monkey", device=device)[1]
    ok &= line(bool(mk), f"monkey (random tap generator): {mk or 'not found'}")
    ok &= line(os.path.exists(BUNDLE_PATH), f"Phase 2 v2 model file: {BUNDLE_PATH}")
    print("\nRESULT: " + ("READY. You can run analyze_dynamic('your_app.apk')." if ok else "NOT READY. Fix the [FAIL] lines above."))
    return {"ready": ok, "device": device, "strace": strace, "props": props}


# =============================================================================
# 2. CAPTURE
# =============================================================================
_ROW = re.compile(r"^\s*\d+(?:\.\d+)?\s+\d+\.\d+\s+\d+\s+(\d+)(?:\s+\d+)?\s+([A-Za-z_][A-Za-z0-9_]*)\s*$")


def parse_proc_net_connections(proc_net_text):
    """Extract remote public IPv4 destinations from emulator /proc/net/tcp output."""
    import ipaddress
    found_ips = set()
    for line in proc_net_text.splitlines():
        parts = line.strip().split()
        if len(parts) < 4 or ":" not in parts[2]:
            continue
        rem_hex = parts[2]
        try:
            ip_hex, port_hex = rem_hex.split(":")
            ip_int = int.from_bytes(bytes.fromhex(ip_hex), byteorder="little")
            port = int(port_hex, 16)
            ip_obj = ipaddress.IPv4Address(ip_int)
            s_ip = str(ip_obj)
            # Filter out private, loopback, multicast, and emulator gateway (10.0.2.x)
            if not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_reserved or not ip_obj.is_global):
                if not s_ip.startswith("10.0.2."):
                    found_ips.add((s_ip, port))
        except Exception:
            pass
    return sorted(found_ips)


def parse_strace_summary(text):
    """Parse the table printed by `strace -c` into {syscall_name: number_of_calls}."""
    counts = {}
    for ln in text.splitlines():
        m = _ROW.match(ln)
        if m and m.group(2) != "total":
            counts[m.group(2)] = counts.get(m.group(2), 0) + int(m.group(1))
    return counts


def package_name(apk_path):
    from androguard.core.apk import APK
    return APK(apk_path).get_package()


def has_launcher_activity(apk_path):
    """Check whether the APK declares an Activity with LAUNCHER intent filter category."""
    try:
        from androguard.core.apk import APK
        apk = APK(apk_path)
        for act in apk.get_activities():
            filters = apk.get_intent_filters("activity", act)
            actions = filters.get("action", [])
            categories = filters.get("category", [])
            if any("MAIN" in str(a) for a in actions) and any("LAUNCHER" in str(c) for c in categories):
                return True
        return False
    except Exception:
        return True


def capture_syscalls(apk_path, seconds=60, uninstall=True, device=None, throttle_ms=300, verbose=True):
    """Install + run the app on the emulator, simulate user input, and count its system calls."""
    say = print if verbose else (lambda *a, **k: None)
    devs = list_devices()
    if not devs:
        raise RuntimeError("No emulator is connected. Start one first.")
    device = device or devs[0]
    pkg = package_name(apk_path)
    adb("root", device=device); time.sleep(1.5)
    if "uid=0" not in sh("id", device=device)[1]:
        raise RuntimeError("No root access. Run check_setup() and follow its instructions.")
    strace = find_strace(device)
    if not strace:
        raise RuntimeError("strace was not found on the emulator. Run check_setup() and follow its instructions.")

    # Normalize APK path for ADB so Windows adb.exe (common in WSL setups) can resolve it
    install_path = apk_path
    try:
        rel = os.path.relpath(apk_path)
        if not rel.startswith(".."):
            install_path = rel
        elif shutil.which("wslpath"):
            wpath = subprocess.check_output(["wslpath", "-w", apk_path], text=True).strip()
            if wpath:
                install_path = wpath
    except Exception:
        pass

    say(f"[1/5] installing {pkg} ...")
    if not has_launcher_activity(apk_path):
        raise RuntimeError(
            f"APK '{os.path.basename(apk_path)}' declares no launcher activity (no android.intent.category.LAUNCHER). "
            "Monkey requires a launchable component to execute the app. Service-only or background components cannot be traced via UI fuzzing."
        )
    code, out, err = adb("install", "-r", "-g", install_path, timeout=180, device=device)
    if "Success" not in out:
        raise RuntimeError(f"Install failed: {(out + ' ' + err)[:300]}")
    procs = []
    try:
        say("[2/5] launching the app ...")
        sh(f"monkey -p {pkg} -c android.intent.category.LAUNCHER 1", device=device)
        pid = ""
        for _ in range(15):
            time.sleep(1)
            out = sh(f"pidof {pkg}", device=device)[1]
            pid = out.split()[0] if out else ""
            if pid:
                break
        if not pid:
            raise RuntimeError("The app did not start (no process found). It may have crashed or needs a newer Android version.")

        say(f"[3/5] tracing system calls of process {pid} for {seconds} s while simulating taps ...")
        sh(f"rm -f {REMOTE_OUT}", device=device)
        p_strace = subprocess.Popen(_adb_cmd(["shell", f"{strace} -c -f -p {pid} -o {REMOTE_OUT}"], device),
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        procs.append(p_strace)
        time.sleep(2)
        if p_strace.poll() is not None:
            raise RuntimeError(f"strace stopped immediately: {(p_strace.stderr.read() or p_strace.stdout.read())[:300]}")
        events = max(50, int(seconds * 1000 / throttle_ms))
        p_monkey = subprocess.Popen(_adb_cmd(["shell", f"monkey -p {pkg} --throttle {throttle_ms} --ignore-crashes "
                                              f"--ignore-timeouts --ignore-security-exceptions -s 42 "
                                              f"--pct-syskeys 0 {events}"], device),
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True)
        procs.append(p_monkey)
        t0 = time.time()
        runtime_connections = set()
        while time.time() - t0 < seconds:
            time.sleep(1)
            # Sample live TCP sockets established by the running processes
            try:
                code, net_out, _ = sh("cat /proc/net/tcp /proc/net/tcp6 2>/dev/null", device=device)
                if code == 0 and net_out:
                    for ip_port in parse_proc_net_connections(net_out):
                        runtime_connections.add(ip_port)
            except Exception:
                pass
            if p_strace.poll() is not None:
                break                                        # strace ended early (the app probably exited)

        say("[4/5] stopping the trace and collecting the counts ...")
        sh("pkill -INT strace || kill -2 $(pidof strace)", device=device)
        try:
            p_strace.wait(timeout=20)
        except subprocess.TimeoutExpired:
            p_strace.terminate()
        p_monkey.terminate()
        sh(f"pkill monkey || kill $(pidof monkey)", device=device)
        local = os.path.join(os.path.dirname(os.path.abspath(apk_path)) or ".", "strace_out.txt")
        adb("pull", REMOTE_OUT, local, device=device)
        text = open(local, errors="ignore").read() if os.path.exists(local) else ""
        counts = parse_strace_summary(text)
        if not counts:
            raise RuntimeError("No system-call counts were captured (the output file was empty). "
                               "The app may have exited right away, or strace could not attach.")
        trace_meta = {
            "trace_start_method": "post_launch",
            "trace_boundary": "Capture started after application launch via strace attach; process initialization and native library load calls prior to attach may be absent from this trace.",
            "pid": pid,
            "runtime_connections": [{"ip": ip, "port": port} for ip, port in sorted(runtime_connections)],
        }
        return {"package": pkg, "pid": pid, "seconds": seconds, "counts": counts, "raw_text": text, "trace_metadata": trace_meta, "runtime_connections": [{"ip": ip, "port": port} for ip, port in sorted(runtime_connections)]}
    finally:
        for p in procs:
            try:
                if p.poll() is None:
                    p.terminate()
            except Exception:
                pass
        try:
            sh("pkill -2 strace 2>/dev/null || pkill -9 strace 2>/dev/null; pkill -9 monkey 2>/dev/null", device=device)
        except Exception:
            pass
        if uninstall:
            say("[5/5] uninstalling the app ...")
            try:
                adb("uninstall", pkg, timeout=60, device=device)
            except Exception:
                pass


# =============================================================================
# 3. MAP TO THE MODEL AND PREDICT
# =============================================================================
def map_to_model(counts, vocabulary):
    """Convert strace names to the model's syscall names. Returns (mapped_counts, coverage, unmapped)."""
    vocab = set(vocabulary)
    mapped, unmapped = {}, {}
    for name, n in counts.items():
        target = name if name in vocab else ALIASES.get(name)
        if target in vocab:
            mapped[target] = mapped.get(target, 0) + n
        else:
            unmapped[name] = n
    total = sum(counts.values()) or 1
    return mapped, sum(mapped.values()) / total, dict(sorted(unmapped.items(), key=lambda kv: -kv[1]))


def predict_from_counts(mapped, bundle_path=BUNDLE_PATH):
    b = get_dynamic_bundle(bundle_path)
    row = pd.DataFrame([[mapped.get(s, 0) for s in b["all_syscalls"]]], columns=b["all_syscalls"])
    shares = row.div(row.sum(axis=1).replace(0, 1), axis=0)
    out = {"counts": float(b["xgb"].predict_proba(row[b["top_features"]])[:, 1][0]),
           "shares": float(b["xgb_share"].predict_proba(shares[b["top_features"]])[:, 1][0])}
    try:                                                      # which syscalls drove the (shares) decision
        explainer = get_dynamic_explainer(bundle_path)
        sv = np.asarray(explainer.shap_values(shares[b["top_features"]]))[0]
        order = np.argsort(-np.abs(sv))[:6]
        out["evidence"] = [(b["top_features"][i], float(row[b["top_features"][i]].iloc[0]), float(sv[i])) for i in order]
    except Exception:
        out["evidence"] = []
    return out


def report(result, mapped, coverage, unmapped, pred):
    line = "=" * 66
    print(line); print("LIVE DYNAMIC ANALYSIS REPORT"); print(line)
    print(f"Package: {result['package']}   traced for {result['seconds']} s   "
          f"system calls counted: {sum(result['counts'].values()):,}")
    print(f"Matched to the model's vocabulary: {coverage:.0%} of all calls "
          f"({len(mapped)} of the model's syscalls were seen)")
    if coverage < 0.8:
        print("  WARNING: under 80% of the calls matched, so this emulator's syscall names differ a lot from the")
        print("  training data. Treat the prediction below as unreliable. Unmatched, most frequent:",
              ", ".join(list(unmapped)[:6]))
    print("\nMalware probability:")
    print(f"   model on normalised shares (recommended for live runs): {pred['shares']:.1%}")
    print(f"   model on raw counts                                    : {pred['counts']:.1%}")
    if pred.get("evidence"):
        print("\nSystem calls that mattered most (shares model; + toward MALWARE, - toward BENIGN):")
        for name, cnt, sv in pred["evidence"]:
            print(f"   {name:22s} count={cnt:<9g} {sv:+.3f}")
    print("\nNOTE: the model was trained on CICMalDroid2020 (older Android, ARM, longer runs). A live run on a")
    print("      different emulator is a demonstration of the pipeline, not a validated detection result.")
    print(line)


def analyze_dynamic(apk_path, seconds=60, bundle_path=BUNDLE_PATH, uninstall=True, device=None, verbose=True):
    res = capture_syscalls(apk_path, seconds=seconds, uninstall=uninstall, device=device, verbose=verbose)
    return analyze_counts(res, bundle_path, verbose)


def analyze_counts(result, bundle_path=BUNDLE_PATH, verbose=True):
    """Turn captured counts into a prediction (also usable on a saved `strace -c` text file, see below)."""
    vocab = get_dynamic_bundle(bundle_path)["all_syscalls"]
    mapped, coverage, unmapped = map_to_model(result["counts"], vocab)
    pred = predict_from_counts(mapped, bundle_path)
    if verbose:
        report(result, mapped, coverage, unmapped, pred)
    return {"result": result, "mapped": mapped, "coverage": coverage, "unmapped": unmapped, "prediction": pred}


def analyze_strace_file(path, package="(from file)", seconds=0, bundle_path=BUNDLE_PATH):
    """No emulator needed: analyse a text file that holds the output of `strace -c`."""
    text = open(path, errors="ignore").read()
    return analyze_counts({"package": package, "pid": "-", "seconds": seconds, "counts": parse_strace_summary(text),
                           "raw_text": text}, bundle_path)


def _to_json_safe(obj):
    """Recursively convert numpy / pandas types to plain Python for json.dumps."""
    import numpy as np
    if isinstance(obj, dict):
        return {k: _to_json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_json_safe(i) for i in obj]
    if isinstance(obj, np.integer):
        return int(obj)
    if isinstance(obj, np.floating):
        return float(obj)
    if isinstance(obj, np.ndarray):
        return obj.tolist()
    return obj


if __name__ == "__main__":
    # Parse optional --json-out PATH from the end of argv
    _args = sys.argv[1:]
    _json_out_path = None
    if "--json-out" in _args:
        _idx = _args.index("--json-out")
        if _idx + 1 < len(_args):
            _json_out_path = _args[_idx + 1]
            _args = _args[:_idx] + _args[_idx + 2:]   # remove flag + value

    if len(_args) >= 1 and _args[0] == "check":
        check_setup()
    elif len(_args) >= 2 and _args[0] == "run":
        _apk  = _args[1]
        _secs = int(_args[2]) if len(_args) > 2 else 60
        _out  = analyze_dynamic(_apk, seconds=_secs)
        if _json_out_path and _out:
            import json
            try:
                with open(_json_out_path, "w") as _jf:
                    json.dump(_to_json_safe(_out), _jf, indent=2)
            except Exception as _je:
                print(f"[json-out] WARNING: could not write {_json_out_path}: {_je}")
    else:
        print("usage:  python phase5_live_capture.py check\n        python phase5_live_capture.py run your_app.apk [seconds]")