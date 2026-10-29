"""Feature explanation and anomaly interpretation engine for Android malware detection.

Provides domain-specific security explanations for Drebin-215 static features
(permissions, sensitive API calls, intent filters, shell commands) and CICMalDroid
dynamic system calls, interpreting their presence, local SHAP contributions, and
contextual security relevance.
"""

from typing import Any


DANGEROUS_PERMISSIONS: dict[str, dict[str, str]] = {
    "SEND_SMS": {
        "description": "Allows sending SMS messages directly without user interaction or confirmation.",
        "security_context": "Frequently abused by premium SMS Trojans and spyware to subscribe users to paid services or exfiltrate credentials.",
        "risk_level": "high",
    },
    "RECEIVE_SMS": {
        "description": "Allows monitoring and intercepting incoming SMS messages before the user reads them.",
        "security_context": "Commonly exploited by banking malware to intercept two-factor authentication (2FA) SMS verification codes.",
        "risk_level": "high",
    },
    "READ_SMS": {
        "description": "Allows reading stored SMS messages on the device.",
        "security_context": "Used by spyware and financial fraud malware to harvesting private conversations and banking authentication codes.",
        "risk_level": "high",
    },
    "READ_PHONE_STATE": {
        "description": "Allows read-only access to phone state, including cellular network, SIM serial, and device IMEI/IMSI numbers.",
        "security_context": "Standard for telemetry, but aggressively used by adware and spyware for persistent hardware fingerprinting and tracking.",
        "risk_level": "medium",
    },
    "CALL_PHONE": {
        "description": "Allows initiating phone calls without going through the Dialer user interface.",
        "security_context": "Can be abused to call premium-rate numbers automatically in toll fraud attacks.",
        "risk_level": "high",
    },
    "ACCESS_FINE_LOCATION": {
        "description": "Allows accessing precise geographical location using GPS, Wi-Fi, and cellular cell tower data.",
        "security_context": "Provides exact GPS coordinates; heavily targeted by stalkerware, tracking trojans, and location-harvesting ad SDKs.",
        "risk_level": "high",
    },
    "ACCESS_COARSE_LOCATION": {
        "description": "Allows accessing approximate geographical location derived from network location providers (Wi-Fi/cell).",
        "security_context": "Enables regional tracking; widespread in both benign applications and tracking adware.",
        "risk_level": "medium",
    },
    "CAMERA": {
        "description": "Allows capturing photos and videos using device camera hardware at any time.",
        "security_context": "Sensitive hardware access; abused by remote access trojans (RATs) and surveillance malware.",
        "risk_level": "high",
    },
    "RECORD_AUDIO": {
        "description": "Allows recording audio streams using device microphone hardware.",
        "security_context": "Highly intrusive capability; weaponized by espionage tools and spyware for ambient eavesdropping.",
        "risk_level": "high",
    },
    "READ_CONTACTS": {
        "description": "Allows reading the user's stored address book contacts and account relationships.",
        "security_context": "Targeted by contact-scraping worms, extortion ransomware, and phishing campaigns to propagate to contacts.",
        "risk_level": "high",
    },
    "WRITE_CONTACTS": {
        "description": "Allows modifying or inserting contacts into the user's address book.",
        "security_context": "Used by social-engineering Trojans to inject spoofed support contacts or alter directory entries.",
        "risk_level": "medium",
    },
    "READ_CALL_LOG": {
        "description": "Allows reading historical incoming, outgoing, and missed telephony call records.",
        "security_context": "Reveals sensitive communication metadata and personal habits; high privacy risk in surveillance apps.",
        "risk_level": "high",
    },
    "WRITE_CALL_LOG": {
        "description": "Allows modifying or deleting records from the device call history log.",
        "security_context": "Malware often deletes outgoing premium call records or incoming verification calls to conceal fraudulent activity.",
        "risk_level": "high",
    },
    "READ_EXTERNAL_STORAGE": {
        "description": "Allows reading shared files, photos, downloads, and documents on external storage (SD card).",
        "security_context": "Broad access to user files, photos, and cached database files; susceptible to data exfiltration.",
        "risk_level": "medium",
    },
    "WRITE_EXTERNAL_STORAGE": {
        "description": "Allows writing, modifying, and deleting files on shared external storage.",
        "security_context": "Enables dropping secondary APK payloads or staging encrypted files during ransomware attacks.",
        "risk_level": "medium",
    },
    "INSTALL_PACKAGES": {
        "description": "Allows initiating application package installations directly without Play Store mediation.",
        "security_context": "Typical of dropper malware, alternative app markets, and modular Trojan loaders.",
        "risk_level": "high",
    },
    "SYSTEM_ALERT_WINDOW": {
        "description": "Allows drawing overlay windows on top of any active foreground application.",
        "security_context": "Key enabler for overlay attacks, credential harvesting fake login screens, and clickjacking.",
        "risk_level": "high",
    },
    "GET_ACCOUNTS": {
        "description": "Allows querying the list of registered user accounts (e.g. Google, social networks) on the device.",
        "security_context": "Used in target profiling and credential theft campaigns to identify user identities.",
        "risk_level": "medium",
    },
    "USE_CREDENTIALS": {
        "description": "Allows requesting authentication authtokens from the Android AccountManager service.",
        "security_context": "Permits authentication token reuse; critical attack surface if abused by malicious third-party apps.",
        "risk_level": "high",
    },
    "RECEIVE_BOOT_COMPLETED": {
        "description": "Allows the application to receive a broadcast notification when the system finishes booting.",
        "security_context": "Allows establishing boot persistence and autostarting background services without user launching the app.",
        "risk_level": "medium",
    },
    "INTERNET": {
        "description": "Allows creating network sockets and communicating over the Internet.",
        "security_context": "Essential for network services and ad SDKs; enables C2 communication and exfiltration in malware.",
        "risk_level": "standard",
    },
}

SUSPICIOUS_APIS: dict[str, dict[str, str]] = {
    "DexClassLoader": {
        "description": "Loads compiled classes and executable DEX bytecode dynamically from secondary `.jar` or `.apk` files.",
        "security_context": "Primary technique for payload dropping, packer unpacking, and post-installation code injection that evades static scans.",
        "risk_level": "high",
    },
    "PathClassLoader": {
        "description": "Standard Android class loader for reading classes from local application package paths.",
        "security_context": "Commonly used for legitimate modular loading, but can be leveraged in reflection-based evasion.",
        "risk_level": "standard",
    },
    "ClassLoader": {
        "description": "Base Java class loader abstraction for resolving and instantiating dynamic types at runtime.",
        "security_context": "Broad dynamic reflection indicator; monitored to detect runtime class manipulation.",
        "risk_level": "standard",
    },
    "Runtime.exec": {
        "description": "Executes native command-line binaries in a separate Linux OS subshell process.",
        "security_context": "Permits executing local shell commands (`su`, `chmod`, `sh`); heavily correlated with root exploits and backdoor tooling.",
        "risk_level": "high",
    },
    "ProcessBuilder": {
        "description": "Constructs and manages operating system process creation with redirected inputs and outputs.",
        "security_context": "Similar to Runtime.exec; used to launch native ARM/x86 binaries packaged inside application assets.",
        "risk_level": "high",
    },
    "TelephonyManager.getDeviceId": {
        "description": "Retrieves hardware device identifier strings (such as IMEI or MEID).",
        "security_context": "Aggressively collected by surveillance Trojans and ad trackers for persistent device fingerprinting across reinstalls.",
        "risk_level": "high",
    },
    "TelephonyManager.getSubscriberId": {
        "description": "Retrieves the unique subscriber identifier (IMSI) associated with the cellular SIM card.",
        "security_context": "Enables cellular subscriber tracking and carrier-specific fraud targeting.",
        "risk_level": "high",
    },
    "TelephonyManager.getSimSerialNumber": {
        "description": "Retrieves the physical SIM card serial number (ICCID).",
        "security_context": "Used in SIM-swap detection or identity binding by commercial spyware.",
        "risk_level": "medium",
    },
    "sendTextMessage": {
        "description": "Transmits raw SMS text messages directly through the cellular radio.",
        "security_context": "Classic signature of SMS premium billing fraud and out-of-band communication.",
        "risk_level": "high",
    },
    "Ljava.lang.Class.getMethod": {
        "description": "Reflectively discovers and inspects declared methods on Java classes at runtime.",
        "security_context": "Obfuscation and evasion tactic used to hide sensitive API invocations from static signature engines.",
        "risk_level": "medium",
    },
    "Ljava.lang.Class.getMethods": {
        "description": "Reflectively enumerates all public methods on a class.",
        "security_context": "Reflection signature; frequently paired with dynamic class loading to invoke hidden payloads.",
        "risk_level": "medium",
    },
    "Ljava.lang.Class.forName": {
        "description": "Resolves and loads a Java class reflectively by its string identifier.",
        "security_context": "Enables string-obfuscated reflection where method and class targets are decrypted only in memory.",
        "risk_level": "medium",
    },
    "HttpURLConnection": {
        "description": "Standard Java HTTP client library for outbound web requests.",
        "security_context": "Ubiquitous in apps; provides transport for both legitimate web traffic and command-and-control communication.",
        "risk_level": "standard",
    },
    "HttpClient": {
        "description": "Legacy Apache HTTP client library for network transactions.",
        "security_context": "Older HTTP transport API; used by legacy apps and older malware families for network callbacks.",
        "risk_level": "standard",
    },
    "Cipher": {
        "description": "Java Cryptography Architecture (JCA) cryptographic cipher engine for encryption and decryption.",
        "security_context": "Standard for securing data, but frequently used by packers and ransomware to decrypt secondary stages or lock user files.",
        "risk_level": "medium",
    },
    "KeyguardManager": {
        "description": "Controls lockscreen states and credential challenge prompts.",
        "security_context": "Screen lock bypass or ransom lockscreen overlay techniques often interact with Keyguard services.",
        "risk_level": "high",
    },
    "transact": {
        "description": "Performs low-level IPC Binder transactions across Android process boundaries.",
        "security_context": "Underlies all Android system service communication; direct calls often indicate low-level IPC manipulation.",
        "risk_level": "standard",
    },
    "bindService": {
        "description": "Binds an application component to a background Service for inter-process communication.",
        "security_context": "Standard architectural primitive; exploited when binding to unexported or privileged service interfaces.",
        "risk_level": "standard",
    },
    "android.os.IBinder": {
        "description": "Base interface for remoting objects through the high-performance Android Binder IPC subsystem.",
        "security_context": "Core IPC mechanism; foundational to both legitimate service architecture and privilege escalation probes.",
        "risk_level": "standard",
    },
}

INTENT_FILTER_DESCRIPTIONS: dict[str, dict[str, str]] = {
    "android.intent.action.BOOT_COMPLETED": {
        "description": "System broadcast delivered when Android completes booting and the user unlocks the device.",
        "security_context": "Common persistence mechanism used by malware to maintain survival across device reboots.",
        "risk_level": "medium",
    },
    "android.intent.action.PACKAGE_ADDED": {
        "description": "Broadcast triggered when a new application package has been installed on the device.",
        "security_context": "Monitored by security software, but also abused by malware to detect antivirus installations or launch droppers.",
        "risk_level": "medium",
    },
    "android.intent.action.PACKAGE_REPLACED": {
        "description": "Broadcast triggered when an existing application has been updated with a new version.",
        "security_context": "Used to reinstall persistence hooks or re-trigger payload execution after an app update.",
        "risk_level": "medium",
    },
    "android.intent.action.NEW_OUTGOING_CALL": {
        "description": "Broadcast broadcast when the user dials an outgoing telephone call.",
        "security_context": "Can be intercepted to block calls to emergency services or redirect calls in phishing attacks.",
        "risk_level": "high",
    },
    "android.intent.action.ACTION_POWER_CONNECTED": {
        "description": "Broadcast delivered when external power is connected to the device.",
        "security_context": "Crypto-miners and battery-heavy botnets use this trigger to delay resource-intensive tasks until plugged in.",
        "risk_level": "standard",
    },
}

COMMAND_DESCRIPTIONS: dict[str, dict[str, str]] = {
    "su": {
        "description": "Switch User binary used to request Superuser (root) elevated privileges.",
        "security_context": "Direct root execution indicator; indicates the application attempts to break out of Android's user sandbox.",
        "risk_level": "high",
    },
    "mount": {
        "description": "Linux mount command for mounting filesystems.",
        "security_context": "Often used in root exploits to remount `/system` as read-write (`rw`) to install persistent system backdoors.",
        "risk_level": "high",
    },
    "remount": {
        "description": "Filesystem remount directive.",
        "security_context": "Directly associated with modifying read-only system partitions in rooted environments.",
        "risk_level": "high",
    },
    "chmod": {
        "description": "Changes file mode bits and executable permissions.",
        "security_context": "Routinely used by native malware droppers to set execution permissions (`chmod 777` or `chmod +x`) on dropped ELF binaries.",
        "risk_level": "high",
    },
    "chown": {
        "description": "Changes ownership of files and directories.",
        "security_context": "Alters user/group permissions in exploit payloads.",
        "risk_level": "medium",
    },
    "/system/bin": {
        "description": "Path to core Android system executable binaries.",
        "security_context": "Referencing system binary directories indicates interaction with native utilities rather than Android Java SDKs.",
        "risk_level": "medium",
    },
    "/system/app": {
        "description": "System partition path where pre-installed system applications reside.",
        "security_context": "Attempting to write or inspect `/system/app` is typical of persistence Trojans trying to convert to system apps.",
        "risk_level": "high",
    },
}

SYSCALL_DESCRIPTIONS: dict[str, dict[str, str]] = {
    "mprotect": {
        "category": "Memory Protection",
        "description": "Sets memory protection flags (Read, Write, Execute) on a region of process virtual memory.",
        "investigation_reason": "Frequently invoked when unpacking encrypted payloads, JIT compilers, or executing shellcode in RWX memory segments.",
        "benign_context": "Also legitimate in modern Android ART runtime JIT engines and native gaming libraries.",
    },
    "execve": {
        "category": "Process Execution",
        "description": "Executes a new program by replacing the current process image with an executable binary.",
        "investigation_reason": "Indicates execution of an external or dropped native binary (e.g. `/system/bin/sh` or extracted ELF executable).",
        "benign_context": "Rare in standard Android apps which rely on Binder IPC, making unexpected occurrences suspicious.",
    },
    "clone": {
        "category": "Process Execution",
        "description": "Creates a child process or new execution thread sharing virtual address space.",
        "investigation_reason": "High frequency indicates multi-threading or subprocess spawning for background operational tasks.",
        "benign_context": "Standard behavior in multi-threaded Android apps, UI rendering engines, and network thread pools.",
    },
    "socket": {
        "category": "Network Sockets",
        "description": "Creates an unbound endpoint for network socket communication (AF_INET, AF_INET6, or AF_UNIX).",
        "investigation_reason": "Direct socket instantiation; should be correlated with expected application network features and destination IPs.",
        "benign_context": "Universal in any application utilizing internet connectivity, analytics, or HTTP REST APIs.",
    },
    "connect": {
        "category": "Network Sockets",
        "description": "Initiates a connection on a socket to a specified remote IP address and port.",
        "investigation_reason": "Signals active outbound network transmission; warrants correlation with threat intelligence and C2 indicators.",
        "benign_context": "Standard for all outbound internet connections including HTTPS, DNS, and telemetry services.",
    },
    "bind": {
        "category": "Network Sockets",
        "description": "Binds a local network address and listening port to a socket.",
        "investigation_reason": "Opening local listening ports can expose local IPC vulnerabilities or establish reverse shells.",
        "benign_context": "Occasionally used for local peer-to-peer, debugging servers, or media streaming services.",
    },
    "openat": {
        "category": "File System",
        "description": "Opens a file descriptor relative to a directory file descriptor.",
        "investigation_reason": "High volume of file opens across sensitive directories (`/proc`, `/data/data`, `/system`) may indicate file scraping or evasion checks.",
        "benign_context": "Standard I/O operation for loading assets, shared libraries, and application preferences.",
    },
    "unlink": {
        "category": "File System",
        "description": "Deletes a name from the filesystem and frees its inode if no processes hold it open.",
        "investigation_reason": "Suspicious when observed deleting temporary dropper artifacts, log files, or self-clearing traces.",
        "benign_context": "Common in cache management, file cleanup, and temporary download handling.",
    },
    "ioctl": {
        "category": "IPC & System Services",
        "description": "Device-specific input/output control operations.",
        "investigation_reason": "In Android, predominantly handles `/dev/binder` IPC transactions; anomalous patterns reflect aggressive system service queries.",
        "benign_context": "Standard mechanism for all Android framework service calls (ActivityManager, WindowManager).",
    },
    "ptrace": {
        "category": "Process Execution",
        "description": "Enables one process to observe and control the execution of another process.",
        "investigation_reason": "Heavily utilized in anti-debugging, anti-emulation, code injection, and runtime hooking detection.",
        "benign_context": "Rarely present in commercial consumer apps; common in security tools, cheat engines, or malware.",
    },
    "_newselect": {
        "category": "Core I/O",
        "description": "Monitors multiple file descriptors to see if any are ready for reading or writing.",
        "investigation_reason": "High activity reflects polling loops across sockets or IPC channels.",
        "benign_context": "Universal event-loop primitive in Android and Linux network libraries.",
    },
    "epoll_wait": {
        "category": "Core I/O",
        "description": "Waits for I/O events on an epoll file descriptor.",
        "investigation_reason": "Part of modern high-performance asynchronous networking and UI event processing.",
        "benign_context": "Standard foundation for Android message looper (`ALooper`) and network runtimes.",
    },
}


def classify_static_feature(name: str) -> str:
    """Classify a Drebin-215 feature into one of 4 categories."""
    if name in COMMAND_DESCRIPTIONS or name in {"mount", "chmod", "remount", "chown", "/system/bin", "/system/app"}:
        return "shell_command"
    if name in INTENT_FILTER_DESCRIPTIONS or name.startswith("android.intent.action.") or name.startswith("intent.action."):
        return "intent_filter"
    if name.isupper() and "_" in name:
        return "permission"
    if name.isupper() and len(name) > 2 and not name.startswith("L"):
        return "permission"
    return "api_call"


def explain_static_feature(
    feature: str,
    present: bool,
    shap_value: float | None = None,
) -> dict[str, Any]:
    """Generate structured explanation and contextual security interpretation for a static feature."""
    category = classify_static_feature(feature)
    desc_info = None
    if category == "permission":
        desc_info = DANGEROUS_PERMISSIONS.get(feature)
    elif category == "api_call":
        for k, v in SUSPICIOUS_APIS.items():
            if k in feature or feature.endswith(k):
                desc_info = v
                break
    elif category == "intent_filter":
        desc_info = INTENT_FILTER_DESCRIPTIONS.get(feature)
    elif category == "shell_command":
        desc_info = COMMAND_DESCRIPTIONS.get(feature)

    default_desc = {
        "permission": f"Android manifest permission: {feature}.",
        "api_call": f"Framework API or method call reference: {feature}.",
        "intent_filter": f"Broadcast intent action filter: {feature}.",
        "shell_command": f"Underlying Linux shell command indicator: {feature}.",
    }[category]

    description = desc_info["description"] if desc_info else default_desc
    security_context = desc_info.get("security_context") if desc_info else (
        "Part of the Drebin-215 feature representation evaluated by the ensemble classifier."
    )
    risk_level = desc_info.get("risk_level", "standard") if desc_info else "standard"

    direction = "neutral"
    interpretation = ""
    if shap_value is not None:
        if shap_value > 0:
            direction = "toward_malware"
            interpretation = (
                f"Feature is {'present' if present else 'absent'} in this APK and pushed the ensemble "
                f"prediction toward the MALWARE class (SHAP impact: +{shap_value:.4f})."
            )
        elif shap_value < 0:
            direction = "toward_benign"
            interpretation = (
                f"Feature is {'present' if present else 'absent'} in this APK and pushed the ensemble "
                f"prediction toward the BENIGN class (SHAP impact: {shap_value:.4f})."
            )
        else:
            direction = "neutral"
            interpretation = "Feature had negligible net attribution for this sample."
    else:
        interpretation = f"Observed status: {'Present' if present else 'Absent'}."

    interpretation += (
        " Note: Indicator presence alone does not establish malicious intent; significance "
        "depends on overall model context and co-occurring features."
    )

    return {
        "feature": feature,
        "category": category,
        "present": present,
        "shap": shap_value,
        "direction": direction,
        "risk_level": risk_level,
        "description": description,
        "security_context": security_context,
        "interpretation": interpretation,
    }


def explain_dynamic_syscall(
    syscall: str,
    count: int,
    shap_value: float | None = None,
) -> dict[str, Any]:
    """Generate structured explanation and investigation justification for a dynamic system call."""
    info = SYSCALL_DESCRIPTIONS.get(syscall, {
        "category": "General System Call",
        "description": f"Linux kernel system call '{syscall}'.",
        "investigation_reason": "Observed during live execution under runtime strace capture.",
        "benign_context": "Routine kernel service used across standard Android processes.",
    })

    direction = "neutral"
    if shap_value is not None:
        if shap_value > 0:
            direction = "toward_malware"
        elif shap_value < 0:
            direction = "toward_benign"

    interpretation = (
        f"Executed {count:,} time{'s' if count != 1 else ''} during runtime sandbox emulation. "
        f"{info['investigation_reason']} "
        f"Caveat: {info['benign_context']} Does not confirm malicious behavior on its own."
    )

    return {
        "syscall": syscall,
        "count": count,
        "category": info["category"],
        "shap": shap_value,
        "direction": direction,
        "description": info["description"],
        "investigation_reason": info["investigation_reason"],
        "benign_context": info["benign_context"],
        "interpretation": interpretation,
    }
