"""
Utility to check port availability, test HTTP services, and find active ports.
"""
import sys
import socket
import argparse
import urllib.request

def can_bind(port: int, host: str = "127.0.0.1") -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        return True
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass

def check_health(port: int) -> int:
    url = f"http://127.0.0.1:{port}/api/health"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "AntigravityLauncher/1.0"})
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            content = resp.read().decode("utf-8", errors="ignore")
            if "status" in content or resp.getcode() == 200:
                return 0
    except Exception:
        pass
    return 1

def check_frontend(port: int) -> int:
    url = f"http://localhost:{port}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "AntigravityLauncher/1.0"})
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            if resp.getcode() == 200:
                return 0
    except Exception:
        pass
    return 1

def pick_backend_port() -> int:
    # 1. If backend is already running on 8000, reuse 8000
    if check_health(8000) == 0:
        print("8000")
        return 0
    # 2. If backend is already running on 8001, reuse 8001
    if check_health(8001) == 0:
        print("8001")
        return 0
    # 3. Otherwise, check if 8000 can be bound
    if can_bind(8000):
        print("8000")
        return 0
    # 4. Fall back to 8001
    if can_bind(8001):
        print("8001")
        return 0
    # 5. Fall back to 8002
    print("8002")
    return 0

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["health", "frontend", "pick_backend_port", "can_bind"])
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()

    if args.action == "health":
        sys.exit(check_health(args.port))
    elif args.action == "frontend":
        sys.exit(check_frontend(args.port))
    elif args.action == "pick_backend_port":
        sys.exit(pick_backend_port())
    elif args.action == "can_bind":
        sys.exit(0 if can_bind(args.port) else 1)
