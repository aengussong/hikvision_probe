import requests
import sys
import select
from urllib.parse import urlparse
from requests.exceptions import SSLError
import urllib3
from urllib3.exceptions import InsecureRequestWarning

# Suppress the InsecureRequestWarning from being printed to std:out
urllib3.disable_warnings(InsecureRequestWarning)

def prepare_url(target_url, target_port):
    # Construct the full target URL
    full_url = f"{target_url}:{str(target_port)}"

    # Add default protocol if missing
    parsed = urlparse(full_url)
    if not parsed.scheme:
        if target_port == 443:
            full_url = f"https://{full_url}"
        else:
            full_url = f"http://{full_url}"
    return full_url

def check_hikvision(full_url):
    # Prepare the User-Agent header as in the original script
    user_agent = "Mozilla/5.0 (iPad; CPU OS 16_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Mobile/15E148 Safari/604.1"
    
    try:
        response = requests.get(full_url, headers={"User-Agent": user_agent}, verify=False, timeout=5)
        server_header = response.headers.get("Server", "").strip()
        content = response.text

        # Check if the response contains "/doc/page/login.asp?_"
        if "App-webs/" in server_header or "/doc/page/login.asp?_" in content:
            return True
        else:
            return False
    except SSLError as e: # can't connect via https, probably not hikvision, or it is misconfigured
        return False
    except requests.exceptions.ConnectionError as e: # peer closed connection, not hikvision or it isn't available
        return False
    except Exception as e:
        print(f"An exception occured: {e}")
        exit(1)

def main():
    # Read from standard input (stdin)
    # Use select to wait for input on stdin with a timeout
    stdin_ready, _, _ = select.select([sys.stdin], [], [], 2)

    # Check if stdin is ready
    if not stdin_ready:
        print("""
        Usage: cat ip_list.txt | python3 hikvision_identifier.py
        IPs in the ip_list.txt should be in the format 10.10.10.10
        """)
        sys.exit()

    urls = sys.stdin.read().splitlines()

    for url in urls:
        url = url.strip()  # Remove any leading/trailing whitespace

        full_url = prepare_url(url, 80)
        if check_hikvision(full_url):
            print(full_url)
        else:
            full_url = prepare_url(url, 443)
            if check_hikvision(full_url):
                print(full_url)

if __name__ == '__main__':
    main()
