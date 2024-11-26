from cve.CVE_2017_7921 import probe_keys
from cve.CVE_2021_36260 import probe_command_injection
from cve.CVE_2022_28171 import probe_blind_sqli
import select
import sys
import urllib3
from urllib3.exceptions import InsecureRequestWarning

# Suppress the InsecureRequestWarning from being printed to std:out
urllib3.disable_warnings(InsecureRequestWarning)

def main():
	# Read from standard input (stdin)
    # Use select to wait for input on stdin with a timeout
    stdin_ready, _, _ = select.select([sys.stdin], [], [], 2)

    # Check if stdin is ready
    if not stdin_ready:
        print("""
        Usage: cat uris.txt | python3 hikvision_probe.py
        URIs in the uris.txt should be in the format http://10.10.10.10:80
        """)
        sys.exit()

    urls = sys.stdin.read().splitlines()

    for url in urls:
        url = url.strip()
        print(f"Probing {url}")

        probe_keys(url)
        probe_command_injection(url)
        probe_blind_sqli(url)

        print("\n")


if __name__ == '__main__':
    main()