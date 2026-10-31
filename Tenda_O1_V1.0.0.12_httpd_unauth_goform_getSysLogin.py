import requests
import urllib3

urllib3.disable_warnings()          # Suppress self-signed certificate warnings

req = {
    "method": "GET",
    "uri": "/goform/getSysLogin",
    "header": "Host: 192.168.31.6",
    "body": "",
}

BASE_URL = "http://192.168.31.6"    # Change to https:// if the device uses HTTPS


def parse_headers(header_str: str) -> dict:
    """Parse a multi-line header string like 'Host: 192.168.31.6' into a dict."""
    headers = {}
    for line in (header_str or "").splitlines():
        line = line.strip()
        if not line:
            continue
        key, _, value = line.partition(":")
        headers[key.strip()] = value.strip()
    return headers


url = BASE_URL + req["uri"]
headers = parse_headers(req["header"])
body = req["body"] or None          # No body for GET

resp = requests.request(
    method=req["method"].upper(),
    url=url,
    headers=headers,
    data=body,
    timeout=10,
    verify=False,
)

print("URL:", resp.url)
print("Status code:", resp.status_code)
print("Response headers:", dict(resp.headers))
print("Response body:", resp.text)