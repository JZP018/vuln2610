import requests

# Request definition
req = {
    "method": "GET",
    "uri": "/goform/getLoginInfo",
    "header": "Host: 192.168.31.6",
    "body": "",
}

BASE_URL = "http://192.168.31.6"   # scheme + host; change to https:// if needed


def parse_headers(header_str: str) -> dict:
    """Parse a multi-line header string like 'Host: 192.168.31.6' into a dict."""
    headers = {}
    for line in header_str.splitlines():
        line = line.strip()
        if not line:
            continue
        key, _, value = line.partition(":")
        headers[key.strip()] = value.strip()
    return headers


url = BASE_URL + req["uri"]
headers = parse_headers(req["header"])
body = req["body"] or None          # no body for GET

resp = requests.request(
    method=req["method"],
    url=url,
    headers=headers,
    data=body,                      # None when body is empty
    timeout=10,
    verify=False,                   # routers often use self-signed certs; harmless over HTTP
)

print("URL:", resp.url)
print("Status code:", resp.status_code)
print("Response headers:", dict(resp.headers))
print("Response body:", resp.text)