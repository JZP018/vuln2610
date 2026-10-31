import requests

url = "http://192.168.31.6/goform/setQuickset"

headers = {
    "Content-Type": "application/x-www-form-urlencoded",
    # The Host header is generated automatically by requests from the URL; usually no need to set it manually
}

data = {
    "password": "Peng456...",
}

resp = requests.post(url, headers=headers, data=data, timeout=10)

print("Status code:", resp.status_code)
print("Response headers:", resp.headers)
print("Response body:", resp.text)
