import requests

url = "http://192.168.31.6/goform/setQuickset"

headers = {
    "Content-Type": "application/x-www-form-urlencoded",
    # Host 头由 requests 自动根据 url 生成，一般无需手动设置
}

data = {
    "password": "Peng456...",
}

resp = requests.post(url, headers=headers, data=data, timeout=10)

print("状态码:", resp.status_code)
print("响应头:", resp.headers)
print("响应体:", resp.text)