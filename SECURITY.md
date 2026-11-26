# Security Policy and Configuration

## Download tool: deny by default

The `download_file_from_url` MCP tool now accepts only HTTPS URLs whose exact
hostname appears in `MCP_DOWNLOAD_ALLOWED_HOSTS`. The variable is a
comma-separated list of trusted hostnames (no wildcard matching). Downloads
from unlisted hosts are rejected.

Windows example (run in the same Command Prompt before `start.bat`):

```bat
set MCP_DOWNLOAD_ALLOWED_HOSTS=images.example.com,files.example.com
start.bat
```

The download client rejects non-public DNS answers, embedded URL credentials,
non-standard ports, and redirects. The response is capped at 25 MiB by default.
Operators can adjust the cap with `MCP_MAX_DOWNLOAD_BYTES` and the network
timeout with `MCP_DOWNLOAD_TIMEOUT` (seconds).

**Important limitation:** hostname resolution is checked before urllib opens
the connection; the current implementation does not pin the validated IP to
the socket. A hostile DNS operator could theoretically change the answer
between validation and connection. Treat the hostname allowlist as trusted
configuration, and do not allow domains controlled by untrusted users. A
follow-up hardening task must pin the resolved address at the transport layer.

## MCP transport DNS rebinding

DNS-rebinding protection is enabled with explicit Host and Origin allowlists.
The defaults permit only the local server:

```bat
set MCP_ALLOWED_HOSTS=127.0.0.1:8000,localhost:8000,[::1]:8000
set MCP_ALLOWED_ORIGINS=http://127.0.0.1:8000,http://localhost:8000,http://[::1]:8000
```

For a named HTTPS tunnel, add the exact public hostname (and the port form
actually forwarded by the proxy) to `MCP_ALLOWED_HOSTS`, for example:

```bat
set MCP_ALLOWED_HOSTS=127.0.0.1:8000,localhost:8000,pc-mcp.example.com,pc-mcp.example.com:443
```

If a browser client sends an Origin header, configure its exact trusted origin
in `MCP_ALLOWED_ORIGINS`. Do not use wildcard hostnames. Quick Tunnel creates
a changing hostname, so it requires a deliberate allowlist update for each
new hostname; the server intentionally does not accept arbitrary tunnel hosts.


The MCP SDK DNS-rebinding protection is enabled in both the compatibility path
and the primary Streamable HTTP app. Some reverse-proxy/tunnel hostnames may
need explicit allow-list configuration supported by the installed MCP SDK.
Do not disable this protection to work around host validation failures.

## Reporting

Do not publish secrets, tunnel tokens, authorization headers, or full
secret-bearing MCP endpoint URLs in issues or logs. Rotate `.mcp_secret`
immediately if it may have been exposed.
