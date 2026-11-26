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

DNS answers are validated and the selected public IP is pinned to the
HTTPS socket. TLS certificate validation and SNI continue to use the original
hostname. This closes the validation-to-connect DNS rebinding gap for this
download path. The exact hostname allowlist must still contain only domains
trusted by the local operator.

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
Quick Tunnel workflow: start `start.bat`, wait for the cloudflared hostname,
close the server window, set
`MCP_ALLOWED_HOSTS=127.0.0.1:8000,localhost:8000,<hostname>` and run
`python server.py` again. The tunnel keeps forwarding to port 8000; only the
server needs the new allowlist. `start.bat` prints the same hint.

The MCP SDK DNS-rebinding protection is enabled in both the compatibility path
and the primary Streamable HTTP app. Some reverse-proxy/tunnel hostnames may
need explicit allow-list configuration supported by the installed MCP SDK.
Do not disable this protection to work around host validation failures.

## Reporting

Do not publish secrets, tunnel tokens, authorization headers, or full
secret-bearing MCP endpoint URLs in issues or logs. Rotate `.mcp_secret`
immediately if it may have been exposed.

## Workspace filesystem protections

Workspace paths reject absolute paths, parent traversal, hidden system
components (`.git`, `.env`, `.mcp_secret`, `.tunnel_token`), symbolic links,
and Windows reparse points. Hidden names are compared case-insensitively, so
`.GIT` and `.Env` are rejected as well. Path components with trailing dots or
spaces, Windows-invalid characters, and reserved device names (`NUL`, `CON`,
`COM1`, ...) are rejected. After resolution the final path is validated again,
which covers Windows 8.3 short-name aliases such as `MCP_SE~1`.

Reads open the file first and then verify type, identity, and size on the open
descriptor, so a file swapped or grown between validation and read is rejected
or truncated to the limit. File writes use a same-directory temporary file
followed by an atomic replace, and the real parent directory is re-checked
against the workspace root before the temporary file is created and again
before the replace. Append is implemented as a locked read-and-replace
operation. `list_files` does not follow links and stops at a configurable
entry count and directory depth.

Writes are refused for extensions that Python or Windows load or execute:
`.py .pyw .pyc .pyo .pyd .pyz .pyzw .pth .so .bat .cmd .com .exe .dll .scr
.pif .cpl .msi .msp .msc .ps1 .psm1 .ps1xml .ps2 .psc1 .vbs .vbe .js .jse
.wsf .wsc .wsh .hta .sct .lnk .scf .url .reg`. The default workspace is the
application directory, which is also `sys.path[0]`; a written `.pyc` or `.pyd`
would shadow a standard-library import at the next start.

Limits are positive integers read from the environment at startup:

- `MCP_MAX_FILE_BYTES`: read, write, Base64 payload, and download cap (25 MiB).
- `MCP_MAX_LIST_ENTRIES`: maximum entries returned by `list_files` (5000).
- `MCP_MAX_LIST_DEPTH`: maximum directory depth walked by `list_files` (32).
- `MCP_COMMAND_TIMEOUT`: seconds before an allowed command is killed (15).

The Streamable HTTP transport of `mcp` 2.x caps request bodies at 4 MiB, so a
single Base64 `write_file` payload above roughly 3 MiB is rejected by the
transport before the tool runs. Use `[APPEND_BASE64]:` chunks for larger
files; the tool-level cap is `MCP_MAX_FILE_BYTES`.

Residual risk: the append lock is process-local: it prevents concurrent
writes handled by threads in this server process, but is not a cross-process
lock. The final parent-directory check and `os.replace` are still separate
operations, so a local actor with write access to the workspace parent could
race directory replacement (TOCTOU). Run the server under a dedicated OS
account and ensure untrusted users cannot modify the workspace root or its
parent. A follow-up platform-specific openat/handle-relative implementation
is required for strong cross-process and hostile-local-user race resistance.

## Command execution

`run_allowed_command` runs a fixed argv list (no shell) with `cwd` set to the
workspace, a hard timeout (`MCP_COMMAND_TIMEOUT`), output capped at 256 KiB,
and `MCP_SECRET` removed from the child environment. `git_status` runs with
`--no-optional-locks -c core.fsmonitor=false` so a repository-controlled
fsmonitor hook is not executed by a status call. Git still reads the other
repository configuration, so do not treat `git_status` on an untrusted
repository as a hardened boundary.

## Secret handling

The secret is compared with `hmac.compare_digest` on bytes for both the URL
prefix and the Bearer header, so a non-ASCII `Authorization` header gets 404
instead of a server error. `.mcp_secret` is created exclusively (`O_EXCL`)
and flushed to disk before it is read back; an empty file stops the server
with an instruction instead of silently generating a new secret. The uvicorn
access log is filtered so the secret-bearing URL path is replaced with
`<redacted>`. `.mcp_secret` and `.tunnel_token` are hidden from MCP reads and
listings.
