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

The download client rejects non-public DNS answers (including the IPv6
translation prefixes `64:ff9b::/96`, `2002::/16` and `::ffff:0:0:0/96`, which can carry a
private IPv4 address), embedded URL credentials, non-standard ports, and
redirects. The response is capped at 25 MiB by default.
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

The default workspace is the `workspace/` subdirectory next to `server.py`,
not the application directory. The application directory is `sys.path[0]` and
holds the dependency and CI configuration of the server itself, so MCP never
writes there by default. Set `MCP_WORKSPACE` to point the tools at another
folder. A relative `MCP_WORKSPACE` resolves against the application folder,
not against the directory the server was started from. A drive-relative
value such as `D:sub` or `D:` is refused, because Windows would resolve it
against the live or remembered directory of that drive. The server refuses to
start when that folder is a filesystem root or the user's home directory; use
a dedicated folder for AI output. The guard compares the resolved path as a
string after removing the Windows `\\?\` prefix. It does not map UNC admin
shares such as `\\localhost\c$\Users\me` onto a local path, and it is advice
against a typo, not a boundary: the operator controls `MCP_WORKSPACE`.

Workspace paths reject absolute paths, parent traversal, hidden system
components, symbolic links, and Windows reparse points. Hidden names are
compared case-insensitively and support globs:

- Server secrets: `.mcp_secret`, `.mcp_secret.*`, `.tunnel_token`, `.tunnel_token.*`, `.git`.
- Environment files: `.env*` (`.env.local`, `.env.production`, `.envrc`),
  `*.env`, `*.env[-._~#0-9]*` and `#*.env#*` (`prod.env`, `prod.env.bak`,
  `prod.env-old`, `prod.env_1`, `prod.env2`, `prod.env~`, `prod.env#`,
  `#prod.env#`). Names such as `prod.environment` stay readable.
- Credential stores: `.ssh`, `.aws`, `.azure`, `.gnupg`, `.kube`, `.docker`,
  `.netrc`, `_netrc`, `.git-credentials`, `.npmrc`, `.pypirc`, `.gitconfig`,
  `.vault-token`, `.pgpass`, `.htpasswd`.
- Key material: `id_rsa*`, `id_dsa*`, `id_dss*`, `id_xmss*`, `id_ed25519*`,
  `id_ecdsa*`, `private-key*`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.jks`,
  `*.keystore`, `*.ppk`, `*.kdbx`.
- Write staging: `.mcp-tmp-*`, so an in-flight or crashed write is not readable.

Hidden names cannot be read, written, or listed. Other secrets inside the
workspace (for example `credentials.json` or `terraform.tfstate`) are still
readable: the workspace is not a secret boundary, so keep real secrets out
of it.

Path components with trailing dots or spaces, Windows-invalid characters,
and reserved device names (`NUL`, `CON`, `COM1`, `COM¹`, `CONOUT$`, ...) are
rejected. After resolution the final path is validated again, which covers
Windows 8.3 short-name aliases such as `MCP_SE~1`.

Reads open the file first and then verify type, identity, and size on the open
descriptor, so a file swapped or grown between validation and read is rejected
or truncated to the limit. File writes use a same-directory temporary file
followed by an atomic replace. The real parent directory is checked against
the workspace root before any directory is created, inside the lock, and
again before the replace. Append is implemented as a locked read-and-replace
operation. `list_files` does not follow links and stops at a configurable
entry count and directory depth.

Writes are refused in two cases.

1. By extension, for files that an interpreter or the operating system loads
   or runs: `.py .pyw .pyc .pyo .pyd .pyz .pyzw .pth .so .dylib .ocx .bat
   .cmd .com .exe .dll .scr .pif .cpl .msi .msp .msc .msix .appx .ps1 .psm1
   .ps1xml .ps2 .psc1 .vbs .vbe .js .jse .wsf .wsc .wsh .hta .sct .sh .bash
   .zsh .fish .ksh .cjs .mjs .rb .pl .pm .php .lua .tcl .jar .command .tool
   .scpt .applescript .terminal .inetloc .desktop .service .lnk .scf .url
   .reg`. A `.pyc` or `.pyd` next to a script shadows standard-library
   imports, and a `.sh` or `.cjs` runs the moment a shell or Node is pointed
   at it.
2. By name, for files that tooling runs or loads without the user opening
   them: dependency manifests (`requirements*.txt`, `pyproject.toml`,
   `setup.cfg`, `Pipfile*`, `poetry.lock`, `uv.lock`, `package.json`,
   `*-lock.json`, `*-lock.yaml`, `yarn.lock`, `bun.lock`, `.yarnrc.yml`,
   `.npmrc`, `Cargo.toml`, `Cargo.lock`, `build.rs`, `go.mod`, `go.sum`,
   `go.work`, `Gemfile*`, `composer.json`, `composer.lock`, `Podfile`,
   `Podfile.lock`, `pubspec.yaml`, `pubspec_overrides.yaml`, `pubspec.lock`,
   `gradle.lockfile`,
   `gradle.properties`, `settings.gradle`, `settings.gradle.kts`,
   `packages.config`, `packages.lock.json`, `nuget.config`), CI
   configuration (`.github`, `.gitlab`, `.gitlab-ci.yml`, `.circleci`,
   `.buildkite`, `.gitea`, `.forgejo`, `Jenkinsfile`, `.travis.yml`,
   `appveyor.yml`, `azure-pipelines.yml`, `.drone.yml`, `.woodpecker.yml`,
   `.pre-commit-config.yaml`, `.husky`, `.huskyrc`, `.huskyrc.*`,
   `*lefthook*.yml`, `*lefthook*.yaml`), build files
   (`Makefile`, `Dockerfile*`, `docker-compose*.yml`, `compose*.yaml`,
   `Containerfile`, `pom.xml`, `build.gradle*`, `CMakeLists.txt`,
   `configure`, `configure.ac`, `configure.in`, `meson.build`, `Rakefile`,
   `Justfile`, `.justfile`, `Taskfile*.yml`, `Taskfile*.yaml`, `flake.nix`,
   `shell.nix`, `default.nix`, `Directory.Build.props`,
   `Directory.Build.targets`, `Directory.Build.rsp`, `Directory.Packages.props`),
   editor and tool configuration that runs commands (`.vscode`, `.claude`,
   `.cargo`, `*.code-workspace`, `*.config.ts`, `*.config.mts`,
   `*.workspace.ts`, `*.workspace.mts`, `*.workspace.json`),
   `.gitmodules`, `.envrc`, and shell or interpreter startup files (`.bashrc`,
   `.bash_profile`, `.profile`, `.zshrc`, `.zshenv`, `.Rprofile`, `.Renviron`,
   `.gdbinit`).

The name list is not exhaustive. It covers the files that common tooling
executes automatically; review what the AI wrote before you commit, build,
or install.

The Bazel files `BUILD`, `WORKSPACE`, `WORKSPACE.bazel`, `WORKSPACE.bzlmod`,
`MODULE.bazel`, `MODULE.bazel.lock`, `.bazeliskrc` and `.bazelversion` are
blocked as the last path component only, so a directory called `build` or
`workspace` stays writable. `WORKSPACE.bzlmod` replaces `WORKSPACE` when
bzlmod is enabled, and `.bazeliskrc` and `.bazelversion` tell Bazelisk which
Bazel binary to download and run, so all three count as code. Files such as
`BUILD.pkg` and `.bzl` modules are not blocked by name; a `.bzl` file runs
only when a blocked file loads it. Review Bazel files by hand.

Limits are positive integers read from the environment at startup:

- `MCP_MAX_FILE_BYTES`: read, write, Base64 payload, and download cap (25 MiB).
- `MCP_MAX_LIST_ENTRIES`: maximum entries returned by `list_files` (5000).
- `MCP_MAX_LIST_DEPTH`: maximum directory depth walked by `list_files` (32).
- `MCP_COMMAND_TIMEOUT`: seconds before an allowed command is killed (15).

The Streamable HTTP transport of `mcp` 2.x caps request bodies at 4 MiB, so a
single Base64 `write_file` payload above roughly 3 MiB is rejected by the
transport before the tool runs. Use `[APPEND_BASE64]:` chunks for larger
files; the tool-level cap is `MCP_MAX_FILE_BYTES`.

Residual risks:

- The append lock is process-local: it prevents concurrent writes handled by
  threads in this server process, but is not a cross-process lock.
- The final parent-directory check and `os.replace` are still separate
  operations, so a local actor with write access to the workspace parent
  could race directory replacement (TOCTOU). Run the server under a
  dedicated OS account and ensure untrusted users cannot modify the
  workspace root or its parent. A follow-up platform-specific
  openat/handle-relative implementation is required for strong
  cross-process and hostile-local-user race resistance.
- There is no workspace quota. Each write is capped by `MCP_MAX_FILE_BYTES`,
  but repeated writes can fill the disk that holds the workspace.
- `_PATH_LOCKS` keeps one lock per distinct path for the life of the process.
  A long session that writes many different files grows it without bound.
- `list_files` hides hidden names, but `list_dir` and `git_status` print raw
  command output and can reveal hidden file and folder names, never contents.
- The access log redactor rewrites the request line only. A traceback logged
  with `exc_info`, or a record whose `args` is a dict or bytes, is not
  redacted. No current uvicorn path logs the secret that way.
- On FAT volumes `st_ino` is 0, which disables the identity check on the
  open descriptor; the type and size checks still apply.
- On Windows the `0o600` mode of a new `.mcp_secret` has no effect; the file
  inherits the ACL of the application directory. On a multi-user machine run
  `icacls .mcp_secret /inheritance:r /grant:r "%USERNAME%:F"` once.

## Command execution

`run_allowed_command` runs a fixed argv list (no shell) with `cwd` set to the
workspace, a hard timeout (`MCP_COMMAND_TIMEOUT`), output capped at 256 KiB,
and `MCP_SECRET` removed from the child environment. The executables are
resolved to absolute paths at startup (`git` and `ls` from the absolute
directories in `PATH` only; relative `PATH` entries and an entry that equals
the startup directory are skipped, because `shutil.which` on Windows searches
the startup directory first; the running interpreter for `python_version`, and
`%SystemRoot%\System32\cmd.exe` for `list_dir` on Windows), because
Win32 `CreateProcess` searches the current directory before `PATH`; an
executable placed inside a workspace is never picked up. On Linux and
macOS `list_dir` runs `ls` instead of `cmd.exe`. A program that is not
installed leaves its command disabled with an error; the server never
falls back to a bare name. A process that the
command leaves behind keeps the output pipe open, and the server then
returns after 5 seconds instead of waiting for it. `git_status` runs with
`--no-optional-locks -c core.fsmonitor=false` so a repository-controlled
fsmonitor hook or `post-index-change` hook is not executed by a status call.
Git still reads the other repository configuration, so do not treat
`git_status` on an untrusted repository as a hardened boundary.

## Secret handling

The secret is compared with `hmac.compare_digest` on bytes for both the URL
prefix and the Bearer header, so a non-ASCII `Authorization` header gets 404
instead of a server error. The `Bearer` scheme is matched
case-insensitively, as RFC 9110 requires. The URL-path form is kept for
clients that cannot set headers; it puts the secret in the request URL, so
it reaches the tunnel provider and any proxy logs. Prefer the Bearer form
when the client supports it and rotate the secret periodically.
`.mcp_secret` is created exclusively (`O_EXCL`)
and flushed to disk before it is read back; an empty file stops the server
with an instruction instead of silently generating a new secret. The uvicorn
access log is filtered so the secret-bearing URL path is replaced with
`<redacted>`, while the record arguments keep their shape for the uvicorn
access formatter. `.mcp_secret` and `.tunnel_token` are hidden from MCP reads
and listings.
