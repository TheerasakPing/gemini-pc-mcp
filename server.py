import os
import base64
import hmac
import locale
import logging
import shutil
import sys
from pathlib import Path
import subprocess
import threading

# Network controls: URL downloads are deny-by-default and size-limited.
from security import download_url
from filesystem import (
    atomic_write,
    list_workspace_files,
    matches_any,
    read_file_bytes,
    safe_workspace_path,
)

def build_transport_security_settings():
    """Build a fail-closed Host/Origin allowlist for the MCP HTTP transport."""
    from mcp.server.transport_security import TransportSecuritySettings

    allowed_hosts = [
        item.strip()
        for item in os.getenv(
            "MCP_ALLOWED_HOSTS",
            "127.0.0.1:8000,localhost:8000,[::1]:8000",
        ).split(",")
        if item.strip()
    ]
    allowed_origins = [
        item.strip()
        for item in os.getenv(
            "MCP_ALLOWED_ORIGINS",
            "http://127.0.0.1:8000,http://localhost:8000,http://[::1]:8000",
        ).split(",")
        if item.strip()
    ]
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=allowed_hosts,
        allowed_origins=allowed_origins,
    )


# รองรับทั้ง mcp เวอร์ชัน 1.x และ 2.x
try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    try:
        from fastmcp import FastMCP
    except ImportError:
        from mcp.server import MCPServer
        class FastMCP(MCPServer):
            def __init__(self, name: str, host: str = "127.0.0.1", port: int = 8000, **kwargs):
                super().__init__(name=name)
                self._default_host = host
                self._default_port = port

            def run(self, transport: str = "stdio", **kwargs):
                if transport == "streamable-http":
                    kwargs.setdefault("host", self._default_host)
                    kwargs.setdefault("port", self._default_port)
                    kwargs.setdefault("transport_security", build_transport_security_settings())
                return super().run(transport=transport, **kwargs)

# สร้างอินสแตนซ์ FastMCP
mcp = FastMCP("PC-Workspace", host="127.0.0.1", port=8000)

# กำหนดโฟลเดอร์ทำงาน (Sandbox)
# ค่าเริ่มต้น: โฟลเดอร์ย่อย workspace/ ข้าง server.py ไม่ใช่โฟลเดอร์แอป
# (โฟลเดอร์แอปคือ sys.path[0] และมีไฟล์ dependency/CI ที่ AI ไม่ควรแก้)
# หรือกำหนดพาธผ่าน Environment Variable 'MCP_WORKSPACE'
DEFAULT_WORKSPACE = Path(__file__).resolve().parent / "workspace"

def resolve_workspace(raw: str | Path | None) -> Path:
    """root ของดิสก์หรือโฮมไดเรกทอรีไม่ใช่ Workspace เพราะเท่ากับเปิดทั้งเครื่องให้ AI"""
    text = str(raw or "").strip()
    # ตัด prefix \\?\ ที่ใช้เลี่ยงการเทียบพาธ และผูก path สัมพัทธ์กับโฟลเดอร์แอป ไม่ใช่ cwd ตอนสั่งรัน
    if text[:4] == "\\\\?\\":
        text = text[4:]
        if text[:4].upper() == "UNC\\":
            text = "\\\\" + text[4:]
    workspace = Path(text or str(DEFAULT_WORKSPACE))
    # D:sub หรือ D: ไม่ใช่ absolute path: Windows จะต่อกับ cwd ปัจจุบัน (หรือไดรฟ์ที่ shell จำไว้) ซึ่งเปลี่ยนได้ทุกครั้งที่สั่งรัน
    if workspace.drive and not workspace.root:
        raise ValueError(
            "MCP_WORKSPACE ห้ามเป็น path แบบ D:folder ให้ใช้ absolute path หรือ path สัมพัทธ์ที่ไม่มีชื่อไดรฟ์"
        )
    if not workspace.is_absolute():
        workspace = DEFAULT_WORKSPACE.parent / workspace
    workspace = workspace.resolve()
    if workspace == Path(workspace.anchor) or workspace == Path.home().resolve():
        raise ValueError(
            "MCP_WORKSPACE ต้องเป็นโฟลเดอร์เฉพาะสำหรับงาน ไม่ใช่ root ของดิสก์หรือโฮมไดเรกทอรี"
        )
    return workspace

WORKSPACE_DIR = resolve_workspace(os.getenv("MCP_WORKSPACE"))
WORKSPACE_DIR.mkdir(parents=True, exist_ok=True)

def safe_path(rel_path: str) -> Path:
    """ตรวจสอบ traversal, symlink และ reparse point ก่อนเข้าถึง Workspace"""
    return safe_workspace_path(WORKSPACE_DIR, rel_path, HIDDEN_NAMES)

# ไฟล์ลับ/ไฟล์ระบบ: ห้ามอ่าน ห้ามเขียน ห้ามแสดงในรายการ
# เทียบชื่อแบบไม่สนตัวพิมพ์ และรองรับ glob เพราะ .env.local หรือ prod.env ก็เป็นไฟล์ลับเหมือน .env
HIDDEN_NAMES = {
    ".tunnel_token", ".tunnel_token.*", ".mcp_secret", ".mcp_secret.*", ".git",
    ".env*", "*.env*",
    ".ssh", ".aws", ".gnupg", ".kube", ".docker",
    ".netrc", ".git-credentials", ".npmrc", ".pypirc", ".gitconfig",
    "id_rsa*", "id_ed25519*", "id_ecdsa*", "*.pem", "*.key", "*.p12", "*.pfx",
    "id_dsa*", "id_dss*", "id_xmss*", "private-key*", "_netrc", ".azure", ".vault-token",
    ".pgpass", ".htpasswd", "*.jks", "*.keystore", "*.ppk", "*.kdbx",
    ".mcp-tmp-*",
}
# ห้ามเขียนทับไฟล์ที่ Python/Windows/shell โหลดหรือรันได้ (.pyc/.pyd shadow โมดูลได้, .sh/.cjs รันโดย interpreter)
BLOCKED_WRITE_EXT = {
    ".py", ".pyw", ".pyc", ".pyo", ".pyd", ".pyz", ".pyzw", ".pth", ".so", ".dylib", ".ocx",
    ".bat", ".cmd", ".com", ".exe", ".dll", ".scr", ".pif", ".cpl", ".msi", ".msp", ".msc",
    ".msix", ".appx", ".settingcontent-ms",
    ".ps1", ".psm1", ".ps1xml", ".ps2", ".psc1",
    ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsc", ".wsh", ".hta", ".sct",
    ".sh", ".bash", ".zsh", ".fish", ".ksh", ".cjs", ".mjs", ".rb", ".pl", ".pm",
    ".php", ".lua", ".tcl", ".jar",
    ".command", ".tool", ".scpt", ".applescript", ".terminal", ".inetloc", ".desktop", ".service",
    ".lnk", ".scf", ".url", ".reg",
}
# ชื่อที่เครื่องมือรันหรือโหลดอัตโนมัติตอน install, build, push, login: AI ห้ามแก้ ผู้ใช้ต้องแก้เอง
BLOCKED_WRITE_NAMES = {
    "requirements*.txt", "pyproject.toml", "setup.cfg", "pipfile*", "poetry.lock", "uv.lock",
    "package.json", "*-lock.json", "*-lock.yaml", "yarn.lock", ".yarnrc.yml", ".npmrc",
    "cargo.toml", "cargo.lock", "build.rs", "go.mod", "go.sum", "gemfile*", ".gitmodules",
    ".github", ".gitlab", ".gitlab-ci.yml", ".circleci", ".buildkite", "jenkinsfile", ".travis.yml",
    "appveyor.yml", "azure-pipelines.yml", ".drone.yml", ".pre-commit-config.yaml",
    "makefile", "gnumakefile", "dockerfile*", "docker-compose*.yml", "docker-compose*.yaml",
    ".envrc",
    ".vscode", ".claude", ".cargo", "*.code-workspace",
    "pom.xml", "build.gradle", "build.gradle.kts", "build.sbt", "cmakelists.txt", "configure",
    "configure.ac", "configure.in", "meson.build", "rakefile", "sconstruct", "build.bazel", "justfile",
    ".justfile", "taskfile.yml", "taskfile.yaml", "flake.nix", "shell.nix", "default.nix", ".bazelrc",
    "bitbucket-pipelines.yml", ".woodpecker.yml", "cloudbuild.yaml", ".gitea", ".forgejo",
    "bun.lock", "bun.lockb", "npm-shrinkwrap.json", "composer.json", "composer.lock",
    "pnpm-workspace.yaml", "bunfig.toml", "uv.toml", "podfile", "podfile.lock", "*.gemspec",
    "compose*.yaml", "compose*.yml", "containerfile", "go.work", "pubspec.lock", "gradle.lockfile",
    "nuget.config", "packages.config", "directory.build.props", ".husky", "lefthook.yml",
    ".rprofile", ".renviron", ".gdbinit", "*.config.ts", "*.config.mts",
    ".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile", ".zshrc", ".zshenv",
    ".zlogin", ".zlogout", ".zprofile", ".kshrc", ".cshrc", ".tcshrc", ".login", ".logout",
}

# ไฟล์รากของ Bazel ตรวจเฉพาะ component สุดท้าย เพราะ build/ กับ workspace/ เป็นชื่อโฟลเดอร์ปกติ
BLOCKED_WRITE_FILE_NAMES = {"build", "workspace", "module.bazel", "workspace.bazel"}

def writable_path(rel_path: str) -> Path:
    target = safe_path(rel_path)
    if target.suffix.lower() in BLOCKED_WRITE_EXT:
        raise ValueError(f"ไม่อนุญาตให้เขียนไฟล์ชนิด {target.suffix} ผ่าน MCP")
    if target.name.casefold() in BLOCKED_WRITE_FILE_NAMES:
        raise ValueError("ไม่อนุญาตให้เขียนไฟล์ BUILD/WORKSPACE ของ Bazel ผ่าน MCP")
    if any(matches_any(part.casefold(), BLOCKED_WRITE_NAMES)
           for part in target.relative_to(WORKSPACE_DIR).parts):
        raise ValueError("ไม่อนุญาตให้แก้ไฟล์ dependency/CI/build/shell config ผ่าน MCP ผู้ใช้ต้องแก้เอง")
    return target

def _env_int(name: str, default: int) -> int:
    raw = (os.getenv(name) or "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} ต้องเป็นจำนวนเต็มบวก") from exc
    if value <= 0:
        raise ValueError(f"{name} ต้องเป็นจำนวนเต็มบวก")
    return value


MAX_FILE_BYTES = _env_int("MCP_MAX_FILE_BYTES", 25 * 1024 * 1024)
MAX_LIST_ENTRIES = _env_int("MCP_MAX_LIST_ENTRIES", 5000)
MAX_LIST_DEPTH = _env_int("MCP_MAX_LIST_DEPTH", 32)
COMMAND_TIMEOUT_SECONDS = _env_int("MCP_COMMAND_TIMEOUT", 15)
COMMAND_OUTPUT_BYTES = 256 * 1024

def _decode_base64_limited(encoded: str) -> bytes:
    compact = encoded.strip()
    if len(compact) > ((MAX_FILE_BYTES + 2) // 3) * 4 + 8:
        raise ValueError("ข้อมูล Base64 มีขนาดเกินขีดจำกัด")
    try:
        data = base64.b64decode(compact, validate=True)
    except Exception as exc:
        raise ValueError("ข้อมูล Base64 ไม่ถูกต้อง") from exc
    if len(data) > MAX_FILE_BYTES:
        raise ValueError("ไฟล์มีขนาดเกินขีดจำกัด")
    return data

def _check_file_size(size: int) -> None:
    if size > MAX_FILE_BYTES:
        raise ValueError("ไฟล์มีขนาดเกินขีดจำกัด")

@mcp.tool()
def list_files() -> list[str]:
    """แสดงรายชื่อไฟล์ในโฟลเดอร์ทำงานบน PC (จำกัดจำนวน/ความลึก ไม่ตาม symlink)"""
    return list_workspace_files(
        WORKSPACE_DIR, HIDDEN_NAMES, max_entries=MAX_LIST_ENTRIES, max_depth=MAX_LIST_DEPTH
    )

@mcp.tool()
def read_file(filename: str) -> str:
    """อ่านเนื้อหาไฟล์ข้อความในโฟลเดอร์ทำงาน"""
    path = safe_path(filename)
    data = read_file_bytes(path, MAX_FILE_BYTES)
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("ไฟล์ไม่ใช่ข้อความ UTF-8") from exc

@mcp.tool()
def write_file(filename: str, content: str) -> str:
    """สร้างหรือแก้ไขไฟล์ในโฟลเดอร์ทำงาน (รองรับทั้งข้อความปกติ, Base64 Data URI / [BASE64]:..., และ [APPEND_BASE64]:... สำหรับไฟล์รูปภาพ/ไบนารี)"""
    path = writable_path(filename)

    # 1. รองรับการต่อไฟล์ไบนารีทีละส่วน (Chunked Base64 Append) สำหรับไฟล์ภาพขนาดใหญ่
    if content.startswith("[APPEND_BASE64]:"):
        b64_str = content[len("[APPEND_BASE64]:"):].strip()
        raw_bytes = _decode_base64_limited(b64_str)
        total = atomic_write(path, raw_bytes, append=True, max_existing_bytes=MAX_FILE_BYTES, root=WORKSPACE_DIR)
        return f"เพิ่มข้อมูลไบนารีลงในไฟล์ {filename} เรียบร้อยแล้ว (+{len(raw_bytes)} bytes, รวม {total} bytes)"

    # 2. รองรับการบันทึกไฟล์ไบนารี/รูปภาพผ่าน Prefix [BASE64]:
    if content.startswith("[BASE64]:"):
        b64_str = content[len("[BASE64]:"):].strip()
        raw_bytes = _decode_base64_limited(b64_str)
        atomic_write(path, raw_bytes, max_existing_bytes=MAX_FILE_BYTES, root=WORKSPACE_DIR)
        return f"บันทึกไฟล์ไบนารี {filename} เรียบร้อยแล้ว (ขนาด {len(raw_bytes)} bytes)"

    # 3. รองรับรูปแบบมาตรฐาน data:image/...;base64,...
    if content.startswith("data:") and ";base64," in content[:120]:
        b64_str = content.split(";base64,", 1)[1].strip()
        raw_bytes = _decode_base64_limited(b64_str)
        atomic_write(path, raw_bytes, max_existing_bytes=MAX_FILE_BYTES, root=WORKSPACE_DIR)
        return f"บันทึกไฟล์รูปภาพ/ไบนารี {filename} เรียบร้อยแล้ว (ขนาด {len(raw_bytes)} bytes)"

    # 4. บันทึกไฟล์ข้อความปกติ (UTF-8)
    raw_bytes = content.encode("utf-8")
    _check_file_size(len(raw_bytes))
    atomic_write(path, raw_bytes, max_existing_bytes=MAX_FILE_BYTES, root=WORKSPACE_DIR)
    return f"บันทึกไฟล์ข้อความ {filename} เรียบร้อยแล้ว (ขนาด {len(content)} ตัวอักษร)"

@mcp.tool()
def write_binary_file(filename: str, base64_data: str, append: bool = False) -> str:
    """สร้างหรือบันทึกไฟล์รูปภาพ/ไบนารี (.png, .jpg, .webp, .mp4 ฯลฯ) จากข้อมูล Base64 ลงในโฟลเดอร์ทำงาน"""
    path = writable_path(filename)
    if base64_data.startswith("data:") and ";base64," in base64_data[:120]:
        base64_data = base64_data.split(";base64,", 1)[1]
    raw_bytes = _decode_base64_limited(base64_data)
    total = atomic_write(path, raw_bytes, append=append, max_existing_bytes=MAX_FILE_BYTES, root=WORKSPACE_DIR)
    return f"บันทึกไฟล์ไบนารี {filename} เรียบร้อยแล้ว (ขนาดรวม {total} bytes)"

@mcp.tool()
def download_file_from_url(filename: str, url: str) -> str:
    """ดาวน์โหลดไฟล์หรือรูปภาพจาก URL มาเก็บไว้ในโฟลเดอร์ทำงานบน PC"""
    path = writable_path(filename)
    data = download_url(url, max_bytes=MAX_FILE_BYTES)
    atomic_write(path, data, max_existing_bytes=MAX_FILE_BYTES, root=WORKSPACE_DIR)
    return f"ดาวน์โหลดไฟล์ {filename} จาก URL เรียบร้อยแล้ว (ขนาด {len(data)} bytes)"

# กำหนดเฉพาะคำสั่งที่อนุญาตให้รันแบบตายตัวเพื่อป้องกันการแทรกคำสั่งอันตราย
# ใช้พาธเต็มของ executable เท่านั้น: Win32 จะหาชื่อที่ตรงกันในโฟลเดอร์ปัจจุบันก่อน PATH
# และ POSIX ที่มี "." อยู่ใน PATH ก็เสี่ยงแบบเดียวกัน หาโปรแกรมไม่เจอให้เก็บ None ห้าม fallback เป็นชื่อเปล่า
def resolve_executable(name: str) -> str | None:
    """คืน absolute path ของโปรแกรมจาก PATH หรือ None ถ้าไม่มี ไม่ค้นโฟลเดอร์ปัจจุบัน"""
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        # shutil.which บน Windows แทรกโฟลเดอร์ปัจจุบันไว้หน้า PATH เว้นแต่ "." อยู่ในรายการแล้ว
        # จึงใส่ "." ต่อท้ายทุกครั้ง แล้วรับเฉพาะผลที่เป็น absolute path (มาจาก directory ไม่ใช่ ".")
        if directory and Path(directory).is_absolute():
            found = shutil.which(name, path=directory + os.pathsep + os.curdir)
            if found and Path(found).is_absolute():
                return str(Path(found).resolve())
    return None

def build_allowed_commands(platform: str = os.name) -> dict:
    """ตารางคำสั่งที่อนุญาต ผูก executable ตอนสร้าง ไม่ใช่ตอนเรียกใช้"""
    if platform == "nt":
        list_dir = [
            str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "cmd.exe"),
            "/c", "dir",
        ]
    else:
        list_dir = [resolve_executable("ls"), "-la"]
    return {
        # -c core.fsmonitor=false: ห้ามให้ hook ที่อยู่ใน repo รันตอนเรียก status
        "git_status": [resolve_executable("git"), "--no-optional-locks", "-c", "core.fsmonitor=false", "status"],
        "python_version": [sys.executable, "--version"],
        "list_dir": list_dir,
    }

ALLOWED_COMMANDS = build_allowed_commands()


def _run_bounded(argv: list[str], *, timeout: float = COMMAND_TIMEOUT_SECONDS,
                 max_output: int = COMMAND_OUTPUT_BYTES) -> str:
    """รัน argv ตายตัว (ไม่ผ่าน shell) จำกัดเวลาและ output; ลูกไม่ได้รับ MCP_SECRET"""
    env = {key: value for key, value in os.environ.items() if key != "MCP_SECRET"}
    process = subprocess.Popen(
        argv, cwd=WORKSPACE_DIR, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    kept = bytearray()
    truncated = False

    def drain() -> None:
        nonlocal truncated
        while True:
            try:
                chunk = process.stdout.read1(65536)
            except (OSError, ValueError):
                return
            if not chunk:
                return
            room = max_output - len(kept)
            if len(chunk) > room:
                truncated = True
            if room > 0:
                kept.extend(chunk[:room])

    reader = threading.Thread(target=drain, daemon=True)
    reader.start()
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        return "คำสั่งทำงานนานเกินกำหนด จึงถูกยกเลิก"
    finally:
        reader.join(timeout=5)
        # A grandchild may still hold the pipe; closing it now blocks until that process exits.
        if not reader.is_alive():
            process.stdout.close()
    text = bytes(kept).decode(locale.getpreferredencoding(False), errors="replace")
    if truncated:
        text += "\n[output truncated]"
    return text


@mcp.tool()
def run_allowed_command(command_key: str) -> str:
    """รันคำสั่งใน PC จากรายการที่อนุญาต (git_status, python_version, list_dir)"""
    if command_key not in ALLOWED_COMMANDS:
        return f"ไม่อนุญาตคำสั่งนี้ คำสั่งที่ใช้ได้คือ: {', '.join(ALLOWED_COMMANDS.keys())}"
    argv = ALLOWED_COMMANDS[command_key]
    if not argv[0]:
        return "ไม่พบโปรแกรมที่คำสั่งนี้ต้องใช้บนเครื่องนี้ ให้ติดตั้งแล้วรีสตาร์ท server"
    try:
        return _run_bounded(argv)
    except OSError as exc:
        return f"รันคำสั่งไม่สำเร็จ: {exc.__class__.__name__}"

# ---------------------------------------------------------------------------
# Auth: ทุก request ต้องมีรหัสลับ (ไฟล์ .mcp_secret ไม่ขึ้น git)
#   แบบ 1 (ใช้กับ Gemini/ตัวที่ใส่ header ไม่ได้):  https://pc-mcp.108ido.com/<secret>/mcp
#   แบบ 2: https://pc-mcp.108ido.com/mcp + header  Authorization: Bearer <secret>
# ไม่มีรหัส/ผิด => 404 เหมือนไม่มีอะไรอยู่
# ---------------------------------------------------------------------------
SECRET_FILE = Path(__file__).resolve().parent / ".mcp_secret"

def _load_secret() -> str:
    env = os.getenv("MCP_SECRET", "").strip()
    if env:
        return env
    if not SECRET_FILE.exists():
        import secrets
        try:
            descriptor = os.open(SECRET_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            descriptor = -1
        if descriptor >= 0:
            with os.fdopen(descriptor, "wb") as stream:  # สร้างครั้งแรกอัตโนมัติ, exclusive + fsync
                stream.write(secrets.token_urlsafe(24).encode("ascii"))
                stream.flush()
                os.fsync(stream.fileno())
    stored = SECRET_FILE.read_text(encoding="ascii").strip()
    if not stored:
        raise SystemExit(".mcp_secret ว่างเปล่า: ลบไฟล์แล้วรันใหม่เพื่อสร้างรหัสใหม่")
    return stored

MCP_SECRET = _load_secret()


class _SecretRedactor(logging.Filter):
    """Keep the secret-bearing URL out of the uvicorn access log line.

    uvicorn's AccessFormatter unpacks record.args, so args must keep its shape.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if MCP_SECRET:
            if isinstance(record.msg, str) and MCP_SECRET in record.msg:
                record.msg = record.msg.replace(MCP_SECRET, "<redacted>")
            if isinstance(record.args, tuple):
                record.args = tuple(
                    argument.replace(MCP_SECRET, "<redacted>")
                    if isinstance(argument, str) else argument
                    for argument in record.args
                )
        return True


def make_app():
    from starlette.responses import PlainTextResponse
    kwargs = {"streamable_http_path": "/mcp", "stateless_http": True}
    kwargs["transport_security"] = build_transport_security_settings()
    inner = mcp.streamable_http_app(**kwargs)
    url_prefix = f"/{MCP_SECRET}".encode()
    not_found = PlainTextResponse("Not Found", status_code=404)
    logging.getLogger("uvicorn.access").addFilter(_SecretRedactor())

    async def app(scope, receive, send):
        if scope["type"] != "http":          # lifespan ฯลฯ ส่งต่อตรง
            return await inner(scope, receive, send)
        path = scope.get("path", "").encode()
        rest = None
        if url_prefix and hmac.compare_digest(path[:len(url_prefix)], url_prefix):
            rest = path[len(url_prefix):]
        elif url_prefix and (path == b"/mcp" or path.startswith(b"/mcp/")):
            auth = dict(scope.get("headers") or []).get(b"authorization", b"")
            scheme, _, token = auth.partition(b" ")
            # RFC 9110: the auth scheme is case-insensitive.
            if scheme.lower() != b"bearer" or not hmac.compare_digest(token.strip(), url_prefix[1:]):
                return await not_found(scope, receive, send)
            return await inner(scope, receive, send)
        if rest is None or not (rest == b"/mcp" or rest.startswith(b"/mcp/")):
            return await not_found(scope, receive, send)
        scope = dict(scope, path=rest.decode(), raw_path=rest)
        return await inner(scope, receive, send)
    return app

if __name__ == "__main__":
    print("=" * 60)
    print("🚀 Gemini PC Workspace - MCP Server (Upgraded Binary/Image Support)")
    print(f"📂 Workspace Directory: {WORKSPACE_DIR}")
    if not MCP_SECRET:
        raise SystemExit("ไม่มีรหัสลับ (กันไม่ให้เปิด server แบบไม่มีรหัส)")
    print("🌐 Endpoint: http://127.0.0.1:8000/<secret>/mcp  (รหัสอยู่ในไฟล์ .mcp_secret)")
    print("=" * 60)
    import uvicorn
    uvicorn.run(make_app(), host="127.0.0.1", port=8000, log_level="info")
