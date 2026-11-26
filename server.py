import os
import base64
from pathlib import Path
import subprocess

# Network controls: URL downloads are deny-by-default and size-limited.
from security import download_url

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
                    try:
                        from mcp.server.transport_security import TransportSecuritySettings
                        kwargs.setdefault(
                            "transport_security",
                            TransportSecuritySettings(enable_dns_rebinding_protection=True),
                        )
                    except Exception:
                        pass
                return super().run(transport=transport, **kwargs)

# สร้างอินสแตนซ์ FastMCP
mcp = FastMCP("PC-Workspace", host="127.0.0.1", port=8000)

# กำหนดโฟลเดอร์ทำงาน (Sandbox)
# ค่าเริ่มต้น: โฟลเดอร์หลักของโปรเจกต์ หรือกำหนดพาธที่ต้องการผ่าน Environment Variable 'MCP_WORKSPACE'
DEFAULT_WORKSPACE = Path(__file__).resolve().parent
WORKSPACE_DIR = Path(os.getenv("MCP_WORKSPACE", DEFAULT_WORKSPACE)).resolve()
WORKSPACE_DIR.mkdir(parents=True, exist_ok=True)

def safe_path(rel_path: str) -> Path:
    """ตรวจสอบความปลอดภัยเพื่อป้องกัน Path Traversal ออกนอกโฟลเดอร์ทำงาน"""
    target = (WORKSPACE_DIR / rel_path).resolve()
    if not target.is_relative_to(WORKSPACE_DIR):
        raise ValueError("ไม่อนุญาตให้เข้าถึงไฟล์นอกโฟลเดอร์ที่กำหนด (Directory Traversal Blocked)")
    if is_hidden(target):
        raise ValueError("ไฟล์นี้เป็นไฟล์ลับของระบบ เข้าถึงไม่ได้")
    return target

# ไฟล์ลับ/ไฟล์ระบบ: ห้ามอ่าน ห้ามเขียน ห้ามแสดงในรายการ
HIDDEN_NAMES = {".tunnel_token", ".mcp_secret", ".git", ".env"}
# ห้ามเขียนทับไฟล์ที่รันได้ (กันคนเขียน server.py/start.bat ใหม่แล้วได้สิทธิ์รันโค้ดบน PC)
BLOCKED_WRITE_EXT = {".py", ".pyw", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".exe", ".dll", ".lnk", ".reg", ".scr", ".msi"}

def is_hidden(path: Path) -> bool:
    try:
        rel = path.resolve().relative_to(WORKSPACE_DIR)
    except ValueError:
        return True
    return any(part in HIDDEN_NAMES for part in rel.parts)

def writable_path(rel_path: str) -> Path:
    target = safe_path(rel_path)
    if target.suffix.lower() in BLOCKED_WRITE_EXT:
        raise ValueError(f"ไม่อนุญาตให้เขียนไฟล์ชนิด {target.suffix} ผ่าน MCP")
    return target

@mcp.tool()
def list_files() -> list[str]:
    """แสดงรายชื่อไฟล์ทั้งหมดในโฟลเดอร์ทำงานบน PC"""
    return [str(p.relative_to(WORKSPACE_DIR)) for p in WORKSPACE_DIR.rglob("*") if p.is_file() and not is_hidden(p)]

@mcp.tool()
def read_file(filename: str) -> str:
    """อ่านเนื้อหาไฟล์ข้อความในโฟลเดอร์ทำงาน"""
    return safe_path(filename).read_text(encoding="utf-8")

@mcp.tool()
def write_file(filename: str, content: str) -> str:
    """สร้างหรือแก้ไขไฟล์ในโฟลเดอร์ทำงาน (รองรับทั้งข้อความปกติ, Base64 Data URI / [BASE64]:..., และ [APPEND_BASE64]:... สำหรับไฟล์รูปภาพ/ไบนารี)"""
    path = writable_path(filename)
    path.parent.mkdir(parents=True, exist_ok=True)

    # 1. รองรับการต่อไฟล์ไบนารีทีละส่วน (Chunked Base64 Append) สำหรับไฟล์ภาพขนาดใหญ่
    if content.startswith("[APPEND_BASE64]:"):
        b64_str = content[len("[APPEND_BASE64]:"):].strip()
        raw_bytes = base64.b64decode(b64_str)
        with open(path, "ab") as f:
            f.write(raw_bytes)
        return f"เพิ่มข้อมูลไบนารีลงในไฟล์ {filename} เรียบร้อยแล้ว (+{len(raw_bytes)} bytes, รวม {path.stat().st_size} bytes)"

    # 2. รองรับการบันทึกไฟล์ไบนารี/รูปภาพผ่าน Prefix [BASE64]:
    if content.startswith("[BASE64]:"):
        b64_str = content[len("[BASE64]:"):].strip()
        raw_bytes = base64.b64decode(b64_str)
        path.write_bytes(raw_bytes)
        return f"บันทึกไฟล์ไบนารี {filename} เรียบร้อยแล้ว (ขนาด {len(raw_bytes)} bytes)"

    # 3. รองรับรูปแบบมาตรฐาน data:image/...;base64,...
    if content.startswith("data:") and ";base64," in content[:120]:
        b64_str = content.split(";base64,", 1)[1].strip()
        raw_bytes = base64.b64decode(b64_str)
        path.write_bytes(raw_bytes)
        return f"บันทึกไฟล์รูปภาพ/ไบนารี {filename} เรียบร้อยแล้ว (ขนาด {len(raw_bytes)} bytes)"

    # 4. บันทึกไฟล์ข้อความปกติ (UTF-8)
    path.write_text(content, encoding="utf-8")
    return f"บันทึกไฟล์ข้อความ {filename} เรียบร้อยแล้ว (ขนาด {len(content)} ตัวอักษร)"

@mcp.tool()
def write_binary_file(filename: str, base64_data: str, append: bool = False) -> str:
    """สร้างหรือบันทึกไฟล์รูปภาพ/ไบนารี (.png, .jpg, .webp, .mp4 ฯลฯ) จากข้อมูล Base64 ลงในโฟลเดอร์ทำงาน"""
    path = writable_path(filename)
    path.parent.mkdir(parents=True, exist_ok=True)
    if base64_data.startswith("data:") and ";base64," in base64_data[:120]:
        base64_data = base64_data.split(";base64,", 1)[1]
    raw_bytes = base64.b64decode(base64_data.strip())
    mode = "ab" if append else "wb"
    with open(path, mode) as f:
        f.write(raw_bytes)
    return f"บันทึกไฟล์ไบนารี {filename} เรียบร้อยแล้ว (ขนาดรวม {path.stat().st_size} bytes)"

@mcp.tool()
def download_file_from_url(filename: str, url: str) -> str:
    """ดาวน์โหลดไฟล์หรือรูปภาพจาก URL มาเก็บไว้ในโฟลเดอร์ทำงานบน PC"""
    path = writable_path(filename)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = download_url(url)
    path.write_bytes(data)
    return f"ดาวน์โหลดไฟล์ {filename} จาก URL เรียบร้อยแล้ว (ขนาด {len(data)} bytes)"

# กำหนดเฉพาะคำสั่งที่อนุญาตให้รันแบบตายตัวเพื่อป้องกันการแทรกคำสั่งอันตราย
ALLOWED_COMMANDS = {
    "git_status": ["git", "status"],
    "python_version": ["python", "--version"],
    "list_dir": ["cmd", "/c", "dir"],
}

@mcp.tool()
def run_allowed_command(command_key: str) -> str:
    """รันคำสั่งใน PC จากรายการที่อนุญาต (git_status, python_version, list_dir)"""
    if command_key not in ALLOWED_COMMANDS:
        return f"ไม่อนุญาตคำสั่งนี้ คำสั่งที่ใช้ได้คือ: {', '.join(ALLOWED_COMMANDS.keys())}"
    result = subprocess.run(
        ALLOWED_COMMANDS[command_key],
        cwd=WORKSPACE_DIR,
        capture_output=True,
        text=True,
        timeout=15,
    )
    return result.stdout or result.stderr

# ---------------------------------------------------------------------------
# Auth: ทุก request ต้องมีรหัสลับ (ไฟล์ .mcp_secret ไม่ขึ้น git)
#   แบบ 1 (ใช้กับ Gemini/ตัวที่ใส่ header ไม่ได้):  https://pc-mcp.108ido.com/<secret>/mcp
#   แบบ 2: https://pc-mcp.108ido.com/mcp + header  Authorization: Bearer <secret>
# ไม่มีรหัส/ผิด => 404 เหมือนไม่มีอะไรอยู่
# ---------------------------------------------------------------------------
import hmac
SECRET_FILE = Path(__file__).resolve().parent / ".mcp_secret"
def _load_secret() -> str:
    env = os.getenv("MCP_SECRET", "").strip()
    if env:
        return env
    if not SECRET_FILE.exists() or not SECRET_FILE.read_text(encoding="ascii").strip():
        import secrets
        SECRET_FILE.write_text(secrets.token_urlsafe(24), encoding="ascii")  # สร้างครั้งแรกอัตโนมัติ
    return SECRET_FILE.read_text(encoding="ascii").strip()

MCP_SECRET = _load_secret()

def make_app():
    from starlette.responses import PlainTextResponse
    kwargs = {"streamable_http_path": "/mcp", "stateless_http": True}
    try:
        from mcp.server.transport_security import TransportSecuritySettings
        kwargs["transport_security"] = TransportSecuritySettings(enable_dns_rebinding_protection=True)
    except Exception:
        pass
    inner = mcp.streamable_http_app(**kwargs)
    prefix = f"/{MCP_SECRET}"
    not_found = PlainTextResponse("Not Found", status_code=404)

    async def app(scope, receive, send):
        if scope["type"] != "http":          # lifespan ฯลฯ ส่งต่อตรง
            return await inner(scope, receive, send)
        path = scope.get("path", "")
        ok = False
        if MCP_SECRET and (path == prefix + "/mcp" or path.startswith(prefix + "/mcp/")):
            scope = dict(scope, path=path[len(prefix):], raw_path=path[len(prefix):].encode())
            ok = True
        elif MCP_SECRET and (path == "/mcp" or path.startswith("/mcp/")):
            auth = dict(scope.get("headers") or []).get(b"authorization", b"").decode()
            ok = hmac.compare_digest(auth, f"Bearer {MCP_SECRET}")
        if not ok:
            return await not_found(scope, receive, send)
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
