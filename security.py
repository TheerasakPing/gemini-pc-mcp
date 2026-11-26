"""Network safety helpers for the Gemini PC MCP server.

Downloads are deny-by-default: configure MCP_DOWNLOAD_ALLOWED_HOSTS with exact
hostnames that the local operator trusts. Redirects are deliberately disabled.
"""
from __future__ import annotations

import ipaddress
import os
import socket
import urllib.error
import urllib.request
from urllib.parse import urlsplit

DEFAULT_MAX_DOWNLOAD_BYTES = 25 * 1024 * 1024
DEFAULT_DOWNLOAD_TIMEOUT = 20


class DownloadSecurityError(ValueError):
    """Raised when a download target or response violates security policy."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _allowed_hosts() -> set[str]:
    return {
        item.strip().lower().rstrip(".")
        for item in os.getenv("MCP_DOWNLOAD_ALLOWED_HOSTS", "").split(",")
        if item.strip()
    }


def _validate_public_resolution(hostname: str) -> None:
    try:
        records = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise DownloadSecurityError("ไม่สามารถตรวจสอบ DNS ของปลายทางได้") from exc

    if not records:
        raise DownloadSecurityError("ปลายทางไม่มี DNS address")

    for record in records:
        address = ipaddress.ip_address(record[4][0].split("%", 1)[0])
        if not address.is_global:
            raise DownloadSecurityError("ปฏิเสธปลายทางที่ resolve ไปยัง IP ภายในหรือ IP พิเศษ")


def validate_download_url(url: str) -> str:
    try:
        parsed = urlsplit(url)
        hostname = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port
    except ValueError as exc:
        raise DownloadSecurityError("URL ไม่ถูกต้อง") from exc

    if parsed.scheme.lower() != "https":
        raise DownloadSecurityError("อนุญาตให้ดาวน์โหลดผ่าน HTTPS เท่านั้น")
    if not hostname or parsed.username or parsed.password:
        raise DownloadSecurityError("URL ต้องมี hostname และห้ามฝัง username/password")
    if port not in (None, 443):
        raise DownloadSecurityError("อนุญาตเฉพาะ HTTPS port 443")
    if hostname not in _allowed_hosts():
        raise DownloadSecurityError("hostname นี้ไม่ได้อยู่ใน MCP_DOWNLOAD_ALLOWED_HOSTS")

    _validate_public_resolution(hostname)
    return hostname


def download_url(url: str, *, max_bytes: int | None = None,
                 timeout: int | None = None) -> bytes:
    validate_download_url(url)
    limit = max_bytes or int(os.getenv("MCP_MAX_DOWNLOAD_BYTES", DEFAULT_MAX_DOWNLOAD_BYTES))
    request_timeout = timeout or int(os.getenv("MCP_DOWNLOAD_TIMEOUT", DEFAULT_DOWNLOAD_TIMEOUT))
    if limit <= 0 or request_timeout <= 0:
        raise DownloadSecurityError("ค่าจำกัดขนาดหรือ timeout ต้องมากกว่า 0")

    request = urllib.request.Request(
        url,
        headers={"User-Agent": "Gemini-PC-MCP/1.0"},
        method="GET",
    )
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(request, timeout=request_timeout) as response:
            length = response.headers.get("Content-Length")
            if length:
                try:
                    if int(length) > limit:
                        raise DownloadSecurityError("ไฟล์ดาวน์โหลดมีขนาดเกินกำหนด")
                except ValueError:
                    raise DownloadSecurityError("Content-Length ไม่ถูกต้อง")
            data = response.read(limit + 1)
    except urllib.error.HTTPError as exc:
        if 300 <= exc.code < 400:
            raise DownloadSecurityError("ไม่อนุญาตให้เปลี่ยนเส้นทางดาวน์โหลด (redirect)") from exc
        raise DownloadSecurityError(f"ดาวน์โหลดไม่สำเร็จ: HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise DownloadSecurityError("เชื่อมต่อปลายทางดาวน์โหลดไม่สำเร็จ") from exc

    if len(data) > limit:
        raise DownloadSecurityError("ไฟล์ดาวน์โหลดมีขนาดเกินกำหนด")
    return data
