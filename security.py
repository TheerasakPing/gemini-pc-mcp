"""Network safety helpers for the Gemini PC MCP server.

Downloads are deny-by-default. Trusted exact hostnames must be configured in
MCP_DOWNLOAD_ALLOWED_HOSTS. DNS answers are validated and the selected public
IP is pinned to the HTTPS socket to prevent DNS-rebinding TOCTOU.
"""
from __future__ import annotations

import http.client
import ipaddress
import os
import socket
import ssl
from urllib.parse import urlsplit

DEFAULT_MAX_DOWNLOAD_BYTES = 25 * 1024 * 1024
DEFAULT_DOWNLOAD_TIMEOUT = 20
# IPv6 translation prefixes that can carry a private IPv4 address: NAT64 and 6to4.
_TRANSLATED_NETWORKS = tuple(
    ipaddress.ip_network(network) for network in ("64:ff9b::/96", "2002::/16", "::ffff:0:0:0/96")
)


class DownloadSecurityError(ValueError):
    """Raised when a download target or response violates security policy."""


def _allowed_hosts() -> set[str]:
    return {
        item.strip().lower().rstrip(".")
        for item in os.getenv("MCP_DOWNLOAD_ALLOWED_HOSTS", "").split(",")
        if item.strip()
    }


def _resolve_public_addresses(hostname: str) -> list[str]:
    try:
        records = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise DownloadSecurityError("ไม่สามารถตรวจสอบ DNS ของปลายทางได้") from exc

    addresses: list[str] = []
    for record in records:
        address = ipaddress.ip_address(record[4][0].split("%", 1)[0])
        if not address.is_global or any(address in network for network in _TRANSLATED_NETWORKS):
            raise DownloadSecurityError("ปฏิเสธปลายทางที่ resolve ไปยัง IP ภายในหรือ IP พิเศษ")
        normalized = str(address)
        if normalized not in addresses:
            addresses.append(normalized)

    if not addresses:
        raise DownloadSecurityError("ปลายทางไม่มี DNS address")
    return addresses


def validate_download_url(url: str) -> tuple[str, list[str], str]:
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

    addresses = _resolve_public_addresses(hostname)
    request_target = parsed.path or "/"
    if parsed.query:
        request_target += "?" + parsed.query
    return hostname, addresses, request_target


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection that dials a validated IP while retaining hostname SNI."""

    def __init__(self, hostname: str, connect_ip: str, timeout: int):
        super().__init__(hostname, port=443, timeout=timeout, context=ssl.create_default_context())
        self._connect_ip = connect_ip

    def connect(self) -> None:
        raw_socket = socket.create_connection((self._connect_ip, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw_socket, server_hostname=self.host)
        except Exception:
            raw_socket.close()
            raise


def download_url(url: str, *, max_bytes: int | None = None,
                 timeout: int | None = None) -> bytes:
    hostname, addresses, request_target = validate_download_url(url)
    limit = int(os.getenv("MCP_MAX_DOWNLOAD_BYTES", DEFAULT_MAX_DOWNLOAD_BYTES)) if max_bytes is None else max_bytes
    request_timeout = int(os.getenv("MCP_DOWNLOAD_TIMEOUT", DEFAULT_DOWNLOAD_TIMEOUT)) if timeout is None else timeout
    if limit <= 0 or request_timeout <= 0:
        raise DownloadSecurityError("ค่าจำกัดขนาดหรือ timeout ต้องมากกว่า 0")

    last_error: Exception | None = None
    for address in addresses:
        connection = _PinnedHTTPSConnection(hostname, address, request_timeout)
        try:
            connection.request(
                "GET",
                request_target,
                headers={"Host": hostname, "User-Agent": "Gemini-PC-MCP/1.0", "Connection": "close"},
            )
            response = connection.getresponse()
            if 300 <= response.status < 400:
                raise DownloadSecurityError("ไม่อนุญาตให้เปลี่ยนเส้นทางดาวน์โหลด (redirect)")
            if response.status < 200 or response.status >= 300:
                raise DownloadSecurityError(f"ดาวน์โหลดไม่สำเร็จ: HTTP {response.status}")

            length = response.getheader("Content-Length")
            if length is not None:
                try:
                    declared_length = int(length)
                except ValueError as exc:
                    raise DownloadSecurityError("Content-Length ไม่ถูกต้อง") from exc
                if declared_length < 0:
                    raise DownloadSecurityError("Content-Length ไม่ถูกต้อง")
                if declared_length > limit:
                    raise DownloadSecurityError("ไฟล์ดาวน์โหลดมีขนาดเกินกำหนด")

            data = response.read(limit + 1)
            if len(data) > limit:
                raise DownloadSecurityError("ไฟล์ดาวน์โหลดมีขนาดเกินกำหนด")
            return data
        except DownloadSecurityError:
            raise
        except (OSError, http.client.HTTPException, TimeoutError) as exc:
            last_error = exc
        finally:
            connection.close()

    raise DownloadSecurityError("เชื่อมต่อปลายทางดาวน์โหลดไม่สำเร็จ") from last_error
