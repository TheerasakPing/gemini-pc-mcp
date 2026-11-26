import os
import unittest
from unittest.mock import patch

from security import (
    DownloadSecurityError,
    _resolve_public_addresses,
    download_url,
    validate_download_url,
)


class DownloadValidationTests(unittest.TestCase):
    def test_rejects_non_https(self):
        with patch.dict(os.environ, {"MCP_DOWNLOAD_ALLOWED_HOSTS": "files.example.com"}):
            with self.assertRaises(DownloadSecurityError):
                validate_download_url("http://files.example.com/file")

    def test_rejects_host_not_on_allowlist(self):
        with patch.dict(os.environ, {"MCP_DOWNLOAD_ALLOWED_HOSTS": "trusted.example.com"}):
            with self.assertRaises(DownloadSecurityError):
                validate_download_url("https://attacker.example.com/file")

    def test_rejects_embedded_credentials(self):
        with patch.dict(os.environ, {"MCP_DOWNLOAD_ALLOWED_HOSTS": "files.example.com"}):
            with self.assertRaises(DownloadSecurityError):
                validate_download_url("https://user:pass@files.example.com/file")

    def test_rejects_nonstandard_port(self):
        with patch.dict(os.environ, {"MCP_DOWNLOAD_ALLOWED_HOSTS": "files.example.com"}):
            with self.assertRaises(DownloadSecurityError):
                validate_download_url("https://files.example.com:8443/file")

    @patch("security.socket.getaddrinfo")
    def test_rejects_private_dns_resolution(self, getaddrinfo):
        getaddrinfo.return_value = [(2, 1, 6, "", ("127.0.0.1", 443))]
        with self.assertRaises(DownloadSecurityError):
            _resolve_public_addresses("files.example.com")

    @patch("security.socket.getaddrinfo")
    def test_rejects_mixed_public_and_private_dns_answers(self, getaddrinfo):
        getaddrinfo.return_value = [
            (2, 1, 6, "", ("8.8.8.8", 443)),
            (2, 1, 6, "", ("10.0.0.5", 443)),
        ]
        with self.assertRaises(DownloadSecurityError):
            _resolve_public_addresses("files.example.com")

    @patch("security._PinnedHTTPSConnection")
    @patch("security._resolve_public_addresses", return_value=["8.8.8.8"])
    def test_download_uses_validated_ip(self, resolve, connection_class):
        response = connection_class.return_value.getresponse.return_value
        response.status = 200
        response.getheader.return_value = "3"
        response.read.return_value = b"abc"

        with patch.dict(os.environ, {"MCP_DOWNLOAD_ALLOWED_HOSTS": "files.example.com"}):
            self.assertEqual(download_url("https://files.example.com/a"), b"abc")

        connection_class.assert_called_once_with("files.example.com", "8.8.8.8", 20)
        connection_class.return_value.request.assert_called_once()

    @patch("security._PinnedHTTPSConnection")
    @patch("security._resolve_public_addresses", return_value=["8.8.8.8"])
    def test_rejects_response_body_over_limit(self, resolve, connection_class):
        response = connection_class.return_value.getresponse.return_value
        response.status = 200
        response.getheader.return_value = None
        response.read.return_value = b"12345"

        with patch.dict(os.environ, {"MCP_DOWNLOAD_ALLOWED_HOSTS": "files.example.com"}):
            with self.assertRaises(DownloadSecurityError):
                download_url("https://files.example.com/file", max_bytes=4)

    @patch("security._PinnedHTTPSConnection")
    @patch("security._resolve_public_addresses", return_value=["8.8.8.8"])
    def test_rejects_oversized_content_length_before_read(self, resolve, connection_class):
        response = connection_class.return_value.getresponse.return_value
        response.status = 200
        response.getheader.return_value = "100"

        with patch.dict(os.environ, {"MCP_DOWNLOAD_ALLOWED_HOSTS": "files.example.com"}):
            with self.assertRaises(DownloadSecurityError):
                download_url("https://files.example.com/file", max_bytes=10)
        response.read.assert_not_called()


if __name__ == "__main__":
    unittest.main()
