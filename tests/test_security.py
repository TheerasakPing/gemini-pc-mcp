import os
import unittest
from unittest.mock import patch

from security import (
    DownloadSecurityError,
    _validate_public_resolution,
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
        getaddrinfo.return_value = [
            (2, 1, 6, "", ("127.0.0.1", 0))
        ]
        with self.assertRaises(DownloadSecurityError):
            _validate_public_resolution("files.example.com")

    @patch("security.socket.getaddrinfo")
    def test_rejects_mixed_public_and_private_dns_answers(self, getaddrinfo):
        getaddrinfo.return_value = [
            (2, 1, 6, "", ("8.8.8.8", 0)),
            (2, 1, 6, "", ("10.0.0.5", 0)),
        ]
        with self.assertRaises(DownloadSecurityError):
            _validate_public_resolution("files.example.com")


    @patch("security.validate_download_url")
    @patch("security.urllib.request.build_opener")
    def test_rejects_response_body_over_limit(self, build_opener, validate):
        class Response:
            headers = {}

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self, size):
                return b"12345"

        build_opener.return_value.open.return_value = Response()
        with self.assertRaises(DownloadSecurityError):
            download_url("https://files.example.com/file", max_bytes=4)

    @patch("security.validate_download_url")
    @patch("security.urllib.request.build_opener")
    def test_rejects_oversized_content_length_before_read(self, build_opener, validate):
        class Response:
            headers = {"Content-Length": "100"}

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self, size):
                raise AssertionError("body should not be read")

        build_opener.return_value.open.return_value = Response()
        with self.assertRaises(DownloadSecurityError):
            download_url("https://files.example.com/file", max_bytes=10)


if __name__ == "__main__":
    unittest.main()
