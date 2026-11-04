import asyncio
import io
import struct
import unittest
import zipfile

from fastapi import HTTPException, UploadFile
from backend.main import upload_apk, UPLOAD_DIR
from phase3_live_demo import extract_indicators, is_asn1_oid, check_ip


class TestZipSecurityAndOidFiltering(unittest.TestCase):
    """Regression tests for:
    1. Bounded ZIP entry-count policy (10,000 max entries).
    2. Decompression bomb, path traversal, oversized uncompressed bytes, and malformed ZIP rejection.
    3. X.509 ASN.1 Object Identifier (OID) filtering in threat intelligence indicator extraction.
    """

    def _create_synthetic_zip(self, count: int, entry_content: bytes = b"a") -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for i in range(count):
                zf.writestr(f"res/raw/file_{i}.txt", entry_content)
        return buf.getvalue()

    def test_normal_small_apk_passes(self):
        """1. A normal small APK passes."""
        zip_bytes = self._create_synthetic_zip(10)
        upload = UploadFile(filename="small_app.apk", file=io.BytesIO(zip_bytes))
        resp = asyncio.run(upload_apk(upload))
        self.assertIsNotNone(resp.upload_id)
        # Clean up created upload file
        uploaded_path = UPLOAD_DIR / f"upload_{resp.upload_id}.apk"
        if uploaded_path.exists():
            uploaded_path.unlink()

    def test_apk_with_2089_entries_passes(self):
        """2. An APK with 2,089 entries passes (Organic Maps scale)."""
        zip_bytes = self._create_synthetic_zip(2089)
        upload = UploadFile(filename="organic_maps_synthetic.apk", file=io.BytesIO(zip_bytes))
        resp = asyncio.run(upload_apk(upload))
        self.assertIsNotNone(resp.upload_id)
        uploaded_path = UPLOAD_DIR / f"upload_{resp.upload_id}.apk"
        if uploaded_path.exists():
            uploaded_path.unlink()

    def test_apk_with_2989_entries_passes(self):
        """3. An APK with 2,989 entries passes (Wikipedia scale)."""
        zip_bytes = self._create_synthetic_zip(2989)
        upload = UploadFile(filename="wikipedia_synthetic.apk", file=io.BytesIO(zip_bytes))
        resp = asyncio.run(upload_apk(upload))
        self.assertIsNotNone(resp.upload_id)
        uploaded_path = UPLOAD_DIR / f"upload_{resp.upload_id}.apk"
        if uploaded_path.exists():
            uploaded_path.unlink()

    def test_apk_with_5680_entries_passes(self):
        """4. An APK with 5,680 entries passes (Feeder scale)."""
        zip_bytes = self._create_synthetic_zip(5680)
        upload = UploadFile(filename="feeder_synthetic.apk", file=io.BytesIO(zip_bytes))
        resp = asyncio.run(upload_apk(upload))
        self.assertIsNotNone(resp.upload_id)
        uploaded_path = UPLOAD_DIR / f"upload_{resp.upload_id}.apk"
        if uploaded_path.exists():
            uploaded_path.unlink()

    def test_apk_exceeding_entry_limit_rejected(self):
        """5. An APK exceeding the new entry-count limit (10,000) is rejected with HTTP 413."""
        zip_bytes = self._create_synthetic_zip(10001)
        upload = UploadFile(filename="too_many_entries.apk", file=io.BytesIO(zip_bytes))
        with self.assertRaises(HTTPException) as ctx:
            asyncio.run(upload_apk(upload))
        self.assertEqual(ctx.exception.status_code, 413)
        self.assertIn("10001 entries (limit: 10000)", str(ctx.exception.detail))

    def test_archive_exceeding_expanded_size_rejected(self):
        """6. An archive exceeding the aggregate expanded-size limit (500 MiB) is rejected with HTTP 413."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("a.txt", b"hello")
        data = bytearray(buf.getvalue())
        cd_sig = b"PK\x01\x02"
        idx = data.find(cd_sig)
        self.assertNotEqual(idx, -1)
        # Patch central directory: compress_size = 250 MiB, file_size = 501 MiB (ratio = 2.0x < 50x)
        data[idx + 20 : idx + 24] = struct.pack("<I", 262668288)
        data[idx + 24 : idx + 28] = struct.pack("<I", 525336576)

        upload = UploadFile(filename="oversized_uncompressed.apk", file=io.BytesIO(bytes(data)))
        with self.assertRaises(HTTPException) as ctx:
            asyncio.run(upload_apk(upload))
        self.assertEqual(ctx.exception.status_code, 413)
        self.assertIn("total uncompressed size exceeds limit (500 MiB)", str(ctx.exception.detail))

    def test_archive_violating_compression_ratio_rejected(self):
        """7. An archive violating the compression-ratio restriction (> 50.0x) is rejected with HTTP 415."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            # 100,000 bytes of zeros compresses to ~115 bytes (ratio > 800x > 50x)
            zf.writestr("zero_bomb.bin", b"0" * 100000)

        upload = UploadFile(filename="zip_bomb.apk", file=io.BytesIO(buf.getvalue()))
        with self.assertRaises(HTTPException) as ctx:
            asyncio.run(upload_apk(upload))
        self.assertEqual(ctx.exception.status_code, 415)
        self.assertIn("suspicious compression ratio", str(ctx.exception.detail))

    def test_archive_path_traversal_rejected(self):
        """8. An archive containing path traversal entries is rejected with HTTP 415."""
        # Test "../evil.dex"
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("../evil.dex", b"malicious")
        upload = UploadFile(filename="traversal.apk", file=io.BytesIO(buf.getvalue()))
        with self.assertRaises(HTTPException) as ctx:
            asyncio.run(upload_apk(upload))
        self.assertEqual(ctx.exception.status_code, 415)
        self.assertIn("path traversal", str(ctx.exception.detail))

        # Test absolute slash "/classes.dex"
        buf_slash = io.BytesIO()
        with zipfile.ZipFile(buf_slash, "w") as zf:
            zf.writestr("/classes.dex", b"malicious")
        upload_slash = UploadFile(filename="traversal_slash.apk", file=io.BytesIO(buf_slash.getvalue()))
        with self.assertRaises(HTTPException) as ctx:
            asyncio.run(upload_apk(upload_slash))
        self.assertEqual(ctx.exception.status_code, 415)
        self.assertIn("path traversal", str(ctx.exception.detail))

    def test_malformed_zip_rejected(self):
        """9. A malformed ZIP is rejected with HTTP 415."""
        malformed_bytes = b"PK\x03\x04NOT_A_VALID_ZIP_ARCHIVE_DATA_CORRUPTED"
        upload = UploadFile(filename="corrupted.apk", file=io.BytesIO(malformed_bytes))
        with self.assertRaises(HTTPException) as ctx:
            asyncio.run(upload_apk(upload))
        self.assertEqual(ctx.exception.status_code, 415)
        self.assertIn("corrupted or not a valid ZIP format", str(ctx.exception.detail))

    def test_x509_oid_filtering_in_static_indicators(self):
        """10. Verify that X.509 OIDs (2.5.29.17, 2.5.4.3, 1.2.840.*) are rejected while legitimate IPs pass."""
        test_strings = [
            "2.5.29.17",               # SubjectAlternativeName
            "2.5.29.19",               # BasicConstraints
            "2.5.4.3",                 # CommonName (CN)
            "2.5.4.10",                # Organization (O)
            "1.2.840.113549.1.1.11",   # sha256WithRSAEncryption
            "1.3.6.1.5.5.7.1.1",       # Authority Information Access
            "2.16.840.1.101.3.4.2.1",  # SHA-256
            "8.8.8.8",                 # Legitimate public IPv4 (Google DNS)
            "1.1.1.1",                 # Legitimate public IPv4 (Cloudflare DNS)
            "2001:4860:4860::8888",    # Legitimate public IPv6
            "192.168.1.1",             # Private IPv4 (RFC 1918)
            "127.0.0.1",               # Loopback
        ]

        ips, domains, ignored = extract_indicators(test_strings)

        # Legitimate public IPs must be extracted
        self.assertIn("8.8.8.8", ips)
        self.assertIn("1.1.1.1", ips)
        self.assertIn("2001:4860:4860::8888", ips)

        # OIDs must NOT be present in ips
        self.assertNotIn("2.5.29.17", ips)
        self.assertNotIn("2.5.29.19", ips)
        self.assertNotIn("2.5.4.3", ips)
        self.assertNotIn("2.5.4.10", ips)
        self.assertNotIn("1.2.840.113549.1.1.11", ips)
        self.assertNotIn("1.3.6.1.5.5.7.1.1", ips)
        self.assertNotIn("2.16.840.1.101.3.4.2.1", ips)

        # Private / loopback must not be present
        self.assertNotIn("192.168.1.1", ips)
        self.assertNotIn("127.0.0.1", ips)

    def test_check_ip_rejects_oid_directly(self):
        """11. check_ip raises ValueError if invoked with an X.509 OID string."""
        with self.assertRaises(ValueError) as ctx:
            check_ip("2.5.29.17", api_key="test_key")
        self.assertIn("X.509 / ASN.1 Object Identifier", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
