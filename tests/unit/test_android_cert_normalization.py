"""Regression coverage for android cert normalization."""
from __future__ import annotations

import pytest

import google_api_scanner as gas


class TestAndroidCertNormalization:
    @pytest.mark.unit
    def test_colon_separated_sha1_becomes_colonless_upper(self):
        h = gas._build_restriction_headers(
            "android", "com.victim.app:AA:BB:CC:DD:EE:FF:00:11")
        assert h["X-Android-Package"] == "com.victim.app"
        assert h["X-Android-Cert"] == "AABBCCDDEEFF0011"
        assert ":" not in h["X-Android-Cert"]

    @pytest.mark.unit
    def test_colonless_lowercase_sha1_becomes_upper(self):
        h = gas._build_restriction_headers(
            "android", "com.victim.app:aabbccddeeff0011")
        assert h["X-Android-Cert"] == "AABBCCDDEEFF0011"

    @pytest.mark.unit
    def test_colonless_uppercase_sha1_preserved(self):
        h = gas._build_restriction_headers(
            "android", "com.victim.app:AABBCCDDEEFF0011")
        assert h["X-Android-Cert"] == "AABBCCDDEEFF0011"

    @pytest.mark.unit
    def test_package_only_value_sets_package_no_cert(self):
        h = gas._build_restriction_headers("android", "com.victim.app")
        assert h["X-Android-Package"] == "com.victim.app"
        assert "X-Android-Cert" not in h

    @pytest.mark.unit
    def test_real_sha1_with_40_hex_chars(self):
        sha1 = ":".join(["%02X" % b for b in range(20)])  # 20 colon-joined byte pairs
        h = gas._build_restriction_headers("android", "com.app:" + sha1)
        cert = h["X-Android-Cert"]
        assert ":" not in cert
        assert len(cert) == 40
        assert cert == cert.upper()

    @pytest.mark.unit
    def test_other_modes_unaffected(self):
        assert gas._build_restriction_headers("none", "") == {}
        ref = gas._build_restriction_headers("referer", "victim.com")
        assert ref["Referer"] == "https://victim.com"
        ios = gas._build_restriction_headers("ios", "com.victim.bundle")
        assert ios["X-Ios-Bundle-Identifier"] == "com.victim.bundle"
