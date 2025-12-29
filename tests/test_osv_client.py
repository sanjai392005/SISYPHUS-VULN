"""
Tests for OSV Client
"""

import pytest
from unittest.mock import patch, MagicMock

from src.osv_client import (
    OSVClient,
    Vulnerability,
    Severity,
    query_vulnerabilities,
    scan_packages,
)


class TestOSVClient:
    """Test cases for OSV API client."""
    
    @pytest.fixture
    def client(self):
        return OSVClient(timeout=10)
    
    @pytest.fixture
    def mock_response(self):
        return {
            "vulns": [
                {
                    "id": "GHSA-test-1234",
                    "summary": "Test vulnerability",
                    "details": "This is a test vulnerability",
                    "published": "2024-01-01T00:00:00Z",
                    "modified": "2024-01-02T00:00:00Z",
                    "aliases": ["CVE-2024-1234"],
                    "references": [
                        {"type": "WEB", "url": "https://example.com"}
                    ],
                    "affected": [
                        {
                            "versions": ["1.0.0", "1.0.1"],
                            "ecosystem_specific": {"severity": "HIGH"}
                        }
                    ]
                }
            ]
        }
    
    def test_parse_vulnerabilities(self, client, mock_response):
        vulns = client._parse_vulnerabilities(mock_response["vulns"])
        
        assert len(vulns) == 1
        vuln = vulns[0]
        assert vuln.id == "GHSA-test-1234"
        assert vuln.summary == "Test vulnerability"
        assert vuln.severity == Severity.HIGH
        assert vuln.cve_id == "CVE-2024-1234"
        assert len(vuln.references) == 1
        assert vuln.affected_versions == ["1.0.0", "1.0.1"]
    
    def test_osv_url(self):
        vuln = Vulnerability(
            id="GHSA-test-1234",
            summary="Test",
            details="",
            severity=Severity.HIGH,
            published="",
            modified=""
        )
        assert vuln.osv_url == "https://osv.dev/vulnerability/GHSA-test-1234"
    
    def test_cve_id_extraction(self):
        vuln = Vulnerability(
            id="GHSA-test",
            summary="Test",
            details="",
            severity=Severity.HIGH,
            published="",
            modified="",
            aliases=["CVE-2024-5678", "GHSA-xxxx"]
        )
        assert vuln.cve_id == "CVE-2024-5678"
    
    def test_cve_id_none_when_no_cve(self):
        vuln = Vulnerability(
            id="GHSA-test",
            summary="Test",
            details="",
            severity=Severity.HIGH,
            published="",
            modified="",
            aliases=["GHSA-xxxx"]
        )
        assert vuln.cve_id is None
    
    def test_severity_parsing(self, client):
        assert client._parse_severity_string("CRITICAL") == Severity.CRITICAL
        assert client._parse_severity_string("HIGH") == Severity.HIGH
        assert client._parse_severity_string("MEDIUM") == Severity.MEDIUM
        assert client._parse_severity_string("LOW") == Severity.LOW
        assert client._parse_severity_string("INVALID") == Severity.UNKNOWN
    
    def test_cvss_to_severity(self, client):
        assert client._cvss_to_severity("9.5") == Severity.CRITICAL
        assert client._cvss_to_severity("7.5") == Severity.HIGH
        assert client._cvss_to_severity("5.0") == Severity.MEDIUM
        assert client._cvss_to_severity("2.0") == Severity.LOW
        assert client._cvss_to_severity("invalid") == Severity.UNKNOWN


class TestLiveOSVQuery:
    """Integration tests that hit the real OSV API.
    
    These tests require network access and may be slow.
    Mark with pytest.mark.integration to skip in CI.
    """
    
    @pytest.mark.integration
    def test_query_known_vulnerability(self):
        """Test querying a package with known vulnerabilities."""
        # requests 2.6.0 has CVE-2015-2296
        vulns = query_vulnerabilities("requests", "2.6.0")
        assert len(vulns) > 0
        
        # Check for the expected CVE
        cve_ids = [v.cve_id for v in vulns if v.cve_id]
        assert any("CVE" in cve for cve in cve_ids)
    
    @pytest.mark.integration  
    def test_query_safe_version(self):
        """Test querying a package version without known vulnerabilities."""
        # Latest requests should be safe (mostly)
        vulns = query_vulnerabilities("requests", "2.31.0")
        # We can't guarantee no vulns, but it should work without error
        assert isinstance(vulns, list)
    
    @pytest.mark.integration
    def test_scan_packages_batch(self):
        """Test batch scanning multiple packages."""
        packages = {
            "requests": "2.6.0",
            "flask": "0.12.0",  # Has known vulnerabilities
        }
        
        results = scan_packages(packages)
        
        assert "requests" in results
        assert "flask" in results
        assert results["requests"].package_name == "requests"
        assert results["flask"].package_name == "flask"


class TestSeverity:
    """Test Severity enum."""
    
    def test_severity_values(self):
        assert Severity.CRITICAL.value == "CRITICAL"
        assert Severity.HIGH.value == "HIGH"
        assert Severity.MEDIUM.value == "MEDIUM"
        assert Severity.LOW.value == "LOW"
        assert Severity.UNKNOWN.value == "UNKNOWN"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-m", "not integration"])
