"""
OSV API Client Module
API Documentation: https://google.github.io/osv.dev/
"""

import requests
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from enum import Enum


class Severity(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


@dataclass
class Reference:
    """Reference link for a vulnerability."""
    type: str
    url: str


@dataclass
class AffectedRange:
    """Version range affected by a vulnerability."""
    type: str
    events: List[Dict[str, str]]
    repo: Optional[str] = None


@dataclass 
class Vulnerability:
    """Represents a single vulnerability from OSV."""
    id: str
    summary: str
    details: str
    severity: Severity
    published: str
    modified: str
    references: List[Reference] = field(default_factory=list)
    affected_versions: List[str] = field(default_factory=list)
    aliases: List[str] = field(default_factory=list)  # CVE IDs, etc.
    
    @property
    def cve_id(self) -> Optional[str]:
        """Get the CVE ID if available."""
        for alias in self.aliases:
            if alias.startswith('CVE-'):
                return alias
        return None
    
    @property
    def osv_url(self) -> str:
        """Get the OSV database URL for this vulnerability."""
        return f"https://osv.dev/vulnerability/{self.id}"


@dataclass
class PackageVulnerabilities:
    """Vulnerabilities for a specific package."""
    package_name: str
    version: str
    vulnerabilities: List[Vulnerability]
    
    @property
    def has_vulnerabilities(self) -> bool:
        return len(self.vulnerabilities) > 0
    
    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.CRITICAL)
    
    @property
    def high_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.HIGH)


class OSVClient:
    """
    Client for the OSV (Open Source Vulnerabilities) API.
    """
    
    BASE_URL = "https://api.osv.dev/v1"
    ECOSYSTEM = "PyPI"
    
    def __init__(self, timeout: int = 30):
        """
        Initialize the OSV client.
        
        Args:
            timeout: Request timeout in seconds
        """
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        })
    
    def query(self, package_name: str, version: str) -> List[Vulnerability]:
        """
        Query vulnerabilities for a specific package version.
        
        Args:
            package_name: The PyPI package name
            version: The package version
            
        Returns:
            List of vulnerabilities affecting this package version
        """
        payload = {
            "package": {
                "name": package_name,
                "ecosystem": self.ECOSYSTEM
            },
            "version": version
        }
        
        try:
            response = self.session.post(
                f"{self.BASE_URL}/query",
                json=payload,
                timeout=self.timeout
            )
            response.raise_for_status()
            
            data = response.json()
            return self._parse_vulnerabilities(data.get('vulns', []))
            
        except requests.exceptions.RequestException as e:
            # Log error but don't crash - return empty list
            print(f"Warning: Failed to query OSV for {package_name}=={version}: {e}")
            return []
    
    def query_batch(self, packages: List[Dict[str, str]]) -> Dict[str, List[Vulnerability]]:
        """
        Query vulnerabilities for multiple packages at once.
        
        Args:
            packages: List of dicts with 'name' and 'version' keys
            
        Returns:
            Dictionary mapping "name==version" to list of vulnerabilities
        """
        queries = []
        for pkg in packages:
            queries.append({
                "package": {
                    "name": pkg['name'],
                    "ecosystem": self.ECOSYSTEM
                },
                "version": pkg['version']
            })
        
        payload = {"queries": queries}
        
        try:
            response = self.session.post(
                f"{self.BASE_URL}/querybatch",
                json=payload,
                timeout=self.timeout
            )
            response.raise_for_status()
            
            data = response.json()
            results = {}
            
            for i, result in enumerate(data.get('results', [])):
                pkg = packages[i]
                key = f"{pkg['name']}=={pkg['version']}"
                vulns = self._parse_vulnerabilities(result.get('vulns', []))
                results[key] = vulns
            
            return results
            
        except requests.exceptions.RequestException as e:
            print(f"Warning: Batch query failed: {e}")
            # Fall back to individual queries
            results = {}
            for pkg in packages:
                key = f"{pkg['name']}=={pkg['version']}"
                results[key] = self.query(pkg['name'], pkg['version'])
            return results
    
    def get_vulnerability(self, vuln_id: str) -> Optional[Vulnerability]:
        """
        Get details for a specific vulnerability by ID.
        
        Args:
            vuln_id: The vulnerability ID (e.g., "GHSA-xxxx-xxxx-xxxx")
            
        Returns:
            Vulnerability details or None if not found
        """
        try:
            response = self.session.get(
                f"{self.BASE_URL}/vulns/{vuln_id}",
                timeout=self.timeout
            )
            response.raise_for_status()
            
            data = response.json()
            vulns = self._parse_vulnerabilities([data])
            return vulns[0] if vulns else None
            
        except requests.exceptions.RequestException:
            return None
    
    def _parse_vulnerabilities(self, vulns_data: List[Dict[str, Any]]) -> List[Vulnerability]:
        """Parse vulnerability data from API response."""
        vulnerabilities = []
        
        for vuln in vulns_data:
            # Extract severity
            severity = self._extract_severity(vuln)
            
            # Extract references
            references = [
                Reference(type=ref.get('type', 'WEB'), url=ref.get('url', ''))
                for ref in vuln.get('references', [])
            ]
            
            # Extract affected versions
            affected_versions = []
            for affected in vuln.get('affected', []):
                versions = affected.get('versions', [])
                affected_versions.extend(versions)
            
            vulnerabilities.append(Vulnerability(
                id=vuln.get('id', 'UNKNOWN'),
                summary=vuln.get('summary', 'No summary available'),
                details=vuln.get('details', ''),
                severity=severity,
                published=vuln.get('published', ''),
                modified=vuln.get('modified', ''),
                references=references,
                affected_versions=affected_versions,
                aliases=vuln.get('aliases', []),
            ))
        
        return vulnerabilities
    
    def _extract_severity(self, vuln: Dict[str, Any]) -> Severity:
        """Extract severity from vulnerability data."""
        # Try database_specific severity
        for affected in vuln.get('affected', []):
            db_specific = affected.get('database_specific', {})
            if 'severity' in db_specific:
                return self._parse_severity_string(db_specific['severity'])
            
            eco_specific = affected.get('ecosystem_specific', {})
            if 'severity' in eco_specific:
                return self._parse_severity_string(eco_specific['severity'])
        
        # Try severity array (CVSS)
        severity_list = vuln.get('severity', [])
        for sev in severity_list:
            if sev.get('type') == 'CVSS_V3':
                score = sev.get('score', '')
                return self._cvss_to_severity(score)
        
        return Severity.UNKNOWN
    
    def _parse_severity_string(self, severity_str: str) -> Severity:
        """Parse a severity string to Severity enum."""
        severity_str = severity_str.upper()
        try:
            return Severity(severity_str)
        except ValueError:
            return Severity.UNKNOWN
    
    def _cvss_to_severity(self, cvss_score: str) -> Severity:
        """Convert CVSS score to severity level."""
        try:
            # CVSS v3 format: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            # We need to parse this to get the score, or it might just be a number
            if '/' in cvss_score:
                # This is a vector string, we'd need to calculate
                return Severity.UNKNOWN
            
            score = float(cvss_score)
            if score >= 9.0:
                return Severity.CRITICAL
            elif score >= 7.0:
                return Severity.HIGH
            elif score >= 4.0:
                return Severity.MEDIUM
            elif score > 0:
                return Severity.LOW
            else:
                return Severity.UNKNOWN
        except (ValueError, TypeError):
            return Severity.UNKNOWN


# Convenience functions
def query_vulnerabilities(package_name: str, version: str) -> List[Vulnerability]:
    """Query OSV for vulnerabilities in a package."""
    client = OSVClient()
    return client.query(package_name, version)


def scan_packages(packages: Dict[str, str]) -> Dict[str, PackageVulnerabilities]:
    """
    Scan multiple packages for vulnerabilities.
    
    Args:
        packages: Dictionary mapping package names to versions
        
    Returns:
        Dictionary mapping package names to their vulnerability info
    """
    client = OSVClient()
    
    # Prepare batch query
    pkg_list = [{"name": name, "version": ver} for name, ver in packages.items() if ver]
    
    if not pkg_list:
        return {}
    
    # Query in batches
    results = client.query_batch(pkg_list)
    
    # Convert to PackageVulnerabilities
    pkg_vulns = {}
    for pkg in pkg_list:
        key = f"{pkg['name']}=={pkg['version']}"
        vulns = results.get(key, [])
        pkg_vulns[pkg['name']] = PackageVulnerabilities(
            package_name=pkg['name'],
            version=pkg['version'],
            vulnerabilities=vulns
        )
    
    return pkg_vulns
