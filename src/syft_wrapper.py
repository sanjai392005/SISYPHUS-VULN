"""
Syft Wrapper Module

Wraps the Syft CLI tool for SBOM generation on regular Python projects.
answers from requirements.txt if Syft not found
"""

import json
import subprocess
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple


@dataclass
class SBOMPackage:
    """A package found in an SBOM."""
    name: str
    version: str
    type: str = "python"
    location: Optional[str] = None
    purl: Optional[str] = None


@dataclass
class SBOM:
    """Software Bill of Materials."""
    packages: List[SBOMPackage]
    source: str
    format: str
    tool: str = "syft"


class SyftNotAvailableError(Exception):
    """Raised when Syft is not installed or not accessible."""
    pass


def check_syft_available() -> bool:
    """True if Syft is available"""
    return shutil.which('syft') is not None


def get_syft_version() -> Optional[str]:
    if not check_syft_available():
        return None
    
    try:
        result = subprocess.run(
            ['syft', 'version'],
            capture_output=True,
            text=True,
            timeout=10
        )
        # Parse version from output
        for line in result.stdout.split('\n'):
            if 'Version:' in line or line.strip().startswith('syft'):
                return line.strip()
        return result.stdout.strip().split('\n')[0]
    except (subprocess.TimeoutExpired, subprocess.SubprocessError):
        return None


def generate_sbom(project_path: str, output_format: str = "json") -> SBOM:
    """
    Generate an SBOM for a project using Syft.
    
    Args:
        project_path: Path to the project directory
        output_format: Output format (json, cyclonedx, spdx-json)
        
    Returns:
        SBOM object containing package information
        
    Raises:
        SyftNotAvailableError: If Syft is not installed
        FileNotFoundError: If the project path doesn't exist
    """
    if not check_syft_available():
        raise SyftNotAvailableError(
            "Syft is not installed. Install it from https://github.com/anchore/syft"
        )
    
    project = Path(project_path)
    if not project.exists():
        raise FileNotFoundError(f"Project path not found: {project_path}")
    
    try:
        result = subprocess.run(
            ['syft', str(project), '-o', 'json'],
            capture_output=True,
            text=True,
            timeout=120 )
        
        if result.returncode != 0:
            raise RuntimeError(f"Syft failed: {result.stderr}")
        
        sbom_data = json.loads(result.stdout)
        return _parse_syft_json(sbom_data, str(project))
        
    except subprocess.TimeoutExpired:
        raise RuntimeError("Syft timed out while analyzing project")
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Failed to parse Syft output: {e}")


def _parse_syft_json(data: Dict, source: str) -> SBOM:
    """Parse Syft JSON output into an SBOM object."""
    packages = []
    
    artifacts = data.get('artifacts', [])
    for artifact in artifacts:
        # Only include Python packages
        pkg_type = artifact.get('type', '').lower()
        if pkg_type not in ('python', 'pip', 'wheel', 'egg'):
            continue
        
        name = artifact.get('name', '')
        version = artifact.get('version', '')
        
        if not name or not version:
            continue
        
        # packageurl
        purl = None
        if 'purl' in artifact:
            purl = artifact['purl']
        
        locations = artifact.get('locations', [])
        location = locations[0].get('path') if locations else None
        
        packages.append(SBOMPackage(
            name=name,
            version=version,
            type=pkg_type,
            location=location,
            purl=purl
        ))
    
    return SBOM(
        packages=packages,
        source=source,
        format="syft-json",
        tool="syft"
    )


def extract_packages_from_sbom(sbom: SBOM) -> Dict[str, str]:
    return {pkg.name: pkg.version for pkg in sbom.packages}


def scan_project(project_path: str) -> Tuple[SBOM, Dict[str, str]]:
    sbom = generate_sbom(project_path)
    packages = extract_packages_from_sbom(sbom)
    return sbom, packages


class SyftWrapper:
    def __init__(self):
        self._available: Optional[bool] = None
        self._version: Optional[str] = None
    
    @property
    def is_available(self) -> bool:
        """Check if Syft is available (cached)."""
        if self._available is None:
            self._available = check_syft_available()
        return self._available
    
    @property
    def version(self) -> Optional[str]:
        """Get Syft version (cached)."""
        if self._version is None and self.is_available:
            self._version = get_syft_version()
        return self._version
    
    def scan(self, project_path: str) -> SBOM:
        if not self.is_available:
            raise SyftNotAvailableError("Syft is not installed")
        return generate_sbom(project_path)
    
    def get_packages(self, project_path: str) -> Dict[str, str]:
        sbom = self.scan(project_path)
        return extract_packages_from_sbom(sbom)


# Alternative: Pure Python fallback for when Syft is not available
def scan_requirements_txt(path: str) -> Dict[str, str]:
    """
    Parse requirements.txt for package information and return dictionary
    """
    packages = {}
    
    try:
        with open(path, 'r') as f:
            for line in f:
                line = line.strip()
                
                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue
                
                # Skip options (e.g., -r, --index-url)
                if line.startswith('-'):
                    continue
                
                # Parse package==version format
                if '==' in line:
                    name, version = line.split('==', 1)
                    packages[name.strip()] = version.strip().split('[')[0]
                elif '>=' in line:
                    name, version = line.split('>=', 1)
                    packages[name.strip()] = version.strip().split(',')[0]
                elif '<=' in line:
                    name, version = line.split('<=', 1)
                    packages[name.strip()] = version.strip().split(',')[0]
                else:
                    # Package without version
                    packages[line.split('[')[0].strip()] = ''
    
    except FileNotFoundError:
        pass
    
    return packages


def scan_pyproject_toml(path: str) -> Dict[str, str]:
    """
same as above but with toml
    """
    packages = {}
    
    try:
        import tomllib  # Python 3.11+
    except ImportError:
        try:
            import tomli as tomllib  # Fallback
        except ImportError:
            return packages  # Can't parse TOML
    
    try:
        with open(path, 'rb') as f:
            data = tomllib.load(f)
        
        # PEP 621 dependencies
        deps = data.get('project', {}).get('dependencies', [])
        for dep in deps:
            # Parse "package>=version" format
            for sep in ['==', '>=', '<=', '~=', '!=', '<', '>']:
                if sep in dep:
                    name, version = dep.split(sep, 1)
                    packages[name.strip()] = version.strip().split(',')[0].split(';')[0]
                    break
            else:
                packages[dep.split('[')[0].strip()] = ''
        
        # Poetry dependencies
        poetry_deps = data.get('tool', {}).get('poetry', {}).get('dependencies', {})
        for name, spec in poetry_deps.items():
            if name.lower() == 'python':
                continue
            if isinstance(spec, str):
                packages[name] = spec.lstrip('^~>=<!')
            elif isinstance(spec, dict):
                packages[name] = spec.get('version', '').lstrip('^~>=<!')
    
    except FileNotFoundError:
        pass
    
    return packages
