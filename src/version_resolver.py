"""
Version Resolver Module -> Resolves package versions from the local Python environment using importlib.metadata.
"""

import subprocess
import sys
from dataclasses import dataclass
from typing import Dict, List, Optional, Set

try:
    from importlib.metadata import version, distributions, PackageNotFoundError
except ImportError:
    # Python < 3.8 fallback
    from importlib_metadata import version, distributions, PackageNotFoundError


@dataclass
class PackageInfo:
    name: str
    version: str
    location: Optional[str] = None


def get_package_version(package_name: str) -> Optional[str]:
    """
    Get the installed version of a package.
    
    Args:
        package_name: The PyPI package name
        
    Returns:
        Version string if installed, None otherwise
    """
    try:
        return version(package_name)
    except PackageNotFoundError:
        # Try case-insensitive search
        try:
            return version(package_name.lower())
        except PackageNotFoundError:
            # Try with underscores replaced by hyphens and vice versa
            alt_name = package_name.replace('_', '-')
            if alt_name != package_name:
                try:
                    return version(alt_name)
                except PackageNotFoundError:
                    pass
            
            alt_name = package_name.replace('-', '_')
            if alt_name != package_name:
                try:
                    return version(alt_name)
                except PackageNotFoundError:
                    pass
    
    return None


def get_all_installed_packages() -> Dict[str, str]:
    """
    Get all installed packages and their versions.
    
    Returns:
        Dictionary mapping package names to versions
    """
    packages = {}
    for dist in distributions():
        packages[dist.metadata['Name']] = dist.version
    return packages


def resolve_versions(package_names: Set[str]) -> Dict[str, Optional[str]]:
    """
    Resolve versions for multiple packages.
    
    Args:
        package_names: Set of package names to resolve
        
    Returns:
        Dictionary mapping package names to versions (or None if not installed)
    """
    return {pkg: get_package_version(pkg) for pkg in package_names}


def get_packages_with_versions(package_names: Set[str]) -> List[PackageInfo]:
    """
    Get package info for packages that are installed.
    
    Args:
        package_names: Set of package names to check
        
    Returns:
        List of PackageInfo for installed packages only
    """
    result = []
    for name in package_names:
        ver = get_package_version(name)
        if ver:
            result.append(PackageInfo(name=name, version=ver))
    return result


def get_environment_info() -> Dict[str, str]:
    """
    Get information about the current Python environment.
    
    Returns:
        Dictionary with environment details
    """
    return {
        'python_version': sys.version,
        'python_executable': sys.executable,
        'platform': sys.platform,
    }


class VersionResolver:
    """
    Version resolver with caching for performance.
    """
    
    def __init__(self):
        self._cache: Dict[str, Optional[str]] = {}
        self._all_packages: Optional[Dict[str, str]] = None
    
    def get_version(self, package_name: str) -> Optional[str]:
        """Get package version with caching."""
        if package_name not in self._cache:
            self._cache[package_name] = get_package_version(package_name)
        return self._cache[package_name]
    
    def get_versions(self, package_names: Set[str]) -> Dict[str, Optional[str]]:
        """Get versions for multiple packages."""
        return {pkg: self.get_version(pkg) for pkg in package_names}
    
    def refresh_cache(self):
        """Clear the version cache."""
        self._cache.clear()
        self._all_packages = None
    
    def get_all_packages(self) -> Dict[str, str]:
        """Get all installed packages (cached)."""
        if self._all_packages is None:
            self._all_packages = get_all_installed_packages()
        return self._all_packages
    
    def find_package(self, search_term: str) -> List[PackageInfo]:
        """
        Search for packages matching a term.
        
        Args:
            search_term: Partial package name to search for
            
        Returns:
            List of matching PackageInfo objects
        """
        all_pkgs = self.get_all_packages()
        matches = []
        
        search_lower = search_term.lower()
        for name, ver in all_pkgs.items():
            if search_lower in name.lower():
                matches.append(PackageInfo(name=name, version=ver))
        
        return matches


def get_requirements_versions(requirements_file: str) -> Dict[str, Optional[str]]:
    """
    Parse a requirements.txt file and get installed versions.
    
    Args:
        requirements_file: Path to requirements.txt
        
    Returns:
        Dictionary mapping package names to installed versions
    """
    packages = set()
    
    try:
        with open(requirements_file, 'r') as f:
            for line in f:
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue
                # Extract package name (before any version specifier)
                pkg_name = line.split('==')[0].split('>=')[0].split('<=')[0].split('~=')[0].split('[')[0].strip()
                if pkg_name:
                    packages.add(pkg_name)
    except FileNotFoundError:
        return {}
    
    return resolve_versions(packages)
