"""
Scanner Module

Main orchestration module that coordinates the vulnerability scanning workflow.
Detects input type and routes to appropriate handlers.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set
from datetime import datetime

from .ipynb_parser import parse_notebook, NotebookParseError
from .ast_extractor import extract_imports_from_cells, filter_stdlib
from .package_mapper import map_imports_to_packages, PackageMapper
from .version_resolver import VersionResolver, PackageInfo
from .osv_client import OSVClient, PackageVulnerabilities, Vulnerability, Severity
from .syft_wrapper import (
    SyftWrapper, 
    SyftNotAvailableError,
    scan_requirements_txt,
    scan_pyproject_toml
)
from .dependency_tree import (
    build_dependency_tree,
    get_all_packages_flat,
    get_dependency_stats,
    DependencyNode
)
from .sbom_generator import generate_cyclonedx_sbom, save_sbom, sbom_summary


@dataclass
class ScanResult:
    """Complete scan result for a file or project."""
    source: str
    source_type: str  # 'notebook', 'project', 'requirements'
    scan_time: str
    total_packages: int
    vulnerable_packages: int
    packages: Dict[str, PackageVulnerabilities]
    unresolved_imports: Set[str] = field(default_factory=set)
    errors: List[str] = field(default_factory=list)
    # New fields for transitive dependency tracking
    direct_packages: int = 0
    transitive_packages: int = 0
    dependency_tree: Optional[Dict[str, DependencyNode]] = None
    
    @property
    def total_vulnerabilities(self) -> int:
        return sum(len(p.vulnerabilities) for p in self.packages.values())
    
    @property
    def critical_count(self) -> int:
        return sum(p.critical_count for p in self.packages.values())
    
    @property
    def high_count(self) -> int:
        return sum(p.high_count for p in self.packages.values())
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            'source': self.source,
            'source_type': self.source_type,
            'scan_time': self.scan_time,
            'summary': {
                'total_packages': self.total_packages,
                'direct_packages': self.direct_packages,
                'transitive_packages': self.transitive_packages,
                'vulnerable_packages': self.vulnerable_packages,
                'total_vulnerabilities': self.total_vulnerabilities,
                'critical': self.critical_count,
                'high': self.high_count,
            },
            'packages': {
                name: {
                    'name': pkg.package_name,
                    'version': pkg.version,
                    'vulnerabilities': [
                        {
                            'id': v.id,
                            'summary': v.summary,
                            'severity': v.severity.value,
                            'cve_id': v.cve_id,
                            'url': v.osv_url,
                            'aliases': v.aliases,
                        }
                        for v in pkg.vulnerabilities
                    ]
                }
                for name, pkg in self.packages.items()
            },
            'unresolved_imports': list(self.unresolved_imports),
            'errors': self.errors,
        }
    
    def generate_sbom(self, output_path: Optional[str] = None) -> dict:
        """
        Generate a CycloneDX SBOM from the scan result.
        
        Args:
            output_path: Optional path to save the SBOM file
            
        Returns:
            CycloneDX SBOM as dict
        """
        if not self.dependency_tree:
            # No tree available, create basic SBOM from packages
            from .dependency_tree import DependencyNode
            self.dependency_tree = {
                pkg.package_name.lower(): DependencyNode(
                    name=pkg.package_name,
                    version=pkg.version,
                    is_direct=True
                )
                for pkg in self.packages.values()
            }
        
        # Collect vulnerabilities by package
        vulns_by_pkg = {}
        for name, pkg in self.packages.items():
            if pkg.vulnerabilities:
                vulns_by_pkg[name] = pkg.vulnerabilities
        
        sbom = generate_cyclonedx_sbom(
            source=self.source,
            dependency_tree=self.dependency_tree,
            vulnerabilities=vulns_by_pkg
        )
        
        if output_path:
            save_sbom(sbom, output_path)
        
        return sbom


class VulnerabilityScanner:
    """
    Main scanner class that orchestrates the vulnerability detection workflow.
    """
    
    def __init__(self):
        self.osv_client = OSVClient()
        self.version_resolver = VersionResolver()
        self.package_mapper = PackageMapper()
        self.syft_wrapper = SyftWrapper()
    
    def scan(self, path: str) -> ScanResult:
        """
        Scan a file or project for vulnerabilities.
        
        Automatically detects the input type and uses the appropriate method:
        - .ipynb files: Novel AST-based extraction
        - Directories: Syft SBOM generation (or fallback)
        - requirements.txt: Direct parsing
        - pyproject.toml: Direct parsing
        
        Args:
            path: Path to file or directory
            
        Returns:
            ScanResult with vulnerability information
        """
        path_obj = Path(path)
        
        if not path_obj.exists():
            return self._error_result(path, f"Path not found: {path}")
        
        # Route to appropriate handler
        if path_obj.is_file():
            if path_obj.suffix.lower() == '.ipynb':
                return self.scan_notebook(path)
            elif path_obj.name == 'requirements.txt':
                return self.scan_requirements(path)
            elif path_obj.name == 'pyproject.toml':
                return self.scan_pyproject(path)
            else:
                return self._error_result(path, f"Unsupported file type: {path_obj.suffix}")
        else:
            return self.scan_project(path)
    
    def scan_notebook(self, notebook_path: str) -> ScanResult:
        """
        Scan a Jupyter Notebook for vulnerable dependencies.
        
        This is the novel workflow:
        1. Parse notebook to extract code cells
        2. Use AST to detect imports
        3. Map imports to package names
        4. Resolve versions from local environment
        5. Build transitive dependency tree
        6. Query OSV for ALL dependencies (direct + transitive)
        
        Args:
            notebook_path: Path to .ipynb file
            
        Returns:
            ScanResult with vulnerability information
        """
        errors = []
        
        # Step 1: Parse notebook
        try:
            code_cells = parse_notebook(notebook_path)
        except (NotebookParseError, FileNotFoundError) as e:
            return self._error_result(notebook_path, str(e), 'notebook')
        
        # Step 2: Extract imports using AST
        all_imports = extract_imports_from_cells(code_cells)
        
        # Filter out standard library
        external_imports = filter_stdlib(all_imports)
        
        # Step 3: Map imports to package names
        import_to_package = self.package_mapper.bulk_map(external_imports)
        package_names = set(import_to_package.values())
        
        # Step 4: Resolve versions from local environment (direct packages)
        package_versions = self.version_resolver.get_versions(package_names)
        
        # Track unresolved packages
        unresolved = {
            imp for imp, pkg in import_to_package.items() 
            if package_versions.get(pkg) is None
        }
        
        # Direct packages to scan
        direct_packages = {
            name: ver for name, ver in package_versions.items() 
            if ver is not None
        }
        
        # Step 5: Build transitive dependency tree (NEW)
        dependency_tree = build_dependency_tree(direct_packages)
        dep_stats = get_dependency_stats(dependency_tree)
        
        # Step 6: Get ALL packages (direct + transitive) for scanning
        all_packages = get_all_packages_flat(direct_packages)
        
        # Query OSV for ALL packages
        pkg_vulns = self._scan_packages(all_packages)
        
        # Count vulnerable packages
        vulnerable_count = sum(1 for p in pkg_vulns.values() if p.has_vulnerabilities)
        
        return ScanResult(
            source=notebook_path,
            source_type='notebook',
            scan_time=datetime.now().isoformat(),
            total_packages=len(all_packages),
            vulnerable_packages=vulnerable_count,
            packages=pkg_vulns,
            unresolved_imports=unresolved,
            errors=errors,
            direct_packages=dep_stats['direct'],
            transitive_packages=dep_stats['transitive'],
            dependency_tree=dependency_tree,
        )
    
    def scan_project(self, project_path: str) -> ScanResult:
        """
        Scan a project directory for vulnerable dependencies.
        
        Uses Syft if available, falls back to requirements.txt parsing.
        
        Args:
            project_path: Path to project directory
            
        Returns:
            ScanResult with vulnerability information
        """
        errors = []
        packages_to_scan = {}
        
        # Try Syft first
        if self.syft_wrapper.is_available:
            try:
                packages_to_scan = self.syft_wrapper.get_packages(project_path)
            except Exception as e:
                errors.append(f"Syft scan failed: {e}")
        
        # Fallback: look for requirements.txt or pyproject.toml
        if not packages_to_scan:
            req_path = Path(project_path) / 'requirements.txt'
            pyproject_path = Path(project_path) / 'pyproject.toml'
            
            if req_path.exists():
                packages_to_scan = scan_requirements_txt(str(req_path))
            elif pyproject_path.exists():
                packages_to_scan = scan_pyproject_toml(str(pyproject_path))
        
        # Resolve versions for packages without specified versions
        for name, ver in list(packages_to_scan.items()):
            if not ver:
                resolved = self.version_resolver.get_version(name)
                if resolved:
                    packages_to_scan[name] = resolved
                else:
                    del packages_to_scan[name]
                    errors.append(f"Could not resolve version for: {name}")
        
        # Query OSV
        pkg_vulns = self._scan_packages(packages_to_scan)
        vulnerable_count = sum(1 for p in pkg_vulns.values() if p.has_vulnerabilities)
        
        return ScanResult(
            source=project_path,
            source_type='project',
            scan_time=datetime.now().isoformat(),
            total_packages=len(packages_to_scan),
            vulnerable_packages=vulnerable_count,
            packages=pkg_vulns,
            errors=errors,
        )
    
    def scan_requirements(self, req_path: str) -> ScanResult:
        """Scan a requirements.txt file."""
        packages_to_scan = scan_requirements_txt(req_path)
        errors = []
        
        # Resolve missing versions
        for name, ver in list(packages_to_scan.items()):
            if not ver:
                resolved = self.version_resolver.get_version(name)
                if resolved:
                    packages_to_scan[name] = resolved
                else:
                    del packages_to_scan[name]
                    errors.append(f"Could not resolve version for: {name}")
        
        pkg_vulns = self._scan_packages(packages_to_scan)
        vulnerable_count = sum(1 for p in pkg_vulns.values() if p.has_vulnerabilities)
        
        return ScanResult(
            source=req_path,
            source_type='requirements',
            scan_time=datetime.now().isoformat(),
            total_packages=len(packages_to_scan),
            vulnerable_packages=vulnerable_count,
            packages=pkg_vulns,
            errors=errors,
        )
    
    def scan_pyproject(self, pyproject_path: str) -> ScanResult:
        """Scan a pyproject.toml file."""
        packages_to_scan = scan_pyproject_toml(pyproject_path)
        errors = []
        
        # Resolve missing versions
        for name, ver in list(packages_to_scan.items()):
            if not ver:
                resolved = self.version_resolver.get_version(name)
                if resolved:
                    packages_to_scan[name] = resolved
                else:
                    del packages_to_scan[name]
                    errors.append(f"Could not resolve version for: {name}")
        
        pkg_vulns = self._scan_packages(packages_to_scan)
        vulnerable_count = sum(1 for p in pkg_vulns.values() if p.has_vulnerabilities)
        
        return ScanResult(
            source=pyproject_path,
            source_type='pyproject',
            scan_time=datetime.now().isoformat(),
            total_packages=len(packages_to_scan),
            vulnerable_packages=vulnerable_count,
            packages=pkg_vulns,
            errors=errors,
        )
    
    def _scan_packages(self, packages: Dict[str, str]) -> Dict[str, PackageVulnerabilities]:
        """Query OSV for vulnerabilities in packages."""
        if not packages:
            return {}
        
        pkg_list = [{"name": n, "version": v} for n, v in packages.items()]
        results = self.osv_client.query_batch(pkg_list)
        
        pkg_vulns = {}
        for name, version in packages.items():
            key = f"{name}=={version}"
            vulns = results.get(key, [])
            pkg_vulns[name] = PackageVulnerabilities(
                package_name=name,
                version=version,
                vulnerabilities=vulns
            )
        
        return pkg_vulns
    
    def _error_result(self, source: str, error: str, source_type: str = 'unknown') -> ScanResult:
        """Create an error result."""
        return ScanResult(
            source=source,
            source_type=source_type,
            scan_time=datetime.now().isoformat(),
            total_packages=0,
            vulnerable_packages=0,
            packages={},
            errors=[error],
        )


# Convenience function
def scan(path: str) -> ScanResult:
    """
    Scan a file or project for vulnerabilities.
    
    Args:
        path: Path to notebook, requirements file, or project directory
        
    Returns:
        ScanResult with vulnerability information
    """
    scanner = VulnerabilityScanner()
    return scanner.scan(path)
