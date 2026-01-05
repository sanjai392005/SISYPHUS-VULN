"""
Dependency Tree Resolver

Resolves the full transitive dependency tree for packages using importlib.metadata.
This enables scanning ALL dependencies (direct + transitive) for vulnerabilities.
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

try:
    from importlib.metadata import metadata, PackageNotFoundError
except ImportError:
    from importlib_metadata import metadata, PackageNotFoundError


@dataclass
class DependencyNode:
    """A node in the dependency tree."""
    name: str
    version: str
    is_direct: bool  # True if directly imported in notebook
    dependencies: List['DependencyNode'] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            'name': self.name,
            'version': self.version,
            'is_direct': self.is_direct,
            'dependencies': [dep.to_dict() for dep in self.dependencies]
        }


def parse_requirement(req_string: str) -> Optional[str]:
    """
    Parse a requirement string to extract the package name.
    
    Handles formats like:
        'requests>=2.0' -> 'requests'
        'urllib3[socks]>=1.0,<2' -> 'urllib3'
        'foo; python_version<"3.8"' -> 'foo'
        'bar[extra] (>=1.0); extra == "dev"' -> 'bar'
    """
    # Remove environment markers (everything after ;)
    req_string = req_string.split(';')[0].strip()
    
    # Remove extras [...]
    req_string = re.sub(r'\[.*?\]', '', req_string)
    
    # Remove version specifiers in parentheses
    req_string = re.sub(r'\s*\(.*?\)', '', req_string)
    
    # Remove version specifiers
    req_string = re.sub(r'[<>=!~].*$', '', req_string)
    
    # Extract just the package name
    match = re.match(r'^([A-Za-z0-9][A-Za-z0-9._-]*)', req_string.strip())
    if match:
        return match.group(1).lower().replace('_', '-')
    return None


def get_package_dependencies(package_name: str) -> List[str]:
    """
    Get the direct dependencies of a package.
    
    Returns list of package names (normalized, lowercase with hyphens).
    Skips optional/extra dependencies.
    """
    try:
        meta = metadata(package_name)
        requires = meta.get_all('Requires-Dist') or []
        
        deps = []
        for req in requires:
            # Skip optional/extra dependencies
            if 'extra ==' in req or 'extra==' in req:
                continue
            
            dep_name = parse_requirement(req)
            if dep_name:
                deps.append(dep_name)
        
        return deps
    except PackageNotFoundError:
        # Try alternative name formats
        for alt_name in [package_name.replace('-', '_'), package_name.replace('_', '-')]:
            try:
                meta = metadata(alt_name)
                requires = meta.get_all('Requires-Dist') or []
                deps = []
                for req in requires:
                    if 'extra ==' in req or 'extra==' in req:
                        continue
                    dep_name = parse_requirement(req)
                    if dep_name:
                        deps.append(dep_name)
                return deps
            except PackageNotFoundError:
                continue
        return []


def get_package_version(package_name: str) -> Optional[str]:
    """Get installed version of a package."""
    try:
        return metadata(package_name)['Version']
    except PackageNotFoundError:
        # Try alternative name formats
        for alt_name in [package_name.replace('-', '_'), package_name.replace('_', '-')]:
            try:
                return metadata(alt_name)['Version']
            except PackageNotFoundError:
                continue
        return None


def build_dependency_tree(
    direct_packages: Dict[str, str],
    max_depth: int = 10
) -> Dict[str, DependencyNode]:
    """
    Build complete dependency tree from direct packages.
    
    Args:
        direct_packages: Dict of directly imported packages with versions
                        {package_name: version}
        max_depth: Maximum recursion depth to prevent infinite loops
        
    Returns:
        Dict mapping all package names (lowercase) to their DependencyNode
    """
    all_packages: Dict[str, DependencyNode] = {}
    visited: Set[str] = set()
    
    def normalize_name(name: str) -> str:
        """Normalize package name for comparison."""
        return name.lower().replace('_', '-')
    
    def resolve_recursive(
        pkg_name: str, 
        is_direct: bool, 
        depth: int
    ) -> Optional[DependencyNode]:
        """Recursively resolve a package and its dependencies."""
        if depth > max_depth:
            return None
        
        normalized = normalize_name(pkg_name)
        
        # Already processed - return existing node
        if normalized in visited:
            return all_packages.get(normalized)
        
        visited.add(normalized)
        
        # Get version
        version = get_package_version(pkg_name)
        if not version:
            return None
        
        # Create node
        node = DependencyNode(
            name=pkg_name,
            version=version,
            is_direct=is_direct
        )
        all_packages[normalized] = node
        
        # Get dependencies and recurse
        deps = get_package_dependencies(pkg_name)
        for dep in deps:
            dep_normalized = normalize_name(dep)
            
            # Check if already resolved
            if dep_normalized in all_packages:
                node.dependencies.append(all_packages[dep_normalized])
            else:
                child_node = resolve_recursive(dep, is_direct=False, depth=depth + 1)
                if child_node:
                    node.dependencies.append(child_node)
        
        return node
    
    # Process all direct packages
    for pkg_name in direct_packages:
        resolve_recursive(pkg_name, is_direct=True, depth=0)
    
    return all_packages


def get_all_packages_flat(direct_packages: Dict[str, str]) -> Dict[str, str]:
    """
    Get ALL packages (direct + transitive) as flat dict.
    
    This is what you pass to OSV for scanning.
    
    Args:
        direct_packages: Dict of directly imported packages {name: version}
        
    Returns:
        Dict of ALL packages {name: version} including transitives
    """
    tree = build_dependency_tree(direct_packages)
    return {node.name: node.version for node in tree.values()}


def get_dependency_stats(tree: Dict[str, DependencyNode]) -> Dict[str, int]:
    """Get statistics about the dependency tree."""
    direct = sum(1 for node in tree.values() if node.is_direct)
    transitive = sum(1 for node in tree.values() if not node.is_direct)
    
    return {
        'direct': direct,
        'transitive': transitive,
        'total': direct + transitive
    }


def print_dependency_tree(tree: Dict[str, DependencyNode], indent: int = 0) -> None:
    """Print the dependency tree for debugging."""
    for name, node in sorted(tree.items()):
        if node.is_direct:
            prefix = "📦 " if indent == 0 else "├── "
            print(f"{' ' * indent}{prefix}{node.name}=={node.version}")
            for dep in node.dependencies:
                print(f"{' ' * (indent + 2)}└── {dep.name}=={dep.version}")
