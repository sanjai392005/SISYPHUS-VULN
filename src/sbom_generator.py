"""
SBOM Generator Module

Generates Software Bill of Materials (SBOM) in CycloneDX 1.5 JSON format
from Jupyter notebook dependency analysis.
"""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any

from .dependency_tree import DependencyNode


def generate_purl(package_name: str, version: str) -> str:
    """
    Generate a Package URL (purl) for a PyPI package.
    
    Format: pkg:pypi/package-name@version
    """
    # Normalize name: lowercase, hyphens instead of underscores
    normalized = package_name.lower().replace('_', '-')
    return f"pkg:pypi/{normalized}@{version}"


def package_to_component(node: DependencyNode) -> dict:
    """
    Convert a DependencyNode to a CycloneDX component.
    """
    purl = generate_purl(node.name, node.version)
    
    component = {
        "type": "library",
        "bom-ref": purl,
        "name": node.name,
        "version": node.version,
        "purl": purl,
        "properties": [
            {
                "name": "sisyphus:dependency:direct",
                "value": str(node.is_direct).lower()
            }
        ]
    }
    
    return component


def build_dependencies_section(
    tree: Dict[str, DependencyNode]
) -> List[dict]:
    """
    Build the dependencies section showing package relationships.
    """
    dependencies = []
    
    for name, node in tree.items():
        purl = generate_purl(node.name, node.version)
        
        dep_entry = {"ref": purl}
        
        if node.dependencies:
            dep_entry["dependsOn"] = [
                generate_purl(child.name, child.version)
                for child in node.dependencies
            ]
        
        dependencies.append(dep_entry)
    
    return dependencies


def vulnerability_to_cyclonedx(
    vuln_id: str,
    summary: str,
    severity: str,
    affected_purl: str,
    cve_id: Optional[str] = None
) -> dict:
    """
    Convert vulnerability data to CycloneDX format.
    """
    vuln = {
        "id": vuln_id,
        "source": {
            "name": "OSV",
            "url": "https://osv.dev"
        },
        "ratings": [
            {
                "severity": severity.lower(),
                "method": "other"
            }
        ],
        "description": summary,
        "affects": [
            {
                "ref": affected_purl
            }
        ]
    }
    
    if cve_id:
        vuln["references"] = [
            {
                "id": cve_id,
                "source": {"name": "NVD"}
            }
        ]
    
    return vuln


def generate_cyclonedx_sbom(
    source: str,
    dependency_tree: Dict[str, DependencyNode],
    vulnerabilities: Optional[Dict[str, List[Any]]] = None,
    include_vulnerabilities: bool = True
) -> dict:
    """
    Generate a complete CycloneDX 1.5 SBOM.
    
    Args:
        source: Path to the scanned file (notebook or project)
        dependency_tree: Complete dependency tree from build_dependency_tree()
        vulnerabilities: Optional dict mapping package names to Vulnerability objects
        include_vulnerabilities: Whether to include vulnerability data in SBOM
        
    Returns:
        CycloneDX 1.5 compliant SBOM as dict
    """
    source_path = Path(source)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    
    # Build components list
    components = [
        package_to_component(node) 
        for node in dependency_tree.values()
    ]
    
    # Sort components: direct first, then alphabetically
    components.sort(key=lambda c: (
        c["properties"][0]["value"] != "true",  # direct first
        c["name"].lower()
    ))
    
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "author": "SISYPHUS",
                        "name": "sisyphus-vuln",
                        "version": "0.1.0"
                    }
                ]
            },
            "component": {
                "type": "application",
                "bom-ref": source,
                "name": source_path.name,
                "description": f"Dependencies extracted from {source_path.name}"
            }
        },
        "components": components,
        "dependencies": build_dependencies_section(dependency_tree)
    }
    
    # Add vulnerabilities if available and requested
    if include_vulnerabilities and vulnerabilities:
        vuln_list = []
        for pkg_name, pkg_vulns in vulnerabilities.items():
            node = dependency_tree.get(pkg_name.lower().replace('_', '-'))
            if node:
                purl = generate_purl(node.name, node.version)
                for vuln in pkg_vulns:
                    vuln_list.append(vulnerability_to_cyclonedx(
                        vuln_id=vuln.id,
                        summary=vuln.summary,
                        severity=vuln.severity.value if hasattr(vuln.severity, 'value') else str(vuln.severity),
                        affected_purl=purl,
                        cve_id=getattr(vuln, 'cve_id', None)
                    ))
        
        if vuln_list:
            sbom["vulnerabilities"] = vuln_list
    
    return sbom


def save_sbom(sbom: dict, output_path: str) -> str:
    """
    Save SBOM to a JSON file.
    
    Args:
        sbom: CycloneDX SBOM dict
        output_path: Path to save the file
        
    Returns:
        Absolute path to the saved file
    """
    output = Path(output_path)
    
    with open(output, 'w', encoding='utf-8') as f:
        json.dump(sbom, f, indent=2)
    
    return str(output.absolute())


def sbom_summary(sbom: dict) -> dict:
    """
    Get a summary of the SBOM contents.
    """
    components = sbom.get("components", [])
    direct = sum(1 for c in components 
                 if any(p["value"] == "true" for p in c.get("properties", [])))
    
    return {
        "total_components": len(components),
        "direct_dependencies": direct,
        "transitive_dependencies": len(components) - direct,
        "vulnerabilities": len(sbom.get("vulnerabilities", [])),
        "format": f"{sbom['bomFormat']} {sbom['specVersion']}"
    }
