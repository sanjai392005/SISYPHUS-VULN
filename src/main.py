"""
CLI Entry Point

Command-line interface for the IPYNB Dependency Vulnerability Scanner.
"""

import argparse
import json
import sys
from pathlib import Path

from .scanner import VulnerabilityScanner, scan


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog='ipynb-vuln-scanner',
        description='Scan Python notebooks and projects for dependency vulnerabilities',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s notebook.ipynb              Scan a Jupyter notebook
  %(prog)s ./my_project                Scan a project directory
  %(prog)s requirements.txt            Scan a requirements file
  %(prog)s notebook.ipynb --json       Output results as JSON
  %(prog)s notebook.ipynb --dashboard  Start web dashboard with results
        """
    )
    
    parser.add_argument(
        'path',
        help='Path to notebook (.ipynb), requirements.txt, or project directory'
    )
    
    parser.add_argument(
        '--json', '-j',
        action='store_true',
        help='Output results as JSON'
    )
    
    parser.add_argument(
        '--output', '-o',
        help='Save results to file'
    )
    
    parser.add_argument(
        '--dashboard', '-d',
        action='store_true',
        help='Start web dashboard to view results'
    )
    
    parser.add_argument(
        '--port', '-p',
        type=int,
        default=5000,
        help='Port for web dashboard (default: 5000)'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Verbose output'
    )
    
    args = parser.parse_args()
    
    # Validate path
    path = Path(args.path)
    if not path.exists():
        print(f"Error: Path not found: {args.path}", file=sys.stderr)
        sys.exit(1)
    
    # Run scan
    if args.verbose:
        print(f"Scanning: {args.path}")
    
    result = scan(str(path))
    
    # Handle errors
    if result.errors and not result.packages:
        for error in result.errors:
            print(f"Error: {error}", file=sys.stderr)
        sys.exit(1)
    
    # Output results
    if args.json:
        output = json.dumps(result.to_dict(), indent=2)
        if args.output:
            with open(args.output, 'w') as f:
                f.write(output)
            print(f"Results saved to: {args.output}")
        else:
            print(output)
    elif args.dashboard:
        start_dashboard(result, args.port)
    else:
        print_results(result, verbose=args.verbose)
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(result.to_dict(), f, indent=2)
            print(f"\nResults saved to: {args.output}")
    
    # Exit with error code if vulnerabilities found
    if result.critical_count > 0 or result.high_count > 0:
        sys.exit(2)  # Vulnerabilities found
    sys.exit(0)


def print_results(result, verbose=False):
    """Print scan results to console."""
    print("\n" + "=" * 60)
    print("VULNERABILITY SCAN RESULTS")
    print("=" * 60)
    
    print(f"\nSource: {result.source}")
    print(f"Type: {result.source_type}")
    print(f"Scan time: {result.scan_time}")
    
    print(f"\n📦 Packages scanned: {result.total_packages}")
    print(f"🔍 Vulnerable packages: {result.vulnerable_packages}")
    print(f"⚠️  Total vulnerabilities: {result.total_vulnerabilities}")
    
    if result.critical_count > 0:
        print(f"🔴 Critical: {result.critical_count}")
    if result.high_count > 0:
        print(f"🟠 High: {result.high_count}")
    
    if result.unresolved_imports:
        print(f"\n⚪ Unresolved imports: {len(result.unresolved_imports)}")
        if verbose:
            for imp in sorted(result.unresolved_imports):
                print(f"   - {imp}")
    
    if result.errors:
        print(f"\n⚠️  Warnings/Errors:")
        for error in result.errors:
            print(f"   - {error}")
    
    # Print vulnerable packages
    vulnerable = [p for p in result.packages.values() if p.has_vulnerabilities]
    
    if vulnerable:
        print("\n" + "-" * 60)
        print("VULNERABLE PACKAGES")
        print("-" * 60)
        
        for pkg in sorted(vulnerable, key=lambda p: (-p.critical_count, -p.high_count, p.package_name)):
            print(f"\n📦 {pkg.package_name}=={pkg.version}")
            print(f"   Vulnerabilities: {len(pkg.vulnerabilities)}")
            
            for vuln in pkg.vulnerabilities:
                severity_icon = {
                    'CRITICAL': '🔴',
                    'HIGH': '🟠',
                    'MEDIUM': '🟡',
                    'LOW': '🟢',
                    'UNKNOWN': '⚪',
                }.get(vuln.severity.value, '⚪')
                
                print(f"\n   {severity_icon} [{vuln.severity.value}] {vuln.id}")
                if vuln.cve_id:
                    print(f"      CVE: {vuln.cve_id}")
                print(f"      Summary: {vuln.summary[:80]}{'...' if len(vuln.summary) > 80 else ''}")
                print(f"      URL: {vuln.osv_url}")
    else:
        print("\n✅ No vulnerabilities found!")
    
    print("\n" + "=" * 60)


def start_dashboard(result, port):
    """Start the web dashboard."""
    try:
        from dashboard.app import create_app
        app = create_app()
        app.config['SCAN_RESULT'] = result
        print(f"\n🌐 Starting dashboard at http://localhost:{port}")
        print("   Press Ctrl+C to stop\n")
        app.run(host='0.0.0.0', port=port, debug=False)
    except ImportError:
        print("Error: Dashboard dependencies not installed.", file=sys.stderr)
        print("Install with: pip install flask", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
