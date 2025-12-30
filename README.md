# SISYPHUS-VULN

A Python-based vulnerability scanner that extends software composition analysis to Jupyter Notebook (.ipynb) by parsing via Abstract Syntax Trees (AST) to identify dependencies and query the OSV database for real-time security risks.

## Key Features

- **Novel .ipynb Support**: Uses AST-based import detection for Jupyter Notebooks
- **OSV Integration**: Queries the Open Source Vulnerabilities database for up-to-date CVE information
- **Syft Integration**: Uses Syft for SBOM generation on regular Python projects
- **Modern Dashboard**: Web-based visualization of vulnerability scan results
- **CLI Interface**: Command-line tool for CI/CD integration

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/example/sisyphus-vuln.git
cd sisyphus-vuln

# Install the package
pip install -e .
```

### Basic Usage

#### Scan a Jupyter Notebook

```bash
# CLI output
sisyphus-vuln notebook.ipynb

# JSON output
sisyphus-vuln notebook.ipynb --json

# Save to file
sisyphus-vuln notebook.ipynb --output results.json

# Launch dashboard
sisyphus-vuln notebook.ipynb --dashboard
```

#### Scan a Project

```bash
# Scan a project directory (uses Syft if available)
sisyphus-vuln ./my_project

# Scan requirements.txt directly
sisyphus-vuln requirements.txt
```

#### Python API

```python
from src.scanner import scan

# Scan a notebook
result = scan("notebook.ipynb")

# Check results
print(f"Vulnerable packages: {result.vulnerable_packages}")
print(f"Critical issues: {result.critical_count}")

# Iterate through vulnerabilities
for pkg in result.packages.values():
    if pkg.has_vulnerabilities:
        print(f"\n{pkg.package_name}=={pkg.version}")
        for vuln in pkg.vulnerabilities:
            print(f"  - [{vuln.severity.value}] {vuln.id}: {vuln.summary}")
```

## How It Works

### For Jupyter Notebooks (.ipynb)

This is my **novel workflow** for python notebooks:

1. **Parse Notebook**: Extract code cells from the .ipynb JSON structure
2. **AST Analysis**: Use Python's Abstract Syntax Tree to detect all import statements
3. **Package Mapping**: Map import names to PyPI package names (e.g., `cv2` → `opencv-python`)
4. **Version Resolution**: Get installed versions from the local Python environment
5. **OSV Query**: Query the OSV database for known vulnerabilities

```
notebook.ipynb → Parse → AST Extract → Map Packages → Resolve Versions → OSV Query → Results
```

### For Regular Projects

Uses [Syft](https://github.com/anchore/syft) to generate an SBOM, then queries OSV:

```
project/ → Syft SBOM → Parse Packages → OSV Query → Results
```

Falls back to parsing `requirements.txt` or `pyproject.toml` if Syft is not available.

## 📊 Dashboard

Launch the web dashboard to view results interactively:

```bash
# Via CLI
sisyphus-vuln notebook.ipynb --dashboard --port 5000

# Direct
python dashboard/app.py
```

Then open http://localhost:5000 in your browser.

Features: (Not fully functional yet)
- 📁 Drag-and-drop file upload
- 📊 Summary statistics with severity counts
- 🔴 Color-coded severity indicators
- 🔗 Direct links to OSV database entries


## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OSV_TIMEOUT` | API request timeout in seconds | 30 |


## 🛠️ Requirements

- Python 3.8+
- `requests` (for OSV API)
- `flask` (optional, for dashboard)
- `syft` (optional, for project scanning)

## Links

- [OSV Database](https://osv.dev)
- [Syft SBOM Tool](https://github.com/anchore/syft)
