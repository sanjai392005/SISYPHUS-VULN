# SISYPHUS

A Python tool that detects external library dependencies and identifies known vulnerabilities (CVEs) by querying the [OSV database](https://osv.dev). 

## 🌟 Key Features

- **Novel .ipynb Support**: Uses AST-based import detection for Jupyter Notebooks
- **OSV Integration**: Queries the Open Source Vulnerabilities database for up-to-date CVE information
- **Syft Integration**: Uses Syft for SBOM generation on regular Python projects
- **Modern Dashboard**: Web-based visualization of vulnerability scan results
- **CLI Interface**: Command-line tool for CI/CD integration

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/example/ipynb-vuln-scanner.git
cd ipynb-vuln-scanner

# Install the package
pip install -e .

# For dashboard support
pip install -e ".[dashboard]"

# For development
pip install -e ".[dev]"
```

### Basic Usage

#### Scan a Jupyter Notebook

```bash
# CLI output
ipynb-vuln-scanner notebook.ipynb

# JSON output
ipynb-vuln-scanner notebook.ipynb --json

# Save to file
ipynb-vuln-scanner notebook.ipynb --output results.json

# Launch dashboard
ipynb-vuln-scanner notebook.ipynb --dashboard
```

#### Scan a Project

```bash
# Scan a project directory (uses Syft if available)
ipynb-vuln-scanner ./my_project

# Scan requirements.txt directly
ipynb-vuln-scanner requirements.txt
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

## 🔍 How It Works

### For Jupyter Notebooks (.ipynb)

This is our **novel workflow**:

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
ipynb-vuln-scanner notebook.ipynb --dashboard --port 5000

# Direct
python dashboard/app.py
```

Then open http://localhost:5000 in your browser.

Features:
- 📁 Drag-and-drop file upload
- 📊 Summary statistics with severity counts
- 🔴 Color-coded severity indicators
- 🔗 Direct links to OSV database entries

## 🧪 Running Tests

```bash
# Run all unit tests
pytest tests/ -v

# Run with coverage
pytest tests/ -v --cov=src --cov-report=html

# Run integration tests (requires network)
pytest tests/ -v -m integration

# Skip integration tests
pytest tests/ -v -m "not integration"
```

## 📦 Project Structure

```
ipynb-dependency-vulnerabilities/
├── src/
│   ├── __init__.py           # Package initialization
│   ├── main.py               # CLI entry point
│   ├── ipynb_parser.py       # Notebook parsing
│   ├── ast_extractor.py      # AST-based import extraction
│   ├── package_mapper.py     # Import → Package name mapping
│   ├── version_resolver.py   # Version resolution from environment
│   ├── osv_client.py         # OSV API client
│   ├── syft_wrapper.py       # Syft CLI wrapper
│   └── scanner.py            # Main scanning orchestration
├── dashboard/
│   ├── app.py                # Flask application
│   ├── templates/
│   │   └── index.html        # Dashboard template
│   └── static/
│       ├── css/styles.css    # Styling
│       └── js/main.js        # JavaScript
├── tests/
│   ├── test_ast_extractor.py
│   ├── test_osv_client.py
│   └── sample_notebooks/
├── requirements.txt
├── pyproject.toml
└── README.md
```

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OSV_TIMEOUT` | API request timeout in seconds | 30 |

### Custom Package Mappings

Add custom import-to-package mappings:

```python
from src.package_mapper import PackageMapper

mapper = PackageMapper(custom_mappings={
    "myimport": "my-pypi-package",
})
```

## 🛠️ Requirements

- Python 3.8+
- `requests` (for OSV API)
- `flask` (optional, for dashboard)
- `syft` (optional, for project scanning)

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## 🔗 Links

- [OSV Database](https://osv.dev)
- [Syft SBOM Tool](https://github.com/anchore/syft)
- [CVE Database](https://cve.mitre.org)
