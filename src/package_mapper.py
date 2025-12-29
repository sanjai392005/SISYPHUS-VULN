"""
Package Mapper Module

Maps Python import names to their corresponding PyPI package names.
Import names often differ from package names (e.g., cv2 -> opencv-python).
"""

from typing import Dict, Optional, Set


# Known mappings from import name to PyPI package name
# This covers common packages where the import name differs from the package name
IMPORT_TO_PACKAGE_MAP: Dict[str, str] = {
    # Computer Vision / Image Processing
    'cv2': 'opencv-python',
    'cv': 'opencv-python',
    'PIL': 'Pillow',
    'Image': 'Pillow',
    'skimage': 'scikit-image',
    
    # Machine Learning / Data Science
    'sklearn': 'scikit-learn',
    'sklearn_crfsuite': 'sklearn-crfsuite',
    'tensorflow': 'tensorflow',
    'tf': 'tensorflow',
    'torch': 'pytorch',
    'torchvision': 'torchvision',
    'xgb': 'xgboost',
    'lgb': 'lightgbm',
    'catboost': 'catboost',
    
    # NLP
    'spacy': 'spacy',
    'gensim': 'gensim',
    'nltk': 'nltk',
    'transformers': 'transformers',
    
    # Data Manipulation
    'pd': 'pandas',
    'np': 'numpy',
    'px': 'plotly',
    'sns': 'seaborn',
    'plt': 'matplotlib',
    'mpl': 'matplotlib',
    
    # Web
    'bs4': 'beautifulsoup4',
    'BeautifulSoup': 'beautifulsoup4',
    'flask': 'Flask',
    'django': 'Django',
    'fastapi': 'fastapi',
    'aiohttp': 'aiohttp',
    'httpx': 'httpx',
    
    # Database
    'psycopg2': 'psycopg2-binary',
    'pymysql': 'PyMySQL',
    'pymongo': 'pymongo',
    'redis': 'redis',
    'sqlalchemy': 'SQLAlchemy',
    
    # Cloud
    'boto3': 'boto3',
    'botocore': 'botocore',
    'google': 'google-cloud-core',
    'azure': 'azure-core',
    
    # Utilities
    'yaml': 'PyYAML',
    'ruamel': 'ruamel.yaml',
    'dotenv': 'python-dotenv',
    'dateutil': 'python-dateutil',
    'jwt': 'PyJWT',
    'jose': 'python-jose',
    'click': 'click',
    'rich': 'rich',
    'tqdm': 'tqdm',
    'pytest': 'pytest',
    'attr': 'attrs',
    'pydantic': 'pydantic',
    
    # Async
    'aio_pika': 'aio-pika',
    'aiokafka': 'aiokafka',
    'aioredis': 'aioredis',
    
    # Serialization
    'msgpack': 'msgpack-python',
    'orjson': 'orjson',
    'ujson': 'ujson',
    
    # Cryptography
    'Crypto': 'pycryptodome',
    'cryptography': 'cryptography',
    'nacl': 'PyNaCl',
    
    # Testing
    'mock': 'mock',
    'faker': 'Faker',
    'hypothesis': 'hypothesis',
    
    # CLI
    'typer': 'typer',
    'fire': 'fire',
}

# Reverse mapping for lookups
PACKAGE_TO_IMPORT_MAP: Dict[str, str] = {v: k for k, v in IMPORT_TO_PACKAGE_MAP.items()}


def map_import_to_package(import_name: str) -> str:
    """
    Map an import name to its PyPI package name.
    
    Args:
        import_name: The name used in the import statement
        
    Returns:
        The corresponding PyPI package name
        
    Note:
        If no mapping is found, returns the import name as-is,
        which is correct for most packages where names match.
    """
    # Check direct mapping
    if import_name in IMPORT_TO_PACKAGE_MAP:
        return IMPORT_TO_PACKAGE_MAP[import_name]
    
    # Try lowercase version
    lower_name = import_name.lower()
    for key, value in IMPORT_TO_PACKAGE_MAP.items():
        if key.lower() == lower_name:
            return value
    
    # Default: assume import name matches package name
    return import_name


def map_imports_to_packages(imports: Set[str]) -> Dict[str, str]:
    """
    Map multiple import names to their PyPI package names.
    
    Args:
        imports: Set of import names
        
    Returns:
        Dictionary mapping import names to package names
    """
    return {imp: map_import_to_package(imp) for imp in imports}


def get_package_alternatives(package_name: str) -> list[str]:
    """
    Get alternative package names that might be used for the same functionality.
    
    Args:
        package_name: The PyPI package name
        
    Returns:
        List of alternative package names
    """
    alternatives = {
        'opencv-python': ['opencv-python-headless', 'opencv-contrib-python'],
        'Pillow': ['PIL'],
        'tensorflow': ['tensorflow-gpu', 'tensorflow-cpu', 'tf-nightly'],
        'pytorch': ['torch', 'pytorch-cpu', 'pytorch-cuda'],
        'psycopg2-binary': ['psycopg2'],
    }
    
    return alternatives.get(package_name, [])


class PackageMapper:
    """
    Extensible package mapper that can be configured with custom mappings.
    """
    
    def __init__(self, custom_mappings: Optional[Dict[str, str]] = None):
        """
        Initialize the mapper with optional custom mappings.
        
        Args:
            custom_mappings: Additional import-to-package mappings
        """
        self.mappings = IMPORT_TO_PACKAGE_MAP.copy()
        if custom_mappings:
            self.mappings.update(custom_mappings)
    
    def map(self, import_name: str) -> str:
        """Map an import name to a package name."""
        if import_name in self.mappings:
            return self.mappings[import_name]
        return import_name
    
    def add_mapping(self, import_name: str, package_name: str):
        """Add a new mapping."""
        self.mappings[import_name] = package_name
    
    def bulk_map(self, imports: Set[str]) -> Dict[str, str]:
        """Map multiple imports at once."""
        return {imp: self.map(imp) for imp in imports}
