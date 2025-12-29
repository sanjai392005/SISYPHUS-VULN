"""
AST Import Extractor Module

Uses Python's Abstract Syntax Tree (AST) module to extract
import statements from Python code.
"""

import ast
from typing import Set, List, Tuple


class ImportVisitor(ast.NodeVisitor):
    """
    AST visitor that collects all import statements.
    """
    
    def __init__(self):
        self.imports: Set[str] = set()
        self.import_details: List[Tuple[str, str, int]] = []  # (module, alias, line)
    
    def visit_Import(self, node: ast.Import):
        """Handle 'import module' statements."""
        for alias in node.names:
            # Get the top-level package name
            module_name = alias.name.split('.')[0]
            self.imports.add(module_name)
            self.import_details.append((
                alias.name,
                alias.asname or alias.name,
                node.lineno
            ))
        self.generic_visit(node)
    
    def visit_ImportFrom(self, node: ast.ImportFrom):
        """Handle 'from module import ...' statements."""
        if node.module:
            # Get the top-level package name
            module_name = node.module.split('.')[0]
            self.imports.add(module_name)
            self.import_details.append((
                node.module,
                node.module,
                node.lineno
            ))
        self.generic_visit(node)


def extract_imports(code: str) -> Set[str]:
    """
    Extract all imported module names from Python code.
    
    Args:
        code: Python source code as a string
        
    Returns:
        Set of top-level module names that are imported
        
    Note:
        Returns empty set if code has syntax errors.
        Only returns the top-level package name (e.g., 'numpy' for 'numpy.random').
    """
    try:
        tree = ast.parse(code)
    except SyntaxError:
        # If there's a syntax error, return empty set
        # This is common in notebooks with magic commands
        return set()
    
    visitor = ImportVisitor()
    visitor.visit(tree)
    
    return visitor.imports


def extract_imports_with_details(code: str) -> List[Tuple[str, str, int]]:
    """
    Extract imports with additional details.
    
    Args:
        code: Python source code as a string
        
    Returns:
        List of tuples: (full_module_name, alias, line_number)
    """
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []
    
    visitor = ImportVisitor()
    visitor.visit(tree)
    
    return visitor.import_details


def extract_imports_from_cells(cells: List[str]) -> Set[str]:
    """
    Extract imports from multiple code cells.
    
    Args:
        cells: List of code cell contents
        
    Returns:
        Combined set of all imported modules
    """
    all_imports = set()
    
    for cell in cells:
        # Pre-process cell to handle IPython magic commands
        processed_cell = _preprocess_cell(cell)
        imports = extract_imports(processed_cell)
        all_imports.update(imports)
    
    return all_imports


def _preprocess_cell(cell: str) -> str:
    """
    Preprocess a notebook cell to make it parseable by AST.
    
    Handles:
    - IPython magic commands (lines starting with % or !)
    - Cell magics (%%magic)
    """
    lines = cell.split('\n')
    processed_lines = []
    skip_cell = False
    
    for i, line in enumerate(lines):
        stripped = line.strip()
        
        # Skip cell magic blocks (%%magic)
        if i == 0 and stripped.startswith('%%'):
            skip_cell = True
            break
        
        # Skip line magics and shell commands
        if stripped.startswith('%') or stripped.startswith('!'):
            processed_lines.append('')  # Replace with empty line to preserve line numbers
        else:
            processed_lines.append(line)
    
    if skip_cell:
        return ''
    
    return '\n'.join(processed_lines)


# Standard library modules to exclude from vulnerability scanning
STDLIB_MODULES = {
    'abc', 'aifc', 'argparse', 'array', 'ast', 'asynchat', 'asyncio',
    'asyncore', 'atexit', 'audioop', 'base64', 'bdb', 'binascii',
    'binhex', 'bisect', 'builtins', 'bz2', 'calendar', 'cgi', 'cgitb',
    'chunk', 'cmath', 'cmd', 'code', 'codecs', 'codeop', 'collections',
    'colorsys', 'compileall', 'concurrent', 'configparser', 'contextlib',
    'contextvars', 'copy', 'copyreg', 'cProfile', 'crypt', 'csv',
    'ctypes', 'curses', 'dataclasses', 'datetime', 'dbm', 'decimal',
    'difflib', 'dis', 'distutils', 'doctest', 'email', 'encodings',
    'enum', 'errno', 'faulthandler', 'fcntl', 'filecmp', 'fileinput',
    'fnmatch', 'fractions', 'ftplib', 'functools', 'gc', 'getopt',
    'getpass', 'gettext', 'glob', 'graphlib', 'grp', 'gzip', 'hashlib',
    'heapq', 'hmac', 'html', 'http', 'idlelib', 'imaplib', 'imghdr',
    'imp', 'importlib', 'inspect', 'io', 'ipaddress', 'itertools',
    'json', 'keyword', 'lib2to3', 'linecache', 'locale', 'logging',
    'lzma', 'mailbox', 'mailcap', 'marshal', 'math', 'mimetypes',
    'mmap', 'modulefinder', 'multiprocessing', 'netrc', 'nis',
    'nntplib', 'numbers', 'operator', 'optparse', 'os', 'ossaudiodev',
    'pathlib', 'pdb', 'pickle', 'pickletools', 'pipes', 'pkgutil',
    'platform', 'plistlib', 'poplib', 'posix', 'posixpath', 'pprint',
    'profile', 'pstats', 'pty', 'pwd', 'py_compile', 'pyclbr',
    'pydoc', 'queue', 'quopri', 'random', 'readline', 're', 'reprlib',
    'resource', 'rlcompleter', 'runpy', 'sched', 'secrets', 'select',
    'selectors', 'shelve', 'shlex', 'shutil', 'signal', 'site',
    'smtpd', 'smtplib', 'sndhdr', 'socket', 'socketserver', 'spwd',
    'sqlite3', 'ssl', 'stat', 'statistics', 'string', 'stringprep',
    'struct', 'subprocess', 'sunau', 'symtable', 'sys', 'sysconfig',
    'syslog', 'tabnanny', 'tarfile', 'telnetlib', 'tempfile', 'termios',
    'test', 'textwrap', 'threading', 'time', 'timeit', 'tkinter',
    'token', 'tokenize', 'tomllib', 'trace', 'traceback', 'tracemalloc',
    'tty', 'turtle', 'turtledemo', 'types', 'typing', 'unicodedata',
    'unittest', 'urllib', 'uu', 'uuid', 'venv', 'warnings', 'wave',
    'weakref', 'webbrowser', 'winreg', 'winsound', 'wsgiref', 'xdrlib',
    'xml', 'xmlrpc', 'zipapp', 'zipfile', 'zipimport', 'zlib', 'zoneinfo',
    # Common aliases/internal modules
    '_thread', '__future__', '_abc', '_collections_abc',
}


def filter_stdlib(imports: Set[str]) -> Set[str]:
    """
    Remove standard library modules from a set of imports, becase stdlib modules dont have version numbers and if we ask importlib.metadata it will crash.
    
    Args:
        imports: Set of module names
        
    Returns:
        Set of non-stdlib module names
    """
    return imports - STDLIB_MODULES
