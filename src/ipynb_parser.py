"""
IPYNB Parser Module

Parses Jupyter Notebook (.ipynb) files and extracts code cells.
Supports both nbformat v3 and v4 notebook formats.
"""

import json
from pathlib import Path
from typing import List, Optional


class NotebookParseError(Exception):
    """Raised when a notebook cannot be parsed."""
    pass


def parse_notebook(path: str) -> List[str]:
    """
    Parse a Jupyter Notebook file and extract all code cell contents.
    
    Args:
        path: Path to the .ipynb file
        
    Returns:
        List of code cell contents as strings
        
    Raises:
        NotebookParseError: If the notebook cannot be parsed
        FileNotFoundError: If the file does not exist
    """
    notebook_path = Path(path)
    
    if not notebook_path.exists():
        raise FileNotFoundError(f"Notebook not found: {path}")
    
    if not notebook_path.suffix.lower() == '.ipynb':
        raise NotebookParseError(f"Not a notebook file: {path}")
    
    try:
        with open(notebook_path, 'r', encoding='utf-8') as f:
            notebook = json.load(f)
    except json.JSONDecodeError as e:
        raise NotebookParseError(f"Invalid notebook JSON: {e}")
    
    return _extract_code_cells(notebook)


def _extract_code_cells(notebook: dict) -> List[str]:
    """
    Extract code cells from a notebook dictionary.
    
    Handles both nbformat v3 (worksheets) and v4 (cells) formats.
    """
    cells = []
    
    # Get nbformat version
    nbformat = notebook.get('nbformat', 4)
    
    if nbformat >= 4:
        # nbformat v4+: cells are at top level
        cells = notebook.get('cells', [])
    else:
        # nbformat v3: cells are inside worksheets
        worksheets = notebook.get('worksheets', [])
        for worksheet in worksheets:
            cells.extend(worksheet.get('cells', []))
    
    code_contents = []
    
    for cell in cells:
        if cell.get('cell_type') == 'code':
            source = cell.get('source', [])
            
            # Source can be a string or list of strings
            if isinstance(source, list):
                code_contents.append(''.join(source))
            else:
                code_contents.append(source)
    
    return code_contents


def get_notebook_metadata(path: str) -> Optional[dict]:
    """
    Extract metadata from a notebook file.
    
    Args:
        path: Path to the .ipynb file
        
    Returns:
        Notebook metadata dictionary, or None if not available
    """
    try:
        with open(path, 'r', encoding='utf-8') as f:
            notebook = json.load(f)
        return notebook.get('metadata', {})
    except (json.JSONDecodeError, FileNotFoundError):
        return None
