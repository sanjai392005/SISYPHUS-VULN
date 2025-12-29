"""
Tests for AST Import Extractor
"""

import pytest
from src.ast_extractor import (
    extract_imports,
    extract_imports_from_cells,
    filter_stdlib,
    _preprocess_cell,
    STDLIB_MODULES,
)


class TestExtractImports:
    """Test cases for extract_imports function."""
    
    def test_simple_import(self):
        code = "import numpy"
        result = extract_imports(code)
        assert result == {"numpy"}
    
    def test_multiple_imports(self):
        code = """
import numpy
import pandas
import matplotlib
"""
        result = extract_imports(code)
        assert result == {"numpy", "pandas", "matplotlib"}
    
    def test_import_with_alias(self):
        code = "import numpy as np"
        result = extract_imports(code)
        assert result == {"numpy"}
    
    def test_from_import(self):
        code = "from sklearn import linear_model"
        result = extract_imports(code)
        assert result == {"sklearn"}
    
    def test_from_import_submodule(self):
        code = "from sklearn.ensemble import RandomForestClassifier"
        result = extract_imports(code)
        assert result == {"sklearn"}
    
    def test_multiple_from_import(self):
        code = "from numpy import array, zeros, ones"
        result = extract_imports(code)
        assert result == {"numpy"}
    
    def test_mixed_imports(self):
        code = """
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from matplotlib import pyplot as plt
"""
        result = extract_imports(code)
        assert result == {"numpy", "pandas", "sklearn", "matplotlib"}
    
    def test_syntax_error_returns_empty(self):
        code = "import def class"  # Invalid Python
        result = extract_imports(code)
        assert result == set()
    
    def test_empty_code(self):
        result = extract_imports("")
        assert result == set()
    
    def test_code_without_imports(self):
        code = """
x = 1
y = 2
print(x + y)
"""
        result = extract_imports(code)
        assert result == set()


class TestPreprocessCell:
    """Test cases for preprocessing notebook cells."""
    
    def test_line_magic(self):
        code = """%matplotlib inline
import numpy"""
        result = _preprocess_cell(code)
        assert "import numpy" in result
        assert "%matplotlib" not in result
    
    def test_shell_command(self):
        code = """!pip install pandas
import pandas"""
        result = _preprocess_cell(code)
        assert "import pandas" in result
        assert "!pip" not in result
    
    def test_cell_magic(self):
        code = """%%timeit
x = 1 + 1"""
        result = _preprocess_cell(code)
        assert result == ""  # Cell magic skips entire cell
    
    def test_mixed_magic_and_code(self):
        code = """%load_ext autoreload
%autoreload 2
import numpy as np
import pandas as pd
!echo "test"
"""
        result = _preprocess_cell(code)
        imports = extract_imports(result)
        assert imports == {"numpy", "pandas"}


class TestExtractImportsFromCells:
    """Test cases for extracting imports from multiple cells."""
    
    def test_multiple_cells(self):
        cells = [
            "import numpy as np",
            "import pandas as pd",
            "from sklearn import metrics",
        ]
        result = extract_imports_from_cells(cells)
        assert result == {"numpy", "pandas", "sklearn"}
    
    def test_cells_with_magic(self):
        cells = [
            "%matplotlib inline",
            "import matplotlib.pyplot as plt",
            "!pip install seaborn",
            "import seaborn as sns",
        ]
        result = extract_imports_from_cells(cells)
        assert result == {"matplotlib", "seaborn"}
    
    def test_empty_cells(self):
        cells = ["", "", ""]
        result = extract_imports_from_cells(cells)
        assert result == set()


class TestFilterStdlib:
    """Test cases for filtering standard library modules."""
    
    def test_filter_stdlib_modules(self):
        imports = {"numpy", "os", "sys", "pandas", "json", "sklearn"}
        result = filter_stdlib(imports)
        assert result == {"numpy", "pandas", "sklearn"}
    
    def test_all_stdlib(self):
        imports = {"os", "sys", "json", "pathlib", "collections"}
        result = filter_stdlib(imports)
        assert result == set()
    
    def test_no_stdlib(self):
        imports = {"numpy", "pandas", "tensorflow", "flask"}
        result = filter_stdlib(imports)
        assert result == imports
    
    def test_empty_set(self):
        result = filter_stdlib(set())
        assert result == set()


class TestStdlibModules:
    """Verify stdlib modules list."""
    
    def test_common_stdlib_included(self):
        common = {"os", "sys", "json", "re", "math", "datetime", "collections"}
        assert common.issubset(STDLIB_MODULES)
    
    def test_common_packages_not_included(self):
        packages = {"numpy", "pandas", "requests", "flask", "django"}
        assert packages.isdisjoint(STDLIB_MODULES)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
