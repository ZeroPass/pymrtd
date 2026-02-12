# Testing Guide for pymrtd

This guide explains how to run tests locally on your PR or branch without modifying the CI workflow files or adding extra commits.

## Quick Start

### 1. Install Dependencies

First, install the package with test dependencies:

```bash
pip install -e .[tests]
```

Or if you prefer, install from requirements:

```bash
pip install -r requirements-dev.txt
```

### 2. Run All Tests

To run the complete test suite:

```bash
pytest tests
```

Or use the more verbose output:

```bash
pytest tests -v
```

### 3. Run Specific Tests

Run tests from a specific file:

```bash
pytest tests/test_ecc_verification.py
```

Run tests from a specific directory:

```bash
pytest tests/pki/
```

Run a specific test function:

```bash
pytest tests/test_ecc_verification.py::test_ec_verify_x962_signature
```

## Advanced Testing

### Run Tests with Coverage

```bash
pip install pytest-cov
pytest tests --cov=pymrtd --cov-report=html
```

View coverage report:

```bash
open htmlcov/index.html  # On macOS
xdg-open htmlcov/index.html  # On Linux
```

### Run Tests in Parallel

```bash
pip install pytest-xdist
pytest tests -n auto
```

### Run Tests with Specific Markers

If tests use markers (like `@pytest.mark.slow`):

```bash
pytest tests -m "not slow"  # Skip slow tests
pytest tests -m integration  # Run only integration tests
```

### Run Tests with Verbose Output

```bash
pytest tests -vv  # Very verbose
pytest tests -vv -s  # Also show print statements
```

### Stop on First Failure

```bash
pytest tests -x  # Stop on first failure
pytest tests --maxfail=3  # Stop after 3 failures
```

## Testing Your Changes

### Before Committing

Run the full test suite to ensure nothing is broken:

```bash
pytest tests -v
```

### Testing Specific Components

For ECC/cryptography changes:

```bash
pytest tests/test_ecc_verification.py -v
pytest tests/pki/ -v
```

For data structure tests:

```bash
pytest tests/ef/ -v
```

## Continuous Integration (CI)

The CI workflow (`.github/workflows/tests.yml`) runs automatically on:
- Pushes to `master` branch
- Pull requests targeting `master` branch

The CI uses:
- Python 3.11.5
- Ubuntu latest
- pytest for test execution

You can replicate the CI environment locally:

```bash
# Use the same Python version
pyenv install 3.11.5
pyenv local 3.11.5

# Install dependencies the same way
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt

# Run tests the same way
pytest tests
```

## Troubleshooting

### Import Errors

If you get import errors, ensure the package is installed in editable mode:

```bash
pip install -e .
```

### Missing Dependencies

Install all test dependencies:

```bash
pip install -e .[tests]
```

### Test Discovery Issues

Ensure you're running pytest from the repository root:

```bash
cd /path/to/pymrtd
pytest tests
```

## Test Structure

```
tests/
├── ef/              # Electronic file tests
├── pki/             # PKI and cryptography tests
└── test_ecc_verification.py  # ECC signature verification tests
```

## Writing New Tests

Follow the existing test patterns:

```python
import pytest
from pymrtd.pki import keys

def test_your_feature():
    # Arrange
    data = setup_test_data()
    
    # Act
    result = function_under_test(data)
    
    # Assert
    assert result == expected_value
```

## Additional Resources

- pytest documentation: https://docs.pytest.org/
- Test fixtures: Use pytest fixtures for reusable test setup
- Test parametrization: Use `@pytest.mark.parametrize` for multiple test cases

## Summary

**To run tests on your PR without modifying workflow files:**

1. `pip install -e .[tests]`
2. `pytest tests -v`

That's it! No need to modify `.github/workflows/tests.yml` or add commits.
