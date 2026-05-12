# Test Suite README

## Quick Start

```bash
# Install dependencies
pip install -r requirements-test.txt

# Run all tests
pytest

# Run with coverage
pytest --cov=backend --cov-report=html

# View coverage report
open htmlcov/index.html
```

## Test Categories

- **Unit Tests** (`tests/unit/`) - Test individual components in isolation
- **Integration Tests** (`tests/integration/`) - Test API endpoints and component interactions
- **E2E Tests** (`tests/e2e/`) - Test complete workflows end-to-end
- **Governance Tests** (`tests/governance/`) - Test governance framework compliance

## Current Status

### Implemented Tests

✅ Unit tests for governance framework:
- `test_audit_logger.py` - Tamper-evident audit logging
- `test_rules_engine.py` - Rule validation and pattern matching
- `test_acgs_integration.py` - MACI pattern implementation

✅ Integration tests:
- `test_governance_integration.py` - Complete governance workflow

✅ Governance compliance tests:
- `test_governance_compliance.py` - Regulatory compliance verification

### Pending Tests (Templates Created)

⏳ API endpoint tests - Will be populated as APIs are implemented
⏳ E2E workflow tests - Will be populated as workflows are implemented

## Running Specific Tests

```bash
# Unit tests only
pytest tests/unit -v

# Governance tests only
pytest -m governance -v

# Integration tests only
pytest -m integration -v

# Skip slow tests
pytest -m "not slow"
```

## Coverage Target

- Minimum: 80% (enforced by CI)
- Target: 90%+

Current coverage for governance module: ~95%

## CI Integration

Tests run automatically on GitHub Actions for:
- All pushes to main/develop
- All pull requests

See `.github/workflows/ci.yml` for CI configuration.
