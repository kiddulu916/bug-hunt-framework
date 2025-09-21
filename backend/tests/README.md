# Bug Bounty Automation Platform - Test Suite

This directory contains the comprehensive test suite for the Bug Bounty Automation Platform backend.

## Test Structure

```
tests/
├── conftest.py              # Pytest configuration and fixtures
├── factories.py             # Model factories for test data generation
├── test_utils.py            # Test utilities and helper functions
├── run_tests.py            # Enhanced test runner script
├── unit/                   # Unit tests
│   ├── test_models/        # Model tests for all Django apps
│   └── test_services/      # Service layer tests
├── integration/            # Integration tests
│   ├── test_api/          # API endpoint tests
│   └── test_workflows/    # Multi-component workflow tests
└── e2e/                   # End-to-end tests
    └── test_complete_flows/
```

## Test Categories

### Unit Tests (`pytest -m unit`)
- **Model Tests**: Comprehensive tests for all Django models including validation, relationships, properties, and methods
- **Service Tests**: Tests for business logic in service layer classes
- **Utility Tests**: Tests for helper functions and utilities

### Integration Tests (`pytest -m integration`)
- **API Tests**: Full API endpoint testing including authentication, permissions, serialization
- **Workflow Tests**: Multi-component integration testing
- **Database Tests**: Complex database operations and transactions

### End-to-End Tests (`pytest -m e2e`)
- **Complete Flow Tests**: Full user workflow testing from start to finish
- **Real Tool Integration**: Tests with actual penetration testing tools (mocked)

## Running Tests

### Using the Test Runner (Recommended)

```bash
# Run all tests with coverage
python tests/run_tests.py all

# Run only unit tests
python tests/run_tests.py unit

# Run integration tests
python tests/run_tests.py integration

# Run with verbose output
python tests/run_tests.py all --verbose

# Run tests in parallel
python tests/run_tests.py all --parallel

# Run specific test file
python tests/run_tests.py specific --test-path tests/unit/test_models/test_target_models.py

# Run only failed tests from last run
python tests/run_tests.py failed

# Generate HTML coverage report
python tests/run_tests.py all --coverage-html
```

### Using Pytest Directly

```bash
# Run all tests
pytest

# Run unit tests only
pytest -m unit

# Run with coverage
pytest --cov=apps --cov=services --cov-report=html

# Run specific test file
pytest tests/unit/test_models/test_target_models.py

# Run specific test function
pytest tests/unit/test_models/test_target_models.py::TargetModelTest::test_target_creation

# Run tests matching pattern
pytest -k "test_target"

# Run tests with verbose output
pytest -v

# Run failed tests only
pytest --lf
```

## Test Configuration

### Pytest Configuration (`pytest.ini`)
- **Coverage Settings**: 80% minimum coverage requirement
- **Test Discovery**: Automatic discovery of test files
- **Markers**: Custom markers for different test types
- **Database Settings**: In-memory SQLite for faster tests

### Test Fixtures (`conftest.py`)
- **Database Fixtures**: Clean database state for each test
- **Authentication Fixtures**: Pre-configured user accounts
- **Mock Fixtures**: External service mocking
- **Sample Data Fixtures**: Realistic test data

### Factories (`factories.py`)
- **Model Factories**: Generate realistic test data using factory_boy
- **Relationship Factories**: Handle complex model relationships
- **Trait Factories**: Specialized factory configurations

## Test Data

### Factories
All models have corresponding factories that generate realistic test data:

```python
from tests.factories import TargetFactory, VulnerabilityFactory

# Create a target with default values
target = TargetFactory.create()

# Create a target with custom values
target = TargetFactory.create(
    target_name='Custom Target',
    platform=BugBountyPlatform.HACKERONE
)

# Create multiple targets
targets = TargetFactory.create_batch(5)
```

### Fixtures
Common fixtures are available in all tests:

```python
def test_something(sample_target, authenticated_client):
    # sample_target: Pre-created target instance
    # authenticated_client: API client with authentication
    pass
```

## Coverage Requirements

- **Minimum Coverage**: 80% overall
- **Model Coverage**: 100% (all models must be fully tested)
- **API Coverage**: 85% (all endpoints must be tested)
- **Service Coverage**: 80% (business logic must be tested)

## Writing Tests

### Model Tests
```python
@pytest.mark.unit
class MyModelTest(TestCase, DatabaseTestMixin):
    def test_model_creation(self):
        instance = MyModel.objects.create(**data)
        self.assertEqual(instance.field, expected_value)
```

### API Tests
```python
@pytest.mark.integration
class MyAPITest(TestCase, APITestMixin):
    def test_api_endpoint(self):
        response = self.authenticated_client.get(url)
        self.assert_api_response(response, 200, ['field1', 'field2'])
```

### Service Tests
```python
@pytest.mark.unit
class MyServiceTest(TestCase):
    @patch('external.service')
    def test_service_method(self, mock_service):
        result = my_service.do_something()
        self.assertTrue(result.success)
```

## Test Markers

Use pytest markers to categorize tests:

- `@pytest.mark.unit` - Unit tests
- `@pytest.mark.integration` - Integration tests
- `@pytest.mark.e2e` - End-to-end tests
- `@pytest.mark.slow` - Long-running tests
- `@pytest.mark.requires_tools` - Tests requiring external tools
- `@pytest.mark.requires_network` - Tests requiring network access

## Mock Guidelines

### External Services
Always mock external services and APIs:

```python
@patch('requests.get')
def test_external_api_call(self, mock_get):
    mock_get.return_value.json.return_value = {'status': 'success'}
    result = my_function()
    self.assertEqual(result['status'], 'success')
```

### File Operations
Mock file operations for consistency:

```python
@patch('builtins.open', mock_open(read_data='test data'))
def test_file_reading(self, mock_file):
    result = read_file('test.txt')
    self.assertEqual(result, 'test data')
```

### Tool Execution
Use MockToolExecutor for penetration testing tools:

```python
def test_tool_execution(self):
    mock_executor = MockToolExecutor('nuclei')
    mock_executor.set_results([{'severity': 'high'}])
    result = mock_executor.execute()
    self.assertTrue(result['success'])
```

## Continuous Integration

Tests are designed to run in CI environments:

- **Fast Execution**: In-memory database, mocked external calls
- **Deterministic**: No random behavior, fixed test data
- **Isolated**: Each test is independent
- **Comprehensive**: High coverage across all components

## Debugging Tests

### Failed Tests
```bash
# Run with detailed output
pytest -v --tb=long

# Drop into debugger on failure
pytest --pdb

# Run specific failing test
pytest tests/path/to/test.py::TestClass::test_method -v
```

### Coverage Analysis
```bash
# Generate detailed coverage report
pytest --cov=apps --cov-report=html
open htmlcov/index.html

# Check missing coverage
pytest --cov=apps --cov-report=term-missing
```

## Performance Testing

For performance-critical code:

```python
@pytest.mark.performance
def test_performance(self):
    import time
    start = time.time()
    result = expensive_operation()
    duration = time.time() - start
    self.assertLess(duration, 1.0)  # Should complete in under 1 second
```

## Security Testing

For security-related functionality:

```python
@pytest.mark.security
def test_security_validation(self):
    # Test input sanitization
    malicious_input = "<script>alert('xss')</script>"
    result = sanitize_input(malicious_input)
    self.assertNotIn('<script>', result)
```

## Best Practices

1. **Test Names**: Use descriptive test names that explain what is being tested
2. **Test Structure**: Follow Arrange-Act-Assert pattern
3. **Test Independence**: Each test should be able to run independently
4. **Mock External Dependencies**: Always mock external services and APIs
5. **Use Factories**: Use factories instead of manual object creation
6. **Test Edge Cases**: Test boundary conditions and error cases
7. **Keep Tests Fast**: Use mocks and in-memory databases
8. **Maintain Coverage**: Aim for high test coverage but focus on quality over quantity

## Troubleshooting

### Common Issues

1. **Test Database Issues**: Ensure Django test database settings are correct
2. **Import Errors**: Check PYTHONPATH and Django settings module
3. **Mock Issues**: Verify mock patch targets and return values
4. **Fixture Issues**: Check fixture scope and dependencies

### Getting Help

- Check the test output for detailed error messages
- Use `pytest -v` for verbose output
- Use `pytest --tb=long` for detailed tracebacks
- Check the test utils and factories for available helpers