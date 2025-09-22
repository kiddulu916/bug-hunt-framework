#!/usr/bin/env python
"""
Test runner script for Bug Bounty Automation Platform
"""

import os
import sys
import argparse
import subprocess
from pathlib import Path

# Add the backend directory to Python path
backend_dir = Path(__file__).parent.parent
sys.path.insert(0, str(backend_dir))

# Set Django settings
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.testing')

import django
django.setup()


class TestRunner:
    """Enhanced test runner with multiple options"""

    def __init__(self):
        # Use virtual environment's pytest if available
        venv_pytest = Path(__file__).parent.parent.parent / '.venv' / 'bin' / 'pytest'
        if venv_pytest.exists():
            self.base_command = [str(venv_pytest)]
        else:
            self.base_command = ['pytest']
        self.test_dir = Path(__file__).parent

    def run_unit_tests(self, coverage=True, verbose=False):
        """Run unit tests only"""
        command = self.base_command.copy()
        command.extend(['-m', 'unit'])

        if coverage:
            command.extend(['--cov=apps', '--cov=services', '--cov=core'])

        if verbose:
            command.append('-v')

        command.append(str(self.test_dir / 'unit'))
        return self._execute_command(command)

    def run_integration_tests(self, coverage=True, verbose=False):
        """Run integration tests only"""
        command = self.base_command.copy()
        command.extend(['-m', 'integration'])

        if coverage:
            command.extend(['--cov=apps', '--cov=services'])

        if verbose:
            command.append('-v')

        command.append(str(self.test_dir / 'integration'))
        return self._execute_command(command)

    def run_e2e_tests(self, verbose=False):
        """Run end-to-end tests only"""
        command = self.base_command.copy()
        command.extend(['-m', 'e2e'])

        if verbose:
            command.append('-v')

        command.append(str(self.test_dir / 'e2e'))
        return self._execute_command(command)

    def run_all_tests(self, coverage=True, verbose=False, parallel=False):
        """Run all tests"""
        command = self.base_command.copy()

        if coverage:
            command.extend([
                '--cov=apps',
                '--cov=services',
                '--cov=core',
                '--cov-report=term-missing',
                '--cov-report=html:htmlcov',
                '--cov-report=xml',
                '--cov-fail-under=80'
            ])

        if verbose:
            command.append('-v')

        if parallel:
            command.extend(['-n', 'auto'])  # Requires pytest-xdist

        command.append(str(self.test_dir))
        return self._execute_command(command)

    def run_specific_test(self, test_path, verbose=False):
        """Run a specific test file or test function"""
        command = self.base_command.copy()

        if verbose:
            command.append('-v')

        command.append(test_path)
        return self._execute_command(command)

    def run_failed_tests(self, verbose=False):
        """Run only the tests that failed in the last run"""
        command = self.base_command.copy()
        command.append('--lf')  # Last failed

        if verbose:
            command.append('-v')

        return self._execute_command(command)

    def run_performance_tests(self, verbose=False):
        """Run performance tests"""
        command = self.base_command.copy()
        command.extend(['-m', 'performance'])

        if verbose:
            command.append('-v')

        return self._execute_command(command)

    def run_security_tests(self, verbose=False):
        """Run security tests"""
        command = self.base_command.copy()
        command.extend(['-m', 'security'])

        if verbose:
            command.append('-v')

        return self._execute_command(command)

    def check_test_coverage(self):
        """Check test coverage without running tests"""
        command = ['coverage', 'report', '--show-missing']
        return self._execute_command(command)

    def generate_coverage_html(self):
        """Generate HTML coverage report"""
        command = ['coverage', 'html']
        result = self._execute_command(command)
        if result == 0:
            print("HTML coverage report generated in htmlcov/")
        return result

    def lint_tests(self):
        """Lint test files"""
        command = ['flake8', str(self.test_dir)]
        return self._execute_command(command)

    def _execute_command(self, command):
        """Execute a command and return the exit code"""
        print(f"Running: {' '.join(command)}")
        try:
            result = subprocess.run(command, cwd=str(backend_dir))
            return result.returncode
        except KeyboardInterrupt:
            print("\nTest execution interrupted by user")
            return 1
        except Exception as e:
            print(f"Error executing command: {e}")
            return 1


def main():
    """Main test runner entry point"""
    parser = argparse.ArgumentParser(description='Bug Bounty Platform Test Runner')

    parser.add_argument(
        'test_type',
        choices=['unit', 'integration', 'e2e', 'all', 'failed', 'performance', 'security', 'specific'],
        help='Type of tests to run'
    )

    parser.add_argument(
        '--no-coverage',
        action='store_true',
        help='Run tests without coverage analysis'
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Run tests in verbose mode'
    )

    parser.add_argument(
        '--parallel', '-p',
        action='store_true',
        help='Run tests in parallel (requires pytest-xdist)'
    )

    parser.add_argument(
        '--test-path',
        help='Specific test path to run (for test_type=specific)'
    )

    parser.add_argument(
        '--coverage-html',
        action='store_true',
        help='Generate HTML coverage report after tests'
    )

    parser.add_argument(
        '--lint',
        action='store_true',
        help='Lint test files before running tests'
    )

    args = parser.parse_args()

    runner = TestRunner()

    # Lint tests if requested
    if args.lint:
        print("Linting test files...")
        lint_result = runner.lint_tests()
        if lint_result != 0:
            print("Linting failed. Fix issues before running tests.")
            return lint_result

    # Run tests based on type
    coverage = not args.no_coverage
    verbose = args.verbose

    if args.test_type == 'unit':
        result = runner.run_unit_tests(coverage=coverage, verbose=verbose)
    elif args.test_type == 'integration':
        result = runner.run_integration_tests(coverage=coverage, verbose=verbose)
    elif args.test_type == 'e2e':
        result = runner.run_e2e_tests(verbose=verbose)
    elif args.test_type == 'all':
        result = runner.run_all_tests(
            coverage=coverage,
            verbose=verbose,
            parallel=args.parallel
        )
    elif args.test_type == 'failed':
        result = runner.run_failed_tests(verbose=verbose)
    elif args.test_type == 'performance':
        result = runner.run_performance_tests(verbose=verbose)
    elif args.test_type == 'security':
        result = runner.run_security_tests(verbose=verbose)
    elif args.test_type == 'specific':
        if not args.test_path:
            print("Error: --test-path required for specific test type")
            return 1
        result = runner.run_specific_test(args.test_path, verbose=verbose)
    else:
        print(f"Unknown test type: {args.test_type}")
        return 1

    # Generate HTML coverage report if requested
    if args.coverage_html and coverage and result == 0:
        print("\nGenerating HTML coverage report...")
        runner.generate_coverage_html()

    # Print summary
    if result == 0:
        print("\n✅ All tests passed!")
    else:
        print("\n❌ Some tests failed!")

    return result


if __name__ == '__main__':
    exit_code = main()
    sys.exit(exit_code)