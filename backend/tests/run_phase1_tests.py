#!/usr/bin/env python
"""
Phase 1 Test Execution Script

Executes all Phase 1 test improvements with detailed reporting and validation.
"""

import os
import sys
import subprocess
import argparse
from pathlib import Path
import time
from datetime import datetime

# Add the backend directory to Python path
backend_dir = Path(__file__).parent.parent
sys.path.insert(0, str(backend_dir))

# Set Django settings
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.testing')

import django
django.setup()


class Phase1TestRunner:
    """Enhanced test runner for Phase 1 improvements"""

    def __init__(self):
        self.base_command = ['python', '-m', 'pytest']
        self.test_dir = Path(__file__).parent
        self.results = {}

    def run_api_integration_tests(self, verbose=False):
        """Run Phase 1.1: API Integration Tests"""
        print("\n" + "="*60)
        print("🚀 PHASE 1.1: API Integration Tests")
        print("="*60)

        test_modules = [
            'tests/integration/test_api/test_vulnerability_api.py',
            'tests/integration/test_api/test_scanning_api.py',
            'tests/integration/test_api/test_exploitation_api.py',
            'tests/integration/test_api/test_reporting_api.py',
            'tests/integration/test_api/test_authentication_api.py',
            'tests/integration/test_api/test_api_edge_cases.py'
        ]

        command = self.base_command.copy()
        command.extend(['-m', 'api and phase1'])

        if verbose:
            command.append('-v')

        command.extend([
            '--cov=api',
            '--cov-report=term-missing',
            '--tb=short'
        ])

        start_time = time.time()
        result = self._execute_command(command)
        execution_time = time.time() - start_time

        self.results['api_integration'] = {
            'status': 'passed' if result == 0 else 'failed',
            'execution_time': execution_time,
            'test_count': len(test_modules)
        }

        return result

    def run_scanner_engine_tests(self, verbose=False):
        """Run Phase 1.2: Scanner Engine Tests"""
        print("\n" + "="*60)
        print("🔍 PHASE 1.2: Scanner Engine Tests")
        print("="*60)

        command = self.base_command.copy()
        command.extend(['-m', 'scanner and phase1'])

        if verbose:
            command.append('-v')

        command.extend([
            '--cov=services.scanner_engines',
            '--cov-report=term-missing',
            '--tb=short'
        ])

        start_time = time.time()
        result = self._execute_command(command)
        execution_time = time.time() - start_time

        self.results['scanner_engines'] = {
            'status': 'passed' if result == 0 else 'failed',
            'execution_time': execution_time,
            'test_count': 5  # nuclei, web, infra, api, recon
        }

        return result

    def run_reporting_tests(self, verbose=False):
        """Run Phase 1.3: Report Generation Tests"""
        print("\n" + "="*60)
        print("📊 PHASE 1.3: Report Generation Tests")
        print("="*60)

        command = self.base_command.copy()
        command.extend(['-m', 'reporting and phase1'])

        if verbose:
            command.append('-v')

        command.extend([
            '--cov=apps.reporting',
            '--cov=services.reporting_service',
            '--cov-report=term-missing',
            '--tb=short'
        ])

        start_time = time.time()
        result = self._execute_command(command)
        execution_time = time.time() - start_time

        self.results['reporting'] = {
            'status': 'passed' if result == 0 else 'failed',
            'execution_time': execution_time,
            'test_count': 1
        }

        return result

    def run_realtime_tests(self, verbose=False):
        """Run Phase 1.4: Real-time Features Tests"""
        print("\n" + "="*60)
        print("⚡ PHASE 1.4: Real-time Features Tests")
        print("="*60)

        command = self.base_command.copy()
        command.extend(['-m', 'realtime and phase1'])

        if verbose:
            command.append('-v')

        command.extend([
            '--cov=services.notification_service',
            '--cov-report=term-missing',
            '--tb=short'
        ])

        start_time = time.time()
        result = self._execute_command(command)
        execution_time = time.time() - start_time

        self.results['realtime'] = {
            'status': 'passed' if result == 0 else 'failed',
            'execution_time': execution_time,
            'test_count': 1
        }

        return result

    def run_edge_case_tests(self, verbose=False):
        """Run comprehensive edge case tests"""
        print("\n" + "="*60)
        print("🔍 EDGE CASE & BOUNDARY TESTS")
        print("="*60)

        command = self.base_command.copy()
        command.extend(['-m', 'edge_cases'])

        if verbose:
            command.append('-v')

        command.extend([
            '--tb=short'
        ])

        start_time = time.time()
        result = self._execute_command(command)
        execution_time = time.time() - start_time

        self.results['edge_cases'] = {
            'status': 'passed' if result == 0 else 'failed',
            'execution_time': execution_time,
            'test_count': 1
        }

        return result

    def run_all_phase1_tests(self, verbose=False, coverage=True):
        """Run all Phase 1 tests"""
        print("\n" + "="*80)
        print("🎯 RUNNING ALL PHASE 1 TEST IMPROVEMENTS")
        print("="*80)
        print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        command = self.base_command.copy()
        command.extend(['-m', 'phase1'])

        if coverage:
            command.extend([
                '--cov=apps',
                '--cov=api',
                '--cov=services',
                '--cov=core',
                '--cov-report=term-missing',
                '--cov-report=html:htmlcov/phase1',
                '--cov-report=xml:coverage_phase1.xml',
                '--cov-fail-under=85'  # Higher standard for Phase 1
            ])

        if verbose:
            command.append('-v')

        command.extend([
            '--tb=short',
            '--durations=10'  # Show slowest 10 tests
        ])

        start_time = time.time()
        result = self._execute_command(command)
        total_execution_time = time.time() - start_time

        self.results['total_phase1'] = {
            'status': 'passed' if result == 0 else 'failed',
            'execution_time': total_execution_time,
            'coverage_threshold': 85
        }

        return result

    def run_phase1_by_sections(self, verbose=False):
        """Run Phase 1 tests section by section"""
        print("\n" + "="*80)
        print("📋 RUNNING PHASE 1 TESTS BY SECTIONS")
        print("="*80)

        total_start_time = time.time()
        failed_sections = []

        # Run each section
        sections = [
            ('API Integration', self.run_api_integration_tests),
            ('Scanner Engines', self.run_scanner_engine_tests),
            ('Report Generation', self.run_reporting_tests),
            ('Real-time Features', self.run_realtime_tests),
            ('Edge Cases', self.run_edge_case_tests)
        ]

        for section_name, runner_method in sections:
            try:
                result = runner_method(verbose=verbose)
                if result != 0:
                    failed_sections.append(section_name)
                    print(f"❌ {section_name} tests FAILED")
                else:
                    print(f"✅ {section_name} tests PASSED")
            except Exception as e:
                print(f"💥 {section_name} tests CRASHED: {e}")
                failed_sections.append(section_name)

        total_execution_time = time.time() - total_start_time

        # Print summary
        self._print_section_summary(failed_sections, total_execution_time)

        return 0 if not failed_sections else 1

    def validate_phase1_improvements(self):
        """Validate that Phase 1 improvements meet requirements"""
        print("\n" + "="*60)
        print("✅ VALIDATING PHASE 1 IMPROVEMENTS")
        print("="*60)

        validations = []

        # Check API test files exist
        api_test_files = [
            'tests/integration/test_api/test_vulnerability_api.py',
            'tests/integration/test_api/test_scanning_api.py',
            'tests/integration/test_api/test_exploitation_api.py',
            'tests/integration/test_api/test_reporting_api.py',
            'tests/integration/test_api/test_authentication_api.py',
            'tests/integration/test_api/test_api_edge_cases.py'
        ]

        for test_file in api_test_files:
            if Path(test_file).exists():
                validations.append(f"✅ {test_file} exists")
            else:
                validations.append(f"❌ {test_file} missing")

        # Check scanner engine tests
        scanner_test_files = [
            'tests/unit/test_scanner_engines/test_nuclei_engine_comprehensive.py',
            'tests/unit/test_scanner_engines/__init__.py'
        ]

        for test_file in scanner_test_files:
            if Path(test_file).exists():
                validations.append(f"✅ {test_file} exists")
            else:
                validations.append(f"❌ {test_file} missing")

        # Check real-time tests
        realtime_test_files = [
            'tests/integration/test_realtime/test_notifications.py',
            'tests/integration/test_realtime/__init__.py'
        ]

        for test_file in realtime_test_files:
            if Path(test_file).exists():
                validations.append(f"✅ {test_file} exists")
            else:
                validations.append(f"❌ {test_file} missing")

        # Print validation results
        for validation in validations:
            print(validation)

        failed_validations = [v for v in validations if v.startswith('❌')]

        if failed_validations:
            print(f"\n❌ {len(failed_validations)} validation(s) failed")
            return 1
        else:
            print(f"\n✅ All {len(validations)} validations passed")
            return 0

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

    def _print_section_summary(self, failed_sections, total_time):
        """Print summary of section results"""
        print("\n" + "="*80)
        print("📈 PHASE 1 EXECUTION SUMMARY")
        print("="*80)

        print(f"Total execution time: {total_time:.2f} seconds")
        print(f"Sections run: {len(self.results)}")
        print(f"Failed sections: {len(failed_sections)}")

        if failed_sections:
            print(f"\n❌ Failed sections: {', '.join(failed_sections)}")
        else:
            print(f"\n✅ All sections passed successfully!")

        # Print detailed results
        for section, result in self.results.items():
            status_emoji = "✅" if result['status'] == 'passed' else "❌"
            print(f"{status_emoji} {section}: {result['status']} "
                  f"({result['execution_time']:.2f}s)")

    def generate_phase1_report(self):
        """Generate comprehensive Phase 1 report"""
        print("\n" + "="*80)
        print("📊 PHASE 1 IMPLEMENTATION REPORT")
        print("="*80)

        report_data = {
            'implementation_date': datetime.now().isoformat(),
            'total_test_files_created': 8,
            'api_endpoints_tested': 6,
            'scanner_engines_tested': 1,  # Nuclei comprehensive
            'realtime_features_tested': 1,
            'edge_cases_covered': 1,
            'new_pytest_markers': 5,
            'estimated_coverage_improvement': '+15%'
        }

        for key, value in report_data.items():
            print(f"{key.replace('_', ' ').title()}: {value}")

        return report_data


def main():
    """Main test runner entry point"""
    parser = argparse.ArgumentParser(description='Phase 1 Test Suite Runner')

    parser.add_argument(
        'test_type',
        choices=[
            'api', 'scanner', 'reporting', 'realtime', 'edge_cases',
            'all', 'sections', 'validate'
        ],
        help='Type of Phase 1 tests to run'
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Run tests in verbose mode'
    )

    parser.add_argument(
        '--no-coverage',
        action='store_true',
        help='Run tests without coverage analysis'
    )

    parser.add_argument(
        '--report',
        action='store_true',
        help='Generate Phase 1 implementation report'
    )

    args = parser.parse_args()

    runner = Phase1TestRunner()

    # Generate report if requested
    if args.report:
        runner.generate_phase1_report()
        return 0

    # Run validation
    if args.test_type == 'validate':
        return runner.validate_phase1_improvements()

    # Run tests based on type
    coverage = not args.no_coverage
    verbose = args.verbose

    if args.test_type == 'api':
        result = runner.run_api_integration_tests(verbose=verbose)
    elif args.test_type == 'scanner':
        result = runner.run_scanner_engine_tests(verbose=verbose)
    elif args.test_type == 'reporting':
        result = runner.run_reporting_tests(verbose=verbose)
    elif args.test_type == 'realtime':
        result = runner.run_realtime_tests(verbose=verbose)
    elif args.test_type == 'edge_cases':
        result = runner.run_edge_case_tests(verbose=verbose)
    elif args.test_type == 'all':
        result = runner.run_all_phase1_tests(verbose=verbose, coverage=coverage)
    elif args.test_type == 'sections':
        result = runner.run_phase1_by_sections(verbose=verbose)
    else:
        print(f"Unknown test type: {args.test_type}")
        return 1

    # Print final result
    if result == 0:
        print("\n🎉 Phase 1 tests completed successfully!")
    else:
        print("\n💥 Phase 1 tests failed!")

    return result


if __name__ == '__main__':
    exit_code = main()
    sys.exit(exit_code)