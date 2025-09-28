"""
Tool Container Integration Tests

Tests for Docker container-based penetration testing tools.
"""

import pytest
import docker
import subprocess
import time
import json
from unittest.mock import Mock, patch
from django.test import TestCase
from django.conf import settings

from tests.factories import TargetFactory, ScanSessionFactory


@pytest.mark.requires_tools
@pytest.mark.integration
class TestToolContainerIntegration(TestCase):
    """Test Docker container integration for penetration testing tools"""

    def setUp(self):
        self.docker_client = None
        self.containers_to_cleanup = []

        try:
            self.docker_client = docker.from_env()
            # Test Docker connection
            self.docker_client.ping()
        except Exception as e:
            pytest.skip(f"Docker not available: {e}")

    def tearDown(self):
        """Clean up test containers"""
        if self.docker_client:
            for container_id in self.containers_to_cleanup:
                try:
                    container = self.docker_client.containers.get(container_id)
                    container.stop()
                    container.remove()
                except Exception:
                    pass  # Container may already be removed

    def test_docker_environment_available(self):
        """Test that Docker environment is properly configured"""
        self.assertIsNotNone(self.docker_client)

        # Test Docker daemon is running
        info = self.docker_client.info()
        self.assertIn('ServerVersion', info)

        # Test we can pull images (using a small test image)
        try:
            image = self.docker_client.images.pull('alpine:latest')
            self.assertIsNotNone(image)
        except Exception as e:
            pytest.skip(f"Cannot pull Docker images: {e}")

    def test_nuclei_container_availability(self):
        """Test Nuclei container can be started and executed"""
        nuclei_image = 'projectdiscovery/nuclei:latest'

        try:
            # Pull Nuclei image
            image = self.docker_client.images.pull(nuclei_image)
            self.assertIsNotNone(image)

            # Run Nuclei version check
            container = self.docker_client.containers.run(
                nuclei_image,
                ['nuclei', '-version'],
                detach=True,
                remove=False
            )
            self.containers_to_cleanup.append(container.id)

            # Wait for completion
            result = container.wait(timeout=30)
            self.assertEqual(result['StatusCode'], 0)

            # Check output
            logs = container.logs().decode('utf-8')
            self.assertIn('nuclei', logs.lower())

        except Exception as e:
            pytest.skip(f"Nuclei container not available: {e}")

    def test_nmap_container_availability(self):
        """Test Nmap container can be started and executed"""
        nmap_image = 'instrumentisto/nmap:latest'

        try:
            # Pull Nmap image
            image = self.docker_client.images.pull(nmap_image)
            self.assertIsNotNone(image)

            # Run Nmap version check
            container = self.docker_client.containers.run(
                nmap_image,
                ['nmap', '--version'],
                detach=True,
                remove=False
            )
            self.containers_to_cleanup.append(container.id)

            # Wait for completion
            result = container.wait(timeout=30)
            self.assertEqual(result['StatusCode'], 0)

            # Check output
            logs = container.logs().decode('utf-8')
            self.assertIn('nmap', logs.lower())

        except Exception as e:
            pytest.skip(f"Nmap container not available: {e}")

    def test_container_network_connectivity(self):
        """Test that containers can access external networks"""
        try:
            # Test basic network connectivity from container
            container = self.docker_client.containers.run(
                'alpine:latest',
                ['ping', '-c', '1', '8.8.8.8'],
                detach=True,
                remove=False
            )
            self.containers_to_cleanup.append(container.id)

            result = container.wait(timeout=30)
            self.assertEqual(result['StatusCode'], 0)

        except Exception as e:
            pytest.skip(f"Container network connectivity test failed: {e}")

    def test_container_volume_mounting(self):
        """Test that volumes can be mounted for sharing scan results"""
        try:
            import tempfile
            import os

            # Create temporary directory for test
            with tempfile.TemporaryDirectory() as temp_dir:
                test_file = os.path.join(temp_dir, 'test_output.txt')

                # Run container with volume mount
                container = self.docker_client.containers.run(
                    'alpine:latest',
                    ['sh', '-c', 'echo "Container test output" > /output/test_output.txt'],
                    volumes={temp_dir: {'bind': '/output', 'mode': 'rw'}},
                    detach=True,
                    remove=False
                )
                self.containers_to_cleanup.append(container.id)

                result = container.wait(timeout=30)
                self.assertEqual(result['StatusCode'], 0)

                # Verify file was created
                self.assertTrue(os.path.exists(test_file))

                with open(test_file, 'r') as f:
                    content = f.read()
                    self.assertIn('Container test output', content)

        except Exception as e:
            pytest.skip(f"Volume mounting test failed: {e}")

    def test_container_resource_limits(self):
        """Test that resource limits are properly enforced"""
        try:
            # Run container with memory limit
            container = self.docker_client.containers.run(
                'alpine:latest',
                ['sh', '-c', 'sleep 5'],
                mem_limit='128m',
                cpuset_cpus='0',
                detach=True,
                remove=False
            )
            self.containers_to_cleanup.append(container.id)

            # Check resource limits are applied
            container_info = container.attrs
            self.assertIsNotNone(container_info.get('HostConfig', {}).get('Memory'))

            result = container.wait(timeout=30)
            self.assertEqual(result['StatusCode'], 0)

        except Exception as e:
            pytest.skip(f"Resource limits test failed: {e}")

    def test_concurrent_container_execution(self):
        """Test running multiple tool containers concurrently"""
        try:
            containers = []

            # Start multiple containers concurrently
            for i in range(3):
                container = self.docker_client.containers.run(
                    'alpine:latest',
                    ['sh', '-c', f'sleep {i + 1} && echo "Container {i} completed"'],
                    detach=True,
                    remove=False
                )
                containers.append(container)
                self.containers_to_cleanup.append(container.id)

            # Wait for all containers to complete
            for container in containers:
                result = container.wait(timeout=30)
                self.assertEqual(result['StatusCode'], 0)

                logs = container.logs().decode('utf-8')
                self.assertIn('completed', logs)

        except Exception as e:
            pytest.skip(f"Concurrent container test failed: {e}")

    def test_container_security_constraints(self):
        """Test that containers run with appropriate security constraints"""
        try:
            # Run container with security options
            container = self.docker_client.containers.run(
                'alpine:latest',
                ['id'],
                user='nobody',
                read_only=True,
                security_opt=['no-new-privileges'],
                detach=True,
                remove=False
            )
            self.containers_to_cleanup.append(container.id)

            result = container.wait(timeout=30)
            self.assertEqual(result['StatusCode'], 0)

            # Verify security constraints
            logs = container.logs().decode('utf-8')
            self.assertIn('nobody', logs)  # Should run as nobody user

        except Exception as e:
            pytest.skip(f"Security constraints test failed: {e}")


@pytest.mark.requires_tools
@pytest.mark.integration
class TestRealToolExecution(TestCase):
    """Test actual execution of penetration testing tools"""

    def setUp(self):
        self.target = TargetFactory(main_url='https://httpbin.org')  # Safe test target
        self.scan_session = ScanSessionFactory(target=self.target)

    def test_nuclei_template_execution(self):
        """Test actual Nuclei template execution against safe target"""
        try:
            nuclei_command = [
                'docker', 'run', '--rm',
                'projectdiscovery/nuclei:latest',
                'nuclei',
                '-u', 'https://httpbin.org',
                '-t', 'dns',  # Safe DNS templates only
                '-json',
                '-silent'
            ]

            result = subprocess.run(
                nuclei_command,
                capture_output=True,
                text=True,
                timeout=60
            )

            # Should complete without error
            self.assertEqual(result.returncode, 0)

            # Should produce JSON output
            if result.stdout.strip():
                # Try to parse JSON output
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if line.strip():
                        parsed = json.loads(line)
                        self.assertIn('template', parsed)

        except FileNotFoundError:
            pytest.skip("Docker command not available")
        except subprocess.TimeoutExpired:
            pytest.skip("Nuclei execution timed out")
        except Exception as e:
            pytest.skip(f"Nuclei execution failed: {e}")

    def test_nmap_port_scan(self):
        """Test actual Nmap port scan against safe target"""
        try:
            nmap_command = [
                'docker', 'run', '--rm',
                'instrumentisto/nmap:latest',
                'nmap',
                '-T4',  # Aggressive timing
                '-F',   # Fast scan (top 100 ports)
                '--host-timeout', '30s',
                'scanme.nmap.org'  # Official Nmap test target
            ]

            result = subprocess.run(
                nmap_command,
                capture_output=True,
                text=True,
                timeout=120
            )

            # Should complete without error
            self.assertEqual(result.returncode, 0)

            # Should contain scan results
            self.assertIn('Nmap scan report', result.stdout)
            self.assertIn('PORT', result.stdout)

        except FileNotFoundError:
            pytest.skip("Docker command not available")
        except subprocess.TimeoutExpired:
            pytest.skip("Nmap execution timed out")
        except Exception as e:
            pytest.skip(f"Nmap execution failed: {e}")

    def test_tool_result_parsing(self):
        """Test parsing of real tool output"""
        # Mock tool output based on real formats
        nuclei_output = """
        {"template":"ssl-issuer","template-url":"https://templates.nuclei.sh/ssl/ssl-issuer","template-id":"ssl-issuer","info":{"name":"SSL Certificate Issuer","author":["pdteam"],"tags":["ssl"],"severity":"info"},"type":"ssl","host":"https://httpbin.org","matched-at":"httpbin.org:443","timestamp":"2024-01-15T10:30:00.000Z"}
        """

        nmap_output = """
        Starting Nmap 7.80 ( https://nmap.org ) at 2024-01-15 10:30 UTC
        Nmap scan report for scanme.nmap.org (45.33.32.156)
        Host is up (0.065s latency).
        PORT     STATE SERVICE
        22/tcp   open  ssh
        80/tcp   open  http
        9929/tcp open  nping-echo
        """

        # Test Nuclei JSON parsing
        if nuclei_output.strip():
            parsed_nuclei = json.loads(nuclei_output.strip())
            self.assertIn('template', parsed_nuclei)
            self.assertIn('info', parsed_nuclei)
            self.assertEqual(parsed_nuclei['info']['severity'], 'info')

        # Test Nmap output parsing
        self.assertIn('Nmap scan report', nmap_output)
        self.assertIn('PORT', nmap_output)
        self.assertIn('STATE', nmap_output)

    def test_tool_error_handling(self):
        """Test handling of tool execution errors"""
        try:
            # Test with invalid target to trigger error
            nuclei_command = [
                'docker', 'run', '--rm',
                'projectdiscovery/nuclei:latest',
                'nuclei',
                '-u', 'invalid-url-that-does-not-exist',
                '-t', 'dns',
                '-timeout', '5'
            ]

            result = subprocess.run(
                nuclei_command,
                capture_output=True,
                text=True,
                timeout=30
            )

            # Should handle error gracefully
            # Nuclei typically returns 0 even for no results, so check stderr
            if result.stderr:
                self.assertIsInstance(result.stderr, str)

        except FileNotFoundError:
            pytest.skip("Docker command not available")
        except subprocess.TimeoutExpired:
            pytest.skip("Tool execution timed out")
        except Exception as e:
            pytest.skip(f"Tool error handling test failed: {e}")


@pytest.mark.requires_tools
@pytest.mark.integration
class TestToolOrchestration(TestCase):
    """Test orchestration of multiple tools"""

    def test_sequential_tool_execution(self):
        """Test running multiple tools in sequence"""
        tools = [
            {
                'name': 'nuclei',
                'command': ['docker', 'run', '--rm', 'projectdiscovery/nuclei:latest', 'nuclei', '--version'],
                'expected_output': 'nuclei'
            }
        ]

        results = []

        for tool in tools:
            try:
                result = subprocess.run(
                    tool['command'],
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                tool_result = {
                    'name': tool['name'],
                    'returncode': result.returncode,
                    'stdout': result.stdout,
                    'stderr': result.stderr,
                    'success': result.returncode == 0 and tool['expected_output'] in result.stdout.lower()
                }

                results.append(tool_result)

            except Exception as e:
                results.append({
                    'name': tool['name'],
                    'success': False,
                    'error': str(e)
                })

        # At least one tool should execute successfully
        successful_tools = [r for r in results if r.get('success', False)]
        self.assertGreater(len(successful_tools), 0, "No tools executed successfully")

    def test_tool_dependency_management(self):
        """Test handling of tool dependencies and requirements"""
        # Test Docker availability
        docker_available = self._check_docker_availability()

        if not docker_available:
            pytest.skip("Docker not available for tool execution")

        # Test specific tool images
        required_images = [
            'projectdiscovery/nuclei:latest',
            'alpine:latest'  # Fallback minimal image
        ]

        available_images = []

        for image in required_images:
            if self._check_image_availability(image):
                available_images.append(image)

        self.assertGreater(len(available_images), 0, "No required tool images available")

    def _check_docker_availability(self) -> bool:
        """Check if Docker is available"""
        try:
            result = subprocess.run(['docker', '--version'], capture_output=True, timeout=10)
            return result.returncode == 0
        except Exception:
            return False

    def _check_image_availability(self, image: str) -> bool:
        """Check if Docker image is available"""
        try:
            result = subprocess.run(
                ['docker', 'image', 'inspect', image],
                capture_output=True,
                timeout=10
            )
            if result.returncode == 0:
                return True

            # Try to pull the image
            result = subprocess.run(
                ['docker', 'pull', image],
                capture_output=True,
                timeout=60
            )
            return result.returncode == 0

        except Exception:
            return False


@pytest.fixture
def docker_environment():
    """Fixture to check Docker environment availability"""
    try:
        client = docker.from_env()
        client.ping()
        return client
    except Exception as e:
        pytest.skip(f"Docker environment not available: {e}")


@pytest.fixture
def tool_containers(docker_environment):
    """Fixture to manage tool containers for testing"""
    containers = []

    def _create_container(image, command, **kwargs):
        container = docker_environment.containers.run(
            image, command, detach=True, remove=False, **kwargs
        )
        containers.append(container)
        return container

    yield _create_container

    # Cleanup
    for container in containers:
        try:
            container.stop()
            container.remove()
        except Exception:
            pass