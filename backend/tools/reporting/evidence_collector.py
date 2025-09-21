"""
Evidence Collector
backend/tools/reporting/evidence_collector.py

Collects and organizes evidence files for vulnerability reports.
"""

import os
import shutil
import logging
import hashlib
from typing import Dict, List, Optional, Any
from pathlib import Path
from datetime import datetime
import json
import base64
from PIL import Image, ImageDraw, ImageFont
import requests

logger = logging.getLogger(__name__)

class EvidenceCollector:
    """
    Collects and organizes evidence files for vulnerability reports
    """

    def __init__(self, evidence_directory: str = "evidence"):
        self.evidence_directory = Path(evidence_directory)
        self.evidence_directory.mkdir(exist_ok=True)

        # Create subdirectories for different types of evidence
        (self.evidence_directory / "screenshots").mkdir(exist_ok=True)
        (self.evidence_directory / "requests").mkdir(exist_ok=True)
        (self.evidence_directory / "responses").mkdir(exist_ok=True)
        (self.evidence_directory / "payloads").mkdir(exist_ok=True)
        (self.evidence_directory / "logs").mkdir(exist_ok=True)
        (self.evidence_directory / "poc").mkdir(exist_ok=True)

    def collect_all_evidence(self, findings: List[Any]) -> Dict[str, List[str]]:
        """
        Collect all evidence files for the given findings

        Args:
            findings: List of vulnerability findings

        Returns:
            Dictionary mapping evidence type to file paths
        """
        evidence_paths = {
            'screenshots': [],
            'requests': [],
            'responses': [],
            'payloads': [],
            'logs': [],
            'poc': []
        }

        for finding in findings:
            finding_id = getattr(finding, 'id', 'unknown')

            # Collect evidence based on finding data
            if hasattr(finding, 'evidence_files') and finding.evidence_files:
                for evidence_file in finding.evidence_files:
                    if os.path.exists(evidence_file):
                        copied_file = self.copy_evidence_file(evidence_file, finding_id)
                        evidence_type = self.determine_evidence_type(evidence_file)
                        evidence_paths[evidence_type].append(copied_file)

            # Generate PoC evidence
            if hasattr(finding, 'proof_of_concept') and finding.proof_of_concept:
                poc_file = self.create_poc_file(finding.proof_of_concept, finding_id)
                evidence_paths['poc'].append(poc_file)

            # Generate payload evidence
            if hasattr(finding, 'affected_urls') and finding.affected_urls:
                for url in finding.affected_urls:
                    payload_file = self.create_payload_evidence(
                        url,
                        getattr(finding, 'proof_of_concept', ''),
                        finding_id
                    )
                    evidence_paths['payloads'].append(payload_file)

        return evidence_paths

    def copy_evidence_file(self, source_path: str, finding_id: str) -> str:
        """Copy evidence file to evidence directory"""
        source = Path(source_path)
        if not source.exists():
            logger.warning(f"Evidence file not found: {source_path}")
            return ""

        # Generate new filename with finding ID
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        new_filename = f"{finding_id}_{timestamp}_{source.name}"

        # Determine subdirectory
        evidence_type = self.determine_evidence_type(source_path)
        destination = self.evidence_directory / evidence_type / new_filename

        try:
            shutil.copy2(source, destination)
            logger.info(f"Copied evidence file: {destination}")
            return str(destination)
        except Exception as e:
            logger.error(f"Error copying evidence file {source_path}: {str(e)}")
            return ""

    def determine_evidence_type(self, file_path: str) -> str:
        """Determine evidence type based on file extension"""
        extension = Path(file_path).suffix.lower()

        if extension in ['.png', '.jpg', '.jpeg', '.gif', '.bmp']:
            return 'screenshots'
        elif extension in ['.txt', '.log']:
            return 'logs'
        elif extension in ['.json', '.xml', '.http']:
            return 'requests'
        elif extension in ['.html', '.htm']:
            return 'responses'
        else:
            return 'poc'

    def create_poc_file(self, poc_content: str, finding_id: str) -> str:
        """Create a proof of concept file"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{finding_id}_{timestamp}_poc.txt"
        filepath = self.evidence_directory / "poc" / filename

        try:
            with open(filepath, 'w') as f:
                f.write(f"Proof of Concept for Finding: {finding_id}\n")
                f.write(f"Generated: {datetime.now().isoformat()}\n")
                f.write("-" * 50 + "\n\n")
                f.write(poc_content)

            logger.info(f"Created PoC file: {filepath}")
            return str(filepath)
        except Exception as e:
            logger.error(f"Error creating PoC file: {str(e)}")
            return ""

    def create_payload_evidence(self, url: str, payload: str, finding_id: str) -> str:
        """Create payload evidence file"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{finding_id}_{timestamp}_payload.json"
        filepath = self.evidence_directory / "payloads" / filename

        payload_data = {
            'finding_id': finding_id,
            'target_url': url,
            'payload': payload,
            'timestamp': datetime.now().isoformat(),
            'method': 'GET',  # Default, could be determined from context
            'headers': {
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
        }

        try:
            with open(filepath, 'w') as f:
                json.dump(payload_data, f, indent=2)

            logger.info(f"Created payload evidence: {filepath}")
            return str(filepath)
        except Exception as e:
            logger.error(f"Error creating payload evidence: {str(e)}")
            return ""

    def capture_screenshot(self, url: str, finding_id: str, payload: str = None) -> str:
        """
        Capture screenshot of a vulnerability (placeholder implementation)
        In a real implementation, this would use Selenium or similar
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{finding_id}_{timestamp}_screenshot.png"
        filepath = self.evidence_directory / "screenshots" / filename

        try:
            # Create a placeholder screenshot with vulnerability info
            self.create_placeholder_screenshot(filepath, url, payload or "No payload")
            logger.info(f"Created screenshot evidence: {filepath}")
            return str(filepath)
        except Exception as e:
            logger.error(f"Error creating screenshot: {str(e)}")
            return ""

    def create_placeholder_screenshot(self, filepath: Path, url: str, payload: str):
        """Create a placeholder screenshot with vulnerability information"""
        # Create a simple image with text
        width, height = 800, 600
        img = Image.new('RGB', (width, height), color='white')
        draw = ImageDraw.Draw(img)

        # Try to load a font, fallback to default if not available
        try:
            font_large = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 20)
            font_medium = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 14)
            font_small = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 12)
        except:
            font_large = ImageFont.load_default()
            font_medium = ImageFont.load_default()
            font_small = ImageFont.load_default()

        # Draw content
        y_position = 50

        # Title
        draw.text((50, y_position), "Vulnerability Evidence Screenshot", fill='black', font=font_large)
        y_position += 40

        # URL
        draw.text((50, y_position), f"Target URL: {url}", fill='black', font=font_medium)
        y_position += 30

        # Payload
        draw.text((50, y_position), "Payload:", fill='black', font=font_medium)
        y_position += 25

        # Split payload into lines if too long
        max_chars_per_line = 80
        payload_lines = [payload[i:i+max_chars_per_line] for i in range(0, len(payload), max_chars_per_line)]

        for line in payload_lines[:10]:  # Limit to 10 lines
            draw.text((70, y_position), line, fill='blue', font=font_small)
            y_position += 20

        # Timestamp
        y_position += 20
        draw.text((50, y_position), f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", fill='gray', font=font_small)

        # Save the image
        img.save(filepath)

    def create_http_request_evidence(self, url: str, method: str, headers: Dict[str, str],
                                   data: str, finding_id: str) -> str:
        """Create HTTP request evidence file"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{finding_id}_{timestamp}_request.http"
        filepath = self.evidence_directory / "requests" / filename

        try:
            with open(filepath, 'w') as f:
                f.write(f"{method} {url} HTTP/1.1\n")

                for header, value in headers.items():
                    f.write(f"{header}: {value}\n")

                if data:
                    f.write(f"\n{data}")

            logger.info(f"Created HTTP request evidence: {filepath}")
            return str(filepath)
        except Exception as e:
            logger.error(f"Error creating HTTP request evidence: {str(e)}")
            return ""

    def create_http_response_evidence(self, response_data: Dict[str, Any], finding_id: str) -> str:
        """Create HTTP response evidence file"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{finding_id}_{timestamp}_response.http"
        filepath = self.evidence_directory / "responses" / filename

        try:
            with open(filepath, 'w') as f:
                f.write(f"HTTP/1.1 {response_data.get('status_code', 200)} OK\n")

                headers = response_data.get('headers', {})
                for header, value in headers.items():
                    f.write(f"{header}: {value}\n")

                body = response_data.get('body', '')
                if body:
                    f.write(f"\n{body}")

            logger.info(f"Created HTTP response evidence: {filepath}")
            return str(filepath)
        except Exception as e:
            logger.error(f"Error creating HTTP response evidence: {str(e)}")
            return ""

    def create_log_evidence(self, log_content: str, log_type: str, finding_id: str) -> str:
        """Create log evidence file"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{finding_id}_{timestamp}_{log_type}.log"
        filepath = self.evidence_directory / "logs" / filename

        try:
            with open(filepath, 'w') as f:
                f.write(f"Log Type: {log_type}\n")
                f.write(f"Finding ID: {finding_id}\n")
                f.write(f"Generated: {datetime.now().isoformat()}\n")
                f.write("-" * 50 + "\n\n")
                f.write(log_content)

            logger.info(f"Created log evidence: {filepath}")
            return str(filepath)
        except Exception as e:
            logger.error(f"Error creating log evidence: {str(e)}")
            return ""

    def generate_evidence_index(self, evidence_paths: Dict[str, List[str]]) -> str:
        """Generate an index file listing all evidence"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"evidence_index_{timestamp}.json"
        filepath = self.evidence_directory / filename

        index_data = {
            'generated': datetime.now().isoformat(),
            'total_files': sum(len(files) for files in evidence_paths.values()),
            'evidence_by_type': evidence_paths,
            'evidence_summary': {
                evidence_type: len(files)
                for evidence_type, files in evidence_paths.items()
            }
        }

        try:
            with open(filepath, 'w') as f:
                json.dump(index_data, f, indent=2)

            logger.info(f"Created evidence index: {filepath}")
            return str(filepath)
        except Exception as e:
            logger.error(f"Error creating evidence index: {str(e)}")
            return ""

    def compress_evidence(self, evidence_paths: Dict[str, List[str]]) -> str:
        """Compress all evidence into a ZIP file"""
        import zipfile

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        zip_filename = f"evidence_package_{timestamp}.zip"
        zip_filepath = self.evidence_directory / zip_filename

        try:
            with zipfile.ZipFile(zip_filepath, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for evidence_type, file_paths in evidence_paths.items():
                    for file_path in file_paths:
                        if os.path.exists(file_path):
                            # Add file to zip with folder structure
                            arcname = f"{evidence_type}/{os.path.basename(file_path)}"
                            zipf.write(file_path, arcname)

                # Add evidence index
                index_file = self.generate_evidence_index(evidence_paths)
                if index_file and os.path.exists(index_file):
                    zipf.write(index_file, "evidence_index.json")

            logger.info(f"Created evidence package: {zip_filepath}")
            return str(zip_filepath)
        except Exception as e:
            logger.error(f"Error creating evidence package: {str(e)}")
            return ""

    def validate_evidence_integrity(self, evidence_paths: Dict[str, List[str]]) -> Dict[str, Any]:
        """Validate the integrity of evidence files"""
        validation_results = {
            'valid_files': 0,
            'invalid_files': 0,
            'missing_files': 0,
            'file_checksums': {},
            'validation_errors': []
        }

        for evidence_type, file_paths in evidence_paths.items():
            for file_path in file_paths:
                if not os.path.exists(file_path):
                    validation_results['missing_files'] += 1
                    validation_results['validation_errors'].append(f"Missing file: {file_path}")
                    continue

                try:
                    # Calculate file checksum
                    with open(file_path, 'rb') as f:
                        file_hash = hashlib.md5(f.read()).hexdigest()

                    validation_results['file_checksums'][file_path] = file_hash
                    validation_results['valid_files'] += 1

                except Exception as e:
                    validation_results['invalid_files'] += 1
                    validation_results['validation_errors'].append(f"Error validating {file_path}: {str(e)}")

        return validation_results

# Example usage
def main():
    """Example usage of the EvidenceCollector"""
    collector = EvidenceCollector("./evidence")

    # Create sample evidence
    sample_finding = type('Finding', (), {
        'id': 'vuln_001',
        'proof_of_concept': "' OR '1'='1' --",
        'affected_urls': ['https://example.com/login']
    })()

    # Collect evidence
    evidence_paths = collector.collect_all_evidence([sample_finding])

    # Generate additional evidence
    screenshot_path = collector.capture_screenshot(
        "https://example.com/vulnerable",
        "vuln_001",
        "<script>alert('XSS')</script>"
    )

    request_path = collector.create_http_request_evidence(
        "https://example.com/api/test",
        "POST",
        {"Content-Type": "application/json"},
        '{"test": "payload"}',
        "vuln_001"
    )

    # Validate evidence
    validation = collector.validate_evidence_integrity(evidence_paths)
    print(f"Evidence validation: {validation['valid_files']} valid, {validation['invalid_files']} invalid")

    # Create evidence package
    package_path = collector.compress_evidence(evidence_paths)
    print(f"Evidence package created: {package_path}")

if __name__ == "__main__":
    main()