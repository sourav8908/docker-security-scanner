import docker
import subprocess
import json
import tempfile
import os

class ImageBuilder:
    """Builds and validates fixed Docker images"""

    def __init__(self):
        """Initialize Docker client"""
        try:
            self.client = docker.from_env()
        except docker.errors.DockerException as e:
            raise RuntimeError(f"Docker not available: {e}")

    def build_fixed_image(self, dockerfile_content, original_image, tag_suffix='fixed'):
        """
        Build image from fixed Dockerfile
        """
        if ':' in original_image:
            base_name, original_tag = original_image.rsplit(':', 1)
            fixed_tag = f"{base_name}:{original_tag}-{tag_suffix}"
        else:
            fixed_tag = f"{original_image}-{tag_suffix}"

        print(f"🏗️  Building fixed image: {fixed_tag}")

        with tempfile.TemporaryDirectory() as tmpdir:
            dockerfile_path = os.path.join(tmpdir, 'Dockerfile')
            with open(dockerfile_path, 'w', encoding='utf-8') as f:
                f.write(dockerfile_content)

            dockerignore_path = os.path.join(tmpdir, '.dockerignore')
            with open(dockerignore_path, 'w', encoding='utf-8') as f:
                f.write('.git\n.gitignore\n*.md\n')

            try:
                image, build_logs = self.client.images.build(
                    path=tmpdir,
                    tag=fixed_tag,
                    rm=True,
                    forcerm=True
                )

                logs = []
                for chunk in build_logs:
                    if 'stream' in chunk:
                        logs.append(chunk['stream'].strip())

                return {
                    'success': True,
                    'image_name': fixed_tag,
                    'image_id': image.id,
                    'logs': logs
                }

            except docker.errors.BuildError as e:
                return {
                    'success': False,
                    'error': str(e),
                    'logs': [str(log) for log in e.build_log]
                }
            except Exception as e:
                return {
                    'success': False,
                    'error': str(e),
                    'logs': []
                }

    # 🔧 WINDOWS-SAFE TRIVY SCAN
    def scan_image(self, image_name):
        """
        Scan image using Trivy (Windows-safe implementation)
        """
        print(f"🔍 Scanning {image_name}...")

        try:
            # Create temp file to avoid encoding issues
            with tempfile.NamedTemporaryFile(delete=False, suffix='.json') as tmp:
                output_file = tmp.name

            # Run Trivy and write JSON directly to file
            result = subprocess.run(
                [
                    'trivy',
                    'image',
                    '--quiet',
                    '--format', 'json',
                    '--output', output_file,
                    image_name
                ],
                timeout=300
            )

            if result.returncode != 0:
                return {
                    'success': False,
                    'error': 'Trivy scan failed'
                }

            # Read JSON safely
            with open(output_file, 'r', encoding='utf-8', errors='ignore') as f:
                scan_data = json.load(f)

            # Cleanup temp file
            try:
                os.remove(output_file)
            except:
                pass

            vulnerabilities = []
            for result_item in scan_data.get('Results', []):
                for vuln in result_item.get('Vulnerabilities', []):
                    vulnerabilities.append({
                        'cve_id': vuln.get('VulnerabilityID'),
                        'severity': vuln.get('Severity'),
                        'package_name': vuln.get('PkgName'),
                        'installed_version': vuln.get('InstalledVersion'),
                        'fixed_version': vuln.get('FixedVersion', 'Not available')
                    })

            summary = {
                'total': len(vulnerabilities),
                'critical': sum(1 for v in vulnerabilities if v['severity'] == 'CRITICAL'),
                'high': sum(1 for v in vulnerabilities if v['severity'] == 'HIGH'),
                'medium': sum(1 for v in vulnerabilities if v['severity'] == 'MEDIUM'),
                'low': sum(1 for v in vulnerabilities if v['severity'] == 'LOW')
            }

            return {
                'success': True,
                'vulnerabilities': vulnerabilities,
                'summary': summary
            }

        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Scan timeout'
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def compare_scans(self, original_summary, fixed_summary):
        """Compare vulnerability counts before and after"""
        comparison = {
            'original': original_summary,
            'fixed': fixed_summary,
            'reduction': {},
            'reduction_percentage': {}
        }

        for severity in ['critical', 'high', 'medium', 'low', 'total']:
            original_count = original_summary.get(severity, 0)
            fixed_count = fixed_summary.get(severity, 0)

            reduction = original_count - fixed_count
            comparison['reduction'][severity] = reduction

            if original_count > 0:
                pct = int((reduction / original_count) * 100)
                comparison['reduction_percentage'][severity] = pct
            else:
                comparison['reduction_percentage'][severity] = 0

        return comparison
