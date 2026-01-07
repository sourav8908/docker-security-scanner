import docker
import subprocess
import json
import tempfile
import os

class ImageScanner:
    """Scans Docker images using Trivy"""
    
    def __init__(self):
        """Initialize Docker client"""
        try:
            self.client = docker.from_env()
        except docker.errors.DockerException as e:
            raise RuntimeError(f"Docker is not running or not accessible: {e}")
    
    def list_local_images(self):
        """List all local Docker images"""
        images = self.client.images.list()
        return [
            {
                'id': img.id,
                'tags': img.tags,
                'size': img.attrs['Size'],
                'created': img.attrs['Created']
            }
            for img in images if img.tags
        ]
    
    def scan_image(self, image_name):
        """
        Scan Docker image using Trivy
        
        Args:
            image_name: Docker image name (e.g., 'nginx:latest')
        
        Returns:
            dict: Scan results
        """
        print(f"🔍 Scanning {image_name} with Trivy...")
        
        try:
            # Run Trivy scan
            result = subprocess.run(
                ['trivy', 'image', '--format', 'json', '--quiet', image_name],
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes timeout
            )
            
            if result.returncode != 0:
                raise RuntimeError(f"Trivy scan failed: {result.stderr}")
            
            # Parse JSON output
            scan_data = json.loads(result.stdout)
            
            return {
                'image_name': image_name,
                'scan_data': scan_data,
                'success': True
            }
        
        except subprocess.TimeoutExpired:
            return {
                'image_name': image_name,
                'error': 'Scan timeout (>5 minutes)',
                'success': False
            }
        except FileNotFoundError:
            raise RuntimeError("Trivy not installed. Install: brew install trivy")
        except Exception as e:
            return {
                'image_name': image_name,
                'error': str(e),
                'success': False
            }
    
    def get_image_info(self, image_name):
        """Get Docker image metadata"""
        try:
            image = self.client.images.get(image_name)
            return {
                'id': image.id,
                'tags': image.tags,
                'size': image.attrs['Size'],
                'created': image.attrs['Created'],
                'architecture': image.attrs.get('Architecture', 'unknown'),
                'os': image.attrs.get('Os', 'unknown')
            }
        except docker.errors.ImageNotFound:
            return None
    
    def extract_dockerfile(self, image_name):
        """
        Try to extract Dockerfile from image history
        (Note: This is approximate, original Dockerfile may differ)
        """
        try:
            image = self.client.images.get(image_name)
            history = image.history()
            
            # Reconstruct approximate Dockerfile
            dockerfile_lines = []
            
            for layer in reversed(history):
                created_by = layer.get('CreatedBy', '')
                if created_by and not created_by.startswith('/bin/sh -c #(nop)'):
                    # Clean up the command
                    cmd = created_by.replace('/bin/sh -c ', '')
                    if cmd.strip():
                        dockerfile_lines.append(cmd)
            
            return '\n'.join(dockerfile_lines) if dockerfile_lines else None
        except Exception:
            return None