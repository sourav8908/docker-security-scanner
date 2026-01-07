import argparse
import sys
import yaml
import subprocess
from colorama import Fore, Style, init

from scanner.image_scanner import ImageScanner
from scanner.vulnerability_analyzer import VulnerabilityAnalyzer
from scanner.dockerfile_fixer import DockerfileFixer
from scanner.report_generator import ReportGenerator
from scanner.image_builder import ImageBuilder

# Initialize colorama
init(autoreset=True)


def load_config():
    try:
        with open('config/config.yaml', 'r') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        print(f"{Fore.YELLOW}⚠️  Using default configuration{Style.RESET_ALL}")
        return {
            'scanner': {'severity_levels': ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']},
            'auto_fix': {'enabled': True, 'base_image_upgrades': {}},
            'report': {'output_file': 'security_report.html'}
        }


def print_banner():
    print(f"""
{Fore.RED}╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║        🔒  DOCKER SECURITY SCANNER  🔒                       ║
║                                                              ║
║           Scan images, find vulnerabilities,                ║
║           and auto-generate fixes                           ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
""")


def get_running_container_images():
    """Return unique images used by running containers"""
    try:
        result = subprocess.run(
            ["docker", "ps", "--format", "{{.Image}}"],
            capture_output=True,
            text=True,
            check=True
        )
        return list({line.strip() for line in result.stdout.splitlines() if line.strip()})
    except Exception as e:
        print(f"{Fore.RED}❌ Failed to detect running containers: {e}{Style.RESET_ALL}")
        return []


def main():
    # ---------------- ARGUMENTS ----------------
    parser = argparse.ArgumentParser(
        description='Docker Security Scanner - Find and fix vulnerabilities'
    )
    parser.add_argument(
        'image',
        nargs='?',
        help='Docker image to scan (e.g., nginx:1.18)'
    )
    parser.add_argument(
        '--scan-running',
        action='store_true',
        help='Scan all images used by running containers'
    )
    parser.add_argument(
        '--output',
        default=None,
        help='Output HTML report file'
    )
    parser.add_argument(
        '--validate',
        action='store_true',
        help='Build fixed image and validate fixes (single image only)'
    )

    args = parser.parse_args()

    # ---------------- CONFIG ----------------
    config = load_config()
    output_file = args.output or config['report']['output_file']

    print_banner()

    try:
        # ---------------- IMAGE SELECTION ----------------
        if args.scan_running:
            print(f"{Fore.CYAN}📋 Mode: Scan running containers{Style.RESET_ALL}")
            images_to_scan = get_running_container_images()
            if not images_to_scan:
                print(f"{Fore.RED}❌ No running containers found{Style.RESET_ALL}")
                sys.exit(1)
        else:
            if not args.image:
                print(f"{Fore.RED}❌ Image name required unless --scan-running is used{Style.RESET_ALL}")
                sys.exit(1)
            images_to_scan = [args.image]
            print(f"{Fore.CYAN}📋 Image: {args.image}{Style.RESET_ALL}")

        print(f"{Fore.CYAN}📄 Output: {output_file}{Style.RESET_ALL}\n")

        # ---------------- SCAN LOOP ----------------
        scanner = ImageScanner()
        analyzer = VulnerabilityAnalyzer(
            ignore_cves=config['scanner'].get('ignore_cves', [])
        )

        all_vulnerabilities = []
        combined_scan_result = {
            'image_name': 'Running Containers' if args.scan_running else images_to_scan[0]
        }

        for image in images_to_scan:
            print(f"{Fore.CYAN}🔍 Scanning image: {image}{Style.RESET_ALL}")
            scan_result = scanner.scan_image(image)

            if not scan_result.get('success'):
                print(f"{Fore.RED}❌ Scan failed for {image}{Style.RESET_ALL}")
                continue

            vulns = analyzer.parse_trivy_results(scan_result['scan_data'])
            for v in vulns:
                v['image'] = image

            all_vulnerabilities.extend(vulns)

        if not all_vulnerabilities:
            print(f"{Fore.RED}❌ No vulnerabilities found{Style.RESET_ALL}")
            sys.exit(1)

        # ---------------- AUTO-FIX + VALIDATE ----------------
        comparison_data = None

        if not args.scan_running and config['auto_fix']['enabled']:
            summary = analyzer.get_summary(all_vulnerabilities)

            fixer = DockerfileFixer(
                base_image_upgrades=config['auto_fix'].get('base_image_upgrades', {})
            )

            complete_fix = fixer.generate_complete_dockerfile(
                original_image=args.image,
                vulnerabilities=all_vulnerabilities,
                summary=summary
            )

            fixer.save_dockerfile(complete_fix['dockerfile'], 'Dockerfile.fixed')

            print(f"{Fore.GREEN}✅ Dockerfile.fixed generated{Style.RESET_ALL}")
            print(f"   Base image: {complete_fix['original_image']} → {complete_fix['base_image']}")
            print(f"   Expected reduction: ~{complete_fix['expected_reduction']}%")

            if args.validate:
                builder = ImageBuilder()
                build_result = builder.build_fixed_image(
                    dockerfile_content=complete_fix['dockerfile'],
                    original_image=args.image
                )

                if build_result.get('success'):
                    fixed_scan = builder.scan_image(build_result['image_name'])
                    if fixed_scan.get('success'):
                        # ✅ IMPORTANT: wrap comparison by image name
                        comparison_data = {
                            args.image: builder.compare_scans(
                                summary,
                                fixed_scan['summary']
                            )
                        }

        # ---------------- REPORT ----------------
        print(f"{Fore.CYAN}📝 Generating security report...{Style.RESET_ALL}")

        report = ReportGenerator(
            scan_results=combined_scan_result,
            vulnerabilities=all_vulnerabilities,
            comparison=comparison_data
        )
        report.generate_html_report(output_file)

        print(f"{Fore.GREEN}✅ Report generated: {output_file}{Style.RESET_ALL}")

    except Exception as e:
        print(f"{Fore.RED}❌ Error: {e}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
