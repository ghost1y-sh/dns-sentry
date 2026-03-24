#!/usr/bin/env python3
"""dns-sentry - DNS Suspicious Domain Analyzer"""

import argparse
import json
import sys
from dotenv import load_dotenv
import os

load_dotenv()

from app import create_app
from app.analyzer import DomainAnalyzer


def run_cli(domains, vt_api_key=None):
    """Run analysis in CLI mode without Flask."""
    analyzer = DomainAnalyzer(vt_api_key=vt_api_key)

    results = []
    for domain in domains:
        print(f"\n{'='*60}")
        print(f"  Analyzing: {domain}")
        print(f"{'='*60}")

        result = analyzer.analyze(domain)
        results.append(result)

        print(f"  Overall Risk Score: {result['risk_score']}/100")
        print(f"  Risk Level:         {result['risk_level']}")
        print()

        for check in result["checks"]:
            status = "!!" if check["flagged"] else "OK"
            print(f"  [{status}] {check['name']}: {check['detail']}")

    print(f"\n{'='*60}")
    print(f"  Summary: {len(results)} domain(s) analyzed")

    flagged = [r for r in results if r["risk_level"] in ("high", "critical")]
    if flagged:
        print(f"  FLAGGED: {len(flagged)} suspicious domain(s):")
        for r in flagged:
            print(f"    - {r['domain']} (score: {r['risk_score']}, level: {r['risk_level']})")
    else:
        print("  No suspicious domains detected.")

    print(f"{'='*60}\n")

    return results


def main():
    parser = argparse.ArgumentParser(
        description="dns-sentry - DNS Suspicious Domain Analyzer"
    )
    parser.add_argument(
        "--web", action="store_true",
        help="Run as a Flask web service"
    )
    parser.add_argument(
        "--host", default="0.0.0.0",
        help="Host to bind the web service to (default: 0.0.0.0)"
    )
    parser.add_argument(
        "--port", type=int, default=5000,
        help="Port for the web service (default: 5000)"
    )
    parser.add_argument(
        "-d", "--domain", action="append",
        help="Domain to analyze (can be specified multiple times)"
    )
    parser.add_argument(
        "-f", "--file",
        help="File containing domains to analyze (one per line)"
    )
    parser.add_argument(
        "--vt-key",
        help="VirusTotal API key for reputation lookups"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output results to JSON file"
    )

    args = parser.parse_args()

    if args.web:
        app = create_app()
        app.run(host=args.host, port=args.port, debug=False)
        return

    #CLI mode - collect domains
    domains = []

    if args.domain:
        domains.extend(args.domain)

    if args.file:
        try:
            with open(args.file, "r") as f:
                file_domains = [
                    line.strip() for line in f
                    if line.strip() and not line.startswith("#")
                ]
                domains.extend(file_domains)
        except FileNotFoundError:
            print(f"Error: File '{args.file}' not found.")
            sys.exit(1)

    if not domains:
        parser.print_help()
        print("\nError: Provide domains with -d or -f, or use --web for the web service.")
        sys.exit(1)

    vt_key = args.vt_key or os.getenv("VT_API_KEY")
    results = run_cli(domains, vt_api_key=vt_key)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"Results saved to {args.output}")


if __name__ == "__main__":
    main()