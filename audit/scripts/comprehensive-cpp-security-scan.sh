#!/usr/bin/env bash
# comprehensive-cpp-security-scan.sh
# SOURCE: https://sbomgenerator.com/guides/cpp

set -euo pipefail
PROJECT_DIR="${1:-.}"
OUTPUT_DIR="${2:-./security-analysis}"
SBOM_FILE="${3:-sbom.json}"
echo "=== C++ Comprehensive Security Analysis ==="
echo "Project: $PROJECT_DIR"
echo "Output: $OUTPUT_DIR"
# Create output structure
mkdir -p "$OUTPUT_DIR"/{sboms,vulnerabilities,licenses,compliance}
# 1. Generate comprehensive SBOM
echo "1. Generating comprehensive SBOM..."
syft packages dir:"$PROJECT_DIR" \
    -o spdx-json="$OUTPUT_DIR/sboms/complete.spdx.json" \
    -o cyclonedx-json="$OUTPUT_DIR/sboms/complete.cyclonedx.json" \
    -v
# 2. Multiple vulnerability scans
echo "2. Running vulnerability scans..."
# Grype scan
grype dir:"$PROJECT_DIR" \
    -o json > "$OUTPUT_DIR/vulnerabilities/grype.json"
grype dir:"$PROJECT_DIR" \
    -o table > "$OUTPUT_DIR/vulnerabilities/grype.txt"
# Trivy scan
trivy fs "$PROJECT_DIR" \
    --format json \
    --output "$OUTPUT_DIR/vulnerabilities/trivy.json"
# OSV Scanner
if command -v osv-scanner &> /dev/null; then
    osv-scanner --format json "$PROJECT_DIR" > "$OUTPUT_DIR/vulnerabilities/osv.json" 2>/dev/null || echo "OSV scan failed"
fi
# 3. License analysis
echo "3. Analyzing licenses..."
# Create license template before invoking syft (syft 1.39 requires -t path)
cat > "$OUTPUT_DIR/licenses/licenses.tmpl" << 'EOF'
{{- range .Artifacts}}
{{- if .Licenses}}
Package: {{.Name}}@{{.Version}}
{{- range .Licenses}}
License: {{.}}
{{- end}}
{{- end}}
{{- end}}
EOF
syft packages dir:"$PROJECT_DIR" \
    -o template -t "$OUTPUT_DIR/licenses/licenses.tmpl" \
    > "$OUTPUT_DIR/licenses/detected-licenses.txt"
# 4. Binary analysis for additional security insights
echo "4. Performing binary security analysis..."
find "$PROJECT_DIR" -type f -executable | while read binary; do
    if file "$binary" | grep -q ELF; then
        filename=$(basename "$binary")
        # Check for security features
        echo "=== Security Analysis for $filename ===" >> "$OUTPUT_DIR/security-features.txt"
        # Stack canary
        if objdump -d "$binary" | grep -q "__stack_chk_fail"; then
            echo "✓ Stack canary protection enabled" >> "$OUTPUT_DIR/security-features.txt"
        else
            echo "✗ Stack canary protection disabled" >> "$OUTPUT_DIR/security-features.txt"
        fi
        # NX bit / DEP
        if readelf -l "$binary" | grep -q "GNU_STACK.*RWE"; then
            echo "✗ Executable stack (security risk)" >> "$OUTPUT_DIR/security-features.txt"
        else
            echo "✓ Non-executable stack" >> "$OUTPUT_DIR/security-features.txt"
        fi
        # PIE (Position Independent Executable)
        if readelf -h "$binary" | grep -q "Type:.*DYN"; then
            echo "✓ Position Independent Executable (PIE)" >> "$OUTPUT_DIR/security-features.txt"
        else
            echo "✗ Not a PIE binary" >> "$OUTPUT_DIR/security-features.txt"
        fi
        # RELRO
        if readelf -l "$binary" | grep -q "GNU_RELRO"; then
            echo "✓ RELRO protection enabled" >> "$OUTPUT_DIR/security-features.txt"
        else
            echo "✗ RELRO protection disabled" >> "$OUTPUT_DIR/security-features.txt"
        fi
        echo "" >> "$OUTPUT_DIR/security-features.txt"
    fi
done
# 5. Static analysis (if cppcheck available)
echo "5. Running static analysis..."
if command -v cppcheck &> /dev/null; then
    cppcheck --xml --xml-version=2 \
        --enable=all \
        --suppress=missingIncludeSystem \
        "$PROJECT_DIR" 2> "$OUTPUT_DIR/static-analysis-cppcheck.xml" || true
fi
# 6. Dependency confusion check
echo "6. Checking for dependency confusion risks..."
cat > "$OUTPUT_DIR/dependency-confusion-check.py" << 'EOF'
import json
import sys
import re
import os
output_dir = os.environ.get("OUTPUT_DIR", ".")
project_dir = os.environ.get("PROJECT_DIR", ".")
def check_dependency_confusion(sbom_file):
    """Check for potential dependency confusion attacks"""
    risks = []
    try:
        with open(sbom_file, 'r') as f:
            sbom = json.load(f)
        # Check for internal/private packages that might be confused with public ones
        packages = sbom.get('components', sbom.get('packages', []))
        for pkg in packages:
            name = pkg.get('name', '')
            version = pkg.get('version', pkg.get('versionInfo', ''))
            # Check for suspicious patterns
            if re.search(r'(internal|private|corp|company)', name.lower()):
                risks.append({
                    'package': name,
                    'version': version,
                    'risk': 'Internal package name - check for typosquatting',
                    'severity': 'medium'
                })
            # Check for single character differences from popular packages
            popular_packages = ['boost', 'openssl', 'curl', 'zlib', 'protobuf']
            for popular in popular_packages:
                if len(name) == len(popular) and sum(c1 != c2 for c1, c2 in zip(name.lower(), popular)) == 1:
                    risks.append({
                        'package': name,
                        'version': version,
                        'risk': f'Similar to popular package "{popular}" - potential typosquatting',
                        'severity': 'high'
                    })
    except Exception as e:
        print(f"Error analyzing SBOM: {e}")
        return []
    return risks
if __name__ == "__main__":
    risks = check_dependency_confusion(f"{output_dir}/sboms/complete.cyclonedx.json")
    with open(f"{output_dir}/dependency-confusion-risks.json", 'w') as f:
        json.dump(risks, f, indent=2)
    if risks:
        print("⚠️  Potential dependency confusion risks found:")
        for risk in risks:
            print(f"  - {risk['package']}: {risk['risk']}")
    else:
        print("✓ No obvious dependency confusion risks detected")
EOF
OUTPUT_DIR="$OUTPUT_DIR" PROJECT_DIR="$PROJECT_DIR" python3 "$OUTPUT_DIR/dependency-confusion-check.py"
# 7. Generate compliance report
echo "7. Generating compliance report..."
cat > "$OUTPUT_DIR/compliance/compliance-report.md" << EOF
# C++ Project Security Compliance Report
Generated: $(date)
Project: $PROJECT_DIR
## Executive Summary
### Vulnerability Summary
- Grype vulnerabilities: $(jq '.matches | length' "$OUTPUT_DIR/vulnerabilities/grype.json")
- Trivy vulnerabilities: $(jq '.Results[0].Vulnerabilities | length' "$OUTPUT_DIR/vulnerabilities/trivy.json" 2>/dev/null || echo "0")
### License Summary
- Total packages analyzed: $(jq '.artifacts | length' "$OUTPUT_DIR/sboms/complete.spdx.json")
- Unique licenses detected: $(grep "License:" "$OUTPUT_DIR/licenses/detected-licenses.txt" | sort -u | wc -l)
### Security Features Analysis
$(cat "$OUTPUT_DIR/security-features.txt")
## Detailed Findings
### High Severity Vulnerabilities
$(jq -r '.matches[] | select(.vulnerability.severity == "High") | "- \(.vulnerability.id): \(.artifact.name)@\(.artifact.version)"' "$OUTPUT_DIR/vulnerabilities/grype.json")
### License Compliance Issues
$(grep -E "(GPL|AGPL|SSPL)" "$OUTPUT_DIR/licenses/detected-licenses.txt" || echo "No restrictive licenses detected")
### Recommendations
1. Update dependencies with known vulnerabilities
2. Enable all security compilation flags (stack canaries, PIE, RELRO)
3. Review license compatibility for commercial use
4. Implement dependency pinning to prevent confusion attacks
## Files Generated
- SBOM: \`sboms/complete.spdx.json\` and \`sboms/complete.cyclonedx.json\`
- Vulnerabilities: \`vulnerabilities/grype.json\` and \`vulnerabilities/trivy.json\`
- Licenses: \`licenses/detected-licenses.txt\`
- Security features: \`security-features.txt\`
EOF
# 8. Summary
echo ""
echo "=== Security Analysis Complete ==="
echo "Reports generated in: $OUTPUT_DIR"
echo ""
echo "Key findings:"
echo "- Vulnerabilities: $(jq '.matches | length' "$OUTPUT_DIR/vulnerabilities/grype.json") found by Grype"
echo "- Licenses: $(grep "License:" "$OUTPUT_DIR/licenses/detected-licenses.txt" | sort -u | wc -l) unique licenses detected"
echo "- SBOM packages: $(jq '.artifacts | length' "$OUTPUT_DIR/sboms/complete.spdx.json") components tracked"
echo ""
echo "Review the compliance report: $OUTPUT_DIR/compliance/compliance-report.md"
