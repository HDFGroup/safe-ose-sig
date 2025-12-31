#!/usr/bin/env python3

"""
C++ Binary SBOM Analyzer
Extracts dependency information from compiled binaries
SOURCE: https://sbomgenerator.com/guides/cpp
"""

import subprocess
import json
import re
from pathlib import Path
from elftools.elf.elffile import ELFFile
from elftools.elf.dynamic import DynamicSection

class BinaryAnalyzer:
    def __init__(self, binary_path):
        self.binary_path = Path(binary_path)
    def analyze(self):
        """Analyze binary for dependency information"""
        analysis = {
            "binary": str(self.binary_path),
            "dynamic_dependencies": self._get_dynamic_deps(),
            "static_libraries": self._detect_static_libs(),
            "symbols": self._extract_symbols(),
            "build_info": self._get_build_info()
        }
        return analysis
    def _get_dynamic_deps(self):
        """Extract dynamic library dependencies"""
        deps = []
        try:
            with open(self.binary_path, 'rb') as f:
                elf = ELFFile(f)
                for section in elf.iter_sections():
                    if isinstance(section, DynamicSection):
                        for tag in section.iter_tags():
                            if tag.entry.d_tag == 'DT_NEEDED':
                                deps.append(tag.needed)
        except Exception as e:
            print(f"Error reading ELF file: {e}")
            # Fallback to objdump
            try:
                result = subprocess.run(
                    ["objdump", "-p", str(self.binary_path)],
                    capture_output=True, text=True
                )
                for line in result.stdout.split('\n'):
                    if 'NEEDED' in line:
                        lib = line.split()[-1]
                        deps.append(lib)
            except Exception as e2:
                print(f"Fallback objdump failed: {e2}")
        return deps
    def _detect_static_libs(self):
        """Detect statically linked libraries through symbol analysis"""
        static_libs = []
        try:
            # Use nm to get symbols
            result = subprocess.run(
                ["nm", "-D", str(self.binary_path)],
                capture_output=True, text=True
            )
            symbols = result.stdout
            # Known library patterns
            lib_patterns = {
                "boost": [r"boost::", r"_ZN5boost"],
                "openssl": [r"SSL_", r"EVP_", r"RSA_"],
                "zlib": [r"inflate", r"deflate", r"gzip"],
                "protobuf": [r"google::protobuf", r"_ZN6google8protobuf"],
                "curl": [r"curl_", r"CURL"]
            }
            for lib_name, patterns in lib_patterns.items():
                if any(re.search(pattern, symbols) for pattern in patterns):
                    static_libs.append(lib_name)
        except Exception as e:
            print(f"Error analyzing symbols: {e}")
        return static_libs
    def _extract_symbols(self):
        """Extract important symbol information"""
        symbols = {"imported": [], "exported": []}
        try:
            # Get imported symbols
            result = subprocess.run(
                ["objdump", "-T", str(self.binary_path)],
                capture_output=True, text=True
            )
            for line in result.stdout.split('\n'):
                if 'UND' in line:  # Undefined (imported) symbols
                    parts = line.split()
                    if len(parts) >= 7:
                        symbols["imported"].append(parts[-1])
        except Exception as e:
            print(f"Error extracting symbols: {e}")
        return symbols
    def _get_build_info(self):
        """Extract build information from binary"""
        build_info = {}
        try:
            # Get file info
            result = subprocess.run(
                ["file", str(self.binary_path)],
                capture_output=True, text=True
            )
            build_info["file_type"] = result.stdout.strip()
            # Get strings that might indicate compiler/version
            result = subprocess.run(
                ["strings", str(self.binary_path)],
                capture_output=True, text=True
            )
            strings_output = result.stdout
            # Look for compiler signatures
            if "GCC:" in strings_output:
                gcc_match = re.search(r"GCC: \(.*\) ([\d.]+)", strings_output)
                if gcc_match:
                    build_info["compiler"] = f"GCC {gcc_match.group(1)}"
            if "clang" in strings_output.lower():
                clang_match = re.search(r"clang version ([\d.]+)", strings_output)
                if clang_match:
                    build_info["compiler"] = f"Clang {clang_match.group(1)}"
        except Exception as e:
            print(f"Error extracting build info: {e}")
        return build_info
    def generate_sbom(self, output_file):
        """Generate SBOM from binary analysis"""
        analysis = self.analyze()
        sbom = {
            "SPDXID": "SPDXRef-DOCUMENT",
            "spdxVersion": "SPDX-2.3",
            "creationInfo": {
                "creators": ["Tool: binary-analyzer"],
                "created": "2024-01-01T00:00:00Z"
            },
            "name": self.binary_path.name,
            "documentNamespace": f"https://binary-analysis/{self.binary_path.name}",
            "packages": [],
            "relationships": []
        }
        # Add main binary package
        main_package = {
            "SPDXID": "SPDXRef-Binary",
            "name": self.binary_path.name,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": True,
            "copyrightText": "NOASSERTION"
        }
        sbom["packages"].append(main_package)
        # Add dynamic dependencies
        for dep in analysis["dynamic_dependencies"]:
            dep_package = {
                "SPDXID": f"SPDXRef-{dep.replace('.', '-').replace('-', '')}",
                "name": dep,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "copyrightText": "NOASSERTION"
            }
            sbom["packages"].append(dep_package)
            sbom["relationships"].append({
                "spdxElementId": "SPDXRef-Binary",
                "relatedSpdxElement": dep_package["SPDXID"],
                "relationshipType": "DEPENDS_ON"
            })
        # Add static dependencies
        for static_lib in analysis["static_libraries"]:
            static_package = {
                "SPDXID": f"SPDXRef-{static_lib}",
                "name": static_lib,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "copyrightText": "NOASSERTION",
                "comment": "Statically linked library detected through symbol analysis"
            }
            sbom["packages"].append(static_package)
            sbom["relationships"].append({
                "spdxElementId": "SPDXRef-Binary", 
                "relatedSpdxElement": static_package["SPDXID"],
                "relationshipType": "STATIC_LINK"
            })
        # Write SBOM
        with open(output_file, 'w') as f:
            json.dump(sbom, f, indent=2)
        return output_file
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Analyze binary for SBOM generation")
    parser.add_argument("binary", help="Path to binary file")
    parser.add_argument("-o", "--output", default="binary-sbom.spdx.json", help="Output SBOM file")
    args = parser.parse_args()
    analyzer = BinaryAnalyzer(args.binary)
    output_file = analyzer.generate_sbom(args.output)
    print(f"Generated SBOM: {output_file}")