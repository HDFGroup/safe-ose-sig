#!/usr/bin/env bash
# static-library-detection.sh
# SOURCE: https://sbomgenerator.com/guides/cpp

echo "=== Static Library Detection for C++ Projects ==="
BINARY_DIR="${1:-./build}"
OUTPUT_FILE="${2:-static-libs-detected.json}"
if [ ! -d "$BINARY_DIR" ]; then
    echo "Binary directory not found: $BINARY_DIR"
    exit 1
fi
echo "Analyzing binaries in: $BINARY_DIR"
# Create output structure
cat > "$OUTPUT_FILE" << 'EOF'
{
  "static_libraries_detected": [],
  "analysis_method": "symbol_analysis",
  "binaries_analyzed": []
}
EOF
# Function to detect static libraries in binary
detect_static_libs() {
    local binary="$1"
    local output_json="$2"
    echo "Analyzing: $binary"
    # Get symbols
    if ! nm "$binary" >/dev/null 2>&1; then
        echo "  Cannot analyze symbols in $binary"
        return
    fi
    # Common library detection patterns
    declare -A lib_patterns
    lib_patterns[hdf5]="H5|HDF5"
    lib_patterns[hdf5_hl]="H5DO|H5DS|H5LT|H5PT|H5TB"
    lib_patterns[hdf5_tools]="h5tools"
    lib_patterns[libaec]="aec_"
    lib_patterns[zlib]="inflate|deflate|gzip|compress"
    # Extract symbols
    symbols=$(nm "$binary" 2>/dev/null | cut -d' ' -f3- | grep -v '^$')
    detected_libs=()
    for lib in "${!lib_patterns[@]}"; do
        pattern="${lib_patterns[$lib]}"
        if grep -qE "$pattern" <<<"$symbols"; then
            detected_libs+=("$lib")
            echo "  ✓ Detected static library: $lib"
        fi
    done
    # Update JSON file
    if [ ${#detected_libs[@]} -gt 0 ]; then
        for lib in "${detected_libs[@]}"; do
            # Add to JSON (simplified - in practice use jq)
            sed -i "s/\"static_libraries_detected\": \[/\"static_libraries_detected\": [\"$lib\", /" "$output_json"
        done
    fi
    # Add binary to analyzed list
    sed -i "s/\"binaries_analyzed\": \[/\"binaries_analyzed\": [\"$(basename $binary)\", /" "$output_json"
}
# Find and analyze all binaries
find "$BINARY_DIR" -type f -executable | while read binary; do
    if file "$binary" | grep -q ELF; then
        detect_static_libs "$binary" "$OUTPUT_FILE"
    fi
done
# Clean up JSON formatting
sed -i 's/, \]/]/' "$OUTPUT_FILE"
echo ""
echo "Static library detection complete!"
echo "Results saved to: $OUTPUT_FILE"
echo ""
echo "Summary:"
jq -r '.static_libraries_detected | unique | .[]' "$OUTPUT_FILE" | sort | while read lib; do
    echo "  - $lib"
done
