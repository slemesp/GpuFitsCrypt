#!/bin/bash

# GpuFitsCrypt: Paper Artifacts Generator
# ---------------------------------------
# Orchestrates the generation of all tables and figures for the paper.

set -e

INPUT_CSV="${1:-./results/benchmark_results.csv}"
INPUT_ZIP="./results/benchmark_results.zip"
COMPARABLE_DIR="./results/per_gpu"
OUTPUT_DIR="paper_outputs"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR_ABS="$SCRIPT_DIR/$OUTPUT_DIR"

# Auto-decompression if needed (default paths only)
if [ ! -f "$INPUT_CSV" ] || [ ! -d "$COMPARABLE_DIR" ]; then
    if [ -f "$INPUT_ZIP" ]; then
        echo "Extracting benchmark data from $INPUT_ZIP..."
        (cd results/ && unzip -o benchmark_results.zip)
    fi
fi

INPUT_CSV_ABS="$(realpath -m "$INPUT_CSV")"

echo "========================================================"
echo "   GpuFitsCrypt Paper Artifacts Generator"
echo "========================================================"
echo "Input CSV:        $INPUT_CSV_ABS"
echo "Comparable dir:   $COMPARABLE_DIR"
echo "Output Dir:       $OUTPUT_DIR_ABS"

if [ ! -f "$INPUT_CSV_ABS" ]; then
    echo "Error: Input CSV not found. Run benchmarks first."
    exit 1
fi

mkdir -p "$OUTPUT_DIR_ABS/tables" "$OUTPUT_DIR_ABS/figures"

# --- 1. Table 3: Optimal Kernel Configs ---
echo -e "\n[1/4] Generating Table 3 (Optimal Kernel Configs)..."
python3 "$SCRIPT_DIR/generate_optimal_kernel_configs.py" \
    --csv "$INPUT_CSV_ABS" \
    --output-dir "$OUTPUT_DIR_ABS/tables" \
    --filter large \
    --mode gcm

# --- 2. Table 4: GCM vs CTR Comparison ---
echo -e "\n[2/4] Generating Table 4 (GCM vs CTR Comparison)..."
python3 "$SCRIPT_DIR/generate_gcm_vs_ctr_comparison.py" \
    --csv "$INPUT_CSV_ABS" \
    --output-dir "$OUTPUT_DIR_ABS/tables" \
    --filter large,extra_large

# --- 3. Table 5: Literature Comparison ---
echo -e "\n[3/4] Generating Table 5 (Literature Comparison)..."
python3 "$SCRIPT_DIR/generate_literature_comparison.py" \
    --comparable-dir "$COMPARABLE_DIR" \
    --output-dir "$OUTPUT_DIR_ABS/tables"

# --- 4. Figure 4: Time Breakdown ---
echo -e "\n[4/4] Generating Figure 4 (Time Breakdown)..."
python3 "$SCRIPT_DIR/generate_time_breakdown.py" \
    --csv "$INPUT_CSV_ABS" \
    --output-dir "$OUTPUT_DIR_ABS/figures" \
    --filter large

python3 "$SCRIPT_DIR/generate_time_breakdown.py" \
    --csv "$INPUT_CSV_ABS" \
    --output-dir "$OUTPUT_DIR_ABS/figures" \
    --filter large \
    --log-scale

echo -e "\n========================================================"
echo "   Artifact Generation Complete!"
echo "========================================================"
find "$OUTPUT_DIR_ABS" -type f | sed 's|^.*/||' | sort
