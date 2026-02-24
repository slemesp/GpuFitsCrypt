#!/bin/bash

# GpuFitsCrypt: Paper Artifacts Generator
# ---------------------------------------
# Orchestrates the generation of all tables and figures for the paper.

set -e

INPUT_CSV="${1:-./results/benchmark_results.csv}"
OUTPUT_DIR="paper_outputs"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INPUT_CSV_ABS="$(realpath -m "$INPUT_CSV")"
OUTPUT_DIR_ABS="$SCRIPT_DIR/$OUTPUT_DIR"

echo "========================================================"
echo "   GpuFitsCrypt Paper Artifacts Generator"
echo "========================================================"
echo "Input CSV:  $INPUT_CSV_ABS"
echo "Output Dir: $OUTPUT_DIR_ABS"

if [ ! -f "$INPUT_CSV_ABS" ]; then
    echo "Error: Input CSV not found. Run benchmarks first."
    exit 1
fi

mkdir -p "$OUTPUT_DIR_ABS/tables" "$OUTPUT_DIR_ABS/figures"

# --- 1. Table 4: Optimal Kernel Configs ---
echo -e "\n[1/3] Generating Table 4 (Optimal Kernel Configs)..."
python3 "$SCRIPT_DIR/generate_optimal_kernel_configs.py" \
    --csv "$INPUT_CSV_ABS" \
    --output-dir "$OUTPUT_DIR_ABS/tables" \
    --filter large \
    --mode gcm

# --- 2. Table 5: GCM vs CTR Comparison ---
echo -e "\n[2/3] Generating Table 5 (GCM vs CTR Comparison)..."
python3 "$SCRIPT_DIR/generate_gcm_vs_ctr_comparison.py" \
    --csv "$INPUT_CSV_ABS" \
    --output-dir "$OUTPUT_DIR_ABS/tables" \
    --filter large,extra_large

# --- 3. Figure 4: Time Breakdown ---
echo -e "\n[3/3] Generating Figure 4 (Time Breakdown)..."
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
