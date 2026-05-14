#!/usr/bin/env python3
"""
generate_literature_comparison.py

Generates Table 5 (literature_comparison.tex) comparing GpuFitsCrypt
GHASH-only throughput against prior GPU AES implementations from the
literature.

Data sources:
- Our 4 GPUs: GHashKernelOnly throughputs from the comparable benchmark
  CSVs (TS256_R4, Large file, N=200 runs, median).
- Literature: hardcoded values from cited papers (see LITERATURE_DATA).

Usage:
    python3 generate_literature_comparison.py \\
        --comparable-dir <path/to/comparable/> \\
        --output-dir <path/to/manuscript/tables/>
"""
import argparse
import os
import glob
import pandas as pd
from pathlib import Path
import sys

GHASH_METRIC = 'CTime_DataDecryptGPU_GHashKernelOnly_s'
FILE_SIZE_METRIC = 'OriginalFileSize_bytes'
LARGE_FILE = 'image_sim_large_001.fits'

GPU_NAME_MAP = {
    'NVIDIA L40S': 'L40S',
    'NVIDIA H100 PCIe': 'H100 PCIe',
    'NVIDIA GeForce RTX 3090': 'RTX 3090',
    'NVIDIA A100-SXM4-80GB': 'A100-SXM4',
}

GPU_ORDER_OWN = ['L40S', 'H100 PCIe', 'RTX 3090', 'A100-SXM4']

# Hardcoded literature data (verified against MANUSCRIPT_R2B_AUDIT.md §8)
LITERATURE_DATA = [
    {
        'implementation': 'Lee et al.',
        'gpu': 'RTX 4090',
        'mode': r'GCM (GHASH, 16\,KB)',
        'throughput_gbps': 536,
        'aad': r'$\checkmark$',
        'fits_aware': r'$\times$',
        'cite': 'lee_parallel_2025',
    },
    {
        'implementation': 'Lee et al.',
        'gpu': 'RTX 3090',
        'mode': r'GCM (GHASH, 16\,KB)',
        'throughput_gbps': 247,
        'aad': r'$\checkmark$',
        'fits_aware': r'$\times$',
        'cite': 'lee_parallel_2025',
    },
    {
        'implementation': 'Lee et al.',
        'gpu': 'RTX 3080',
        'mode': 'CTR',
        'throughput_gbps': 1623,
        'aad': r'$\times$',
        'fits_aware': r'$\times$',
        'cite': 'lee_speed_2024',
    },
    {
        'implementation': 'Tezcan',
        'gpu': 'RTX 2070 Super',
        'mode': 'CTR',
        'throughput_gbps': 879,
        'aad': r'$\times$',
        'fits_aware': r'$\times$',
        'cite': 'tezcan_optimization_2021',
    },
]


def compute_own_throughputs(comparable_dir: Path) -> dict:
    """Load all comparable CSVs and compute GHashKernelOnly Large throughput per GPU."""
    csv_files = list(comparable_dir.glob('*.csv'))
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in {comparable_dir}")

    frames = []
    for f in csv_files:
        df = pd.read_csv(f, low_memory=False)
        frames.append(df)
    df_all = pd.concat(frames, ignore_index=True)

    df_ok = df_all[(df_all['LibErrorCode'] == 0) & (df_all['LibWarningCode'] != 2)].copy()
    df_gcm = df_ok[df_ok['TestCaseID_Config'].str.contains('_gcm_', na=False)].copy()
    df_large = df_gcm[df_gcm['OriginalFile'] == LARGE_FILE].copy()
    df_valid = df_large[df_large[GHASH_METRIC] > 0].copy()

    results = {}
    for gpu_csv, gpu_label in GPU_NAME_MAP.items():
        sub = df_valid[df_valid['GPU_Name'] == gpu_csv]
        if sub.empty:
            print(f'  WARNING: no data for {gpu_csv}', file=sys.stderr)
            continue
        median_s = sub[GHASH_METRIC].median()
        size_bytes = sub[FILE_SIZE_METRIC].median()
        gbps = (size_bytes * 8) / (median_s * 1e9)
        results[gpu_label] = {
            'throughput_gbps': int(round(gbps)),
            'median_ms': median_s * 1000,
            'n_runs': len(sub),
        }
        print(f'  {gpu_label}: {int(round(gbps))} Gbps '
              f'(median {median_s*1000:.3f} ms, N={len(sub)})')

    return results


def generate_latex_table(own_data: dict, literature: list, output_file: Path) -> None:
    caption = (
        r'Comparison of GpuFitsCrypt kernel-level throughput against prior GPU AES '
        r'implementations from the literature. Throughput (Gbps) is kernel-only, '
        r'excluding host-side I/O. '
        r'GpuFitsCrypt values are GHASH-only medians over $N=200$ runs on the '
        r'Large ($\approx$600\,MB) FITS dataset (TS256\_R4 configuration). '
        r'Lee et al.\ \citeyearpar{lee_parallel_2025} values are for 16\,KB pre-staged '
        r'messages; the measurement scope is equivalent (GHASH kernel only) but the '
        r'input size differs. '
        r'AAD: support for Associated Authenticated Data; '
        r'FITS-aware: direct integration with the Astropy/cfitsio ecosystem.'
    )

    lines = [
        r'\begin{table*}[t]',
        r'\centering',
        rf'\caption{{{caption}}}',
        r'\label{tab:literature_comparison}',
        r'\resizebox{\textwidth}{!}{%',
        r'\begin{tabular}{l c c r c c}',
        r'\toprule',
        (r'\textbf{Implementation} & \textbf{GPU} & \textbf{AES Mode} & '
         r'\textbf{Throughput (Gbps)} & \textbf{AAD} & \textbf{FITS-aware} \\'),
        r'\midrule',
        r'\textit{This work (GpuFitsCrypt)} \\',
    ]

    for gpu_label in GPU_ORDER_OWN:
        if gpu_label not in own_data:
            lines.append(f'% MISSING: {gpu_label}')
            continue
        tput = own_data[gpu_label]['throughput_gbps']
        lines.append(
            f'GpuFitsCrypt & {gpu_label} & GCM (GHASH only) & {tput} & '
            r'$\checkmark$ & $\checkmark$ \\'
        )

    lines += [
        r'\midrule',
        r'\textit{Prior GPU AES literature} \\',
    ]

    for entry in literature:
        gpu = entry['gpu']
        mode = entry['mode']
        tput = entry['throughput_gbps']
        aad = entry['aad']
        fits = entry['fits_aware']
        cite = entry['cite']
        # Implementation column contains the full \citet{} citation
        lines.append(
            r'\citet{' + cite + r'} & ' + f'{gpu} & {mode} & {tput} & {aad} & {fits} ' + r'\\'
        )

    lines += [
        r'\bottomrule',
        r'\end{tabular}%',
        r'}',
        r'\end{table*}',
    ]

    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text('\n'.join(lines) + '\n')
    print(f'\nWrote: {output_file}')
    print(f'Lines: {len(lines)}')


def main():
    parser = argparse.ArgumentParser(
        description='Generate literature_comparison.tex for GpuFitsCrypt manuscript.'
    )
    parser.add_argument('--comparable-dir', required=True,
                        help='Directory containing the comparable benchmark CSVs')
    parser.add_argument('--output-dir', required=True,
                        help='Output directory (manuscript tables/)')
    args = parser.parse_args()

    comparable_dir = Path(args.comparable_dir)
    output_dir = Path(args.output_dir)

    print(f'Reading comparable CSVs from: {comparable_dir}')
    own_data = compute_own_throughputs(comparable_dir)

    print(f'\nExpected: L40S=664, H100 PCIe=541, RTX 3090=472, A100-SXM4=436')

    output_file = output_dir / 'literature_comparison.tex'
    generate_latex_table(own_data, LITERATURE_DATA, output_file)


if __name__ == '__main__':
    main()
