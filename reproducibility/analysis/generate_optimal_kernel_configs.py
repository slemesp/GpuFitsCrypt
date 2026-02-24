#!/usr/bin/env python3
"""
generate_optimal_kernel_configs.py

Generates the Optimal Kernel Configurations table (Table 4 in the paper) from benchmark CSV results.
Output: optimal_kernel_configs.tex
"""
import argparse
import os
import pandas as pd
import numpy as np
from pathlib import Path
import sys

# Setup path to project root
SCRIPT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SCRIPT_ROOT))

# Defaults
DEFAULT_LARGE_REGEX = r"(?<!extra_)large"
TS_R_LIMIT_DEFAULT = 262144
KERNEL_BASE_TIME = 'CTime_DataDecryptGPU_KernelOnly_s'

# GPU Categories for Table Grouping
GPU_CONFIG = {
    'NVIDIA H100 PCIe': {'category': 'Datacenter / HPC', 'order': 1, 'name': 'H100 PCIe'},
    'NVIDIA A100-SXM4-80GB': {'category': 'Datacenter / HPC', 'order': 2, 'name': 'A100'},
    'NVIDIA L40S': {'category': 'Datacenter / HPC', 'order': 3, 'name': 'L40S'},
    'NVIDIA GeForce RTX 3090': {'category': 'Consumer / Workstation', 'order': 4, 'name': 'GeForce RTX 3090'},
    'NVIDIA GeForce RTX 3060': {'category': 'Consumer / Workstation', 'order': 5, 'name': 'GeForce RTX 3060'},
    'NVIDIA GeForce RTX 3050 Ti Laptop GPU': {'category': 'Consumer / Workstation', 'order': 6, 'name': 'GeForce RTX 3050 Ti'},
    'Orin (nvgpu)': {'category': 'Edge', 'order': 7, 'name': 'Jetson Orin'}
}

CATEGORY_ORDER = ['Datacenter / HPC', 'Consumer / Workstation', 'Edge']

def process_benchmark_data(df):
    required_cols = [
        "GPU_Name", "OriginalFile", "OriginalFileSize_bytes", "TestCaseID_Config",
        "ThreadSizeBS", "RepeatBS", "TotalOpenTime_s", KERNEL_BASE_TIME, "LibErrorCode"
    ]

    missing = [c for c in required_cols if c not in df.columns]
    if missing:
        raise ValueError(f"CSV missing required columns: {missing}")

    for col in ["TotalOpenTime_s", KERNEL_BASE_TIME, "ThreadSizeBS", "RepeatBS", "OriginalFileSize_bytes"]:
        df[col] = pd.to_numeric(df[col], errors='coerce')

    df = df[df['LibErrorCode'] == 0].copy()
    df.dropna(subset=required_cols, inplace=True)

    # Outlier removal (IQR)
    group_keys = ['GPU_Name', 'OriginalFile', 'ThreadSizeBS', 'RepeatBS']

    def remove_outliers(group):
        if len(group) < 4: return group
        for col in ['TotalOpenTime_s', KERNEL_BASE_TIME]:
            q1 = group[col].quantile(0.25)
            q3 = group[col].quantile(0.75)
            iqr = q3 - q1
            if iqr > 0:
                lower = q1 - 1.5 * iqr
                upper = q3 + 1.5 * iqr
                group = group[(group[col] >= lower) & (group[col] <= upper)]
        return group

    df_cleaned = df.groupby(group_keys, as_index=False, group_keys=False).apply(remove_outliers).reset_index(drop=True)

    stats = df_cleaned.groupby(group_keys).agg(
        Kernel_Time_Mean=(KERNEL_BASE_TIME, 'mean'),
        Kernel_Time_Std=(KERNEL_BASE_TIME, 'std'),
        E2E_Time_Mean=('TotalOpenTime_s', 'mean'),
        E2E_Time_Std=('TotalOpenTime_s', 'std'),
        Valid_Runs=('TotalOpenTime_s', 'count'),
        TestCaseID_Config=('TestCaseID_Config', 'first'),
        OriginalFileSize_bytes=('OriginalFileSize_bytes', 'first')
    ).reset_index()

    return stats

def find_optimal_kernel_config(df_large, ts_r_limit=TS_R_LIMIT_DEFAULT):
    if df_large is None or df_large.empty: return pd.DataFrame()

    df = df_large.copy()
    df['TS_x_R'] = (df['ThreadSizeBS'] * df['RepeatBS']).astype(int)
    df = df[df['TS_x_R'] <= int(ts_r_limit)].copy()

    optimal_configs = []
    for gpu_name, group in df.groupby('GPU_Name'):
        best_row = group.sort_values('Kernel_Time_Mean').iloc[0]
        optimal_configs.append({
            'GPU_Name': gpu_name,
            'ThreadSizeBS': int(best_row['ThreadSizeBS']),
            'RepeatBS': int(best_row['RepeatBS']),
            'Kernel_Time_Mean': float(best_row['Kernel_Time_Mean']),
            'Kernel_Time_Std': float(best_row['Kernel_Time_Std']) if not pd.isna(best_row['Kernel_Time_Std']) else 0.0,
        })

    res = pd.DataFrame(optimal_configs)
    if not res.empty:
        res['Category'] = res['GPU_Name'].map(lambda x: GPU_CONFIG.get(x, {}).get('category', 'Other'))
        res['Order'] = res['GPU_Name'].map(lambda x: GPU_CONFIG.get(x, {}).get('order', 99))
        res['Display_Name'] = res['GPU_Name'].map(lambda x: GPU_CONFIG.get(x, {}).get('name', x))
        res = res.sort_values('Order').reset_index(drop=True)
    return res

def generate_latex_table(df, output_file):
    lines = [
        r"\begin{table}[t]",
        r"\centering",
        r"\caption{Kernel-optimal parameters (\texttt{TS}: Thread Size, \texttt{R}: Repeat Blocks) and execution time for AES-GCM on the large FITS dataset ($\approx 600$~MB). Note that for this workload size, the execution time on Datacenter GPUs (H100, A100) is dominated by kernel launch latency rather than computational throughput, resulting in times comparable to consumer cards.}",
        r"\label{tab:optimal_kernel_configs}",
        r"\resizebox{\columnwidth}{!}{%",
        r"\begin{tabular}{l c c c}",
        r"\toprule",
        r"\textbf{GPU Model} & \textbf{Opt. TS} & \textbf{Opt. R} & \textbf{Kernel Time (s)} \\",
    ]

    df_grouped = df.groupby('Category')
    for category in CATEGORY_ORDER:
        if category not in df_grouped.groups: continue
        group = df_grouped.get_group(category).sort_values('Order')
        
        lines.append(r"\midrule")
        lines.append(rf"\textit{{{category}}} \\")
        
        for _, row in group.iterrows():
            lines.append(f"{row['Display_Name']} & {int(row['ThreadSizeBS'])} & {int(row['RepeatBS'])} & {row['Kernel_Time_Mean']:.3f} $\\pm$ {row['Kernel_Time_Std']:.3f} \\\\")

    lines.extend([r"\bottomrule", r"\end{tabular}%", r"}", r"\end{table}"])

    Path(output_file).parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, 'w') as f: f.write('\n'.join(lines))
    print(f"LaTeX saved to: {output_file}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--csv', required=True)
    parser.add_argument('--output-dir', required=True)
    parser.add_argument('--filter', default='large')
    parser.add_argument('--mode', default='gcm')
    args = parser.parse_args()

    df = pd.read_csv(args.csv, low_memory=False)
    
    # Filter by mode
    df = df[df['TestCaseID_Config'].str.contains(f'_{args.mode}_', case=False, na=False)].copy()
    
    stats = process_benchmark_data(df)
    
    # Filter by size
    regex = r"(?<!extra_)large" if args.filter == 'large' else args.filter
    df_large = stats[stats['OriginalFile'].str.contains(regex, case=False, regex=True)].copy()

    optimal = find_optimal_kernel_config(df_large)
    if optimal.empty:
        print("No optimal configs found.")
        return

    generate_latex_table(optimal, os.path.join(args.output_dir, 'optimal_kernel_configs.tex'))

if __name__ == '__main__':
    main()
