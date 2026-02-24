#!/usr/bin/env python3
"""
generate_time_breakdown.py

Generates Figure 4: Execution Time Breakdown for AES-GCM.
Output: time_breakdown_gcm_{filter}[_log].pdf/png
"""
import argparse
import os
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from pathlib import Path
import sys

SCRIPT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SCRIPT_ROOT))

E2E_METRIC = 'TotalOpenTime_s'
KERNEL_METRIC = 'CTime_DataDecryptGPU_KernelOnly_s'
DEFAULT_LARGE_REGEX = r"(?<!extra_)large"

GPU_NAME_MAP = {
    'NVIDIA A100-SXM4-80GB': 'NVIDIA A100',
    'NVIDIA H100 PCIe': 'NVIDIA H100',
    'NVIDIA L40S': 'NVIDIA L40S',
    'NVIDIA GeForce RTX 3090': 'RTX 3090',
    'NVIDIA GeForce RTX 3060': 'RTX 3060',
    'NVIDIA GeForce RTX 3050 Ti Laptop GPU': 'RTX 3050 Ti',
    'Orin (nvgpu)': 'Jetson Orin'
}

GPU_ORDER_PRIORITY = ['NVIDIA H100', 'NVIDIA A100', 'NVIDIA L40S', 'RTX 3090', 'RTX 3060', 'RTX 3050 Ti', 'Jetson Orin']

def process_data(csv_path, filter_regex):
    df = pd.read_csv(csv_path, low_memory=False)
    for col in [E2E_METRIC, KERNEL_METRIC]: df[col] = pd.to_numeric(df[col], errors='coerce')
    
    df = df[(df['LibErrorCode'] == 0) & df['TestCaseID_Config'].str.contains('_gcm_', case=False)].copy()
    df.dropna(subset=[E2E_METRIC, KERNEL_METRIC], inplace=True)
    
    df = df[df['OriginalFile'].str.contains(filter_regex, case=False, regex=True)].copy()
    if df.empty: return pd.DataFrame()

    return df.loc[df.groupby('GPU_Name')[E2E_METRIC].idxmin()].copy()

def generate_plot(df, output_path, log_scale=False):
    df['Short_Name'] = df['GPU_Name'].map(GPU_NAME_MAP).fillna(df['GPU_Name'])
    df['Short_Name'] = pd.Categorical(df['Short_Name'], categories=GPU_ORDER_PRIORITY, ordered=True)
    df = df.sort_values('Short_Name')

    gpu_names = df['Short_Name'].tolist()
    total_times = df[E2E_METRIC].values
    kernel_times = df[KERNEL_METRIC].values
    io_times = np.maximum(0, total_times - kernel_times)

    plt.rcParams.update({
        "font.family": "serif",
        "font.serif": ["DejaVu Serif", "Bitstream Vera Serif", "Computer Modern Roman", "Times New Roman", "serif"],
        "figure.autolayout": True
    })
    
    fig, ax = plt.subplots(figsize=(5, 4))
    FONT_SIZE = 10
    
    indices = np.arange(len(df))
    ax.bar(indices, kernel_times, 0.6, label='GPU Kernel (GHASH + AES)', color='#1f77b4', edgecolor='black', linewidth=0.8)
    ax.bar(indices, io_times, 0.6, bottom=kernel_times, label='Disk I/O & Transfers', color='#d62728', edgecolor='black', hatch='//', alpha=0.9)

    if log_scale:
        ax.set_yscale('log')
        ax.set_ylabel('Execution Time [s] (Log Scale)', fontsize=FONT_SIZE, fontweight='bold')
        min_k = min([k for k in kernel_times if k > 0]) if any(kernel_times > 0) else 0.001
        ax.set_ylim(bottom=min_k * 0.5, top=max(total_times) * 3)
    else:
        ax.set_ylabel('Execution Time [s]', fontsize=FONT_SIZE, fontweight='bold')
        ax.set_ylim(0, max(total_times) * 1.15)

    ax.set_xticks(indices)
    ax.set_xticklabels(gpu_names, rotation=25, ha='right', fontsize=FONT_SIZE-1)
    ax.legend(loc='upper left', fontsize=FONT_SIZE-2, frameon=True)
    ax.yaxis.grid(True, linestyle='--', alpha=0.5, which='both' if log_scale else 'major')
    ax.set_axisbelow(True)

    for i, (total, k_time, io_time) in enumerate(zip(total_times, kernel_times, io_times)):
        # Total time label
        offset = 1.1 if log_scale else 0.02
        pos_y = total * offset if log_scale else total + offset
        ax.text(i, pos_y, f"{total:.2f}s", ha='center', va='bottom', fontsize=FONT_SIZE-2, fontweight='bold')

        # Kernel Percentage Label
        if k_time > 0:
            if log_scale:
                y_bottom = ax.get_ylim()[0]
                y_bottom = min(y_bottom, k_time)
                label_y_k = np.sqrt(y_bottom * k_time)
                # Relaxed threshold for log scale
                if (k_time / y_bottom) > 1.1: 
                    ax.text(i, label_y_k, f"{(k_time/total)*100:.0f}%", ha='center', va='center', color='white', fontweight='bold', fontsize=FONT_SIZE-2)
            else:
                label_y_k = k_time / 2
                # Relaxed threshold: show if bar is > 2% of max height
                if k_time > max(total_times) * 0.02:
                    ax.text(i, label_y_k, f"{(k_time/total)*100:.0f}%", ha='center', va='center', color='white', fontweight='bold', fontsize=FONT_SIZE-2)

        # I/O Percentage Label
        if io_time > 0:
            if log_scale:
                bar_bottom = max(k_time, ax.get_ylim()[0])
                label_y_io = np.sqrt(bar_bottom * total)
                if (total / bar_bottom) > 1.1:
                    ax.text(i, label_y_io, f"{(io_time/total)*100:.0f}%", ha='center', va='center', color='white', fontweight='bold', fontsize=FONT_SIZE-2)
            else:
                label_y_io = k_time + (io_time / 2)
                if io_time > max(total_times) * 0.02:
                    ax.text(i, label_y_io, f"{(io_time/total)*100:.0f}%", ha='center', va='center', color='white', fontweight='bold', fontsize=FONT_SIZE-2)

    suffix = '_log' if log_scale else ''
    plt.savefig(output_path.with_name(f"{output_path.stem}{suffix}.pdf"), format='pdf', bbox_inches='tight')
    plt.savefig(output_path.with_name(f"{output_path.stem}{suffix}.png"), dpi=300, bbox_inches='tight')
    print(f"Plot saved: {output_path.stem}{suffix}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--csv', required=True)
    parser.add_argument('--output-dir', required=True)
    parser.add_argument('--filter', default='large')
    parser.add_argument('--log-scale', action='store_true')
    args = parser.parse_args()

    regex = r"(?<!extra_)large" if args.filter == 'large' else args.filter
    df = process_data(args.csv, regex)
    
    if not df.empty:
        generate_plot(df, Path(args.output_dir) / f"time_breakdown_gcm_{args.filter}", args.log_scale)

if __name__ == '__main__':
    main()
