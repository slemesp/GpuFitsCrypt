#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
GpuFitsCrypt: Benchmark Result Analysis
---------------------------------------
This script processes the CSV results from benchmark_suite.py, performs
outlier removal, identifies optimal kernel configurations, and generates
performance visualization plots.

Usage:
    python3 reproducibility/benchmarks/analyze_results.py
"""

import os
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from matplotlib.ticker import FuncFormatter
from tabulate import tabulate

# --- Configuration ---
CSV_FILE_PATH = "benchmark_results.csv"
PLOTS_OUTPUT_DIR = "analysis_plots"
os.makedirs(PLOTS_OUTPUT_DIR, exist_ok=True)

# --- Styles ---
sns.set_theme(style="whitegrid", palette="viridis", font_scale=1.1)

def load_and_prepare_data(csv_path):
    """Loads and cleans the benchmark DataFrame."""
    if not os.path.exists(csv_path):
        print(f"Error: CSV file '{csv_path}' not found.")
        return None

    df = pd.read_csv(csv_path, low_memory=False)
    print(f"Data loaded: {len(df)} rows.")

    # Required columns based on new benchmark_suite.py
    required_cols = ["GPU", "File", "FileSize_MB", "TSBS", "RBS", "Astropy_s", "Total_s", "C_Total_s", "C_Kernel_s", "ErrorCode"]

    for col in ["FileSize_MB", "TSBS", "RBS", "Astropy_s", "Total_s", "C_Total_s", "C_Kernel_s", "ErrorCode"]:
        df[col] = pd.to_numeric(df[col], errors='coerce')

    df.dropna(subset=required_cols, inplace=True)
    df = df[df['ErrorCode'] == 0].copy()

    print(f"Valid rows after cleaning: {len(df)}.")
    return df

def clean_outliers_iqr(df):
    """Removes outliers using the IQR method per group."""
    if df.empty: return df
    
    print("--- Cleaning outliers (IQR Method) ---")
    original_rows = len(df)
    group_cols = ['GPU', 'File', 'TSBS', 'RBS']

    def remove_outliers_group(group, column_name):
        if len(group) < 4: return group
        q1 = group[column_name].quantile(0.25)
        q3 = group[column_name].quantile(0.75)
        iqr = q3 - q1
        if iqr == 0: return group
        lower = q1 - 1.5 * iqr
        upper = q3 + 1.5 * iqr
        return group[(group[column_name] >= lower) & (group[column_name] <= upper)]

    df_cleaned = df.groupby(group_cols, group_keys=False).apply(lambda x: remove_outliers_group(x, 'Total_s'))
    
    final_rows = len(df_cleaned)
    print(f"  Cleaned: {original_rows} -> {final_rows} rows ({((original_rows-final_rows)/original_rows)*100:.2f}% removed)")
    return df_cleaned

def find_optimal_configs(df):
    """Identifies the best TSBS/RBS combination for each GPU and file."""
    stats = df.groupby(['GPU', 'File', 'TSBS', 'RBS']).agg(
        median_total=('Total_s', 'median'),
        mean_total=('Total_s', 'mean'),
        std_total=('Total_s', 'std'),
        median_kernel=('C_Kernel_s', 'median'),
        mean_astropy=('Astropy_s', 'mean'),
        count=('Total_s', 'count')
    ).reset_index()

    # Find row with minimum median_total for each GPU/File
    idx_min = stats.groupby(['GPU', 'File'])['median_total'].idxmin()
    optimal = stats.loc[idx_min].reset_index(drop=True)
    
    optimal['Speedup'] = optimal['mean_astropy'] / optimal['mean_total']
    
    print("\n--- Optimal Configurations Found ---")
    print(tabulate(optimal[['GPU', 'File', 'TSBS', 'RBS', 'mean_total', 'mean_astropy', 'Speedup']], 
                   headers='keys', tablefmt='pipe', floatfmt=".4f"))
    return optimal

def plot_performance_comparison(df, optimal_configs):
    """Generates a bar plot comparing optimal performance across GPUs."""
    plt.figure(figsize=(12, 7))
    ax = sns.barplot(data=optimal_configs, x='File', y='mean_total', hue='GPU')
    ax.set_title('Optimal Decryption Performance by GPU', fontsize=16)
    ax.set_ylabel('Mean Total Time (s)')
    plt.xticks(rotation=30, ha='right')
    plt.tight_layout()
    plt.savefig(os.path.join(PLOTS_OUTPUT_DIR, "1_optimal_performance.png"), dpi=150)
    plt.close()

def plot_throughput(df, optimal_configs):
    """Generates a throughput (MB/s) plot."""
    optimal_configs['Throughput_MBs'] = (pd.to_numeric(optimal_configs['File'].str.extract('(\d+)')[0], errors='coerce').fillna(500)) / optimal_configs['mean_total']
    
    plt.figure(figsize=(12, 7))
    ax = sns.lineplot(data=optimal_configs, x='File', y='Throughput_MBs', hue='GPU', marker='o')
    ax.set_title('End-to-End Throughput (MB/s)', fontsize=16)
    ax.set_ylabel('Throughput (MB/s)')
    plt.tight_layout()
    plt.savefig(os.path.join(PLOTS_OUTPUT_DIR, "2_throughput_analysis.png"), dpi=150)
    plt.close()

if __name__ == "__main__":
    df_raw = load_and_prepare_data(CSV_FILE_PATH)
    if df_raw is not None:
        df_clean = clean_outliers_iqr(df_raw)
        opt_df = find_optimal_configs(df_clean)
        plot_performance_comparison(df_clean, opt_df)
        # plot_throughput(df_clean, opt_df)
        print(f"\nAnalysis complete. Plots saved in '{PLOTS_OUTPUT_DIR}'")
