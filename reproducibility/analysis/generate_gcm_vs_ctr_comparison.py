#!/usr/bin/env python3
"""
generate_gcm_vs_ctr_comparison.py

Generates Table 5: Performance scalability analysis comparing GCM vs CTR.
Output: gcm_vs_ctr_comparison.tex
"""
import argparse
import os
import pandas as pd
from pathlib import Path
import sys

SCRIPT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SCRIPT_ROOT))

E2E_METRIC = 'TotalOpenTime_s'
ASTROPY_METRIC = 'TimeAstropyNormalOpen_s'
FILE_SIZE_METRIC = 'OriginalFileSize_bytes'

GPU_NAME_MAP = {
    'NVIDIA A100-SXM4-80GB': 'A100',
    'NVIDIA H100 PCIe': 'H100 PCIe',
    'NVIDIA L40S': 'L40S',
    'NVIDIA GeForce RTX 3090': 'GeForce RTX 3090',
    'NVIDIA GeForce RTX 3060': 'GeForce RTX 3060',
    'NVIDIA GeForce RTX 3050 Ti Laptop GPU': 'GeForce RTX 3050 Ti',
    'Orin (nvgpu)': 'Jetson Orin'
}

GPU_ORDER_PRIORITY = ['H100 PCIe', 'A100', 'L40S', 'GeForce RTX 3090', 'GeForce RTX 3060', 'GeForce RTX 3050 Ti', 'Jetson Orin']

def format_size(size_bytes):
    if size_bytes >= 1024**3: return f"{size_bytes / (1024**3):.1f} GB"
    mb = size_bytes / (1024**2)
    return f"{round(mb / 100) * 100:.0f} MB" if mb >= 100 else f"{round(mb / 10) * 10:.0f} MB"

def find_best_times_per_gpu(df, mode_name):
    if df.empty: return pd.DataFrame()
    best_idx = df.loc[df.groupby('GPU_Name')[E2E_METRIC].idxmin()]
    result = best_idx[['GPU_Name', E2E_METRIC, ASTROPY_METRIC]].copy()
    result.rename(columns={E2E_METRIC: f'{mode_name.upper()}_Time_s'}, inplace=True)
    return result

def generate_latex_table(results_by_size, output_file):
    size_descs = [f"{k.replace('_', '-').title()} ($\\approx {format_size(d['avg_size'])}$)" for k, d in results_by_size.items()]
    caption = f"Performance scalability analysis comparing {' and '.join(size_descs)} FITS files. The table decomposes the total End-to-End (E2E) time into a baseline I/O component (\\texttt{{Astropy Time}}) and the \\texttt{{Net GCM Cost}} (calculated as E2E Time - Astropy Time). This isolation reveals that while I/O masks performance differences on smaller files, the \\texttt{{Net GCM Cost}} scales effectively on datacenter hardware for larger workloads. \\textit{{Note: Consumer-grade and edge devices with limited VRAM (RTX 3060, 3050 Ti, and Jetson Orin) are excluded from the Extra-Large benchmark as the dataset size exceeds their available memory capacity.}}"

    lines = [
        r"\begin{table*}[t]",
        r"\centering",
        rf"\caption{{{caption}}}",
        r"\label{tab:gcm_vs_ctr_comparison}",
        r"\resizebox{\textwidth}{!}{%",
        r"\begin{tabular}{l c c c c c c}",
        r"\toprule",
        r"\textbf{GPU Model} & \textbf{Astropy Time} & \textbf{E2E CTR Time} & \textbf{E2E GCM Time} & \textbf{Net CTR Cost} & \textbf{Net GCM Cost} & \textbf{GCM/CTR Net Ratio} \\"
    ]

    for size_key, data in results_by_size.items():
        df = data['df']
        lines.append(r"\midrule")
        lines.append(rf"\textit{{{size_key.replace('_', '-').title()} ($\approx {format_size(data['avg_size'])}$)}} \\")

        df['Short_Name'] = df['GPU_Name'].map(GPU_NAME_MAP).fillna(df['GPU_Name'])
        df['Short_Name'] = pd.Categorical(df['Short_Name'], categories=GPU_ORDER_PRIORITY, ordered=True)
        
        for _, row in df.sort_values('Short_Name').iterrows():
            if pd.isna(row['Short_Name']): continue
            lines.append(f"{row['Short_Name']:<18} & {row[ASTROPY_METRIC]:.3f} & {row['CTR_Time_s']:.3f} & {row['GCM_Time_s']:.3f} & {row['Net_CTR_Cost_s']:.3f} & {row['Net_GCM_Cost_s']:.3f} & {row['Net_Cost_Ratio']:.2f}x \\\\")

    lines.extend([r"\bottomrule", r"\end{tabular}%", r"}", r"\end{table*}"])

    Path(output_file).parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, 'w') as f: f.write('\n'.join(lines))
    print(f"LaTeX saved to: {output_file}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--csv', required=True)
    parser.add_argument('--output-dir', required=True)
    parser.add_argument('--filter', default='large,extra_large')
    args = parser.parse_args()

    df_full = pd.read_csv(args.csv, low_memory=False)
    df_full = df_full[df_full['LibErrorCode'] == 0].copy()
    
    results_by_size = {}
    for size_filter in [s.strip() for s in args.filter.split(',')]:
        regex = r"(?<!extra_)large" if size_filter == 'large' else size_filter
        df_filtered = df_full[df_full['OriginalFile'].str.contains(regex, case=False, regex=True)].copy()
        
        if df_filtered.empty: continue
        
        avg_size = df_filtered[FILE_SIZE_METRIC].mean()
        best_ctr = find_best_times_per_gpu(df_filtered[df_filtered['TestCaseID_Config'].str.contains('_ctr_')], 'ctr')
        best_gcm = find_best_times_per_gpu(df_filtered[df_filtered['TestCaseID_Config'].str.contains('_gcm_')], 'gcm')

        if best_ctr.empty or best_gcm.empty: continue

        comp = pd.merge(best_ctr.drop(columns=[ASTROPY_METRIC]), best_gcm, on='GPU_Name')
        comp['Net_CTR_Cost_s'] = comp['CTR_Time_s'] - comp[ASTROPY_METRIC]
        comp['Net_GCM_Cost_s'] = comp['GCM_Time_s'] - comp[ASTROPY_METRIC]
        comp['Net_Cost_Ratio'] = comp['Net_GCM_Cost_s'].divide(comp['Net_CTR_Cost_s']).replace(float('inf'), 0)

        results_by_size[size_filter] = {'df': comp, 'avg_size': avg_size}

    if results_by_size:
        generate_latex_table(results_by_size, os.path.join(args.output_dir, 'gcm_vs_ctr_comparison.tex'))

if __name__ == '__main__':
    main()
