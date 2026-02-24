# GpuFitsCrypt Reproducibility Suite

This directory contains the complete toolchain required to replicate the benchmarks and analysis presented in the paper "GpuFitsCrypt: High-Throughput Granular Encryption for Astronomical Archives".

The suite is designed to be fully autonomous, handling data generation, encryption, benchmarking, and the generation of LaTeX tables and figures.

---

## Quick Start (Docker)

The easiest way to reproduce the results is using the provided Docker environment, which isolates all dependencies (CUDA, cfitsio, Python libraries).

### Prerequisites
*   Docker & Docker Compose
*   NVIDIA Container Toolkit (for GPU access inside Docker)
*   Supported GPU (NVIDIA Volta, Ampere, Hopper, or Jetson Orin)

### 1. Run the Benchmark
This command will build the container, compile the library, generate synthetic data, and run the full benchmark suite.

```bash
# Run with your user ID to avoid permission issues on output files
UID=$(id -u) GID=$(id -g) docker-compose -f reproducibility/docker/docker-compose.yml up --build
```

*For Jetson Orin devices, use `docker-compose_jetson.yml` instead.*

### 2. Generate Paper Artifacts
Once the benchmark is complete, a CSV file will be available in `results/benchmark_results.csv`. You can then generate the tables and figures:

```bash
cd reproducibility/analysis
./run_paper_artifacts.sh
```

The output files (LaTeX tables and PDF figures) will be in `reproducibility/analysis/paper_outputs/`.

---

## Directory Structure

```text
reproducibility/
├── benchmarks/           # Python scripts for data collection
│   ├── main_runner.py    # Orchestrator (Entry point)
│   ├── benchmark_suite.py# Performance measurement logic
│   ├── encrypt_all.py    # Batch encryption utility
│   └── fits_utils.py     # Synthetic FITS generator
│
├── analysis/             # Scripts to process results -> Paper Artifacts
│   ├── run_paper_artifacts.sh        # Master script
│   ├── generate_optimal_kernel...py  # Generates Table 4
│   ├── generate_gcm_vs_ctr...py      # Generates Table 5
│   └── generate_time_breakdown.py    # Generates Figure 4
│
└── docker/               # Container configuration
    ├── Dockerfile        # x86_64 (H100, A100, RTX)
    ├── Dockerfile_jetson # ARM64 (Jetson Orin)
    └── .env              # Configuration variables
```

---

## Configuration

You can customize the benchmark behavior by editing `reproducibility/docker/.env`.

| Variable | Default | Description |
| :--- | :--- | :--- |
| `BENCH_MODE` | `both` | Crypto modes to test: `gcm`, `ctr`, or `both`. |
| `BENCH_CONFIG_MODE` | `full` | Kernel parameter sweep: `full` (75 configs), `reduced`, or `test`. |
| `BENCH_VERIFY_FILES` | *(empty)* | Filter specific files (e.g., `image_sim_large`). Useful if VRAM is limited. |
| `BENCH_TIMED_RUNS` | `200` | Number of repetitions for statistical stability. |

---

## Manual Execution (Local)

If you prefer to run without Docker, ensure you have `cuda-toolkit`, `libcfitsio-dev`, and `python3` installed.

1.  **Install Python dependencies:**
    ```bash
    pip install -r requirements.txt python-dotenv
    ```

2.  **Run the orchestrator:**
    ```bash
    python3 reproducibility/benchmarks/main_runner.py
    ```

3.  **Run the analysis:**
    ```bash
    cd reproducibility/analysis
    ./run_paper_artifacts.sh
    ```
