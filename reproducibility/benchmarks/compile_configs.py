# GpuFitsCrypt: Kernel Compilation Configurations

COMPILE_CONFIGS_TEST = [
    {"TSBS": 64, "RBS": 4, "DESC": "TS64_R4"}
]

COMPILE_CONFIGS_REDUCED = [
    # TS = 64
    {"TSBS": 64, "RBS": 4, "DESC": "TS64_R4"}, {"TSBS": 64, "RBS": 8, "DESC": "TS64_R8"},
    {"TSBS": 64, "RBS": 16, "DESC": "TS64_R16"}, {"TSBS": 64, "RBS": 32, "DESC": "TS64_R32"},
    {"TSBS": 64, "RBS": 64, "DESC": "TS64_R64"}, {"TSBS": 64, "RBS": 128, "DESC": "TS64_R128"},
    {"TSBS": 64, "RBS": 256, "DESC": "TS64_R256"}, {"TSBS": 64, "RBS": 512, "DESC": "TS64_R512"},
    {"TSBS": 64, "RBS": 1024, "DESC": "TS64_R1024"}, {"TSBS": 64, "RBS": 2048, "DESC": "TS64_R2048"},
    {"TSBS": 64, "RBS": 4096, "DESC": "TS64_R4096"}, {"TSBS": 64, "RBS": 8192, "DESC": "TS64_R8192"},
    # TS = 128
    {"TSBS": 128, "RBS": 4, "DESC": "TS128_R4"}, {"TSBS": 128, "RBS": 8, "DESC": "TS128_R8"},
    {"TSBS": 128, "RBS": 16, "DESC": "TS128_R16"}, {"TSBS": 128, "RBS": 32, "DESC": "TS128_R32"},
    {"TSBS": 128, "RBS": 64, "DESC": "TS128_R64"}, {"TSBS": 128, "RBS": 128, "DESC": "TS128_R128"},
    {"TSBS": 128, "RBS": 256, "DESC": "TS128_R256"}, {"TSBS": 128, "RBS": 512, "DESC": "TS128_R512"},
    {"TSBS": 128, "RBS": 1024, "DESC": "TS128_R1024"}, {"TSBS": 128, "RBS": 2048, "DESC": "TS128_R2048"},
    {"TSBS": 128, "RBS": 4096, "DESC": "TS128_R4096"}, {"TSBS": 128, "RBS": 8192, "DESC": "TS128_R8192"},
    # TS = 256
    {"TSBS": 256, "RBS": 4, "DESC": "TS256_R4"}, {"TSBS": 256, "RBS": 8, "DESC": "TS256_R8"},
    {"TSBS": 256, "RBS": 16, "DESC": "TS256_R16"}, {"TSBS": 256, "RBS": 32, "DESC": "TS256_R32"},
    {"TSBS": 256, "RBS": 64, "DESC": "TS256_R64"}, {"TSBS": 256, "RBS": 128, "DESC": "TS256_R128"},
    {"TSBS": 256, "RBS": 256, "DESC": "TS256_R256"}, {"TSBS": 256, "RBS": 512, "DESC": "TS256_R512"},
    {"TSBS": 256, "RBS": 1024, "DESC": "TS256_R1024"}, {"TSBS": 256, "RBS": 2048, "DESC": "TS256_R2048"},
    {"TSBS": 256, "RBS": 4096, "DESC": "TS256_R4096"}, {"TSBS": 256, "RBS": 8192, "DESC": "TS256_R8192"},
]

COMPILE_CONFIGS_FULL = [
    # RBS = 4
    {"TSBS": 64, "RBS": 4, "DESC": "TS64_R4"}, {"TSBS": 128, "RBS": 4, "DESC": "TS128_R4"},
    {"TSBS": 256, "RBS": 4, "DESC": "TS256_R4"}, {"TSBS": 512, "RBS": 4, "DESC": "TS512_R4"},
    {"TSBS": 1024, "RBS": 4, "DESC": "TS1024_R4"},
    # RBS = 8
    {"TSBS": 64, "RBS": 8, "DESC": "TS64_R8"}, {"TSBS": 128, "RBS": 8, "DESC": "TS128_R8"},
    {"TSBS": 256, "RBS": 8, "DESC": "TS256_R8"}, {"TSBS": 512, "RBS": 8, "DESC": "TS512_R8"},
    {"TSBS": 1024, "RBS": 8, "DESC": "TS1024_R8"},
    # RBS = 16
    {"TSBS": 64, "RBS": 16, "DESC": "TS64_R16"}, {"TSBS": 128, "RBS": 16, "DESC": "TS128_R16"},
    {"TSBS": 256, "RBS": 16, "DESC": "TS256_R16"}, {"TSBS": 512, "RBS": 16, "DESC": "TS512_R16"},
    {"TSBS": 1024, "RBS": 16, "DESC": "TS1024_R16"},
    # RBS = 32
    {"TSBS": 64, "RBS": 32, "DESC": "TS64_R32"}, {"TSBS": 128, "RBS": 32, "DESC": "TS128_R32"},
    {"TSBS": 256, "RBS": 32, "DESC": "TS256_R32"}, {"TSBS": 512, "RBS": 32, "DESC": "TS512_R32"},
    {"TSBS": 1024, "RBS": 32, "DESC": "TS1024_R32"},
    # RBS = 64
    {"TSBS": 64, "RBS": 64, "DESC": "TS64_R64"}, {"TSBS": 128, "RBS": 64, "DESC": "TS128_R64"},
    {"TSBS": 256, "RBS": 64, "DESC": "TS256_R64"}, {"TSBS": 512, "RBS": 64, "DESC": "TS512_R64"},
    {"TSBS": 1024, "RBS": 64, "DESC": "TS1024_R64"},
    # RBS = 128
    {"TSBS": 64, "RBS": 128, "DESC": "TS64_R128"}, {"TSBS": 128, "RBS": 128, "DESC": "TS128_R128"},
    {"TSBS": 256, "RBS": 128, "DESC": "TS256_R128"}, {"TSBS": 512, "RBS": 128, "DESC": "TS512_R128"},
    {"TSBS": 1024, "RBS": 128, "DESC": "TS1024_R128"},
    # RBS = 256
    {"TSBS": 64, "RBS": 256, "DESC": "TS64_R256"}, {"TSBS": 128, "RBS": 256, "DESC": "TS128_R256"},
    {"TSBS": 256, "RBS": 256, "DESC": "TS256_R256"}, {"TSBS": 512, "RBS": 256, "DESC": "TS512_R256"},
    {"TSBS": 1024, "RBS": 256, "DESC": "TS1024_R256"},
    # RBS = 512
    {"TSBS": 64, "RBS": 512, "DESC": "TS64_R512"}, {"TSBS": 128, "RBS": 512, "DESC": "TS128_R512"},
    {"TSBS": 256, "RBS": 512, "DESC": "TS256_R512"}, {"TSBS": 512, "RBS": 512, "DESC": "TS512_R512"},
    {"TSBS": 1024, "RBS": 512, "DESC": "TS1024_R512"},
    # RBS = 1024
    {"TSBS": 64, "RBS": 1024, "DESC": "TS64_R1024"}, {"TSBS": 128, "RBS": 1024, "DESC": "TS128_R1024"},
    {"TSBS": 256, "RBS": 1024, "DESC": "TS256_R1024"}, {"TSBS": 512, "RBS": 1024, "DESC": "TS512_R1024"},
    {"TSBS": 1024, "RBS": 1024, "DESC": "TS1024_R1024"},
    # RBS = 2048
    {"TSBS": 64, "RBS": 2048, "DESC": "TS64_R2048"}, {"TSBS": 128, "RBS": 2048, "DESC": "TS128_R2048"},
    {"TSBS": 256, "RBS": 2048, "DESC": "TS256_R2048"}, {"TSBS": 512, "RBS": 2048, "DESC": "TS512_R2048"},
    {"TSBS": 1024, "RBS": 2048, "DESC": "TS1024_R2048"},
    # RBS = 4096
    {"TSBS": 64, "RBS": 4096, "DESC": "TS64_R4096"}, {"TSBS": 128, "RBS": 4096, "DESC": "TS128_R4096"},
    {"TSBS": 256, "RBS": 4096, "DESC": "TS256_R4096"}, {"TSBS": 512, "RBS": 4096, "DESC": "TS512_R4096"},
    {"TSBS": 1024, "RBS": 4096, "DESC": "TS1024_R4096"},
    # RBS = 8192
    {"TSBS": 64, "RBS": 8192, "DESC": "TS64_R8192"}, {"TSBS": 128, "RBS": 8192, "DESC": "TS128_R8192"},
    {"TSBS": 256, "RBS": 8192, "DESC": "TS256_R8192"}, {"TSBS": 512, "RBS": 8192, "DESC": "TS512_R8192"},
    {"TSBS": 1024, "RBS": 8192, "DESC": "TS1024_R8192"},
]
