cmake_minimum_required(VERSION 3.18)
project(GpuFitsCrypt LANGUAGES CXX CUDA)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CUDA_STANDARD 17)

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
option(BUILD_TESTS "Build C++ unit tests" OFF)

# ---------------------------------------------------------------------------
# CUDA architecture targets
# Default covers Volta (sm_70), Turing (sm_75), Ampere (sm_80/sm_86),
# Ada (sm_89), and Hopper (sm_90).
# ---------------------------------------------------------------------------
if(NOT DEFINED CMAKE_CUDA_ARCHITECTURES)
    set(CMAKE_CUDA_ARCHITECTURES 70 75 80 86 89 90)
endif()

# ---------------------------------------------------------------------------
# Compiler flags
# ---------------------------------------------------------------------------
set(CUDA_NVCC_FLAGS "${CUDA_NVCC_FLAGS} -O3 --use_fast_math")

# ---------------------------------------------------------------------------
# GHASH kernel library
# ---------------------------------------------------------------------------
add_library(ghash_kernel STATIC
    src/gpufitscrypt/kernels/ghash_kernel.cu
)
target_include_directories(ghash_kernel PUBLIC
    src/gpufitscrypt/kernels
)
set_target_properties(ghash_kernel PROPERTIES
    CUDA_SEPARABLE_COMPILATION ON
    POSITION_INDEPENDENT_CODE ON
)

# ---------------------------------------------------------------------------
# AES-GCM fused kernel library
# ---------------------------------------------------------------------------
add_library(aes_gcm_kernel STATIC
    src/gpufitscrypt/kernels/aes_gcm_kernel.cu
)
target_include_directories(aes_gcm_kernel PUBLIC
    src/gpufitscrypt/kernels
)
set_target_properties(aes_gcm_kernel PROPERTIES
    CUDA_SEPARABLE_COMPILATION ON
    POSITION_INDEPENDENT_CODE ON
)

# ---------------------------------------------------------------------------
# Installation
# ---------------------------------------------------------------------------
install(TARGETS ghash_kernel aes_gcm_kernel
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
)
