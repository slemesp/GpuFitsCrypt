# Makefile

NVCC = nvcc
GXX = g++

# --- Compilation Configuration ---
NVCC_COMMON_FLAGS_BASE = -Xcompiler -fPIC -O3 --use_fast_math -lineinfo -std=c++11
CXX_COMMON_FLAGS = -fPIC -O2 -std=c++11

DEFAULT_GENCODE_FLAGS = \
    -gencode arch=compute_80,code=sm_80 \
    -gencode arch=compute_86,code=sm_86 \
    -gencode arch=compute_80,code=compute_80
NVCC_GENCODE_FLAGS := $(if $(NVCC_GENCODE_OPTIONS),$(NVCC_GENCODE_OPTIONS),$(DEFAULT_GENCODE_FLAGS))
NVCC_LINK_ARCH_FLAG = # Normally left empty or used for gencode if the nvcc linker needs it for LTO, etc.

# --- Paths and Libraries ---
CUDA_HOME = /usr/local/cuda-12.0
CUDA_INCLUDE_DIR = $(CUDA_HOME)/include
CUDA_LIB_DIR = $(CUDA_HOME)/lib64
CFITSIO_CFLAGS = $(shell pkg-config --cflags cfitsio 2>/dev/null || cfitsio-config --cflags 2>/dev/null || echo "-I/usr/include/cfitsio")
CFITSIO_LIBS = $(shell pkg-config --libs cfitsio 2>/dev/null || cfitsio-config --libs 2>/dev/null || echo "-lcfitsio")
CUDA_RUNTIME_LIB = -L$(CUDA_LIB_DIR) -lcudart

# --- Base Target Names ---
LIB_BASE_NAME = libgpufitscrypt

# --- Source Files Definition ---
AES_LOW_LEVEL_SRC = AES.cu aes_keyschedule_lut.cu aes_encrypt_gpu.cu aes_encrypt.cu
UTILS_CPP_SRC = lib_internal_utils.cpp
GPU_HELPERS_CU_SRC = gpu_utils.cu
FITS_CRYPTO_CU_SRC = fits_crypto_operations.cu
LIB_API_CU_SRC = kernel.cu

# =======================================================
# === NEW: Add GCM source files =======================
# =======================================================
GCM_KERNELS_CU_SRC = gcm_kernels.cu
GCM_OPERATIONS_CU_SRC = gcm_operations.cu

# --- Common Includes ---
NVCC_INCLUDES = -I. $(CFITSIO_CFLAGS) -I$(CUDA_INCLUDE_DIR)
GXX_INCLUDES = -I. $(CFITSIO_CFLAGS) -I$(CUDA_INCLUDE_DIR)

# --- Common Headers for Dependencies ---
DEPS_HEADERS = libgpufitscrypt.h lib_internal_utils.h gpu_utils.h \
               fits_crypto_operations.h aes.h internal-aes.h tables.h \
               gcm_operations.h gcm_kernels.h

# --- Configurations for Multiple Libraries ---
_CONFIGS_TO_BUILD_RAW = \
	64_4   128_4   256_4   512_4   1024_4 \
	64_8   128_8   256_8   512_8   1024_8 \
	64_16  128_16  256_16  512_16  1024_16 \
	64_32  128_32  256_32  512_32  1024_32 \
	64_64  128_64  256_64  512_64  1024_64 \
	64_128 128_128 256_128 512_128 1024_128 \
	64_256 128_256 256_256 512_256 1024_256 \
	64_512 128_512 256_512 512_512 1024_512 \
	64_1024 128_1024 256_1024 512_1024 1024_1024 \
	64_2048 128_2048 256_2048 512_2048 1024_2048 \
	64_4096 128_4096 256_4096 512_4096 1024_4096 \
	64_8192 128_8192 256_8192 512_8192 1024_8192

CONFIGS_TO_BUILD = $(sort $(_CONFIGS_TO_BUILD_RAW))

# Object Directories
OBJ_PARAM_DIR_PREFIX = obj_param
COMMON_OBJ_DIR = obj_common

TARGET_LIBS = $(foreach config,$(CONFIGS_TO_BUILD),$(LIB_BASE_NAME)_$(config).so)

# --- New Target for Specific Compilation ---
CONFIG_TARGETS := $(CONFIGS_TO_BUILD)

.PHONY: $(CONFIG_TARGETS)
$(CONFIG_TARGETS):
	@echo "==> Starting specific compilation for configuration: $@"
	@$(MAKE) all_1 CONFIG=$@

.PHONY: all_1 all all_libs clean clean_objects clean_libs print_vars clean_all_but_sources

# --- Main Targets ---
FIRST_CONFIG := $(if $(CONFIG),$(CONFIG),$(firstword $(CONFIGS_TO_BUILD)))
FIRST_CONFIG_LIB_SO_NAME = $(LIB_BASE_NAME)_$(FIRST_CONFIG).so

# MODIFIED LINE: Only depend on libraries
all_1: $(FIRST_CONFIG_LIB_SO_NAME)

all: all_libs

all_libs: $(TARGET_LIBS)

# --- Helper Functions for Object Paths ---
parametrized_obj_path = $(OBJ_PARAM_DIR_PREFIX)_$(2)_$(3)/$(notdir $(basename $(1))).o
common_obj_path = $(COMMON_OBJ_DIR)/$(notdir $(basename $(1))).o

# --- Macro for Parametrized .cu Object Compilation Rule ---
define COMPILE_CU_PARAMETRIZED_RULE
$(3): $(4) $(5)
	@mkdir -p $(dir $(3))
	@echo "Compiling (NVCC Config $(1)/$(2)): $(4) -> $(3)"
	$(NVCC) $(NVCC_GENCODE_FLAGS) $(NVCC_COMMON_FLAGS_BASE) \
		-DthreadSizeBS=$(1) -DREPEATBS=$(2) \
		$(NVCC_INCLUDES) -c -o $(3) $(4)
endef

# --- Generation of Compilation Rules for Parametrized .cu Objects ---
ALL_PARAM_CU_SRCS = $(AES_LOW_LEVEL_SRC) $(GPU_HELPERS_CU_SRC) $(FITS_CRYPTO_CU_SRC) $(LIB_API_CU_SRC) \
$(GCM_KERNELS_CU_SRC) $(GCM_OPERATIONS_CU_SRC)


$(foreach config,$(CONFIGS_TO_BUILD),\
    $(eval current_tsbs := $(word 1,$(subst _, ,$(config))))\
    $(eval current_rbs := $(word 2,$(subst _, ,$(config))))\
    $(foreach src,$(ALL_PARAM_CU_SRCS),\
        $(eval obj_target_name_for_rule := $(call parametrized_obj_path,$(src),$(current_tsbs),$(current_rbs)))\
        $(eval $(call COMPILE_CU_PARAMETRIZED_RULE,$(current_tsbs),$(current_rbs),$(obj_target_name_for_rule),$(src),$(DEPS_HEADERS)))\
    )\
)

# --- Non-Parametrized C++ Objects (compiled once in COMMON_OBJ_DIR) ---
UTILS_COMMON_OBJ_FILE = $(call common_obj_path,$(UTILS_CPP_SRC))

$(UTILS_COMMON_OBJ_FILE): $(UTILS_CPP_SRC) lib_internal_utils.h
	@mkdir -p $(dir $@)
	@echo "Compiling (GXX Common): $< -> $@"
	$(GXX) $(CXX_COMMON_FLAGS) $(GXX_INCLUDES) -c -o $@ $<

# --- Definition of Variables with Object Lists for Library Linking ---
define DEFINE_LIB_OBJS_VAR_FOR_CONFIG
OBJS_FOR_LIB_$(1)_$(2) := \
    $(call parametrized_obj_path,$(LIB_API_CU_SRC),$(1),$(2)) \
    $(call parametrized_obj_path,$(FITS_CRYPTO_CU_SRC),$(1),$(2)) \
    $(call parametrized_obj_path,$(GPU_HELPERS_CU_SRC),$(1),$(2)) \
    $(call parametrized_obj_path,$(GCM_KERNELS_CU_SRC),$(1),$(2)) \
    $(call parametrized_obj_path,$(GCM_OPERATIONS_CU_SRC),$(1),$(2)) \
    $(UTILS_COMMON_OBJ_FILE) \
    $(foreach src,$(AES_LOW_LEVEL_SRC),$(call parametrized_obj_path,$(src),$(1),$(2)))
endef

$(foreach config,$(CONFIGS_TO_BUILD),\
    $(eval $(call DEFINE_LIB_OBJS_VAR_FOR_CONFIG,$(word 1,$(subst _, ,$(config))),$(word 2,$(subst _, ,$(config)))))\
)

# --- LINKING RULE FOR PARAMETRIZED LIBRARIES (Using define and tabs) ---
define GENERATE_LIB_LINK_RULE
$(2)_$(1).so: $$(OBJS_FOR_LIB_$(1))
	@echo "Linking Parametrized Library: $$@ (Config $(1))"
	$(NVCC) $(NVCC_LINK_ARCH_FLAG) --shared -o $$@ $$(filter %.o,$$^) $(CFITSIO_LIBS) $(CUDA_RUNTIME_LIB)
endef

# Instantiate linking rules for each library
$(foreach config,$(CONFIGS_TO_BUILD),\
    $(eval $(call GENERATE_LIB_LINK_RULE,$(config),$(LIB_BASE_NAME)))\
)

# --- Cleanup Target ---
clean: clean_objects clean_libs
	@echo "Cleaning executables and various files..."

clean_objects:
	@echo "Cleaning object directories..."
	rm -rf $(OBJ_PARAM_DIR_PREFIX)_*
	rm -rf $(COMMON_OBJ_DIR)

clean_libs:
	@echo "Cleaning generated libraries..."
	rm -f $(LIB_BASE_NAME)_*.so

clean_all_but_sources: clean
	@echo "Complete cleanup performed."

print_vars:
	@echo "--- Makefile Variables ---"
	@echo "CONFIGS_TO_BUILD: [$(CONFIGS_TO_BUILD)]"
	$(foreach config,$(CONFIGS_TO_BUILD),\
		$(info Objects for lib_$(config).so are: [$(OBJS_FOR_LIB_$(config))])\
	)
	@echo "---------------------------"
