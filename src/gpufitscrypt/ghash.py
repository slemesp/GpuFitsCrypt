"""GHASH computation for AES-GCM.

Provides two equivalent implementations:

Sequential (reference):
    Y_i = (Y_{i-1} XOR X_i) * H, starting at Y_0 = 0.
    Runtime: O(n) sequential GF multiplications.

Parallel tree reduction (novel GPU contribution):
    Rewrites GHASH as a weighted dot product:
        GHASH_H(X_1, ..., X_m) = X_1*H^m XOR X_2*H^(m-1) XOR ... XOR X_m*H^1

    This formulation decomposes into three data-parallel steps:
        1. Precompute H^1, H^2, ..., H^m  (log-depth with squarings)
        2. Compute partial products X_i * H^(m-i+1) independently per thread
        3. XOR-reduce all partial products using a binary tree

    GPU parallelism: steps 2 and 3 map directly onto CUDA thread blocks,
    transforming the O(n) sequential bottleneck into O(log n) parallel work.
    The CUDA implementation is in kernels/ghash_kernel.cu.
"""

from .gf128 import gf128_mul, gf128_pow


def ghash_sequential(h: int, blocks: list) -> int:
    """Compute GHASH sequentially (reference implementation).

    Args:
        h:      Hash subkey H = AES_K(0^128) as a 128-bit integer.
        blocks: List of 128-bit integer GHASH input blocks.

    Returns:
        GHASH_H(blocks) as a 128-bit integer.
    """
    y = 0
    for x in blocks:
        y = gf128_mul(y ^ x, h)
    return y


def ghash_parallel(h: int, blocks: list) -> int:
    """Compute GHASH using the parallel tree-reduction algorithm.

    This CPU implementation mirrors the GPU kernel structure in
    kernels/ghash_kernel.cu.  Each of the three phases maps onto
    distinct CUDA kernel launches:

      Phase 1 - Power precomputation:
          Computed on-device with a log-depth reduction so that
          H^k is available in shared memory before phase 2.

      Phase 2 - Parallel partial products (one thread per block):
          thread_i computes partial[i] = blocks[i] * H_powers[m - i]
          All m threads execute concurrently within a CUDA grid.

      Phase 3 - Parallel XOR tree reduction (warp-level primitives):
          Uses __shfl_xor_sync / shared-memory reduction to XOR the
          m partial products into a single 128-bit result in O(log m)
          synchronisation steps.

    Args:
        h:      Hash subkey H = AES_K(0^128) as a 128-bit integer.
        blocks: List of 128-bit integer GHASH input blocks (len >= 1).

    Returns:
        GHASH_H(blocks) as a 128-bit integer, identical to ghash_sequential.
    """
    m = len(blocks)
    if m == 0:
        return 0

    # Phase 1: Precompute H^1 ... H^m.
    # On GPU this is done with a parallel prefix product kernel so that
    # H_powers[k] = H^k is stored in device memory.
    h_powers = [0] * (m + 1)
    h_powers[1] = h
    for k in range(2, m + 1):
        h_powers[k] = gf128_mul(h_powers[k - 1], h)

    # Phase 2: Compute partial products (fully independent, one per thread).
    # On GPU: partial[i] = blocks[i] * H_powers[m - i] with no dependencies.
    partial = [gf128_mul(blocks[i], h_powers[m - i]) for i in range(m)]

    # Phase 3: XOR tree reduction in O(log m) synchronisation rounds.
    # On GPU: each round halves the active threads using __syncthreads().
    while len(partial) > 1:
        partial = [
            partial[i] ^ partial[i + 1] if i + 1 < len(partial) else partial[i]
            for i in range(0, len(partial), 2)
        ]

    return partial[0]
