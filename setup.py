"""Setup configuration for GpuFitsCrypt."""

from setuptools import find_packages, setup

setup(
    name="gpufitscrypt",
    version="0.1.0",
    description=(
        "GPU-accelerated AES-GCM authenticated encryption with parallel "
        "GHASH tree reduction for large-scale astronomical FITS catalogs"
    ),
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="GpuFitsCrypt Contributors",
    license="MIT",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    python_requires=">=3.9",
    install_requires=[
        "cryptography>=41.0",
        "astropy>=5.0",
        "numpy>=1.24",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0",
        ],
        "gpu": [
            "pycuda>=2022.1",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Science/Research",
        "Topic :: Scientific/Engineering :: Astronomy",
        "Topic :: Security :: Cryptography",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
)
