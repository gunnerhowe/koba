"""
VACP - Verifiable Agent Action Control Plane

Setup script for installation.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README
readme_path = Path(__file__).parent / "README.md"
long_description = ""
if readme_path.exists():
    long_description = readme_path.read_text(encoding="utf-8")

setup(
    name="vacp",
    version="0.1.0",
    author="Koba Contributors",
    author_email="koba-dev@proton.me",
    description="Koba - Cryptographic AI Governance Platform",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/gunnerhowe/koba",
    packages=find_packages(exclude=["tests*", "examples*"]),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.9",
    install_requires=[
        # Core dependencies (minimal)
        # cryptography is optional but recommended
    ],
    extras_require={
        "crypto": [
            "cryptography>=41.0.0",
        ],
        "server": [
            "fastapi>=0.104.0",
            "uvicorn>=0.24.0",
        ],
        "dev": [
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.0",
            "black>=23.0.0",
            "mypy>=1.6.0",
            "ruff>=0.1.0",
        ],
        "all": [
            "cryptography>=41.0.0",
            "fastapi>=0.104.0",
            "uvicorn>=0.24.0",
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "vacp-server=vacp.api.server:run_server",
            "vacp-test=vacp.tests.test_core:run_tests",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
