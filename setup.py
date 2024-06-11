from setuptools import find_packages, setup

VERSION = "0.6.0"
REQUIRED = [
    "click~=8.0",
    "click-default-group~=1.2",
    "requests~=2.32",
    "rich~=11.0",
]

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="gdetect",
    version=VERSION,
    author="GLIMPS dev core team",
    author_email="contact@glimps.re",
    description="Library and CLI for GLIMPS Detect API",
    license="MIT",
    long_description=long_description,
    long_description_content_type="text/markdown",
    package_dir={"": "src"},
    packages=find_packages(where="src", exclude=["tests"]),
    install_requires=REQUIRED,
    entry_points={
        "console_scripts": [
            "gdetect = gdetect.cli:gdetect",
        ],
    },
    keywords=["python", "glimps", "detection", "gmalware", "malware", "gdetect"],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Programming Language :: Python :: 3",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX :: Linux",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.8",
)
