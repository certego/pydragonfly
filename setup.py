"""
# PyDragonfly
Robust Python SDK and CLI for interacting with Dragonfly's API.
## Docs & Example Usage: https://github.com/certego/pydragonfly
"""

import pathlib
from setuptools import setup, find_packages
from pydragonfly.version import VERSION

# constants
GITHUB_URL = "https://github.com/certego/pydragonfly"

# The directory containing this file
HERE = pathlib.Path(__file__).parent
# The text of the README file
README = (HERE / "README.md").read_text()
# Get requirements from files
requirements = (HERE / "requirements.txt").read_text().split("\n")
requirements_test = (HERE / "requirements.dev.txt").read_text().split("\n")

# This call to setup() does all the work
setup(
    name="pydragonfly",
    version=VERSION,
    description="Robust Python SDK and CLI for Dragonfly's API",
    long_description=README,
    long_description_content_type="text/markdown",
    url=GITHUB_URL,
    author="Matteo Lodi",
    classifiers=[
        "Development Status :: 3 - Alpha",
        # Indicate who your project is intended for
        "Intended Audience :: Developers",
        # Pick your license as you wish (should match "license" above)
        "License :: OSI Approved :: BSD License",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    packages=find_packages(),
    python_requires=">=3.6",
    include_package_data=True,
    install_requires=requirements,
    project_urls={
        "Documentation": GITHUB_URL,
        "Source": GITHUB_URL,
        "Tracker": f"{GITHUB_URL}/issues",
    },
    keywords="certego dragonfly sdk python command line osint threat intel malware",
    # List additional groups of dependencies here (e.g. development
    # dependencies). You can install these using the following syntax,
    # for example:
    # $ pip install -e .[dev,test]
    extras_require={
        "dev": requirements_test + requirements,
        "test": requirements_test + requirements,
    },
    # pip install --editable .
    entry_points="""
        [console_scripts]
        pyintelowl=pyintelowl.main:cli
    """,
)
