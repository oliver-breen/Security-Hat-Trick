from setuptools import setup, find_packages

setup(
    name="security-hat-trick",
    version="1.0.0",
    description="A security auditor with testing abilities and vulnerable app",
    author="Security Hat Trick Team",
    packages=find_packages(),
    install_requires=[
        "flask>=2.3.0",
        "requests>=2.31.0",
        "pytest>=7.4.0",
        "pytest-cov>=4.1.0",
        "beautifulsoup4>=4.12.0",
    ],
    python_requires=">=3.8",
)
