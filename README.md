# MyBB Scanner

```txt
# MyBB Security Assessment Tool Requirements
# For authorized penetration testing only

# Core HTTP library for making requests
requests>=2.31.0

# HTML parsing library for extracting information
beautifulsoup4>=4.12.0

# Terminal color output for better readability
colorama>=0.4.6

# Optional: For progress bars during long scans
tqdm>=4.66.0

# Optional: For additional URL parsing and manipulation
urllib3>=2.0.0

# Optional: For SSL certificate handling
certifi>=2023.0.0

# Optional: For SOCKS proxy support if needed
PySocks>=1.7.1

# Development and testing dependencies (optional)
# pytest>=7.4.0
# pytest-cov>=4.1.0
# flake8>=6.1.0
# black>=23.0.0
```

## Installation Instructions

### Basic installation (minimum requirements)
```bash
pip install -r requirements.txt
```

### For development/testing (includes optional dependencies)
```bash
pip install -r requirements.txt --extra-index-url https://pypi.org/simple
```

### For maximum compatibility (pin specific versions)
```txt
requests==2.31.0
beautifulsoup4==4.12.2
colorama==0.4.6
tqdm==4.66.1
urllib3==2.0.7
certifi==2023.11.17
PySocks==1.7.1
```

## Alternative: requirements.txt with exact versions for production stability

```txt
# Production-stable versions
requests==2.31.0
beautifulsoup4==4.12.2
colorama==0.4.6
tqdm==4.66.1
urllib3==2.0.7
certifi==2023.11.17
PySocks==1.7.1

# Security updates (keep these updated)
# pip-audit>=2.6.0
# safety>=2.3.5
```

## For Docker/Containerized environments

```txt
# Docker-optimized requirements
requests>=2.31.0,<3.0.0
beautifulsoup4>=4.12.0,<5.0.0
colorama>=0.4.6,<0.5.0
tqdm>=4.66.0,<5.0.0
urllib3>=2.0.0,<3.0.0
certifi>=2023.0.0,<2024.0.0
```

## One-liner installation with all dependencies

```bash
pip install requests beautifulsoup4 colorama tqdm urllib3 certifi PySocks
```

## Virtual environment setup (recommended)

```bash
# Create virtual environment
python3 -m venv mybb-scanner-env

# Activate it (Linux/Mac)
source mybb-scanner-env/bin/activate

# Activate it (Windows)
mybb-scanner-env\Scripts\activate

# Install requirements
pip install -r requirements.txt
```

## For offline/air-gapped environments

```txt
# Create a requirements.txt with download URLs
--find-links ./packages
requests==2.31.0
beautifulsoup4==4.12.2
colorama==0.4.6

# Download packages for offline use:
pip download -r requirements.txt -d ./packages
```

## Additional tools for development (requirements.txt)

```txt
# Development dependencies
pytest>=7.4.0
pytest-cov>=4.1.0
pytest-xdist>=3.3.0
flake8>=6.1.0
black>=23.0.0
isort>=5.12.0
mypy>=1.5.0
pre-commit>=3.4.0
bandit>=1.7.5  # Security linter
safety>=2.3.5  # Check dependencies for known vulnerabilities
```

## To install everything including development tools

```bash
pip install -r requirements.txt -r dev-requirements.txt
```

## Quick setup script (setup.sh)

```bash
#!/bin/bash
echo "Setting up MyBB Security Assessment Tool..."

# Check Python version
python_version=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
required_version="3.8"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" = "$required_version" ]; then 
    echo "Python $python_version detected - OK"
else
    echo "Python 3.8+ required. Found $python_version"
    exit 1
fi

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install requirements
pip install -r requirements.txt

echo "Setup complete! Run: python mybb_scanner.py -u <target_url>"
```

## Note
- The tool requires **Python 3.8 or higher**
- All dependencies are open-source and freely available
- Always use in a virtual environment to avoid conflicts
- For maximum security, consider using a dedicated testing machine or container

The requirements are minimal and focused on the core functionality needed for your MyBB security assessment tool. The main dependencies are:
- `requests` - for HTTP requests
- `beautifulsoup4` - for HTML parsing
- `colorama` - for colored terminal output

The other packages are optional but recommended for enhanced functionality and better user experience.
