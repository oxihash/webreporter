# webreporter
All in one web scanner

## ⚠️ Legal Notice

This tool is for **authorized security testing only**. Unauthorized access to computer systems is illegal. Users are responsible for:
- Obtaining written permission before testing
- Complying with all applicable laws
- Understanding legal consequences of unauthorized testing

Installation Requirements:
# Install Python dependencies
pip install -r requirements.txt

# Install external tools (macOS with Homebrew)
brew install nmap subfinder assetfinder ffuf nuclei wafw00f

# Linux (Ubuntu/Debian)
sudo apt-get install nmap
# Then install Go-based tools via their releases

# Basic usage
python3 webreporter.py -u https://example.com

# Aggressive mode with custom threads
python3 webreporter.py -u https://example.com -a -t 10 -o my_results/

# Custom output directory and timeout
python3 webreporter.py -u https://target.com -o results/ --timeout 600
