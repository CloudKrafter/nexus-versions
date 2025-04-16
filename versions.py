#!/usr/bin/env python3

import requests
from bs4 import BeautifulSoup
import json
import re
from typing import Dict, Optional, Tuple
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class NexusVersionScraper:
    def __init__(self, url: str):
        self.url = url
        self.versions: Dict = {}
        
        # Define supported OS and architecture patterns
        self.os_patterns = {
            'unix': r'(?:unix|linux)(?!-mac)',  # Match unix or linux but not unix-mac
            'mac': r'mac|darwin',
            'windows': r'win(?:64|dows)?'
        }
        
        self.arch_patterns = {
            'x86_64': r'x86[_-]64',  # Match both x86_64 and x86-64
            'aarch64': r'(?:aarch|arm)[_-]?64'  # Match aarch64, aarch_64, arm64
        }
        
        self.java_patterns = {
            'java8': r'java8',
            'java11': r'java11',
            'java17': r'java17'
        }

    def fetch_page(self) -> Optional[str]:
        """Fetch the HTML content of the download archives page."""
        try:
            response = requests.get(self.url)
            response.raise_for_status()
            return response.text
        except requests.RequestException as e:
            logger.error(f"Failed to fetch page: {e}")
            return None

    def extract_version(self, text: str) -> Optional[str]:
        """Extract version number from text using regex."""
        match = re.search(r'(\d+\.\d+\.\d+-\d+)', text)
        return match.group(1) if match else None

    def detect_os_arch_java(self, filename: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Detect OS, architecture and Java version from filename.
        
        Args:
            filename (str): The filename to analyze
            
        Returns:
            tuple: (os_type, architecture, java_version)
        """
        filename = filename.lower()
        
        # Detect OS
        detected_os = None
        for os_name, pattern in self.os_patterns.items():
            if re.search(pattern, filename):
                detected_os = os_name
                break
        
        # Detect architecture
        detected_arch = None
        for arch_name, pattern in self.arch_patterns.items():
            if re.search(pattern, filename):
                detected_arch = arch_name
                break
        
        # Detect Java version
        detected_java = None
        for java_name, pattern in self.java_patterns.items():
            if re.search(pattern, filename):
                detected_java = java_name
                break

        # Default to x86_64 for older packages that don't specify arch
        if detected_os and not detected_arch:
            detected_arch = 'x86_64'
            
        return detected_os, detected_arch, detected_java

    def process_download_link(self, link: str) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[Dict]]:
        """Process a download link and return OS, arch, Java version, and package info."""
        os_type, arch, java_version = self.detect_os_arch_java(link)
        if not os_type:
            return None, None, None, None

        # Remove .sha512 extension if present
        base_url = link[:-7] if link.endswith('.sha512') else link
            
        package_info = {
            "url": base_url,
            "hashes": {
                "md5": f"{base_url}.md5",
                "sha1": f"{base_url}.sha1",
                "sha256": f"{base_url}.sha256",
                "sha512": f"{base_url}.sha512"
            }
        }
            
        return os_type, arch, java_version, package_info

    def parse_html(self, html: str) -> None:
        """Parse the HTML content and extract version information."""
        soup = BeautifulSoup(html, 'html.parser')
        # Find download links but exclude hash files
        all_links = soup.find_all('a', href=re.compile(r'download\.sonatype\.com/nexus/3/nexus-'))
        download_links = [
            link for link in all_links 
            if not any(link.get('href').endswith(ext) 
                      for ext in ['.md5', '.sha1', '.sha256', '.sha512'])
        ]
        
        for link in download_links:
            href = link.get('href')
            version = self.extract_version(href)
            
            if not version:
                continue

            # Initialize version entry with empty OS sections
            if version not in self.versions:
                self.versions[version] = {
                    "unix": {},
                    "mac": {},
                    "windows": {}
                }

            os_type, arch, java_version, package_info = self.process_download_link(href)
            if os_type and arch:
                # Initialize architecture if not present
                if arch not in self.versions[version][os_type]:
                    self.versions[version][os_type][arch] = {}
                
                # Add package info under Java version if present, otherwise directly under arch
                if java_version:
                    self.versions[version][os_type][arch][java_version] = package_info
                else:
                    # For packages without Java version, store directly under arch
                    self.versions[version][os_type][arch] = package_info

    def save_json(self, output_file: str) -> None:
        """Save the version information to a JSON file."""
        try:
            with open(output_file, 'w') as f:
                json.dump({"versions": self.versions}, f, indent=2)
            logger.info(f"Successfully saved version information to {output_file}")
        except IOError as e:
            logger.error(f"Failed to save JSON file: {e}")

    def run(self, output_file: str) -> bool:
        """
        Run the scraper and save results.
        
        Args:
            output_file (str): Path to save the JSON output
            
        Returns:
            bool: True if successful, False otherwise
        """
        html = self.fetch_page()
        if not html:
            return False

        self.parse_html(html)
        if not self.versions:
            logger.error("No versions found")
            return False

        self.save_json(output_file)
        return True

def main():
    url = "https://help.sonatype.com/en/download-archives---repository-manager-3.html"
    output_file = "nexus_versions.json"
    
    scraper = NexusVersionScraper(url)
    if scraper.run(output_file):
        logger.info("Successfully generated version information")
    else:
        logger.error("Failed to generate version information")

if __name__ == "__main__":
    main()
