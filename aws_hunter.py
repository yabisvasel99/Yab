#!/usr/bin/env python3
import re
import sys
import json
import urllib.request
import concurrent.futures
import boto3
from urllib.parse import urlparse, parse_qs
from botocore.exceptions import ClientError

class AWSCredentialScanner:
    def __init__(self):
        # AWS credential patterns
        self.patterns = {
            'aws_access_key': r'(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])',
            'aws_secret_key': r'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])',
            'aws_session_token': r'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{100,400}(?![A-Za-z0-9/+=])'
        }
        
        self.results = []

    def validate_aws_credentials(self, access_key, secret_key, session_token=None):
        """Validate AWS credentials by attempting to list S3 buckets"""
        try:
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                aws_session_token=session_token
            )
            
            # Try to list S3 buckets to validate credentials
            s3 = session.client('s3')
            s3.list_buckets()
            return True
        except ClientError as e:
            return False
        except Exception as e:
            return False

    def scan_url_content(self, url):
        """Scan URL content for AWS credentials"""
        try:
            # Fetch URL content
            response = urllib.request.urlopen(url)
            content = response.read().decode('utf-8')
            
            # Extract potential credentials
            credentials = {}
            
            for key, pattern in self.patterns.items():
                matches = re.findall(pattern, content)
                if matches:
                    credentials[key] = matches[0]
            
            # Check URL parameters
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query)
            
            for param_name, param_value in params.items():
                param_str = param_value[0] if param_value else ''
                for key, pattern in self.patterns.items():
                    if re.match(pattern, param_str):
                        credentials[key] = param_str
            
            if credentials:
                # Validate credentials if we have a key pair
                if 'aws_access_key' in credentials and 'aws_secret_key' in credentials:
                    is_valid = self.validate_aws_credentials(
                        credentials['aws_access_key'],
                        credentials['aws_secret_key'],
                        credentials.get('aws_session_token')
                    )
                    
                    self.results.append({
                        'url': url,
                        'credentials': credentials,
                        'valid': is_valid
                    })
                    
                    if is_valid:
                        print(f"\033[92m[+] Valid credentials found in {url}\033[0m")
                        print(f"    Access Key: {credentials['aws_access_key']}")
                        print(f"    Secret Key: {credentials['aws_secret_key']}")
                        if 'aws_session_token' in credentials:
                            print(f"    Session Token: {credentials['aws_session_token']}")
                    else:
                        print(f"\033[93m[!] Invalid credentials found in {url}\033[0m")
            
        except Exception as e:
            print(f"\033[91m[-] Error scanning {url}: {str(e)}\033[0m")

    def scan_urls_from_file(self, filename):
        """Scan multiple URLs from a text file"""
        try:
            with open(filename, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
            
            print(f"\033[94m[*] Scanning {len(urls)} URLs for AWS credentials...\033[0m")
            
            # Use thread pool for concurrent scanning
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                executor.map(self.scan_url_content, urls)
            
            # Save results to JSON file
            with open('scan_results.json', 'w') as f:
                json.dump(self.results, f, indent=2)
            
            print(f"\n\033[94m[*] Scan complete. Results saved to scan_results.json\033[0m")
            
            # Print summary
            valid_count = sum(1 for r in self.results if r['valid'])
            print(f"\n\033[94mSummary:\033[0m")
            print(f"Total URLs scanned: {len(urls)}")
            print(f"Credentials found: {len(self.results)}")
            print(f"Valid credentials: {valid_count}")
            
        except FileNotFoundError:
            print(f"\033[91m[-] Error: File {filename} not found\033[0m")
        except Exception as e:
            print(f"\033[91m[-] Error: {str(e)}\033[0m")

def main():
    if len(sys.argv) != 2:
        print("Usage: python aws_hunter.py <urls_file>")
        sys.exit(1)
    
    scanner = AWSCredentialScanner()
    scanner.scan_urls_from_file(sys.argv[1])

if __name__ == "__main__":
    main()