#!/usr/bin/env python3

import asyncio
import aiohttp
import aiofiles
import os
import sys
import time
import random
from urllib.parse import urljoin, urlparse
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import List, Optional
import re
import ssl
import json
import csv

# Clear screen
os.system('clear' if os.name == 'posix' else 'cls')

# Renk kodları sınıfı
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


@dataclass
class ScanResult:
    url: str
    status_code: int
    content_length: int
    response_time: float
    content_type: str
    server: str
    title: str
    redirect_url: str
    timestamp: str


class AdvancedWebScanner:
    def __init__(self):
        self.results: List[ScanResult] = []
        self.session: Optional[aiohttp.ClientSession] = None
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0'
        ]

    async def create_session(self, proxy: str = None, timeout: int = 10):
        connector = aiohttp.TCPConnector(
            limit=100,
            limit_per_host=20,
            ssl=ssl.create_default_context(),
            force_close=True,
            enable_cleanup_closed=True
        )

        timeout_config = aiohttp.ClientTimeout(total=timeout)

        headers = {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }

        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout_config,
            headers=headers
        )

    async def close_session(self):
        if self.session:
            await self.session.close()

    def extract_title(self, html_content: str) -> str:
        try:
            title_match = re.search(r'<title[^>]*>(.*?)</title>', html_content, re.IGNORECASE | re.DOTALL)
            if title_match:
                return title_match.group(1).strip()[:100]
        except:
            pass
        return ""

    async def scan_url(self, base_url: str, path: str, semaphore: asyncio.Semaphore, proxy: str = None) -> Optional[ScanResult]:
        async with semaphore:
            try:
                full_url = urljoin(base_url, path)
                start_time = time.time()

                kwargs = {
                    'allow_redirects': False,
                    'ssl': False
                }

                if proxy:
                    kwargs['proxy'] = proxy

                async with self.session.get(full_url, **kwargs) as response:
                    response_time = time.time() - start_time

                    content_length = int(response.headers.get('content-length', 0))
                    content_type = response.headers.get('content-type', '').split(';')[0]
                    server = response.headers.get('server', '')
                    redirect_url = response.headers.get('location', '')

                    title = ""
                    if response.status == 200 and 'text/html' in content_type:
                        try:
                            content = await response.text()
                            title = self.extract_title(content)
                        except:
                            pass

                    return ScanResult(
                        url=full_url,
                        status_code=response.status,
                        content_length=content_length,
                        response_time=round(response_time, 3),
                        content_type=content_type,
                        server=server,
                        title=title,
                        redirect_url=redirect_url,
                        timestamp=datetime.now().isoformat()
                    )

            except asyncio.TimeoutError:
                return None
            except Exception:
                return None

    async def load_wordlist(self, wordlist_path: str) -> List[str]:
        paths = []
        try:
            async with aiofiles.open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                async for line in f:
                    path = line.strip()
                    if path and not path.startswith('#'):
                        if not path.startswith('/'):
                            path = '/' + path
                        paths.append(path)
        except FileNotFoundError:
            print(f"{Colors.FAIL}[ERROR]{Colors.ENDC} Wordlist file not found: {wordlist_path}")
            sys.exit(1)
        except Exception as e:
            print(f"{Colors.FAIL}[ERROR]{Colors.ENDC} Error reading wordlist: {e}")
            sys.exit(1)

        return paths

    def filter_results(self, min_status: int = 200, max_status: int = 399,
                      exclude_extensions: List[str] = None) -> List[ScanResult]:
        filtered = []
        exclude_extensions = exclude_extensions or []

        for result in self.results:
            if min_status <= result.status_code <= max_status:
                url_path = urlparse(result.url).path.lower()
                if not any(url_path.endswith(ext) for ext in exclude_extensions):
                    filtered.append(result)

        return filtered

    def generate_report(self, output_file: str, format_type: str = 'json'):
        if not self.results:
            print(f"{Colors.WARNING}[INFO]{Colors.ENDC} No results to export")
            return

        try:
            if format_type.lower() == 'json':
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump([asdict(result) for result in self.results], f, indent=2, ensure_ascii=False)

            elif format_type.lower() == 'csv':
                with open(output_file, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['URL', 'Status Code', 'Content Length', 'Response Time',
                                   'Content Type', 'Server', 'Title', 'Redirect URL', 'Timestamp'])
                    for result in self.results:
                        writer.writerow([
                            result.url, result.status_code, result.content_length,
                            result.response_time, result.content_type, result.server,
                            result.title, result.redirect_url, result.timestamp
                        ])

            elif format_type.lower() == 'txt':
                with open(output_file, 'w', encoding='utf-8') as f:
                    for result in self.results:
                        f.write(f"[{result.status_code}] {result.url}\n")
                        if result.title:
                            f.write(f"    Title: {result.title}\n")
                        if result.server:
                            f.write(f"    Server: {result.server}\n")
                        f.write(f"    Size: {result.content_length} bytes\n")
                        f.write(f"    Time: {result.response_time}s\n")
                        f.write("-" * 50 + "\n")

            print(f"{Colors.OKGREEN}[SUCCESS]{Colors.ENDC} Report saved to: {output_file}")

        except Exception as e:
            print(f"{Colors.FAIL}[ERROR]{Colors.ENDC} Failed to save report: {e}")

    async def scan_website(self, target_url: str, wordlist_path: str,
                          concurrent_requests: int = 50, delay: float = 0,
                          proxy: str = None, timeout: int = 10):

        print(f"""
{Colors.OKCYAN}[INFO]{Colors.ENDC} Target: {target_url}
{Colors.OKCYAN}[INFO]{Colors.ENDC} Wordlist: {wordlist_path}
{Colors.OKCYAN}[INFO]{Colors.ENDC} Concurrent requests: {concurrent_requests} (auto-optimized)
{Colors.OKCYAN}[INFO]{Colors.ENDC} Delay: {delay}s
{Colors.OKCYAN}[INFO]{Colors.ENDC} Proxy: {proxy if proxy else 'None'}
{Colors.OKCYAN}[INFO]{Colors.ENDC} Timeout: {timeout}s
{Colors.OKCYAN}[INFO]{Colors.ENDC} Mode: Complete scan (will process entire wordlist)
        """)

        paths = await self.load_wordlist(wordlist_path)
        print(f"{Colors.OKBLUE}[INFO]{Colors.ENDC} Loaded {len(paths)} paths")

        await self.create_session(proxy, timeout)
        semaphore = asyncio.Semaphore(concurrent_requests)

        print(f"{Colors.OKCYAN}[INFO]{Colors.ENDC} Starting scan...")
        start_time = time.time()

        tasks = []
        for path in paths:
            tasks.append(self.scan_url(target_url, path, semaphore, proxy))
            if delay > 0:
                await asyncio.sleep(delay)

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, ScanResult):
                self.results.append(result)

                if result.status_code == 200:
                    color = Colors.OKGREEN
                elif result.status_code in [301, 302, 307, 308]:
                    color = Colors.WARNING
                elif result.status_code == 403:
                    color = Colors.FAIL
                else:
                    color = Colors.OKBLUE

                print(f"{color}[{result.status_code}]{Colors.ENDC} {result.url} "
                      f"({result.content_length}b, {result.response_time}s)")

                if result.title:
                    print(f"      └─ Title: {result.title}")
                if result.redirect_url:
                    print(f"      └─ Redirect: {result.redirect_url}")

        await self.close_session()

        total_time = time.time() - start_time
        print(f"\n{Colors.OKCYAN}[INFO]{Colors.ENDC} Scan completed in {total_time:.2f} seconds")
        print(f"{Colors.OKCYAN}[INFO]{Colors.ENDC} Total requests: {len(tasks)}")
        print(f"{Colors.OKCYAN}[INFO]{Colors.ENDC} Successful responses: {len(self.results)}")

        interesting = self.filter_results(200, 399, ['.css', '.js', '.png', '.jpg', '.gif'])
        if interesting:
            print(f"\n{Colors.HEADER}[INTERESTING]{Colors.ENDC} Found {len(interesting)} interesting paths:")
            for result in interesting[:10]:
                print(f"  → [{result.status_code}] {result.url}")
            if len(interesting) > 10:
                print(f"  ... and {len(interesting) - 10} more")


def create_default_wordlist():
    default_paths = [
        'admin', 'administrator', 'admin.php', 'admin.html', 'admin.htm',
        'admin/', 'admin/admin.php', 'admin/login.php', 'admin/admin.html',
        'admin/account.php', 'admin/admin-login.php', 'admin/admin_login.php',
        'login', 'login.php', 'login.html', 'user', 'users', 'config.php',
        'config', 'config.json', 'backup', 'backup.zip', 'backup.tar.gz',
        'db_backup', 'database', 'test', 'test.php', 'test.html',
        'robots.txt', 'sitemap.xml', 'api', 'api.php', 'api/v1/', 'uploads/',
        'upload', 'files', 'css', 'js', 'images'
    ]

    filename = 'default_wordlist.txt'
    with open(filename, 'w', encoding='utf-8') as f:
        for path in default_paths:
            f.write(path + '\n')

    return filename


async def main():
    print(f"""
{Colors.OKCYAN}

    _   __
   / | / /__  ____ _   ______________ _____  ____  ___  _____
  /  |/ / _ \/ __ `/  / ___/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
 / /|  /  __/ /_/ /  (__  ) /__/ /_/ / / / / / / /  __/ /
/_/ |_/\___/\__,_/  /____/\___/\__,_/_/ /_/_/ /_/\___/_/


{Colors.ENDC}
{Colors.BOLD}              Nea Web Scanner Tool - Directory Enumeration{Colors.ENDC}
    """)

    print(f"{Colors.OKGREEN}[INPUT]{Colors.ENDC} Enter target URL (with http:// or https://): ", end='')
    target_url = input().strip()

    if not target_url.startswith(('http://', 'https://')):
        print(f"{Colors.FAIL}[ERROR]{Colors.ENDC} URL must start with http:// or https://")
        sys.exit(1)

    print(f"{Colors.OKGREEN}[INPUT]{Colors.ENDC} Enter wordlist file path (or leave empty to create default): ", end='')
    wordlist_path = input().strip()

    if wordlist_path == '':
        wordlist_path = create_default_wordlist()
        print(f"{Colors.OKBLUE}[INFO]{Colors.ENDC} Created default wordlist: {wordlist_path}")
    elif not os.path.exists(wordlist_path):
        print(f"{Colors.FAIL}[ERROR]{Colors.ENDC} Wordlist file not found: {wordlist_path}")
        sys.exit(1)

    print(f"{Colors.OKGREEN}[INPUT]{Colors.ENDC} Concurrent requests (default 50): ", end='')
    concurrent_input = input().strip()
    concurrent_requests = int(concurrent_input) if concurrent_input.isdigit() else 50

    print(f"{Colors.OKGREEN}[INPUT]{Colors.ENDC} Delay between requests in seconds (default 0): ", end='')
    delay_input = input().strip()
    delay = float(delay_input) if delay_input else 0

    print(f"{Colors.OKGREEN}[INPUT]{Colors.ENDC} Request timeout in seconds (default 10): ", end='')
    timeout_input = input().strip()
    timeout = int(timeout_input) if timeout_input else 10

    print(f"{Colors.OKGREEN}[INPUT]{Colors.ENDC} Proxy server URL (e.g. http://127.0.0.1:8080) or leave empty: ", end='')
    proxy = input().strip()
    proxy = proxy if proxy else None

    print(f"{Colors.OKGREEN}[INPUT]{Colors.ENDC} Output file path (optional): ", end='')
    output_file = input().strip()
    output_file = output_file if output_file else None

    output_format = 'json'
    if output_file:
        print(f"{Colors.OKGREEN}[INPUT]{Colors.ENDC} Output format (json/csv/txt, default json): ", end='')
        fmt = input().strip().lower()
        if fmt in ['json', 'csv', 'txt']:
            output_format = fmt

    scanner = AdvancedWebScanner()
    await scanner.scan_website(
        target_url=target_url,
        wordlist_path=wordlist_path,
        concurrent_requests=concurrent_requests,
        delay=delay,
        proxy=proxy,
        timeout=timeout
    )

    if output_file:
        scanner.generate_report(output_file, output_format)

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[INFO]{Colors.ENDC} Scan aborted by user")
        sys.exit(0)
