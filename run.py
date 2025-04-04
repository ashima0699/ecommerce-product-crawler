# E-commerce Product URL Crawler
# This crawler discovers product URLs across multiple e-commerce websites with advanced anti-blocking

import asyncio
import re
import time
import random
import urllib.parse
from collections import defaultdict
from typing import List, Set, Dict, Tuple, Optional

import aiohttp
from bs4 import BeautifulSoup
import logging

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class EcommerceProductCrawler:
    def __init__(self, domains: List[str], max_pages_per_domain: int = 500,
                 max_workers: int = 5, timeout: int = 30,
                 max_retries: int = 1, retry_delay: int = 1):
        """
        Initialize the crawler with a list of e-commerce domains.

        Args:
            domains: List of domain URLs to crawl
            max_pages_per_domain: Maximum number of pages to crawl per domain
            max_workers: Maximum number of concurrent requests
            timeout: Request timeout in seconds
            max_retries: Maximum number of retries for failed requests
            retry_delay: Delay between retries in seconds
        """
        self.domains = domains
        self.max_pages_per_domain = max_pages_per_domain
        self.max_workers = max_workers
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay

        # Regular expressions to identify product URLs
        self.product_patterns = [
            r'/product[s]?/',
            r'/item[s]?/',
            r'/p/',
            r'/pd/',
            r'/buy/',
            r'/shop/product[s]?/',
            r'/[a-z-]+/[a-z0-9-]+-p-\d+',  # Common pattern: category/product-name-p-12345
            r'/[a-z-]+/\d+',  # Simple ID-based pattern
            r'/products/[a-z0-9-]+',
            r'/product-detail/',
            r'/item-detail/',
            r'/[a-z-]+/[a-z0-9-]+-\d+\.html',  # Common pattern with .html extension
        ]

        # Domain-specific patterns
        self.domain_patterns = {
            'virgio.com': [r'/products/', r'/collections/'],
            'tatacliq.com': [r'/[a-z-]+/[a-z0-9-]+-p-[a-z0-9]+', r'/product-details/'],
            'nykaafashion.com': [r'/[a-z-]+/p/\d+', r'/product/'],
            'westside.com': [r'/[a-z-]+/[a-z0-9-]+-\d+', r'/products/']
        }

        # Reject patterns - typically non-product pages
        self.reject_patterns = [
            r'/cart/',
            r'/checkout/',
            r'/account/',
            r'/login/',
            r'/register/',
            r'/search\?',
            r'/auth/',
            r'/profile/',
            r'/wishlist/',
            r'/contact',
            r'/about',
            r'/terms',
            r'/privacy',
            r'/faq',
            r'/help',
            r'/support/',
            r'/blog/',
            r'/news/',
            r'/articles/',
            r'/tag/',
            r'/category/',
            r'/returns/',
        ]

        # Domain access status
        self.domain_status = {}

        # List of real browser user agents for rotation
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/117.0',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (iPad; CPU OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36 Edg/118.0.2088.76',
        ]

        # Domain-specific access methods
        self.domain_access_methods = {
            'nykaafashion.com': self.access_nykaa_fashion,
            # Add more domain-specific methods as needed
        }

    async def is_product_url(self, url: str, domain: str) -> bool:
        """
        Check if a URL is likely to be a product page based on patterns.

        Args:
            url: URL to check
            domain: Domain of the website

        Returns:
            True if URL is likely a product page, False otherwise
        """
        # First check if URL contains any reject patterns
        for pattern in self.reject_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return False

        # Check domain-specific patterns
        for domain_key, patterns in self.domain_patterns.items():
            if domain_key in domain:
                for pattern in patterns:
                    if re.search(pattern, url, re.IGNORECASE):
                        return True

        # Check general product patterns
        for pattern in self.product_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return True

        return False

    def normalize_url(self, base_url: str, url: str) -> str:
        """
        Normalize a URL by handling relative paths and ensuring proper formatting.

        Args:
            base_url: Base URL for the domain
            url: URL to normalize

        Returns:
            Normalized URL
        """
        parsed_base = urllib.parse.urlparse(base_url)
        domain = f"{parsed_base.scheme}://{parsed_base.netloc}"

        # Handle different URL formats
        if url.startswith('//'):
            return f"{parsed_base.scheme}:{url}"
        elif url.startswith('/'):
            return f"{domain}{url}"
        elif not url.startswith(('http://', 'https://')):
            # Handle relative URLs
            path = '/'.join(parsed_base.path.split('/')[:-1]) if parsed_base.path else ''
            if path and not path.endswith('/'):
                path += '/'
            if url.startswith('./'):
                url = url[2:]
            return f"{domain}{path}{url}"

        return url

    def get_domain_from_url(self, url: str) -> str:
        """
        Extract the domain from a URL.

        Args:
            url: URL to extract domain from

        Returns:
            Domain string
        """
        parsed = urllib.parse.urlparse(url)
        return parsed.netloc

    def get_random_user_agent(self) -> str:
        """
        Get a random user agent from the list.

        Returns:
            Random user agent string
        """
        return random.choice(self.user_agents)

    def get_headers(self) -> Dict[str, str]:
        """
        Get headers that mimic a real browser.

        Returns:
            Dictionary of HTTP headers
        """
        return {
            'User-Agent': self.get_random_user_agent(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Cache-Control': 'max-age=0',
        }

    async def access_nykaa_fashion(self, session: aiohttp.ClientSession) -> Tuple[bool, Optional[str]]:
        """
        Special method to access Nykaa Fashion which has stricter bot protection.

        Args:
            session: aiohttp client session

        Returns:
            Tuple of (success boolean, entry URL or None)
        """
        # Alternative entry points for Nykaa Fashion
        entry_points = [
            "https://nykaafashion.com/",
            "https://www.nykaafashion.com/",
            "https://nykaafashion.com/women/c/7",  # Women's category
            "https://nykaafashion.com/men/c/8",  # Men's category
        ]

        # Try all entry points with different approaches
        for entry in entry_points:
            # Approach 1: Direct access with browser-like headers
            try:
                headers = self.get_headers()
                # Add referrer from a common site
                headers['Referer'] = 'https://www.google.com/'

                async with session.get(entry, timeout=self.timeout, allow_redirects=True, headers=headers) as response:
                    if response.status == 200:
                        logger.info(f"Successfully accessed Nykaa Fashion via {entry}")
                        return True, entry
            except Exception as e:
                logger.warning(f"Failed to access {entry}: {str(e)}")

            # Add a delay between attempts
            await asyncio.sleep(2 + random.random() * 2)  # 2-4 second delay

            # Approach 2: Try with mobile user agent
            try:
                mobile_ua = 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1'
                headers = self.get_headers()
                headers['User-Agent'] = mobile_ua

                async with session.get(entry, timeout=self.timeout, allow_redirects=True, headers=headers) as response:
                    if response.status == 200:
                        logger.info(f"Successfully accessed Nykaa Fashion via {entry} with mobile UA")
                        return True, entry
            except Exception as e:
                logger.warning(f"Failed to access {entry} with mobile UA: {str(e)}")

            # Add a delay between attempts
            await asyncio.sleep(2 + random.random() * 2)  # 2-4 second delay

            # Approach 3: Try via a product category URL
            try:
                category_url = f"{entry}?q=dress"
                headers = self.get_headers()

                async with session.get(category_url, timeout=self.timeout, allow_redirects=True,
                                       headers=headers) as response:
                    if response.status == 200:
                        logger.info(f"Successfully accessed Nykaa Fashion via {category_url}")
                        return True, category_url
            except Exception as e:
                logger.warning(f"Failed to access {category_url}: {str(e)}")

        logger.error("All attempts to access Nykaa Fashion failed")
        return False, None

    async def fetch_page(self, session: aiohttp.ClientSession, url: str, retry_count: int = 0) -> Tuple[
        str, Optional[str]]:
        """
        Fetch a web page and return its HTML content.

        Args:
            session: aiohttp client session
            url: URL to fetch
            retry_count: Current retry attempt

        Returns:
            Tuple of (URL, HTML content or None if failed)
        """
        # Randomize delay between requests (0.5-1.5 seconds)
        await asyncio.sleep(0.5 + random.random())

        # Rotate user agent and headers for each request
        headers = self.get_headers()

        try:
            async with session.get(url, timeout=self.timeout, allow_redirects=True, headers=headers) as response:
                if response.status == 200:
                    content = await response.text()
                    return url, content
                elif response.status == 403 or response.status == 401:
                    logger.warning(f"Access denied for {url}, status: {response.status}")
                    domain = self.get_domain_from_url(url)
                    self.domain_status[domain] = f"Access denied (Status: {response.status})"
                    return url, None
                elif retry_count < self.max_retries:
                    retry_delay = self.retry_delay + random.uniform(1, 3)  # Add randomness
                    logger.warning(
                        f"Failed to fetch {url}, status: {response.status}, retrying in {retry_delay:.2f}s...")
                    await asyncio.sleep(retry_delay)
                    # Try with different headers on retry
                    return await self.fetch_page(session, url, retry_count + 1)
                else:
                    logger.warning(f"Failed to fetch {url} after {self.max_retries} retries, status: {response.status}")
                    return url, None
        except asyncio.TimeoutError:
            if retry_count < self.max_retries:
                retry_delay = self.retry_delay + random.uniform(1, 3)
                logger.warning(f"Timeout fetching {url}, retrying in {retry_delay:.2f}s...")
                await asyncio.sleep(retry_delay)
                return await self.fetch_page(session, url, retry_count + 1)
            else:
                logger.error(f"Timeout fetching {url} after {self.max_retries} retries")
                domain = self.get_domain_from_url(url)
                self.domain_status[domain] = "Timeout error after multiple retries"
                return url, None
        except aiohttp.ClientConnectorError as e:
            logger.error(f"Connection error for {url}: {str(e)}")
            domain = self.get_domain_from_url(url)
            self.domain_status[domain] = f"Connection error: {str(e)}"
            return url, None
        except Exception as e:
            logger.error(f"Error fetching {url}: {str(e)}")
            return url, None

    async def extract_links(self, html: str, base_url: str) -> Set[str]:
        """
        Extract all links from an HTML page.

        Args:
            html: HTML content
            base_url: Base URL for resolving relative links

        Returns:
            Set of links found in the page
        """
        links = set()
        if not html:
            return links

        try:
            soup = BeautifulSoup(html, 'html.parser')

            # Extract links from <a> tags
            for link in soup.find_all('a', href=True):
                href = link.get('href')
                if href and not href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                    normalized_url = self.normalize_url(base_url, href)
                    links.add(normalized_url)

            # Some websites use other elements with URLs (e.g., for AJAX loading)
            for elem in soup.find_all(['div', 'span', 'button'], attrs={'data-url': True}):
                data_url = elem.get('data-url')
                if data_url:
                    normalized_url = self.normalize_url(base_url, data_url)
                    links.add(normalized_url)

            # Look for links in JavaScript variables (often used in e-commerce sites)
            # This is a simplified approach - a real crawler might need more sophisticated JS parsing
            scripts = soup.find_all('script')
            for script in scripts:
                if script.string:
                    # Look for product URLs in JavaScript
                    js_text = script.string
                    url_matches = re.findall(r'["\'](/[^"\']*?product[^"\']*?)["\']', js_text)
                    for match in url_matches:
                        normalized_url = self.normalize_url(base_url, match)
                        links.add(normalized_url)

        except Exception as e:
            logger.error(f"Error extracting links from {base_url}: {str(e)}")

        return links

    async def verify_domain_access(self, domain: str, session: aiohttp.ClientSession) -> bool:
        """
        Verify if a domain can be accessed before crawling.

        Args:
            domain: Domain URL to verify
            session: aiohttp client session

        Returns:
            True if domain can be accessed, False otherwise
        """
        domain_netloc = self.get_domain_from_url(domain)

        # Check if there's a special access method for this domain
        for domain_key, access_method in self.domain_access_methods.items():
            if domain_key in domain_netloc:
                success, entry_url = await access_method(session)
                if success and entry_url:
                    # Replace the domain URL with the successful entry URL
                    index = self.domains.index(domain)
                    self.domains[index] = entry_url
                return success

        # Standard access verification
        try:
            # Try different approaches if initial access fails
            for url_variant in [domain, f"https://{domain_netloc}", f"http://{domain_netloc}"]:
                try:
                    headers = self.get_headers()
                    async with session.get(url_variant, timeout=self.timeout, allow_redirects=True,
                                           headers=headers) as response:
                        if response.status == 200:
                            logger.info(f"Successfully accessed {domain}")
                            return True
                        elif response.status in [403, 401]:
                            logger.warning(f"Access denied for {domain}, status: {response.status}")
                            self.domain_status[domain_netloc] = f"Access denied (Status: {response.status})"
                except Exception:
                    continue

                # Add a delay between attempts
                await asyncio.sleep(1 + random.random())

            logger.error(f"Failed to access {domain} after multiple attempts")
            self.domain_status[domain_netloc] = "Failed to access domain after multiple attempts"
            return False
        except Exception as e:
            logger.error(f"Error verifying domain access for {domain}: {str(e)}")
            self.domain_status[domain_netloc] = f"Error: {str(e)}"
            return False

    async def crawl_domain(self, domain: str) -> Set[str]:
        """
        Crawl a single domain to find product URLs.

        Args:
            domain: Domain URL to crawl

        Returns:
            Set of product URLs found
        """
        domain_netloc = self.get_domain_from_url(domain)
        visited = set()
        to_visit = {domain}
        product_urls = set()

        # Use ClientSession with cookie jar and increased connection limits
        connector = aiohttp.TCPConnector(limit=self.max_workers, force_close=True)
        cookie_jar = aiohttp.CookieJar(unsafe=True)  # Allow cross-domain cookies

        async with aiohttp.ClientSession(
                connector=connector,
                cookie_jar=cookie_jar,
                headers=self.get_headers()
        ) as session:
            # First verify if we can access the domain
            if not await self.verify_domain_access(domain, session):
                logger.warning(f"Skipping domain {domain} due to access issues")
                return product_urls

            while to_visit and len(visited) < self.max_pages_per_domain:
                # Process URLs in batches to control concurrency
                current_batch = list(to_visit)[:self.max_workers]
                to_visit = to_visit - set(current_batch)

                # Fetch pages concurrently
                tasks = [self.fetch_page(session, url) for url in current_batch]
                results = await asyncio.gather(*tasks)

                # Process results
                for url, html in results:
                    visited.add(url)

                    # Skip empty or failed responses
                    if not html:
                        continue

                    # Check if this is a product URL
                    if await self.is_product_url(url, domain_netloc):
                        product_urls.add(url)
                        logger.info(f"Found product URL: {url}")

                    # Extract links for further crawling
                    new_links = await self.extract_links(html, url)

                    # Filter links to only include those from the same domain
                    for link in new_links:
                        link_domain = self.get_domain_from_url(link)
                        if (
                                link_domain == domain_netloc
                                and link not in visited
                                and link not in to_visit
                        ):
                            to_visit.add(link)

                logger.info(
                    f"Domain {domain}: Visited {len(visited)} pages, Found {len(product_urls)} products, Queue: {len(to_visit)}")

                # Add a randomized delay to be polite and avoid detection
                await asyncio.sleep(0.5 + random.random())

        return product_urls

    async def crawl_all_domains(self) -> Dict[str, Set[str]]:
        """
        Crawl all domains to find product URLs.

        Returns:
            Dictionary mapping domains to sets of product URLs
        """
        # Process domains sequentially instead of in parallel to avoid IP-based blocking
        domain_to_products = {}

        for domain in self.domains:
            domain_netloc = self.get_domain_from_url(domain)
            logger.info(f"Starting to crawl {domain}")

            product_urls = await self.crawl_domain(domain)
            domain_to_products[domain_netloc] = product_urls

            # Add a longer delay between domains
            await asyncio.sleep(5 + random.random() * 5)

        return domain_to_products

    def run(self) -> Dict[str, List[str]]:
        """
        Run the crawler and return the results.

        Returns:
            Dictionary mapping domains to lists of product URLs
        """
        logger.info(f"Starting crawler for domains: {self.domains}")
        start_time = time.time()

        # Run the async crawl
        loop = asyncio.get_event_loop()
        results = loop.run_until_complete(self.crawl_all_domains())

        # Convert sets to lists for the output
        output = {domain: sorted(list(urls)) for domain, urls in results.items()}

        logger.info(f"Crawling completed in {time.time() - start_time:.2f} seconds")
        for domain, urls in output.items():
            if domain in self.domain_status:
                logger.info(f"Domain {domain}: {self.domain_status[domain]}")
            else:
                logger.info(f"Found {len(urls)} product URLs for {domain}")

        return output

    def get_domain_status(self) -> Dict[str, str]:
        """
        Get the status of each domain crawled.

        Returns:
            Dictionary mapping domains to their status
        """
        return self.domain_status


# Function to save results to a file
def save_results_to_file(results: Dict[str, List[str]], status: Dict[str, str] = None,
                         filename: str = "product_url.txt"):
    """
    Save the crawling results to a file.

    Args:
        results: Dictionary mapping domains to lists of product URLs
        status: Dictionary mapping domains to their status
        filename: Output filename
    """
    with open(filename, "w") as f:
        for domain, urls in results.items():
            f.write(f"Domain: {domain}\n")

            if status and domain in status:
                f.write(f"Status: {status[domain]}\n")

            f.write(f"Total Product URLs: {len(urls)}\n")
            f.write("-" * 80 + "\n")
            for url in urls:
                f.write(f"{url}\n")
            f.write("\n" + "=" * 80 + "\n\n")

    logger.info(f"Results saved to {filename}")


# Example usage
if __name__ == "__main__":
    domains = [
        "https://www.virgio.com/",
        "https://nykaafashion.com/",
        "https://www.westside.com/"
    ]

    # Create crawler with reduced concurrency and more retries
    crawler = EcommerceProductCrawler(
        domains=domains,
        max_workers=3,  # Reduce concurrent requests
        max_retries=1,  # Increase retry attempts
        retry_delay=1  # Longer delay between retries
    )

    results = crawler.run()

    # Save results to a file
    save_results_to_file(results, crawler.get_domain_status())