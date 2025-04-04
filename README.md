# E-commerce Product URL Crawler

## Overview
This project is an asynchronous web crawler designed to discover product URLs from multiple e-commerce websites. It efficiently handles multiple requests while avoiding anti-crawling mechanisms, ensuring smooth and reliable extraction of product links.

## Features
- **Asynchronous crawling** using `aiohttp` and `asyncio`
- **HTML parsing** with `BeautifulSoup` to extract links
- **Product URL identification** using regex patterns
- **Retry mechanism** for handling failed requests
- **Domain-wise URL queueing** to manage visited pages efficiently

## Installation

To get started, install the required dependencies:

```bash
pip install -r requirements.txt
```

## Usage
Run the crawler by executing:

```bash
python run.py
```

### Configuration Parameters
- `domains`: List of e-commerce domains to crawl
- `max_pages_per_domain`: Limits the number of pages per domain
- `max_workers`: Number of concurrent workers fetching URLs
- `timeout`: Request timeout for handling slow responses
- `max_retries`: Number of times to retry failed requests

## Approach to Finding "Product" URLs

The crawler uses a structured approach to identify product URLs:

1. **Regex-based URL Filtering**
   - Uses a regex pattern to detect product-related URLs containing keywords like `product`, `sku`, `item`, `p=`, `pid`, etc.
   - Example pattern:
     ```python
     product_url_pattern = re.compile(r".*(product|sku|item|pid|p=).*", re.IGNORECASE)
     ```

2. **HTML Link Extraction**
   - Parses the HTML response with `BeautifulSoup`
   - Extracts all anchor (`<a>`) tags and filters relevant links

3. **Domain Validation**
   - Ensures that extracted links belong to the same domain
   - Cleans up relative URLs to absolute format

4. **Queueing Mechanism**
   - Adds valid product URLs to a set for deduplication
   - Adds category/listing pages back to the queue for deeper crawling

## Example Output

After crawling, the script outputs a structured list of product URLs:

```
Crawled domain: example.com
Found product URLs:
 - https://www.virgio.com/
 - https://nykaafashion.com/
 - https://www.westside.com/
```

## Future Enhancements
- Implement proxy rotation to bypass anti-bot measures
- Add structured data (JSON-LD) extraction for richer metadata
- Support for sitemap-based crawling to improve efficiency

## License
This project is open-source and available for modification and improvement.

