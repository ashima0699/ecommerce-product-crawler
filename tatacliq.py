from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager
import time


def setup_driver():
    """Configure and return a Chrome WebDriver with optimized settings"""
    options = webdriver.ChromeOptions()
    options.add_argument('--headless')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    options.add_argument('--disable-blink-features=AutomationControlled')
    options.add_argument(
        'user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36')

    # Suppress unnecessary logs
    service = Service(ChromeDriverManager().install())
    service.creationflags = 0x08000000  # Suppress ChromeDriver logs on Windows

    driver = webdriver.Chrome(service=service, options=options)
    return driver


def fetch_product_links(category_url):
    """Fetch product links from a Tata CLIQ category page"""
    driver = setup_driver()

    try:
        driver.get(category_url)
        print(f"Loading page: {category_url}")

        # Wait for products to load and scroll to load more products
        last_height = driver.execute_script("return document.body.scrollHeight")
        scroll_attempts = 0

        while scroll_attempts < 3:  # Try scrolling 3 times to load more products
            driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
            time.sleep(2)  # Wait for content to load
            new_height = driver.execute_script("return document.body.scrollHeight")
            if new_height == last_height:
                break
            last_height = new_height
            scroll_attempts += 1

        # Wait for product elements to be present
        wait = WebDriverWait(driver, 15)
        wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, "[href*='/p-']")))

        # Find all product links - using more specific selectors
        product_elements = driver.find_elements(By.CSS_SELECTOR, "[href*='/p-']")
        print(f"Found {len(product_elements)} potential product links")

        # Filter and normalize links
        base_url = "https://www.tatacliq.com"
        links = set()

        for element in product_elements:
            href = element.get_attribute("href")
            if href and '/p-' in href:  # More specific filtering
                if not href.startswith('http'):
                    href = base_url + href
                links.add(href.split('?')[0])  # Remove query parameters

        return links

    except Exception as e:
        print(f"Error fetching products: {str(e)}")
        return set()
    finally:
        driver.quit()


def run():
    """Main execution function"""
    category_urls = [
        "https://www.tatacliq.com/womens-clothing/c-msh11",
        "https://www.tatacliq.com/mens-clothing/c-msh12",
        "https://www.tatacliq.com/footwear/c-msh1210001",
        "https://www.tatacliq.com/womens-footwear/c-msh1110001",
        "https://www.tatacliq.com/womens-bags-wallets/c-msh1110002",
        "https://www.tatacliq.com/mens-bags-wallets/c-msh1210002",
        "https://www.tatacliq.com/watches/c-msh13",
        "https://www.tatacliq.com/jewellery/c-msh14",
        "https://www.tatacliq.com/beauty/c-msh15",
        "https://www.tatacliq.com/home-kitchen/c-msh16",
    ]

    all_products = set()

    for url in category_urls:
        print(f"\nProcessing category: {url}")
        products = fetch_product_links(url)
        all_products.update(products)
        print(f"Found {len(products)} products in this category")
        time.sleep(2)  # Be polite between requests

    print("\nFinal Results:")
    print(f"Total unique products found: {len(all_products)}")

    # Save to file
    with open("tata_cliq_products.txt", "w") as f:
        for product in sorted(all_products):
            f.write(f"{product}\n")

    print("Results saved to tata_cliq_products.txt")


if __name__ == "__main__":
    run()