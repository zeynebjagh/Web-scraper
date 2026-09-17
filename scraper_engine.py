"""
Website Scraper - Core Engine
Cybersecurity Project – Information Assurance and Security
Team: Farah Haddad, Mariem Maddouri, Zeineb Jaghmoun, Mayssa Ben Youssef, Mariem Soltani

This module handles:
  - robots.txt compliance check
  - Rate limiting (ethical scraping)
  - HTML fetching with User-Agent headers
  - HTML parsing and data extraction
  - Output to CSV, JSON, or Excel
"""

import time
import random
import logging
import json
import csv
import os
from datetime import datetime
from urllib.parse import urlparse, urljoin
from urllib.robotparser import RobotFileParser

import requests
from bs4 import BeautifulSoup
import openpyxl

# ─────────────────────────────────────────────
# LOGGER SETUP (Step 9 in data flow)
# ─────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# SECURITY CONTROL: User-Agent pool (Section 8)
# ─────────────────────────────────────────────
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/117.0",
]


# ─────────────────────────────────────────────
# SECURITY CONTROL: robots.txt check (Section 8)
# ─────────────────────────────────────────────
def check_robots_txt(url: str) -> dict:
    """
    Fetch and parse robots.txt for the given URL.
    Returns a dict with: allowed (bool), reason (str), crawl_delay (int)
    """
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    robots_url = urljoin(base, "/robots.txt")

    result = {
        "robots_url": robots_url,
        "allowed": True,
        "reason": "No robots.txt found — scraping allowed by default.",
        "crawl_delay": 2,
        "warnings": []
    }

    try:
        rp = RobotFileParser()
        rp.set_url(robots_url)
        rp.read()

        # Check if our user-agent is allowed
        allowed = rp.can_fetch("*", url)
        result["allowed"] = allowed

        if not allowed:
            result["reason"] = (
                f"robots.txt DISALLOWS scraping this path. "
                f"Ethical scraping requires you to respect this."
            )
            result["warnings"].append("BLOCKED by robots.txt")
        else:
            result["reason"] = "robots.txt allows scraping this path."

        # Check crawl-delay
        delay = rp.crawl_delay("*")
        if delay:
            result["crawl_delay"] = int(delay)
            result["warnings"].append(f"robots.txt requests a crawl-delay of {delay}s — will be respected.")

    except Exception as e:
        logger.warning(f"Could not fetch robots.txt: {e}")
        result["reason"] = f"Could not read robots.txt ({e}). Proceeding with default 2s delay."

    return result


# ─────────────────────────────────────────────
# HTML FETCHER (Step 3 in data flow)
# ─────────────────────────────────────────────
def fetch_html(url: str, timeout: int = 10) -> dict:
    """
    Fetch raw HTML from a URL with rotating User-Agent and TLS verification.
    Returns dict with: html, status_code, elapsed_ms, error
    """
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }

    result = {"html": None, "status_code": None, "elapsed_ms": None, "error": None}

    try:
        # SECURITY: TLS verification enabled by default (verify=True)
        response = requests.get(url, headers=headers, timeout=timeout, verify=True)
        result["status_code"] = response.status_code
        result["elapsed_ms"] = int(response.elapsed.total_seconds() * 1000)

        if response.status_code == 200:
            result["html"] = response.text
            logger.info(f"Fetched {url} → {response.status_code} ({result['elapsed_ms']}ms)")
        elif response.status_code == 429:
            result["error"] = "HTTP 429 Too Many Requests — server is rate-limiting us."
            logger.warning(result["error"])
        elif response.status_code == 403:
            result["error"] = "HTTP 403 Forbidden — access denied by server."
        else:
            result["error"] = f"HTTP {response.status_code} — unexpected response."

    except requests.exceptions.SSLError as e:
        result["error"] = f"TLS/SSL certificate error: {e}"
        logger.error(result["error"])
    except requests.exceptions.ConnectionError as e:
        result["error"] = f"Connection error: {e}"
    except requests.exceptions.Timeout:
        result["error"] = "Request timed out."
    except Exception as e:
        result["error"] = f"Unexpected error: {e}"

    return result


# ─────────────────────────────────────────────
# PARSER + DATA EXTRACTOR (Steps 4–5)
# ─────────────────────────────────────────────
def extract_data(html: str, fields: list) -> list:
    """
    Parse HTML and extract data based on requested field types.
    Supported fields: title, headings, paragraphs, links, images, meta_description, all_text
    Returns a list of dicts.
    """
    soup = BeautifulSoup(html, "html.parser")
    records = []

    for field in fields:
        field = field.strip().lower()

        if field == "title":
            tag = soup.find("title")
            records.append({"field": "title", "value": tag.get_text(strip=True) if tag else "N/A"})

        elif field == "headings":
            for tag in soup.find_all(["h1", "h2", "h3"]):
                text = tag.get_text(strip=True)
                if text:
                    records.append({"field": tag.name, "value": text})

        elif field == "paragraphs":
            for p in soup.find_all("p"):
                text = p.get_text(strip=True)
                if text:
                    records.append({"field": "paragraph", "value": text})

        elif field == "links":
            for a in soup.find_all("a", href=True):
                records.append({"field": "link", "value": a["href"], "text": a.get_text(strip=True)})

        elif field == "images":
            for img in soup.find_all("img"):
                records.append({"field": "image", "value": img.get("src", ""), "alt": img.get("alt", "")})

        elif field == "meta_description":
            tag = soup.find("meta", attrs={"name": "description"})
            value = tag["content"] if tag and tag.get("content") else "N/A"
            records.append({"field": "meta_description", "value": value})

        elif field == "all_text":
            text = soup.get_text(separator="\n", strip=True)
            for line in text.splitlines():
                if line.strip():
                    records.append({"field": "text", "value": line.strip()})

    return records


# ─────────────────────────────────────────────
# DATA TRANSFORMER (Step 7)
# ─────────────────────────────────────────────
def transform_records(records: list) -> list:
    """
    Clean and normalize extracted records.
    - Strip whitespace
    - Remove empty values
    - Truncate very long strings
    """
    cleaned = []
    for rec in records:
        clean_rec = {}
        for k, v in rec.items():
            v = str(v).strip()
            if len(v) > 1000:
                v = v[:1000] + "..."
            clean_rec[k] = v
        if any(v for v in clean_rec.values()):
            cleaned.append(clean_rec)
    return cleaned


# ─────────────────────────────────────────────
# STORAGE HANDLER (Step 8)
# ─────────────────────────────────────────────
def save_output(records: list, output_format: str, output_dir: str = "output") -> str:
    """
    Save records to CSV, JSON, or Excel.
    Returns the file path of the saved output.
    """
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if output_format == "csv":
        filepath = os.path.join(output_dir, f"scraped_{timestamp}.csv")
        if records:
            keys = list(records[0].keys())
            with open(filepath, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
                writer.writeheader()
                writer.writerows(records)

    elif output_format == "json":
        filepath = os.path.join(output_dir, f"scraped_{timestamp}.json")
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(records, f, indent=2, ensure_ascii=False)

    elif output_format == "excel":
        filepath = os.path.join(output_dir, f"scraped_{timestamp}.xlsx")
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "Scraped Data"
        if records:
            headers = list(records[0].keys())
            ws.append(headers)
            for rec in records:
                ws.append([rec.get(h, "") for h in headers])
        wb.save(filepath)

    else:
        raise ValueError(f"Unknown output format: {output_format}")

    logger.info(f"Saved {len(records)} records to {filepath}")
    return filepath


# ─────────────────────────────────────────────
# MAIN SCRAPER FUNCTION
# ─────────────────────────────────────────────
def run_scraper(url: str, fields: list, output_format: str, output_dir: str = "output") -> dict:
    """
    Full pipeline: check robots.txt → fetch → parse → extract → transform → save.
    Returns a result summary dict.
    """
    result = {
        "url": url,
        "timestamp": datetime.now().isoformat(),
        "robots_check": None,
        "fetch": None,
        "records_count": 0,
        "output_file": None,
        "errors": [],
        "warnings": []
    }

    # Step 1: robots.txt compliance check
    logger.info("Checking robots.txt...")
    robots = check_robots_txt(url)
    result["robots_check"] = robots
    result["warnings"].extend(robots.get("warnings", []))

    if not robots["allowed"]:
        result["errors"].append(robots["reason"])
        logger.error("Scraping blocked by robots.txt. Aborting.")
        return result

    # Step 2: Rate limiting — respect crawl-delay
    delay = robots.get("crawl_delay", 2)
    logger.info(f"Waiting {delay}s (rate limiting)...")
    time.sleep(delay)

    # Step 3: Fetch HTML
    logger.info(f"Fetching {url}...")
    fetch = fetch_html(url)
    result["fetch"] = {
        "status_code": fetch["status_code"],
        "elapsed_ms": fetch["elapsed_ms"],
        "error": fetch["error"]
    }

    if fetch["error"] or not fetch["html"]:
        result["errors"].append(fetch["error"] or "No HTML returned.")
        return result

    # Steps 4–5: Parse + Extract
    logger.info(f"Extracting fields: {fields}")
    raw_records = extract_data(fetch["html"], fields)

    # Step 7: Transform
    clean_records = transform_records(raw_records)
    result["records_count"] = len(clean_records)

    # Step 8: Save
    if clean_records:
        filepath = save_output(clean_records, output_format, output_dir)
        result["output_file"] = filepath
    else:
        result["warnings"].append("No data extracted — the page may use JavaScript rendering.")

    return result
