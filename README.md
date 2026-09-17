# Website Scraper — Ethical Web Scraping System

Cybersecurity project (Information Assurance & Security) — an ethical web scraping tool with built-in security and compliance controls.

## What it does

A decoupled Flask + Python application that scrapes websites while enforcing ethical and security boundaries at every step:

- **robots.txt compliance** — checks and respects site scraping rules before any request
- **Rate limiting** — configurable delay (min. 2s) between requests to avoid overloading servers
- **User-Agent rotation** — rotates realistic browser identities per request
- **TLS/HTTPS enforcement** — certificate verification on every request
- **Structured error handling** — safely captures timeouts, SSL errors, and blocked requests
- **Multi-format export** — outputs to CSV, JSON, or Excel

## Architecture

```
User → Scheduler → Crawler → HTML Fetcher → Parser → Data Extractor → Transformer → Storage Handler → Output
```

Each stage logs structured events to a centralized logger for audit and debugging.

## Identified threats & mitigations

| Risk level | Threat | Mitigation |
|---|---|---|
| High | IP blocking/blacklisting | Request throttling |
| High | Legal liability | robots.txt compliance |
| High | Accidental DoS | Request throttling |
| Medium | Man-in-the-middle attack | TLS encryption |
| Medium | Bot detection & anti-scraping | User-Agent rotation |
| Medium | Malicious response injection | Data truncation |
| Medium | Sensitive data exposure | Input validation |
| Low | Data poisoning | Flagged for future enhancement |

## Tech stack

Python, Flask, Requests, BeautifulSoup4, lxml, openpyxl, HTML/CSS/JavaScript

## Project structure

```
├── scraper_engine.py     # Core scraping engine (robots.txt check, fetch, parse, transform, save)
├── app.py                 # Flask API (if applicable)
├── templates/              # Frontend HTML
├── presentation/           # Project slides (PDF)
└── requirements.txt
```

## Team

Farah Haddad, Mariem Maddouri, Zeineb Jaghmoun, Mayssa Ben Youssef, Mariem Soltani
Tunis Business School — Information Assurance & Security, 2025/2026
