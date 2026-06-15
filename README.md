# Subdomain Finder

Professional subdomain enumeration tool with 8 powerful discovery techniques, real-time progress tracking, interactive pause/resume, and automatic state persistence.

## Features

- **8 Discovery Techniques**:
  - HTML/Response Crawling with link extraction
  - DNS ANY Query with zone transfer attempts
  - Certificate Transparency logs (crt.sh)
  - Wayback Machine historical data
  - Public DNS datasets (BufferOver)
  - Smart permutations of discovered subdomains
  - Numeric pattern detection
  - Dictionary bruteforce with custom wordlists

- **Interactive Control**:
  - Pause/Resume with Ctrl+C
  - Skip current operation
  - End detection phase
  - Change verbosity on the fly
  - Force exit with state save (3x Ctrl+C)

- **Professional Features**:
  - Asynchronous HTTP requests with atomhttp
  - Random User-Agent rotation
  - DNS resolution with thread pool
  - Rate limiting and retry logic
  - Full state persistence for resume
  - Detailed logging with file organization
  - DNS record extraction and logging
  - Subdomain validation and classification

## Installation

```bash
git clone https://github.com/inject3r/subdomain-finder.git
cd subdomain-finder
pip install -r requirements.txt
```

### Requirements

- Python 3.8 or higher
- atomhttp 1.0.1 or higher
- beautifulsoup4 4.12.0 or higher
- dnspython 2.4.0 or higher
- colorama 0.4.6 or higher
- build 1.0.0 or higher
- twine 4.0.0 or higher

## Usage

### Basic usage

```bash
subdomain.py -d example.com
```

### Advanced options

```bash
subdomain.py -d example.com -t 100 --max-pages 100 --random-agent
```

### Resume interrupted scan

```bash
subdomain.py -d example.com --resume
```

### Command line arguments

| Argument       | Description                             | Default  |
| -------------- | --------------------------------------- | -------- |
| -d, --domain   | Target domain (required)                | -        |
| -t, --threads  | Number of threads for DNS resolution    | 50       |
| -w, --wordlist | Custom wordlist file path               | list.txt |
| --timeout      | DNS timeout in seconds                  | 5        |
| --resume       | Resume from previous scan state         | False    |
| --max-pages    | Maximum pages to crawl                  | 50       |
| --random-agent | Use random User-Agent for HTTP requests | False    |

## Interactive Controls

When the tool is paused with Ctrl+C, the following menu appears:

| Command    | Action                                  |
| ---------- | --------------------------------------- |
| S / SKIP   | Skip current operation and move to next |
| E / END    | Stop current detection phase entirely   |
| N / NEXT   | Skip to next technique                  |
| C / CHANGE | Change output verbosity level           |
| R / RESUME | Resume current operation                |
| Q / QUIT   | Save state and exit                     |

### Force exit

Press Ctrl+C three times within 5 seconds to save state and force exit immediately.

## Output Structure

All results are saved in the `logs/` directory:

```
logs/
└── example.com/
    ├── result.txt        # Discovered subdomains with IPs
    ├── details.json      # Complete JSON report
    ├── state.pkl         # Serialized state for resume
    ├── raw_output.log    # Raw log with timestamps
    ├── crawled_urls.txt  # All crawled URLs
    └── dns_records.txt   # All DNS records found
```

### Result format

```
subdomain.example.com                   -> 192.168.1.1, 192.168.1.2 [technique]
mail.example.com                        -> 10.0.0.1 [crt.sh]
api.example.com                         -> 203.0.113.5 [bruteforce]
```

## Discovery Techniques Explained

### 1. HTML Crawler

Extracts subdomains from HTML responses, JavaScript code, JSON data, and link attributes. Crawls up to specified depth and verifies findings with DNS lookup.

### 2. DNS ANY Query

Performs ANY record queries to extract all DNS records including A, AAAA, CNAME, MX, NS, TXT, SOA, and attempts zone transfers from authoritative nameservers.

### 3. Certificate Transparency

Queries crt.sh certificate logs for subdomains that have been issued SSL/TLS certificates.

### 4. Wayback Machine

Fetches historical URLs from the Internet Archive to discover old or deprecated subdomains.

### 5. Public DNS Datasets

Queries public DNS datasets like BufferOver for historical DNS records.

### 6. Smart Permutations

Generates intelligent permutations based on already discovered subdomains (e.g., dev-www, api-admin).

### 7. Numeric Patterns

Tests common numeric patterns like ns1, ns2, server01, node02, etc.

### 8. Dictionary Bruteforce

Tests subdomains from a wordlist file with configurable thread pool and rate limiting.

## Wordlist

The tool automatically creates a default wordlist if none is provided:

```
www, mail, ftp, admin, blog, dev, test, api, cdn, vpn,
ns1, ns2, smtp, pop3, imap, webmail, cpanel, whm, mysql,
database, backup, storage, cloud, app, apps, portal, dashboard,
status, stats, monitor, monitoring, logs, metrics, trace,
jenkins, gitlab, github, jira, confluence, wiki, docs,
support, help, forum, community, news, shop, store,
checkout, payment, gateway, billing
```

You can provide your own wordlist with the `-w` parameter.

## Verbosity Levels

| Level | Output                                   |
| ----- | ---------------------------------------- |
| 0     | Results only (quiet mode)                |
| 1     | Basic progress information               |
| 2     | Detailed output with debugging (default) |

Change verbosity during scan with Ctrl+C then selecting option C.

## Logging

All operations are logged to the `logs/<domain>/` directory:

- **result.txt**: Clean list of discovered subdomains with IP addresses
- **details.json**: Complete structured data including timestamps and metadata
- **state.pkl**: Pickled state object for resume functionality
- **raw_output.log**: Timestamped log of all activities
- **crawled_urls.txt**: Complete list of URLs crawled
- **dns_records.txt**: All DNS records discovered during ANY queries

## Error Handling

The tool handles various error conditions gracefully:

- DNS timeouts - automatically retries up to 2 times
- Network errors - logs and continues
- HTTP errors - skips problematic URLs
- Keyboard interrupts - saves state and exits cleanly

## Legal Disclaimer

This tool is for educational and authorized testing purposes only. Usage for attacking targets without prior mutual consent is illegal. Users assume all liability and responsibility for any misuse or damage. Always obtain proper authorization before scanning any domain you do not own.

## License

MIT License

## Contributing

Contributions are welcome. Please submit pull requests or open issues on GitHub.
