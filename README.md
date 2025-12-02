# Twitter Scraper

This project is a Python-based tool for scraping data from Twitter and extracting cryptocurrency addresses from tweets and their replies.

## Features

- Fetches tweet data from a list of provided Twitter URLs.
- Extracts cryptocurrency addresses (BTC, ETH, SOL, TRON, XRP, ADA, LTC, DOGE, DOT, etc.) from tweets and user profiles.
- Gets all replies to specified tweets automatically.
- Uses API credentials from a configuration file.
- Saves scraped data into the `twitter_data` directory in JSON or CSV format.
- Generates a summary file for each batch of scraped data.
- Supports batch processing of multiple URLs.

## Project Structure

```
.
├── config.py.example   # Example configuration file (copy to config.py)
├── twitter_urls.txt    # List of Twitter URLs to scrape
├── twitterapi_io.py   # Main script for scraping
├── twitter_data/      # Directory for storing scraped data
├── .gitignore         # Git ignore file
└── README.md          # This file
```

## Setup

1.  **Clone the repository.**
2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
3.  **Configure API Credentials:**
    - Copy `config.py.example` to `config.py`:
      ```bash
      cp config.py.example config.py
      ```
    - Open `config.py` and add your Twitter API key:
      ```python
      api_key = "YOUR_API_KEY"
      ```
    - Get your API key from: https://twitterapi.io/dashboard (Note: This service requires payment)
4.  **Add URLs:**
    Open `twitter_urls.txt` and add the Twitter URLs you want to scrape, one URL per line.

## Usage

### Single URL Processing

To process a single Twitter URL:

```bash
python twitterapi_io.py --url "https://x.com/username/status/123456" --format csv
```

### Batch Processing

To process multiple URLs from a file:

```bash
python twitterapi_io.py --file twitter_urls.txt --format csv
```

### Command Line Options

- `--url`: Process a single Twitter URL
- `--file` or `-f`: Path to file containing Twitter URLs (default: `twitter_urls.txt`)
- `--format`: Output format - `json` or `csv` (default: `csv`)
- `--output` or `-o`: Output filename (optional, auto-generated if not specified)
- `--prefix`: Prefix for auto-generated filenames (default: `twitter_data`)

The script will read the URLs, fetch the data, extract cryptocurrency addresses, and save it in the `twitter_data` directory. A batch summary file will also be created in the same directory.

## Important Notes

- **API Service**: This project uses [twitterapi.io](https://twitterapi.io/dashboard) API service, which requires payment/credits to use.
- **Security**: Never commit `config.py` to version control. It contains your API key. Use `config.py.example` as a template.
