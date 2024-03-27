# config.py
"""
Configuration Settings for threat2year's threat analysis pipeline

This configuration file centralizes settings used across the scripts in the pipeline:
- download.py: For downloading exploits.
- convert_yara.py: For converting exploits to YARA rules.
- validate_yara.py: For validating and organizing YARA rules.

General Configuration:
- OPENAI_API_KEY: The API key for accessing OpenAI's GPT-3.5-turbo model.
- API_REQUEST_TIMEOUT: Timeout in seconds for OpenAI API requests.

download.py Configuration:
- MAX_EXPLOIT_ID: The highest ID to attempt to download from the exploit database.
- MIN_EXPLOIT_ID: The starting ID for downloading exploits.
- MAX_WORKERS: Maximum number of concurrent download threads.
- DELAY: Delay in seconds between individual download attempts.
- DELAY_NOT_FOUND: Additional delay in seconds for handling 404 responses.
- EXPLOIT_FOLDER: Folder name where downloaded exploit files are stored.
- USE_TOR: Boolean flag to indicate whether to use TOR for downloading exploits.
- USER_AGENTS: List of user agent strings to be used randomly in download requests.

convert_yara.py Configuration:
- DELAY_SECONDS: Delay in seconds between creating YARA rules to manage API rate.
- YARA_FOLDER: Folder where generated YARA rules will be saved.
- MAX_QUERIES_PER_RUN: Maximum number of queries to execute in a single script run.

validate_yara.py Configuration:
- YARA_BINARY_PATH: File path to the YARA binary used for rule validation.
- COPY_MODE: Boolean flag to copy (True) or move (False) files during organization.
- SILENT_MODE: Boolean flag for silent mode operation (only print actions).

Output Folders for validate_yara.py:
- OUTPUT_NON_CVE_FOLDER: Folder for rules that lack a complete CVE ID.
- OUTPUT_WEAK_RULES_FOLDER: Folder for rules with weak or generic indicators.
- OUTPUT_BROKEN_RULES_FOLDER: Folder for rules that failed syntax validation.
- OUTPUT_CVE_YEAR_PREFIX: Prefix for folders organizing rules by year of CVE.

Note: Adjust these configurations based on your specific requirements and environment.
Ensure that sensitive information, such as OPENAI_API_KEY, is securely managed.

(c) Jan Miller (@miller_itsec) for OPSWAT, Inc.
"""
import os

###
# General Configuration
###
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY', '')
OPENAI_MODEL = os.getenv('OPENAI_MODEL', 'gpt-3.5-turbo-16k')
API_REQUEST_TIMEOUT = int(os.getenv('API_REQUEST_TIMEOUT', 20))  # in seconds

###
# Configuration for download.py and convert_yara.py
###
DOWNLOAD_URL_PATTERN = os.getenv('DOWNLOAD_URL_PATTERN', 'https://www.exploit-db.com/exploits/{}')  # Use {} as placeholder for ID
OUTPUT_FILE_PATTERN = os.getenv('OUTPUT_FILE_PATTERN', 'exploit_{}.txt')  # Example: 'data_123.txt'
MIN_DATA_ID = int(os.getenv('MIN_DATA_ID', 1))
MAX_DATA_ID = int(os.getenv('MAX_DATA_ID', 51917))
MAX_WORKERS = int(os.getenv('MAX_WORKERS', 5))
DELAY = int(os.getenv('DELAY', 1))
DELAY_NOT_FOUND = int(os.getenv('DELAY_NOT_FOUND', 10))
USE_TOR = os.getenv('USE_TOR', 'False') == 'True'
DOWNLOAD_FOLDER = os.getenv('DOWNLOAD_FOLDER', 'download-db')
YARA_FOLDER = os.getenv('YARA_FOLDER', 'yara-db')
PERFORM_DOMAIN_DOWNLOAD = False
DOMAIN_DOWNLOAD_FILE_NAME = 'domains.txt'

# Randomly pick a user agent
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.2 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.135 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Linux; Android 10; SM-G981B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.152 Mobile Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36'
]

######
# Configuration for convert_yara.py
###
# Note: make sure the pattern matches the OUTPUT_FILE_PATTERN above
FILE_PATTERN = os.getenv('FILE_PATTERN', r'(.+)_(\d+)')
FILE_GLOB_PATTERN = os.getenv('FILE_GLOB_PATTERN', '*.txt')
# Note: this is to avoid exhaustion of OpenAPI queries. Re-running the script is safe, as duplicate work is avoided
MAX_QUERIES_PER_RUN = int(os.getenv('MAX_QUERIES_PER_RUN', 15000))
DELAY_QUERY_IN_SECONDS = float(os.getenv('DELAY_QUERY_IN_SECONDS', 0.2))
SKIP_FILES_LARGER_THAN_KB = int(os.getenv('SKIP_FILES_LARGER_THAN_KB', 16))

######
# Configuration for validate_yara.py
###
OUTPUT_NON_CVE_FOLDER = os.getenv('OUTPUT_NON_CVE_FOLDER', 'non-cve')
OUTPUT_WEAK_RULES_FOLDER = os.getenv('OUTPUT_WEAK_RULES_FOLDER', 'weak-rules')
OUTPUT_BROKEN_RULES_FOLDER = os.getenv('OUTPUT_BROKEN_RULES_FOLDER', 'broken')
OUTPUT_CVE_YEAR_PREFIX = os.getenv('OUTPUT_CVE_YEAR_PREFIX', 'year-')

# Define a "weak" rule based on its complexity (0 = allow all)
YARA_COMPLEXITY_THRESHOLD = 100

YARA_BINARY_PATH = os.getenv('YARA_BINARY_PATH', '/opt/homebrew/bin/yara')
COPY_MODE = os.getenv('COPY_MODE', 'True') == 'True'
SILENT_MODE = os.getenv('SILENT_MODE', 'True') == 'True'
FIX_BAD_RULES = os.getenv('FIX_BAD_RULES', 'True') == 'True'

######
# Configuration for generate_regex.py
###
YARA_AUTHOR_NAME = "Generated by OpenAI and threat2yar for OPSWAT, Inc."
STRING_SIMILARITY_THRESHOLD = 0.7  # Adjust as needed
MIN_CLUSTER_SIZE = 10  # Minimum size for a cluster to trigger regex generation
SMALL_STRING_MAX_LEN = 20
MEDIUM_STRING_MAX_LEN = 100
MAX_REGEXES_PER_RULE = 10
MAX_REGEX_LENGTH = 150
MIN_REGEX_LENGTH = 20
MAX_NESTED_QUANTIFIERS = 3
MAX_ADVANCED_CONSTRUCTS = 2
MAX_ESCAPED_CHARACTERS = 10
MAX_CLASSES_ALTERNATION = 20
