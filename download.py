# download.py
"""
Automate data downloads from various sources with this adaptable script, perfect for cybersecurity research and data archiving.

Features:
- Automated Downloads: Cycles through IDs to fetch and store data.
- Throttling and Resilience: Manages download frequency and accommodates missing data.
- Random User-Agents & Optional TOR Use: Improves accessibility and maintains confidentiality.
- Efficient Parallel Downloads: Uses ThreadPoolExecutor for increased speed.
- Configurable Parameters: Allows customization of download URL, output naming, range of IDs, and more (configurable in config.py).

Usage:
- Set the required parameters in config.py, including URL pattern and file naming.
- Run the script in a Python environment with necessary dependencies installed.
- Progress is tracked and files are stored in the specified directory.

Note:
- The script is built for effective error handling. Ensure adherence to source websites' terms of service.

An essential resource for accumulating a diverse range of data for comprehensive analysis.

(c) Jan Miller (@miller_itsec) for OPSWAT, Inc.
"""
from config import *
import requests
import time
import os
import random
from concurrent.futures import ThreadPoolExecutor

if USE_TOR:
    import socks
    import socket
    socks.set_default_proxy(socks.SOCKS5, "localhost", 9050)
    socket.socket = socks.socksocket


def download_data(data_id):
    filename = os.path.join(DOWNLOAD_FOLDER, OUTPUT_FILE_PATTERN.format(data_id))
    url = DOWNLOAD_URL_PATTERN.format(data_id)
    headers = {'User-Agent': random.choice(USER_AGENTS)}
    try:
        print(f"Accessing {url}")
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            with open(filename, 'wb') as file:
                file.write(response.content)
            print(f"Downloaded data for ID {data_id}")
        elif response.status_code == 404:
            print(f"Data for ID {data_id} not found (404)")
            if not os.path.exists(filename) or os.path.getsize(filename) == 0:
                print(f"Creating placeholder {filename}...")
                with open(filename, 'w') as file:
                    pass  # Creating an empty file
            time.sleep(DELAY_NOT_FOUND)
        else:
            print(f"Failed to download data for ID {data_id}, status code: {response.status_code}")
            print("Response text:", response.text)
    except Exception as e:
        print(f"Error downloading data for ID {data_id}: {e}")


def main():
    if not os.path.exists(DOWNLOAD_FOLDER):
        os.makedirs(DOWNLOAD_FOLDER)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        for data_id in reversed(range(MIN_DATA_ID, MAX_DATA_ID + 1)):
            filename = os.path.join(DOWNLOAD_FOLDER, OUTPUT_FILE_PATTERN.format(data_id))
            if os.path.exists(filename):
                continue
            executor.submit(download_data, data_id)
            time.sleep(DELAY)


if __name__ == "__main__":
    main()
