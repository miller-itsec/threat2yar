# convert_yara.py
"""
This Python script employs the OpenAI GPT-3.5-turbo model to automate the creation of YARA rules for a range of data files.
It's designed to generate accurate YARA rules from various data formats, making it versatile for experts and researchers.

Key Features:
- Flexible Data Handling: Processes files from 'EXPLOIT_FOLDER' based on configurable patterns.
- OpenAI Integration: Leverages GPT-3.5-turbo to generate YARA rules from file contents.
- Rule Customization: Targets specific characteristics of data to create relevant YARA rules, avoiding generic placeholders.
- Metadata Enrichment: Automatically includes essential metadata like descriptions, reference URLs, and CVE numbers in rules.
- Organized Output: Systematically stores generated YARA rules in 'YARA_FOLDER'.

Configuration: Customize file patterns, API key, folder paths, and more in config.py.

Usage:
1. Configure the script via config.py with API key and file patterns.
2. Execute the script to process files and generate YARA rules.
3. Monitor the query count for efficient use of the OpenAI API.

Note: Ensure the correct setup of the API key and comply with API usage limits.

A versatile and efficient solution for cybersecurity rule generation and analysis tasks.

(c) Jan Miller (@miller_itsec) for OPSWAT, Inc.
"""
from config import *
from common import *

import os
import re
import glob
import time
from openai import OpenAI


def create_openai_client(api_key):
    return OpenAI(api_key=api_key)


def create_yara_rule(threat_identifier, threat_number, threat_text, client):
    introduction = "I'm parsing threat investigations (e.g. exploits) and want to create YARA rules to detect them."
    instructions = (
        "Please suggest a solid YARA rule to detect re-usage of this threat in the wild "
        "by eg detecting the shellcode bytes, interesting strings, etc. It can be very specific, "
        "but be careful not to include server.com, your_ip or other placeholder in string detection rules."
    )
    meta_section = (
        "Into the Meta section, please add a description, a reference URL and description containing "
        "the CVE number and notes about the threat. The only acceptable meta keys are description, "
        "reference and cve_id."
    )
    rule_naming = (
        f"Make sure to have the rule name be {threat_identifier}_{threat_number}. "
        f"Do not use sub-rule syntax with a colon for the rule name, it has to be a clean rule name."
    )
    additional_instructions = (
        "Please avoid using specific placeholders like 'your_IP', 'your_server', or 'your_IMPHASH' in the rule. "
        "Do not require a specific starting byte/offset in the rule or anything that talks about replacing a variable "
        "with something."
    )
    final_request = "In your response, please do not include anything else except the final YARA rule."
    # Combine the prompt parts
    prompt = f"{introduction} {instructions} {meta_section} {rule_naming} {additional_instructions} {final_request}\n\n{threat_text}"
    try:
        response = client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[{"role": "user", "content": prompt}],
            timeout=API_REQUEST_TIMEOUT
        )
        if response.choices:
            # Directly extracting the message content
            message_content = response.choices[0].message.content
            return extract_yara_rule(message_content)
        else:
            return "No suitable response received from the API."
    except Exception as e:
        return f"Error generating YARA rule: {e}"


def write_yara_rule(file_name, yara_rule):
    with open(file_name, 'w') as file:
        file.write(yara_rule)


def main():
    api_key = OPENAI_API_KEY if OPENAI_API_KEY else os.getenv('OPENAI_API_KEY')
    if not api_key:
        print("OpenAI API key not found. Please set the API key.")
        return

    client = create_openai_client(api_key)
    if not os.path.exists(YARA_FOLDER):
        os.makedirs(YARA_FOLDER)

    pattern = FILE_PATTERN
    file_paths = glob.glob(os.path.join(DOWNLOAD_FOLDER, FILE_GLOB_PATTERN))
    file_paths.sort(key=lambda x: int(re.search(pattern, os.path.basename(x)).group(2)), reverse=True)

    if len(file_paths) == 0:
        print(f"No files found in {DOWNLOAD_FOLDER}")
        return

    query_count = 0
    for file_path in file_paths:
        file_name = os.path.basename(file_path)
        match = re.search(pattern, file_name)
        if not match:
            print(f"Filename does not match pattern: {file_name}")
            continue

        identifier = match.group(1)
        number = match.group(2)

        output_file_name = os.path.join(YARA_FOLDER, f"yara_{identifier}_{number}.yar")
        if os.path.exists(output_file_name):
            print(f"YARA rule already exists for {output_file_name}, skipping.")
            continue

        file_size_kb = os.path.getsize(file_path) / 1024
        if file_size_kb / 1024 >= SKIP_FILES_LARGER_THAN_KB:
            print(f"Skipping {file_path} as its file size ({file_size_kb} KB) exceeds the threshold ({SKIP_FILES_LARGER_THAN_KB}")
            continue

        try:
            exploit_text = read_file(file_path)
        except IOError as e:
            print(f"Error reading {file_path}: {e}")
            continue
        except UnicodeDecodeError as e:
            print(f"Error reading {file_path}: {e}")
            continue

        if len(exploit_text) <= 0:
            print(f"Skipping empty file {file_path}")
            continue

        print(f"Converting {file_path} to YARA rule {output_file_name} ...")
        yara_rule = create_yara_rule(identifier, number, exploit_text, client)
        if is_unacceptable_yara_rule_response(yara_rule):
            print(f"Failed to generate sufficient YARA rule for {file_path}: {yara_rule}")
            # TODO: deal with "This model's maximum context length is 16385 tokens. However, your messages resulted in XXX tokens"
        else:
            write_yara_rule(output_file_name, yara_rule)
            print(f"YARA Rule for {file_path}:\n{yara_rule}\n")
            print(f"YARA Rule saved in {output_file_name}")

        time.sleep(DELAY_QUERY_IN_SECONDS)
        query_count += 1
        if query_count >= MAX_QUERIES_PER_RUN:
            print(f"Aborting, as we performed {MAX_QUERIES_PER_RUN} queries")
            return


if __name__ == "__main__":
    main()
