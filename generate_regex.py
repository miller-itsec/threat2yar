# generate_regex.py
"""
This Python script automates the creation of YARA rules using OpenAI's GPT-3 model, tailored for cybersecurity analysis and research.

Key Features:
- Flexible Data Handling: Processes files from 'YARA_FOLDER' based on configurable patterns.
- String Clustering: Stores strings in buckets based on similarity, enhancing rule creation efficiency.
- Regex Filtering: Filters generated regexes based on complexity criteria for optimal rule quality.
- OpenAI Integration: Utilizes GPT-3 for regex generation and refinement, ensuring rule accuracy and effectiveness.
- Master Rule Refinement: Aggregates generated regexes into master rule files, refining them with OpenAI feedback.
- Organized Output: Systematically stores generated YARA rules in 'YARA_FOLDER'.

Configuration: Customize file patterns, API key, and folder paths in config.py.

Usage:
1. Configure the script via config.py with API key and file patterns.
2. Execute the script to process files and generate YARA rules.
3. Monitor API usage for efficient OpenAI utilization and compliance.

A versatile solution for automating YARA rule generation, enhancing cybersecurity analysis and research.

(c) Jan Miller (@miller_itsec) for OPSWAT, Inc.
"""
from common import is_unacceptable_string
from config import *
import os
import re
from openai import OpenAI
import Levenshtein
import datetime
import time


def current_datetime():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")


REGEX_MASTER_RULE_NAME = f"master_regex_rule_{current_datetime()}.yar"
REGEX_MASTER_RULE_PATH = os.path.join(YARA_FOLDER, REGEX_MASTER_RULE_NAME)


# Function to create OpenAI client
def create_openai_client(api_key):
    return OpenAI(api_key=api_key)


# Function to extract strings from YARA rule
def extract_strings_and_condition(rule_content):
    strings = re.findall(r'\$[^\s]+ = ([^\n]+)', rule_content)
    try:
        condition = re.search(r'condition:\s*(.*)', rule_content).group(1).strip()
    except AttributeError:
        return strings, None
    return strings, condition


# Function to calculate similarity
def calculate_similarity(str1, str2):
    return Levenshtein.ratio(str1, str2)


# Function to categorize string length
def categorize_string_length(string):
    if len(string) <= SMALL_STRING_MAX_LEN:
        return "short"
    elif len(string) <= MEDIUM_STRING_MAX_LEN:
        return "medium"
    else:
        return "long"


def is_regex_too_complex(regex):
    # Length check
    if len(regex) > MAX_REGEX_LENGTH or len(regex) < MIN_REGEX_LENGTH:
        print("Excluding regex, length not in threshold")
        return True

    # Nested Quantifiers
    if len(re.findall(r'\*|\+|\?|\{[\d,]+\}', regex)) > MAX_NESTED_QUANTIFIERS:
        print("Excluding regex, too many nested quantifiers found")
        return True

    # Advanced Constructs
    advanced_constructs = [r'\(\?\=.*?\)', r'\(\?\!.*?\)', r'\(\?\<\=.*?\)', r'\(\?\<\!.*?\)', r'\(\?\:.*?\)']
    for construct in advanced_constructs:
        if len(re.findall(construct, regex)) > MAX_ADVANCED_CONSTRUCTS:
            print("Excluding regex, too many advanced constructs found")
            return True

    # Escaped Characters
    if len(re.findall(r'\\.', regex)) > MAX_ESCAPED_CHARACTERS:
        print("Excluding regex, too many escaped sequences found")
        return True

    # Character Classes and Alternation
    if len(re.findall(r'\[.*?\]', regex)) + len(re.findall(r'\|', regex)) > MAX_CLASSES_ALTERNATION:
        print("Excluding regex, too many character classes and alternations found")
        return True

    return False


# Function to generate regex from a cluster
def generate_regex_for_cluster(cluster, openai_client):
    prompt = ("I need a regular expression that matches the following strings with high performance optimization: "
              + ", ".join(cluster) + ". The regex should be concise and optimized for performance and low false positive detection ratio, as it will be used in a security product."
                                     "However, if not possible to find a regex rule that covers all strings, it is okay to cover only the majority. "
                                     "Please only output the regex surrounded by the regex ``` code formatting. No explanation.")
    try:
        response = openai_client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[{"role": "user", "content": prompt}],
            timeout=API_REQUEST_TIMEOUT
        )
        if response.choices:
            response_content = response.choices[0].message.content.strip()
            # Extract regex using regular expression
            regex_match = re.search(r'```(?:regex)?\s*(.+?)\s*```', response_content, re.DOTALL)
            if regex_match:
                regex = regex_match.group(1).strip()
                return regex
            else:
                print("Regex pattern not found in response.")
                print(f"Response: {response_content}")
                return None
        else:
            print("No suitable response received from OpenAI.")
            return None
    except Exception as e:
        print(f"Error generating regex: {e}")
        return None


def print_cluster_statistics(clusters):
    print("\nCluster Statistics:")
    for length_category in clusters:
        print(f"\nCategory: {length_category}")
        for cluster_key, cluster_strings in clusters[length_category].items():
            print(f"  Cluster Key: {cluster_key}")
            print(f"    Cluster Size: {len(cluster_strings)}")
            print(f"    Strings in Cluster: {cluster_strings}")
    print("\nEnd of Cluster Statistics\n")


# Main clustering and regex generation logic
def process_yara_files(client):
    start_time = time.time()
    clusters = {"short": {}, "medium": {}, "long": {}}
    regex_patterns = []
    master_rule_seq = 1

    print("Starting YARA file processing...")

    for root, dirs, files in os.walk(YARA_FOLDER):
        for file in files:
            if file.endswith(".yar"):
                file_path = os.path.join(root, file)
                with open(file_path, 'r') as f:
                    rule_content = f.read()

                strings, condition = extract_strings_and_condition(rule_content)
                for string in strings:

                    if is_unacceptable_string(string):
                        continue

                    length_category = categorize_string_length(string)
                    string_added = False

                    for existing_string in clusters[length_category]:
                        if calculate_similarity(string, existing_string) >= STRING_SIMILARITY_THRESHOLD:
                            clusters[length_category][existing_string].append(string)
                            string_added = True
                            break

                    if not string_added:
                        clusters[length_category][string] = [string]

                # Check if any clusters have reached the minimum size for regex generation
                for length_category, cluster_group in clusters.items():
                    for cluster_key, cluster in cluster_group.items():
                        if len(cluster) >= MIN_CLUSTER_SIZE:
                            print(f"Generating regex for a cluster in '{length_category}' category...")
                            regex = generate_regex_for_cluster(cluster, client)
                            if regex:
                                if is_regex_too_complex(regex):
                                    print(f"Skipping inclusion of regex {regex}, as it does not meet the complexity criteria")
                                else:
                                    regex_patterns.append(regex)
                                display_strings = cluster[:3]
                                if len(cluster) > 3:
                                    display_strings.append("...")
                                print(f"Cluster: {display_strings}")
                                print(f"Generated regex: /{regex}/")
                                # Reset the cluster after generating regex
                                clusters[length_category][cluster_key] = []

                        if len(regex_patterns) >= MAX_REGEXES_PER_RULE:
                            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                            master_rule_filename = f"master_regex_rule_{timestamp}_{master_rule_seq}.yar"
                            master_rule_path = os.path.join(YARA_FOLDER, master_rule_filename)
                            rule_name = f"MasterRegexRule_{timestamp}_{master_rule_seq}"
                            # Construct the initial rule
                            initial_rule_content = "rule " + rule_name + " {\nstrings:\n"
                            for i, regex in enumerate(regex_patterns):
                                initial_rule_content += f"    $regex{i} = /{regex}/\n"
                            initial_rule_content += "condition:\n    any of them\n}"

                            # Create prompt for OpenAI
                            prompt = (
                                f"User\nPlease revise the rule and suggest an improved version. Ensure that meta-data fields, including the author name ({YARA_AUTHOR_NAME}), "
                                f"date, and version 1.0, are included within the YARA rule. Set a description meta-data based on an educated guess of the threat that the specific regex patterns "
                                f"may be targeting. You can also use a better rule name, but keep the timestamp and sequence number. Do not use fullword and output only the YARA rule. No explanation.\n\n{initial_rule_content}"
                            )

                            # Call OpenAI API
                            print("Requesting rule improvement from OpenAI...")
                            print(f"Prompt: {prompt}")
                            response = openai_client.chat.completions.create(
                                model=OPENAI_MODEL,
                                messages=[{"role": "user", "content": prompt}],
                                timeout=API_REQUEST_TIMEOUT
                            )
                            if response.choices:
                                revised_rule = response.choices[0].message.content.strip()
                                with open(master_rule_path, 'w') as master_rule_file:
                                    master_rule_file.write(revised_rule)
                                print(
                                    f"Improved master regex rule '{master_rule_filename}' created with {len(regex_patterns)} regexes.")
                            else:
                                print("No suitable response received from OpenAI for rule improvement.")

                            master_rule_seq += 1
                            regex_patterns.clear()

    end_time = time.time()
    print("Completed processing. Master regex rule created.")
    print(f"Total processing time: {end_time - start_time:.2f} seconds.")


# Entry point
if __name__ == "__main__":
    openai_client = create_openai_client(OPENAI_API_KEY)
    process_yara_files(openai_client)
