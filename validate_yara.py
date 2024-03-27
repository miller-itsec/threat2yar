# validate_yara.py
"""
This script automates YARA rule management and validation.
It categorizes rules, checks syntax with the YARA binary, and utilizes OpenAI for syntax correction.

Features:
- Rule Management: Categorizes YARA rules based on content.
- Syntax Validation: Checks and fixes rule syntax with the YARA binary and OpenAI.
- Configurable Modes: Offers copy and silent modes for flexible file handling.

Folder Organization:
- 'non-cve': For rules lacking complete CVE IDs or containing placeholders.
- 'weak-rules': For rules with weak indicators like pe.imphash or hash.sha256.
- 'broken': For rules failing syntax validation, attempted to be fixed.
- Year-based folders: For organizing valid rules by CVE year.

Usage:
1. Set configurations in config.py.
2. Run the script where YARA rules are stored.

Modify as needed for additional functionalities. Ensure YARA binary installation for syntax checks.

(c) Jan Miller (@miller_itsec) for OPSWAT, Inc.
"""
from config import *
from common import *

import os
import re
import subprocess
import shutil
import tempfile
from openai import OpenAI


def create_openai_client(api_key):
    # Create an OpenAI client with the provided API key
    return OpenAI(api_key=api_key)


def read_file(file_path):
    # Read the content of the given file
    with open(file_path, 'r') as file:
        return file.read()


def move_or_copy_file(file_path, sub_folder, copy_mode, silent_mode):
    target_folder = os.path.join(YARA_FOLDER, sub_folder)
    target_path = os.path.join(target_folder, os.path.basename(file_path))
    action = "Copying" if copy_mode else "Moving"
    print(f"{action} '{file_path}' to '{target_path}'")
    if not silent_mode:
        initialize_folder(target_folder)
        if copy_mode:
            shutil.copy(file_path, target_path)
        else:
            os.rename(file_path, target_path)


def fix_yara_rule(rule_content, syntax_error, openai_client):
    prompt = (f"The following YARA rule has a syntax error:\n{rule_content}\n\n"
              f"The syntax error is: {syntax_error}. Please fix the YARA rule. "
              "If there are references to the pe module or undefined identifiers, please remove them. "
              "If the rule has an incomplete CVE ID in the meta-data, please remove it. "
              "In your response, please do not include anything else except the final YARA rule.")

    try:
        response = openai_client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[{"role": "user", "content": prompt}],
            timeout=API_REQUEST_TIMEOUT
        )
        if response.choices:
            return extract_yara_rule(response.choices[0].message.content.strip())
        else:
            return None
    except Exception as e:
        print(f"Error fixing YARA rule: {e}")
        return None


# Complexity Algorithm for YARA Rules:
# This algorithm calculates the complexity of a YARA rule's strings section.
# Complexity is measured based on the types and lengths of strings, and the conditions applied.
# - Byte arrays and longer human-readable strings are deemed more complex.
# - The condition ("all of" vs. "any of") influences the complexity score.
# - The total number of strings and their individual lengths also contribute to the score.
# This metric helps in filtering out overly simplistic or overly complex rules.
def calculate_complexity(rule_content):
    byte_array_weight = 3
    code_snippet_weight = 1
    file_path_weight = 0.5
    all_of_multiplier = 1.5  # Increase if the condition uses "all of them"

    # Extract strings and condition
    strings = re.findall(r'\$[^\s]+ = ([^\n]+)', rule_content)
    try:
        condition = re.search(r'condition:\s*(.*)', rule_content).group(1).strip()
    except AttributeError:
        return 0

    # Initialize complexity score
    total_complexity = 0

    # Evaluate complexity of each string
    for string in strings:
        # Exclude short strings
        if len(string) < 5:
            continue

        # Assign complexity weight
        if re.match(r'{[0-9A-Fa-f\s]+}', string):  # Byte array pattern
            weight = byte_array_weight
        elif re.match(r'\".*\"', string):  # Human-readable pattern
            weight = code_snippet_weight
        else:  # Assume file path or other
            weight = file_path_weight

        total_complexity += len(string) * weight

    # Adjust complexity based on condition
    if 'all of' in condition and len(strings) > 1:
        total_complexity *= all_of_multiplier

    return total_complexity


def check_rule_syntax(file_path, openai_client, attempt_fix=FIX_BAD_RULES):
    result = subprocess.run([YARA_BINARY_PATH, file_path, '.'], capture_output=True)
    if result.returncode == 0:
        print(f"Successfully validated {file_path} syntax")
        return True
    else:
        print(f"Error in YARA rule {file_path}:")
        print(result.stderr.decode().strip())
        if attempt_fix:
            with open(file_path, 'r') as file:
                original_content = file.read()
            print("Attempting to fix the YARA rule...")
            fixed_content = fix_yara_rule(original_content, result.stderr.decode(), openai_client)
            if fixed_content:
                print(f"Suggested fixed YARA rule:\n\n{fixed_content}")
                if is_unacceptable_yara_rule_response(fixed_content):
                    print(f"Unfortunately, the suggested fixed rule is insufficient")
                    return False
                with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.yar') as temp_file:
                    temp_file.write(fixed_content)
                    temp_file_path = temp_file.name
                if check_rule_syntax(temp_file_path, openai_client, False):
                    shutil.move(temp_file_path, file_path)
                    print(f"Successfully fixed the rule and updated {file_path}")
                    return True
                else:
                    os.remove(temp_file_path)  # Delete the temp file if not fixed
    return False


def process_files(copy_mode, silent_mode, client):
    for file_name in os.listdir(YARA_FOLDER):
        if file_name.endswith('.yar'):
            file_path = os.path.join(YARA_FOLDER, file_name)
            with open(file_path, 'r') as file:
                content = file.read()
            complexity = 0 if YARA_COMPLEXITY_THRESHOLD == 0 else calculate_complexity(content)
            if 0 < complexity < YARA_COMPLEXITY_THRESHOLD:
                print(f"Rule in {file_name} is below complexity threshold ({complexity} < {YARA_COMPLEXITY_THRESHOLD})")
                print(content)
                move_or_copy_file(file_path, OUTPUT_WEAK_RULES_FOLDER, copy_mode, silent_mode)
            elif any(weak_indicator in content for weak_indicator in ['pe.imphash', 'hash.sha256', 'cuckoo.']):
                move_or_copy_file(file_path, OUTPUT_WEAK_RULES_FOLDER, copy_mode, silent_mode)
            elif 'cve_id = "N/A"' in content or re.search(r'cve_id = "CVE-\d+-XXXX"', content):
                move_or_copy_file(file_path, OUTPUT_NON_CVE_FOLDER, copy_mode, silent_mode)
            elif not check_rule_syntax(file_path, client):
                move_or_copy_file(file_path, OUTPUT_BROKEN_RULES_FOLDER, copy_mode, silent_mode)
            else:
                match = re.search(r'CVE-(\d{4})-\d+', content)
                if match:
                    year = match.group(1)
                    move_or_copy_file(file_path, f"{OUTPUT_CVE_YEAR_PREFIX}{year}", copy_mode, silent_mode)


def initialize_folder(folder):
    if not os.path.exists(folder):
        os.makedirs(folder)


def main():
    api_key = OPENAI_API_KEY if OPENAI_API_KEY else os.getenv('OPENAI_API_KEY')
    if not api_key:
        print("OpenAI API key not found. Please set the API key.")
        return

    client = create_openai_client(api_key)

    # Initialize output folders
    initialize_folder(os.path.join(YARA_FOLDER, OUTPUT_NON_CVE_FOLDER))
    initialize_folder(os.path.join(YARA_FOLDER, OUTPUT_WEAK_RULES_FOLDER))
    initialize_folder(os.path.join(YARA_FOLDER, OUTPUT_BROKEN_RULES_FOLDER))

    # Process YARA files
    process_files(COPY_MODE, SILENT_MODE, client)


if __name__ == "__main__":
    main()
