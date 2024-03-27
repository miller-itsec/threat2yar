# common.py
"""
Common functions used in threat2yar

(c) Jan Miller (@miller_itsec) for OPSWAT, Inc.
"""


def read_file(file_path):
    with open(file_path, 'r') as file:
        return file.read()


def extract_yara_rule(response_text):
    start_token = "rule "
    end_token = "}"
    start_index = response_text.find(start_token)
    end_index = response_text.rfind(end_token)

    if start_index != -1 and end_index != -1:
        # Include the closing curly bracket in the extracted rule
        return response_text[start_index:end_index + len(end_token)].strip()
    else:
        return response_text.strip()


def is_unacceptable_yara_rule_response(yara_rule):
    error_conditions = [
        "No suitable response",  # General error
        "Shellcode bytes here", "/* bytes of the shellcode */", # Placeholder for shellcode bytes
        "$someString", "$string1", "$data", "CHANGE_ME",  # Generic strings
        "{ ? ? ? ? }", "{ DD DD DD DD }",  # Undefined byte sequences
        "$hashValue", "hash_here",  # Unspecified hash values
        "$ip", "ip_address_here",  # Generic IP addresses
        "domain.com", "url_here",  # Unspecific domains or URLs
        "/regex_pattern/", "$regex",  # Placeholder regular expressions
        "$filePath", "filepath_here",  # Unknown file paths
        "$filename", "filename.exe",  # Unspecific file names
        "your_IMPHASH", "$imphash",  # Placeholder import hashes
        "CVE-XXXX-XXXX", "CVE-????-????",  # Incomplete CVE numbers
        "$condition", "condition_here"  # Unspecified conditions
    ]

    return any(condition in yara_rule for condition in error_conditions)


def is_unacceptable_string(str):
    trash_strings = [
        "interesting string",
        "INSERT INTERESTING STRING",
        "shellcode bytes",
    ]

    return any(condition in str for condition in trash_strings)
