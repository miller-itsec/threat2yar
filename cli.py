# cli.py
"""
The `cli.py` script offers a convenient way to control and automate the pipeline stages directly from the command line.

(c) Jan Miller (@miller_itsec) for OPSWAT, Inc.
"""

import os
import argparse
import download
import convert_yara
import validate_yara
import generate_regex
import importlib
import config

def run_download():
    download.main()

def run_convert_yara():
    convert_yara.main()

def run_validate_yara():
    validate_yara.main()

def run_generate_regex():
    generate_regex.main()

def set_environment_vars(args):
    if args.api_key:
        os.environ['OPENAI_API_KEY'] = args.api_key
    if args.model:
        os.environ['OPENAI_MODEL'] = args.model
    if args.api_request_timeout:
        os.environ['API_REQUEST_TIMEOUT'] = str(args.api_request_timeout)
    if args.download_url_pattern:
        os.environ['DOWNLOAD_URL_PATTERN'] = args.download_url_pattern
    if args.output_file_pattern:
        os.environ['OUTPUT_FILE_PATTERN'] = args.output_file_pattern
    if args.min_data_id:
        os.environ['MIN_DATA_ID'] = str(args.min_data_id)
    if args.max_data_id:
        os.environ['MAX_DATA_ID'] = str(args.max_data_id)
    if args.max_workers:
        os.environ['MAX_WORKERS'] = str(args.max_workers)
    if args.delay:
        os.environ['DELAY'] = str(args.delay)
    if args.delay_not_found:
        os.environ['DELAY_NOT_FOUND'] = str(args.delay_not_found)
    if args.use_tor:
        os.environ['USE_TOR'] = str(args.use_tor)
    if args.download_folder:
        os.environ['DOWNLOAD_FOLDER'] = args.download_folder
    if args.yara_folder:
        os.environ['YARA_FOLDER'] = args.yara_folder
    if args.file_pattern:
        os.environ['FILE_PATTERN'] = args.file_pattern
    if args.file_glob_pattern:
        os.environ['FILE_GLOB_PATTERN'] = args.file_glob_pattern
    if args.max_queries_per_run:
        os.environ['MAX_QUERIES_PER_RUN'] = str(args.max_queries_per_run)
    if args.delay_query_in_seconds:
        os.environ['DELAY_QUERY_IN_SECONDS'] = str(args.delay_query_in_seconds)
    if args.skip_files_larger_than_kb:
        os.environ['SKIP_FILES_LARGER_THAN_KB'] = str(args.skip_files_larger_than_kb)
    if args.output_non_cve_folder:
        os.environ['OUTPUT_NON_CVE_FOLDER'] = args.output_non_cve_folder
    if args.output_weak_rules_folder:
        os.environ['OUTPUT_WEAK_RULES_FOLDER'] = args.output_weak_rules_folder
    if args.output_broken_rules_folder:
        os.environ['OUTPUT_BROKEN_RULES_FOLDER'] = args.output_broken_rules_folder
    if args.output_cve_year_prefix:
        os.environ['OUTPUT_CVE_YEAR_PREFIX'] = args.output_cve_year_prefix
    if args.yara_binary_path:
        os.environ['YARA_BINARY_PATH'] = args.yara_binary_path
    if args.copy_mode is not None:
        os.environ['COPY_MODE'] = str(args.copy_mode)
    if args.silent_mode is not None:
        os.environ['SILENT_MODE'] = str(args.silent_mode)
    if args.fix_bad_rules is not None:
        os.environ['FIX_BAD_RULES'] = str(args.fix_bad_rules)

def main():
    parser = argparse.ArgumentParser(description='Threat2YAR: CLI for Automated Threat Data to YARA Pipeline')
    parser.add_argument('--api-key', type=str, help='OpenAI API Key')
    parser.add_argument('--model', type=str, default='gpt-3.5-turbo-16k', help='OpenAI Model')
    parser.add_argument('--api-request-timeout', type=int, help='Timeout for OpenAI API requests in seconds')
    parser.add_argument('--download-url-pattern', type=str, help='URL pattern for downloading data')
    parser.add_argument('--output-file-pattern', type=str, help='Output file naming pattern')
    parser.add_argument('--min-data-id', type=int, help='Minimum data ID for download range')
    parser.add_argument('--max-data-id', type=int, help='Maximum data ID for download range')
    parser.add_argument('--max-workers', type=int, help='Maximum number of worker threads for downloading')
    parser.add_argument('--delay', type=int, help='Delay between download requests in seconds')
    parser.add_argument('--delay-not-found', type=int, help='Delay when a download ID is not found')
    parser.add_argument('--use-tor', type=bool, help='Whether to use TOR for downloading')
    parser.add_argument('--download-folder', type=str, help='Folder for downloaded data')
    parser.add_argument('--yara-folder', type=str, help='Folder for YARA rules output')
    parser.add_argument('--file-pattern', type=str, help='Pattern for identifying data files')
    parser.add_argument('--file-glob-pattern', type=str, help='Glob pattern for data files')
    parser.add_argument('--max-queries-per-run', type=int, help='Maximum number of OpenAI queries per run')
    parser.add_argument('--delay-query-in-seconds', type=float, help='Delay in seconds between OpenAI queries')
    parser.add_argument('--skip-files-larger-than-kb', type=int, help='Skip files larger than this size in KB')
    parser.add_argument('--output-non-cve-folder', type=str, help='Folder for non-CVE YARA rules')
    parser.add_argument('--output-weak-rules-folder', type=str, help='Folder for weak YARA rules')
    parser.add_argument('--output-broken-rules-folder', type=str, help='Folder for broken YARA rules')
    parser.add_argument('--output-cve-year-prefix', type=str, help='Prefix for CVE year folders')
    parser.add_argument('--yara-binary-path', type=str, default='/opt/homebrew/bin/yara', help='Path to YARA binary')
    parser.add_argument('--copy-mode', type=bool, help='Whether to copy files instead of moving')
    parser.add_argument('--silent-mode', type=bool, help='Whether to operate in silent mode')
    parser.add_argument('--fix-bad-rules', type=bool, help='Whether to attempt fixing bad YARA rules')
    parser.add_argument('--stage', choices=['download', 'convert', 'validate', 'regex', 'all'], help='Pipeline stage to run')

    args = parser.parse_args()
    set_environment_vars(args)
    importlib.reload(config)

    if args.stage == 'download':
        run_download()
    elif args.stage == 'convert':
        run_convert_yara()
    elif args.stage == 'validate':
        run_validate_yara()
    elif args.stage == 'regex':
        run_generate_regex()
    elif args.stage == 'all':
        run_download()
        run_convert_yara()
        run_validate_yara()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
