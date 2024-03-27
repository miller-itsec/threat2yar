# Threat2YAR: Automated Threat Data to YARA Pipeline

Welcome to `threat2yar`, an advanced pipeline for automating the download, conversion, and validation of various threat data into YARA rules, enhancing cybersecurity analysis and research.

## Pipeline Overview

`threat2yar` encompasses four main scripts, each with a distinct role in processing threat data:

1. **Download Data (`download.py`):** Retrieves threat data from specified sources.
2. **Generate YARA Rules (`convert_yara.py`):** Transforms threat descriptions into YARA rules.
3. **Validate YARA Rules (`validate_yara.py`):** Assesses rule quality and syntax.
4. **Generate Regex Rules (`generate_regex.py`):** Utilizes string similarity and OpenAI to generate regular expressions from extracted strings.

Each component contributes to a robust process for thorough threat analysis.

## Common Components

- **Configuration (`config.py`):** Centralized settings for the pipeline.
- **Common Functions (`common.py`):** Shared utilities across scripts.

## Stage 1: Download Data

**Script Name:** `download.py`

### Functionality:
- Automated download of threat data based on flexible URL patterns.
- Creation of placeholder files for missing data.
- Configurable local storage of downloaded data.

### Key Features:
- Rate control and TOR integration for discreet downloads.
- Multi-threaded approach for efficient data retrieval.

## Stage 2: Generate YARA Rules

**Script Name:** `convert_yara.py`

### Functionality:
- Processes downloaded threat data.
- Utilizes OpenAI's GPT-3.5-turbo model for YARA rule generation.
- Systematic storage of generated YARA rules.

### Key Features:
- Accurate and relevant YARA rule generation.
- Customizable settings for API interactions and data processing.

## Stage 3: Validate YARA Rules

**Script Name:** `validate_yara.py`

### Functionality:
- Syntax verification of YARA rules using YARA binary.
- Uses OpenAI API for automated error correction.
- Sorts YARA rules into categories based on syntax, content, and complexity.

### Key Features:
- Syntax validation and automatic correction process.
- Complexity analysis to filter out overly simplistic or convoluted rules.
- Organized categorization of rules for easy management.

## Stage 4: Generate Regex Rules

**Script Name:** `generate_regex.py`

### Functionality:
- Extracts strings from YARA rules and categorizes them based on similarity.
- Utilizes OpenAI API to generate regular expressions from string clusters.
- Filters regex rules based on complexity and relevance.

### Key Features:
- Efficient clustering of strings to optimize regex generation.
- Integration with OpenAI API for accurate regex generation.
- Automatic filtering of complex or irrelevant regex patterns.

## Command-Line Interface (CLI)

`cli.py` simplifies pipeline control, allowing direct command-line management of all stages.

### CLI Features:

- Unified access point for all pipeline stages.
- Customization options for parameters such as API key, download URL, and file patterns.
- Ability to run specific stages or the entire pipeline seamlessly.

### Usage:

Execute specific stages or the entire process via CLI:

```bash
python cli.py --api-key [Your_API_Key] --download-url [URL_Pattern] --min-id [Min_ID] --max-id [Max_ID] --file-pattern [File_Pattern] --stage [Stage]
```

### Example:

![Example](example.png?raw=true "Example output")
