# Phishing Email Analyzer

A Python-based static email analysis tool that examines `.eml` files for suspicious authentication results, URLs, attachments, metadata, and contextual indicators.

The analyzer produces a weighted risk score from **0–40**, assigns a risk level, and generates a human-readable terminal report.

## Features

- Parses `.eml` email files
- Analyzes SPF, DKIM, and DMARC authentication results
- Detects missing, failed, or indeterminate authentication data
- Detects suspicious URL characteristics
- Detects risky attachment types
- Checks for missing or malformed email metadata
- Performs contextual analysis across multiple indicators
- Generates a weighted risk score and risk level
- Produces a readable terminal analysis report
- Handles multiple DKIM signatures and authentication results

## Requirements

- Python 3

The current version uses only Python standard-library modules and does not require external packages.

## Usage

Run the analyzer from the project directory and provide the path to an `.eml` file:

```bash
python main.py "path\to\email.eml"
```

Example:

```bash
python main.py "samples\sample.eml"
```

If no file is supplied, the program displays:

```text
Usage: python main.py <email.eml>
```

The analyzer only accepts `.eml` files.

## Risk Levels

| Score | Risk Level |
|---|---|------------|
| 0–10  | Low        |
| 11–19 | Medium     |
| 20–29 | High       |
| 30–40 | Critical   |

The risk score represents accumulated technical and contextual indicators. It is **not a definitive determination that an email is malicious**.

## Project Structure

```text
Email-Analyzer/
├── individual_analysis/
│   ├── __init__.py
│   ├── attachment_analysis.py
│   ├── authentication_analysis.py
│   ├── individual_indicators.py
│   ├── metadata_analysis.py
│   └── url_analysis.py
├── contextual_analysis.py
├── observations.py
├── read_email.py
├── risk_report.py
├── risk_score.py
├── main.py
├── README.md
└── .gitignore
```

## How It Works

The analyzer processes each email through a staged pipeline:

```text
.eml file
   ↓
Email parsing
   ↓
Raw observations
   ↓
Individual indicator analysis
   ↓
Contextual analysis
   ↓
Risk scoring
   ↓
Human-readable report
```

### 1. Email Parsing

`read_email.py` validates and parses the supplied `.eml` file using Python's email parsing library.

### 2. Observation Extraction

`observations.py` extracts raw information including:

- Sender
- Recipient
- Subject
- Date
- Message-ID
- Reply-To
- Return-Path
- SPF results
- DKIM results and signatures
- DMARC results
- Received headers
- URLs
- Attachments
- MIME body structure

### 3. Individual Analysis

Individual analysis modules examine observations independently.

#### Authentication

The analyzer evaluates:

- SPF failures
- SPF soft failures
- SPF errors
- Missing or indeterminate SPF results
- DKIM failures
- DKIM errors
- Missing or indeterminate DKIM results
- Multiple DKIM signatures
- DMARC failures
- DMARC errors
- Missing or indeterminate DMARC results

When a message does not contain a usable `DKIM-Signature` header but `Authentication-Results` contains a DKIM result, the analyzer can use that authentication result as fallback evidence.

#### URLs

URL analysis includes detection of:

- HTTP links
- IP-address-based URLs
- Punycode domains
- Known URL shorteners
- Links to suspicious file types
- Excessive subdomains
- Abnormally long URLs
- User information embedded inside URLs
- Missing hostnames

#### Attachments

The analyzer identifies potentially risky attachment categories including:

- Executables
- Scripts
- Macro-enabled Office documents
- Archives
- Disk images
- Other potentially dangerous file types
- Attachments with missing filenames

#### Metadata

Metadata checks include:

- Missing sender
- Malformed sender address
- Missing Message-ID
- Missing Date
- Missing Subject

### 4. Contextual Analysis

Some indicators become more meaningful when they appear together.

The analyzer currently detects contextual patterns including:

- From / Reply-To domain mismatch
- Multiple authentication failures
- Suspicious attachment and suspicious URL appearing together

### 5. Risk Scoring

Detected indicators are assigned weighted values based on their security significance.

Examples include:

- SPF failure: `+8`
- DKIM failure: `+8`
- DMARC failure: `+15`
- From / Reply-To domain mismatch: `+15`
- URL shortener: `+4`
- High-risk attachment extension: `+10`
- Multiple authentication failures: `+10`

Repeated indicators are generally counted once per subtype to prevent repeated URLs or attachments from artificially dominating the score.

DKIM failures are handled separately because an email may contain multiple independent DKIM signatures. The first definite DKIM failure receives the normal DKIM failure weight, while additional failed signatures contribute smaller additional amounts.

The raw score is retained internally. The displayed score is capped at **40**.

## Example Report

```text
============================================================
PHISHING EMAIL ANALYSIS REPORT
============================================================

EMAIL INFORMATION
------------------------------------------------------------
From: Microsoft Account Team <noreply@microsoftonline-verify.com>
To: user@example.com
Subject: [Action Required] Unusual sign-in activity on your account
Date: Fri, 06 Feb 2026 17:14:18 +0000

RISK ASSESSMENT
------------------------------------------------------------
Risk Score: 40/40
Risk Level: CRITICAL

SCORING BREAKDOWN
------------------------------------------------------------
- Spf Failure (+8)
- Dkim Failure (count: 1) (+8)
- Dmarc Failure (+15)
- Url Shortener (+4)
- Multiple Authentication Failures (+10)

INDIVIDUAL INDICATORS
------------------------------------------------------------
- Spf Failure [Severity: HIGH]
- Dkim Failure [Severity: HIGH]
- Dmarc Failure [Severity: HIGH]
- Url Shortener [Severity: MEDIUM]

CONTEXTUAL INDICATORS
------------------------------------------------------------
- Multiple Authentication Failures [Severity: HIGH]

EMAIL CONTENT SUMMARY
------------------------------------------------------------
URLs Found: 1
Attachments Found: 0

============================================================
This score represents detected risk indicators and does not
constitute a definitive determination that an email is malicious.
============================================================
```

## Testing

The analyzer has been tested against legitimate emails, bulk marketing messages, spam, and confirmed phishing samples.

During development, observed scores included:

| Sample Type | Score |
|---|---:|
| Legitimate email | 0 |
| Legitimate marketing email | 3 |
| Legitimate university marketing email | 6 |
| Legitimate forwarded/protected email | 11 |
| Confirmed phishing sample | 21 |
| Confirmed phishing sample | 21 |
| Confirmed phishing sample | 38 |
| Confirmed phishing sample | 40 |

These results were used to establish the current tentative risk thresholds.

The thresholds and indicator weights may be adjusted as additional real-world samples are tested.

## Limitations

This project performs **static email analysis**. It does not determine maliciousness with certainty.

The current version does not:

- Visit suspicious URLs
- Execute attachments
- Perform malware sandboxing
- Query domain or IP reputation services
- Query external threat-intelligence APIs
- Detect every form of social engineering
- Perform full brand-impersonation or typosquatting detection
- Guarantee that a low-risk message is safe
- Guarantee that a high-risk message is malicious

Legitimate emails can contain suspicious technical characteristics, while sophisticated phishing campaigns may use properly authenticated infrastructure.

The score should therefore be interpreted as accumulated evidence that can help guide further investigation.

## Security

Do not execute attachments or visit suspicious URLs while analyzing phishing samples.

Real-world email samples may contain:

- Active phishing links
- Personal information
- Tracking identifiers
- Malicious attachments
- Live attacker infrastructure

Sanitize email samples before publishing them publicly.

Test samples containing private email data or live phishing infrastructure should not be committed to the repository.

## Status

This project is under active development.

Potential future improvements include:

- Additional contextual detection rules
- Brand impersonation and typosquatting detection
- Domain and IP reputation lookups
- Report export
- Expanded automated testing
- Larger legitimate and phishing calibration datasets
- Improved command-line interface
- Additional email header analysis

## Disclaimer

This project is intended for cybersecurity education, defensive analysis, and research.

The generated score is a risk assessment based on observable indicators and should not be treated as a definitive verdict about whether an email is malicious.