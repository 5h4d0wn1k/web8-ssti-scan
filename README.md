# WEB8 — SSTI Scanner

Server-Side Template Injection detection for Jinja2, Twig, Mako, ERB, and other template engines.

## Overview

This project detects and exploits SSTI vulnerabilities across multiple template engines:
- **Detection** — Math evaluation tests to confirm injection
- **Engine identification** — Identify the template engine from error messages
- **Payload crafting** — RCE and file-read payloads per engine
- **RCE verification** — Execute commands to confirm exploitation
- **Batch scanning** — Multi-threaded scanning of multiple targets

## Supported Engines

- Jinja2 (Python/Flask/Django)
- Twig (PHP/Symfony)
- Mako (Python)
- ERB (Ruby/Rails)
- FreeMarker (Java)
- Velocity (Java)
- Smarty (PHP)

## Features

- Math-based injection detection (`{{7*7}}` = `49`)
- Automatic template engine fingerprinting
- Engine-specific RCE payload generation
- File read capabilities via SSTI
- Concurrent multi-target scanning
- Endpoint fuzzing with common paths/parameters

## Requirements

- Python 3.8+
- No external dependencies (standard library only)

## Usage

```bash
# Detect SSTI
python3 ssti_scanner.py --url "http://target/search?q=" --param q

# Show payloads for an engine
python3 ssti_scanner.py --payloads --engine jinja2

# Fuzz common paths and parameters
python3 ssti_scanner.py --fuzz http://target --param name,q,input
```

## Legal Disclaimer

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**. 

### Authorization Requirements
- You MUST have explicit written permission from the network owner before using this tool
- Unauthorized interception of network communications is illegal under federal and state laws
- This tool should ONLY be used on networks you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Wiretap Act (18 U.S.C. § 2511)**: Interception of electronic communications without consent is illegal
- **State Laws**: Many states have additional computer crime and wiretapping statutes
- **GDPR/CCPA**: Data collection may be subject to privacy regulations

### Acceptable Use
- Testing security of your own networks
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Intercepting communications on networks you do not own
- Attacking infrastructure without authorization
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
