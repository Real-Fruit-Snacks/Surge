# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in SURGE, please report it by emailing the maintainers directly rather than opening a public issue.

## Scope

SURGE is a static web application with no server-side code. Security considerations include:

- **XSS vulnerabilities** in the frontend rendering
- **Build script issues** that could execute malicious code from markdown files
- **Service worker** cache poisoning concerns

## Reference Content

The technical references in this repository document system administration and troubleshooting techniques for **authorized use only**. Users are responsible for:

- Obtaining proper authorization before performing system changes
- Complying with applicable laws and regulations
- Using techniques only in authorized environments (labs, production with approval)

## Supported Versions

Only the latest version on the `main` branch is actively maintained.
