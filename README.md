<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Surge/main/docs/assets/logo-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Surge/main/docs/assets/logo-light.svg">
  <img alt="Surge" src="https://raw.githubusercontent.com/Real-Fruit-Snacks/Surge/main/docs/assets/logo-dark.svg" width="520">
</picture>

![JavaScript](https://img.shields.io/badge/language-JavaScript-f9e2af.svg)
![Platform](https://img.shields.io/badge/platform-Browser%20%7C%20PWA-lightgrey)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

**Markdown-to-command-reference with fuzzy search, variable substitution, and offline PWA**

Static web app that transforms markdown notes into a searchable, offline-first command reference. Fuzzy search powered by Fuse.js, `<variable>` substitution with workspace support, four Catppuccin themes, full keyboard navigation, and complete offline support via service worker. Edit in Obsidian, view in Surge.

[Quick Start](#quick-start) • [Features](#features) • [Architecture](#architecture) • [Configuration](#configuration) • [Reference Format](#reference-format) • [Tech Stack](#tech-stack)

</div>

---

## Highlights

<table>
<tr>
<td width="50%">

**Instant Fuzzy Search**
Search across titles, categories, tags, notes, and commands with real-time results powered by Fuse.js. Sub-50ms response times across the entire index.

**Four Catppuccin Themes**
Mocha (default), Macchiato, Frappe, and Latte. Click the title to cycle. Preference saved in localStorage. All colors via CSS custom properties.

**Obsidian Compatible**
Standard markdown with YAML frontmatter, inline tags, and callout syntax. Edit in Obsidian, view in Surge. No proprietary format.

**One-Click Copy**
Copy individual commands or entire procedures. Variables are automatically substituted with your current values before copying to clipboard.

</td>
<td width="50%">

**Variable System**
Define `<variables>` in commands. Workspace support lets you save different variable sets per environment (Lab, Production, etc.).

**Offline Support**
Full functionality without internet after first visit via service worker. All assets bundled locally. Zero external requests.

**Keyboard Driven**
Full keyboard navigation with arrow keys, Enter to expand, `c` to copy, `v` for variables, `w` for wrap, Esc to clear. Power user friendly.

**Smart Filtering**
Toggle visibility of procedures by custom tags. Filter state persists across sessions. Configurable default visibility per tag.

</td>
</tr>
</table>

---

## Quick Start

### Prerequisites

<table>
<tr>
<th>Requirement</th>
<th>Version</th>
<th>Purpose</th>
</tr>
<tr>
<td>Python</td>
<td>3.7+</td>
<td>Build script (standard library only)</td>
</tr>
<tr>
<td>Browser</td>
<td>Modern</td>
<td>Chrome, Firefox, Safari, Edge</td>
</tr>
</table>

### Build

```bash
# Clone repository
git clone https://github.com/Real-Fruit-Snacks/Surge.git
cd Surge

# Build search index from markdown notes
python3 build.py

# Start local server
python3 -m http.server 8080 --directory site

# Open browser
# http://localhost:8080
```

### Verification

```bash
# Check build output
ls -la site/commands.json

# Verify site serves correctly
curl -s http://localhost:8080 | head -5
```

---

## Features

| Feature | Description |
|---------|-------------|
| **Fuzzy search** | Real-time search across titles, categories, tags, and commands |
| **Variable substitution** | `<var>` syntax with workspace support for different environments |
| **Workspaces** | Save variable sets per environment (Lab, Production, etc.) |
| **Copy with substitution** | One-click copy replaces variables with current values |
| **Four Catppuccin themes** | Mocha, Macchiato, Frappe, Latte — click title to cycle |
| **Offline support** | Service worker caches everything for full offline use |
| **Keyboard navigation** | Arrow keys, Enter, c/w/v/Esc shortcuts for power users |
| **Tag filtering** | Toggle procedure visibility by custom tags |
| **Obsidian compatible** | YAML frontmatter, inline tags, callout syntax |
| **Syntax highlighting** | Bash, PowerShell, Python, and more via Highlight.js |
| **Code wrapping** | Toggle line wrapping on code blocks with `w` key |
| **History panel** | Track recently viewed procedures |
| **Analyzer panel** | Character analysis and MD5 hashing |
| **Zero dependencies** | No CDN, no runtime deps — everything bundled |

---

## Architecture

```
Surge/
├── build.py                          # Markdown parser and index generator
│
├── site/                             # ── Static Web Application ──
│   ├── index.html                    # Single-page shell
│   ├── app.js                        # Application logic (~1500 lines)
│   ├── config.js                     # Filter configuration (edit this!)
│   ├── styles.css                    # Catppuccin themes + styling
│   ├── commands.json                 # Generated search index (gitignored)
│   ├── sw.js                         # Service worker for offline support
│   └── vendor/                       # Bundled dependencies (Fuse.js, Highlight.js)
│
├── notes/                            # ── Markdown References ──
│   ├── *.md                          # Draft notes (ignored by build and git)
│   ├── _Archive/                     # Archived notes (ignored by build)
│   └── {Category}/                   # Organized by topic
│
├── docs/                             # ── GitHub Pages ──
│   ├── index.html                    # Project website
│   └── assets/
│       ├── logo-dark.svg             # Logo for dark theme
│       ├── logo-light.svg            # Logo for light theme
│       ├── banner-dark.svg           # Banner for dark theme
│       └── banner-light.svg          # Banner for light theme
│
└── .github/
    └── workflows/                    # GitHub Pages deployment
```

---

## Configuration

Customize Surge by editing `site/config.js`. This controls which tags can be filtered in the UI.

**Example configuration:**

```javascript
const TOGGLES = [
  { tag: 'Draft', label: 'Drafts', default: false },      // Hidden by default
  { tag: 'Reference', label: 'Reference', default: true }, // Visible by default
  { tag: 'Lab', label: 'Lab Notes', default: false },
];
```

Tag procedures in YAML frontmatter:

```yaml
---
tags:
  - Draft
  - Linux
---
```

The Filters dropdown will show toggles for each configured tag. Procedures with disabled filter tags are hidden from search results.

---

## Reference Format

Surge uses standard markdown with special conventions:

- `## H2` creates a procedure (main searchable card)
- `### H3` creates a step within a procedure
- Code blocks are syntax-highlighted and copyable
- `<variables>` in code blocks are highlighted and substitutable
- `> blockquote` creates styled notes
- `> [!warning]` creates Obsidian-style callouts

**Example:**

````markdown
---
tags: [networking, linux]
---

# Network Configuration

## SSH Connection Setup

> [!info] Standard SSH connection with port forwarding.

### Connect to Remote Host

```bash
ssh <user>@<remote_host> -p <port>
```

### Setup Port Forward [optional]

```bash
ssh -L <local_port>:localhost:<remote_port> <user>@<remote_host>
```
````

This creates a searchable procedure with two steps. The `[optional]` flag excludes the second step from "Copy All".

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| Search | Fuse.js 6.6.2 (fuzzy matching) |
| Syntax Highlighting | Highlight.js 11.8.0 |
| Build | Python 3.7+ (standard library only) |
| Theming | Catppuccin via CSS custom properties |
| Offline | Service worker with static cache |
| Hosting | Any static file server (GitHub Pages, GitLab, nginx) |

---

## Platform Support

<table>
<tr>
<th>Capability</th>
<th>Chrome</th>
<th>Firefox</th>
<th>Safari</th>
<th>Edge</th>
</tr>
<tr>
<td>Fuzzy Search</td>
<td>Full</td>
<td>Full</td>
<td>Full</td>
<td>Full</td>
</tr>
<tr>
<td>Variable Substitution</td>
<td>Full</td>
<td>Full</td>
<td>Full</td>
<td>Full</td>
</tr>
<tr>
<td>Service Worker / PWA</td>
<td>Full</td>
<td>Full</td>
<td>Limited</td>
<td>Full</td>
</tr>
<tr>
<td>Catppuccin Themes</td>
<td>Full</td>
<td>Full</td>
<td>Full</td>
<td>Full</td>
</tr>
<tr>
<td>Keyboard Navigation</td>
<td>Full</td>
<td>Full</td>
<td>Full</td>
<td>Full</td>
</tr>
<tr>
<td>Copy to Clipboard</td>
<td>Full</td>
<td>Full</td>
<td>Full</td>
<td>Full</td>
</tr>
<tr>
<td>Syntax Highlighting</td>
<td>Full</td>
<td>Full</td>
<td>Full</td>
<td>Full</td>
</tr>
</table>

---

## Security

### Vulnerability Reporting

**Report security issues via:**
- GitHub Security Advisories (preferred)
- Private disclosure to maintainers
- Responsible disclosure timeline (90 days)

**Do NOT:**
- Open public GitHub issues for vulnerabilities
- Disclose before coordination with maintainers

---

## License

MIT License

Copyright &copy; 2026 Real-Fruit-Snacks

```
THIS SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND.
THE AUTHORS ARE NOT LIABLE FOR ANY DAMAGES ARISING FROM USE.
```

---

## Resources

- **GitHub**: [github.com/Real-Fruit-Snacks/Surge](https://github.com/Real-Fruit-Snacks/Surge)
- **Issues**: [Report a Bug](https://github.com/Real-Fruit-Snacks/Surge/issues)
- **Security**: [SECURITY.md](SECURITY.md)
- **Contributing**: [CONTRIBUTING.md](CONTRIBUTING.md)
- **Changelog**: [CHANGELOG.md](CHANGELOG.md)

---

<div align="center">

**Part of the Real-Fruit-Snacks toolkit**

[Aquifer](https://github.com/Real-Fruit-Snacks/Aquifer) • [Cascade](https://github.com/Real-Fruit-Snacks/Cascade) • [Conduit](https://github.com/Real-Fruit-Snacks/Conduit) • [Deadwater](https://github.com/Real-Fruit-Snacks/Deadwater) • [Deluge](https://github.com/Real-Fruit-Snacks/Deluge) • [Depth](https://github.com/Real-Fruit-Snacks/Depth) • [Dew](https://github.com/Real-Fruit-Snacks/Dew) • [Droplet](https://github.com/Real-Fruit-Snacks/Droplet) • [Fathom](https://github.com/Real-Fruit-Snacks/Fathom) • [Flux](https://github.com/Real-Fruit-Snacks/Flux) • [Grotto](https://github.com/Real-Fruit-Snacks/Grotto) • [HydroShot](https://github.com/Real-Fruit-Snacks/HydroShot) • [Maelstrom](https://github.com/Real-Fruit-Snacks/Maelstrom) • [Rapids](https://github.com/Real-Fruit-Snacks/Rapids) • [Ripple](https://github.com/Real-Fruit-Snacks/Ripple) • [Riptide](https://github.com/Real-Fruit-Snacks/Riptide) • [Runoff](https://github.com/Real-Fruit-Snacks/Runoff) • [Seep](https://github.com/Real-Fruit-Snacks/Seep) • [Shallows](https://github.com/Real-Fruit-Snacks/Shallows) • [Siphon](https://github.com/Real-Fruit-Snacks/Siphon) • [Slipstream](https://github.com/Real-Fruit-Snacks/Slipstream) • [Spillway](https://github.com/Real-Fruit-Snacks/Spillway) • [Sunken-Archive](https://github.com/Real-Fruit-Snacks/Sunken-Archive) • **Surge** • [Tidemark](https://github.com/Real-Fruit-Snacks/Tidemark) • [Tidepool](https://github.com/Real-Fruit-Snacks/Tidepool) • [Undercurrent](https://github.com/Real-Fruit-Snacks/Undercurrent)

*Searchable command reference.*

</div>
