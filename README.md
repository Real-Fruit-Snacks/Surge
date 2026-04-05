<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Surge/main/docs/assets/logo-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Surge/main/docs/assets/logo-light.svg">
  <img alt="Surge" src="https://raw.githubusercontent.com/Real-Fruit-Snacks/Surge/main/docs/assets/logo-dark.svg" width="520">
</picture>

![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=flat&logo=javascript&logoColor=black)
![Platform](https://img.shields.io/badge/platform-Browser%20%7C%20PWA-lightgrey)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

**Searchable command reference with fuzzy search, variable substitution, and offline PWA**

Static web app that transforms markdown notes into a searchable, offline-first command reference.
Fuzzy search powered by Fuse.js, `<variable>` substitution with workspace support, four Catppuccin
themes, full keyboard navigation, and complete offline support via service worker. Edit notes in
Obsidian, view them in Surge.

</div>

---

## Quick Start

### Prerequisites

- Python 3.7+ (standard library only, for the build script)
- Any modern browser (Chrome, Firefox, Safari, Edge)

### Build and Run

```bash
git clone https://github.com/Real-Fruit-Snacks/Surge.git
cd Surge

# Build search index from markdown notes
python3 build.py

# Start local server
python3 -m http.server 8080 --directory site

# Open http://localhost:8080
```

### Verify

```bash
ls -la site/commands.json    # check generated index
curl -s http://localhost:8080 | head -5
```

---

## Features

### Fuzzy Search

Real-time search across titles, categories, tags, notes, and commands powered by Fuse.js. Sub-50ms response times across the entire index with highlighted matches and relevance ranking.

```
Type in the search bar to filter procedures instantly.
Results ranked by relevance with matched terms highlighted.
Search covers: title, category, tags, notes, commands.
```

### Variable Substitution

Define `<variables>` in commands that get highlighted in the UI. Set values once and they auto-substitute into every command on copy. Workspace support lets you save different variable sets per environment.

```bash
# Template with variables
ssh <user>@<remote_host> -p <port>

# After setting variables: user=admin, remote_host=10.0.0.1, port=22
ssh admin@10.0.0.1 -p 22
```

### Workspaces

Save named variable sets for different environments. Switch between Lab, Production, and custom workspaces without re-entering values each time.

```
Workspace: Lab
  <target_ip>  = 10.0.0.50
  <user>       = admin

Workspace: Production
  <target_ip>  = 192.168.1.100
  <user>       = deploy
```

### Four Catppuccin Themes

Mocha (default), Macchiato, Frappe, and Latte. Click the title to cycle through themes. Preference is saved in localStorage. All colors are driven by CSS custom properties.

```css
/* Theme switching via CSS custom properties */
:root {
  --ctp-base: #1e1e2e;      /* Mocha */
  --ctp-text: #cdd6f4;
  --ctp-mauve: #cba6f7;
}
```

### Keyboard Navigation

Full keyboard-driven workflow for power users. No mouse required for common operations:

```
/          →  focus search bar
Arrow keys →  navigate procedures
Enter      →  expand/collapse procedure
c          →  copy command to clipboard
v          →  open variable panel
w          →  toggle code line wrapping
Escape     →  clear search / close panels
```

### Offline Support

Full functionality without internet after first visit. Service worker caches all assets locally. Zero external requests at runtime -- everything is bundled into the static site.

```javascript
// sw.js caches all static assets on install
const CACHE_FILES = [
  '/', '/app.js', '/styles.css',
  '/commands.json', '/vendor/fuse.js',
  '/vendor/highlight.min.js'
];
```

### Tag Filtering

Toggle visibility of procedures by custom tags. Filter state persists across sessions. Configure default visibility per tag in `site/config.js`.

```javascript
// site/config.js
const TOGGLES = [
  { tag: 'Draft', label: 'Drafts', default: false },
  { tag: 'Reference', label: 'Reference', default: true },
  { tag: 'Lab', label: 'Lab Notes', default: false },
];
```

### One-Click Copy

Copy individual commands or entire procedures with a single click. Variables are automatically substituted with current workspace values before copying. Visual toast notification confirms the copy action.

---

## Reference Format

Surge uses standard markdown with YAML frontmatter. Notes are fully compatible with Obsidian.

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

- `## H2` headings create searchable procedure cards
- `### H3` headings create steps within a procedure
- Code blocks are syntax-highlighted and copyable
- `<variables>` in code blocks are highlighted and substitutable
- `> [!warning]` creates Obsidian-style callouts
- `[optional]` flag on step headings excludes from "Copy All"

---

## Architecture

```
Surge/
├── build.py               # Markdown parser and index generator
├── site/                  # Static web application
│   ├── index.html         # Single-page shell
│   ├── app.js             # Application logic (~1500 lines)
│   ├── config.js          # Filter tag configuration
│   ├── styles.css         # Catppuccin themes and styling
│   ├── commands.json      # Generated search index (gitignored)
│   ├── sw.js              # Service worker for offline support
│   └── vendor/            # Bundled Fuse.js and Highlight.js
├── notes/                 # Markdown source files by category
└── docs/                  # GitHub Pages project site
```

The build script (`build.py`) parses markdown files from `notes/` into a JSON index consumed by the single-page app. No runtime server required -- the entire application is static files that can be served from any web server, GitHub Pages, or opened locally.

---

## Platform Support

| Capability | Chrome | Firefox | Safari | Edge |
|------------|--------|---------|--------|------|
| Fuzzy Search | Full | Full | Full | Full |
| Variable Substitution | Full | Full | Full | Full |
| Service Worker / PWA | Full | Full | Limited | Full |
| Catppuccin Themes | Full | Full | Full | Full |
| Keyboard Navigation | Full | Full | Full | Full |
| Copy to Clipboard | Full | Full | Full | Full |
| Syntax Highlighting | Full | Full | Full | Full |

---

## License

[MIT](LICENSE) — Copyright 2026 Real-Fruit-Snacks
