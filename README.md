<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Surge/main/docs/assets/logo-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Surge/main/docs/assets/logo-light.svg">
  <img alt="Surge" src="https://raw.githubusercontent.com/Real-Fruit-Snacks/Surge/main/docs/assets/logo-dark.svg" width="100%">
</picture>

> [!IMPORTANT]
> **Searchable command reference with fuzzy search, variable substitution, and offline PWA.** Static web app that transforms markdown notes into a searchable, offline-first command reference. Edit notes in Obsidian, view them in Surge.

> *Edit your notes in one tab, surge through them in another. Felt fitting for a static index that takes you from "I know I had this command" to clipboard in two keystrokes.*

---

## §1 / Premise

Surge is a **static command reference** generated from markdown notes. Drop notes into `notes/`, run `python3 build.py`, and the site has a fuzzy search index covering titles, categories, tags, notes, and code blocks. `<variable>` placeholders are highlighted in the UI; set values once and they auto-substitute on copy. Workspaces save named variable sets per environment (Lab, Production, custom).

Fuse.js drives the fuzzy search with sub-50 ms response across the full index. A service worker caches everything for full offline use after the first visit. Notes are standard markdown with YAML frontmatter — fully Obsidian-compatible.

▶ **[Live demo](https://Real-Fruit-Snacks.github.io/Surge/)**

---

## §2 / Specs

| KEY        | VALUE                                                                       |
|------------|-----------------------------------------------------------------------------|
| SEARCH     | **Fuse.js** · sub-50 ms · ranks across title · category · tags · notes · commands |
| VARIABLES  | `<placeholder>` highlight · auto-substitute on copy · per-workspace values  |
| WORKSPACES | Saved variable sets · switch between Lab / Production / custom              |
| THEMES     | **4 Catppuccin flavors** · Mocha · Macchiato · Frappé · Latte               |
| OFFLINE    | Service worker · cache-first · zero external requests at runtime            |
| FORMAT     | Standard markdown + YAML frontmatter · Obsidian-compatible                  |
| BUILD      | **Python 3.7+** standard library only · no Node, no npm                     |
| STACK      | **Vanilla JS** · Fuse.js + Highlight.js (vendored) · MIT                    |

Architecture in §5 below.

---

## §3 / Quickstart

```bash
git clone https://github.com/Real-Fruit-Snacks/Surge.git
cd Surge

# Build search index from markdown notes
python3 build.py

# Start local server
python3 -m http.server 8080 --directory site

# Open http://localhost:8080
```

Verify:

```bash
ls -la site/commands.json     # check generated index
curl -s http://localhost:8080 | head -5
```

---

## §4 / Reference

```
KEYBOARD

  /                    Focus search bar
  Arrow keys           Navigate procedures
  Enter                Expand / collapse procedure
  c                    Copy command to clipboard
  v                    Open variable panel
  w                    Toggle code line wrapping
  Escape               Clear search / close panels

VARIABLE TEMPLATE

  ssh <user>@<remote_host> -p <port>
  →   ssh admin@10.0.0.1 -p 22

  Workspace: Lab          Workspace: Production
    <target_ip>=10.0.0.50   <target_ip>=192.168.1.100
    <user>=admin            <user>=deploy

NOTE FORMAT

  ---
  tags: [networking, linux]
  ---
  ## H2  → searchable procedure card
  ### H3 → step within a procedure
  ```bash → syntax-highlighted, copyable code block
  > [!warning] → Obsidian-style callout
  [optional] flag on step heading → excluded from "Copy All"

TAG FILTERING

  site/config.js
    { tag: 'Draft',      label: 'Drafts',     default: false }
    { tag: 'Reference',  label: 'Reference',  default: true  }
    { tag: 'Lab',        label: 'Lab Notes',  default: false }
```

---

## §5 / Architecture

```
Surge/
  build.py                  Markdown parser and index generator
  site/
    index.html              Single-page shell
    app.js                  Application logic (~1500 lines)
    config.js               Filter tag configuration
    styles.css              Catppuccin themes and styling
    commands.json           Generated search index (gitignored)
    sw.js                   Service worker for offline support
    vendor/                 Bundled Fuse.js and Highlight.js
  notes/                    Markdown source files by category
  docs/                     GitHub Pages project site
```

| Layer        | Implementation                                                  |
|--------------|-----------------------------------------------------------------|
| **Build**    | `build.py` parses markdown → `site/commands.json` index         |
| **Search**   | Fuse.js · runs in-browser · matches highlighted in results      |
| **Vars**     | `<placeholder>` syntax · per-workspace values · clipboard substitution on copy |
| **Themes**   | CSS custom properties · click title to cycle · localStorage persistence |
| **Offline**  | Service worker pre-caches all static assets on install          |
| **Deploy**   | Static — any web server, GitHub Pages, or local file            |

**Key patterns:** No runtime server. The build step parses your `notes/` and writes one JSON index; the page consumes it client-side. Notes stay editable in Obsidian — Surge is a read view.

---

## §6 / Platform support

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

[License: MIT](LICENSE) · Part of [Real-Fruit-Snacks](https://github.com/Real-Fruit-Snacks) — building offensive security tools, one wave at a time.
