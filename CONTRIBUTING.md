# Contributing to SURGE

Thanks for your interest in contributing! This guide will help you get started.

## Quick Start

```bash
git clone https://github.com/real-fruit-snacks/surge.git
cd surge
python3 build.py
python3 -m http.server 8080 --directory site
```

Open [http://localhost:8080](http://localhost:8080) to preview changes.

## Adding References

1. Create a markdown file in `/notes/<category>/`
2. Add YAML frontmatter with tags
3. Follow the format below
4. Run `python3 build.py` to test
5. Submit a pull request

### Reference Format

```markdown
---
tags:
  - Category
  - Tool
---

## Procedure Title
resources: [Docs](https://example.com)

> Notes explain context or requirements.

### Step Title
```bash
command --flag <Variable>
```
```

### Guidelines

- Use `<VariableName>` for user-supplied values (PascalCase)
- Add `resources:` links to official documentation
- Mark optional steps with `[optional]` or `[alternate]`
- Use `[Remote]` and `[Local]` flags for multi-host procedures
- Keep commands practical and tested
- No blank lines between headers and content
- Blank line before and after code blocks

## Code Contributions

### Frontend (`site/index.html`)

The entire frontend is a single HTML file with embedded CSS and JavaScript. Changes should:

- Maintain zero external runtime dependencies
- Work offline after initial load
- Support all 16 themes
- Be mobile-responsive

### Build System (`build.py`)

The parser has no external dependencies. Changes should:

- Handle edge cases gracefully
- Maintain backward compatibility with existing notes
- Include clear error messages

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/description`)
3. Make your changes
4. Test locally with `python3 build.py`
5. Submit a pull request with a clear description

## Reporting Issues

- Search existing issues first
- Include steps to reproduce bugs
- For reference errors, include the file path

## Style Guide

- No emojis in notes or code
- Prefer existing patterns over new abstractions
- Keep changes focused and minimal

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
