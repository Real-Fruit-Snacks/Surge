#!/usr/bin/env python3
"""
Build script that parses markdown cheatsheets into a single JSON file.
Supports Obsidian-style markdown including:
- YAML frontmatter for tags
- Inline #hashtags
- Wiki links [[...]] (ignored)
- Callouts > [!note] (ignored)
"""

import json
import re
import os
import sys
import shutil
from pathlib import Path

def check_environment():
    """Check for potential issues in restrictive environments."""
    print("--- Environment Check ---")
    print(f"Python Version: {sys.version}")
    print(f"Operating System: {os.name} ({sys.platform})")
    print(f"Current Directory: {os.getcwd()}")
    
    site_dir = Path(__file__).parent / 'site'
    if site_dir.exists():
        print(f"Site directory exists: {site_dir}")
        # Check write permission
        try:
            test_file = site_dir / '.write_test'
            test_file.write_text('test')
            test_file.unlink()
            print("  Write permission to 'site/': OK")
        except Exception as e:
            print(f"  WARNING: No write permission to 'site/': {e}")
    else:
        print(f"Site directory does not exist: {site_dir}")
    print("-------------------------\n")

def parse_frontmatter(content):
    """Extract YAML frontmatter and return (frontmatter_dict, remaining_content)."""
    frontmatter = {}

    if content.startswith('---'):
        end_match = re.search(r'\n---\n', content[3:])
        if end_match:
            yaml_content = content[3:end_match.start() + 3]
            remaining = content[end_match.end() + 3:]

            # Simple YAML parsing for tags
            for line in yaml_content.split('\n'):
                line = line.strip()
                if line.startswith('tags:'):
                    tag_part = line[5:].strip()
                    # Handle both [tag1, tag2] and tag1, tag2 formats
                    tag_part = tag_part.strip('[]')
                    if tag_part:
                        frontmatter['tags'] = [t.strip().strip('"\'') for t in tag_part.split(',')]
                    else:
                        # Multi-line tags format
                        frontmatter['tags'] = []
                elif line.startswith('- ') and 'tags' in frontmatter:
                    frontmatter['tags'].append(line[2:].strip().strip('"\''))

            return frontmatter, remaining

    return frontmatter, content

def extract_inline_tags(text):
    """Extract #hashtags from text."""
    # Match #tag but not inside code blocks or URLs
    tags = re.findall(r'(?<!\S)#([a-zA-Z][a-zA-Z0-9_-]*)', text)
    return tags

def clean_obsidian_syntax(text):
    """Remove/clean Obsidian-specific syntax."""
    # Remove wiki links [[link]] -> link, [[link|display]] -> display
    text = re.sub(r'\[\[([^\]|]+)\|([^\]]+)\]\]', r'\2', text)
    text = re.sub(r'\[\[([^\]]+)\]\]', r'\1', text)

    # Remove inline #tags from display (we've already extracted them)
    text = re.sub(r'(?<!\S)#[a-zA-Z][a-zA-Z0-9_-]*\s*', '', text)

    # Remove callout markers but keep content
    text = re.sub(r'^>\s*\[!(\w+)\].*$', '', text, flags=re.MULTILINE)

    return text

def extract_content(text):
    """Extract blockquotes and plain text, returning structured content with types.

    Returns list of dicts: [{'type': 'note'|'text', 'content': '...', 'variant': '...'}]
    Blockquotes (>) become 'note', plain text becomes 'text'.
    Supports Obsidian-style callouts: > [!warning] text
    """
    lines = text.split('\n')
    content_items = []
    current_group = []
    current_type = None
    current_variant = None

    # Lines to skip (metadata, not content)
    skip_patterns = [
        r'^tags:\s*',
        r'^resources?:\s*',
    ]

    # Callout pattern: [!type] with optional text after
    callout_pattern = re.compile(r'^\[!(\w+)\]\s*(.*)?$')

    def should_skip(line):
        for pattern in skip_patterns:
            if re.match(pattern, line, re.IGNORECASE):
                return True
        return False

    def save_group():
        nonlocal current_group, current_type, current_variant
        if current_group and current_type:
            content = '\n'.join(current_group).strip()
            if content:
                item = {'type': current_type, 'content': content}
                if current_variant:
                    item['variant'] = current_variant
                content_items.append(item)
        current_group = []
        current_type = None
        current_variant = None

    for line in lines:
        stripped = line.strip()

        # Skip metadata lines
        if should_skip(stripped):
            save_group()
            continue

        if stripped.startswith('>'):
            # Blockquote line
            content = stripped[1:].lstrip()

            # Check for callout on first line of a new note
            if current_type != 'note':
                save_group()
                current_type = 'note'
                # Check if this line has a callout marker
                callout_match = callout_pattern.match(content)
                if callout_match:
                    current_variant = callout_match.group(1).lower()
                    # Get any text after the callout marker
                    remaining = callout_match.group(2)
                    if remaining and remaining.strip():
                        current_group.append(remaining.strip())
                else:
                    current_group.append(content)
            else:
                current_group.append(content)
        elif not stripped:
            # Blank line - ends current group
            save_group()
        else:
            # Plain text line
            if current_type == 'text':
                current_group.append(stripped)
            else:
                save_group()
                current_type = 'text'
                current_group.append(stripped)

    # Don't forget the last group
    save_group()

    return content_items

def strip_code_blocks(content, filepath=None):
    """Replace code blocks with placeholders to avoid parsing headers inside them."""
    blocks = []
    warnings = []
    def save_block(match):
        block = match.group(0)
        # Warn if code block contains H2 headers (likely unclosed block eating content)
        if re.search(r'\n##[ \t]+', block):
            warnings.append(block[:100])
        blocks.append(block)
        return f'\x00CODEBLOCK{len(blocks)-1}\x00'
    # Require closing ``` to be at start of line (handles backticks inside code)
    stripped = re.sub(r'```[^\n]*\n.*?\n```', save_block, content, flags=re.DOTALL)
    for warning in warnings:
        fname = filepath.name if filepath else 'file'
        print(f'  WARNING: Code block in {fname} may be unclosed (contains ## header):')
        print(f'    {warning[:60]}...')
    return stripped, blocks

def restore_code_blocks(content, blocks):
    """Restore code blocks from placeholders."""
    for i, block in enumerate(blocks):
        content = content.replace(f'\x00CODEBLOCK{i}\x00', block)
    return content

def parse_markdown_file(filepath):
    """Parse a single markdown file into structured data."""
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    procedures = []
    category = Path(filepath).stem  # filename without extension

    # Parse frontmatter
    frontmatter, content = parse_frontmatter(content)
    file_tags = frontmatter.get('tags', [])

    # Tags that indicate the file should be kept as a single procedure (not split by ##)
    single_card_tags = ['Lab']
    is_single_card = any(t in file_tags for t in single_card_tags)

    # Strip code blocks before splitting on headers
    stripped_content, code_blocks = strip_code_blocks(content, filepath)

    # For single-card files, convert ## to ### and ### to #### (except first ##)
    if is_single_card:
        # Count H2 headers to see if we need to transform
        h2_count = len(re.findall(r'^##[ \t]+', stripped_content, re.MULTILINE))
        if h2_count > 1:
            lines = stripped_content.split('\n')
            new_lines = []
            found_first_h2 = False
            converting_h3 = False  # Only convert ### to #### after we've converted a ## to ###
            for line in lines:
                if re.match(r'^##[ \t]+', line) and not re.match(r'^###', line):
                    if found_first_h2:
                        # Convert subsequent ## to ###
                        line = '#' + line
                        converting_h3 = True  # Start converting ### to #### from here
                    else:
                        found_first_h2 = True
                elif re.match(r'^###[ \t]+', line) and not re.match(r'^####', line):
                    if converting_h3:
                        # Convert ### to #### only after a ## was converted
                        line = '#' + line
                new_lines.append(line)
            stripped_content = '\n'.join(new_lines)

    # Split by H2 (## ) to get each procedure (allow space or tab after ##)
    h2_pattern = r'^##[ \t]+(.+)$'
    sections = re.split(h2_pattern, stripped_content, flags=re.MULTILINE)

    # First element is the H1 header and any preamble, skip it
    # Then pairs of (title, content)
    i = 1
    while i < len(sections):
        if i + 1 >= len(sections):
            break

        title = sections[i].strip()
        body = restore_code_blocks(sections[i + 1], code_blocks)

        # Extract tags from multiple sources
        tags = set(file_tags)  # Start with frontmatter tags

        # Traditional tags: line
        tags_match = re.search(r'^tags:\s*(.+)$', body, re.MULTILINE)
        if tags_match:
            for t in tags_match.group(1).split(','):
                tags.add(t.strip())

        # Extract resources/references (accept both singular and plural)
        resources = []
        resources_match = re.search(r'^resources?:\s*(.+)$', body, re.MULTILINE | re.IGNORECASE)
        if resources_match:
            # Parse markdown links [text](url) or plain URLs
            resource_str = resources_match.group(1)
            # Find markdown links
            md_links = re.findall(r'\[([^\]]+)\]\(([^)]+)\)', resource_str)
            for text, url in md_links:
                resources.append({'text': text.strip(), 'url': url.strip()})
            # Find plain URLs (not already in markdown links)
            plain_urls = re.findall(r'(?<!\()https?://[^\s,\)]+', resource_str)
            for url in plain_urls:
                resources.append({'text': url, 'url': url})

        # Obsidian inline #tags
        inline_tags = extract_inline_tags(body)
        tags.update(inline_tags)

        # Also check title for inline tags
        title_tags = extract_inline_tags(title)
        tags.update(title_tags)

        # Clean title of obsidian syntax
        title = clean_obsidian_syntax(title).strip()

        # Extract steps (H3 headers with code blocks, allow space or tab after ###)
        steps = []
        h3_pattern = r'^###[ \t]+(.+)$'
        # Strip code blocks before splitting on H3 headers
        stripped_body, body_code_blocks = strip_code_blocks(body)
        step_sections = re.split(h3_pattern, stripped_body, flags=re.MULTILINE)

        # Extract procedure-level content (blockquotes and text before first H3)
        procedure_notes = extract_content(restore_code_blocks(step_sections[0], body_code_blocks)) if step_sections else []

        j = 1
        while j < len(step_sections):
            if j + 1 >= len(step_sections):
                break

            step_title = step_sections[j].strip()
            step_body = restore_code_blocks(step_sections[j + 1], body_code_blocks)

            # Check for flags
            optional = '[optional]' in step_title.lower()
            alternative = '[alternative]' in step_title.lower() or '[alternate]' in step_title.lower()
            remote = '[remote]' in step_title.lower()
            local = '[local]' in step_title.lower()
            step_title = re.sub(r'\[optional\]\s*', '', step_title, flags=re.IGNORECASE)
            step_title = re.sub(r'\[alternative\]\s*', '', step_title, flags=re.IGNORECASE)
            step_title = re.sub(r'\[alternate\]\s*', '', step_title, flags=re.IGNORECASE)
            step_title = re.sub(r'\[remote\]\s*', '', step_title, flags=re.IGNORECASE)
            step_title = re.sub(r'\[local\]\s*', '', step_title, flags=re.IGNORECASE)

            # Clean step title of obsidian syntax
            step_title = clean_obsidian_syntax(step_title).strip()

            # Language normalization map for highlight.js
            lang_map = {
                'ps1': 'powershell', 'sh': 'bash', 'shell': 'bash', 'zsh': 'bash',
                'cmd': 'bash', 'bat': 'bash', 'dos': 'bash', 'batch': 'bash', 'cisco': 'bash',
                'kql': 'sql', 'kusto': 'sql',
                'aspx': 'xml', 'jsp': 'xml',
                'py': 'python', 'js': 'javascript', 'ts': 'typescript', 'rb': 'ruby',
                'rs': 'rust', 'cs': 'csharp', 'c++': 'cpp', 'yml': 'yaml'
            }

            # Check for H4 sub-steps
            h4_pattern = r'^####[ \t]+(.+)$'
            stripped_step_body, step_code_blocks = strip_code_blocks(step_body)
            h4_sections = re.split(h4_pattern, stripped_step_body, flags=re.MULTILINE)

            if len(h4_sections) > 1:
                # Has sub-steps - parse H4 sections
                substeps = []
                # First element is content before first H4 (step-level notes and code)
                step_preamble = restore_code_blocks(h4_sections[0], step_code_blocks)

                # Extract any code blocks before the first H4
                code_pattern = r'```(\w+)?\n(.*?)\n```'
                preamble_code_matches = list(re.finditer(code_pattern, step_preamble, re.DOTALL | re.IGNORECASE))
                step_codes = None
                step_notes = []
                if preamble_code_matches:
                    step_codes = [{'lang': lang_map.get((m.group(1) or 'bash').lower(), (m.group(1) or 'bash').lower()), 'code': m.group(2).strip()} for m in preamble_code_matches]
                    # Extract content only from before/after code blocks
                    before_code = step_preamble[:preamble_code_matches[0].start()]
                    step_notes = extract_content(before_code)
                else:
                    # No code blocks - extract all content
                    step_notes = extract_content(step_preamble)

                k = 1
                while k < len(h4_sections):
                    if k + 1 >= len(h4_sections):
                        break

                    substep_title = h4_sections[k].strip()
                    substep_body = restore_code_blocks(h4_sections[k + 1], step_code_blocks)

                    # Check for flags on substep
                    substep_optional = '[optional]' in substep_title.lower()
                    substep_alternative = '[alternative]' in substep_title.lower() or '[alternate]' in substep_title.lower()
                    substep_remote = '[remote]' in substep_title.lower()
                    substep_local = '[local]' in substep_title.lower()
                    substep_title = re.sub(r'\[optional\]\s*', '', substep_title, flags=re.IGNORECASE)
                    substep_title = re.sub(r'\[alternative\]\s*', '', substep_title, flags=re.IGNORECASE)
                    substep_title = re.sub(r'\[alternate\]\s*', '', substep_title, flags=re.IGNORECASE)
                    substep_title = re.sub(r'\[remote\]\s*', '', substep_title, flags=re.IGNORECASE)
                    substep_title = re.sub(r'\[local\]\s*', '', substep_title, flags=re.IGNORECASE)
                    substep_title = clean_obsidian_syntax(substep_title).strip()

                    # Extract code blocks from substep
                    code_pattern = r'```(\w+)?\n(.*?)\n```'
                    code_matches = list(re.finditer(code_pattern, substep_body, re.DOTALL | re.IGNORECASE))
                    if code_matches:
                        codes = [{'lang': lang_map.get((m.group(1) or 'bash').lower(), (m.group(1) or 'bash').lower()), 'code': m.group(2).strip()} for m in code_matches]

                        before_code = substep_body[:code_matches[0].start()]
                        after_code = substep_body[code_matches[-1].end():]
                        substep_notes = extract_content(before_code)
                        substep_post_notes = extract_content(after_code)

                        substep_data = {
                            'title': substep_title,
                            'codes': codes,
                            'optional': substep_optional,
                            'alternative': substep_alternative,
                            'remote': substep_remote,
                            'local': substep_local
                        }
                        if substep_notes:
                            substep_data['notes'] = substep_notes
                        if substep_post_notes:
                            substep_data['postNotes'] = substep_post_notes
                        substeps.append(substep_data)
                    else:
                        # No code blocks - check if there is content to display
                        substep_notes = extract_content(substep_body)
                        if substep_notes:
                            substep_data = {
                                'title': substep_title,
                                'codes': [],
                                'optional': substep_optional,
                                'alternative': substep_alternative,
                                'remote': substep_remote,
                                'local': substep_local,
                                'notes': substep_notes
                            }
                            substeps.append(substep_data)

                    k += 2

                if substeps:
                    step_data = {
                        'title': step_title,
                        'substeps': substeps,
                        'optional': optional,
                        'alternative': alternative,
                        'remote': remote,
                        'local': local
                    }
                    if step_codes:
                        step_data['codes'] = step_codes
                    if step_notes:
                        step_data['notes'] = step_notes
                    steps.append(step_data)
            else:
                # No sub-steps - parse as before
                code_pattern = r'```(\w+)?\n(.*?)\n```'
                code_matches = list(re.finditer(code_pattern, step_body, re.DOTALL | re.IGNORECASE))
                if code_matches:
                    codes = [{'lang': lang_map.get((m.group(1) or 'bash').lower(), (m.group(1) or 'bash').lower()), 'code': m.group(2).strip()} for m in code_matches]

                    # Get notes before first code block and after last code block
                    before_code = step_body[:code_matches[0].start()]
                    after_code = step_body[code_matches[-1].end():]

                    # Extract content before and after code blocks
                    step_notes = extract_content(before_code)
                    post_notes = extract_content(after_code)

                    step_data = {
                        'title': step_title,
                        'codes': codes,
                        'optional': optional,
                        'alternative': alternative,
                        'remote': remote,
                        'local': local
                    }
                    if step_notes:
                        step_data['notes'] = step_notes
                    if post_notes:
                        step_data['postNotes'] = post_notes
                    steps.append(step_data)
                else:
                    # No code blocks - check if there is content to display
                    step_notes = extract_content(step_body)
                    if step_notes:
                        step_data = {
                            'title': step_title,
                            'codes': [],
                            'optional': optional,
                            'alternative': alternative,
                            'remote': remote,
                            'local': local,
                            'notes': step_notes
                        }
                        steps.append(step_data)

            j += 2

        if steps or procedure_notes:  # Add if there are steps OR procedure-level notes
            # Filter tags - these become boolean properties and are hidden from display
            # Must match the TOGGLES config in index.html
            filter_tags = ['Foundational', 'Advanced', 'Exploit_Development', 'Knowledge', 'Lab', 'Operator_Handbook', 'RTFM']

            # Check which filter tags are present (case-insensitive)
            tag_flags = {}
            for ft in filter_tags:
                if ft in tags or ft.lower() in [t.lower() for t in tags]:
                    tag_flags[ft.lower()] = True

            # Remove filter tags from display tags
            filter_tags_lower = {ft.lower() for ft in filter_tags}
            display_tags = {t for t in tags if t.lower() not in filter_tags_lower}

            proc_data = {
                'category': category,
                'title': title,
                'tags': sorted(list(display_tags)),  # Convert set to sorted list
                'steps': steps,
                'resources': resources
            }
            # Add boolean flags for each filter tag found
            for key, value in tag_flags.items():
                proc_data[key] = value
            if procedure_notes:
                proc_data['notes'] = procedure_notes
            procedures.append(proc_data)

        i += 2

    return procedures

def build():
    """Build the commands.json file from all markdown files."""
    cheatsheets_dir = Path(__file__).parent / 'notes'
    output_file = Path(__file__).parent / 'site' / 'commands.json'

    all_procedures = []

    # Folders to ignore (case-insensitive)
    ignored_folders = {'.obsidian', '_archive'}

    for md_file in cheatsheets_dir.glob('**/*.md'):
        # Skip ignored folders (case-insensitive check)
        if ignored_folders & {p.lower() for p in md_file.parts}:
            continue
        # Skip files in the root notes directory (must be in a subdirectory)
        if md_file.parent == cheatsheets_dir:
            continue
        print(f'Parsing {md_file.name}...')
        procedures = parse_markdown_file(md_file)
        all_procedures.extend(procedures)
        print(f'  Found {len(procedures)} procedures')

    # Sort alphabetically by procedure title
    all_procedures.sort(key=lambda p: p['title'].lower())

    # Ensure output directory exists
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(all_procedures, f, indent=2)

    print(f'\nBuilt {output_file} with {len(all_procedures)} total procedures')

def create_release(version=None):
    """Create a zipped release of the app without notes."""
    if not version:
        version = "v2.5.0"
    release_name = f"surge-{version}"
    release_dir = Path(__file__).parent / release_name
    zip_name = f"{release_name}.zip"

    print(f"Creating release {zip_name}...")

    if release_dir.exists():
        shutil.rmtree(release_dir)
    release_dir.mkdir()

    # Copy site directory
    site_dest = release_dir / 'site'
    shutil.copytree(Path(__file__).parent / 'site', site_dest)

    # Remove commands.json
    commands_json = site_dest / 'commands.json'
    if commands_json.exists():
        commands_json.unlink()

    # Create clean config.js
    clean_config = """/**
 * SURGE Configuration
 *
 * Customize filters, defaults, and behavior here.
 */

const TOGGLES = [
  { tag: 'Foundational', label: 'Foundational', default: true },
  { tag: 'Advanced', label: 'Advanced', default: true },
  { tag: 'Lab', label: 'Lab', default: false },
];
"""
    (site_dest / 'config.js').write_text(clean_config, encoding='utf-8')

    # Copy other files
    for f in ['build.py', 'README.md', 'LICENSE']:
        src = Path(__file__).parent / f
        if src.exists():
            shutil.copy2(src, release_dir / f)

    # Create zip
    shutil.make_archive(release_name, 'zip', root_dir=Path(__file__).parent, base_dir=release_name)

    # Cleanup
    shutil.rmtree(release_dir)
    print(f"Release created: {zip_name}")

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--release':
        version = sys.argv[2] if len(sys.argv) > 2 else None
        create_release(version)
    else:
        build()
