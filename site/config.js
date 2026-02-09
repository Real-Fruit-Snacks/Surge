/**
 * SURGE Configuration
 *
 * Customize filters, defaults, and behavior here.
 */

/**
 * TOGGLES - Filter system configuration
 *
 * Define tags that control procedure visibility. Procedures with these tags
 * can be shown/hidden via the Filters dropdown in the UI.
 *
 * Each toggle has:
 *   - tag: The tag name (case-sensitive, must match your note's YAML frontmatter)
 *   - label: Display name shown in the Filters dropdown
 *   - default: true = shown by default, false = hidden by default
 *
 * Notes:
 *   - Filter tags are automatically hidden from the tag display on cards
 *   - If a procedure has multiple filter tags, it shows if ANY are enabled
 *   - Set TOGGLES = [] to disable the filter system entirely
 *
 * Example configurations:
 *
 * // Empty - no filters, all notes always visible
 * const TOGGLES = [];
 *
 * // Simple draft system
 * const TOGGLES = [
 *   { tag: 'Draft', label: 'Drafts', default: false },
 * ];
 *
 * // Content organization
 * const TOGGLES = [
 *   { tag: 'Beginner', label: 'Beginner', default: true },
 *   { tag: 'Advanced', label: 'Advanced', default: false },
 *   { tag: 'Reference', label: 'Reference', default: false },
 * ];
 */
const TOGGLES = [
  { tag: 'Foundational', label: 'Foundational', default: true },
  { tag: 'Advanced', label: 'Advanced', default: true },
  { tag: 'Lab', label: 'Lab', default: false },
];
