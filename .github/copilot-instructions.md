---
applyTo: '**'
---

# WordPress Plugin Development Standards

## 🎯 Core Principles

**Work Environment:** Remote GitHub Codespaces only. Never suggest local Terminal commands.

**WordPress First:** Use WordPress APIs, hooks, and standards exclusively. Avoid non-WP frameworks.

**Security Critical:** Sanitize all input, escape all output, use WordPress security functions.

**Thorough Analysis:** Read complete files (minimum 1500 lines) for accurate code review.

## 📋 Essential Requirements

### WordPress Compatibility

- **WordPress:** 6.5+ minimum
- **PHP:** 7.4+ minimum  
- **WooCommerce:** 5.0+ (when applicable)
- Follow [WordPress Coding Standards](https://developer.wordpress.org/coding-standards/) for PHP, JS, CSS, HTML, and accessibility

### Code Quality Standards

1. **Security First:** Always sanitize input (`sanitize_*()`) and escape output (`esc_*()`)
2. **WordPress APIs:** Use WP functions instead of raw PHP/SQL
3. **Hook System:** Proper use of `add_action()` and `add_filter()`
4. **Internationalization:** Use `__()`, `_e()`, `esc_html__()` for all strings
5. **Performance:** Avoid N+1 queries, use WP caching, optimize database calls

## 🔒 Security Requirements (Critical)

**Input Handling:**
- Use `sanitize_text_field()`, `sanitize_email()`, `wp_kses()` for user input
- Validate with `is_email()`, `absint()`, `wp_verify_nonce()` for security
- Use prepared statements for database queries (`$wpdb->prepare()`)

**Output Security:**
- Escape all output: `esc_html()`, `esc_attr()`, `esc_url()`, `esc_js()`
- Use `wp_nonce_field()` and `wp_verify_nonce()` for forms
- Check permissions with `current_user_can()` before sensitive operations

**Vulnerability Prevention:**
- Prevent SQL injection, XSS, CSRF, Local File Inclusion (LFI), and path traversal
- Follow principle of least privilege
- Auto-identify and fix security issues when found

## 📝 Documentation & Versioning

**Changelog Management:**
- Always update CHANGELOG.md and readme.txt when making code changes
- **Sync both changelogs:** CHANGELOG.md and readme.txt changelog section
- Use "Unreleased" section for ongoing changes

**Version Release Process (only when instructed):**
- Follow semantic versioning (MAJOR.MINOR.PATCH)
- Update version in: plugin header, README.md, readme.txt, CHANGELOG.md, GEMINI.md, and `.pot` language files, constants section, package.json, and composer.json
- Move "Unreleased" changes to new version section in both changelogs
- **Never auto-update versions** - wait for explicit instruction

**Code Documentation:**
- Use PHPDoc with `@param`, `@return`, `@since` tags
- Write clear function/class descriptions
- Document security considerations and hooks used

**Internationalization (i18n):**
- Update `.pot` language files when adding or modifying translatable strings
- Always use the correct text domain when dealing with translation functions
- Mark all user-facing strings with `__()`, `_e()`, `esc_html__()`, `esc_attr__()`, etc.

## ⚡ Performance & Quality

**Performance Optimization:**
- Use WordPress caching (`wp_cache_*()`, transients)
- Optimize database queries, avoid N+1 problems
- Proper asset enqueueing with `wp_enqueue_*()` functions
- Focus on correctness first, then optimize

**Code Architecture:**
- Group by feature, not by type
- Use descriptive function/variable names
- Remove unused code automatically
- Follow feature-sliced design when applicable

**Error Handling:**
- Use `WP_Error` for WordPress-specific errors
- Log errors without exposing sensitive data
- Handle edge cases gracefully
- Validate all function parameters

## 🚀 Workflow & Automation

**Task Execution:**
- Make changes directly to existing files (don't create duplicates)
- Proceed automatically unless action is destructive
- Auto-identify and fix bugs when possible
- Only ask confirmation for data loss/deletion scenarios

**File Management:**
- Edit files in place (e.g., modify `admin.php` directly)
- Create new files only when truly necessary
- Avoid file duplication and unnecessary rewrites
- Maintain clean project structure

**Communication:**
- Provide concise, actionable responses
- Use clear formatting for readability
- Never create change summaries as separate .md files
- Focus on specific changes made, not verbose explanations