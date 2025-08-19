---
applyTo: '**'
---
Coding standards, domain knowledge, and preferences that AI should follow.

# Work Environment

This project is coded entirely in a remote development environment using GitHub Codespaces. The AI will never ask me to run Terminal commands or use a local development environment. All code changes, tests, and debugging will be done within remote repositories on GitHub. 

Change summaries should be concise and clear, focusing on the specific changes made. The AI should not ask for confirmation before making changes, as all code modifications will be done directly in the remote environment. 

# Responses

When delivering responses, the AI should provide clear, concise, and actionable information. Responses should be formatted in a way that is easy to read and understand, with a focus on clarity and precision. The AI should avoid unnecessary verbosity or complexity in its explanations.

Responses should be delivered only in the chat interface. Formatting and styling should be utilized to enhance readability.

Change summaries should never be created in the form of new .md files.

# Code Analysis and Reading Standards

You must read files completely and thoroughly, with a minimum of 1500 lines per read operation when analyzing code. Never truncate files or stop reading at arbitrary limits like 50 or 100 lines. Your analysis must be based on the complete file content, not partial snapshots. Take the time to read everything properly because thoroughness and accuracy based on complete file knowledge is infinitely more valuable than quick, incomplete reviews that miss critical context and lead to incorrect suggestions.

# Coding Standards and Preferences

## WordPress Focused Design

- Leverage WordPress APIs, hooks (actions and filters), and functions where applicable.
- Ensure compatibility with modern WordPress versions and PHP standards.
- Ensure all code is compatible with the WordPress ecosystem, including themes and plugins.
- Avoid using frameworks, libraries, or non-standard features that are not compatible or commonly used with WordPress.

## WordPress Coding Standards

- Use WordPress coding standards for PHP, JavaScript, and CSS:
  - [PHP Coding Standards](https://developer.wordpress.org/coding-standards/wordpress-coding-standards/php/)
  - [JavaScript Coding Standards](https://developer.wordpress.org/coding-standards/wordpress-coding-standards/javascript/)
  - [CSS Coding Standards](https://developer.wordpress.org/coding-standards/wordpress-coding-standards/css/)
- Use WordPress coding standards for HTML and template files:
  - [HTML Coding Standards](https://developer.wordpress.org/coding-standards/wordpress-coding-standards/html/)
- Use WordPress coding standards for accessibility:
  - [Accessibility Coding Standards](https://developer.wordpress.org/coding-standards/wordpress-coding-standards/accessibility/)
- Use WordPress Gutenberg Project Coding Guidelines:
  - [Gutenberg Project Coding Guidelines](https://developer.wordpress.org/block-editor/contributors/code/coding-guidelines/)
- Use WordPress JavaScript Documentation Standards:
  - [JavaScript Documentation Standards](https://developer.wordpress.org/coding-standards/inline-documentation-standards/javascript/)
- Use WordPress PHP Documentation Standards:
  - [PHP Documentation Standards](https://developer.wordpress.org/coding-standards/inline-documentation-standards/php/)

## Supported Versions

- This project supports modern software versions:
  - WordPress 6.5+ (minimum)
  - PHP 7.4+ (minimum)
  - WooCommerce 5.0+ (if applicable)
- Do not use features or functions that are deprecated or not available in these versions.

## Version Control and Documentation

- Release versions, software tested versions, and minimum software supported versions for this project are listed in numerous places, when updating the release version for this project, ensure that all of these locations are updated accordingly.
- Version Locations:
  - README.md
  - readme.txt (for WordPress.org)
  - CHANGELOG.md
  - plugin header (in the main plugin file)
  - plugin section: "// Define plugin constants"
  - plugin *.pot files (e.g., languages/plugin-name.pot)
  - package.json (if applicable)
  - composer.json (if applicable)
  - documentation files (e.g., docs/README.md)
- Use semantic versioning (MAJOR.MINOR.PATCH) for all releases.
- Always add new information to the changelog when we make changes to the codebase, even if a new version is not released.
- When adding new information to the changelogs, changes will first be added to an "Unreleased" section at the top of the changelog file, and then later moved to a new version section when a new version is released. Be sure to follow this pattern and do not skip any of the changelog files.
- Do not automatically update the version number in the plugin header or other files. Instead, provide a clear and concise change summary that includes the version number and a brief description of the changes made.
- When making changes to the codebase, always update the relevant documentation files, including README.md, readme.txt, and CHANGELOG.md, even when a new version is not released.
- I will instruct you when to update the version number, and you should not do this automatically. Always ask for confirmation before updating the version number.
- When the version number is updated, ensure that the new version number is reflected in all relevant files, as outlined in Version Locations above.
- When the version number is updated, make special note to update the "Unreleased" section in the changelog files to reflect the new version number and a brief description of the changes made. This ensures that all changes are documented and easily accessible for future reference.

# General Coding Standards

- The above standards are prioritized over general coding standards.
- The standards below are general coding standards that apply to all code, including WordPress code. Do not apply them if they conflict with WordPress standards.

## Accessibility & UX

- Follow accessibility best practices for UI components
- Ensure forms are keyboard-navigable and screen reader friendly
- Validate user-facing labels, tooltips, and messages for clarity

## Performance & Optimization

- Optimize for performance and scalability where applicable
- Avoid premature optimization—focus on correctness first
- Detect and flag performance issues (e.g., unnecessary re-renders, N+1 queries)
- Use lazy loading, memoization, or caching where needed

## Type Safety & Standards

- Use strict typing wherever possible (TypeScript, C#, etc.)
- Avoid using `any` or untyped variables
- Use inferred and narrow types when possible
- Define shared types centrally (e.g., `types/` or `shared/` folders)

## Security & Error Handling

- Sanitize all input and output, especially in forms, APIs, and database interactions
- Escape, validate, and normalize all user-supplied data
- Automatically handle edge cases and error conditions
- Fail securely and log actionable errors
- Avoid leaking sensitive information in error messages or logs
- Use secure coding practices to prevent common vulnerabilities (e.g., XSS, CSRF, SQL injection)
- Use prepared statements for database queries
- Use secure authentication and authorization mechanisms
- When using third-party libraries or APIs, ensure they are well-maintained and secure
- Regularly update dependencies to their latest stable versions
- Use HTTPS for all API requests and data transmission
- When handling sensitive data, ensure it is encrypted both in transit and at rest
- If you suspect a security vulnerability, attempt to identify and fix it automatically. Alert me to the issue and provide a detailed explanation of the vulnerability, how it can be exploited, and the steps taken to mitigate it.
- Always follow the principle of least privilege when implementing security features, ensuring that users and processes have only the permissions they need to perform their tasks.
- If I ask you to make changes that could potentially introduce security vulnerabilities, you should always ask for confirmation before proceeding. This ensures that the project maintainers are aware of the potential risk and can provide guidance on how to address it safely.

## Code Quality & Architecture

- Organize code using **feature-sliced architecture** when applicable
- Group code by **feature**, not by type (e.g., keep controller, actions, and helpers together by feature)
- Write clean, readable, and self-explanatory code
- Use meaningful and descriptive names for files, functions, and variables
- Remove unused imports, variables, and dead code automatically

## Task Execution & Automation

- Always proceed to the next task automatically unless confirmation is required
- Only ask for confirmation when an action is destructive (e.g., data loss, deletion)
- Always attempt to identify and fix bugs automatically
- Only ask for manual intervention if domain-specific knowledge is required
- Auto-lint and format code using standard tools (e.g., Prettier, ESLint, dotnet format)
- Changes should be made directly to the file in question. Example: admin.php should be modified directly, not by creating a new file like admin-changes.php.
- New files may be created when appropriate, but they should be relevant to the task at hand, so long as they are not a rewrite of an existing file. We want to avoid unnecessary duplication of files.