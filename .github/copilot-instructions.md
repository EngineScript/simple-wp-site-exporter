---
applyTo: '**'
---
Coding standards, domain knowledge, and preferences that AI should follow.

# Work Environment

This project is coded entirely in a remote development environment using GitHub Codespaces. All code changes, tests, and debugging will be done within remote repositories on GitHub.

The AI will never ask me to run terminal commands or use a local development environment.

# Responses

When delivering responses, the AI should provide clear, concise, and actionable information. Responses should be formatted in a way that is easy to read and understand, with a focus on clarity and precision. The AI should avoid unnecessary verbosity or complexity in its explanations.

Responses, change summaries, and code comments should be written in American English. All communication should be clear and professional, adhering to standard English grammar and spelling conventions. 

Responses should be delivered only in the chat interface and should never be created in the form of new .md files. Formatting and styling within the chat window should be utilized to enhance readability.

# Code Analysis and Reading Standards

You must read files completely and thoroughly, with a minimum of 2000 lines per read operation when analyzing code. Never truncate files or stop reading at arbitrary limits like 50 or 100 lines - this lazy approach provides incomplete context and leads to poor suggestions. Take the time to read everything properly because thoroughness and accuracy based on complete file knowledge is infinitely more valuable than quick, incomplete reviews that miss critical context and lead to incorrect suggestions.

# Coding Standards and Preferences

## WordPress Focused Design

- This project is focused on WordPress development.
- Use WordPress coding standards and best practices.
- Leverage WordPress APIs and functions where applicable.
- Ensure compatibility with modern WordPress versions and PHP standards. WordPress 6.5+ and PHP 7.4+ are the baseline.
- Use WordPress hooks (actions and filters) to extend functionality.
- Follow WordPress theme and plugin development guidelines.
- Use WordPress REST API for custom endpoints and data retrieval.
- Ensure all code is compatible with the WordPress ecosystem, including themes and plugins.
- As this is a WordPress-focused project, avoid using frameworks or libraries that are not compatible or commonly used with WordPress.
- Avoid using non-standard or experimental features that are not widely adopted in the WordPress community.

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
- Maintain changelogs at readme.txt (for WordPress.org) and CHANGELOG.md (for developers).
- Please do not skip these locations, as the changelog files must be in sync with each other, and the version numbers must be consistent across all files.
- I will instruct you when to update the version number, and you should not do this automatically.
- When the version number is updated, ensure that the new version number is reflected in all relevant files, as outlined in Version Locations above.
- When the version number is updated, make special note to update the "Unreleased" section in the changelog files to reflect the new version number and a brief description of the changes made. This ensures that all changes are documented and easily accessible for future reference.

# General Coding Standards

- WordPress coding standards should be prioritized over general coding standards.
- The standards below are general coding standards that apply to all code, including WordPress code. Do not apply them if they conflict with WordPress standards and best practices.

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
- Always follow the principle of least privilege when implementing security features, ensuring that users and processes have only the permissions they need to perform their tasks.
- If there is a possible security vulnerability in the codebase, you should always ask for confirmation before proceeding.
- If I ask you to make changes that could potentially introduce security vulnerabilities, you should always ask for confirmation before proceeding.

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

# Final Step for Each Task

- After completing a task:
  - Review your changes to ensure they have met the WordPress coding standards and best practices.
  - Ensure all changes are documented in the changelog files.
  - Ensure all user inputs are properly sanitized and validated.
  - Ensure all outputs are properly escaped.
  - Perform a final check to ensure we have not introduced any security vulnerabilities such as XSS, CSRF, or SQL injection.
  - In the chat interface, deliver a summary of the security checks performed, including any potential vulnerabilities identified and how they were addressed. Do not allow yourself to skip this step as it is crucial for maintaining the security and integrity of the codebase.