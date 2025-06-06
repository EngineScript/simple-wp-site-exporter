=== Simple WP Site Exporter ===
Contributors: enginescript
Tags: backup, export, migration, site export, database export
Requires at least: 5.8
Tested up to: 6.8
Stable tag: 1.6.4
Requires PHP: 7.4
License: GPLv3 or later
License URI: https://www.gnu.org/licenses/gpl-3.0.html

Export your entire WordPress site, including files and database, as a secure downloadable ZIP archive.

== Description ==

Simple WP Site Exporter provides WordPress administrators with a straightforward, secure way to export their entire website. With a single click, you can create a complete backup of your site's files and database, perfect for site migrations, backups, or local development environments.

Key features:
* One-Click Export: Create a complete site backup with just one click
* Database Export: Includes a full database dump in your export
* Automatic Cleanup: Exports are automatically deleted after 5 minutes to enhance security
* Secure Downloads: All exports use WordPress security tokens for protected access
* WP-CLI Integration: Leverages WP-CLI for efficient database exports when available
* Export Management: Download or manually delete export files as needed
* EngineScript Integration: Natively works with EngineScript's LEMP server environment and site import tools

This plugin is designed to work seamlessly with the EngineScript LEMP server environment:

* Native Integration: Automatically detected and configured when running on an EngineScript server
* Compatible Exports: All exports created with this plugin are directly compatible with EngineScript's site import tools
* Streamlined Migrations: Export from any WordPress site and import directly to an EngineScript-powered server
* Optimized Performance: When used on an EngineScript server, the plugin leverages server-optimized settings

The export format is specifically designed to work with EngineScript's site import functionality, allowing for seamless site migrations between WordPress installations.

== Installation ==

1. Upload the plugin files to the `/wp-content/plugins/simple-wp-site-exporter` directory, or install the plugin through the WordPress plugins screen directly.
2. Activate the plugin through the 'Plugins' screen in WordPress.
3. Navigate to Tools → Site Exporter in your WordPress admin.
4. Click the "Export Site" button to create a full site backup.

== Frequently Asked Questions ==

= How large of a site can I export? =

The plugin is designed to work with most WordPress sites, but very large sites (multiple GB) may encounter timeout or memory limitations depending on your hosting environment.

= Where are the export files stored? =

Exports are stored in your WordPress uploads directory, specifically at:
`[wp-root]/wp-content/uploads/simple-wp-site-exporter-exports/`

= Why do export files disappear after 5 minutes? =

For security and disk space considerations, all exports are automatically deleted after 5 minutes. This ensures sensitive site data isn't left stored indefinitely.

= Can I create multiple exports? =

Yes, you can create as many exports as needed. Each will have a unique filename based on the timestamp of creation.

= Does this include my themes and plugins? =

Yes, the export includes your entire WordPress installation: themes, plugins, uploads, and the complete database.

= Can I use this plugin with non-EngineScript servers? =

Absolutely! While the plugin integrates seamlessly with EngineScript servers, it works perfectly on any WordPress installation regardless of the server environment.

= Will this work on shared hosting environments? =

Yes, the plugin is designed to be compatible with most shared hosting environments. However, large sites may encounter timeout or memory limitations on restrictive hosting plans.

== Changelog ==

= 1.6.4 =
* Fixed text domain mismatch to use 'Simple-WP-Site-Exporter' for WordPress plugin compliance
* Updated plugin header text domain to match expected slug format for WordPress.org directory standards

= 1.6.3 =
* Version consistency update across all plugin files and documentation

= 1.6.2 =
* Plugin renamed from "EngineScript: Simple Site Exporter" to "Simple WP Site Exporter"
* Updated text domain to 'simple-wp-site-exporter' for consistency
* Updated composer package name to 'enginescript/simple-wp-site-exporter'
* Updated export directory naming to 'simple-wp-site-exporter-exports'
* Updated all GitHub workflows and documentation to reflect new plugin name
* Enhanced plugin branding and consistency

= 1.6.1 =
* WordPress Plugin Check compliance fixes
* Fixed timezone issues by replacing date() with gmdate() for UTC consistency
* Improved debug logging with WordPress wp_debug_log() support and proper fallback
* Fixed admin page title display issue with get_admin_page_title() usage
* Enhanced documentation with proper PHPDoc comments and phpcs annotations
* Addressed all WordPress Plugin Check warnings and errors

= 1.6.0 =
* Major security and code quality improvements
* Enhanced logging system with WP_DEBUG integration and database storage for critical errors
* Improved file operations using WordPress Filesystem API instead of direct file functions
* Added execution time safety with reasonable limits and proper logging
* Implemented comprehensive path validation to prevent directory traversal attacks
* Standardized text domain across all translatable strings
* Pinned GitHub Actions to specific commit hashes for improved security
* Updated all repository references and workflow configurations
* Created WordPress-compatible readme.txt file
* Updated composer.json with correct package information and GPL-3.0-or-later license
* Fixed code structure issues and improved WordPress coding standards compliance

= 1.5.9 =
* Reduced export file auto-deletion time from 1 hour to 5 minutes for improved security
* Removed dependency on external systems for file security management
* Simplified user interface by removing environment-specific messaging
* Enhanced self-containment of the plugin's security features

= 1.5.8 =
* Refactored validation functions to eliminate code duplication
* Created shared validation function for both download and deletion operations
* Improved code maintainability while preserving security controls
* Updated license to GPL v3
* Enhanced file path validation
* Strengthened regex pattern for export file validation
* Added proper documentation for security-related functions

= 1.5.7 =
* Implemented comprehensive file path validation function to prevent directory traversal attacks
* Added referrer checks for download and delete operations
* Enhanced file pattern validation with stronger regex patterns
* Improved path display in admin interface
* Added security headers to file download operations
* Implemented strict comparison operators throughout the plugin
* Consistently applied sanitization to nonce values before verification

= 1.5.6 =
* Added more detailed logging for export operations
* Improved error handling during file operations
* Fixed potential memory issues during export of large sites
* Resolved a race condition in the scheduled deletion process

= 1.5.5 =
* Added automatic deletion of export files after 1 hour
* Implemented secure download mechanism through WordPress admin
* Added ability to manually delete export files
* Enhanced file export process with better error handling
* Improved progress feedback during export operations

= 1.5.4 =
* Added deletion request validation and confirmation
* Implemented redirect after deletion with status notification
* Fixed database export issues on some hosting environments

= 1.5.3 =
* Added manual export file deletion
* Enhanced security for file operations
* Better error handling for WP-CLI operations
* Improved user interface with clearer notifications

= 1.5.2 =
* Added WP-CLI integration for database exports
* Implemented fallback methods for database exports
* Fixed ZIP creation issues on certain hosting environments

= 1.5.1 =
* Enhanced ZIP file creation process
* Improved handling of large files
* Added exclusion for cache and temporary directories

= 1.5.0 =
* Initial Release
* Basic site export functionality
* Database and file export
* Simple admin interface

== Upgrade Notice ==

= 1.6.1 =
WordPress Plugin Check compliance update: Fixed timezone issues, improved debug logging, and addressed all plugin check warnings. Recommended update for WordPress.org submission.

= 1.6.0 =
Major security and code quality update: Enhanced logging system, improved file operations with WordPress Filesystem API, execution time safety improvements, comprehensive path validation, standardized text domains, and GitHub Actions security updates. Recommended upgrade for all users.

= 1.5.9 =
This update improves security by reducing export file auto-deletion time from 1 hour to 5 minutes and enhances overall plugin security with simplified, self-contained security features.

= 1.5.8 =
This update includes improved code quality, better validation functions, and enhanced security with file path validation and stronger regex patterns. Includes update to GPL v3 license.

= 1.5.7 =
Important security update: Includes comprehensive file path validation, referrer checks for download operations, enhanced validation patterns, and improved security headers.
