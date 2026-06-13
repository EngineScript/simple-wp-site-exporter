<?php
/**
 * Export workflow: request handling, validation, directory setup, DB export.
 *
 * @package EngineScript_Site_Exporter
 */

if ( ! defined( 'ABSPATH' ) ) {
	return;
}

/**
 * Handles the site export process when the form is submitted.
 *
 * @since 1.0.0
 * @return void
 */
function sse_handle_export(): void {
	if ( ! sse_validate_export_request() ) {
		sse_redirect_to_exporter_page();
	}

	// Check for and set an export lock.
	if ( get_transient( 'sse_export_lock' ) ) {
		sse_show_error_notice( __( 'An export process is already running. Please wait for it to complete before starting a new one.', 'enginescript-site-exporter' ) );
		sse_redirect_to_exporter_page();
	}
	// Set lock with a 1-hour expiration to prevent permanent locks on failure.
	set_transient( 'sse_export_lock', time(), HOUR_IN_SECONDS );

	$previous_umask = umask( 0077 );
	$export_paths   = null;
	$export_success = false;

	try {
		do {
			$max_exec_time = sse_get_execution_time_limit();
			if ( $max_exec_time > 0 && $max_exec_time < 1800 ) {
				sse_log( "Current execution time limit ({$max_exec_time}s) may be insufficient for large exports. Consider increasing server limits.", 'warning' );
			}

			$export_paths = sse_setup_export_directories();
			if ( is_wp_error( $export_paths ) ) {
				sse_show_error_notice( $export_paths->get_error_message() );
				break;
			}

			$site_identifier = sse_get_export_site_identifier();
			$timestamp       = sse_get_export_timestamp();

			$database_file = sse_export_database( $export_paths['export_dir'], $site_identifier, $timestamp );
			if ( is_wp_error( $database_file ) ) {
				sse_show_error_notice( $database_file->get_error_message() );
				break;
			}

			$zip_result = sse_create_site_archive( $export_paths, $database_file, $site_identifier, $timestamp );
			if ( is_wp_error( $zip_result ) ) {
				sse_cleanup_files( [ $database_file['filepath'] ] );
				sse_show_error_notice( $zip_result->get_error_message() );
				break;
			}

			sse_cleanup_files( [ $database_file['filepath'] ] );

			sse_schedule_export_cleanup( $zip_result['filepath'] );

			// Schedule a bulk cleanup sweep in case individual files were missed.
			sse_schedule_bulk_cleanup();

			sse_show_success_notice( $zip_result );
			$export_success = true;
		} while ( false );
	} finally {
		if ( is_array( $export_paths ) && ! $export_success ) {
			sse_delete_directory_tree( $export_paths['export_dir'] );
		}

		umask( $previous_umask );
		// Always release the lock and clean up user preferences.
		delete_transient( 'sse_export_lock' );
		delete_transient( 'sse_export_max_file_size_' . get_current_user_id() );
	}

	sse_redirect_to_exporter_page();
}

/**
 * Validates the export request for security and permissions.
 *
 * @since 1.0.0
 * @return bool True if request is valid, false otherwise.
 */
function sse_validate_export_request(): bool { // phpcs:ignore WordPress.Security.NonceVerification.Missing
	$post_action = isset( $_POST['action'] ) && is_string( $_POST['action'] ) ? sanitize_key( wp_unslash( $_POST['action'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verification happens below
	if ( 'sse_export_site' !== $post_action ) {
		return false;
	}

	check_admin_referer( 'sse_export_action', 'sse_export_nonce' );

	if ( ! sse_current_user_can_export_site() ) {
		sse_wp_die( __( 'You do not have permission to perform this action.', 'enginescript-site-exporter' ), 403 );
	}

	// Store the user's max file size selection for use during export.
	$max_file_size = isset( $_POST['sse_max_file_size'] ) ? absint( $_POST['sse_max_file_size'] ) : 0; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified above
	set_transient( 'sse_export_max_file_size_' . get_current_user_id(), $max_file_size, HOUR_IN_SECONDS );

	return true;
}

/**
 * Sets up export directories and returns path information.
 *
 * @since 1.0.0
 * @return array{export_dir: string, export_dir_name: string}|WP_Error Array of paths on success, WP_Error on failure.
 */
function sse_setup_export_directories() {
	$export_base_dir = sse_get_export_directory_path();
	if ( is_wp_error( $export_base_dir ) ) {
		return $export_base_dir;
	}

	if ( sse_is_path_within_directory( dirname( $export_base_dir ), ABSPATH ) ) {
		sse_log( 'Private export base directory parent resolved inside the WordPress web root: ' . $export_base_dir, 'security' );
		return new WP_Error( 'export_dir_public', __( 'The export directory is inside the WordPress web root. Configure WP_TEMP_DIR to a private, non-public directory and try again.', 'enginescript-site-exporter' ) );
	}

	$base_dir_result = sse_prepare_export_base_directory( $export_base_dir );
	if ( is_wp_error( $base_dir_result ) ) {
		return $base_dir_result;
	}

	if ( sse_is_path_within_directory( $export_base_dir, ABSPATH ) ) {
		sse_log( 'Private export base directory resolved inside the WordPress web root: ' . $export_base_dir, 'security' );
		return new WP_Error( 'export_dir_public', __( 'The export directory is inside the WordPress web root. Configure WP_TEMP_DIR to a private, non-public directory and try again.', 'enginescript-site-exporter' ) );
	}

	$export_dir = sse_create_private_export_directory( $export_base_dir );
	if ( is_wp_error( $export_dir ) ) {
		return $export_dir;
	}

	$filesystem_init = sse_init_filesystem();
	if ( is_wp_error( $filesystem_init ) ) {
		return $filesystem_init;
	}

	global $wp_filesystem;
	if ( ! $wp_filesystem->is_writable( $export_dir ) ) {
		sse_log( 'Export directory is not writable: ' . $export_dir, 'error' );
		return new WP_Error( 'export_dir_not_writable', __( 'The export directory is not writable. Please adjust filesystem permissions.', 'enginescript-site-exporter' ) );
	}

	sse_create_index_file( $export_base_dir );

	return [
		'export_dir'      => $export_dir,
		'export_dir_name' => basename( $export_dir ),
	];
}

/**
 * Creates or verifies the fixed private export base directory.
 *
 * @since 2.1.1
 * @param string $export_base_dir Export base directory path.
 * @return true|WP_Error True on success, WP_Error on failure.
 */
function sse_prepare_export_base_directory( string $export_base_dir ) {
	if ( is_link( $export_base_dir ) ) {
		sse_log( 'Rejected symlinked export base directory: ' . $export_base_dir, 'security' );
		return new WP_Error( 'export_dir_symlink', __( 'The export directory is a symbolic link and cannot be used safely.', 'enginescript-site-exporter' ) );
	}

	if ( ! file_exists( $export_base_dir ) ) { // phpcs:ignore WordPressVIPMinimum.Functions.RestrictedFunctions.file_exists_file_exists -- Controlled private export directory creation.
		if ( ! mkdir( $export_base_dir, SSE_PRIVATE_DIR_MODE ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_mkdir -- Exact private mode is required for export secrecy.
			sse_log( 'Failed to create export base directory at path: ' . $export_base_dir, 'error' );
			return new WP_Error( 'export_dir_creation_failed', __( 'Could not create the export directory. Please verify filesystem permissions.', 'enginescript-site-exporter' ) );
		}
	}

	clearstatcache( true, $export_base_dir );

	if ( ! is_dir( $export_base_dir ) || is_link( $export_base_dir ) ) {
		sse_log( 'Rejected unsafe export base directory: ' . $export_base_dir, 'security' );
		return new WP_Error( 'export_dir_unsafe', __( 'The export directory exists but is not a safe private directory.', 'enginescript-site-exporter' ) );
	}

	if ( ! sse_chmod_private_directory( $export_base_dir ) ) {
		sse_log( 'Failed to enforce private permissions on export base directory: ' . $export_base_dir, 'security' );
		return new WP_Error( 'export_dir_permissions_failed', __( 'Could not secure the export directory permissions.', 'enginescript-site-exporter' ) );
	}

	return true;
}

/**
 * Creates a random private directory for a single export.
 *
 * @since 2.1.1
 * @param string $export_base_dir Private export base directory.
 * @return string|WP_Error Private per-export directory path on success, WP_Error on failure.
 */
function sse_create_private_export_directory( string $export_base_dir ) {
	for ( $attempt = 0; $attempt < 10; ++$attempt ) {
		$export_dir_name = sse_generate_private_export_directory_name();
		$export_dir      = trailingslashit( $export_base_dir ) . $export_dir_name;

		if ( file_exists( $export_dir ) || is_link( $export_dir ) ) { // phpcs:ignore WordPressVIPMinimum.Functions.RestrictedFunctions.file_exists_file_exists -- Reject pre-existing generated export paths.
			sse_log( 'Rejected pre-existing private export directory candidate: ' . $export_dir, 'security' );
			continue;
		}

		if ( ! mkdir( $export_dir, SSE_PRIVATE_DIR_MODE ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_mkdir -- Exact private mode is required for export secrecy.
			continue;
		}

		clearstatcache( true, $export_dir );

		if ( ! is_dir( $export_dir ) || is_link( $export_dir ) || ! sse_is_path_within_directory( $export_dir, $export_base_dir ) ) {
			sse_log( 'Rejected unsafe private export directory after creation: ' . $export_dir, 'security' );
			if ( is_dir( $export_dir ) && ! is_link( $export_dir ) ) {
				rmdir( $export_dir ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_rmdir -- Removing unsafe just-created export directory.
			}
			return new WP_Error( 'private_export_dir_unsafe', __( 'Could not create a safe private export directory.', 'enginescript-site-exporter' ) );
		}

		if ( ! sse_chmod_private_directory( $export_dir ) ) {
			sse_log( 'Failed to enforce private permissions on export directory: ' . $export_dir, 'security' );
			rmdir( $export_dir ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_rmdir -- Removing just-created export directory after permission failure.
			return new WP_Error( 'private_export_dir_permissions_failed', __( 'Could not secure the private export directory permissions.', 'enginescript-site-exporter' ) );
		}

		return $export_dir;
	}

	return new WP_Error( 'private_export_dir_creation_failed', __( 'Could not create a private export directory. Please verify filesystem permissions.', 'enginescript-site-exporter' ) );
}

/**
 * Creates protection files in the export directory to prevent directory listing
 * and deny direct HTTP access to export files.
 *
 * Creates:
 * - index.php: Prevents directory listing.
 * - .htaccess: Denies direct HTTP access to all files (Apache).
 *
 * @since 2.0.0
 * @param string $export_dir The export directory path.
 * @return void
 */
function sse_create_index_file( string $export_dir ): void {
	if ( is_wp_error( sse_init_filesystem() ) ) {
		return;
	}

	global $wp_filesystem;
	if ( ! $wp_filesystem->is_writable( $export_dir ) ) {
		sse_log( 'Failed to write protection files or directory not writable: ' . $export_dir, 'error' );
		return;
	}

	// Create index.php to prevent directory listing.
	$index_file_path = trailingslashit( $export_dir ) . 'index.php';
	if ( ! file_exists( $index_file_path ) ) { // phpcs:ignore WordPressVIPMinimum.Functions.RestrictedFunctions.file_exists_file_exists -- Checking controlled export directory
		$wp_filesystem->put_contents(
			$index_file_path,
			'<?php // Silence is golden.',
			SSE_PRIVATE_FILE_MODE
		);
	}
	if ( $wp_filesystem->exists( $index_file_path ) ) {
		sse_chmod_private_file( $index_file_path );
	}

	// Create .htaccess to deny direct HTTP access (Apache).
	$htaccess_path = trailingslashit( $export_dir ) . '.htaccess';
	if ( ! file_exists( $htaccess_path ) ) { // phpcs:ignore WordPressVIPMinimum.Functions.RestrictedFunctions.file_exists_file_exists -- Checking controlled export directory
		$htaccess_content  = "# Deny direct access to export files.\n";
		$htaccess_content .= "# For Nginx, add a location block to deny access to this directory.\n";
		$htaccess_content .= "<IfModule mod_authz_core.c>\n";
		$htaccess_content .= "\tRequire all denied\n";
		$htaccess_content .= "</IfModule>\n";
		$htaccess_content .= "<IfModule !mod_authz_core.c>\n";
		$htaccess_content .= "\tOrder deny,allow\n";
		$htaccess_content .= "\tDeny from all\n";
		$htaccess_content .= "</IfModule>\n";

		$wp_filesystem->put_contents(
			$htaccess_path,
			$htaccess_content,
			SSE_PRIVATE_FILE_MODE
		);
	}
	if ( $wp_filesystem->exists( $htaccess_path ) ) {
		sse_chmod_private_file( $htaccess_path );
	}
}

/**
 * Finds a safe path to the WP-CLI executable.
 *
 * @since 2.0.0
 * @return string|WP_Error The path to WP-CLI on success, or a WP_Error on failure.
 */
function sse_get_safe_wp_cli_path() {
	$trusted_system_paths = [
		'/usr/local/bin/wp',
		'/usr/bin/wp',
	];

	foreach ( $trusted_system_paths as $path ) {
		$validation = sse_validate_wp_cli_executable_path( $path );
		if ( ! is_wp_error( $validation ) ) {
			return $validation;
		}
	}

	$configured_path = sse_get_configured_wp_cli_path();
	if ( '' !== $configured_path ) {
		$validation = sse_validate_wp_cli_executable_path( $configured_path );
		if ( ! is_wp_error( $validation ) ) {
			return $validation;
		}

		return $validation;
	}

	return new WP_Error( 'wp_cli_not_found', __( 'WP-CLI executable not found in a trusted system location. Install WP-CLI at /usr/local/bin/wp or /usr/bin/wp, or explicitly configure a trusted executable with SSE_WP_CLI_PATH or the sse_wp_cli_path filter.', 'enginescript-site-exporter' ) );
}

/**
 * Gets an explicitly configured WP-CLI path.
 *
 * @since 2.1.1
 * @return string Configured path, or empty string.
 */
function sse_get_configured_wp_cli_path(): string {
	$configured_path = '';
	if ( defined( 'SSE_WP_CLI_PATH' ) && is_string( SSE_WP_CLI_PATH ) ) {
		$configured_path = SSE_WP_CLI_PATH;
	}

	/**
	 * Filters the explicit WP-CLI executable path.
	 *
	 * @since 2.1.1
	 *
	 * @param string $configured_path Explicit WP-CLI path, or empty string.
	 */
	$filtered_path = apply_filters( 'sse_wp_cli_path', $configured_path );
	if ( ! is_string( $filtered_path ) ) {
		return '';
	}

	return trim( $filtered_path );
}

/**
 * Validates a WP-CLI executable path, ownership, and mode.
 *
 * @since 2.1.1
 * @param string $path Candidate executable path.
 * @return string|WP_Error Resolved executable path on success, WP_Error on failure.
 */
function sse_validate_wp_cli_executable_path( string $path ) {
	if ( '' === $path || ! sse_is_absolute_path( $path ) ) {
		return new WP_Error( 'wp_cli_invalid_path', __( 'Configured WP-CLI path must be absolute.', 'enginescript-site-exporter' ) );
	}

	$resolved_path = realpath( $path );
	if ( false === $resolved_path || ! is_file( $resolved_path ) || ! is_executable( $resolved_path ) ) {
		return new WP_Error( 'wp_cli_not_executable', __( 'WP-CLI executable was not found or is not executable.', 'enginescript-site-exporter' ) );
	}

	if ( ! sse_wp_cli_has_safe_mode( $resolved_path ) ) {
		return new WP_Error( 'wp_cli_unsafe_mode', __( 'WP-CLI executable has unsafe writable permissions.', 'enginescript-site-exporter' ) );
	}

	if ( ! sse_wp_cli_has_safe_owner( $resolved_path ) ) {
		return new WP_Error( 'wp_cli_unsafe_owner', __( 'WP-CLI executable ownership is not trusted.', 'enginescript-site-exporter' ) );
	}

	return $resolved_path;
}

/**
 * Checks whether a path is absolute on Unix or Windows.
 *
 * @since 2.1.1
 * @param string $path Path to check.
 * @return bool True when the path is absolute.
 */
function sse_is_absolute_path( string $path ): bool {
	return 1 === preg_match( '#^(?:/|[A-Za-z]:[\\\\/])#', $path );
}

/**
 * Checks whether a WP-CLI executable rejects group/public writes.
 *
 * @since 2.1.1
 * @param string $path Resolved executable path.
 * @return bool True when mode is not group/public writable.
 */
function sse_wp_cli_has_safe_mode( string $path ): bool {
	$permissions = fileperms( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fileperms -- Required to verify executable mode.
	if ( false === $permissions ) {
		return false;
	}

	return 0 === ( $permissions & 0022 );
}

/**
 * Checks whether a WP-CLI executable has trusted ownership.
 *
 * Root-owned executables may be owner-writable. Non-root executables must not be
 * owner-writable, which prevents a writable web-root foothold from replacing an
 * explicitly configured local PHAR.
 *
 * @since 2.1.1
 * @param string $path Resolved executable path.
 * @return bool True when ownership and owner-write bits are acceptable.
 */
function sse_wp_cli_has_safe_owner( string $path ): bool {
	$owner       = fileowner( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fileowner -- Required to verify executable ownership.
	$permissions = fileperms( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fileperms -- Required to verify executable mode.

	if ( false === $owner || false === $permissions ) {
		return false;
	}

	if ( 0 === $owner ) {
		return true;
	}

	return 0 === ( $permissions & 0200 );
}

/**
 * Exports the database and returns file information.
 *
 * @since 1.0.0
 * @param string $export_dir      The directory to save the database dump.
 * @param string $site_identifier Sanitized site identifier.
 * @param string $timestamp       Export timestamp.
 * @return array{filename: string, filepath: string}|WP_Error Array with file info on success, WP_Error on failure.
 */
function sse_export_database( string $export_dir, string $site_identifier, string $timestamp ) {
	$db_filename = "{$site_identifier}_db_{$timestamp}.sql";
	$db_filepath = trailingslashit( $export_dir ) . $db_filename;

	if ( ! function_exists( 'shell_exec' ) ) {
		return new WP_Error( 'shell_exec_disabled', __( 'shell_exec function is disabled on this server.', 'enginescript-site-exporter' ) );
	}

	// Enhanced WP-CLI path validation.
	$wp_cli_path = sse_get_safe_wp_cli_path();
	if ( is_wp_error( $wp_cli_path ) ) {
		return $wp_cli_path;
	}

	// Only append --allow-root if we are actually running as root (hardening).
	$allow_root_flag = '';
	if ( function_exists( 'posix_geteuid' ) ) {
		if ( 0 === posix_geteuid() ) {
			$allow_root_flag = ' --allow-root';
		}
	}
	$command = sprintf(
		'%s db export %s --path=%s%s',
		escapeshellarg( $wp_cli_path ), // phpcs:ignore WordPressVIPMinimum.Functions.RestrictedFunctions.escapeshellarg_escapeshellarg -- Required for shell command security
		escapeshellarg( $db_filepath ), // phpcs:ignore WordPressVIPMinimum.Functions.RestrictedFunctions.escapeshellarg_escapeshellarg -- Required for shell command security
		escapeshellarg( ABSPATH ), // phpcs:ignore WordPressVIPMinimum.Functions.RestrictedFunctions.escapeshellarg_escapeshellarg -- Required for shell command security
		$allow_root_flag
	);

	$output = shell_exec( $command . ' 2>&1' ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.system_calls_shell_exec -- Required for WP-CLI database export: all parameters are validated and escaped with escapeshellarg()

	if ( ! file_exists( $db_filepath ) || filesize( $db_filepath ) <= 0 ) { // phpcs:ignore WordPressVIPMinimum.Functions.RestrictedFunctions.file_exists_file_exists -- Validating WP-CLI export success
		// Sanitize WP-CLI output to avoid leaking absolute paths or sensitive data.
		$safe_output = '';
		if ( is_string( $output ) && '' !== $output ) {
			$output_lines = preg_split( '/\r?\n/', $output );
			if ( false !== $output_lines ) {
				$output_lines = array_slice( $output_lines, 0, 5 );
				$output_lines = array_map(
					static function ( string $line ): string {
						// Remove absolute paths (rudimentary) and collapse whitespace.
						$line_without_paths = preg_replace( '#(/|[A-Za-z]:\\\\)[^\s]+#', '[path]', $line );
						if ( ! is_string( $line_without_paths ) ) {
							$line_without_paths = $line;
						}

						$line_with_collapsed_space = preg_replace( '/\s+/', ' ', $line_without_paths );
						if ( ! is_string( $line_with_collapsed_space ) ) {
							$line_with_collapsed_space = $line_without_paths;
						}

						return trim( $line_with_collapsed_space );
					},
					$output_lines
				);
				$safe_output  = sanitize_text_field( implode( ' | ', $output_lines ) );
			}
		}
		$error_message = '' !== $safe_output ? $safe_output : 'WP-CLI command failed silently.';
		return new WP_Error( 'db_export_failed', $error_message );
	}

	if ( ! sse_chmod_private_file( $db_filepath ) ) {
		sse_cleanup_files( [ $db_filepath ] );
		return new WP_Error( 'db_export_permissions_failed', __( 'Could not secure database export file permissions.', 'enginescript-site-exporter' ) );
	}

	sse_log( 'Database export successful', 'info' );
	return [
		'filename' => $db_filename,
		'filepath' => $db_filepath,
	];
}
