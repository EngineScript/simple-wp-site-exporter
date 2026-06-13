<?php
/**
 * Helper utilities: logging, IP detection, export paths, redirects, and filesystem init.
 *
 * @package EngineScript_Site_Exporter
 */

if ( ! defined( 'ABSPATH' ) ) {
	return;
}

/**
 * Safely get client IP address.
 *
 * @since 1.0.0
 * @return string Client IP address or 'unknown' if not available.
 */
function sse_get_client_ip(): string {
	$client_ip = filter_input( INPUT_SERVER, 'REMOTE_ADDR', FILTER_VALIDATE_IP );

	if ( is_string( $client_ip ) ) {
		return $client_ip;
	}

	return 'unknown';
}

/**
 * Stores important log messages in database for review.
 *
 * @since 1.0.0
 * @param string $message The log message.
 * @param string $level   The log level.
 * @return void
 */
function sse_store_log_in_database( string $message, string $level ): void {
	// Store last 20 important messages in an option.
	$logs   = get_option( 'sse_error_logs', [] );
	$logs[] = [
		'time'    => time(),
		'level'   => $level,
		'message' => $message,
		'user_id' => get_current_user_id(),
		'ip'      => sse_get_client_ip(),
	];

	// Keep only the most recent 20 logs.
	if ( count( $logs ) > 20 ) {
		$logs = array_slice( $logs, -20 );
	}

	update_option( 'sse_error_logs', $logs, false );
}

/**
 * Outputs log message to the WordPress debug log.
 *
 * @since 1.0.0
 * @param string $formatted_message The formatted log message.
 * @return void
 */
function sse_output_log_message( string $formatted_message ): void {
	if ( function_exists( 'wp_debug_log' ) ) {
		wp_debug_log( $formatted_message );
		return;
	}

	error_log( $formatted_message ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Fallback for older WordPress installs; sse_log() already checks WP_DEBUG_LOG.
}

/**
 * Safely log plugin messages
 *
 * @since 1.0.0
 * @param string $message The message to log.
 * @param string $level   The log level (error, warning, info).
 * @return void
 */
function sse_log( string $message, string $level = 'info' ): void {
	// Check if WP_DEBUG is enabled.
	if ( ! defined( 'WP_DEBUG' ) || ! WP_DEBUG ) {
		return;
	}

	// Format the message with a timestamp (using GMT to avoid timezone issues).
	$formatted_message = sprintf(
		'[%s] [%s] %s: %s',
		gmdate( 'Y-m-d H:i:s' ),
		'EngineScript Site Exporter',
		strtoupper( $level ),
		$message
	);

	// Only log if debug logging is enabled.
	if ( ! defined( 'WP_DEBUG_LOG' ) || ! WP_DEBUG_LOG ) {
		return;
	}

	sse_output_log_message( $formatted_message );

	// Store logs in the database (errors and security events to prevent issues).
	if ( 'error' === $level || 'security' === $level ) {
		sse_store_log_in_database( $message, $level );
	}
}

/**
 * Safely get the PHP execution time limit.
 *
 * @since 1.0.0
 * @return int Current PHP execution time limit in seconds.
 */
function sse_get_execution_time_limit(): int {
	// Get the current execution time limit.
	$max_exec_time = ini_get( 'max_execution_time' );

	// Handle all possible return types from ini_get().
	if ( false === $max_exec_time ) {
		// Ini_get failed.
		return 30;
	}

	if ( '' === $max_exec_time ) {
		// Empty string returned.
		return 30;
	}

	if ( ! is_numeric( $max_exec_time ) ) {
		// Non-numeric value returned.
		return 30;
	}

	return (int) $max_exec_time;
}

/**
 * Builds the canonical combined EngineScript archive filename.
 *
 * @since 2.0.0
 * @param string $site_identifier Sanitized site identifier.
 * @param string $timestamp       Export timestamp in Ymd_His format.
 * @return string Combined ZIP filename.
 */
function sse_get_engine_script_archive_filename( string $site_identifier, string $timestamp ): string {
	return $site_identifier . '_' . SSE_EXPORT_ARCHIVE_MARKER . '_' . $timestamp . '.zip';
}

/**
 * Gets the validation regex for combined EngineScript archive filenames.
 *
 * @since 2.0.0
 * @return non-empty-string Regex pattern with site_identifier and timestamp capture groups.
 */
function sse_get_engine_script_archive_filename_pattern(): string {
	return '/^(?P<site_identifier>[a-zA-Z0-9._-]+)_' . preg_quote( SSE_EXPORT_ARCHIVE_MARKER, '/' ) . '_(?P<timestamp>\d{8}_\d{6})\.zip$/';
}

/**
 * Checks whether a filename matches the canonical combined archive format.
 *
 * @since 2.0.0
 * @param string $filename Filename to validate.
 * @return bool True when the filename matches the generated archive format.
 */
function sse_is_engine_script_archive_filename( string $filename ): bool {
	if ( ! preg_match( sse_get_engine_script_archive_filename_pattern(), $filename, $matches ) ) {
		return false;
	}

	$site_identifier = $matches['site_identifier'] ?? '';
	$timestamp       = $matches['timestamp'] ?? '';

	if ( '' === $site_identifier || '' === $timestamp ) {
		return false;
	}

	return sse_get_engine_script_archive_filename( $site_identifier, $timestamp ) === $filename;
}

/**
 * Gets the private export directory path.
 *
 * Exports contain a full database dump and site files, so they should not live
 * in the public uploads tree. WordPress' temp directory is the safest native
 * default and can be moved with WP_TEMP_DIR when a host needs a custom path.
 *
 * @since 2.0.0
 * @return string|WP_Error Export directory path on success, WP_Error on failure.
 */
function sse_get_export_directory_path() {
	$temp_dir = get_temp_dir();
	if ( '' === $temp_dir ) {
		return new WP_Error( 'temp_dir_unavailable', __( 'Could not determine a private temporary directory for exports.', 'enginescript-site-exporter' ) );
	}

	return trailingslashit( $temp_dir ) . SSE_EXPORT_DIR_NAME;
}

/**
 * Gets the capability used to show the exporter menu.
 *
 * @since 2.1.1
 * @return string WordPress capability.
 */
function sse_get_exporter_menu_capability(): string {
	return is_multisite() ? 'manage_network_options' : 'manage_options';
}

/**
 * Checks whether the current user may perform full-site export actions.
 *
 * On multisite, the export contains the full database and files under ABSPATH,
 * so site admins are not sufficient.
 *
 * @since 2.1.1
 * @return bool True when the current user may export, download, or delete exports.
 */
function sse_current_user_can_export_site(): bool {
	if ( is_multisite() ) {
		return is_super_admin() || current_user_can( 'manage_network_options' );
	}

	return current_user_can( 'manage_options' );
}

/**
 * Gets the validation regex for private per-export directory names.
 *
 * @since 2.1.1
 * @return non-empty-string Regex pattern for generated private directory names.
 */
function sse_get_export_private_directory_name_pattern(): string {
	return '/^' . preg_quote( SSE_EXPORT_PRIVATE_DIR_PREFIX, '/' ) . '\d{8}_\d{6}-[a-f0-9]{32}$/';
}

/**
 * Checks whether a directory name matches the generated private export format.
 *
 * @since 2.1.1
 * @param string $directory_name Directory basename to validate.
 * @return bool True when the directory name matches the generated format.
 */
function sse_is_export_private_directory_name( string $directory_name ): bool {
	return 1 === preg_match( sse_get_export_private_directory_name_pattern(), $directory_name );
}

/**
 * Generates a private per-export directory name.
 *
 * @since 2.1.1
 * @return string Private export directory basename.
 */
function sse_generate_private_export_directory_name(): string {
	try {
		$random_suffix = bin2hex( random_bytes( 16 ) );
	} catch ( Exception $e ) {
		$random_suffix = '';
		for ( $index = 0; $index < 32; ++$index ) {
			$random_suffix .= dechex( wp_rand( 0, 15 ) );
		}
	}

	return SSE_EXPORT_PRIVATE_DIR_PREFIX . gmdate( 'Ymd_His' ) . '-' . $random_suffix;
}

/**
 * Checks whether a filesystem path has no group or public permission bits.
 *
 * @since 2.1.1
 * @param string $path Path to inspect.
 * @return bool True when group/other permissions are not set.
 */
function sse_has_private_mode( string $path ): bool {
	$permissions = fileperms( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fileperms -- Required to verify private filesystem modes.
	if ( false === $permissions ) {
		return false;
	}

	return 0 === ( $permissions & 0077 );
}

/**
 * Applies and verifies a private filesystem mode.
 *
 * @since 2.1.1
 * @param string $path Path to chmod.
 * @param int    $mode Mode to apply.
 * @return bool True when chmod succeeds and no group/public bits remain.
 */
function sse_chmod_private_path( string $path, int $mode ): bool {
	if ( ! chmod( $path, $mode ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- Export secrecy requires exact private file modes.
		return false;
	}

	clearstatcache( true, $path );

	return sse_has_private_mode( $path );
}

/**
 * Applies and verifies private directory permissions.
 *
 * @since 2.1.1
 * @param string $directory Directory path.
 * @return bool True when the directory is private.
 */
function sse_chmod_private_directory( string $directory ): bool {
	return sse_chmod_private_path( $directory, SSE_PRIVATE_DIR_MODE );
}

/**
 * Applies and verifies private file permissions.
 *
 * @since 2.1.1
 * @param string $file_path File path.
 * @return bool True when the file is private.
 */
function sse_chmod_private_file( string $file_path ): bool {
	return sse_chmod_private_path( $file_path, SSE_PRIVATE_FILE_MODE );
}

/**
 * Redirects back to the exporter admin page.
 *
 * @since 2.0.0
 * @param array<string, string> $args Optional query args.
 * @return never
 */
function sse_redirect_to_exporter_page( array $args = [] ): never {
	wp_safe_redirect(
		add_query_arg(
			$args,
			admin_url( 'tools.php?page=enginescript-site-exporter' )
		)
	);
	exit; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Required after wp_safe_redirect().
}

/**
 * Stops execution with an escaped WordPress error response.
 *
 * @since 2.0.0
 * @param string $message  Error message.
 * @param int    $response HTTP response code.
 * @return never
 *
 * @psalm-suppress InvalidReturnType WordPress exits from wp_die() at runtime.
 */
function sse_wp_die( string $message, int $response = 500 ): never {
	wp_die(
		esc_html( $message ),
		'',
		[
			'response' => absint( $response ),
		]
	);
}

/**
 * Initializes the WordPress Filesystem API.
 *
 * Centralizes the repeated WP_Filesystem initialization pattern
 * used across multiple functions.
 *
 * @since 2.0.0
 * @return true|WP_Error True on success, WP_Error on failure.
 */
function sse_init_filesystem() {
	global $wp_filesystem;

	if ( ! empty( $wp_filesystem ) ) {
		return true;
	}

	/**
	 * WordPress core is available at runtime.
	 *
	 * @psalm-suppress MissingFile
	 */
	require_once ABSPATH . 'wp-admin/includes/file.php';
	if ( ! WP_Filesystem() ) {
		sse_log( 'Failed to initialize WordPress filesystem API', 'error' );
		return new WP_Error( 'filesystem_init_failed', __( 'Failed to initialize WordPress filesystem API.', 'enginescript-site-exporter' ) );
	}

	return true;
}
