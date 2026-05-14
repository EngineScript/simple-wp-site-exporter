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
	// Use WordPress logging (wp_debug_log is available in WP 5.1+).
	if ( function_exists( 'wp_debug_log' ) ) {
		wp_debug_log( $formatted_message );
	}
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
 * Redirects back to the exporter admin page.
 *
 * @since 2.0.0
 * @param array<string, string> $args Optional query args.
 * @return void
 */
function sse_redirect_to_exporter_page( array $args = [] ): void {
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
 * @return void
 */
function sse_wp_die( string $message, int $response = 500 ): void {
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

	require_once ABSPATH . 'wp-admin/includes/file.php';
	if ( ! WP_Filesystem() ) {
		sse_log( 'Failed to initialize WordPress filesystem API', 'error' );
		return new WP_Error( 'filesystem_init_failed', __( 'Failed to initialize WordPress filesystem API.', 'enginescript-site-exporter' ) );
	}

	return true;
}
