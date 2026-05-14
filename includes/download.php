<?php
/**
 * Download and deletion: secure file serving, rate limiting, export deletion.
 *
 * @package EngineScript_Site_Exporter
 */

if ( ! defined( 'ABSPATH' ) ) {
	return;
}

/**
 * Handles secure download requests for export files.
 *
 * @since 2.0.0
 * @return void
 */
function sse_handle_secure_download(): void { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
	$filename = isset( $_GET['file'] ) ? sanitize_file_name( wp_unslash( $_GET['file'] ) ) : '';
	if ( '' === $filename ) {
		sse_wp_die( __( 'No file specified.', 'enginescript-site-exporter' ), 400 );
	}

	check_admin_referer( 'sse_secure_download_' . $filename );

	// Verify user capabilities.
	if ( ! current_user_can( 'manage_options' ) ) {
		sse_wp_die( __( 'You do not have permission to download export files.', 'enginescript-site-exporter' ), 403 );
	}

	$validation = sse_validate_export_file_for_download( $filename );

	if ( sse_is_wp_error( $validation ) ) {
		sse_wp_die( $validation->get_error_message(), 404 );
	}

	// Rate limiting check.
	if ( ! sse_check_download_rate_limit() ) {
		sse_wp_die( __( 'Too many download requests. Please wait before trying again.', 'enginescript-site-exporter' ), 429 );
	}

	sse_serve_file_download( $validation );
}

/**
 * Handles manual deletion of export files.
 *
 * @since 2.0.0
 * @return void
 */
function sse_handle_export_deletion(): void { // phpcs:ignore WordPress.Security.NonceVerification.Missing
	$filename = isset( $_POST['file'] ) ? sanitize_file_name( wp_unslash( $_POST['file'] ) ) : '';
	if ( '' === $filename ) {
		sse_wp_die( __( 'No file specified.', 'enginescript-site-exporter' ), 400 );
	}

	check_admin_referer( 'sse_delete_export_' . $filename );

	// Verify user capabilities.
	if ( ! current_user_can( 'manage_options' ) ) {
		sse_wp_die( __( 'You do not have permission to delete export files.', 'enginescript-site-exporter' ), 403 );
	}

	$validation = sse_validate_basic_export_file( $filename );

	if ( sse_is_wp_error( $validation ) ) {
		sse_wp_die( $validation->get_error_message(), 404 );
	}

	if ( sse_safely_delete_file( $validation['filepath'] ) ) {
		sse_log( 'Manual deletion of export file: ' . $validation['filepath'], 'info' );
		sse_set_exporter_notice(
			[
				'type'    => 'success',
				'message' => __( 'Export file successfully deleted.', 'enginescript-site-exporter' ),
			]
		);
		sse_redirect_to_exporter_page();
	}

	sse_log( 'Failed manual deletion of export file: ' . $validation['filepath'], 'error' );
	sse_set_exporter_notice(
		[
			'type'    => 'error',
			'message' => __( 'Failed to delete export file.', 'enginescript-site-exporter' ),
		]
	);
	sse_redirect_to_exporter_page();
}

/**
 * Implements basic rate limiting for downloads.
 *
 * @since 2.0.0
 * @return bool True if request is within rate limits, false otherwise.
 */
function sse_check_download_rate_limit(): bool {
	$user_id        = get_current_user_id();
	$rate_limit_key = 'sse_download_rate_limit_' . $user_id;
	$current_time   = time();

	$last_download = get_transient( $rate_limit_key );

	// Allow one download per minute per user.
	if ( false !== $last_download && is_numeric( $last_download ) && ( $current_time - (int) $last_download ) < 60 ) {
		return false;
	}

	set_transient( $rate_limit_key, $current_time, 60 );
	return true;
}

/**
 * Sets appropriate headers for file download.
 *
 * @since 2.0.0
 * @param string $filename  The filename for download.
 * @param int    $filesize  The file size in bytes.
 * @return void
 */
function sse_set_download_headers( string $filename, int $filesize ): void {
	// Security: Set safe Content-Type based on file extension to prevent XSS.
	$file_extension = strtolower( pathinfo( $filename, PATHINFO_EXTENSION ) );
	switch ( $file_extension ) {
		case 'zip':
			$content_type = 'application/zip';
			break;
		default:
			// Security: Default to octet-stream for unknown types to prevent execution.
			$content_type = 'application/octet-stream';
			break;
	}

	// Security: Set headers to prevent XSS and ensure proper download behavior.
	header( 'Content-Type: ' . $content_type );
	header( 'Content-Disposition: attachment; filename="' . str_replace( '"', '', $filename ) . '"; filename*=UTF-8\'\'' . rawurlencode( $filename ) );
	header( 'Content-Length: ' . absint( $filesize ) );
	header( 'Cache-Control: no-cache, no-store, must-revalidate' );
	header( 'Pragma: no-cache' );
	header( 'Expires: 0' );
	header( 'X-Content-Type-Options: nosniff' ); // Security: Prevent MIME sniffing.
	header( 'X-Frame-Options: DENY' ); // Security: Prevent framing.

	// Disable output buffering for large files.
	if ( ob_get_level() ) {
		ob_end_clean();
	}
}

/**
 * Validates file output security before serving download.
 *
 * Security: Returns the realpath()-resolved filepath to ensure the path used for
 * readfile() is the same path that was validated (prevents TOCTOU and SSRF).
 *
 * @since 2.0.0
 * @param string $filepath The file path to validate.
 * @return string The realpath()-resolved file path, safe for readfile().
 */
function sse_validate_file_output_security( string $filepath ): string {
	// Security: Final validation before file output to prevent SSRF.
	if ( ! sse_validate_file_extension( $filepath ) ) {
		sse_log( 'Security: Blocked attempt to serve file with invalid extension: ' . pathinfo( $filepath, PATHINFO_EXTENSION ), 'security' );
		sse_wp_die( __( 'Access denied - invalid file type.', 'enginescript-site-exporter' ), 403 );
	}

	// Security: Ensure file is within our controlled directory before serving.
	$export_dir = sse_get_export_directory_path();
	if ( sse_is_wp_error( $export_dir ) ) {
		sse_wp_die( $export_dir->get_error_message() );
	}

	$real_file_path = sse_normalize_realpath( $filepath );
	if ( false === $real_file_path || ! sse_is_path_within_directory( $real_file_path, $export_dir ) ) {
		sse_log( 'Security: File not within controlled export directory: ' . $filepath, 'security' );
		sse_wp_die( __( 'Access denied.', 'enginescript-site-exporter' ), 403 );
	}

	return $real_file_path;
}

/**
 * Outputs file content for download.
 *
 * @since 2.0.0
 * @param string $filepath The validated file path.
 * @param string $filename The filename for logging.
 * @return never
 */
function sse_output_file_content( string $filepath, string $filename ): never {
	// Security: Validate and resolve to realpath before any filesystem access.
	$resolved_path = sse_validate_file_output_security( $filepath );

	// Security: Use resolved path (from realpath) for all filesystem operations to prevent SSRF/TOCTOU.
	if ( function_exists( 'readfile' ) && is_readable( $resolved_path ) && is_file( $resolved_path ) ) {
		readfile( $resolved_path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_readfile -- Security validated export file download.
		sse_log( 'Secure file download served via readfile: ' . $filename, 'info' );
		exit; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Required to terminate script after file download.
	}

	sse_log( 'Failed to serve secure file download: ' . $filename, 'error' );
	sse_wp_die( __( 'Unable to serve file download.', 'enginescript-site-exporter' ) );
}

/**
 * Serves a file download with enhanced security validation.
 *
 * @since 2.0.0
 * @param array{filename: string, filesize: int, filepath: string} $file_data Validated file information array.
 * @return never
 */
function sse_serve_file_download( array $file_data ): never {
	// Set download headers.
	sse_set_download_headers( $file_data['filename'], $file_data['filesize'] );

	// Output file content (includes final security validation before readfile).
	sse_output_file_content( $file_data['filepath'], $file_data['filename'] );
}
