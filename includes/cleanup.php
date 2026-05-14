<?php
/**
 * File cleanup: scheduled deletion, bulk cleanup, temporary file removal.
 *
 * @package EngineScript_Site_Exporter
 */

if ( ! defined( 'ABSPATH' ) ) {
	return;
}

/**
 * Cleans up temporary files.
 *
 * @since 1.0.0
 * @param string[] $files Array of file paths to delete.
 * @return void
 */
function sse_cleanup_files( array $files ): void {
	foreach ( $files as $file ) {
		if ( sse_safely_delete_file( $file ) ) {
			sse_log( 'Cleaned up temporary file: ' . $file, 'info' );
		}
	}
}

/**
 * Schedules cleanup of export files.
 *
 * @since 1.0.0
 * @param string $zip_filepath The ZIP file path to schedule for deletion.
 * @return void
 */
function sse_schedule_export_cleanup( string $zip_filepath ): void {
	// Check if already scheduled.
	if ( wp_next_scheduled( 'sse_delete_export_file', [ $zip_filepath ] ) ) {
		return;
	}

	$scheduled_time = time() + ( 5 * 60 );
	$result         = wp_schedule_single_event( $scheduled_time, 'sse_delete_export_file', [ $zip_filepath ] );

	if ( false === $result ) {
		sse_log( 'Failed to schedule export file deletion: ' . $zip_filepath, 'error' );
		$cron_disabled = defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON;
		if ( $cron_disabled ) {
			sse_log( 'DISABLE_WP_CRON is true — cron events will not fire automatically', 'warning' );
		}
	} else {
		sse_log( 'Export file deletion scheduled for ' . gmdate( 'Y-m-d H:i:s', $scheduled_time ) . ' GMT: ' . $zip_filepath, 'info' );
	}
}

/**
 * Schedules a bulk cleanup of all export files in the private export directory.
 * This runs as a safety net to catch any files that individual cleanup missed.
 *
 * @since 2.0.0
 * @return void
 */
function sse_schedule_bulk_cleanup(): void {
	if ( wp_next_scheduled( 'sse_bulk_cleanup_exports' ) ) {
		return;
	}

	$scheduled_time = time() + ( 10 * 60 );
	$result         = wp_schedule_single_event( $scheduled_time, 'sse_bulk_cleanup_exports' );

	if ( false === $result ) {
		sse_log( 'Failed to schedule bulk export cleanup', 'error' );
	}
}

/**
 * Handles bulk cleanup of all export files older than 5 minutes.
 * This is a safety net to catch any files missed by individual cleanup.
 *
 * @since 2.0.0
 * @return void
 */
function sse_bulk_cleanup_exports_handler(): void {
	sse_log( 'Bulk export cleanup handler triggered', 'info' );

	$export_dir = sse_get_export_directory_path();
	if ( sse_is_wp_error( $export_dir ) ) {
		sse_log( 'Could not determine export directory for cleanup: ' . $export_dir->get_error_message(), 'error' );
		return;
	}

	if ( ! is_dir( $export_dir ) ) {
		sse_log( 'Export directory does not exist, nothing to clean up', 'info' );
		return;
	}

	try {
		$dir_iterator = new DirectoryIterator( $export_dir );
	} catch ( RuntimeException $e ) {
		sse_log( 'Failed to read export directory: ' . $e->getMessage(), 'error' );
		return;
	}

	$files = [];
	foreach ( $dir_iterator as $entry ) {
		if ( $entry->isDot() || ! $entry->isFile() ) {
			continue;
		}
		if ( '.zip' === substr( $entry->getFilename(), -4 ) ) {
			$files[] = $entry->getPathname();
		}
	}

	if ( empty( $files ) ) {
		sse_log( 'No export files found in bulk cleanup', 'info' );
		return;
	}

	$cleaned_count = 0;
	$cutoff_time   = time() - ( 5 * 60 ); // Files older than 5 minutes.

	foreach ( $files as $file_path ) {
		if ( sse_cleanup_expired_export_file( $file_path, $cutoff_time ) ) {
			++$cleaned_count;
		}
	}

	sse_log( "Bulk cleanup completed. Deleted {$cleaned_count} export files.", 'info' );
}

/**
 * Attempts to clean up a single expired export file.
 *
 * @since 2.0.0
 * @param string $file_path   The file path to check and potentially delete.
 * @param int    $cutoff_time Unix timestamp; files modified before this are eligible.
 * @return bool True if the file was deleted, false otherwise.
 */
function sse_cleanup_expired_export_file( string $file_path, int $cutoff_time ): bool {
	$file_time = filemtime( $file_path );

	if ( false === $file_time || $file_time >= $cutoff_time ) {
		return false;
	}

	$filename   = basename( $file_path );
	$validation = sse_validate_basic_export_file( $filename );

	if ( sse_is_wp_error( $validation ) ) {
		sse_log( 'Bulk cleanup skipped invalid file: ' . $file_path . ' - ' . $validation->get_error_message(), 'warning' );
		return false;
	}

	if ( sse_safely_delete_file( $validation['filepath'] ) ) {
		sse_log( 'Bulk cleanup deleted export file: ' . $validation['filepath'], 'info' );
		return true;
	}

	sse_log( 'Bulk cleanup failed to delete: ' . $file_path, 'error' );
	return false;
}

/**
 * Handles scheduled deletion of export files.
 *
 * @since 1.0.0
 * @param string $file File path to delete.
 * @return void
 */
function sse_delete_export_file_handler( string $file ): void {
	sse_log( 'Scheduled deletion handler triggered for file: ' . $file, 'info' );

	// Validate that this is actually an export file before deletion.
	$filename = basename( $file );

	$format_validation = sse_validate_filename_format( $filename );
	if ( sse_is_wp_error( $format_validation ) ) {
		sse_log( 'Scheduled deletion blocked - invalid file: ' . $file . ' - ' . $format_validation->get_error_message(), 'warning' );
		return;
	}

	$validation = sse_validate_export_file_path( $filename );
	if ( sse_is_wp_error( $validation ) ) {
		sse_log( 'Scheduled deletion blocked - invalid file: ' . $file . ' - ' . $validation->get_error_message(), 'warning' );
		return;
	}

	$validated_file = $validation['filepath'];
	if ( file_exists( $validated_file ) ) { // phpcs:ignore WordPressVIPMinimum.Functions.RestrictedFunctions.file_exists_file_exists -- Controlled scheduled deletion validation
		if ( sse_safely_delete_file( $validated_file ) ) {
			sse_log( 'Scheduled deletion successful: ' . $validated_file, 'info' );
			return;
		}
		sse_log( 'Scheduled deletion failed: ' . $validated_file, 'error' );
	} else {
		// Graceful handling: file already gone (likely manually deleted) - not an error.
		sse_log( 'Scheduled deletion skipped - file already removed: ' . $validated_file, 'info' );
	}
}

/**
 * Safely delete a file using WordPress' directory containment helper.
 *
 * @since 1.0.0
 * @param string $filepath Path to the file to delete.
 * @return bool Whether the file was deleted successfully.
 */
function sse_safely_delete_file( string $filepath ): bool {
	require_once ABSPATH . 'wp-admin/includes/file.php';

	$export_dir = sse_get_export_directory_path();
	if ( sse_is_wp_error( $export_dir ) ) {
		return false;
	}

	return wp_delete_file_from_directory( $filepath, $export_dir );
}
