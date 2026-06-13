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
	if ( false !== wp_next_scheduled( 'sse_delete_export_file', [ $zip_filepath ] ) ) {
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
	if ( false !== wp_next_scheduled( 'sse_bulk_cleanup_exports' ) ) {
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
	if ( is_wp_error( $export_dir ) ) {
		sse_log( 'Could not determine export directory for cleanup: ' . $export_dir->get_error_message(), 'error' );
		return;
	}

	if ( ! is_dir( $export_dir ) ) {
		sse_log( 'Export directory does not exist, nothing to clean up', 'info' );
		return;
	}

	$files = sse_get_export_files_for_bulk_cleanup( $export_dir );

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
 * Gets export ZIP files eligible for bulk cleanup lookup.
 *
 * @since 2.1.1
 * @param string $export_dir Export base directory.
 * @return string[] Export ZIP file paths.
 */
function sse_get_export_files_for_bulk_cleanup( string $export_dir ): array {
	try {
		$dir_iterator = new DirectoryIterator( $export_dir );
	} catch ( RuntimeException $e ) {
		sse_log( 'Failed to read export directory: ' . $e->getMessage(), 'error' );
		return [];
	}

	$files = [];
	foreach ( $dir_iterator as $entry ) {
		$files = array_merge( $files, sse_get_export_files_from_directory_entry( $entry ) );
	}

	return $files;
}

/**
 * Gets export ZIP paths represented by one export base directory entry.
 *
 * @since 2.1.1
 * @param DirectoryIterator $entry Directory entry.
 * @return string[] Export ZIP file paths.
 */
function sse_get_export_files_from_directory_entry( DirectoryIterator $entry ): array {
	if ( $entry->isDot() || $entry->isLink() ) {
		return [];
	}

	if ( sse_is_export_zip_entry( $entry ) ) {
		return [ $entry->getPathname() ];
	}

	if ( ! $entry->isDir() || ! sse_is_export_private_directory_name( $entry->getFilename() ) ) {
		return [];
	}

	return sse_get_export_files_from_private_directory( $entry->getPathname() );
}

/**
 * Gets export ZIP paths from a private per-export directory.
 *
 * @since 2.1.1
 * @param string $directory Private export directory.
 * @return string[] Export ZIP file paths.
 */
function sse_get_export_files_from_private_directory( string $directory ): array {
	try {
		$private_dir_iterator = new DirectoryIterator( $directory );
	} catch ( RuntimeException $e ) {
		sse_log( 'Failed to read private export directory: ' . $e->getMessage(), 'error' );
		return [];
	}

	$files = [];
	foreach ( $private_dir_iterator as $private_entry ) {
		if ( sse_is_export_zip_entry( $private_entry ) ) {
			$files[] = $private_entry->getPathname();
		}
	}

	return $files;
}

/**
 * Checks whether a directory entry is an export ZIP file.
 *
 * @since 2.1.1
 * @param DirectoryIterator $entry Directory entry.
 * @return bool True when the entry is a ZIP file.
 */
function sse_is_export_zip_entry( DirectoryIterator $entry ): bool {
	return ! $entry->isDot() && ! $entry->isLink() && $entry->isFile() && '.zip' === substr( $entry->getFilename(), -4 );
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

	$filename        = basename( $file_path );
	$export_dir_name = basename( dirname( $file_path ) );
	if ( ! sse_is_export_private_directory_name( $export_dir_name ) ) {
		$export_dir_name = '';
	}

	$validation = sse_validate_basic_export_file( $filename, $export_dir_name );

	if ( is_wp_error( $validation ) ) {
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
	if ( is_wp_error( $format_validation ) ) {
		sse_log( 'Scheduled deletion blocked - invalid file: ' . $file . ' - ' . $format_validation->get_error_message(), 'warning' );
		return;
	}

	if ( ! file_exists( $file ) ) { // phpcs:ignore WordPressVIPMinimum.Functions.RestrictedFunctions.file_exists_file_exists -- Scheduled cleanup gracefully handles already-deleted exports.
		sse_log( 'Scheduled deletion skipped - file already removed: ' . $filename, 'info' );
		return;
	}

	$export_dir_name = basename( dirname( $file ) );
	if ( ! sse_is_export_private_directory_name( $export_dir_name ) ) {
		$export_dir_name = '';
	}

	$validation = sse_validate_export_file_path( $filename, $export_dir_name );
	if ( is_wp_error( $validation ) ) {
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
	/**
	 * WordPress core is available at runtime.
	 *
	 * @psalm-suppress MissingFile
	 */
	require_once ABSPATH . 'wp-admin/includes/file.php';

	$export_dir = sse_get_export_directory_path();
	if ( is_wp_error( $export_dir ) ) {
		return false;
	}

	$deleted = wp_delete_file_from_directory( $filepath, $export_dir );
	if ( $deleted ) {
		sse_delete_empty_private_export_directory( dirname( $filepath ), $export_dir );
	}

	return $deleted;
}

/**
 * Deletes an empty generated private export directory.
 *
 * @since 2.1.1
 * @param string $directory  Candidate private export directory path.
 * @param string $export_dir Export base directory path.
 * @return void
 */
function sse_delete_empty_private_export_directory( string $directory, string $export_dir ): void {
	if ( ! sse_is_export_private_directory_name( basename( $directory ) ) ) {
		return;
	}

	if ( ! is_dir( $directory ) || is_link( $directory ) || ! sse_is_path_within_directory( $directory, $export_dir ) ) {
		return;
	}

	try {
		$dir_iterator = new DirectoryIterator( $directory );
		foreach ( $dir_iterator as $entry ) {
			if ( ! $entry->isDot() ) {
				return;
			}
		}
	} catch ( RuntimeException $e ) {
		return;
	}

	rmdir( $directory ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_rmdir -- Removes empty generated private export directories after file cleanup.
}
