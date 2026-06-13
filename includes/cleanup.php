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

	$filesystem_init = sse_init_filesystem();
	if ( is_wp_error( $filesystem_init ) ) {
		sse_log( 'Could not initialize filesystem for cleanup: ' . $filesystem_init->get_error_message(), 'error' );
		return;
	}

	global $wp_filesystem;
	if ( ! $wp_filesystem->is_dir( $export_dir ) ) {
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
	$filesystem_init = sse_init_filesystem();
	if ( is_wp_error( $filesystem_init ) ) {
		sse_log( 'Failed to initialize filesystem for export cleanup: ' . $filesystem_init->get_error_message(), 'error' );
		return [];
	}

	global $wp_filesystem;
	$dir_entries = $wp_filesystem->dirlist( $export_dir, true, false );
	if ( ! is_array( $dir_entries ) ) {
		sse_log( 'Failed to read export directory for cleanup.', 'error' );
		return [];
	}

	$files = [];
	foreach ( $dir_entries as $entry_name => $entry ) {
		$files = array_merge( $files, sse_get_export_files_from_directory_entry( (string) $entry_name, $entry, $export_dir ) );
	}

	return $files;
}

/**
 * Gets export ZIP paths represented by one export base directory entry.
 *
 * @since 2.1.1
 * @param string              $entry_name Directory entry name.
 * @param array<string,mixed> $entry      Directory entry data from WP_Filesystem::dirlist().
 * @param string              $export_dir Export base directory.
 * @return string[] Export ZIP file paths.
 */
function sse_get_export_files_from_directory_entry( string $entry_name, array $entry, string $export_dir ): array {
	$filename = isset( $entry['name'] ) && is_string( $entry['name'] ) ? $entry['name'] : $entry_name;
	$type     = isset( $entry['type'] ) && is_string( $entry['type'] ) ? $entry['type'] : '';

	if ( '.' === $filename || '..' === $filename || 'l' === $type ) {
		return [];
	}

	$entry_path = trailingslashit( $export_dir ) . $filename;
	if ( sse_is_export_zip_entry( $filename, $type ) ) {
		return [ $entry_path ];
	}

	if ( 'd' !== $type || ! sse_is_export_private_directory_name( $filename ) ) {
		return [];
	}

	return sse_get_export_files_from_private_directory( $entry_path );
}

/**
 * Gets export ZIP paths from a private per-export directory.
 *
 * @since 2.1.1
 * @param string $directory Private export directory.
 * @return string[] Export ZIP file paths.
 */
function sse_get_export_files_from_private_directory( string $directory ): array {
	$filesystem_init = sse_init_filesystem();
	if ( is_wp_error( $filesystem_init ) ) {
		sse_log( 'Failed to initialize filesystem for private export cleanup: ' . $filesystem_init->get_error_message(), 'error' );
		return [];
	}

	global $wp_filesystem;
	$private_entries = $wp_filesystem->dirlist( $directory, true, false );
	if ( ! is_array( $private_entries ) ) {
		sse_log( 'Failed to read private export directory for cleanup.', 'error' );
		return [];
	}

	$files = [];
	foreach ( $private_entries as $entry_name => $entry ) {
		if ( ! is_array( $entry ) ) {
			continue;
		}

		$filename = isset( $entry['name'] ) && is_string( $entry['name'] ) ? $entry['name'] : (string) $entry_name;
		$type     = isset( $entry['type'] ) && is_string( $entry['type'] ) ? $entry['type'] : '';
		if ( sse_is_export_zip_entry( $filename, $type ) ) {
			$files[] = trailingslashit( $directory ) . $filename;
		}
	}

	return $files;
}

/**
 * Checks whether a directory entry is an export ZIP file.
 *
 * @since 2.1.1
 * @param string $filename Directory entry filename.
 * @param string $type     Directory entry type.
 * @return bool True when the entry is a ZIP file.
 */
function sse_is_export_zip_entry( string $filename, string $type ): bool {
	return 'f' === $type && '.zip' === substr( $filename, -4 );
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
	$filesystem_init = sse_init_filesystem();
	if ( is_wp_error( $filesystem_init ) ) {
		return false;
	}

	global $wp_filesystem;
	$file_time = $wp_filesystem->mtime( $file_path );

	if ( false === $file_time || $file_time >= $cutoff_time ) {
		return false;
	}

	$filename        = wp_basename( $file_path );
	$export_dir_name = wp_basename( dirname( $file_path ) );
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
	$filename = wp_basename( $file );

	$format_validation = sse_validate_filename_format( $filename );
	if ( is_wp_error( $format_validation ) ) {
		sse_log( 'Scheduled deletion blocked - invalid file: ' . $file . ' - ' . $format_validation->get_error_message(), 'warning' );
		return;
	}

	$filesystem_init = sse_init_filesystem();
	if ( is_wp_error( $filesystem_init ) ) {
		sse_log( 'Scheduled deletion blocked - filesystem unavailable: ' . $filesystem_init->get_error_message(), 'error' );
		return;
	}

	global $wp_filesystem;
	if ( ! $wp_filesystem->exists( $file ) ) {
		sse_log( 'Scheduled deletion skipped - file already removed: ' . $filename, 'info' );
		return;
	}

	$export_dir_name = wp_basename( dirname( $file ) );
	if ( ! sse_is_export_private_directory_name( $export_dir_name ) ) {
		$export_dir_name = '';
	}

	$validation = sse_validate_export_file_path( $filename, $export_dir_name );
	if ( is_wp_error( $validation ) ) {
		sse_log( 'Scheduled deletion blocked - invalid file: ' . $file . ' - ' . $validation->get_error_message(), 'warning' );
		return;
	}

	$validated_file = $validation['filepath'];
	if ( $wp_filesystem->exists( $validated_file ) ) {
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
	$filesystem_init = sse_init_filesystem();
	if ( is_wp_error( $filesystem_init ) ) {
		return;
	}

	if ( ! sse_is_export_private_directory_name( wp_basename( $directory ) ) ) {
		return;
	}

	global $wp_filesystem;
	if ( ! $wp_filesystem->is_dir( $directory ) || is_link( $directory ) || ! sse_is_path_within_directory( $directory, $export_dir ) ) {
		return;
	}

	$dir_entries = $wp_filesystem->dirlist( $directory, true, false );
	if ( ! is_array( $dir_entries ) || [] !== $dir_entries ) {
		return;
	}

	$wp_filesystem->delete( $directory, false, 'd' );
}
