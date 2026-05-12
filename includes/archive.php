<?php
/**
 * EngineScript archive operations: ZIP bundle creation, file iteration, exclusion logic.
 *
 * @package EngineScript_Site_Exporter
 */

if ( ! defined( 'ABSPATH' ) ) {
	return;
}

/**
 * Gets the site identifier used in EngineScript archive filenames.
 *
 * @since 2.0.0
 * @return string Sanitized site identifier.
 */
function sse_get_export_site_identifier(): string {
	$site_host = wp_parse_url( home_url( '/' ), PHP_URL_HOST );
	if ( ! is_string( $site_host ) || '' === $site_host ) {
		$site_host = get_bloginfo( 'name' );
	}

	$site_identifier = sanitize_file_name( strtolower( $site_host ) );
	if ( '' === $site_identifier ) {
		return 'wordpress-site';
	}

	return $site_identifier;
}

/**
 * Gets the current EngineScript export timestamp.
 *
 * @since 2.0.0
 * @return string Timestamp formatted to match EngineScript shell exports.
 */
function sse_get_export_timestamp(): string {
	return gmdate( 'Ymd_His' );
}

/**
 * Checks whether a resolved path stays within the export source directory.
 *
 * @since 2.0.0
 * @param string $path      Path to check.
 * @param string $directory Directory that must contain the path.
 * @return bool True if the path resolves inside the directory.
 */
function sse_is_path_within_export_source( string $path, string $directory ): bool {
	$real_path      = realpath( $path );
	$real_directory = realpath( $directory );

	if ( false === $real_path || false === $real_directory ) {
		return false;
	}

	$real_path      = wp_normalize_path( $real_path );
	$real_directory = trailingslashit( wp_normalize_path( $real_directory ) );

	return 0 === strpos( $real_path, $real_directory );
}

/**
 * Creates a site archive with database and files.
 *
 * @since 1.0.0
 * @param array{export_dir: string, export_url: string, export_dir_name: string} $export_paths     Export directory paths.
 * @param array{filename: string, filepath: string}                             $database_file    Database file information.
 * @param string                                                                $site_identifier Sanitized site identifier.
 * @param string                                                                $timestamp       Export timestamp.
 * @return array{filename: string, filepath: string}|WP_Error Archive info on success, WP_Error on failure.
 */
function sse_create_site_archive( array $export_paths, array $database_file, string $site_identifier, string $timestamp ) {
	if ( ! class_exists( 'ZipArchive' ) ) {
		return new WP_Error( 'zip_not_available', __( 'ZipArchive class is not available on your server. Cannot create ZIP file.', 'enginescript-site-exporter' ) );
	}

	if ( ! class_exists( 'PharData' ) ) {
		return new WP_Error( 'phar_not_available', __( 'PharData class is not available on your server. Cannot create files archive.', 'enginescript-site-exporter' ) );
	}

	if ( ! function_exists( 'gzopen' ) ) {
		return new WP_Error( 'gzip_not_available', __( 'Gzip functions are not available on your server. Cannot create compressed database file.', 'enginescript-site-exporter' ) );
	}

	$bundle_paths = sse_prepare_engine_script_bundle_paths( $export_paths, $site_identifier, $timestamp );
	$setup_result = sse_create_bundle_staging_directories( $bundle_paths );
	if ( is_wp_error( $setup_result ) ) {
		return $setup_result;
	}

	try {
		$database_result = sse_create_compressed_database_file( $database_file['filepath'], $bundle_paths['database_path'] );
		if ( is_wp_error( $database_result ) ) {
			return $database_result;
		}

		$file_result = sse_create_wordpress_files_archive( $bundle_paths['files_archive_path'], $export_paths['export_dir'] );
		if ( is_wp_error( $file_result ) ) {
			return $file_result;
		}

		$manifest_result = sse_write_engine_script_manifest( $bundle_paths, $site_identifier );
		if ( is_wp_error( $manifest_result ) ) {
			return $manifest_result;
		}

		$zip_result = sse_create_combined_engine_script_zip( $bundle_paths );
		if ( is_wp_error( $zip_result ) ) {
			return $zip_result;
		}

		sse_log( 'Site archive created successfully: ' . $bundle_paths['combined_zip_path'], 'info' );
		return [
			'filename' => $bundle_paths['combined_zip_filename'],
			'filepath' => $bundle_paths['combined_zip_path'],
		];
	} finally {
		sse_delete_directory_tree( $bundle_paths['staging_dir'] );
	}
}

/**
 * Prepares canonical EngineScript bundle paths and filenames.
 *
 * @since 2.0.0
 * @param array{export_dir: string, export_url: string, export_dir_name: string} $export_paths     Export directory paths.
 * @param string                                                                $site_identifier Sanitized site identifier.
 * @param string                                                                $timestamp       Export timestamp.
 * @return array{staging_dir: string, bundle_root_dir: string, database_dir: string, files_dir: string, manifest_path: string, database_filename: string, database_gz_filename: string, database_path: string, files_archive_filename: string, files_archive_path: string, combined_zip_filename: string, combined_zip_path: string}
 */
function sse_prepare_engine_script_bundle_paths( array $export_paths, string $site_identifier, string $timestamp ): array {
	$staging_dir           = trailingslashit( $export_paths['export_dir'] ) . 'staging-' . $timestamp;
	$bundle_root_dir       = trailingslashit( $staging_dir ) . 'bundle';
	$database_dir          = trailingslashit( $bundle_root_dir ) . 'database';
	$files_dir             = trailingslashit( $bundle_root_dir ) . 'files';
	$database_filename      = "{$site_identifier}_db_{$timestamp}.sql";
	$database_gz_filename   = $database_filename . '.gz';
	$files_archive_filename = "{$site_identifier}_files_{$timestamp}.tar.gz";
	$combined_zip_filename  = "{$site_identifier}_enginescript_site_export_{$timestamp}.zip";

	return [
		'staging_dir'            => $staging_dir,
		'bundle_root_dir'        => $bundle_root_dir,
		'database_dir'           => $database_dir,
		'files_dir'              => $files_dir,
		'manifest_path'          => trailingslashit( $bundle_root_dir ) . 'manifest.txt',
		'database_filename'      => $database_filename,
		'database_gz_filename'   => $database_gz_filename,
		'database_path'          => trailingslashit( $database_dir ) . $database_gz_filename,
		'files_archive_filename' => $files_archive_filename,
		'files_archive_path'     => trailingslashit( $files_dir ) . $files_archive_filename,
		'combined_zip_filename'  => $combined_zip_filename,
		'combined_zip_path'      => trailingslashit( $export_paths['export_dir'] ) . $combined_zip_filename,
	];
}

/**
 * Creates bundle staging directories.
 *
 * @since 2.0.0
 * @param array{database_dir: string, files_dir: string} $bundle_paths Bundle paths.
 * @return true|WP_Error True on success, WP_Error on failure.
 */
function sse_create_bundle_staging_directories( array $bundle_paths ) {
	if ( wp_mkdir_p( $bundle_paths['database_dir'] ) && wp_mkdir_p( $bundle_paths['files_dir'] ) ) {
		return true;
	}

	return new WP_Error( 'bundle_staging_failed', __( 'Could not create EngineScript export staging directories.', 'enginescript-site-exporter' ) );
}

/**
 * Creates a gzip-compressed copy of the database dump.
 *
 * @since 2.0.0
 * @param string $source_path Source SQL dump path.
 * @param string $target_path Target SQL gzip path.
 * @return true|WP_Error True on success, WP_Error on failure.
 */
function sse_create_compressed_database_file( string $source_path, string $target_path ) {
	$source_handle = fopen( $source_path, 'rb' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Streaming a local WP-CLI export into gzip.
	if ( false === $source_handle ) {
		return new WP_Error( 'db_compress_source_failed', __( 'Could not open database dump for compression.', 'enginescript-site-exporter' ) );
	}

	$target_handle = gzopen( $target_path, 'wb9' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- gzopen is required to create the EngineScript .sql.gz payload.
	if ( false === $target_handle ) {
		fclose( $source_handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Closing local file handle opened above.
		sse_cleanup_files( [ $target_path ] );
		return new WP_Error( 'db_compress_target_failed', __( 'Could not create compressed database file.', 'enginescript-site-exporter' ) );
	}

	while ( ! feof( $source_handle ) ) {
		$chunk = fread( $source_handle, 1024 * 1024 ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread -- Streaming large local SQL file.
		if ( false === $chunk || gzwrite( $target_handle, $chunk ) === false ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite -- gzwrite is required for gzip output.
			fclose( $source_handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Closing local file handle opened above.
			gzclose( $target_handle );
			sse_cleanup_files( [ $target_path ] );
			return new WP_Error( 'db_compress_write_failed', __( 'Failed while compressing database dump.', 'enginescript-site-exporter' ) );
		}
	}

	fclose( $source_handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Closing local file handle opened above.
	gzclose( $target_handle );

	if ( ! file_exists( $target_path ) || filesize( $target_path ) <= 0 ) { // phpcs:ignore WordPressVIPMinimum.Functions.RestrictedFunctions.file_exists_file_exists, WordPress.WP.AlternativeFunctions.file_system_operations_filesize -- Verifying generated local gzip payload.
		sse_cleanup_files( [ $target_path ] );
		return new WP_Error( 'db_compress_verify_failed', __( 'Compressed database file was not created successfully.', 'enginescript-site-exporter' ) );
	}

	return true;
}

/**
 * Creates a tar.gz archive of the WordPress files.
 *
 * @since 2.0.0
 * @param string $files_archive_path Target tar.gz path.
 * @param string $export_dir         Export directory to exclude.
 * @return true|WP_Error True on success, WP_Error on failure.
 */
function sse_create_wordpress_files_archive( string $files_archive_path, string $export_dir ) {
	$tar_path = preg_replace( '/\.gz$/', '', $files_archive_path );
	if ( ! is_string( $tar_path ) || '' === $tar_path ) {
		return new WP_Error( 'files_archive_path_failed', __( 'Could not determine files archive path.', 'enginescript-site-exporter' ) );
	}

	sse_cleanup_files( [ $tar_path, $files_archive_path ] );

	try {
		$tar_archive = new PharData( $tar_path );
		$file_result = sse_add_wordpress_files_to_tar( $tar_archive, $export_dir );
		unset( $tar_archive );

		if ( is_wp_error( $file_result ) ) {
			sse_cleanup_files( [ $tar_path, $files_archive_path ] );
			return $file_result;
		}

		$tar_archive = new PharData( $tar_path );
		$tar_archive->compress( Phar::GZ );
		unset( $tar_archive );
		sse_cleanup_files( [ $tar_path ] );
	} catch ( Exception $e ) {
		sse_cleanup_files( [ $tar_path, $files_archive_path ] );
		return new WP_Error(
			'files_archive_failed',
			sprintf(
				/* translators: %s: error message */
				__( 'Failed to create WordPress files archive: %s', 'enginescript-site-exporter' ),
				$e->getMessage()
			)
		);
	}

	if ( ! file_exists( $files_archive_path ) || filesize( $files_archive_path ) <= 0 ) { // phpcs:ignore WordPressVIPMinimum.Functions.RestrictedFunctions.file_exists_file_exists, WordPress.WP.AlternativeFunctions.file_system_operations_filesize -- Verifying generated local tar.gz payload.
		return new WP_Error( 'files_archive_verify_failed', __( 'WordPress files archive was not created successfully.', 'enginescript-site-exporter' ) );
	}

	return true;
}

/**
 * Writes the EngineScript archive manifest.
 *
 * @since 2.0.0
 * @param array{manifest_path: string, database_gz_filename: string, files_archive_filename: string} $bundle_paths     Bundle paths.
 * @param string                                                                                   $site_identifier Sanitized site identifier.
 * @return true|WP_Error True on success, WP_Error on failure.
 */
function sse_write_engine_script_manifest( array $bundle_paths, string $site_identifier ) {
	$manifest_content = implode(
		"\n",
		[
			'format=enginescript-site-archive',
			'version=1',
			'site=' . $site_identifier,
			'created_at_utc=' . gmdate( 'Y-m-d\TH:i:s\Z' ),
			'database_path=database/' . $bundle_paths['database_gz_filename'],
			'files_archive_path=files/' . $bundle_paths['files_archive_filename'],
		]
	) . "\n";

	if ( false === file_put_contents( $bundle_paths['manifest_path'], $manifest_content ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Writing generated local manifest into staging directory.
		return new WP_Error( 'manifest_write_failed', __( 'Could not write EngineScript export manifest.', 'enginescript-site-exporter' ) );
	}

	return true;
}

/**
 * Creates the outer EngineScript ZIP archive.
 *
 * @since 2.0.0
 * @param array{combined_zip_path: string, manifest_path: string, database_path: string, database_gz_filename: string, files_archive_path: string, files_archive_filename: string} $bundle_paths Bundle paths.
 * @return true|WP_Error True on success, WP_Error on failure.
 */
function sse_create_combined_engine_script_zip( array $bundle_paths ) {
	$zip = new ZipArchive();
	if ( $zip->open( $bundle_paths['combined_zip_path'], ZipArchive::CREATE | ZipArchive::OVERWRITE ) !== true ) {
		return new WP_Error(
			'zip_create_failed',
			sprintf(
				/* translators: %s: filename */
				__( 'Could not create ZIP file at %s', 'enginescript-site-exporter' ),
				basename( $bundle_paths['combined_zip_path'] ) // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.system_calls_basename -- Safe usage: path is constructed from controlled export directory and sanitized filename.
			)
		);
	}

	$zip->addEmptyDir( 'database' );
	$zip->addEmptyDir( 'files' );

	$entries = [
		'manifest.txt' => $bundle_paths['manifest_path'],
		'database/' . $bundle_paths['database_gz_filename'] => $bundle_paths['database_path'],
		'files/' . $bundle_paths['files_archive_filename']  => $bundle_paths['files_archive_path'],
	];

	foreach ( $entries as $entry_name => $entry_path ) {
		if ( ! $zip->addFile( $entry_path, $entry_name ) ) {
			$zip->close();
			sse_cleanup_files( [ $bundle_paths['combined_zip_path'] ] );
			return new WP_Error( 'zip_payload_add_failed', __( 'Failed to add EngineScript payload file to ZIP archive.', 'enginescript-site-exporter' ) );
		}

		if ( ! $zip->setCompressionName( $entry_name, ZipArchive::CM_STORE ) ) {
			$zip->close();
			sse_cleanup_files( [ $bundle_paths['combined_zip_path'] ] );
			return new WP_Error( 'zip_store_mode_failed', __( 'Failed to store EngineScript ZIP payload without recompression.', 'enginescript-site-exporter' ) );
		}
	}

	$zip_close_status = $zip->close();

	if ( ! $zip_close_status || ! file_exists( $bundle_paths['combined_zip_path'] ) ) { // phpcs:ignore WordPressVIPMinimum.Functions.RestrictedFunctions.file_exists_file_exists -- Verifying generated export archive.
		sse_cleanup_files( [ $bundle_paths['combined_zip_path'] ] );
		return new WP_Error( 'zip_finalize_failed', __( 'Failed to finalize or save the ZIP archive after processing files.', 'enginescript-site-exporter' ) );
	}

	return true;
}

/**
 * Deletes a directory tree created during export staging.
 *
 * @since 2.0.0
 * @param string $directory Directory to delete.
 * @return bool True if deleted or absent, false on failure.
 */
function sse_delete_directory_tree( string $directory ): bool {
	if ( is_wp_error( sse_init_filesystem() ) ) {
		return false;
	}

	global $wp_filesystem;
	if ( ! $wp_filesystem->exists( $directory ) ) {
		return true;
	}

	return $wp_filesystem->delete( $directory, true, 'd' );
}

/**
 * Adds WordPress files to a tar archive.
 *
 * @since 1.0.0
 * @param PharData $tar        The tar archive object.
 * @param string   $export_dir The export directory to exclude.
 * @return true|WP_Error True on success, WP_Error on failure.
 */
function sse_add_wordpress_files_to_tar( PharData $tar, string $export_dir ) {
	$source_path = realpath( ABSPATH );
	if ( ! $source_path ) {
		sse_log( 'Could not resolve real path for ABSPATH. Using ABSPATH directly.', 'warning' );
		$source_path = ABSPATH;
	}

	try {
		$files = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator( $source_path, RecursiveDirectoryIterator::SKIP_DOTS | FilesystemIterator::UNIX_PATHS ),
			RecursiveIteratorIterator::SELF_FIRST
		);

		foreach ( $files as $file_info ) {
			sse_process_file_for_tar( $tar, $file_info, $source_path, $export_dir );
		}
	} catch ( RuntimeException $e ) {
		return new WP_Error(
			'file_iteration_failed',
			sprintf(
				/* translators: %s: error message */
				__( 'Error during file processing: %s', 'enginescript-site-exporter' ),
				$e->getMessage()
			)
		);
	} catch ( Exception $e ) {
		return new WP_Error(
			'file_iteration_failed',
			sprintf(
				/* translators: %s: error message */
				__( 'Error during file processing: %s', 'enginescript-site-exporter' ),
				$e->getMessage()
			)
		);
	}

	return true;
}

/**
 * Process a single file for addition to tar archive.
 *
 * @since 2.0.0
 * @param PharData    $tar         Tar archive object.
 * @param SplFileInfo $file_info   File information object.
 * @param string      $source_path Source directory path.
 * @param string      $export_dir  Export directory to exclude.
 * @return true|null True on success, null if skipped.
 */
function sse_process_file_for_tar( PharData $tar, SplFileInfo $file_info, string $source_path, string $export_dir ) {
	if ( ! $file_info->isReadable() ) {
		sse_log( 'Skipping unreadable file/dir: ' . $file_info->getPathname(), 'warning' );
		return null;
	}

	if ( $file_info->isLink() ) {
		sse_log( 'Skipping symbolic link during export: ' . $file_info->getPathname(), 'warning' );
		return null;
	}

	$file          = $file_info->getRealPath();
	$pathname      = $file_info->getPathname();
	$relative_path = ltrim( substr( $pathname, strlen( $source_path ) ), '/' );

	if ( false === $file || ! sse_is_path_within_export_source( $file, $source_path ) ) {
		sse_log( 'Skipping file outside export source: ' . $pathname, 'warning' );
		return null;
	}

	if ( empty( $relative_path ) ) {
		return null;
	}

	if ( sse_should_exclude_file( $pathname, $relative_path, $export_dir, $file_info ) ) {
		return null;
	}

	return sse_add_file_to_tar( $tar, $file_info, $file, $pathname, $relative_path ) ? true : null;
}

/**
 * Adds a file or directory to the tar archive.
 *
 * @since 1.0.0
 * @param PharData     $tar           The tar archive object.
 * @param SplFileInfo  $file_info     File information object.
 * @param string|false $file          Real file path or false if getRealPath() failed.
 * @param string       $pathname      Original pathname.
 * @param string       $relative_path Relative path in archive.
 * @return true
 */
function sse_add_file_to_tar( PharData $tar, SplFileInfo $file_info, $file, string $pathname, string $relative_path ): bool {
	try {
		if ( $file_info->isDir() ) {
			$tar->addEmptyDir( $relative_path );
			return true;
		}

		if ( $file_info->isFile() ) {
			// Use real path (getRealPath() must succeed for security).
			if ( false === $file ) {
				sse_log( 'Skipping file with unresolvable real path: ' . $pathname, 'warning' );
				return true; // Skip this file but continue processing.
			}

			$tar->addFile( $file, $relative_path );
		}
	} catch ( Exception $e ) {
		sse_log( 'Failed to add file to tar: ' . $relative_path . ' (Source: ' . $pathname . ') - ' . $e->getMessage(), 'error' );
	}

	return true;
}

/**
 * Determines if a file should be excluded from the export.
 *
 * @since 1.0.0
 * @param string      $pathname      The full pathname.
 * @param string      $relative_path The relative path.
 * @param string      $export_dir    The export directory to exclude.
 * @param SplFileInfo $file_info     File information object.
 * @return bool True if file should be excluded.
 */
function sse_should_exclude_file( string $pathname, string $relative_path, string $export_dir, SplFileInfo $file_info ): bool {
	// Exclude export directory.
	if ( strpos( $pathname, $export_dir ) === 0 ) {
		return true;
	}

	// Exclude cache and temporary directories.
	if ( preg_match( '#^wp-content/(cache|upgrade|temp)/#', $relative_path ) ) {
		return true;
	}

	// Exclude version control and system files.
	if ( preg_match( '#(^|/)\.(git|svn|hg|DS_Store|htaccess|user\.ini)$#i', $relative_path ) ) {
		return true;
	}

	// Exclude files based on size.
	if ( $file_info->isFile() ) {
		// Cache the max file size to avoid repeated transient/filter lookups per file.
		static $cached_max_file_size = null;

		/**
		 * Filters the maximum allowed file size for inclusion in the export.
		 *
		 * @since 1.8.5
		 *
		 * @param int $max_file_size Maximum file size in bytes. Default is user's selection or 0 (no limit).
		 */
		$cached_max_file_size ??= (int) apply_filters(
			SSE_FILTER_MAX_FILE_SIZE,
			get_transient( 'sse_export_max_file_size_' . get_current_user_id() ) ?: 0
		);

		if ( $cached_max_file_size > 0 && $file_info->getSize() > $cached_max_file_size ) {
			sse_log( 'Excluding large file: ' . $pathname . ' (Size: ' . size_format( $file_info->getSize() ) . ', Limit: ' . size_format( $cached_max_file_size ) . ')', 'info' );
			return true;
		}
	}

	return false;
}
