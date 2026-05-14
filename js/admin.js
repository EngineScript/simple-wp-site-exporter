/*
 * EngineScript Site Exporter — Admin Scripts
 *
 * Enqueued only on the Site Exporter admin page (tools_page_enginescript-site-exporter).
 *
 * Package: EngineScript_Site_Exporter
 * Since:   2.0.0
 */

( () => {
	document.addEventListener( 'DOMContentLoaded', () => {
		const deleteButtons = document.querySelectorAll( '.sse-confirm-delete' );

		deleteButtons.forEach( ( button ) => { // eslint-disable-line lodash/prefer-lodash-collection-iteration
			button.addEventListener( 'click', ( event ) => {
				/* global sseAdmin */
				const message = ( typeof sseAdmin !== 'undefined' && sseAdmin.confirmDelete )
					? sseAdmin.confirmDelete
					: 'Are you sure you want to delete this export file?';

				if ( ! window.confirm( message ) ) {
					event.preventDefault();
				}
			} );
		} );
	} );
} )();
