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

		deleteButtons.forEach( ( button ) => {
			button.addEventListener( 'click', ( event ) => {
				/* global sseAdmin */
				if ( typeof sseAdmin === 'undefined' || sseAdmin.confirmDelete === undefined || sseAdmin.confirmDelete === null ) {
					event.preventDefault();
					return;
				}

				if ( ! window.confirm( String( sseAdmin.confirmDelete ) ) ) {
					event.preventDefault();
				}
			} );
		} );
	} );
} )();
