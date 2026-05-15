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
		const deleteForms = document.querySelectorAll( '.sse-confirm-delete' );

		deleteForms.forEach( ( form ) => {
			form.addEventListener( 'submit', ( event ) => {
				const confirmDelete = window.sseAdmin?.confirmDelete;

				if ( confirmDelete === undefined || confirmDelete === null ) {
					event.preventDefault();
					return;
				}

				if ( ! window.confirm( String( confirmDelete ) ) ) {
					event.preventDefault();
				}
			} );
		} );
	} );
} )();
