/*
 * EngineScript Site Exporter — Admin Scripts
 *
 * Enqueued only on the Site Exporter admin page (tools_page_enginescript-site-exporter).
 *
 * Package: EngineScript_Site_Exporter
 * Since:   2.0.0
 */

( () => {
	const handleDeleteSubmit = ( event ) => {
		const confirmMessage = event.currentTarget?.dataset?.sseConfirmMessage;

		if ( ! confirmMessage ) {
			event.preventDefault();
			return;
		}

		if ( ! globalThis.confirm( confirmMessage ) ) {
			event.preventDefault();
		}
	};

	document.querySelectorAll( '.sse-confirm-delete' ).forEach( ( form ) => {
		form.addEventListener( 'submit', handleDeleteSubmit );
	} );
} )();
