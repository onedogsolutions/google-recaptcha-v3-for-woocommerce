import { useState, useEffect } from '@wordpress/element';
import { __ } from '@wordpress/i18n';
import apiFetch from '@wordpress/api-fetch';

import StatusBadge from './StatusBadge';
import SettingsPanel from './SettingsPanel';
import PageToggles from './PageToggles';
import KeyScavenger from './KeyScavenger';

export default function App() {
	const initialData = window.recaptchaWooAdminData || {
		settings: {
			site_key: '',
			secret_key: '',
			key_type: 'classic',
			gcp_project_id: '',
			gcp_api_key: '',
			enable_login: '0',
			enable_registration: '0',
			enable_checkout: '0',
			threshold_login: '0.5',
			threshold_registration: '0.5',
			threshold_checkout: '0.5',
		},
	};

	const [ settings, setSettings ] = useState( initialData.settings );
	const [ isSaving, setIsSaving ] = useState( false );
	const [ toast, setToast ] = useState( { message: '', type: null } );

	// On mount, check REST connectivity and load settings
	useEffect( () => {
		// Configure apiFetch nonce if present
		if ( initialData.nonce ) {
			apiFetch.use( apiFetch.createNonceMiddleware( initialData.nonce ) );
		}

		// Load fresh settings from database to ensure up-to-date state
		apiFetch( { path: '/recaptcha-woo/v1/settings' } )
			.then( ( data ) => {
				setSettings( data );
			} )
			.catch( ( err ) => {
				// eslint-disable-next-line no-console
				console.error( 'Failed to load settings', err );
			} );
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [] );

	// Handle option changes
	const handleSettingChange = ( key, value ) => {
		setSettings( ( prev ) => ( {
			...prev,
			[ key ]: value,
		} ) );
	};

	// Import credentials from scavenger
	const handleImport = ( siteKey, secretKey ) => {
		setSettings( ( prev ) => ( {
			...prev,
			site_key: siteKey,
			secret_key: secretKey || prev.secret_key,
		} ) );
		showToast(
			__(
				'Credentials imported. Make sure to save changes!',
				'google-recaptcha-v3-for-woocommerce'
			),
			'info'
		);
	};

	// Helper to show alert
	const showToast = ( message, type ) => {
		setToast( { message, type } );
		setTimeout( () => {
			setToast( { message: '', type: null } );
		}, 4000 );
	};

	// Save settings handler
	const handleSave = ( e ) => {
		e.preventDefault();
		setIsSaving( true );

		apiFetch( {
			path: '/recaptcha-woo/v1/settings',
			method: 'POST',
			data: settings,
		} )
			.then( ( data ) => {
				setSettings( data );
				setIsSaving( false );
				showToast(
					__(
						'Settings saved successfully!',
						'google-recaptcha-v3-for-woocommerce'
					),
					'success'
				);
			} )
			.catch( ( err ) => {
				setIsSaving( false );
				showToast(
					err.message ||
						__(
							'Failed to save settings. Please try again.',
							'google-recaptcha-v3-for-woocommerce'
						),
					'error'
				);
			} );
	};

	return (
		<div className="mx-auto max-w-5xl px-4 py-8 sm:px-6 lg:px-8 bg-gray-50/50 min-h-screen">
			{ /* Toast Notification */ }
			{ toast.message && (
				<div className="fixed bottom-5 right-5 z-50 max-w-sm rounded-lg p-4 shadow-lg border animate-slideIn transition-all duration-300 bg-white border-gray-150">
					<div className="flex items-center gap-x-3">
						{ toast.type === 'success' && (
							<span className="text-green-500 text-lg">✓</span>
						) }
						{ toast.type === 'error' && (
							<span className="text-red-500 text-lg">✗</span>
						) }
						{ toast.type === 'info' && (
							<span className="text-blue-500 text-lg">ℹ</span>
						) }
						<p className="text-sm font-medium text-gray-900">
							{ toast.message }
						</p>
					</div>
				</div>
			) }

			{ /* Header Panel */ }
			<div className="md:flex md:items-center md:justify-between border-b border-gray-200 pb-5 mb-8">
				<div className="min-w-0 flex-1">
					<h1 className="text-2xl font-bold leading-7 text-gray-900 sm:truncate sm:text-3xl tracking-tight">
						{ __(
							'Google reCAPTCHA v3',
							'google-recaptcha-v3-for-woocommerce'
						) }
					</h1>
					<p className="mt-1 text-sm text-gray-500">
						{ __(
							'Secure customer endpoints with invisible spam protection.',
							'google-recaptcha-v3-for-woocommerce'
						) }
					</p>
				</div>
				<div className="mt-4 flex md:ml-4 md:mt-0 items-center gap-x-4">
					<StatusBadge settings={ settings } />
				</div>
			</div>

			{ /* Main Settings Form */ }
			<form onSubmit={ handleSave } className="space-y-8">
				<div className="grid grid-cols-1 gap-x-8 gap-y-8 md:grid-cols-2">
					{ /* API credentials panel */ }
					<SettingsPanel
						settings={ settings }
						onChange={ handleSettingChange }
					/>

					{ /* Form toggles and score thresholds */ }
					<PageToggles
						settings={ settings }
						onChange={ handleSettingChange }
					/>

					{ /* Key Scavenger panel */ }
					<KeyScavenger onImport={ handleImport } />
				</div>

				{ /* Form Submission Bar */ }
				<div className="flex justify-end gap-x-3 border-t border-gray-900/10 pt-6">
					<button
						type="submit"
						disabled={ isSaving }
						className="inline-flex items-center gap-x-2 rounded-md bg-indigo-600 px-4 py-2.5 text-sm font-semibold text-white shadow-sm hover:bg-indigo-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-600 transition disabled:opacity-50"
					>
						{ isSaving ? (
							<>
								<svg
									className="animate-spin -ml-1 mr-2 h-4 w-4 text-white"
									fill="none"
									viewBox="0 0 24 24"
								>
									<circle
										className="opacity-25"
										cx="12"
										cy="12"
										r="10"
										stroke="currentColor"
										strokeWidth="4"
									/>
									<path
										className="opacity-75"
										fill="currentColor"
										d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
									/>
								</svg>
								{ __(
									'Saving…',
									'google-recaptcha-v3-for-woocommerce'
								) }
							</>
						) : (
							__(
								'Save Settings',
								'google-recaptcha-v3-for-woocommerce'
							)
						) }
					</button>
				</div>
			</form>
		</div>
	);
}
