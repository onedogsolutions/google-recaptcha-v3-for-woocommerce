import { useState, useEffect } from '@wordpress/element';
import { __ } from '@wordpress/i18n';
import apiFetch from '@wordpress/api-fetch';

import StatusBadge from './StatusBadge';
import SettingsTabs from './SettingsTabs';
import SettingsPanel from './SettingsPanel';
import PageToggles from './PageToggles';
import Compatibility from './Compatibility';
import FormProtection from './FormProtection';
import TransactionDefense from './TransactionDefense';
import AccountDefender from './AccountDefender';
import PasswordDefense from './PasswordDefense';
import AlertSettings from './AlertSettings';
import TwoFactorNotice from './TwoFactorNotice';
import Diagnostics from './Diagnostics';

const TABS = [
	{
		id: 'credentials',
		label: __( 'API Credentials', 'google-security-for-wordpress' ),
	},
	{
		id: 'forms',
		label: __( 'Form Protection', 'google-security-for-wordpress' ),
	},
	{
		id: 'defense',
		label: __( 'Enterprise Defense', 'google-security-for-wordpress' ),
	},
	{
		id: 'two-factor',
		label: __( 'Two-Factor Auth', 'google-security-for-wordpress' ),
	},
	{
		id: 'advanced',
		label: __( 'Alerts & Compatibility', 'google-security-for-wordpress' ),
	},
];

const getTabFromHash = () => {
	const match = window.location.hash.match( /tab=([\w-]+)/ );
	const id = match ? match[ 1 ] : null;
	return TABS.some( ( tab ) => tab.id === id ) ? id : TABS[ 0 ].id;
};

export default function App() {
	const initialData = window.gswpAdminData || {
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
			txn_defense: '0',
			txn_block: '0',
			threshold_txn: '0.8',
			account_defender: '0',
			ad_step_up: '0',
			ad_events: '1',
			ad_block_signup: '0',
			ad_block_lostpw: '0',
			ad_share_email: '0',
			password_defense: '0',
			pd_login: '1',
			pd_block_choice: '1',
			pd_force_reset: '0',
			pd_supported: false,
			alerts: '0',
			alert_email: '',
			alert_mode: 'immediate',
			alert_login: '1',
			alert_registration: '1',
			alert_checkout: '1',
			alert_leak: '1',
			verbose_logging: '0',
			trusted_proxies: '',
			client_ip_header: 'X-Forwarded-For',
			trusted_cloudflare: '0',
			trusted_quiccloud: '0',
			cdn_ips_cloudflare: '',
			cdn_ips_quiccloud: '',
			cdn_last_refresh: '',
			enable_wp_login: '0',
			enable_wp_register: '0',
			enable_wp_lostpassword: '0',
			threshold_wp_login: '0.5',
			threshold_wp_register: '0.5',
			threshold_wp_lostpassword: '0.5',
			enable_comments: '0',
			threshold_comments: '0.5',
			enable_bb_contact: '0',
			threshold_bb_contact: '0.5',
			enable_bb_subscribe: '0',
			threshold_bb_subscribe: '0.5',
			conflict_mode: 'off',
			tfa_enabled: '1',
			tfa_enforced_roles: [],
			tfa_remember: '1',
			tfa_env_binding: '1',
			tfa_grace_days: '14',
			tfa_block_app_passwords: '0',
			tfa_app_password_exempt_users: '',
		},
	};

	const [ settings, setSettings ] = useState( initialData.settings );
	const [ isSaving, setIsSaving ] = useState( false );
	const [ toast, setToast ] = useState( { message: '', type: null } );
	const [ activeTab, setActiveTab ] = useState( getTabFromHash );

	// Keep the URL hash in sync with the active tab (refresh + deep-link support)
	useEffect( () => {
		window.history.replaceState( null, '', `#tab=${ activeTab }` );
	}, [ activeTab ] );

	// On mount, check REST connectivity and load settings
	useEffect( () => {
		// Configure apiFetch nonce if present
		if ( initialData.nonce ) {
			apiFetch.use( apiFetch.createNonceMiddleware( initialData.nonce ) );
		}

		// Load fresh settings from database to ensure up-to-date state
		apiFetch( { path: '/gswp/v1/settings' } )
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
		setSettings( ( prev ) => {
			// provider_enabled is a map keyed by provider id; merge rather than
			// replace so a pending change to one provider is not discarded by
			// a change to another.
			if ( key === 'provider_enabled' ) {
				return {
					...prev,
					provider_enabled: { ...prev.provider_enabled, ...value },
				};
			}

			return { ...prev, [ key ]: value };
		} );
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
			path: '/gswp/v1/settings',
			method: 'POST',
			data: settings,
		} )
			.then( ( data ) => {
				setSettings( data );
				setIsSaving( false );
				showToast(
					__(
						'Settings saved successfully!',
						'google-security-for-wordpress'
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
							'google-security-for-wordpress'
						),
					'error'
				);
			} );
	};

	return (
		<div className="mx-auto max-w-5xl px-4 py-8 sm:px-6 lg:px-8">
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
							'Google Security',
							'google-security-for-wordpress'
						) }
					</h1>
					<p className="mt-1 text-sm text-gray-500">
						{ __(
							'Invisible reCAPTCHA v3 spam protection plus two-factor authentication.',
							'google-security-for-wordpress'
						) }
					</p>
				</div>
				<div className="mt-4 flex md:ml-4 md:mt-0 items-center gap-x-4">
					<StatusBadge settings={ settings } />
				</div>
			</div>

			{ /* Main Settings Form */ }
			<form onSubmit={ handleSave } className="space-y-8">
				<SettingsTabs
					tabs={ TABS }
					active={ activeTab }
					onChange={ setActiveTab }
				>
					{ {
						credentials: (
							<SettingsPanel
								settings={ settings }
								onChange={ handleSettingChange }
							/>
						),
						forms: (
							<PageToggles
								settings={ settings }
								onChange={ handleSettingChange }
								woocommerceActive={
									!! initialData.woocommerceActive
								}
								beaverBuilderActive={
									!! initialData.beaverBuilderActive
								}
								powerpackActive={
									!! initialData.powerpackActive
								}
							/>
						),
						defense: (
							<>
								{ /* Not gated on WooCommerce since 2.20.2:
								     Gravity Forms payments use Transaction
								     Defense too, and hiding the panel on a
								     site without WooCommerce made the setting
								     unreachable on exactly the sites that
								     need it. */ }
								<TransactionDefense
									settings={ settings }
									onChange={ handleSettingChange }
								/>
								<AccountDefender
									settings={ settings }
									onChange={ handleSettingChange }
								/>
								<PasswordDefense
									settings={ settings }
									onChange={ handleSettingChange }
								/>
								<Diagnostics settings={ settings } />
							</>
						),
						'two-factor': (
							<TwoFactorNotice
								profileUrl={ initialData.profileUrl }
								settings={ settings }
								onChange={ handleSettingChange }
								roles={ initialData.roles }
							/>
						),
						advanced: (
							<>
								<AlertSettings
									settings={ settings }
									onChange={ handleSettingChange }
									woocommerceActive={
										!! initialData.woocommerceActive
									}
								/>
								<Compatibility
									settings={ settings }
									onChange={ handleSettingChange }
								/>
								<FormProtection
									settings={ settings }
									onChange={ handleSettingChange }
								/>
							</>
						),
					} }
				</SettingsTabs>

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
									'google-security-for-wordpress'
								) }
							</>
						) : (
							__(
								'Save Settings',
								'google-security-for-wordpress'
							)
						) }
					</button>
				</div>
			</form>
		</div>
	);
}
