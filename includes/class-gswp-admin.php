<?php
/**
 * Admin Class
 *
 * Sets up the administrative submenu and enqueues scripts for the React application.
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class GSWP_Admin {

	/**
	 * Constructor.
	 */
	public function __construct() {
		add_action( 'admin_menu', array( $this, 'register_admin_page' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_admin_assets' ) );
	}

	/**
	 * Register the settings page under the core Settings menu.
	 */
	public function register_admin_page() {
		add_options_page(
			__( 'Google Security Settings', 'google-security-for-wordpress' ),
			__( 'Google Security', 'google-security-for-wordpress' ),
			'manage_options',
			'gswp-admin',
			array( $this, 'render_admin_page' )
		);
	}

	/**
	 * Render the administrative page mount container.
	 */
	public function render_admin_page() {
		?>
		<div class="wrap">
			<div id="gswp-admin-root" class="gswp-admin-isolated">
				<!-- The React application will mount here -->
				<p class="description"><?php esc_html_e( 'Loading reCAPTCHA settings...', 'google-security-for-wordpress' ); ?></p>
			</div>
		</div>
		<?php
	}

	/**
	 * Enqueue assets for our settings panel.
	 *
	 * @param string $hook The current admin page hook.
	 */
	public function enqueue_admin_assets( $hook ) {
		// Only load assets on our specific settings page.
		if ( 'settings_page_gswp-admin' !== $hook ) {
			return;
		}

		$asset_file_path = GSWP_PLUGIN_DIR . 'build/index.asset.php';
		$dependencies    = array( 'wp-element', 'wp-api-fetch', 'wp-i18n' );
		$version         = GSWP_VERSION;

		if ( file_exists( $asset_file_path ) ) {
			$asset_file   = include $asset_file_path;
			$dependencies = isset( $asset_file['dependencies'] ) ? $asset_file['dependencies'] : $dependencies;
			$version      = isset( $asset_file['version'] ) ? $asset_file['version'] : $version;
		}

		// Enqueue compiled script.
		wp_enqueue_script(
			'gswp-admin-js',
			GSWP_PLUGIN_URL . 'build/index.js',
			$dependencies,
			$version,
			true
		);

		// Enqueue compiled stylesheet.
		wp_enqueue_style(
			'gswp-admin-css',
			GSWP_PLUGIN_URL . 'build/index.css',
			array(),
			$version
		);

		// Fetch current settings to bootstrap the React app.
		$initial_settings = array(
			'site_key'               => get_option( 'gswp_site_key', '' ),
			'secret_key'             => get_option( 'gswp_secret_key', '' ),
			'key_type'               => get_option( 'gswp_key_type', 'classic' ),
			'gcp_project_id'         => get_option( 'gswp_gcp_project_id', '' ),
			'gcp_api_key'            => get_option( 'gswp_gcp_api_key', '' ),
			'enable_login'           => get_option( 'gswp_enable_login', '0' ),
			'enable_registration'    => get_option( 'gswp_enable_registration', '0' ),
			'enable_checkout'        => get_option( 'gswp_enable_checkout', '0' ),
			'threshold_login'        => get_option( 'gswp_threshold_login', '0.5' ),
			'threshold_registration' => get_option( 'gswp_threshold_registration', '0.5' ),
			'threshold_checkout'     => get_option( 'gswp_threshold_checkout', '0.5' ),
			'txn_defense'            => get_option( 'gswp_txn_defense', '0' ),
			'txn_block'              => get_option( 'gswp_txn_block', '0' ),
			'threshold_txn'          => get_option( 'gswp_threshold_txn', '0.8' ),
			'account_defender'       => get_option( 'gswp_account_defender', '0' ),
			'ad_step_up'             => get_option( 'gswp_ad_step_up', '0' ),
			'ad_events'              => get_option( 'gswp_ad_events', '1' ),
			'ad_block_signup'        => get_option( 'gswp_ad_block_signup', '0' ),
			'ad_block_lostpw'        => get_option( 'gswp_ad_block_lostpw', '0' ),
			'ad_share_email'         => get_option( 'gswp_ad_share_email', '0' ),
			'alerts'                 => get_option( 'gswp_alerts', '0' ),
			'alert_email'            => get_option( 'gswp_alert_email', '' ),
			'alert_mode'             => get_option( 'gswp_alert_mode', 'immediate' ),
			'alert_login'            => get_option( 'gswp_alert_login', '1' ),
			'alert_registration'     => get_option( 'gswp_alert_registration', '1' ),
			'alert_checkout'         => get_option( 'gswp_alert_checkout', '1' ),
			'verbose_logging'        => get_option( 'gswp_verbose_logging', '0' ),
			'trusted_proxies'        => get_option( 'gswp_trusted_proxies', '' ),
			'client_ip_header'       => get_option( 'gswp_client_ip_header', 'X-Forwarded-For' ),
			'resolved_client_ip'     => GSWP_Client_IP::get(),
			'remote_addr'            => GSWP_Client_IP::remote_addr(),
			'enable_wp_login'        => get_option( 'gswp_enable_wp_login', '0' ),
			'enable_wp_register'     => get_option( 'gswp_enable_wp_register', '0' ),
			'enable_wp_lostpassword' => get_option( 'gswp_enable_wp_lostpassword', '0' ),
			'threshold_wp_login'     => get_option( 'gswp_threshold_wp_login', '0.5' ),
			'threshold_wp_register'  => get_option( 'gswp_threshold_wp_register', '0.5' ),
			'threshold_wp_lostpassword' => get_option( 'gswp_threshold_wp_lostpassword', '0.5' ),
			// WordPress comment form protection.
			'enable_comments'        => get_option( 'gswp_enable_comments', '0' ),
			'threshold_comments'     => get_option( 'gswp_threshold_comments', '0.5' ),
			// Beaver Builder core module protection.
			'enable_bb_contact'      => get_option( 'gswp_enable_bb_contact', '0' ),
			'threshold_bb_contact'   => get_option( 'gswp_threshold_bb_contact', '0.5' ),
			'enable_bb_subscribe'    => get_option( 'gswp_enable_bb_subscribe', '0' ),
			'threshold_bb_subscribe' => get_option( 'gswp_threshold_bb_subscribe', '0.5' ),
			// PowerPack module protection (Contact Form, Subscribe Form).
			'enable_pp_contact'      => get_option( 'gswp_enable_pp_contact', '0' ),
			'threshold_pp_contact'   => get_option( 'gswp_threshold_pp_contact', '0.5' ),
			'enable_pp_subscribe'    => get_option( 'gswp_enable_pp_subscribe', '0' ),
			'threshold_pp_subscribe' => get_option( 'gswp_threshold_pp_subscribe', '0.5' ),
			// Gravity Forms, per class of form. Before 2.22.0 every non-payment
			// GF form was scored against threshold_wp_register.
			'threshold_gf_submit'    => get_option( 'gswp_threshold_gf_submit', '0.5' ),
			'threshold_gf_register'  => get_option( 'gswp_threshold_gf_register', '0.5' ),
			'threshold_gf_account_update' => get_option( 'gswp_threshold_gf_account_update', '0.5' ),
			'threshold_gf_password'  => get_option( 'gswp_threshold_gf_password', '0.5' ),
			'conflict_mode'          => get_option( 'gswp_conflict_mode', 'off' ),
			'form_providers_enabled' => GSWP_Form_Provider_Registry::enabled() ? '1' : '0',
			'gf_internal_forms'      => array_map( 'intval', (array) get_option( 'gswp_gf_internal_forms', array() ) ),
			'tfa_enabled'            => get_option( 'gswp_2fa_enabled', '1' ),
			'tfa_enforced_roles'     => array_values( (array) get_option( 'gswp_2fa_enforced_roles', array() ) ),
			'tfa_remember'           => get_option( 'gswp_2fa_remember', '1' ),
			'tfa_grace_days'         => get_option( 'gswp_2fa_grace_days', '14' ),
			'tfa_block_app_passwords' => get_option( 'gswp_2fa_block_app_passwords', '0' ),
			'tfa_app_password_exempt_users' => get_option( 'gswp_2fa_app_password_exempt_users', '' ),
		);

		// Localize script with REST endpoint variables and initial state.
		wp_localize_script(
			'gswp-admin-js',
			'gswpAdminData',
			array(
				'restUrl'            => esc_url_raw( rest_url( 'gswp/v1' ) ),
				'nonce'              => wp_create_nonce( 'wp_rest' ),
				'settings'           => $initial_settings,
				'woocommerceActive'  => class_exists( 'WooCommerce' ),
				'beaverBuilderActive' => class_exists( 'FLBuilder' ),
				'powerpackActive'    => class_exists( 'BB_PowerPack' ),
				'profileUrl'         => esc_url_raw( admin_url( 'profile.php' ) . '#gswp-2fa' ),
				'roles'              => wp_roles()->get_names(),
				'loaderConflict'     => GSWP_Recaptcha_Loader::stored_conflict(),
				'ourSiteKeyMasked'   => GSWP_Recaptcha_Loader::mask_key( GSWP_Recaptcha_Loader::site_key() ),
				'formProviders'      => GSWP_Form_Provider_Registry::audit_all(),
			)
		);
	}
}
