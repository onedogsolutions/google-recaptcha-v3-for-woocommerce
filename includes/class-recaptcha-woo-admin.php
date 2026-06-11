<?php
/**
 * Admin Class
 *
 * Sets up the administrative submenu and enqueues scripts for the React application.
 *
 * @package Google_Recaptcha_V3_For_WooCommerce
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Recaptcha_Woo_Admin {

	/**
	 * Constructor.
	 */
	public function __construct() {
		add_action( 'admin_menu', array( $this, 'register_admin_page' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_admin_assets' ) );
	}

	/**
	 * Register the submenu page.
	 */
	public function register_admin_page() {
		add_submenu_page(
			'woocommerce',
			__( 'reCAPTCHA v3 Settings', 'google-recaptcha-v3-for-woocommerce' ),
			__( 'reCAPTCHA v3', 'google-recaptcha-v3-for-woocommerce' ),
			'manage_woocommerce',
			'recaptcha-woo-admin',
			array( $this, 'render_admin_page' )
		);
	}

	/**
	 * Render the administrative page mount container.
	 */
	public function render_admin_page() {
		?>
		<div class="wrap">
			<div id="recaptcha-woo-admin-root" class="recaptcha-woo-admin-isolated">
				<!-- The React application will mount here -->
				<p class="description"><?php esc_html_e( 'Loading reCAPTCHA settings...', 'google-recaptcha-v3-for-woocommerce' ); ?></p>
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
		// Only load assets on our specific plugin submenu page.
		if ( 'woocommerce_page_recaptcha-woo-admin' !== $hook ) {
			return;
		}

		$asset_file_path = RECAPTCHA_WOO_PLUGIN_DIR . 'build/index.asset.php';
		$dependencies    = array( 'wp-element', 'wp-api-fetch', 'wp-i18n' );
		$version         = RECAPTCHA_WOO_VERSION;

		if ( file_exists( $asset_file_path ) ) {
			$asset_file   = include $asset_file_path;
			$dependencies = isset( $asset_file['dependencies'] ) ? $asset_file['dependencies'] : $dependencies;
			$version      = isset( $asset_file['version'] ) ? $asset_file['version'] : $version;
		}

		// Enqueue compiled script.
		wp_enqueue_script(
			'recaptcha-woo-admin-js',
			RECAPTCHA_WOO_PLUGIN_URL . 'build/index.js',
			$dependencies,
			$version,
			true
		);

		// Enqueue compiled stylesheet.
		wp_enqueue_style(
			'recaptcha-woo-admin-css',
			RECAPTCHA_WOO_PLUGIN_URL . 'build/index.css',
			array(),
			$version
		);

		// Fetch current settings to bootstrap the React app.
		$initial_settings = array(
			'site_key'               => get_option( 'recaptcha_woo_site_key', '' ),
			'secret_key'             => get_option( 'recaptcha_woo_secret_key', '' ),
			'key_type'               => get_option( 'recaptcha_woo_key_type', 'classic' ),
			'gcp_project_id'         => get_option( 'recaptcha_woo_gcp_project_id', '' ),
			'gcp_api_key'            => get_option( 'recaptcha_woo_gcp_api_key', '' ),
			'enable_login'           => get_option( 'recaptcha_woo_enable_login', '0' ),
			'enable_registration'    => get_option( 'recaptcha_woo_enable_registration', '0' ),
			'enable_checkout'        => get_option( 'recaptcha_woo_enable_checkout', '0' ),
			'threshold_login'        => get_option( 'recaptcha_woo_threshold_login', '0.5' ),
			'threshold_registration' => get_option( 'recaptcha_woo_threshold_registration', '0.5' ),
			'threshold_checkout'     => get_option( 'recaptcha_woo_threshold_checkout', '0.5' ),
		);

		// Localize script with REST endpoint variables and initial state.
		wp_localize_script(
			'recaptcha-woo-admin-js',
			'recaptchaWooAdminData',
			array(
				'restUrl'  => esc_url_raw( rest_url( 'recaptcha-woo/v1' ) ),
				'nonce'    => wp_create_nonce( 'wp_rest' ),
				'settings' => $initial_settings,
			)
		);
	}
}
