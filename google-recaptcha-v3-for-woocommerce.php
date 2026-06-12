<?php
/**
 * Plugin Name: Google reCAPTCHA v3 for WooCommerce
 * Description: Google reCAPTCHA v3 integration for WooCommerce Login, Registration, and Checkout with smart key scavenging.
 * Version: 1.2.1
 * Author: One Dog Solutions
 * Author URI: https://onedog.solutions/
 * Requires at least: 5.8
 * Requires PHP: 7.4
 * Requires Plugins: woocommerce
 * Text Domain: google-recaptcha-v3-for-woocommerce
 * Domain Path: /languages
 *
 * @package Google_Recaptcha_V3_For_WooCommerce
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly.
}

// Define plugin constants.
define( 'RECAPTCHA_WOO_VERSION', '1.2.1' );
define( 'RECAPTCHA_WOO_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'RECAPTCHA_WOO_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'RECAPTCHA_WOO_FILE', __FILE__ );

/**
 * Autoload classes or include them.
 */
require_once RECAPTCHA_WOO_PLUGIN_DIR . 'includes/class-recaptcha-woo-key-scavenger.php';
require_once RECAPTCHA_WOO_PLUGIN_DIR . 'includes/class-recaptcha-woo-verifier.php';
// REST requests are not admin context (is_admin() is false for /wp-json),
// so the REST API class must load unconditionally for its routes to exist.
require_once RECAPTCHA_WOO_PLUGIN_DIR . 'includes/class-recaptcha-woo-rest-api.php';

if ( is_admin() ) {
	require_once RECAPTCHA_WOO_PLUGIN_DIR . 'includes/class-recaptcha-woo-admin.php';
} else {
	require_once RECAPTCHA_WOO_PLUGIN_DIR . 'includes/class-recaptcha-woo-frontend.php';
}

/**
 * Activate the plugin.
 */
function recaptcha_woo_activate() {
	// Set default settings if not already set.
	add_option( 'recaptcha_woo_site_key', '' );
	add_option( 'recaptcha_woo_secret_key', '' );
	add_option( 'recaptcha_woo_key_type', 'classic' );
	add_option( 'recaptcha_woo_gcp_project_id', '' );
	add_option( 'recaptcha_woo_gcp_api_key', '' );
	add_option( 'recaptcha_woo_enable_login', '0' );
	add_option( 'recaptcha_woo_enable_registration', '0' );
	add_option( 'recaptcha_woo_enable_checkout', '0' );
	add_option( 'recaptcha_woo_threshold_login', '0.5' );
	add_option( 'recaptcha_woo_threshold_registration', '0.5' );
	add_option( 'recaptcha_woo_threshold_checkout', '0.5' );
}
register_activation_hook( __FILE__, 'recaptcha_woo_activate' );

/**
 * Initialize the plugin classes.
 */
function recaptcha_woo_init() {
	// Initialize validation/verification first.
	new Recaptcha_Woo_Verifier();

	// Routes only register when rest_api_init fires, so this is a no-op
	// outside REST requests.
	new Recaptcha_Woo_Rest_Api();

	if ( is_admin() ) {
		new Recaptcha_Woo_Admin();
	} else {
		new Recaptcha_Woo_Frontend();
	}
}
add_action( 'plugins_loaded', 'recaptcha_woo_init' );
