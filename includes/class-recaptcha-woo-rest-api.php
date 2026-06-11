<?php
/**
 * REST API Class
 *
 * Exposes REST API endpoints for settings management and key scavenging.
 *
 * @package Google_Recaptcha_V3_For_WooCommerce
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Recaptcha_Woo_Rest_Api {

	/**
	 * Constructor.
	 */
	public function __construct() {
		add_action( 'rest_api_init', array( $this, 'register_routes' ) );
	}

	/**
	 * Register REST API routes.
	 */
	public function register_routes() {
		register_rest_route(
			'recaptcha-woo/v1',
			'/settings',
			array(
				array(
					'methods'             => WP_REST_Server::READABLE,
					'callback'            => array( $this, 'get_settings' ),
					'permission_callback' => array( $this, 'check_permissions' ),
				),
				array(
					'methods'             => WP_REST_Server::CREATABLE,
					'callback'            => array( $this, 'update_settings' ),
					'permission_callback' => array( $this, 'check_permissions' ),
				),
			)
		);

		register_rest_route(
			'recaptcha-woo/v1',
			'/scan-keys',
			array(
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'scavenge_keys' ),
				'permission_callback' => array( $this, 'check_permissions' ),
			)
		);
	}

	/**
	 * Check capabilities for API access.
	 *
	 * @return bool True if authorized, false otherwise.
	 */
	public function check_permissions() {
		return current_user_can( 'manage_woocommerce' );
	}

	/**
	 * Get settings callback.
	 *
	 * @return WP_REST_Response REST response containing settings.
	 */
	public function get_settings() {
		$settings = array(
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

		return new WP_REST_Response( $settings, 200 );
	}

	/**
	 * Update settings callback.
	 *
	 * @param WP_REST_Request $request The REST request.
	 * @return WP_REST_Response REST response containing status or updated settings.
	 */
	public function update_settings( $request ) {
		$params = $request->get_params();

		// Sanitize and update Site Key.
		if ( isset( $params['site_key'] ) ) {
			update_option( 'recaptcha_woo_site_key', sanitize_text_field( $params['site_key'] ) );
		}

		// Sanitize and update Secret Key.
		if ( isset( $params['secret_key'] ) ) {
			update_option( 'recaptcha_woo_secret_key', sanitize_text_field( $params['secret_key'] ) );
		}

		// Key type. Only 'classic' or 'enterprise' are valid.
		if ( isset( $params['key_type'] ) ) {
			$key_type = 'enterprise' === $params['key_type'] ? 'enterprise' : 'classic';
			update_option( 'recaptcha_woo_key_type', $key_type );
		}

		// Sanitize and update Enterprise credentials.
		if ( isset( $params['gcp_project_id'] ) ) {
			update_option( 'recaptcha_woo_gcp_project_id', sanitize_text_field( $params['gcp_project_id'] ) );
		}
		if ( isset( $params['gcp_api_key'] ) ) {
			update_option( 'recaptcha_woo_gcp_api_key', sanitize_text_field( $params['gcp_api_key'] ) );
		}

		// Toggles (Login, Registration, Checkout).
		if ( isset( $params['enable_login'] ) ) {
			update_option( 'recaptcha_woo_enable_login', $params['enable_login'] ? '1' : '0' );
		}
		if ( isset( $params['enable_registration'] ) ) {
			update_option( 'recaptcha_woo_enable_registration', $params['enable_registration'] ? '1' : '0' );
		}
		if ( isset( $params['enable_checkout'] ) ) {
			update_option( 'recaptcha_woo_enable_checkout', $params['enable_checkout'] ? '1' : '0' );
		}

		// Thresholds. Must validate they are floats between 0.0 and 1.0.
		if ( isset( $params['threshold_login'] ) ) {
			$val = floatval( $params['threshold_login'] );
			$val = max( 0.0, min( 1.0, $val ) );
			update_option( 'recaptcha_woo_threshold_login', strval( $val ) );
		}
		if ( isset( $params['threshold_registration'] ) ) {
			$val = floatval( $params['threshold_registration'] );
			$val = max( 0.0, min( 1.0, $val ) );
			update_option( 'recaptcha_woo_threshold_registration', strval( $val ) );
		}
		if ( isset( $params['threshold_checkout'] ) ) {
			$val = floatval( $params['threshold_checkout'] );
			$val = max( 0.0, min( 1.0, $val ) );
			update_option( 'recaptcha_woo_threshold_checkout', strval( $val ) );
		}

		return $this->get_settings();
	}

	/**
	 * Scavenge keys callback.
	 *
	 * @return WP_REST_Response REST response containing scavenged keys status and payload.
	 */
	public function scavenge_keys() {
		$keys = Recaptcha_Woo_Key_Scavenger::scan();

		if ( ! empty( $keys ) ) {
			$found = $keys[0];
			return new WP_REST_Response(
				array(
					'success'    => true,
					'keys_found' => true,
					'source'     => $found['source'],
					'site_key'   => $found['site_key'],
					'secret_key' => $found['secret_key'],
				),
				200
			);
		}

		return new WP_REST_Response(
			array(
				'success'    => true,
				'keys_found' => false,
			),
			200
		);
	}
}
