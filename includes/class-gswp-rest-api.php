<?php
/**
 * REST API Class
 *
 * Exposes REST API endpoints for settings management.
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class GSWP_Rest_Api {

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
			'gswp/v1',
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
			'gswp/v1',
			'/diagnose',
			array(
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'run_diagnostic' ),
				'permission_callback' => array( $this, 'check_permissions' ),
			)
		);

		register_rest_route(
			'gswp/v1',
			'/refresh-cdn-ips',
			array(
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'refresh_cdn_ips' ),
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
		return current_user_can( 'manage_options' );
	}

	/**
	 * Get settings callback.
	 *
	 * @return WP_REST_Response REST response containing settings.
	 */
	public function get_settings() {
		$settings = array(
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
			'trusted_cloudflare'     => get_option( 'gswp_trusted_cloudflare', '0' ),
			'trusted_quiccloud'      => get_option( 'gswp_trusted_quiccloud', '0' ),
			'cdn_ips_cloudflare'     => get_option( 'gswp_cdn_ips_cloudflare', '' ),
			'cdn_ips_quiccloud'      => get_option( 'gswp_cdn_ips_quiccloud', '' ),
			'cdn_last_refresh'       => get_option( 'gswp_cdn_last_refresh', '' ),
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
			// Fluent Forms, per class of form. Deliberately its own set rather
			// than sharing the Gravity Forms dials: a site tuning one form
			// plugin's registration threshold must not silently retune another,
			// which is the defect 2.22.0 fixed when GF stopped borrowing
			// threshold_wp_register.
			'threshold_ff_submit'    => get_option( 'gswp_threshold_ff_submit', '0.5' ),
			'threshold_ff_register'  => get_option( 'gswp_threshold_ff_register', '0.5' ),
			'threshold_ff_account_update' => get_option( 'gswp_threshold_ff_account_update', '0.5' ),
			'threshold_ff_password'  => get_option( 'gswp_threshold_ff_password', '0.5' ),
			'conflict_mode'          => get_option( 'gswp_conflict_mode', 'off' ),
			'form_providers_enabled' => GSWP_Form_Provider_Registry::enabled() ? '1' : '0',
			'form_providers'         => GSWP_Form_Provider_Registry::audit_all(),
			'gf_internal_forms'      => array_map( 'intval', (array) get_option( 'gswp_gf_internal_forms', array() ) ),
			'ff_internal_forms'      => array_map( 'intval', (array) get_option( 'gswp_ff_internal_forms', array() ) ),
			// Two-factor authentication.
			'tfa_enabled'            => get_option( 'gswp_2fa_enabled', '1' ),
			'tfa_enforced_roles'     => array_values( (array) get_option( 'gswp_2fa_enforced_roles', array() ) ),
			'tfa_remember'           => get_option( 'gswp_2fa_remember', '1' ),
			'tfa_env_binding'        => get_option( 'gswp_2fa_env_binding', '1' ),
			'tfa_grace_days'         => get_option( 'gswp_2fa_grace_days', '14' ),
			'tfa_block_app_passwords' => get_option( 'gswp_2fa_block_app_passwords', '0' ),
			'tfa_app_password_exempt_users' => get_option( 'gswp_2fa_app_password_exempt_users', '' ),
			// Password Defense (leaked-credential detection).
			'password_defense'       => get_option( 'gswp_password_defense', '0' ),
			'pd_login'                => get_option( 'gswp_pd_login', '1' ),
			'pd_block_choice'         => get_option( 'gswp_pd_block_choice', '1' ),
			'pd_force_reset'          => get_option( 'gswp_pd_force_reset', '0' ),
			'pd_supported'            => GSWP_Password_Defense::supported(),
			'alert_leak'              => get_option( 'gswp_alert_leak', '1' ),
		);

		return new WP_REST_Response( $settings, 200 );
	}

	/**
	 * Run a live diagnostic against Google's reCAPTCHA Enterprise API.
	 *
	 * Performs test assessments with a dummy token to verify connectivity and
	 * credential validity, and returns the exact payloads the plugin sends for
	 * Account Defender and Transaction Defense so the admin can audit what
	 * Google receives.
	 *
	 * @param WP_REST_Request $request The REST request.
	 * @return WP_REST_Response Structured diagnostic results.
	 */
	public function run_diagnostic( $request ) {
		$results = array(
			'timestamp'      => gmdate( 'Y-m-d H:i:s' ) . ' UTC',
			'configuration'  => $this->diagnose_configuration(),
			'connectivity'   => $this->diagnose_connectivity(),
			'account_defender' => $this->diagnose_account_defender(),
			'transaction_defense' => $this->diagnose_transaction_defense(),
			'loader_conflicts' => $this->diagnose_loader_conflicts(),
			'form_coverage' => $this->diagnose_form_coverage(),
		);

		return new WP_REST_Response( $results, 200 );
	}

	/**
	 * Refresh CDN edge IP lists on demand.
	 *
	 * @param WP_REST_Request $request The REST request.
	 * @return WP_REST_Response Result of the refresh.
	 */
	public function refresh_cdn_ips( $request ) {
		$provider = sanitize_key( (string) $request->get_param( 'provider' ) );

		if ( '' !== $provider && ! isset( GSWP_Client_IP::CDN_PROVIDERS[ $provider ] ) ) {
			return new WP_REST_Response(
				array(
					'success' => false,
					'message' => __( 'Unknown CDN provider.', 'google-security-for-wordpress' ),
				),
				400
			);
		}

		$results = GSWP_Client_IP::refresh_cdn_ips( $provider );

		return new WP_REST_Response( $results, 200 );
	}

	/**
	 * Report per-form coverage for every active form provider.
	 *
	 * The guard against silent gaps: the form plugin's own reCAPTCHA covers all
	 * of its forms automatically, we cover only what we hook, so this states
	 * plainly which forms we would actually protect if the plugin's own
	 * implementation were retired.
	 *
	 * @return array Coverage status.
	 */
	private function diagnose_form_coverage() {
		$audit = GSWP_Form_Provider_Registry::audit_all();

		if ( empty( $audit['providers'] ) ) {
			return array(
				'status'  => 'ok',
				'message' => __( 'No supported form plugins are active, so there is nothing to take over.', 'google-security-for-wordpress' ),
			);
		}

		if ( ! $audit['enabled'] ) {
			return array(
				'status'  => 'warning',
				'message' => __( 'Form provider interception is switched off by the kill switch. Form plugins are using their own reCAPTCHA.', 'google-security-for-wordpress' ),
			);
		}

		$rows       = array();
		$status     = 'ok';
		$messages   = array();

		foreach ( $audit['providers'] as $provider ) {
			$uncovered  = count( $provider['uncovered'] );
			$ineligible = count( $provider['ineligible'] );

			$rows[] = array(
				'provider'   => $provider['label'],
				'on'         => $provider['on'],
				'forms'      => count( $provider['forms'] ),
				'uncovered'  => $uncovered,
				'ineligible' => $ineligible,
				'detail'     => $provider['forms'],
			);

			// A form we are supposed to be covering but have never observed a
			// token field reaching is the signal that matters here.
			$never_injected = 0;
			foreach ( $provider['forms'] as $form ) {
				if ( $form['covered'] && empty( $form['injected'] ) ) {
					++$never_injected;
				}
			}

			if ( $provider['on'] && $never_injected > 0 ) {
				$status     = 'warning';
				$messages[] = sprintf(
					/* translators: 1: provider name, 2: number of forms. */
					__( '%1$s: %2$d covered form(s) have never been observed receiving a token field. Load each on the front end and re-run this check; a form that never receives one is submitted unscored.', 'google-security-for-wordpress' ),
					$provider['label'],
					$never_injected
				);
			}
		}

		return array(
			'status'    => $status,
			'message'   => empty( $messages )
				? __( 'Every eligible form is covered.', 'google-security-for-wordpress' )
				: implode( ' ', $messages ),
			'providers' => $rows,
		);
	}

	/**
	 * Report third-party reCAPTCHA loaders observed on the front end.
	 *
	 * Detection happens during front-end rendering (GSWP_Recaptcha_Loader), so
	 * this reads the recorded observation rather than re-scanning: a REST
	 * request enqueues no front-end scripts and would always look clean.
	 *
	 * @return array Loader conflict status.
	 */
	private function diagnose_loader_conflicts() {
		$conflict = GSWP_Recaptcha_Loader::stored_conflict();

		if ( null === $conflict || empty( $conflict['loaders'] ) ) {
			return array(
				'status'  => 'ok',
				'message' => __( 'No conflicting reCAPTCHA loaders have been observed. Either this plugin is the only one loading reCAPTCHA, or the others use the same site key and share a single loader.', 'google-security-for-wordpress' ),
				'loaders' => array(),
			);
		}

		$suppressing = ! empty( $conflict['suppressing'] );

		return array(
			'status'      => $suppressing ? 'error' : 'warning',
			'suppressing' => $suppressing,
			'observed'    => isset( $conflict['observed'] ) ? gmdate( 'Y-m-d H:i:s', (int) $conflict['observed'] ) . ' UTC' : '',
			'message'     => $suppressing
				? __( 'Conflict handling is set to remove other plugins\' reCAPTCHA, and this plugin is stripping one that uses a different site key. That plugin\'s forms, including payment forms, may be failing to submit. Align the site keys, or switch conflict handling to "Share one loader".', 'google-security-for-wordpress' )
				: __( 'Another plugin loads reCAPTCHA with a different site key. Nothing is being removed, but only one site key can be pre-rendered per page, so one of the two will fail to execute. Align the site keys.', 'google-security-for-wordpress' ),
			'our_key'     => GSWP_Recaptcha_Loader::mask_key( GSWP_Recaptcha_Loader::site_key() ),
			'loaders'     => $conflict['loaders'],
		);
	}

	/**
	 * Check that all required credentials are present and non-empty.
	 *
	 * @return array Configuration status.
	 */
	private function diagnose_configuration() {
		$key_type   = get_option( 'gswp_key_type', 'classic' );
		$site_key   = get_option( 'gswp_site_key', '' );
		$secret_key = get_option( 'gswp_secret_key', '' );
		$project_id = get_option( 'gswp_gcp_project_id', '' );
		$api_key    = get_option( 'gswp_gcp_api_key', '' );

		$checks = array(
			'key_type'   => array(
				'label' => 'Key type',
				'value' => $key_type,
				'ok'    => in_array( $key_type, array( 'classic', 'enterprise' ), true ),
			),
			'site_key'   => array(
				'label' => 'Site key',
				'value' => '' !== $site_key ? substr( $site_key, 0, 8 ) . '…' : '(empty)',
				'ok'    => '' !== $site_key,
			),
		);

		if ( 'enterprise' === $key_type ) {
			$checks['gcp_project_id'] = array(
				'label' => 'GCP Project ID',
				'value' => '' !== $project_id ? $project_id : '(empty)',
				'ok'    => '' !== $project_id,
			);
			$checks['gcp_api_key'] = array(
				'label' => 'GCP API key',
				'value' => '' !== $api_key ? substr( $api_key, 0, 8 ) . '…' : '(empty)',
				'ok'    => '' !== $api_key,
			);
		} else {
			$checks['secret_key'] = array(
				'label' => 'Secret key',
				'value' => '' !== $secret_key ? substr( $secret_key, 0, 8 ) . '…' : '(empty)',
				'ok'    => '' !== $secret_key,
			);
		}

		$all_ok = true;
		foreach ( $checks as $check ) {
			if ( ! $check['ok'] ) {
				$all_ok = false;
				break;
			}
		}

		return array(
			'ok'     => $all_ok,
			'checks' => $checks,
		);
	}

	/**
	 * Perform a live test call to Google's API with a dummy token.
	 *
	 * A successful credential check returns HTTP 200 with tokenProperties.valid
	 * = false (TOKEN_NOT_FOUND), proving the API key, project ID, and site key
	 * are all correct. Non-200 responses reveal the exact configuration error.
	 *
	 * @return array Connectivity test results including request/response.
	 */
	private function diagnose_connectivity() {
		$key_type = get_option( 'gswp_key_type', 'classic' );

		if ( 'enterprise' === $key_type ) {
			return $this->test_enterprise_connectivity();
		}

		return $this->test_classic_connectivity();
	}

	/**
	 * Test Enterprise API connectivity.
	 *
	 * @return array Test results.
	 */
	private function test_enterprise_connectivity() {
		$project_id = get_option( 'gswp_gcp_project_id', '' );
		$api_key    = get_option( 'gswp_gcp_api_key', '' );
		$site_key   = get_option( 'gswp_site_key', '' );

		if ( '' === $project_id || '' === $api_key || '' === $site_key ) {
			return array(
				'ok'      => false,
				'skipped' => true,
				'message' => 'Enterprise credentials incomplete. Fill in Project ID, API key, and Site key first.',
			);
		}

		$api_url = sprintf(
			'https://recaptchaenterprise.googleapis.com/v1/projects/%s/assessments?key=%s',
			rawurlencode( $project_id ),
			rawurlencode( $api_key )
		);

		// A dummy token: Google will reject it as invalid, but a 200 response
		// with tokenProperties proves the credentials and API are correct.
		$event = array(
			'token'          => 'gswp-diagnostic-dummy-token',
			'siteKey'        => $site_key,
			'expectedAction' => 'diagnostic',
			'userIpAddress'  => GSWP_Client_IP::get( '127.0.0.1' ),
		);

		$request_body = wp_json_encode( array( 'event' => $event ) );

		$response = wp_remote_post(
			$api_url,
			array(
				'timeout' => 15,
				'headers' => array( 'Content-Type' => 'application/json' ),
				'body'    => $request_body,
			)
		);

		if ( is_wp_error( $response ) ) {
			return array(
				'ok'       => false,
				'message'  => 'Network error: ' . $response->get_error_message(),
				'request'  => array(
					'url'  => preg_replace( '/key=[^&]+/', 'key=***', $api_url ),
					'body' => json_decode( $request_body, true ),
				),
				'response' => null,
			);
		}

		$status = wp_remote_retrieve_response_code( $response );
		$body   = json_decode( wp_remote_retrieve_body( $response ), true );

		// Interpret the result.
		$ok      = false;
		$message = '';

		if ( 200 === $status && is_array( $body ) ) {
			$token_props = isset( $body['tokenProperties'] ) ? $body['tokenProperties'] : array();
			if ( isset( $token_props['valid'] ) && ! $token_props['valid'] ) {
				$reason  = isset( $token_props['invalidReason'] ) ? $token_props['invalidReason'] : 'UNKNOWN';
				$ok      = true;
				$message = 'Credentials valid. API returned tokenProperties.invalidReason=' . $reason . ' (expected for a dummy token). Assessments are reaching Google correctly.';
			} else {
				$ok      = true;
				$message = 'API returned HTTP 200. Credentials are valid.';
			}
		} elseif ( is_array( $body ) && isset( $body['error']['message'] ) ) {
			$message = 'HTTP ' . $status . ': ' . $body['error']['message'];
		} else {
			$message = 'HTTP ' . $status . ': unexpected response.';
		}

		return array(
			'ok'      => $ok,
			'message' => $message,
			'request' => array(
				'url'  => preg_replace( '/key=[^&]+/', 'key=***', $api_url ),
				'body' => json_decode( $request_body, true ),
			),
			'response' => array(
				'http_status' => $status,
				'body'        => $body,
			),
		);
	}

	/**
	 * Test classic reCAPTCHA v3 siteverify connectivity.
	 *
	 * @return array Test results.
	 */
	private function test_classic_connectivity() {
		$secret_key = get_option( 'gswp_secret_key', '' );

		if ( '' === $secret_key ) {
			return array(
				'ok'      => false,
				'skipped' => true,
				'message' => 'Secret key is empty. Configure it under API Credentials first.',
			);
		}

		$response = wp_remote_post(
			'https://www.google.com/recaptcha/api/siteverify',
			array(
				'timeout' => 15,
				'body'    => array(
					'secret'   => $secret_key,
					'response' => 'gswp-diagnostic-dummy-token',
					'remoteip' => GSWP_Client_IP::get( '127.0.0.1' ),
				),
			)
		);

		if ( is_wp_error( $response ) ) {
			return array(
				'ok'       => false,
				'message'  => 'Network error: ' . $response->get_error_message(),
				'request'  => array(
					'url'  => 'https://www.google.com/recaptcha/api/siteverify',
					'body' => array( 'secret' => '***', 'response' => 'gswp-diagnostic-dummy-token' ),
				),
				'response' => null,
			);
		}

		$status = wp_remote_retrieve_response_code( $response );
		$body   = json_decode( wp_remote_retrieve_body( $response ), true );

		$ok      = false;
		$message = '';

		if ( is_array( $body ) && isset( $body['success'] ) ) {
			if ( false === $body['success'] ) {
				$error_codes = isset( $body['error-codes'] ) ? $body['error-codes'] : array();
				if ( in_array( 'invalid-input-secret', $error_codes, true ) || in_array( 'missing-input-secret', $error_codes, true ) ) {
					$message = 'Secret key is INVALID. Google rejected it: ' . implode( ', ', $error_codes );
				} elseif ( in_array( 'invalid-input-response', $error_codes, true ) || in_array( 'missing-input-response', $error_codes, true ) ) {
					$ok      = true;
					$message = 'Credentials valid. Google rejected the dummy token (expected): ' . implode( ', ', $error_codes ) . '. Real tokens will verify correctly.';
				} else {
					$message = 'Google returned errors: ' . implode( ', ', $error_codes );
				}
			} else {
				$ok      = true;
				$message = 'siteverify returned success (unexpected for a dummy token, but credentials work).';
			}
		} else {
			$message = 'HTTP ' . $status . ': unexpected response format.';
		}

		return array(
			'ok'      => $ok,
			'message' => $message,
			'request' => array(
				'url'  => 'https://www.google.com/recaptcha/api/siteverify',
				'body' => array( 'secret' => '***', 'response' => 'gswp-diagnostic-dummy-token' ),
			),
			'response' => array(
				'http_status' => $status,
				'body'        => $body,
			),
		);
	}

	/**
	 * Build a sample Account Defender assessment payload and optionally test it.
	 *
	 * Shows the exact userInfo structure sent with login/registration assessments.
	 *
	 * @return array Account Defender diagnostic.
	 */
	private function diagnose_account_defender() {
		$key_type = get_option( 'gswp_key_type', 'classic' );
		$enabled  = '1' === get_option( 'gswp_account_defender', '0' );

		$result = array(
			'enabled' => $enabled,
			'ok'      => false,
		);

		if ( 'enterprise' !== $key_type ) {
			$result['message'] = 'Account Defender requires Enterprise key type.';
			return $result;
		}

		if ( ! $enabled ) {
			$result['message'] = 'Account Defender is disabled in plugin settings.';
			return $result;
		}

		$project_id = get_option( 'gswp_gcp_project_id', '' );
		$api_key    = get_option( 'gswp_gcp_api_key', '' );
		$site_key   = get_option( 'gswp_site_key', '' );

		// Build the sample payload exactly as the verifier does for a login.
		$current_user = wp_get_current_user();
		$user_info    = array(
			'accountId' => hash( 'sha256', 'gswp-diagnostic|id:' . $current_user->ID ),
		);

		if ( $current_user->user_registered ) {
			$registered = strtotime( $current_user->user_registered . ' UTC' );
			if ( $registered ) {
				$user_info['createAccountTime'] = gmdate( 'Y-m-d\TH:i:s\Z', $registered );
			}
		}

		if ( '1' === get_option( 'gswp_ad_share_email', '0' ) && is_email( $current_user->user_email ) ) {
			$user_info['userIds'] = array( array( 'email' => strtolower( $current_user->user_email ) ) );
		}

		$event = array(
			'token'          => 'gswp-diagnostic-dummy-token',
			'siteKey'        => $site_key,
			'expectedAction' => 'login',
			'userIpAddress'  => GSWP_Client_IP::get( '127.0.0.1' ),
			'userInfo'       => $user_info,
		);

		$request_body = wp_json_encode( array( 'event' => $event ) );

		$api_url = sprintf(
			'https://recaptchaenterprise.googleapis.com/v1/projects/%s/assessments?key=%s',
			rawurlencode( $project_id ),
			rawurlencode( $api_key )
		);

		$response = wp_remote_post(
			$api_url,
			array(
				'timeout' => 15,
				'headers' => array( 'Content-Type' => 'application/json' ),
				'body'    => $request_body,
			)
		);

		if ( is_wp_error( $response ) ) {
			$result['message'] = 'Network error: ' . $response->get_error_message();
			$result['request'] = array(
				'url'  => preg_replace( '/key=[^&]+/', 'key=***', $api_url ),
				'body' => json_decode( $request_body, true ),
			);
			return $result;
		}

		$status = wp_remote_retrieve_response_code( $response );
		$body   = json_decode( wp_remote_retrieve_body( $response ), true );

		$result['request'] = array(
			'url'  => preg_replace( '/key=[^&]+/', 'key=***', $api_url ),
			'body' => json_decode( $request_body, true ),
		);
		$result['response'] = array(
			'http_status' => $status,
			'body'        => $body,
		);

		if ( 200 === $status && is_array( $body ) ) {
			$result['ok']      = true;
			$result['message'] = 'Account Defender assessment accepted by Google (userInfo payload is valid).';

			// Show any accountDefenderAssessment labels returned.
			if ( isset( $body['accountDefenderAssessment'] ) ) {
				$result['accountDefenderAssessment'] = $body['accountDefenderAssessment'];
			} else {
				$result['accountDefenderAssessment'] = null;
				$result['note'] = 'No accountDefenderAssessment returned. This is normal if Account Defense is not yet enabled for this key in Google Cloud Console (Fraud Defense → Configure Account defense), or the model has insufficient data.';
			}
		} elseif ( is_array( $body ) && isset( $body['error']['message'] ) ) {
			$result['message'] = 'HTTP ' . $status . ': ' . $body['error']['message'];
		} else {
			$result['message'] = 'HTTP ' . $status . ': unexpected response.';
		}

		return $result;
	}

	/**
	 * Build a sample Transaction Defense assessment payload and test it.
	 *
	 * Shows the exact transactionData structure sent during checkout.
	 *
	 * @return array Transaction Defense diagnostic.
	 */
	private function diagnose_transaction_defense() {
		$key_type = get_option( 'gswp_key_type', 'classic' );
		$enabled  = '1' === get_option( 'gswp_txn_defense', '0' );

		$result = array(
			'enabled' => $enabled,
			'ok'      => false,
		);

		if ( 'enterprise' !== $key_type ) {
			$result['message'] = 'Transaction Defense requires Enterprise key type.';
			return $result;
		}

		if ( ! $enabled ) {
			$result['message'] = 'Transaction Defense is disabled in plugin settings.';
			return $result;
		}

		$project_id = get_option( 'gswp_gcp_project_id', '' );
		$api_key    = get_option( 'gswp_gcp_api_key', '' );
		$site_key   = get_option( 'gswp_site_key', '' );

		// Build a realistic sample transactionData payload matching what the
		// verifier sends during a real checkout.
		$transaction_data = array(
			'paymentMethod'  => 'stripe',
			'currencyCode'   => function_exists( 'get_woocommerce_currency' ) ? get_woocommerce_currency() : 'USD',
			'value'          => 49.99,
			'shippingValue'  => 5.00,
			'billingAddress' => array(
				'recipient'          => 'Diagnostic Test',
				'locality'           => 'San Francisco',
				'administrativeArea' => 'CA',
				'regionCode'         => 'US',
				'postalCode'         => '94102',
				'address'            => array( '123 Test St' ),
			),
			'shippingAddress' => array(
				'recipient'          => 'Diagnostic Test',
				'locality'           => 'San Francisco',
				'administrativeArea' => 'CA',
				'regionCode'         => 'US',
				'postalCode'         => '94102',
				'address'            => array( '123 Test St' ),
			),
			'items'          => array(
				array(
					'name'     => 'Diagnostic Test Product',
					'value'    => 49.99,
					'quantity' => '1',
				),
			),
		);

		$current_user = wp_get_current_user();
		if ( $current_user->exists() ) {
			$transaction_data['user'] = array(
				'email'         => strtolower( $current_user->user_email ),
				'accountId'     => (string) $current_user->ID,
				'emailVerified' => true,
			);
			$registered = strtotime( $current_user->user_registered . ' UTC' );
			if ( $registered ) {
				$transaction_data['user']['creationMs'] = (string) ( $registered * 1000 );
			}
		}

		$event = array(
			'token'           => 'gswp-diagnostic-dummy-token',
			'siteKey'         => $site_key,
			'expectedAction'  => 'checkout',
			'userIpAddress'   => GSWP_Client_IP::get( '127.0.0.1' ),
			'transactionData' => $transaction_data,
			'fraudPrevention' => 'ENABLED',
		);

		$request_body = wp_json_encode( array( 'event' => $event ) );

		$api_url = sprintf(
			'https://recaptchaenterprise.googleapis.com/v1/projects/%s/assessments?key=%s',
			rawurlencode( $project_id ),
			rawurlencode( $api_key )
		);

		$response = wp_remote_post(
			$api_url,
			array(
				'timeout' => 15,
				'headers' => array( 'Content-Type' => 'application/json' ),
				'body'    => $request_body,
			)
		);

		if ( is_wp_error( $response ) ) {
			$result['message'] = 'Network error: ' . $response->get_error_message();
			$result['request'] = array(
				'url'  => preg_replace( '/key=[^&]+/', 'key=***', $api_url ),
				'body' => json_decode( $request_body, true ),
			);
			return $result;
		}

		$status = wp_remote_retrieve_response_code( $response );
		$body   = json_decode( wp_remote_retrieve_body( $response ), true );

		$result['request'] = array(
			'url'  => preg_replace( '/key=[^&]+/', 'key=***', $api_url ),
			'body' => json_decode( $request_body, true ),
		);
		$result['response'] = array(
			'http_status' => $status,
			'body'        => $body,
		);

		if ( 200 === $status && is_array( $body ) ) {
			$result['ok']      = true;
			$result['message'] = 'Transaction Defense assessment accepted by Google (transactionData payload is valid).';

			if ( isset( $body['fraudPreventionAssessment'] ) ) {
				$result['fraudPreventionAssessment'] = $body['fraudPreventionAssessment'];
			} else {
				$result['fraudPreventionAssessment'] = null;
				$result['note'] = 'No fraudPreventionAssessment returned. This is normal if Transaction defense is not yet enabled for this key in Google Cloud Console (Fraud Defense → Configure Transaction defense), or the model has insufficient data.';
			}
		} elseif ( 400 === $status && is_array( $body ) && isset( $body['error']['message'] ) ) {
			$result['message'] = 'HTTP 400 (Bad Request): ' . $body['error']['message'] . ' — This indicates the transactionData payload has a field Google rejects. Check the request body below.';
		} elseif ( is_array( $body ) && isset( $body['error']['message'] ) ) {
			$result['message'] = 'HTTP ' . $status . ': ' . $body['error']['message'];
		} else {
			$result['message'] = 'HTTP ' . $status . ': unexpected response.';
		}

		return $result;
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
			update_option( 'gswp_site_key', sanitize_text_field( $params['site_key'] ) );
		}

		// Sanitize and update Secret Key.
		if ( isset( $params['secret_key'] ) ) {
			update_option( 'gswp_secret_key', sanitize_text_field( $params['secret_key'] ) );
		}

		// Key type. Only 'classic' or 'enterprise' are valid.
		if ( isset( $params['key_type'] ) ) {
			$key_type = 'enterprise' === $params['key_type'] ? 'enterprise' : 'classic';
			update_option( 'gswp_key_type', $key_type );
		}

		// Sanitize and update Enterprise credentials.
		if ( isset( $params['gcp_project_id'] ) ) {
			update_option( 'gswp_gcp_project_id', sanitize_text_field( $params['gcp_project_id'] ) );
		}
		if ( isset( $params['gcp_api_key'] ) ) {
			update_option( 'gswp_gcp_api_key', sanitize_text_field( $params['gcp_api_key'] ) );
		}

		// Toggles for WooCommerce (Login, Registration, Checkout) and the
		// WordPress core screens (Login, Registration, Lost Password).
		$toggles = array(
			'enable_login',
			'enable_registration',
			'enable_checkout',
			'txn_defense',
			'txn_block',
			'account_defender',
			'ad_step_up',
			'ad_events',
			'ad_block_signup',
			'ad_block_lostpw',
			'ad_share_email',
			'alerts',
			'alert_login',
			'alert_registration',
			'alert_checkout',
			'verbose_logging',
			'enable_wp_login',
			'enable_wp_register',
			'enable_wp_lostpassword',
			'enable_comments',
			'enable_bb_contact',
			'enable_bb_subscribe',
			'enable_pp_contact',
			'enable_pp_subscribe',
			'password_defense',
			'pd_login',
			'pd_block_choice',
			'pd_force_reset',
			'alert_leak',
			'trusted_cloudflare',
			'trusted_quiccloud',
		);
		// Remember CDN toggle states before updating so a 0 -> 1 transition can
		// trigger an immediate IP-list refresh.
		$cdn_toggles = array(
			'cloudflare' => '1' === (string) get_option( 'gswp_trusted_cloudflare', '0' ),
			'quiccloud'  => '1' === (string) get_option( 'gswp_trusted_quiccloud', '0' ),
		);

		foreach ( $toggles as $toggle ) {
			if ( isset( $params[ $toggle ] ) ) {
				update_option( 'gswp_' . $toggle, $params[ $toggle ] ? '1' : '0' );
			}
		}

		// When a CDN toggle is turned on, refresh its edge IP list immediately
		// so the operator sees coverage right away instead of waiting for cron.
		foreach ( $cdn_toggles as $provider => $was_on ) {
			$param   = 'trusted_' . $provider;
			$now_on  = isset( $params[ $param ] ) && $params[ $param ];
			$flipped = ! $was_on && $now_on;

			if ( $flipped ) {
				GSWP_Client_IP::refresh_cdn_ips( $provider );
			}
		}

		// Thresholds. Must validate they are floats between 0.0 and 1.0.
		$thresholds = array(
			'threshold_login',
			'threshold_registration',
			'threshold_checkout',
			'threshold_txn',
			'threshold_wp_login',
			'threshold_wp_register',
			'threshold_wp_lostpassword',
			'threshold_comments',
			'threshold_bb_contact',
			'threshold_bb_subscribe',
			'threshold_pp_contact',
			'threshold_pp_subscribe',
			'threshold_gf_submit',
			'threshold_gf_register',
			'threshold_gf_account_update',
			'threshold_gf_password',
			'threshold_ff_submit',
			'threshold_ff_register',
			'threshold_ff_account_update',
			'threshold_ff_password',
		);
		foreach ( $thresholds as $threshold ) {
			if ( isset( $params[ $threshold ] ) ) {
				$val = floatval( $params[ $threshold ] );
				$val = max( 0.0, min( 1.0, $val ) );
				update_option( 'gswp_' . $threshold, strval( $val ) );
			}
		}

		// Alert recipients: comma-separated list, each address validated,
		// invalid entries dropped, re-joined for storage.
		if ( isset( $params['alert_email'] ) ) {
			$emails = array();
			foreach ( explode( ',', (string) $params['alert_email'] ) as $addr ) {
				$addr = sanitize_email( trim( $addr ) );
				if ( '' !== $addr && is_email( $addr ) ) {
					$emails[] = $addr;
				}
			}
			update_option( 'gswp_alert_email', implode( ', ', array_values( array_unique( $emails ) ) ) );
		}

		// Trusted proxies: addresses and CIDR ranges, whitespace or comma
		// separated, each validated, invalid entries dropped. Storing a typo
		// here would not fail loudly — it would simply never match, leaving the
		// site quietly reporting its CDN's address to Google forever.
		if ( isset( $params['trusted_proxies'] ) ) {
			$ranges  = array();
			$entries = preg_split( '/[\s,]+/', (string) $params['trusted_proxies'], -1, PREG_SPLIT_NO_EMPTY );

			foreach ( (array) $entries as $entry ) {
				$entry = sanitize_text_field( $entry );

				if ( GSWP_Client_IP::is_valid_range( $entry ) ) {
					$ranges[] = $entry;
				}
			}

			update_option( 'gswp_trusted_proxies', implode( ', ', array_values( array_unique( $ranges ) ) ) );
		}

		// The header a trusted proxy forwards the client address in. Only the
		// headers the resolver knows how to read are accepted.
		if ( isset( $params['client_ip_header'] ) ) {
			$header = (string) $params['client_ip_header'];
			update_option(
				'gswp_client_ip_header',
				isset( GSWP_Client_IP::HEADERS[ $header ] ) ? $header : 'X-Forwarded-For'
			);
		}

		// Alert delivery mode. Only known modes are accepted. On a change, clear
		// the digest cron so the next load reschedules it at the new recurrence
		// (GSWP_Alerts::maybe_schedule_digest on init).
		if ( isset( $params['alert_mode'] ) ) {
			$alert_mode = in_array( $params['alert_mode'], array( 'immediate', 'hourly', 'daily' ), true )
				? $params['alert_mode']
				: 'immediate';
			if ( $alert_mode !== get_option( 'gswp_alert_mode', 'immediate' ) ) {
				wp_clear_scheduled_hook( 'gswp_alerts_digest_event' );
			}
			update_option( 'gswp_alert_mode', $alert_mode );
		}

		// Conflict handling mode. Only known modes are accepted.
		if ( isset( $params['form_providers_enabled'] ) ) {
			update_option(
				GSWP_Form_Provider_Registry::ENABLED_OPTION,
				'1' === (string) $params['form_providers_enabled'] ? '1' : '0'
			);
		}

		// Per-provider on/off. Turning one off restores that form plugin's own
		// reCAPTCHA on the next request — nothing was written to its settings,
		// so there is nothing to restore.
		if ( isset( $params['provider_enabled'] ) && is_array( $params['provider_enabled'] ) ) {
			foreach ( $params['provider_enabled'] as $provider_id => $on ) {
				$provider_id = sanitize_key( $provider_id );

				if ( null === GSWP_Form_Provider_Registry::get( $provider_id ) ) {
					continue;
				}

				GSWP_Form_Provider_Registry::set( $provider_id, '1' === (string) $on || true === $on );
			}
		}

		// Forms the operator has declared are never submitted by a visitor.
		// One list per provider: form ids are only unique within their own form
		// plugin, so a single shared list would have Gravity Form #3 silencing
		// the alarm on Fluent Form #3.
		foreach ( array(
			'gf_internal_forms' => 'gswp_gf_internal_forms',
			'ff_internal_forms' => 'gswp_ff_internal_forms',
		) as $param => $option ) {
			if ( ! isset( $params[ $param ] ) || ! is_array( $params[ $param ] ) ) {
				continue;
			}

			$internal = array_values(
				array_unique(
					array_filter(
						array_map( 'intval', $params[ $param ] ),
						static function ( $id ) {
							return $id > 0;
						}
					)
				)
			);

			update_option( $option, $internal, false );
		}

		if ( isset( $params['conflict_mode'] ) ) {
			$mode = in_array( $params['conflict_mode'], array( 'off', 'active', 'site' ), true )
				? $params['conflict_mode']
				: 'off';
			update_option( 'gswp_conflict_mode', $mode );
		}

		// Two-factor: master switch.
		if ( isset( $params['tfa_enabled'] ) ) {
			update_option( 'gswp_2fa_enabled', $params['tfa_enabled'] ? '1' : '0' );
		}

		// Two-factor: allow trusted-browser "remember me".
		if ( isset( $params['tfa_remember'] ) ) {
			update_option( 'gswp_2fa_remember', $params['tfa_remember'] ? '1' : '0' );
		}

		// Two-factor: refuse a secret enrolled on a different site (e.g. a
		// staging clone carrying the production database).
		if ( isset( $params['tfa_env_binding'] ) ) {
			update_option( 'gswp_2fa_env_binding', $params['tfa_env_binding'] ? '1' : '0' );
		}

		// Two-factor: block application passwords for users in enforced roles.
		if ( isset( $params['tfa_block_app_passwords'] ) ) {
			update_option( 'gswp_2fa_block_app_passwords', $params['tfa_block_app_passwords'] ? '1' : '0' );
		}

		// Two-factor: accounts exempt from the application-password block.
		// Comma-separated logins; each is sanitized and kept only when it
		// resolves to a real user, so a typo is dropped at save time rather
		// than silently never matching.
		if ( isset( $params['tfa_app_password_exempt_users'] ) ) {
			$logins = array();
			foreach ( explode( ',', (string) $params['tfa_app_password_exempt_users'] ) as $login ) {
				$login = sanitize_user( trim( $login ), true );
				if ( '' !== $login && get_user_by( 'login', $login ) ) {
					$logins[] = $login;
				}
			}
			update_option( 'gswp_2fa_app_password_exempt_users', implode( ', ', array_values( array_unique( $logins ) ) ) );
		}

		// Two-factor: enrolment grace period in days (0 = enforce immediately).
		if ( isset( $params['tfa_grace_days'] ) ) {
			$days = max( 0, min( 30, (int) $params['tfa_grace_days'] ) );
			update_option( 'gswp_2fa_grace_days', strval( $days ) );
		}

		// Two-factor: roles required to enrol, validated against real roles.
		if ( isset( $params['tfa_enforced_roles'] ) ) {
			$submitted = is_array( $params['tfa_enforced_roles'] ) ? $params['tfa_enforced_roles'] : array();
			$valid     = array_keys( wp_roles()->get_names() );
			$roles     = array_values( array_intersect( array_map( 'sanitize_key', $submitted ), $valid ) );
			update_option( 'gswp_2fa_enforced_roles', $roles );
		}

		return $this->get_settings();
	}
}
