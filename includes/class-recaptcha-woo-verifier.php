<?php
/**
 * Verifier Class
 *
 * Intercepts WooCommerce login, registration, and checkout actions to verify reCAPTCHA tokens.
 *
 * @package Google_Recaptcha_V3_For_WooCommerce
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Recaptcha_Woo_Verifier {

	/**
	 * Constructor.
	 */
	public function __construct() {
		// Hook into login validation.
		add_filter( 'woocommerce_process_login_errors', array( $this, 'validate_login' ), 10, 3 );

		// Hook into registration validation.
		add_filter( 'woocommerce_process_registration_errors', array( $this, 'validate_registration' ), 10, 3 );

		// Hook into checkout validation.
		add_action( 'woocommerce_after_checkout_validation', array( $this, 'validate_checkout' ), 10, 2 );
	}

	/**
	 * Validate login request.
	 *
	 * @param WP_Error $validation_error Current validation errors.
	 * @param string   $username         Submitted username.
	 * @param string   $password         Submitted password.
	 * @return WP_Error Filtered validation errors.
	 */
	public function validate_login( $validation_error, $username, $password ) {
		if ( '1' !== get_option( 'recaptcha_woo_enable_login', '0' ) ) {
			return $validation_error;
		}

		$result = $this->verify_token( 'login' );
		if ( is_wp_error( $result ) ) {
			if ( ! is_wp_error( $validation_error ) ) {
				$validation_error = new WP_Error();
			}
			$validation_error->add( 'recaptcha_error', $result->get_error_message() );
		}

		return $validation_error;
	}

	/**
	 * Validate registration request.
	 *
	 * @param WP_Error $validation_errors Current validation errors.
	 * @param string   $username          Submitted username.
	 * @param string   $email             Submitted email.
	 * @return WP_Error Filtered validation errors.
	 */
	public function validate_registration( $validation_errors, $username, $email ) {
		if ( '1' !== get_option( 'recaptcha_woo_enable_registration', '0' ) ) {
			return $validation_errors;
		}

		$result = $this->verify_token( 'registration' );
		if ( is_wp_error( $result ) ) {
			if ( ! is_wp_error( $validation_errors ) ) {
				$validation_errors = new WP_Error();
			}
			$validation_errors->add( 'recaptcha_error', $result->get_error_message() );
		}

		return $validation_errors;
	}

	/**
	 * Validate checkout request.
	 *
	 * @param array    $data   Post data.
	 * @param WP_Error $errors Validation errors object.
	 */
	public function validate_checkout( $data, $errors ) {
		if ( '1' !== get_option( 'recaptcha_woo_enable_checkout', '0' ) ) {
			return;
		}

		$result = $this->verify_token( 'checkout' );
		if ( is_wp_error( $result ) ) {
			$errors->add( 'recaptcha_error', $result->get_error_message() );
		}
	}

	/**
	 * Verify the submitted reCAPTCHA token for the given context.
	 *
	 * Routes verification through the classic siteverify endpoint or the
	 * reCAPTCHA Enterprise assessments API depending on the configured key type.
	 *
	 * @param string $context Target page context ('login', 'registration', 'checkout').
	 * @return true|WP_Error Returns true on success, WP_Error object on failure.
	 */
	private function verify_token( $context ) {
		$key_type = get_option( 'recaptcha_woo_key_type', 'classic' );

		// Skip verification if credentials are not configured to avoid blocking users.
		if ( 'enterprise' === $key_type ) {
			$configured = '' !== get_option( 'recaptcha_woo_gcp_project_id', '' )
				&& '' !== get_option( 'recaptcha_woo_gcp_api_key', '' )
				&& '' !== get_option( 'recaptcha_woo_site_key', '' );
		} else {
			$configured = '' !== get_option( 'recaptcha_woo_secret_key', '' );
		}

		if ( ! $configured ) {
			return true;
		}

		$token = isset( $_POST['g-recaptcha-response'] ) ? sanitize_text_field( wp_unslash( $_POST['g-recaptcha-response'] ) ) : '';

		if ( empty( $token ) ) {
			return new WP_Error(
				'recaptcha_missing',
				__( '<strong>Error:</strong> Anti-spam verification token is missing. Please refresh the page and try again.', 'google-recaptcha-v3-for-woocommerce' )
			);
		}

		$result = 'enterprise' === $key_type
			? $this->assess_enterprise_token( $token, $context )
			: $this->verify_classic_token( $token );

		if ( true !== $result && ! is_wp_error( $result ) ) {
			// Score returned: check it against the configured threshold.
			$threshold = floatval( get_option( 'recaptcha_woo_threshold_' . $context, '0.5' ) );

			if ( floatval( $result ) < $threshold ) {
				return new WP_Error(
					'recaptcha_low_score',
					__( '<strong>Error:</strong> Verification score too low. Submission rejected as potential spam.', 'google-recaptcha-v3-for-woocommerce' )
				);
			}

			return true;
		}

		return $result;
	}

	/**
	 * Perform a classic reCAPTCHA v3 siteverify call.
	 *
	 * @param string $token Submitted reCAPTCHA token.
	 * @return float|true|WP_Error Score on success, true to skip scoring, WP_Error on failure.
	 */
	private function verify_classic_token( $token ) {
		$secret_key = get_option( 'recaptcha_woo_secret_key', '' );

		$response = wp_remote_post(
			'https://www.google.com/recaptcha/api/siteverify',
			array(
				'timeout' => 10,
				'body'    => array(
					'secret'   => $secret_key,
					'response' => $token,
					'remoteip' => $this->get_remote_ip(),
				),
			)
		);

		if ( is_wp_error( $response ) ) {
			return new WP_Error(
				'recaptcha_api_failed',
				__( '<strong>Error:</strong> Failed to connect to Google reCAPTCHA service. Please try again.', 'google-recaptcha-v3-for-woocommerce' )
			);
		}

		$body = wp_remote_retrieve_body( $response );
		$data = json_decode( $body, true );

		if ( ! is_array( $data ) || ! isset( $data['success'] ) ) {
			return new WP_Error(
				'recaptcha_invalid_response',
				__( '<strong>Error:</strong> Invalid verification response. Please try again.', 'google-recaptcha-v3-for-woocommerce' )
			);
		}

		if ( ! $data['success'] ) {
			$error_codes = isset( $data['error-codes'] ) && is_array( $data['error-codes'] ) ? $data['error-codes'] : array();

			// Credential misconfiguration is a site problem, not a visitor
			// problem: log it and let the submission through rather than
			// blocking every customer.
			$config_errors = array_intersect( $error_codes, array( 'invalid-input-secret', 'missing-input-secret', 'invalid-keys' ) );
			if ( ! empty( $config_errors ) ) {
				$this->log( 'siteverify rejected the configured secret key (' . implode( ', ', $config_errors ) . '). Check the secret key in WooCommerce > reCAPTCHA v3. Verification was skipped.' );
				return true;
			}

			return new WP_Error(
				'recaptcha_failed',
				__( '<strong>Error:</strong> Verification failed. You have been flagged as potential spam. Please try again.', 'google-recaptcha-v3-for-woocommerce' )
			);
		}

		return isset( $data['score'] ) ? floatval( $data['score'] ) : 0.0;
	}

	/**
	 * Create a reCAPTCHA Enterprise assessment for the token.
	 *
	 * @param string $token   Submitted reCAPTCHA token.
	 * @param string $context Target page context ('login', 'registration', 'checkout').
	 * @return float|true|WP_Error Score on success, true to skip scoring, WP_Error on failure.
	 */
	private function assess_enterprise_token( $token, $context ) {
		$project_id = get_option( 'recaptcha_woo_gcp_project_id', '' );
		$api_key    = get_option( 'recaptcha_woo_gcp_api_key', '' );
		$site_key   = get_option( 'recaptcha_woo_site_key', '' );

		// The frontend executes with action 'register' on the registration form.
		$expected_action = 'registration' === $context ? 'register' : $context;

		$api_url = sprintf(
			'https://recaptchaenterprise.googleapis.com/v1/projects/%s/assessments?key=%s',
			rawurlencode( $project_id ),
			rawurlencode( $api_key )
		);

		$response = wp_remote_post(
			$api_url,
			array(
				'timeout' => 10,
				'headers' => array( 'Content-Type' => 'application/json' ),
				'body'    => wp_json_encode(
					array(
						'event' => array(
							'token'          => $token,
							'siteKey'        => $site_key,
							'expectedAction' => $expected_action,
							'userIpAddress'  => $this->get_remote_ip(),
						),
					)
				),
			)
		);

		if ( is_wp_error( $response ) ) {
			return new WP_Error(
				'recaptcha_api_failed',
				__( '<strong>Error:</strong> Failed to connect to Google reCAPTCHA service. Please try again.', 'google-recaptcha-v3-for-woocommerce' )
			);
		}

		$status = wp_remote_retrieve_response_code( $response );
		$data   = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( 200 !== $status || ! is_array( $data ) ) {
			// Non-200 responses indicate a configuration problem (bad API
			// key, wrong project ID, API not enabled): log it and let the
			// submission through rather than blocking every customer.
			$detail = is_array( $data ) && isset( $data['error']['message'] ) ? $data['error']['message'] : 'no detail';
			$this->log( 'Enterprise assessment request failed with HTTP ' . $status . ' (' . $detail . '). Check the GCP project ID and API key in WooCommerce > reCAPTCHA v3. Verification was skipped.' );
			return true;
		}

		$token_properties = isset( $data['tokenProperties'] ) && is_array( $data['tokenProperties'] ) ? $data['tokenProperties'] : array();

		if ( empty( $token_properties['valid'] ) ) {
			$reason = isset( $token_properties['invalidReason'] ) ? $token_properties['invalidReason'] : 'UNKNOWN';

			// Expired or already-used tokens just need a fresh attempt.
			if ( in_array( $reason, array( 'EXPIRED', 'DUPE' ), true ) ) {
				return new WP_Error(
					'recaptcha_expired',
					__( '<strong>Error:</strong> Anti-spam verification expired. Please try again.', 'google-recaptcha-v3-for-woocommerce' )
				);
			}

			return new WP_Error(
				'recaptcha_failed',
				__( '<strong>Error:</strong> Verification failed. You have been flagged as potential spam. Please try again.', 'google-recaptcha-v3-for-woocommerce' )
			);
		}

		if ( isset( $token_properties['action'] ) && $token_properties['action'] !== $expected_action ) {
			return new WP_Error(
				'recaptcha_failed',
				__( '<strong>Error:</strong> Verification failed. You have been flagged as potential spam. Please try again.', 'google-recaptcha-v3-for-woocommerce' )
			);
		}

		return isset( $data['riskAnalysis']['score'] ) ? floatval( $data['riskAnalysis']['score'] ) : 0.0;
	}

	/**
	 * Get the visitor IP for the verification request.
	 *
	 * @return string Remote IP address.
	 */
	private function get_remote_ip() {
		return isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
	}

	/**
	 * Log a verification warning to the WooCommerce logger when available.
	 *
	 * @param string $message Log message.
	 */
	private function log( $message ) {
		if ( function_exists( 'wc_get_logger' ) ) {
			wc_get_logger()->warning( $message, array( 'source' => 'recaptcha-woo' ) );
		}
	}
}
