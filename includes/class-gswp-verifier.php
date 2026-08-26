<?php
/**
 * Verifier Class
 *
 * Intercepts WooCommerce login, registration, and checkout actions to verify reCAPTCHA tokens.
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class GSWP_Verifier {

	/**
	 * Resource name of the most recent Enterprise assessment, e.g.
	 * "projects/123/assessments/abc". Captured so a checkout can be tied to
	 * its assessment and annotated later. Empty when none was created.
	 *
	 * @var string
	 */
	private $last_assessment_name = '';

	/**
	 * The fraudPreventionAssessment block from the most recent Enterprise
	 * assessment response, or null when Transaction defense returned nothing.
	 *
	 * @var array|null
	 */
	private $last_fraud_assessment = null;

	/**
	 * The accountDefenderAssessment block from the most recent Enterprise
	 * assessment response, or null when Account Defender returned nothing.
	 *
	 * @var array|null
	 */
	private $last_account_assessment = null;

	/**
	 * Threshold context of the most recent verify_token() call (e.g. 'wp_register').
	 * Lets downstream consumers tell a registration assessment apart from a login
	 * one when both could occur in a single request (auto-login after signup).
	 *
	 * @var string
	 */
	private $last_context = '';

	/**
	 * reCAPTCHA score from the most recent assessment, or null when none was
	 * returned (no verification ran, or the token was rejected before scoring).
	 *
	 * Exposed so a caller that receives a non-score error — notably an action
	 * mismatch — can still consult Google's actual judgement of the traffic
	 * rather than treating a labelling problem as a verdict about the visitor.
	 *
	 * @var float|null
	 */
	private $last_score = null;

	/**
	 * The action reCAPTCHA reported the token was minted with, when the
	 * assessment returned one. Empty for classic verification, which does not
	 * report the action at all.
	 *
	 * @var string
	 */
	private $last_token_action = '';

	/**
	 * Request-scoped cache of token verification results.
	 *
	 * Keyed by token, threshold context and expected action together. Each
	 * entry holds the final verdict (true or WP_Error) plus the score and
	 * token action captured at verification time. When the same single-use
	 * token is verified more than once in a single request, subsequent calls
	 * return the cached verdict instead of making a duplicate API call that
	 * Google would reject with invalidReason: DUPE.
	 *
	 * The context and action are part of the key because the verdict was
	 * computed against both, and a cache hit re-runs neither check. See the
	 * comment at the lookup site in verify_token().
	 *
	 * Assessment metadata (assessment name, fraud/account assessments) is
	 * deliberately NOT cached: each user in a bulk operation would otherwise
	 * inherit the first user's assessment resource, causing later annotation
	 * to annotate the wrong assessment.
	 *
	 * @var array<string, array{result: true|WP_Error, score: float|null, token_action: string}>
	 */
	private $token_cache = array();

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
		if ( '1' !== get_option( 'gswp_enable_login', '0' ) ) {
			return $validation_error;
		}

		$result = $this->verify_token( 'login', 'login', array(), $username );
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
		if ( '1' !== get_option( 'gswp_enable_registration', '0' ) ) {
			return $validation_errors;
		}

		$result = $this->verify_token( 'registration', 'register', array(), $email );
		if ( is_wp_error( $result ) ) {
			if ( ! is_wp_error( $validation_errors ) ) {
				$validation_errors = new WP_Error();
			}
			$validation_errors->add( 'recaptcha_error', $result->get_error_message() );
			return $validation_errors;
		}

		// The score passed; also consult any Account Defender fake-signup labels.
		$screen = class_exists( 'GSWP_Account_Defender' )
			? GSWP_Account_Defender::screen_registration( $this, $email, 'woocommerce' )
			: null;
		if ( is_wp_error( $screen ) ) {
			if ( ! is_wp_error( $validation_errors ) ) {
				$validation_errors = new WP_Error();
			}
			$validation_errors->add( 'recaptcha_error', $screen->get_error_message() );
		}

		// Local content heuristic: catch gibberish field data even when Google
		// returns no Account Defender labels.
		if ( class_exists( 'GSWP_Account_Defender' ) && ( ! is_wp_error( $validation_errors ) || ! $validation_errors->has_errors() ) ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Missing -- WooCommerce validates its own nonce before this filter.
			$content_fields = array(
				'first_name' => isset( $_POST['first_name'] ) ? sanitize_text_field( wp_unslash( $_POST['first_name'] ) ) : '',
				'last_name'  => isset( $_POST['last_name'] ) ? sanitize_text_field( wp_unslash( $_POST['last_name'] ) ) : '',
				'user_url'   => isset( $_POST['website'] ) ? sanitize_text_field( wp_unslash( $_POST['website'] ) ) : '',
			);
			$content_screen = GSWP_Account_Defender::screen_registration_content( $content_fields, (string) $email, 'woocommerce' );
			if ( is_wp_error( $content_screen ) ) {
				if ( ! is_wp_error( $validation_errors ) ) {
					$validation_errors = new WP_Error();
				}
				$validation_errors->add( 'recaptcha_error', $content_screen->get_error_message() );
			}
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
		if ( '1' !== get_option( 'gswp_enable_checkout', '0' ) ) {
			return;
		}

		// Attach payment transaction data so reCAPTCHA Enterprise Transaction
		// defense can return a fraudPreventionAssessment. Empty for classic
		// keys, when the feature is off, or when the minimum fields are absent.
		$event_extra = $this->build_checkout_event_extra();

		$result = $this->verify_token( 'checkout', 'checkout', $event_extra );
		if ( is_wp_error( $result ) ) {
			$errors->add( 'recaptcha_error', $result->get_error_message() );
		}

		// Interpret the Transaction defense verdict: record the risk, stash the
		// assessment name for annotation, and optionally block high-risk orders.
		$this->process_fraud_prevention( $errors );
	}

	/**
	 * Verify the submitted reCAPTCHA token for the given context.
	 *
	 * Routes verification through the classic siteverify endpoint or the
	 * reCAPTCHA Enterprise assessments API depending on the configured key type.
	 *
	 * @param string       $context         Threshold context. The configured threshold
	 *                                is read from "gswp_threshold_{$context}".
	 * @param string|array $expected_action reCAPTCHA action name the frontend executed
	 *                                with, validated for Enterprise assessments.
	 *                                May be a list, in which case the first entry
	 *                                is sent to Google as expectedAction and the
	 *                                token's own action is accepted if it matches
	 *                                any entry. A list is only ever used to accept
	 *                                a second action name WE mint ourselves (see
	 *                                GSWP_Provider_Gravity_Forms::accepted_actions),
	 *                                never to widen what a request may claim.
	 * @param array  $event_extra     Extra fields merged into the Enterprise
	 *                                assessment "event" (e.g. transactionData).
	 *                                Ignored for classic verification.
	 * @param mixed  $account_identifier Optional WP_User, user ID, login, or email
	 *                                identifying the account, used to attach
	 *                                Account Defender userInfo on login/register
	 *                                assessments.
	 * @param string $token           Optional explicit reCAPTCHA token. When null
	 *                                the token is read from the posted
	 *                                g-recaptcha-response field (classic form
	 *                                submissions); Store API callers pass it in.
	 * @return true|WP_Error Returns true on success, WP_Error object on failure.
	 */
	public function verify_token( $context, $expected_action, $event_extra = array(), $account_identifier = null, $token = null ) {
		// Reset any verdict captured by a previous call on this request.
		$this->last_assessment_name   = '';
		$this->last_fraud_assessment  = null;
		$this->last_account_assessment = null;
		$this->last_context            = (string) $context;
		$this->last_score              = null;
		$this->last_token_action       = '';

		// Attach Account Defender account identifiers on login/registration
		// assessments so Google can build its site-specific behavioural model.
		$user_info = $this->build_account_user_info( $context, $account_identifier );
		if ( ! empty( $user_info ) ) {
			$event_extra = array_merge( is_array( $event_extra ) ? $event_extra : array(), $user_info );
		}

		// A4: the same predicate that decides whether a token field is printed.
		// It reads only stored options, so the render request and this
		// validation request always agree — enforcement can never outlive the
		// field. Deciding this from anything in the request body would let a
		// caller opt out by omitting a field, which is the bypass class removed
		// in 2.17.0.
		if ( ! GSWP_Recaptcha_Loader::will_load() ) {
			$this->log( 'No reCAPTCHA site key is configured, so no token field was printed. Verification skipped for context "' . $context . '".' );
			return true;
		}

		$key_type = get_option( 'gswp_key_type', 'classic' );

		// Skip verification if credentials are not configured to avoid blocking users.
		if ( 'enterprise' === $key_type ) {
			$configured = '' !== get_option( 'gswp_gcp_project_id', '' )
				&& '' !== get_option( 'gswp_gcp_api_key', '' )
				&& '' !== get_option( 'gswp_site_key', '' );
		} else {
			$configured = '' !== get_option( 'gswp_secret_key', '' );
		}

		if ( ! $configured ) {
			return true;
		}

		// Classic form submissions carry the token in the posted field; Store API
		// callers pass it explicitly (no $_POST payload exists there).
		if ( null === $token ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Missing
			$token = isset( $_POST['g-recaptcha-response'] ) ? sanitize_text_field( wp_unslash( $_POST['g-recaptcha-response'] ) ) : '';
		}

		if ( empty( $token ) ) {
			return new WP_Error(
				'recaptcha_missing',
				__( '<strong>Error:</strong> Anti-spam verification token is missing. Please refresh the page and try again.', 'google-security-for-wordpress' )
			);
		}

		// Return a cached verdict when the same token has already been verified
		// on this request, so Google's single-use enforcement does not reject
		// the second and later calls with `invalidReason: DUPE`. The API call is
		// skipped; score and token action are restored so threshold and action
		// checks still see the original values. Assessment metadata is left at
		// its reset defaults to avoid annotating the wrong user's assessment
		// later.
		//
		// The key includes the context and the expected action, not just the
		// token. The cached verdict was computed against both — the action check
		// happens inside assess_enterprise_token(), which a cache hit skips, and
		// the threshold is read as gswp_threshold_{$context}. Keying on the
		// token alone would let a verdict earned under a permissive context
		// satisfy a stricter one within the same request without either check
		// being re-run.
		$cache_key = $token . '|' . $context . '|' . ( is_array( $expected_action ) ? implode( ',', $expected_action ) : (string) $expected_action );

		if ( isset( $this->token_cache[ $cache_key ] ) ) {
			$cached                  = $this->token_cache[ $cache_key ];
			$this->last_score        = $cached['score'];
			$this->last_token_action = $cached['token_action'];
			return $cached['result'];
		}

		$result = 'enterprise' === $key_type
			? $this->assess_enterprise_token( $token, $expected_action, $event_extra )
			: $this->verify_classic_token( $token );

		if ( true !== $result && ! is_wp_error( $result ) ) {
			// Score returned: check it against the configured threshold.
			$this->last_score = floatval( $result );
			$threshold        = floatval( get_option( 'gswp_threshold_' . $context, '0.5' ) );

			if ( $this->last_score < $threshold ) {
				// A payment that carried transactionData has already been
				// judged by the model built to judge payments. When that model
				// clears it, it outranks the generic bot score — see
				// fraud_verdict_admits_low_score().
				if ( $this->fraud_verdict_admits_low_score() ) {
					$this->token_cache[ $cache_key ] = array(
						'result'       => true,
						'score'        => $this->last_score,
						'token_action' => $this->last_token_action,
					);

					return true;
				}

				// The only rejection in this class that is an honest statement
				// about the visitor: Google scored the traffic and it came up
				// short. Every other rejection path is about the token.
				$this->log_rejection(
					'score below threshold',
					$expected_action,
					sprintf( 'score %.2f < threshold %.2f', $this->last_score, $threshold )
				);

				$final = new WP_Error(
					'recaptcha_low_score',
					__( '<strong>Error:</strong> This submission did not pass our automated security check. Please refresh the page and try again, or contact us if the problem continues.', 'google-security-for-wordpress' )
				);

				$this->token_cache[ $cache_key ] = array(
					'result'       => $final,
					'score'        => $this->last_score,
					'token_action' => $this->last_token_action,
				);

				return $final;
			}

			$this->token_cache[ $cache_key ] = array(
				'result'       => true,
				'score'        => $this->last_score,
				'token_action' => $this->last_token_action,
			);

			return true;
		}

		// Cache the terminal result (true or WP_Error) so a subsequent call
		// with the same token on this request reuses the verdict.
		$this->token_cache[ $cache_key ] = array(
			'result'       => $result,
			'score'        => $this->last_score,
			'token_action' => $this->last_token_action,
		);

		return $result;
	}

	/**
	 * Record why a submission was rejected.
	 *
	 * Until 2.21.2 every rejection returned a WP_Error and wrote nothing
	 * anywhere — not the siteverify error codes, not the Enterprise
	 * invalidReason, not the observed action. Five materially different causes
	 * all surfaced to the operator as one sentence accusing the visitor of spam,
	 * which is how a working customer came to be reported as a suspected
	 * spammer. A rejection nobody can explain is a defect in its own right.
	 *
	 * @param string       $reason   Short cause, e.g. 'action mismatch'.
	 * @param string|array $expected Expected action, or list of accepted actions.
	 * @param string       $detail   Extra detail for the operator.
	 * @param bool         $is_error Whether this is a site misconfiguration
	 *                               rather than a routine rejection.
	 */
	private function log_rejection( $reason, $expected, $detail = '', $is_error = false ) {
		$parts = array(
			'reCAPTCHA rejected a submission: ' . $reason . '.',
			'context=' . $this->last_context,
			'expected_action=' . implode( '|', array_filter( (array) $expected ) ),
		);

		if ( '' !== $this->last_token_action ) {
			$parts[] = 'token_action=' . $this->last_token_action;
		}
		if ( '' !== $detail ) {
			$parts[] = $detail;
		}

		$parts[] = 'site_key=' . GSWP_Recaptcha_Loader::mask_key( get_option( 'gswp_site_key', '' ) );

		$message = implode( ' ', $parts );

		if ( $is_error ) {
			GSWP_Log::error( $message );
		} else {
			$this->log( $message );
		}
	}

	/**
	 * Whether Transaction defense clears a submission the score would reject.
	 *
	 * reCAPTCHA returns two independent judgements for a payment. `riskAnalysis.score`
	 * is a general "how much does this look like a bot" signal about the browser.
	 * `fraudPreventionAssessment.transactionRisk` — returned only when the assessment
	 * carries transactionData — is a fraud probability for this specific payment.
	 *
	 * Until 2.28.0 the score was checked first and returned a WP_Error on its own,
	 * so a transaction Google's payment model had explicitly cleared could still be
	 * refused because the generic score came up short. That is not hypothetical: a
	 * customer on a corporate VPN, returning to a checkout tab after ten minutes,
	 * scored 0.2 with reason UNEXPECTED_ENVIRONMENT while transactionRisk came back
	 * 0.10. The fraud model looked at the same event and called it safe; the score
	 * gate refused the order and told him he looked like spam. A VPN, a privacy
	 * extension or a corporate proxy depresses the score of every legitimate shopper
	 * behind it, and none of that is evidence about a card.
	 *
	 * So when a fraud verdict exists and it is below the blocking threshold, the
	 * fraud verdict decides. A carding run does not benefit from this: automated
	 * card testing scores low AND carries high transactionRisk, which fails the
	 * check below and is still refused on the score. This only ever admits a
	 * transaction Google's fraud model has already cleared.
	 *
	 * Only reachable where transactionData was sent — WooCommerce checkout, and
	 * Gravity Forms / Fluent Forms payment forms. Every other context leaves
	 * $last_fraud_assessment null and is unaffected.
	 *
	 * Logs whenever it admits. A submission that would have been blocked and was
	 * not is precisely the event an operator needs to be able to find later.
	 *
	 * @return bool True when the fraud verdict should override a low score.
	 */
	public function fraud_verdict_admits_low_score() {
		if ( null === $this->last_fraud_assessment || ! isset( $this->last_fraud_assessment['transactionRisk'] ) ) {
			return false;
		}

		$risk      = floatval( $this->last_fraud_assessment['transactionRisk'] );
		$threshold = floatval( get_option( 'gswp_threshold_txn', '0.8' ) );

		if ( $risk >= $threshold ) {
			return false;
		}

		/**
		 * Filter whether a clean Transaction defense verdict overrides a low
		 * reCAPTCHA score. Return false to restore the pre-2.28.0 behaviour,
		 * where the score blocked the submission on its own.
		 *
		 * @param bool   $admit     Whether to admit the submission.
		 * @param float  $risk      transactionRisk from the fraud assessment.
		 * @param float  $threshold The configured blocking threshold.
		 * @param string $context   Threshold context, e.g. 'checkout'.
		 */
		if ( ! apply_filters( 'gswp_defer_score_to_fraud_verdict', true, $risk, $threshold, $this->last_context ) ) {
			return false;
		}

		$this->log(
			sprintf(
				'reCAPTCHA score %.2f is below the %s threshold, but Transaction defense scored this payment at risk %.2f (below the %.2f blocking threshold). Admitted: the fraud model judges the payment, the score judges the browser. assessment=%s',
				null === $this->last_score ? 0.0 : $this->last_score,
				$this->last_context,
				$risk,
				$threshold,
				'' !== $this->last_assessment_name ? $this->last_assessment_name : 'none'
			)
		);

		return true;
	}

	/**
	 * Perform a classic reCAPTCHA v3 siteverify call.
	 *
	 * @param string $token Submitted reCAPTCHA token.
	 * @return float|true|WP_Error Score on success, true to skip scoring, WP_Error on failure.
	 */
	private function verify_classic_token( $token ) {
		$secret_key = get_option( 'gswp_secret_key', '' );

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
				__( '<strong>Error:</strong> Failed to connect to Google reCAPTCHA service. Please try again.', 'google-security-for-wordpress' )
			);
		}

		$body = wp_remote_retrieve_body( $response );
		$data = json_decode( $body, true );

		if ( ! is_array( $data ) || ! isset( $data['success'] ) ) {
			return new WP_Error(
				'recaptcha_invalid_response',
				__( '<strong>Error:</strong> Invalid verification response. Please try again.', 'google-security-for-wordpress' )
			);
		}

		if ( ! $data['success'] ) {
			$error_codes = isset( $data['error-codes'] ) && is_array( $data['error-codes'] ) ? $data['error-codes'] : array();
			$codes       = implode( ', ', $error_codes );

			// Credential misconfiguration is a site problem, not a visitor
			// problem: log it and let the submission through rather than
			// blocking every customer. Safe to fail open because our stored
			// secret is not something a visitor can influence.
			$config_errors = array_intersect( $error_codes, array( 'invalid-input-secret', 'missing-input-secret', 'invalid-keys' ) );
			if ( ! empty( $config_errors ) ) {
				$this->log( 'siteverify rejected the configured secret key (' . implode( ', ', $config_errors ) . '). Check the secret key in WooCommerce > reCAPTCHA v3. Verification was skipped.' );
				return true;
			}

			// A stale or already-spent token. The Enterprise path has always
			// treated this as "fetch a fresh one and retry"; the classic path
			// had no equivalent, so the single most common siteverify failure
			// fell through to an accusation of spam. v3 tokens last 120 seconds
			// and are single use, so this is routine — a visitor who fills a
			// long form on a phone, backgrounds the tab, and comes back will
			// hit it without doing anything wrong.
			if ( in_array( 'timeout-or-duplicate', $error_codes, true ) ) {
				$this->log_rejection( 'token expired or already used', '', 'error-codes: ' . $codes );

				return new WP_Error(
					'recaptcha_expired',
					__( '<strong>Error:</strong> Anti-spam verification expired. Please try again.', 'google-security-for-wordpress' )
				);
			}

			// The visitor's browser could not produce a usable token. Also not a
			// judgement about them.
			if ( in_array( 'browser-error', $error_codes, true ) ) {
				$this->log_rejection( 'browser could not produce a token', '', 'error-codes: ' . $codes );

				return new WP_Error(
					'recaptcha_expired',
					__( '<strong>Error:</strong> Anti-spam verification could not be completed. Please refresh the page and try again.', 'google-security-for-wordpress' )
				);
			}

			$this->log_rejection( 'siteverify returned success=false', '', 'error-codes: ' . ( '' !== $codes ? $codes : 'none reported' ) );

			return new WP_Error(
				'recaptcha_failed',
				__( '<strong>Error:</strong> We could not verify this submission. Please refresh the page and try again.', 'google-security-for-wordpress' )
			);
		}

		return isset( $data['score'] ) ? floatval( $data['score'] ) : 0.0;
	}

	/**
	 * Create a reCAPTCHA Enterprise assessment for the token.
	 *
	 * @param string $token           Submitted reCAPTCHA token.
	 * @param string $expected_action reCAPTCHA action name the frontend executed with.
	 * @param array  $event_extra     Extra fields merged into the "event" object,
	 *                                such as transactionData and fraudPrevention.
	 * @return float|true|WP_Error Score on success, true to skip scoring, WP_Error on failure.
	 */
	private function assess_enterprise_token( $token, $expected_action, $event_extra = array() ) {
		$project_id = get_option( 'gswp_gcp_project_id', '' );
		$api_key    = get_option( 'gswp_gcp_api_key', '' );
		$site_key   = get_option( 'gswp_site_key', '' );

		$api_url = sprintf(
			'https://recaptchaenterprise.googleapis.com/v1/projects/%s/assessments?key=%s',
			rawurlencode( $project_id ),
			rawurlencode( $api_key )
		);

		// An action list validates against every entry but reports the first to
		// Google, which accepts a single expectedAction.
		$accepted_actions = array_values( array_filter( (array) $expected_action ) );
		$primary_action   = ! empty( $accepted_actions ) ? $accepted_actions[0] : '';

		$event = array_merge(
			array(
				'token'          => $token,
				'siteKey'        => $site_key,
				'expectedAction' => $primary_action,
				'userIpAddress'  => $this->get_remote_ip(),
			),
			is_array( $event_extra ) ? $event_extra : array()
		);

		$response = wp_remote_post(
			$api_url,
			array(
				'timeout' => 10,
				'headers' => array( 'Content-Type' => 'application/json' ),
				'body'    => wp_json_encode( array( 'event' => $event ) ),
			)
		);

		if ( is_wp_error( $response ) ) {
			return new WP_Error(
				'recaptcha_api_failed',
				__( '<strong>Error:</strong> Failed to connect to Google reCAPTCHA service. Please try again.', 'google-security-for-wordpress' )
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

		// Capture the assessment name (for later annotation) and the Transaction
		// defense verdict, when the integration is complete enough to return one.
		if ( isset( $data['name'] ) ) {
			$this->last_assessment_name = sanitize_text_field( $data['name'] );
		}
		if ( isset( $data['fraudPreventionAssessment'] ) && is_array( $data['fraudPreventionAssessment'] ) ) {
			$this->last_fraud_assessment = $data['fraudPreventionAssessment'];
		}
		if ( isset( $data['accountDefenderAssessment'] ) && is_array( $data['accountDefenderAssessment'] ) ) {
			$this->last_account_assessment = $data['accountDefenderAssessment'];
		}

		$token_properties = isset( $data['tokenProperties'] ) && is_array( $data['tokenProperties'] ) ? $data['tokenProperties'] : array();

		if ( isset( $token_properties['action'] ) ) {
			$this->last_token_action = (string) $token_properties['action'];
		}

		$score = isset( $data['riskAnalysis']['score'] ) ? floatval( $data['riskAnalysis']['score'] ) : 0.0;

		if ( empty( $token_properties['valid'] ) ) {
			$reason = isset( $token_properties['invalidReason'] ) ? $token_properties['invalidReason'] : 'UNKNOWN';

			// Expired or already-used tokens just need a fresh attempt. So does
			// a browser that failed to produce one — none of these say anything
			// about the visitor.
			if ( in_array( $reason, array( 'EXPIRED', 'DUPE', 'BROWSER_ERROR' ), true ) ) {
				$this->log_rejection( 'token not usable', $expected_action, 'invalidReason: ' . $reason );

				return new WP_Error(
					'recaptcha_expired',
					__( '<strong>Error:</strong> Anti-spam verification expired. Please try again.', 'google-security-for-wordpress' )
				);
			}

			// The token was minted against a different site key. That is a
			// configuration fault worth shouting about, but — unlike a bad
			// secret — it must NOT fail open: the token comes from the request,
			// so anyone with a reCAPTCHA account of their own could mint one and
			// walk straight past verification. Log loudly, keep blocking.
			if ( 'SITE_MISMATCH' === $reason ) {
				$this->log_rejection(
					'token was minted for a DIFFERENT site key',
					$expected_action,
					'invalidReason: SITE_MISMATCH. Check that every plugin loading reCAPTCHA on this page uses the site key configured here.',
					true
				);

				return new WP_Error(
					'recaptcha_failed',
					__( '<strong>Error:</strong> We could not verify this submission. Please refresh the page and try again.', 'google-security-for-wordpress' )
				);
			}

			$this->log_rejection( 'token rejected by Google', $expected_action, 'invalidReason: ' . $reason );

			return new WP_Error(
				'recaptcha_failed',
				__( '<strong>Error:</strong> We could not verify this submission. Please refresh the page and try again.', 'google-security-for-wordpress' )
			);
		}

		// The token is valid for this site key; only its label disagrees. That
		// is almost always OUR bug — two places deciding the action name and
		// drifting apart, which is exactly what rejected every Gravity Forms
		// account form — or a page cached before an action name changed. It is
		// not evidence about the visitor, so it gets its own error code and the
		// score is kept, letting the caller apply a policy proportionate to the
		// form rather than blocking a customer over a string mismatch.
		if ( '' !== $this->last_token_action && ! empty( $accepted_actions ) && ! in_array( $this->last_token_action, $accepted_actions, true ) ) {
			$this->last_score = $score;

			$this->log_rejection(
				'token action does not match',
				$expected_action,
				'The token is valid for this site key but carries a different action name. This is usually a plugin bug or a page cached before the action changed, not a spam signal.',
				true
			);

			return new WP_Error(
				'recaptcha_action_mismatch',
				__( '<strong>Error:</strong> We could not verify this submission. Please refresh the page and try again.', 'google-security-for-wordpress' )
			);
		}

		return $score;
	}

	/**
	 * reCAPTCHA score from the most recent assessment.
	 *
	 * @return float|null Score (0..1, higher is more likely human), or null when
	 *                    no assessment produced one.
	 */
	public function get_last_score() {
		return $this->last_score;
	}

	/**
	 * The action the most recent token was actually minted with.
	 *
	 * @return string Action name, or '' when none was reported.
	 */
	public function get_last_token_action() {
		return $this->last_token_action;
	}

	/**
	 * Build the extra Enterprise event fields for a checkout assessment.
	 *
	 * Assembles reCAPTCHA Enterprise transactionData from the posted checkout
	 * fields and the WooCommerce cart so Transaction defense can score the
	 * payment. Returns an empty array (no transaction data) unless every
	 * precondition holds: an Enterprise key, the feature enabled, an available
	 * cart, and the minimum fields Google requires (billing region + postal
	 * code + payment method). Without that minimum the assessment API rejects
	 * the request with HTTP 400, which would also skip the reCAPTCHA score.
	 *
	 * @return array Event fields to merge (transactionData, fraudPrevention), or empty.
	 */
	private function build_checkout_event_extra() {
		if ( 'enterprise' !== get_option( 'gswp_key_type', 'classic' ) ) {
			return array();
		}
		if ( '1' !== get_option( 'gswp_txn_defense', '0' ) ) {
			return array();
		}
		if ( ! function_exists( 'WC' ) || ! WC()->cart ) {
			return array();
		}

		$billing  = $this->build_address( 'billing' );
		$shipping = $this->build_address( 'shipping' );

		// WooCommerce reuses the billing address when "ship to a different
		// address" is unchecked, in which case the shipping_* fields are blank.
		if ( empty( $shipping['regionCode'] ) && empty( $shipping['postalCode'] ) ) {
			$shipping = $billing;
		}

		$payment_method = $this->posted_field( 'payment_method' );

		// Enforce Google's documented minimum; otherwise omit transaction data
		// entirely and let the assessment run as a plain reCAPTCHA score.
		if ( empty( $billing['regionCode'] ) || empty( $billing['postalCode'] ) || '' === $payment_method ) {
			return array();
		}

		$transaction_data = array(
			'paymentMethod'  => $payment_method,
			'currencyCode'   => function_exists( 'get_woocommerce_currency' ) ? get_woocommerce_currency() : '',
			'value'          => (float) WC()->cart->get_total( 'edit' ),
			'shippingValue'  => (float) WC()->cart->get_shipping_total(),
			'billingAddress' => $billing,
		);

		if ( ! empty( $shipping['regionCode'] ) || ! empty( $shipping['postalCode'] ) ) {
			$transaction_data['shippingAddress'] = $shipping;
		}

		$user = $this->build_transaction_user();
		if ( ! empty( $user ) ) {
			$transaction_data['user'] = $user;
		}

		$items = $this->build_transaction_items();
		if ( ! empty( $items ) ) {
			$transaction_data['items'] = $items;
		}

		return array(
			'transactionData' => $transaction_data,
			// Force the fraud assessment regardless of the console toggle state.
			'fraudPrevention' => 'ENABLED',
		);
	}

	/**
	 * Read a posted checkout field, unslashed and sanitized.
	 *
	 * @param string $key Field name in $_POST.
	 * @return string Sanitized value, or '' when absent.
	 */
	private function posted_field( $key ) {
		// Nonce verification is handled by WooCommerce checkout before this
		// validation hook fires; we only read fields it has already accepted.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		return isset( $_POST[ $key ] ) ? sanitize_text_field( wp_unslash( $_POST[ $key ] ) ) : '';
	}

	/**
	 * Build a reCAPTCHA Enterprise Address from posted billing/shipping fields.
	 *
	 * @param string $prefix Either "billing" or "shipping".
	 * @return array Address fields keyed for the assessment API.
	 */
	private function build_address( $prefix ) {
		return $this->format_address(
			$this->posted_field( $prefix . '_first_name' ),
			$this->posted_field( $prefix . '_last_name' ),
			$this->posted_field( $prefix . '_address_1' ),
			$this->posted_field( $prefix . '_address_2' ),
			$this->posted_field( $prefix . '_city' ),
			$this->posted_field( $prefix . '_state' ),
			$this->posted_field( $prefix . '_country' ),
			$this->posted_field( $prefix . '_postcode' )
		);
	}

	/**
	 * Assemble a reCAPTCHA Enterprise Address from its component parts.
	 *
	 * Shared by the posted-field (classic checkout) and order-based (Store API /
	 * block checkout) builders so both emit an identical payload shape.
	 *
	 * @param string $first    First name.
	 * @param string $last     Last name.
	 * @param string $line1    Address line 1.
	 * @param string $line2    Address line 2.
	 * @param string $city     Locality.
	 * @param string $state    Administrative area.
	 * @param string $country  Region (country) code.
	 * @param string $postcode Postal code.
	 * @return array Address fields keyed for the assessment API, empties dropped.
	 */
	private function format_address( $first, $last, $line1, $line2, $city, $state, $country, $postcode ) {
		$lines = array_values( array_filter( array( $line1, $line2 ) ) );

		$address = array(
			'recipient'          => trim( $first . ' ' . $last ),
			'locality'           => $city,
			'administrativeArea' => $state,
			'regionCode'         => $country,
			'postalCode'         => $postcode,
		);

		if ( ! empty( $lines ) ) {
			$address['address'] = $lines;
		}

		// Drop empties so the payload only carries what we actually have.
		return array_filter(
			$address,
			static function ( $value ) {
				return '' !== $value && array() !== $value;
			}
		);
	}

	/**
	 * Build the extra Enterprise event fields for a Store API / block checkout.
	 *
	 * Store API submissions carry no $_POST payload, so transaction data is
	 * assembled from the WC_Order that the checkout route has already populated.
	 * Mirrors build_checkout_event_extra(): returns an empty array unless an
	 * Enterprise key is set, Transaction defense is on, and Google's documented
	 * minimum (billing region + postal code + payment method) is present.
	 *
	 * @param WC_Order $order Order being checked out.
	 * @return array Event fields to merge (transactionData, fraudPrevention), or empty.
	 */
	private function build_checkout_event_extra_from_order( $order ) {
		if ( 'enterprise' !== get_option( 'gswp_key_type', 'classic' ) ) {
			return array();
		}
		if ( '1' !== get_option( 'gswp_txn_defense', '0' ) ) {
			return array();
		}
		if ( ! $order instanceof WC_Order ) {
			return array();
		}

		$billing = $this->format_address(
			$order->get_billing_first_name(),
			$order->get_billing_last_name(),
			$order->get_billing_address_1(),
			$order->get_billing_address_2(),
			$order->get_billing_city(),
			$order->get_billing_state(),
			$order->get_billing_country(),
			$order->get_billing_postcode()
		);

		$shipping = $this->format_address(
			$order->get_shipping_first_name(),
			$order->get_shipping_last_name(),
			$order->get_shipping_address_1(),
			$order->get_shipping_address_2(),
			$order->get_shipping_city(),
			$order->get_shipping_state(),
			$order->get_shipping_country(),
			$order->get_shipping_postcode()
		);

		// Orders with no separate shipping address reuse the billing address.
		if ( empty( $shipping['regionCode'] ) && empty( $shipping['postalCode'] ) ) {
			$shipping = $billing;
		}

		$payment_method = $order->get_payment_method();

		// Enforce Google's documented minimum; otherwise omit transaction data
		// entirely and let the assessment run as a plain reCAPTCHA score.
		if ( empty( $billing['regionCode'] ) || empty( $billing['postalCode'] ) || '' === $payment_method ) {
			return array();
		}

		$transaction_data = array(
			'paymentMethod'  => $payment_method,
			'currencyCode'   => $order->get_currency(),
			'value'          => (float) $order->get_total(),
			'shippingValue'  => (float) $order->get_shipping_total(),
			'billingAddress' => $billing,
		);

		if ( ! empty( $shipping['regionCode'] ) || ! empty( $shipping['postalCode'] ) ) {
			$transaction_data['shippingAddress'] = $shipping;
		}

		$user = $this->build_transaction_user_from_order( $order );
		if ( ! empty( $user ) ) {
			$transaction_data['user'] = $user;
		}

		$items = $this->build_transaction_items_from_order( $order );
		if ( ! empty( $items ) ) {
			$transaction_data['items'] = $items;
		}

		return array(
			'transactionData' => $transaction_data,
			// Force the fraud assessment regardless of the console toggle state.
			'fraudPrevention' => 'ENABLED',
		);
	}

	/**
	 * Build the transactionData.user block from an order's payer.
	 *
	 * @param WC_Order $order Order being checked out.
	 * @return array User fields keyed for the assessment API, or empty.
	 */
	private function build_transaction_user_from_order( $order ) {
		$user  = array();
		$email = $order->get_billing_email();

		if ( '' !== $email ) {
			$user['email'] = $email;
		}

		$customer_id = $order->get_customer_id();
		if ( $customer_id > 0 ) {
			$customer              = get_user_by( 'id', $customer_id );
			$user['accountId']     = (string) $customer_id;
			$user['emailVerified'] = true;

			if ( $customer instanceof WP_User ) {
				$registered = strtotime( $customer->user_registered . ' UTC' );
				if ( $registered ) {
					$user['creationMs'] = (string) ( $registered * 1000 );
				}
			}
		}

		return $user;
	}

	/**
	 * Build the transactionData.items list from an order's line items.
	 *
	 * @param WC_Order $order Order being checked out.
	 * @return array List of item arrays keyed for the assessment API.
	 */
	private function build_transaction_items_from_order( $order ) {
		$items = array();

		foreach ( $order->get_items() as $item ) {
			$quantity = (int) $item->get_quantity();
			if ( $quantity < 1 ) {
				continue;
			}

			// Per-item price after line discounts.
			$line_total = (float) $item->get_total();

			$items[] = array(
				'name'     => $item->get_name(),
				'value'    => round( $line_total / $quantity, 2 ),
				'quantity' => (string) $quantity,
			);
		}

		return $items;
	}

	/**
	 * Assess a Store API / block checkout token against the checkout threshold.
	 *
	 * The token is supplied by the block integration (there is no posted field),
	 * and transaction data is built from the order. After this returns, callers
	 * read get_last_assessment_name() and get_last_fraud_risk() to record and act
	 * on the Transaction defense verdict.
	 *
	 * @param string   $token Submitted reCAPTCHA token.
	 * @param WC_Order $order Order being checked out.
	 * @return true|WP_Error True on success (or fail-open skip), WP_Error to block.
	 */
	public function assess_checkout_token( $token, $order ) {
		$event_extra = $this->build_checkout_event_extra_from_order( $order );

		return $this->verify_token( 'checkout', 'checkout', $event_extra, null, $token );
	}

	/**
	 * Transaction risk from the most recent Enterprise assessment.
	 *
	 * @return float|null transactionRisk (0..1, higher is riskier), or null when
	 *                    Transaction defense returned no verdict.
	 */
	public function get_last_fraud_risk() {
		if ( null === $this->last_fraud_assessment || ! isset( $this->last_fraud_assessment['transactionRisk'] ) ) {
			return null;
		}

		return floatval( $this->last_fraud_assessment['transactionRisk'] );
	}

	/**
	 * Build the transactionData.user block for the payer.
	 *
	 * @return array User fields keyed for the assessment API, or empty.
	 */
	private function build_transaction_user() {
		$user  = array();
		$email = $this->posted_field( 'billing_email' );

		if ( '' !== $email ) {
			$user['email'] = $email;
		}

		if ( is_user_logged_in() ) {
			$current = wp_get_current_user();
			$user['accountId']     = (string) $current->ID;
			$user['emailVerified'] = true;

			$registered = strtotime( $current->user_registered );
			if ( $registered ) {
				$user['creationMs'] = (string) ( $registered * 1000 );
			}
		}

		return $user;
	}

	/**
	 * Build the transactionData.items list from the WooCommerce cart.
	 *
	 * @return array List of item arrays keyed for the assessment API.
	 */
	private function build_transaction_items() {
		$items = array();

		foreach ( WC()->cart->get_cart() as $cart_item ) {
			$product  = isset( $cart_item['data'] ) ? $cart_item['data'] : null;
			$quantity = isset( $cart_item['quantity'] ) ? (int) $cart_item['quantity'] : 0;

			if ( ! $product || $quantity < 1 ) {
				continue;
			}

			// Per-item price after line discounts.
			$line_total = isset( $cart_item['line_total'] ) ? (float) $cart_item['line_total'] : 0.0;

			$items[] = array(
				'name'     => $product->get_name(),
				'value'    => $quantity > 0 ? round( $line_total / $quantity, 2 ) : 0.0,
				'quantity' => (string) $quantity,
			);
		}

		return $items;
	}

	/**
	 * Act on the Transaction defense verdict captured during the assessment.
	 *
	 * Logs the transaction risk, hands the assessment name to the annotation
	 * layer via the WooCommerce session (the order does not exist yet), and,
	 * when enabled, blocks orders whose risk meets the configured threshold.
	 *
	 * @param WP_Error $errors WooCommerce checkout validation errors object.
	 */
	private function process_fraud_prevention( $errors ) {
		if ( null === $this->last_fraud_assessment ) {
			return;
		}

		$risk = isset( $this->last_fraud_assessment['transactionRisk'] )
			? floatval( $this->last_fraud_assessment['transactionRisk'] )
			: null;

		// Carry the assessment name and risk to the order via the session so the
		// annotation layer can label the outcome once the order is created.
		if ( '' !== $this->last_assessment_name && function_exists( 'WC' ) && WC()->session ) {
			WC()->session->set( 'gswp_assessment_name', $this->last_assessment_name );
			if ( null !== $risk ) {
				WC()->session->set( 'gswp_transaction_risk', $risk );
			}
		}

		if ( null === $risk ) {
			return;
		}

		// The per-order risk is already recorded as an order note, so the routine
		// case stays out of the log. Only blocked checkouts are logged below;
		// every assessment is logged when verbose logging is enabled.
		if ( '1' === get_option( 'gswp_verbose_logging', '0' ) ) {
			$this->log( sprintf( 'Transaction defense risk %.2f for assessment %s.', $risk, $this->last_assessment_name ) );
		}

		// Optional, opt-in blocking. transactionRisk is a fraud probability:
		// closer to 1.0 is riskier, so block when it meets the threshold.
		if ( '1' === get_option( 'gswp_txn_block', '0' ) ) {
			$threshold = floatval( get_option( 'gswp_threshold_txn', '0.8' ) );
			if ( $risk >= $threshold ) {
				$this->log( sprintf( 'Transaction defense blocked checkout: risk %.2f >= threshold %.2f (assessment %s).', $risk, $threshold, $this->last_assessment_name ) );

				/**
				 * A high-risk checkout was blocked. Fires alongside the log line so
				 * the admin email-alert layer (and any third-party listener) can act
				 * on it without touching this class.
				 */
				do_action( 'gswp_checkout_blocked', $risk, $threshold, $this->build_blocked_checkout_context() );

				$errors->add(
					'recaptcha_transaction_risk',
					__( '<strong>Error:</strong> This transaction was flagged as high risk and cannot be completed. Please contact us if you believe this is a mistake.', 'google-security-for-wordpress' )
				);
			}
		}
	}

	/**
	 * Build the context passed with the gswp_checkout_blocked action for a
	 * classic checkout, read from the posted billing fields and the cart.
	 *
	 * WooCommerce verifies the checkout nonce before this runs, so the posted
	 * fields are trusted here.
	 *
	 * @return array
	 */
	private function build_blocked_checkout_context() {
		// phpcs:disable WordPress.Security.NonceVerification.Missing
		$email = isset( $_POST['billing_email'] ) ? sanitize_email( wp_unslash( $_POST['billing_email'] ) ) : '';
		$first = isset( $_POST['billing_first_name'] ) ? sanitize_text_field( wp_unslash( $_POST['billing_first_name'] ) ) : '';
		$last  = isset( $_POST['billing_last_name'] ) ? sanitize_text_field( wp_unslash( $_POST['billing_last_name'] ) ) : '';
		// phpcs:enable WordPress.Security.NonceVerification.Missing

		$total    = '';
		$currency = '';
		if ( function_exists( 'WC' ) && WC()->cart ) {
			$total = (string) WC()->cart->get_total( 'edit' );
		}
		if ( function_exists( 'get_woocommerce_currency' ) ) {
			$currency = get_woocommerce_currency();
		}

		return array(
			'source'        => 'classic',
			'assessment'    => $this->last_assessment_name,
			'billing_email' => $email,
			'billing_name'  => trim( $first . ' ' . $last ),
			'total'         => $total,
			'currency'      => $currency,
		);
	}

	/**
	 * Resource name of the most recent Enterprise assessment.
	 *
	 * @return string Assessment name, or '' when none was created this request.
	 */
	public function get_last_assessment_name() {
		return $this->last_assessment_name;
	}

	/**
	 * Threshold context of the most recent verify_token() call.
	 *
	 * @return string Context (e.g. 'wp_register'), or '' when none ran yet.
	 */
	public function get_last_context() {
		return $this->last_context;
	}

	/**
	 * Account Defender labels from the most recent Enterprise assessment.
	 *
	 * @return string[] Label strings (e.g. SUSPICIOUS_LOGIN_ACTIVITY), or empty.
	 */
	public function get_last_account_labels() {
		if ( null === $this->last_account_assessment || empty( $this->last_account_assessment['labels'] ) ) {
			return array();
		}

		return array_values( (array) $this->last_account_assessment['labels'] );
	}

	/**
	 * Build the Account Defender userInfo block for a login/registration event.
	 *
	 * Returns an empty array unless Account Defender is enabled, an Enterprise
	 * key is configured, the context is a login or registration assessment, and
	 * an identifier was supplied. Only an opaque, salted account hash is sent —
	 * never the raw email, username, or phone number.
	 *
	 * @param string $context            Assessment context.
	 * @param mixed  $account_identifier WP_User, user ID, login, or email.
	 * @return array { userInfo: array } or empty array.
	 */
	private function build_account_user_info( $context, $account_identifier ) {
		if ( null === $account_identifier ) {
			return array();
		}
		if ( 'enterprise' !== get_option( 'gswp_key_type', 'classic' ) ) {
			return array();
		}
		if ( '1' !== get_option( 'gswp_account_defender', '0' ) ) {
			return array();
		}

		// Account Defender applies to account access and account-modification
		// events, not checkout: logins/registrations (the front door) plus lost
		// password, password reset, and profile/account updates (the actions a
		// takeover performs once inside).
		$account_contexts = array(
			'login',
			'registration',
			'wp_login',
			'wp_register',
			'wp_lostpassword',
			'password_reset',
			'account_update',
		);
		if ( ! in_array( $context, $account_contexts, true ) ) {
			return array();
		}

		list( $account_id, $created ) = $this->resolve_account_id( $account_identifier );
		if ( '' === $account_id ) {
			return array();
		}

		$user_info = array( 'accountId' => $account_id );

		// createAccountTime is a strong signal for account-takeover and
		// fake-signup detection when the account already exists.
		if ( $created > 0 ) {
			$user_info['createAccountTime'] = gmdate( 'Y-m-d\TH:i:s\Z', $created );
		}

		// Opt-in: also send the raw email as a userIds entry. Google recommends
		// this for markedly better detection (it can normalize provider aliasing
		// itself), at the cost of sharing the address rather than only a hash.
		if ( '1' === get_option( 'gswp_ad_share_email', '0' ) ) {
			$email = $this->resolve_identifier_email( $account_identifier );
			if ( '' !== $email ) {
				$user_info['userIds'] = array( array( 'email' => $email ) );
			}
		}

		return array( 'userInfo' => $user_info );
	}

	/**
	 * Resolve an account identifier to its email address, when one is known.
	 *
	 * @param mixed $identifier WP_User, user ID, login, or email.
	 * @return string Lowercased email, or '' when none can be resolved.
	 */
	private function resolve_identifier_email( $identifier ) {
		if ( is_string( $identifier ) && is_email( $identifier ) ) {
			return strtolower( trim( $identifier ) );
		}

		$user = null;
		if ( $identifier instanceof WP_User ) {
			$user = $identifier;
		} elseif ( is_numeric( $identifier ) ) {
			$user = get_user_by( 'id', (int) $identifier );
		} elseif ( is_string( $identifier ) && '' !== $identifier ) {
			$user = get_user_by( 'login', $identifier );
		}

		if ( $user instanceof WP_User && is_email( $user->user_email ) ) {
			return strtolower( $user->user_email );
		}

		return '';
	}

	/**
	 * Resolve an identifier to a stable, opaque account hash.
	 *
	 * Existing users are keyed by their immutable user ID so the same account
	 * maps to the same hash across logins regardless of whether they signed in
	 * with a username or email. A not-yet-created account (registration) is
	 * keyed by its normalised email.
	 *
	 * @param mixed $identifier WP_User, user ID, login, or email.
	 * @return array{0:string,1:int} [ account hash, account creation epoch seconds ].
	 */
	private function resolve_account_id( $identifier ) {
		$user = null;

		if ( $identifier instanceof WP_User ) {
			$user = $identifier;
		} elseif ( is_numeric( $identifier ) ) {
			$user = get_user_by( 'id', (int) $identifier );
		} elseif ( is_string( $identifier ) && '' !== $identifier ) {
			$user = get_user_by( 'login', $identifier );
			if ( ! $user && is_email( $identifier ) ) {
				$user = get_user_by( 'email', $identifier );
			}
		}

		if ( $user instanceof WP_User ) {
			$created = strtotime( $user->user_registered . ' UTC' );
			return array( $this->hash_account( 'id:' . $user->ID ), $created ? (int) $created : 0 );
		}

		// No existing account: key registrations by their normalised email.
		if ( is_string( $identifier ) && is_email( $identifier ) ) {
			return array( $this->hash_account( 'email:' . $this->normalize_email_identifier( $identifier ) ), 0 );
		}

		if ( is_string( $identifier ) && '' !== $identifier ) {
			return array( $this->hash_account( 'login:' . strtolower( $identifier ) ), 0 );
		}

		return array( '', 0 );
	}

	/**
	 * Normalize an email for identity hashing, collapsing Gmail aliasing.
	 *
	 * Gmail ignores dots in the local part and anything after a plus sign, and
	 * googlemail.com is the same inbox as gmail.com — the classic "dot-trick"
	 * lets one inbox register with endless unique-looking addresses. Collapsing
	 * those variants before hashing means every alias of one inbox maps to the
	 * same opaque accountId, so Account Defender can cluster repeat signups.
	 * Other providers only get lowercasing (dot/plus semantics vary elsewhere).
	 *
	 * @param string $email Raw submitted email.
	 * @return string Normalized email.
	 */
	private function normalize_email_identifier( $email ) {
		$email = strtolower( trim( $email ) );

		$at = strrpos( $email, '@' );
		if ( false === $at ) {
			return $email;
		}

		$local  = substr( $email, 0, $at );
		$domain = substr( $email, $at + 1 );

		if ( 'googlemail.com' === $domain ) {
			$domain = 'gmail.com';
		}

		if ( 'gmail.com' === $domain ) {
			$plus = strpos( $local, '+' );
			if ( false !== $plus ) {
				$local = substr( $local, 0, $plus );
			}
			$local = str_replace( '.', '', $local );
		}

		return $local . '@' . $domain;
	}

	/**
	 * Hash an identifier with a stable site-specific salt.
	 *
	 * The salt is generated once and stored, so the same account always yields
	 * the same opaque hash without exposing any personal data to Google.
	 *
	 * @param string $value Pre-namespaced identifier (e.g. "id:42").
	 * @return string 64-char hex hash.
	 */
	private function hash_account( $value ) {
		$salt = get_option( 'gswp_account_salt', '' );
		if ( '' === $salt ) {
			$salt = wp_generate_password( 64, true, true );
			update_option( 'gswp_account_salt', $salt, false );
		}

		return hash( 'sha256', $salt . '|' . $value );
	}

	/**
	 * Get the visitor IP for the verification request.
	 *
	 * @return string Remote IP address.
	 */
	private function get_remote_ip() {
		return GSWP_Client_IP::get();
	}

	/**
	 * Log a verification warning to the WooCommerce logger when available.
	 *
	 * @param string $message Log message.
	 */
	private function log( $message ) {
		GSWP_Log::warning( $message );
	}
}
