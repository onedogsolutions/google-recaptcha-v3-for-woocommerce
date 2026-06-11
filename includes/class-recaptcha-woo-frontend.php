<?php
/**
 * Frontend Class
 *
 * Handles public enqueuing of the Google reCAPTCHA scripts and form hidden inputs.
 *
 * @package Google_Recaptcha_V3_For_WooCommerce
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Recaptcha_Woo_Frontend {

	/**
	 * Constructor.
	 */
	public function __construct() {
		add_action( 'wp_enqueue_scripts', array( $this, 'register_scripts' ) );

		// Check if forms are enabled and hook accordingly.
		if ( '1' === get_option( 'recaptcha_woo_enable_login', '0' ) ) {
			add_action( 'woocommerce_login_form_end', array( $this, 'inject_login_field' ) );
		}

		if ( '1' === get_option( 'recaptcha_woo_enable_registration', '0' ) ) {
			add_action( 'woocommerce_register_form_end', array( $this, 'inject_registration_field' ) );
		}

		if ( '1' === get_option( 'recaptcha_woo_enable_checkout', '0' ) ) {
			add_action( 'woocommerce_review_order_before_submit', array( $this, 'inject_checkout_field' ) );
		}
	}

	/**
	 * Register the Google reCAPTCHA v3 script.
	 */
	public function register_scripts() {
		$site_key = get_option( 'recaptcha_woo_site_key', '' );
		if ( empty( $site_key ) ) {
			return;
		}

		// Enterprise site keys must load enterprise.js; classic v3 keys use api.js.
		$script_base = 'enterprise' === get_option( 'recaptcha_woo_key_type', 'classic' )
			? 'https://www.google.com/recaptcha/enterprise.js'
			: 'https://www.google.com/recaptcha/api.js';

		// Register Google API script (jQuery dependency guarantees ordering for our inline bootstrap).
		wp_register_script(
			'google-recaptcha-v3',
			$script_base . '?render=' . rawurlencode( $site_key ),
			array( 'jquery' ),
			RECAPTCHA_WOO_VERSION,
			true
		);
	}

	/**
	 * Inject the hidden field for the login form.
	 */
	public function inject_login_field() {
		$this->inject_recaptcha_field( 'login' );
	}

	/**
	 * Inject the hidden field for the registration form.
	 */
	public function inject_registration_field() {
		$this->inject_recaptcha_field( 'register' );
	}

	/**
	 * Inject the hidden field for the checkout form.
	 */
	public function inject_checkout_field() {
		$this->inject_recaptcha_field( 'checkout' );
	}

	/**
	 * Inject hidden reCAPTCHA response fields into the form.
	 *
	 * @param string $action The reCAPTCHA action name for this form.
	 */
	public function inject_recaptcha_field( $action ) {
		$site_key = get_option( 'recaptcha_woo_site_key', '' );
		if ( empty( $site_key ) ) {
			return;
		}

		// Ensure the API script is enqueued and our bootstrap is attached once.
		// The inline script rides on the main page footer, so it is never
		// duplicated when WooCommerce re-renders this field inside AJAX
		// checkout fragments.
		wp_enqueue_script( 'google-recaptcha-v3' );

		static $js_attached = false;
		if ( ! $js_attached ) {
			wp_add_inline_script( 'google-recaptcha-v3', $this->get_inline_js( $site_key ) );
			$js_attached = true;
		}

		// Print the hidden input field.
		printf(
			'<input type="hidden" name="g-recaptcha-response" class="g-recaptcha-response" data-recaptcha-action="%s" value="" />',
			esc_attr( $action )
		);
	}

	/**
	 * Build the inline JavaScript that keeps a fresh token in every field.
	 *
	 * Tokens are fetched proactively on page load and refreshed before the
	 * two-minute expiry, so submissions triggered by third-party scripts
	 * (Stripe, PayPal smart buttons, express checkout flows) always carry a
	 * valid token even when they bypass the standard submit events.
	 *
	 * @param string $site_key The reCAPTCHA site key.
	 * @return string Inline JavaScript.
	 */
	private function get_inline_js( $site_key ) {
		$is_enterprise = 'enterprise' === get_option( 'recaptcha_woo_key_type', 'classic' );

		ob_start();
		?>
		(function($) {
			'use strict';

			if (window.recaptchaWooInit) {
				return;
			}
			window.recaptchaWooInit = true;

			var siteKey = <?php echo wp_json_encode( $site_key ); ?>;
			var isEnterprise = <?php echo $is_enterprise ? 'true' : 'false'; ?>;
			// reCAPTCHA v3 tokens expire after 120 seconds; refresh before that.
			var REFRESH_INTERVAL = 100 * 1000;

			function api() {
				if (typeof grecaptcha === 'undefined') {
					return null;
				}
				return isEnterprise ? grecaptcha.enterprise : grecaptcha;
			}

			function fetchToken($input) {
				var client = api();
				var deferred = $.Deferred();

				if (!client || !$input.length) {
					return deferred.reject().promise();
				}

				client.ready(function() {
					client.execute(siteKey, { action: $input.data('recaptchaAction') || 'submit' }).then(
						function(token) {
							$input.val(token);
							deferred.resolve(token);
						},
						function() {
							deferred.reject();
						}
					);
				});

				return deferred.promise();
			}

			function refreshAll() {
				$('.g-recaptcha-response').each(function() {
					fetchToken($(this));
				});
			}

			$(function() {
				refreshAll();

				setInterval(function() {
					if (!document.hidden) {
						refreshAll();
					}
				}, REFRESH_INTERVAL);

				// Tokens go stale while the tab is in the background.
				document.addEventListener('visibilitychange', function() {
					if (!document.hidden) {
						refreshAll();
					}
				});

				// WooCommerce replaces the payment fragment (and our hidden
				// input) whenever the order review updates.
				$(document.body).on('updated_checkout', refreshAll);

				// Tokens are single use: a failed checkout attempt consumed
				// the current one, so clear it and fetch a replacement.
				$(document.body).on('checkout_error', function() {
					$('form.woocommerce-checkout .g-recaptcha-response').val('');
					refreshAll();
				});

				// Fallback: intercept standard form submits (Login, Register)
				// if the token is somehow still missing.
				$(document).on('submit', 'form.login, form.register', function(e) {
					var $form = $(this);
					var $input = $form.find('.g-recaptcha-response');

					if ($input.length && !$input.val() && api()) {
						e.preventDefault();
						fetchToken($input).always(function() {
							$form.trigger('submit');
						});
					}
				});

				// Fallback: intercept the WooCommerce checkout AJAX submission.
				$(document.body).on('checkout_place_order', function() {
					var $form = $('form.woocommerce-checkout');
					var $input = $form.find('.g-recaptcha-response');

					if ($input.length && !$input.val() && api()) {
						fetchToken($input).always(function() {
							$form.trigger('submit');
						});
						return false;
					}
					return true;
				});
			});
		})(jQuery);
		<?php
		return ob_get_clean();
	}
}
