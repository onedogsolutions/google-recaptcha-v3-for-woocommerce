<?php
/**
 * reCAPTCHA Loader Ownership
 *
 * Single owner of the Google reCAPTCHA API script on the front end. Google
 * documents reCAPTCHA as one-load-per-page; before this class the plugin
 * registered the same handle from three places and had no idea whether another
 * plugin was also loading it, which produced duplicate loaders and — via the
 * Conflict Guard — suppression of other plugins' reCAPTCHA on payment pages.
 *
 * Responsibilities:
 *  1. Register this plugin's loader exactly once (replacing the duplicated
 *     registration logic in GSWP_Assets, GSWP_Frontend and
 *     GSWP_Blocks_Integration).
 *  2. Detect third-party reCAPTCHA loaders generically, by matching the script
 *     src and parsing its `render=` site key. No knowledge of any other
 *     plugin's option keys or script handles is required, so this works for
 *     Gravity Forms, WPForms, Elementor, Fluent Forms, CF7 and anything else.
 *  3. Deduplicate at render time: when several tags would load reCAPTCHA with
 *     the same site key, only the first is emitted. Both plugins then share one
 *     `grecaptcha` global.
 *  4. Report divergent site keys, which cannot be resolved automatically —
 *     two Enterprise keys cannot both be pre-rendered via `?render=`.
 *  5. Print the token-refresh bootstrap from the footer rather than attaching
 *     it to our own script handle, so it survives our tag being deduplicated.
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class GSWP_Recaptcha_Loader {

	/**
	 * Script handle for the Google reCAPTCHA API.
	 */
	const HANDLE = 'google-recaptcha-v3';

	/**
	 * Transient recording third-party loaders observed on the front end, so the
	 * admin screens (which never see a front-end enqueue) can warn about them.
	 */
	const CONFLICT_TRANSIENT = 'gswp_foreign_recaptcha';

	/**
	 * Source fragments that identify a Google reCAPTCHA loader.
	 *
	 * @var string[]
	 */
	private static $src_needles = array(
		'google.com/recaptcha',
		'recaptcha.net/recaptcha',
		'gstatic.com/recaptcha',
	);

	/**
	 * Site keys already emitted on this request, keyed by site key. Used to drop
	 * duplicate loaders for the same key at render time.
	 *
	 * @var array<string,bool>
	 */
	private static $emitted_keys = array();

	/**
	 * Whether a caller has asked for the token-refresh bootstrap this request.
	 *
	 * @var bool
	 */
	private static $bootstrap_requested = false;

	/**
	 * Whether the bootstrap has been printed this request.
	 *
	 * @var bool
	 */
	private static $bootstrap_printed = false;

	/**
	 * Cached third-party loader scan for this request.
	 *
	 * @var array|null
	 */
	private static $foreign_cache = null;

	/**
	 * Site key observed being loaded by both API families this request, or ''.
	 *
	 * @var string
	 */
	private static $family_conflict = '';

	/**
	 * Wire the render-time hooks. Called once from the plugin bootstrap.
	 */
	public static function init() {
		// Priority 5: run before GSWP_Conflict_Guard (priority 10) so a
		// deduplicated tag never reaches the suppression logic.
		add_filter( 'script_loader_tag', array( __CLASS__, 'filter_tag' ), 5, 3 );

		// Print the token bootstrap after all scripts, independent of whether
		// our own loader tag survived deduplication.
		add_action( 'wp_print_footer_scripts', array( __CLASS__, 'print_bootstrap' ), 20 );

		// The same bootstrap is needed in wp-admin for screens such as the
		// user profile "Send Reset Link" button.
		add_action( 'admin_print_footer_scripts', array( __CLASS__, 'print_bootstrap' ), 20 );

		// Record third-party loaders for the admin warning surfaces.
		add_action( 'wp_footer', array( __CLASS__, 'record_conflicts' ), 99 );
	}

	/**
	 * Configured reCAPTCHA site key.
	 *
	 * @return string Site key, or empty string when unset.
	 */
	public static function site_key() {
		return (string) get_option( 'gswp_site_key', '' );
	}

	/**
	 * Whether the Enterprise key type is configured.
	 *
	 * @return bool True for Enterprise, false for classic v3.
	 */
	public static function is_enterprise() {
		return 'enterprise' === get_option( 'gswp_key_type', 'classic' );
	}

	/**
	 * Whether this plugin will be able to populate a token field.
	 *
	 * The single predicate shared by field printing and server-side token
	 * enforcement. It depends only on stored options — never on page state —
	 * so the render request (GET) and the validation request (POST) always
	 * reach the same answer. Deciding enforcement from anything request-scoped
	 * would let a caller opt out by omitting a field, which is the class of
	 * hole removed in 2.17.0.
	 *
	 * @return bool True when a site key is configured.
	 */
	public static function will_load() {
		return '' !== self::site_key();
	}

	/**
	 * Full URL of this plugin's reCAPTCHA loader.
	 *
	 * @return string Loader URL, or '' when no site key is configured.
	 */
	public static function loader_src() {
		$site_key = self::site_key();
		if ( '' === $site_key ) {
			return '';
		}

		$base = self::is_enterprise()
			? 'https://www.google.com/recaptcha/enterprise.js'
			: 'https://www.google.com/recaptcha/api.js';

		return $base . '?render=' . rawurlencode( $site_key );
	}

	/**
	 * Register this plugin's loader script. Idempotent.
	 *
	 * The handle is always registered with its src so the dependency graph
	 * resolves — GSWP_Blocks_Integration lists it as a dependency, and
	 * WordPress silently refuses to enqueue a script whose dependency is
	 * unregistered. Whether the tag is actually emitted is decided later, at
	 * render time, by filter_tag().
	 *
	 * @return bool True when the handle is available, false when unconfigured.
	 */
	public static function ensure_registered() {
		if ( ! self::will_load() ) {
			return false;
		}

		if ( ! wp_script_is( self::HANDLE, 'registered' ) ) {
			wp_register_script( self::HANDLE, self::loader_src(), array(), GSWP_VERSION, true );
		}

		return true;
	}

	/**
	 * Register and enqueue the loader, and request the token bootstrap.
	 *
	 * @return bool True when enqueued, false when no site key is configured.
	 */
	public static function enqueue() {
		if ( ! self::ensure_registered() ) {
			return false;
		}

		wp_enqueue_script( self::HANDLE );
		self::$bootstrap_requested = true;

		return true;
	}

	/**
	 * Ask for the token-refresh bootstrap to be printed in the footer.
	 */
	public static function request_bootstrap() {
		self::$bootstrap_requested = true;
	}

	/**
	 * Whether a script src loads Google reCAPTCHA.
	 *
	 * @param string $src Script source URL.
	 * @return bool True when the src is a reCAPTCHA loader.
	 */
	public static function is_recaptcha_src( $src ) {
		if ( empty( $src ) ) {
			return false;
		}

		foreach ( self::$src_needles as $needle ) {
			if ( false !== strpos( $src, $needle ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Which reCAPTCHA API family a loader belongs to.
	 *
	 * `api.js` (classic) and `enterprise.js` are different APIs that happen to
	 * accept the same site key. Classic defines `grecaptcha` only; Enterprise
	 * callers need `grecaptcha.enterprise`. Treating them as interchangeable
	 * because their `render=` matches is how a page ends up with one script and
	 * two consumers, one of which is calling a namespace that was never loaded.
	 *
	 * @param string $src Script source URL.
	 * @return string 'enterprise', 'classic', or '' when not a reCAPTCHA loader.
	 */
	public static function family_from_src( $src ) {
		if ( ! self::is_recaptcha_src( $src ) ) {
			return '';
		}

		return false !== stripos( (string) $src, '/enterprise.js' ) ? 'enterprise' : 'classic';
	}

	/**
	 * Extract the site key a reCAPTCHA loader pre-renders.
	 *
	 * @param string $src Script source URL.
	 * @return string Site key from the `render` parameter, or '' when absent
	 *                (e.g. an explicit-render loader carrying no key).
	 */
	public static function key_from_src( $src ) {
		if ( empty( $src ) ) {
			return '';
		}

		$query = wp_parse_url( $src, PHP_URL_QUERY );
		if ( empty( $query ) ) {
			return '';
		}

		$args = array();
		wp_parse_str( $query, $args );

		if ( empty( $args['render'] ) || 'explicit' === $args['render'] ) {
			return '';
		}

		return (string) $args['render'];
	}

	/**
	 * Third-party reCAPTCHA loaders registered on this request.
	 *
	 * @return array List of [ 'handle', 'src', 'key' ] for non-GSWP loaders.
	 */
	public static function foreign_loaders() {
		if ( null !== self::$foreign_cache ) {
			return self::$foreign_cache;
		}

		$found = array();
		$wp_scripts = wp_scripts();

		if ( $wp_scripts && ! empty( $wp_scripts->registered ) ) {
			foreach ( $wp_scripts->registered as $handle => $script ) {
				if ( self::HANDLE === $handle ) {
					continue;
				}

				$src = isset( $script->src ) ? (string) $script->src : '';
				if ( ! self::is_recaptcha_src( $src ) ) {
					continue;
				}

				$found[] = array(
					'handle' => (string) $handle,
					'src'    => $src,
					'key'    => self::key_from_src( $src ),
				);
			}
		}

		self::$foreign_cache = $found;

		return $found;
	}

	/**
	 * Third-party loaders configured with a site key different from ours.
	 *
	 * A loader carrying no `render` key is not a conflict: it pre-renders
	 * nothing and cannot collide with our key.
	 *
	 * @return array List of conflicting loaders, in foreign_loaders() shape.
	 */
	public static function conflicts() {
		$ours = self::site_key();
		if ( '' === $ours ) {
			return array();
		}

		$conflicts = array();
		foreach ( self::foreign_loaders() as $loader ) {
			if ( '' !== $loader['key'] && $loader['key'] !== $ours ) {
				$conflicts[] = $loader;
			}
		}

		return $conflicts;
	}

	/**
	 * Deduplicate reCAPTCHA loader tags at render time.
	 *
	 * When several tags would load reCAPTCHA with the same site key, only the
	 * first is emitted; the rest are dropped. Order does not matter — whichever
	 * tag prints first satisfies every consumer, because `grecaptcha` is a
	 * global. This is what fixes the original Gravity Forms / Stripe failure:
	 * with a shared key, our loader and theirs collapse into one and neither
	 * plugin is suppressed.
	 *
	 * Loaders carrying a *different* key are left alone here; resolving those
	 * is the Conflict Guard's business (and is reported as a conflict).
	 *
	 * @param string $tag    The full script tag.
	 * @param string $handle The script handle.
	 * @param string $src    The script source URL.
	 * @return string The tag, or '' when it duplicates an already-emitted key.
	 */
	public static function filter_tag( $tag, $handle, $src ) {
		if ( ! self::is_recaptcha_src( $src ) ) {
			return $tag;
		}

		$key = self::key_from_src( $src );

		// An explicit-render loader pre-renders no key and never duplicates.
		if ( '' === $key ) {
			return $tag;
		}

		// Deduplicate on key AND API family. Two tags for the same key are only
		// duplicates when they load the same script: `api.js` and
		// `enterprise.js` are different APIs. Collapsing them would leave one
		// consumer calling a namespace the surviving script never defined —
		// classic `api.js` defines `grecaptcha` but not `grecaptcha.enterprise`,
		// so an Enterprise caller would silently stop producing tokens.
		$family = self::family_from_src( $src );
		$slot   = $family . '|' . $key;

		if ( isset( self::$emitted_keys[ $slot ] ) ) {
			return '';
		}

		self::$emitted_keys[ $slot ] = true;

		// Same key, other family already emitted: both are needed, so neither is
		// dropped — but it is a misconfiguration worth reporting, because the
		// page now carries two reCAPTCHA scripts and one of the two plugins is
		// on the wrong integration type.
		$other = ( 'enterprise' === $family ? 'classic' : 'enterprise' ) . '|' . $key;
		if ( isset( self::$emitted_keys[ $other ] ) ) {
			self::$family_conflict = $key;
		}

		return $tag;
	}

	/**
	 * Whether a reCAPTCHA loader for our site key has already been emitted.
	 *
	 * @return bool
	 */
	public static function key_emitted() {
		$site_key = self::site_key();
		if ( '' === $site_key ) {
			return false;
		}

		return isset( self::$emitted_keys[ 'enterprise|' . $site_key ] )
			|| isset( self::$emitted_keys[ 'classic|' . $site_key ] );
	}

	/**
	 * Site key loaded by both API families on this request, if any.
	 *
	 * @return string
	 */
	public static function family_conflict() {
		return self::$family_conflict;
	}

	/**
	 * Persist observed third-party loaders so wp-admin can warn about them.
	 *
	 * Detection only happens on the front end, but the warning surfaces live in
	 * wp-admin. The transient bridges the two. It is only written when the
	 * observed set changes, so the common case costs one get_transient() per
	 * request and no write at all.
	 */
	public static function record_conflicts() {
		// Same key, both API families: not a key conflict, but a real one.
		if ( '' !== self::$family_conflict ) {
			GSWP_Log::error(
				'reCAPTCHA integration-type conflict: site key '
				. self::mask_key( self::$family_conflict )
				. ' is being loaded as BOTH classic (api.js) and Enterprise (enterprise.js) on the same page. '
				. 'Both scripts are being kept because they are different APIs, but one of the plugins involved is '
				. 'configured with the wrong integration type. Set them both to the same type.'
			);
		}

		$conflicts = self::conflicts();

		if ( empty( $conflicts ) ) {
			if ( false !== get_transient( self::CONFLICT_TRANSIENT ) ) {
				delete_transient( self::CONFLICT_TRANSIENT );
			}
			return;
		}

		$suppressing = self::is_suppressing();

		$record = array(
			'hash'        => self::conflict_hash( $conflicts, $suppressing ),
			'suppressing' => $suppressing,
			'observed'    => time(),
			'loaders'     => array(),
		);

		foreach ( $conflicts as $loader ) {
			$record['loaders'][] = array(
				'handle' => $loader['handle'],
				'key'    => self::mask_key( $loader['key'] ),
				'src'    => esc_url_raw( $loader['src'] ),
			);
		}

		$stored = get_transient( self::CONFLICT_TRANSIENT );
		if ( is_array( $stored ) && isset( $stored['hash'] ) && $stored['hash'] === $record['hash'] ) {
			return;
		}

		set_transient( self::CONFLICT_TRANSIENT, $record, 7 * DAY_IN_SECONDS );

		self::log_conflict( $record );
	}

	/**
	 * Whether the Conflict Guard is currently suppressing a divergent loader.
	 *
	 * This is the Critical state: another plugin's reCAPTCHA is being removed
	 * from pages, so its forms — including payment forms — may be failing.
	 *
	 * @return bool
	 */
	public static function is_suppressing() {
		// Since 2.18.1 only 'site' mode removes anything. 'off' and 'active' are
		// both non-destructive: matching keys are shared, divergent ones are
		// reported. So the Critical state can now only arise when an operator
		// has deliberately opted into suppression.
		return 'site' === get_option( 'gswp_conflict_mode', 'off' );
	}

	/**
	 * Stable hash identifying a conflict state, so a dismissed admin notice
	 * re-arms when the conflict changes rather than staying dismissed forever.
	 *
	 * @param array $conflicts   Conflicting loaders.
	 * @param bool  $suppressing Whether suppression is active.
	 * @return string
	 */
	public static function conflict_hash( $conflicts, $suppressing ) {
		$parts = array( $suppressing ? 'suppressing' : 'observing' );

		foreach ( $conflicts as $loader ) {
			$parts[] = $loader['handle'] . '|' . $loader['key'];
		}

		sort( $parts );

		return substr( hash( 'sha256', implode( ',', $parts ) ), 0, 16 );
	}

	/**
	 * Mask a site key for display, keeping enough to identify it.
	 *
	 * @param string $key Site key.
	 * @return string Masked key.
	 */
	public static function mask_key( $key ) {
		$key = (string) $key;
		if ( strlen( $key ) <= 10 ) {
			return $key;
		}

		return substr( $key, 0, 6 ) . '…' . substr( $key, -4 );
	}

	/**
	 * The stored conflict record, for the admin warning surfaces.
	 *
	 * @return array|null Record, or null when no conflict has been observed.
	 */
	public static function stored_conflict() {
		$stored = get_transient( self::CONFLICT_TRANSIENT );

		return is_array( $stored ) ? $stored : null;
	}

	/**
	 * Log a newly observed conflict.
	 *
	 * Logged at error level when suppression is active — another plugin's
	 * reCAPTCHA is being removed and its forms may be failing right now.
	 *
	 * @param array $record Conflict record.
	 */
	private static function log_conflict( $record ) {
		$handles = array();
		foreach ( $record['loaders'] as $loader ) {
			$handles[] = $loader['handle'] . ' (key ' . $loader['key'] . ')';
		}

		$message = $record['suppressing']
			? 'reCAPTCHA loader conflict: suppressing third-party loader(s) configured with a DIFFERENT site key — '
				. implode( ', ', $handles )
				. '. Those plugins\' forms, including payment forms, may fail. Change reCAPTCHA Conflict Handling to Disabled, or align the site keys.'
			: 'reCAPTCHA loader conflict: third-party loader(s) configured with a different site key detected — '
				. implode( ', ', $handles )
				. '. Two reCAPTCHA site keys cannot both be pre-rendered on one page; one of them will fail to execute.';

		if ( $record['suppressing'] ) {
			GSWP_Log::error( $message );
		} else {
			GSWP_Log::warning( $message );
		}
	}

	/**
	 * Print the token-refresh bootstrap in the footer.
	 *
	 * Printed directly rather than attached to our script handle with
	 * wp_add_inline_script(): our tag may be deduplicated away, and an inline
	 * script attached to an unregistered handle is silently dropped — one of
	 * the failure modes behind the 2.16.0 "verification token is missing"
	 * outage. Guarded on `grecaptcha` with a bounded poll so it works whichever
	 * plugin's loader tag actually won.
	 */
	public static function print_bootstrap() {
		if ( self::$bootstrap_printed || ! self::$bootstrap_requested ) {
			return;
		}
		if ( ! self::will_load() ) {
			return;
		}

		self::$bootstrap_printed = true;

		printf(
			'<script>%s</script>',
			self::get_bootstrap_js() // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- JSON-encoded values, no HTML.
		);
	}

	/**
	 * Build the token-refresh bootstrap JavaScript.
	 *
	 * Keeps every `.g-recaptcha-response` field on the page populated with a
	 * fresh token: fetched on load, refreshed before the two-minute expiry, on
	 * tab refocus, on a bfcache restore, whenever a matching field is added to
	 * the DOM, and — since 2.22.1 — immediately after any submission that spent
	 * one. Covers WooCommerce checkout fragment replacement and AJAX login
	 * popups, and intercepts standard login/register submits as a last resort.
	 *
	 * INVARIANT: a token field is never observably empty once it has been
	 * populated. Tokens are replaced in place (the new value is assigned only
	 * when it resolves), never cleared first. A form that takes payment or
	 * creates an account fails CLOSED on a missing token, so a blank field
	 * during a refresh round trip would reject a live payment outright. The
	 * degraded case is a stale token and a soft "please try again"; it must
	 * never be a hard block. The one deliberate exception is
	 * clearCheckoutTokens(), which is scoped to the WooCommerce checkout form
	 * and paired with an immediate refresh.
	 *
	 * The constraint is NOT specific to one form plugin, though it was found
	 * through Gravity Forms. Every provider implementing GSWP_Form_Provider
	 * enforces the same asymmetry — see validate_submission() in
	 * GSWP_Provider_Gravity_Forms and GSWP_Provider_Fluent_Forms — so a site
	 * with no Gravity Forms is not a site where blanking becomes safe. Adding a
	 * provider adds a caller of this invariant, never an exemption from it.
	 *
	 * Vanilla JS with no jQuery dependency so script optimizers that delay
	 * jQuery cannot delay token generation; the jQuery bindings are a
	 * progressive enhancement when jQuery is present.
	 *
	 * @return string Inline JavaScript.
	 */
	private static function get_bootstrap_js() {
		$site_key      = self::site_key();
		$is_enterprise = self::is_enterprise();

		ob_start();
		?>
		(function() {
			'use strict';

			if (window.gswpInit) {
				return;
			}
			window.gswpInit = true;

			var siteKey = <?php echo wp_json_encode( $site_key ); ?>;
			var isEnterprise = <?php echo $is_enterprise ? 'true' : 'false'; ?>;
			// reCAPTCHA v3 tokens expire after 120 seconds; refresh before that.
			var REFRESH_INTERVAL = 100 * 1000;
			// Another plugin's loader may print after ours; poll briefly for it.
			var READY_POLL_MS = 100;
			var READY_TIMEOUT_MS = 10000;

			function api() {
				if (typeof grecaptcha === 'undefined') {
					return null;
				}
				return isEnterprise ? grecaptcha.enterprise : grecaptcha;
			}

			function fetchToken(input) {
				return new Promise(function(resolve, reject) {
					var client = api();

					if (!client || !input) {
						reject();
						return;
					}

					client.ready(function() {
						var action = input.getAttribute('data-recaptcha-action') || 'submit';
						client.execute(siteKey, { action: action }).then(
							function(token) {
								input.value = token;
								input.setAttribute('data-gswp-minted', String(Date.now()));
								resolve(token);
							},
							reject
						);
					});
				});
			}

			function noop() {}

			function refreshAll() {
				var inputs = document.querySelectorAll('.g-recaptcha-response');
				for (var i = 0; i < inputs.length; i++) {
					fetchToken(inputs[i]).catch(noop);
				}
			}

			// Replace one field's token in place. fetchToken() assigns only when
			// the new token resolves, so the field keeps the old (spent) value
			// until then and is never empty. See the INVARIANT note in PHP.
			function replaceToken(input) {
				if (input) {
					fetchToken(input).catch(noop);
				}
			}

			// The token that just left with a submission is spent: v3 tokens are
			// single use. Deferred a tick so the in-flight submission serializes
			// the current value first.
			function replaceAfterSubmit(input) {
				if (!input) {
					return;
				}
				window.setTimeout(function() {
					replaceToken(input);
				}, 0);
			}

			// A v3 token is valid for 120 seconds and the interval below
			// refreshes at 100, so a field older than that is one the interval
			// did not reach: a backgrounded tab or a locked phone, where timers
			// are suspended. That is how a ten-minute-old token reached a
			// checkout on 2026-08-26 and was scored 0.2.
			//
			// Reading the stamp never writes to the field. The INVARIANT above
			// still holds — a stale token is left in place and still submitted
			// if a fresh one cannot be fetched. Stale is a reason to try for a
			// better token, never a reason to block a payment.
			var MAX_TOKEN_AGE = REFRESH_INTERVAL;

			function isStale(input) {
				if (!input || !input.value) {
					return false;
				}

				var minted = parseInt(input.getAttribute('data-gswp-minted'), 10);

				// Populated but unstamped: not minted by this bootstrap on this
				// page load. Treat as stale and re-mint; the cost is one extra
				// token, and the alternative is submitting an unknown one.
				if (!minted) {
					return true;
				}

				return (Date.now() - minted) > MAX_TOKEN_AGE;
			}

			function tokenFieldIn(node) {
				return node && node.querySelector
					? node.querySelector('.g-recaptcha-response')
					: null;
			}

			// Coalesce bursts of DOM mutations into a single refresh.
			var refreshTimer = null;
			function queueRefresh() {
				if (refreshTimer) {
					return;
				}
				refreshTimer = setTimeout(function() {
					refreshTimer = null;
					refreshAll();
				}, 250);
			}

			function clearCheckoutTokens() {
				var inputs = document.querySelectorAll('form.woocommerce-checkout .g-recaptcha-response');
				for (var i = 0; i < inputs.length; i++) {
					inputs[i].value = '';
				}
			}

			function containsMatch(node, selector) {
				if (node.nodeType !== 1) {
					return false;
				}
				return (node.matches && node.matches(selector)) || !!node.querySelector(selector);
			}

			function start() {
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

				// A bfcache restore (back button) resurrects a page whose token
				// expired while it was frozen: timers were paused, so the
				// interval above never ran, and visibilitychange does not fire
				// for a page that was already visible when it was frozen.
				window.addEventListener('pageshow', function(e) {
					if (e.persisted) {
						refreshAll();
					}
				});

				// WooCommerce replaces the payment fragment (and our hidden
				// input) whenever the order review updates, and inserts a
				// notice group when a checkout attempt fails. Tokens are
				// single use, so a failed attempt also needs a replacement.
				// AJAX login popups inject their forms the same way.
				var observer = new MutationObserver(function(mutations) {
					for (var i = 0; i < mutations.length; i++) {
						var added = mutations[i].addedNodes;
						for (var j = 0; j < added.length; j++) {
							if (containsMatch(added[j], '.g-recaptcha-response')) {
								queueRefresh();
								return;
							}
							if (containsMatch(added[j], '.woocommerce-NoticeGroup-checkout, .woocommerce-error')) {
								clearCheckoutTokens();
								queueRefresh();
								return;
							}
						}
					}
				});
				observer.observe(document.body, { childList: true, subtree: true });

				// Two separate jobs on submit.
				//
				// 1. Last-resort fallback, unchanged: a standard (non-AJAX)
				//    login or register form carrying no token at all is held
				//    back until one arrives. Still scoped to those two
				//    selectors on purpose — preventDefault()ing an arbitrary
				//    form is not something to widen casually, and least of all
				//    a payment form. The native form.submit() does not re-fire
				//    this listener.
				//
				// 2. Replace the token the submission just spent. This is the
				//    only hook tied to a submission, and a submission is the
				//    only thing that spends a token: without it a form that
				//    stays in the DOM (any AJAX login form, e.g. the PowerPack
				//    or Xootix modules) resubmits the spent value and Google
				//    returns DUPE, which surfaces to the visitor as "Anti-spam
				//    verification expired" no matter what they type. Before
				//    2.22.1 the only recovery was the 100-second interval.
				document.addEventListener('submit', function(e) {
					var form = e.target;
					var input = tokenFieldIn(form);
					if (!input) {
						return;
					}

					if (!input.value && api() && form.matches
						&& form.matches('form.login, form.register')) {
						e.preventDefault();
						e.stopPropagation();
						var submit = function() {
							form.submit();
						};
						fetchToken(input).then(submit, submit);
						return;
					}

					replaceAfterSubmit(input);
				}, true);

				// Some modules submit from a click handler that calls
				// preventDefault(), so no submit event ever fires at all. Cover
				// those from the click instead.
				//
				// Deliberately NOT a global jQuery ajaxComplete hook: a Gravity
				// Forms page fires AJAX for multi-page navigation, conditional
				// logic, and the Stripe add-on's payment-intent calls, and
				// re-minting a token against a form that is mid-payment is not
				// something to do on every XHR that happens to complete.
				//
				// This also covers multi-page GF forms, where gform_validation
				// runs per page transition and therefore spends the token on
				// each "Next".
				document.addEventListener('click', function(e) {
					var target = e.target;
					if (!target || !target.closest) {
						return;
					}

					var control = target.closest('button, input[type="submit"], input[type="image"]');
					if (!control) {
						return;
					}

					replaceAfterSubmit(tokenFieldIn(control.closest('form')));
				}, true);

				// Progressive enhancement: when jQuery is present, also hook
				// WooCommerce's jQuery-only checkout events for immediate
				// refreshes and a last-resort veto on the place-order event.
				if (window.jQuery) {
					var $ = window.jQuery;

					$(document.body).on('updated_checkout', queueRefresh);

					$(document.body).on('checkout_error', function() {
						clearCheckoutTokens();
						queueRefresh();
					});

					// Suppression is keyed to FAILURE, not to every veto.
					//
					// fetchToken() resubmits on rejection as well as on success
					// — a reCAPTCHA outage must not strand a customer at a dead
					// Place order button — so a field that cannot be refreshed
					// would otherwise veto, resubmit, veto again, and spin. But
					// throttling every veto would break the case this hook was
					// written for: checkout_error blanks the field and queues a
					// refresh, and a customer who clicks again before that
					// lands needs the veto to fire, however recently it fired.
					//
					// So vetoes are free while tokens can be minted, and stop
					// only once minting has actually failed. The stale or empty
					// token then goes to the server, which rejects it with a
					// message that tells the customer to try again — degraded,
					// but never a spin and never a dead button.
					var vetoBlockedUntil = 0;

					$(document.body).on('checkout_place_order', function() {
						var $form = $('form.woocommerce-checkout');
						var $input = $form.find('.g-recaptcha-response');
						var input = $input.get(0);

						if ($input.length && (!$input.val() || isStale(input)) && api()
							&& Date.now() > vetoBlockedUntil) {
							var resubmit = function() {
								$form.trigger('submit');
							};

							fetchToken(input).then(resubmit, function() {
								vetoBlockedUntil = Date.now() + 15000;
								resubmit();
							});

							return false;
						}
						return true;
					});
				}
			}

			// Wait for whichever plugin's loader tag actually won.
			function waitForApi(elapsed) {
				if (api()) {
					start();
					return;
				}
				if (elapsed >= READY_TIMEOUT_MS) {
					return;
				}
				setTimeout(function() {
					waitForApi(elapsed + READY_POLL_MS);
				}, READY_POLL_MS);
			}

			function init() {
				waitForApi(0);
			}

			if ('loading' === document.readyState) {
				document.addEventListener('DOMContentLoaded', init);
			} else {
				init();
			}
		})();
		<?php
		return ob_get_clean();
	}
}
