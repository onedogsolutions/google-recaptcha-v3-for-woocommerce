<?php
/**
 * Gravity Forms Provider
 *
 * Makes this plugin the reCAPTCHA implementation for Gravity Forms: when the
 * provider is on, every eligible form is scored here.
 *
 * It does NOT switch Gravity Forms' own reCAPTCHA off. Until 2.21.0 it did, by
 * filtering the add-on's stored settings so they read as unconfigured. The
 * add-on's settings screen reads that option to populate its fields and saves
 * back what it read, so it wrote the filtered blanks to disk and destroyed the
 * stored keys on a live site. Detection of GF's reCAPTCHA remains — it drives
 * the coverage report and the operator notice — but retiring it is the
 * operator's action, not ours.
 *
 * ---------------------------------------------------------------------------
 * VERIFICATION STATUS
 *
 * The Gravity Forms bindings below (hook names, feed meta keys, native-captcha
 * option names) were written WITHOUT the installed Gravity Forms source to hand
 * and are marked individually. Writing GF integration code from assumption is
 * the defect that produced the 2.16.0 Stripe outage, so every host-plugin call
 * here is guarded and fails to the pessimistic answer:
 *
 *   - an unrecognised captcha state returns 'unknown', never 'off';
 *   - a form we cannot inspect is ineligible, so we do not claim to cover it;
 *   - a form we cannot classify is treated as a PAYMENT form, so it fails
 *     closed rather than silently fails open on a real payment;
 *   - unreadable transaction mappings yield no transactionData, which
 *     GSWP_Verifier already degrades to a plain score rather than an API error.
 *
 * Since 2.20.0 there is no staged rollout to catch a bad binding over time, so
 * two mechanisms carry that weight instead:
 *
 *   - inject_into_markup() injects into the finished form HTML whenever the
 *     primary hook did not, so coverage does not depend on having guessed the
 *     render paths correctly;
 *   - validate_submission() refuses to penalise a submission for a form we have
 *     no record of injecting into, and reports it as a coverage gap instead.
 *
 * Reads of Gravity Forms' own settings are for reporting only, and go straight
 * to the database rather than through get_option(), so nothing this plugin does
 * can colour what it reports about another plugin.
 * ---------------------------------------------------------------------------
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class GSWP_Provider_Gravity_Forms implements GSWP_Form_Provider {

	/**
	 * Name of the hidden token field injected into GF forms.
	 *
	 * Deliberately NOT 'g-recaptcha-response': that name is read by
	 * GSWP_Verifier for WooCommerce and may be read by GF for its own reCAPTCHA
	 * field. The class attribute is what matters — the shared footer bootstrap
	 * fills every .g-recaptcha-response on the page.
	 */
	const TOKEN_FIELD = 'gswp_gf_token';

	/**
	 * Entry meta key holding the assessment resource name.
	 */
	const META_ASSESSMENT = 'gswp_assessment_name';

	/**
	 * Entry meta key flagging an entry admitted without a verified token
	 * (fail-open on a non-payment form).
	 */
	const META_UNVERIFIED = 'gswp_unverified';

	/**
	 * Entry meta key guarding against double annotation.
	 */
	const META_ANNOTATED = 'gswp_annotated';

	/**
	 * Option recording, per form, when a token field was last successfully
	 * injected on a real front-end render.
	 *
	 * This is what turns a coverage gap from silent into loud. With the staged
	 * rollout gone there is no shadow period in which to discover a render path
	 * we failed to hook, so the question "did we actually inject into this
	 * form?" has to be answerable at validation time.
	 */
	const INJECTION_OPTION = 'gswp_gf_injection_log';

	/**
	 * Option recording, per form, why the last submission was rejected.
	 *
	 * "Why is form #12 rejecting?" was unanswerable from wp-admin, and
	 * unanswerable from the logs too, because nothing was written there. The
	 * coverage report is where an operator already goes to ask what this plugin
	 * is doing to a form, so the answer belongs there.
	 */
	const REJECTION_OPTION = 'gswp_gf_last_rejection';

	/**
	 * Option listing form ids that are never submitted by a visitor.
	 *
	 * Not every Gravity Form is a form in the ordinary sense. A site can drive
	 * one programmatically — generating a certificate when a student completes a
	 * course, for instance — so it is never rendered on the front end and never
	 * carries a browser-minted token.
	 *
	 * This plugin had no concept of that, and the consequences all pointed the
	 * wrong way: the coverage report showed a permanent "no token seen yet" state
	 * with the un-actionable instruction to load the form on the front end, and
	 * every programmatic submission logged a COVERAGE GAP at error level and
	 * fired the operator alert. Alerts that cry wolf on routine activity are
	 * worse than no alerts, because they teach the operator to ignore the real
	 * one.
	 *
	 * Listing a form here suppresses the missing-token alarm for it: no coverage
	 * gap, no error log line, no operator email. That is ALL it does.
	 *
	 * It deliberately does NOT stop the form being scored. The first cut made an
	 * internal form ineligible, which switched this plugin off for it entirely —
	 * and an operator who ticked the box on a password-change form reachable in
	 * the browser silently lost all bot scoring on a credential change. A
	 * reporting preference must never be able to remove protection; the two are
	 * not the operator's to trade against each other by accident. A submission
	 * carrying a token is scored whatever this says, so the declaration is
	 * inert on any form a human can actually reach.
	 *
	 * Deliberately an operator declaration rather than anything inferred from
	 * the request, so it cannot be spoofed by a caller omitting a field (the
	 * bypass class removed in 2.17.0).
	 */
	const INTERNAL_OPTION = 'gswp_gf_internal_forms';

	/**
	 * Add-on slugs whose presence marks a form as taking payment.
	 *
	 * UNVERIFIED against installed source. Incompleteness is safe: an
	 * unrecognised feed falls through to the product-field check below, and a
	 * form we cannot classify is treated as a payment form.
	 *
	 * @var string[]
	 */
	private static $payment_addons = array(
		'gravityformsstripe',
		'gravityformspaypal',
		'gravityformspaypalcheckout',
		'gravityformssquare',
		'gravityformsauthorizenet',
		'gravityforms2checkout',
		'gravityformsmollie',
		'gravityformsrazorpay',
	);

	/**
	 * Add-on slugs whose feeds create or modify a WordPress account.
	 *
	 * A form that creates a user account is a security surface, not a contact
	 * form. Treating it like one — accepting a submission with no verification
	 * token — is how spam registrations get in, which this plugin has a history
	 * of chasing (see the Account Defender and content-heuristic work). It gets
	 * the same fail-closed treatment as a payment.
	 *
	 * The slug is the same for feeds that CREATE an account and feeds that
	 * UPDATE one, which is why account_feed_type() has to look at the feed's own
	 * type. Treating both alike meant a signed-in customer editing her own
	 * profile was judged as if she were a stranger signing up.
	 *
	 * UNVERIFIED against installed source.
	 *
	 * @var string[]
	 */
	private static $account_addons = array(
		'gravityformsuserregistration',
	);

	/**
	 * Per-request cache of derived form classification, keyed bucket => form id.
	 *
	 * Classification now runs on the render path as well as the validation path
	 * (the action a form's token is minted with depends on it), and each answer
	 * costs a GFAPI::get_feeds() query. A page with several forms would repeat
	 * those queries per render hook without this.
	 *
	 * @var array<string,array<int,mixed>>
	 */
	private $memo = array();

	/**
	 * Setting names inside GF's reCAPTCHA option that hold a site key.
	 *
	 * Suffixed names verified against the reCAPTCHA add-on 2.2.2; the
	 * unsuffixed ones are kept as a fallback for other versions.
	 *
	 * @var string[]
	 */
	private static $native_site_key_names = array( 'site_key_v3', 'site_key_v2', 'site_key', 'public_key', 'siteKey' );

	/**
	 * Setting names inside GF's reCAPTCHA option that hold a secret.
	 *
	 * @var string[]
	 */
	private static $native_secret_key_names = array( 'secret_key_v3', 'secret_key_v2', 'secret_key', 'private_key' );

	/**
	 * Shared verifier.
	 *
	 * @var GSWP_Verifier|null
	 */
	private $verifier = null;

	/**
	 * Error message to surface on a rejected submission, per form.
	 *
	 * @var array<int,string>
	 */
	private $errors = array();

	/**
	 * Assessment name captured during validation, awaiting an entry to store it
	 * on. Keyed by form id.
	 *
	 * @var array<int,string>
	 */
	private $pending_assessment = array();

	/**
	 * Forms admitted this request without a verified token.
	 *
	 * @var array<int,bool>
	 */
	private $pending_unverified = array();

	/**
	 * {@inheritDoc}
	 */
	public function id() {
		return 'gravity-forms';
	}

	/**
	 * {@inheritDoc}
	 */
	public function label() {
		return 'Gravity Forms';
	}

	/**
	 * {@inheritDoc}
	 */
	public function is_active() {
		return class_exists( 'GFAPI' ) && ( defined( 'GF_VERSION' ) || class_exists( 'GFCommon' ) );
	}

	/**
	 * {@inheritDoc}
	 */
	public function forms() {
		if ( ! $this->is_active() || ! method_exists( 'GFAPI', 'get_forms' ) ) {
			return array();
		}

		$forms = GFAPI::get_forms( true );
		if ( ! is_array( $forms ) ) {
			return array();
		}

		$out = array();
		foreach ( $forms as $form ) {
			if ( ! is_array( $form ) || ! isset( $form['id'] ) ) {
				continue;
			}
			$out[ (int) $form['id'] ] = isset( $form['title'] ) ? (string) $form['title'] : ( '#' . $form['id'] );
		}

		return $out;
	}

	/**
	 * {@inheritDoc}
	 *
	 * A form is ineligible when it uses a visible v2 checkbox challenge. Our
	 * implementation is score-only, so replacing that would change both the UX
	 * and the threat model. Those forms keep GF's own reCAPTCHA — partial
	 * takeover is a supported end state, not a failure.
	 */
	public function form_is_eligible( $form_id ) {
		$form = $this->form( $form_id );
		if ( null === $form ) {
			// Cannot inspect it, so do not claim to cover it.
			return false;
		}

		// NOTE: an internal form is deliberately still eligible. Making it
		// ineligible — as 2.22.0 first did — switched this plugin off for that
		// form entirely: no token field, no scoring, nothing. On a form that
		// really is only ever driven programmatically that is merely useless,
		// but on a form reachable in a browser it silently strips protection
		// from whatever the form does, up to and including changing a password.
		// A reporting preference must never be able to do that. See
		// form_is_internal(): the declaration now suppresses the missing-token
		// ALARM and nothing else.
		return 'v2' !== $this->native_captcha_state( $form_id );
	}

	/**
	 * Whether a form is driven programmatically rather than submitted by a
	 * visitor.
	 *
	 * Declared by the operator, never inferred from the request. See
	 * INTERNAL_OPTION for why this exists.
	 *
	 * @param int|string $form_id Form identifier.
	 * @return bool
	 */
	public function form_is_internal( $form_id ) {
		$listed = get_option( self::INTERNAL_OPTION, array() );
		$listed = is_array( $listed ) ? array_map( 'intval', $listed ) : array();

		$internal = in_array( (int) $form_id, $listed, true );

		/**
		 * Filter whether a Gravity Form is internal (never publicly submitted).
		 *
		 * @param bool $internal Whether the form is internal.
		 * @param int  $form_id  Form identifier.
		 */
		return (bool) apply_filters( 'gswp_gf_form_is_internal', $internal, (int) $form_id );
	}

	/**
	 * {@inheritDoc}
	 *
	 * Deliberately biased toward "yes". A form wrongly classified as payment
	 * fails closed on a missing token, which is an inconvenience. A payment form
	 * wrongly classified as non-payment fails open, which is a hole. When in
	 * doubt, choose the inconvenience.
	 */
	public function form_has_payment( $form_id ) {
		$cached = $this->memo_get( 'payment', $form_id );
		if ( null !== $cached ) {
			return $cached;
		}

		return $this->memo_set( 'payment', $form_id, $this->compute_has_payment( $form_id ) );
	}

	/**
	 * Uncached body of form_has_payment().
	 *
	 * @param int|string $form_id Form identifier.
	 * @return bool
	 */
	private function compute_has_payment( $form_id ) {
		$form = $this->form( $form_id );
		if ( null === $form ) {
			return true;
		}

		// An active feed from a known payment add-on.
		if ( method_exists( 'GFAPI', 'get_feeds' ) ) {
			$feeds = GFAPI::get_feeds( null, (int) $form_id );
			if ( is_array( $feeds ) ) {
				foreach ( $feeds as $feed ) {
					if ( empty( $feed['is_active'] ) ) {
						continue;
					}
					$slug = isset( $feed['addon_slug'] ) ? (string) $feed['addon_slug'] : '';
					if ( in_array( $slug, self::$payment_addons, true ) ) {
						return true;
					}
				}
			}
		}

		// Fallback: any pricing field means money is being quoted, which is
		// enough to warrant the stricter policy.
		if ( ! empty( $form['fields'] ) && is_array( $form['fields'] ) ) {
			foreach ( $form['fields'] as $field ) {
				$type = is_object( $field ) && isset( $field->type ) ? $field->type : '';
				if ( in_array( $type, array( 'product', 'total', 'shipping', 'option', 'creditcard' ), true ) ) {
					return true;
				}
			}
		}

		return false;
	}

	/**
	 * Whether a form's active feeds create a new WordPress account.
	 *
	 * @param int|string $form_id Form identifier.
	 * @return bool
	 */
	public function form_creates_account( $form_id ) {
		return 'create' === $this->account_feed_type( $form_id );
	}

	/**
	 * Whether a form's active feeds update an existing WordPress account.
	 *
	 * A profile-edit form. WordPress has already authenticated whoever is
	 * submitting it, so reCAPTCHA here is defence in depth, not the gate —
	 * see form_is_strict().
	 *
	 * @param int|string $form_id Form identifier.
	 * @return bool
	 */
	public function form_updates_account( $form_id ) {
		return 'update' === $this->account_feed_type( $form_id );
	}

	/**
	 * What a form's User Registration feeds do to an account.
	 *
	 * UNVERIFIED against installed source: the feed's type is expected at
	 * `meta['feedType']` with the values 'create' and 'update'. Chunk 19 of the
	 * manual verification suite prints the raw value per form so this can be
	 * confirmed on a live install.
	 *
	 * Fails to the strict answer, per this class's standing rule: a User
	 * Registration feed whose type cannot be read is treated as 'create', which
	 * is exactly how every such feed was treated before 2.22.0. A form carrying
	 * both kinds of feed is 'create' — the stricter of the two.
	 *
	 * @param int|string $form_id Form identifier.
	 * @return string 'create', 'update', or '' when the form touches no account.
	 */
	private function account_feed_type( $form_id ) {
		$cached = $this->memo_get( 'account_feed_type', $form_id );
		if ( null !== $cached ) {
			return $cached;
		}

		if ( ! method_exists( 'GFAPI', 'get_feeds' ) ) {
			return $this->memo_set( 'account_feed_type', $form_id, $this->filter_account_type( '', $form_id ) );
		}

		$feeds = GFAPI::get_feeds( null, (int) $form_id );
		if ( ! is_array( $feeds ) ) {
			return $this->memo_set( 'account_feed_type', $form_id, $this->filter_account_type( '', $form_id ) );
		}

		$type = '';

		foreach ( $feeds as $feed ) {
			if ( empty( $feed['is_active'] ) ) {
				continue;
			}
			$slug = isset( $feed['addon_slug'] ) ? (string) $feed['addon_slug'] : '';
			if ( ! in_array( $slug, self::$account_addons, true ) ) {
				continue;
			}

			$meta     = isset( $feed['meta'] ) && is_array( $feed['meta'] ) ? $feed['meta'] : array();
			$declared = isset( $meta['feedType'] ) ? strtolower( trim( (string) $meta['feedType'] ) ) : '';

			if ( 'update' === $declared ) {
				// Only downgrade to 'update' if nothing has claimed 'create'.
				$type = ( 'create' === $type ) ? 'create' : 'update';
				continue;
			}

			// 'create', or a value we do not recognise, or no value at all.
			return $this->memo_set( 'account_feed_type', $form_id, $this->filter_account_type( 'create', $form_id ) );
		}

		return $this->memo_set( 'account_feed_type', $form_id, $this->filter_account_type( $type, $form_id ) );
	}

	/**
	 * Let a site correct a form's account classification.
	 *
	 * The feed-type binding is UNVERIFIED, and getting it wrong is not
	 * cosmetic: a profile-edit form misread as a signup is scored under the
	 * stricter threshold and rejected outright when its token is missing. A
	 * site that hits this should not have to wait for a release, so the answer
	 * is filterable:
	 *
	 *     add_filter( 'gswp_gf_account_feed_type', function ( $type, $form_id ) {
	 *         return in_array( $form_id, array( 7, 9 ), true ) ? 'update' : $type;
	 *     }, 10, 2 );
	 *
	 * Returning anything other than 'create' or 'update' means "this form
	 * touches no account".
	 *
	 * @param string $type    Derived type: 'create', 'update', or ''.
	 * @param int    $form_id Form identifier.
	 * @return string Filtered type.
	 */
	private function filter_account_type( $type, $form_id ) {
		$filtered = apply_filters( 'gswp_gf_account_feed_type', $type, (int) $form_id );

		return in_array( $filtered, array( 'create', 'update' ), true ) ? $filtered : '';
	}

	/**
	 * {@inheritDoc}
	 *
	 * Fail closed on anything that moves money or creates an account. Both are
	 * outcomes worth refusing rather than admitting unverified; a contact form
	 * entry is not, and neither is a signed-in user editing her own profile —
	 * WordPress has already authenticated her, and locking her out of her own
	 * account details is a worse outcome than admitting one unscored edit.
	 */
	public function form_is_strict( $form_id ) {
		return $this->form_has_payment( $form_id ) || $this->form_creates_account( $form_id );
	}

	/**
	 * The reCAPTCHA action a form's token is minted with and checked against.
	 *
	 * ONE resolver, called from both token_field() (which labels the token in
	 * the browser) and validate_submission() (which tells Google what to expect).
	 *
	 * Before 2.21.2 those two decisions were two separate ternaries, and they
	 * disagreed: a non-payment form with a User Registration feed rendered
	 * 'submit' but was validated as 'register'. Enterprise assessments reject on
	 * expectedAction mismatch, so every submission of every account form failed,
	 * for every visitor, with a message accusing them of being spam. The fix is
	 * not to correct one of the two expressions — it is to have only one.
	 *
	 * @param int|string $form_id Form identifier.
	 * @return string reCAPTCHA action name.
	 */
	private function action_for( $form_id ) {
		if ( $this->form_has_payment( $form_id ) ) {
			return 'checkout';
		}
		if ( $this->form_creates_account( $form_id ) ) {
			return 'register';
		}
		// Ranked above a plain account update: changing a password is the step
		// an account takeover performs to lock the real owner out, so it is
		// worth scoring and tuning on its own rather than averaging in with
		// profile edits.
		if ( $this->form_changes_password( $form_id ) ) {
			return 'password_reset';
		}
		if ( $this->form_updates_account( $form_id ) ) {
			return 'account_update';
		}

		return 'submit';
	}

	/**
	 * Whether a form sets or changes a password.
	 *
	 * Read from the stored form definition, never the request. A password field
	 * is the signal: whether the change lands via a User Registration update
	 * feed or the site's own handler, the form is a credential-changing surface
	 * either way.
	 *
	 * @param int|string $form_id Form identifier.
	 * @return bool
	 */
	public function form_changes_password( $form_id ) {
		$cached = $this->memo_get( 'password', $form_id );
		if ( null !== $cached ) {
			return $cached;
		}

		$form = $this->form( $form_id );
		if ( null === $form || empty( $form['fields'] ) || ! is_array( $form['fields'] ) ) {
			return $this->memo_set( 'password', $form_id, false );
		}

		foreach ( $form['fields'] as $field ) {
			$type = is_object( $field ) && isset( $field->type ) ? $field->type : '';
			if ( 'password' === $type ) {
				return $this->memo_set( 'password', $form_id, true );
			}
		}

		return $this->memo_set( 'password', $form_id, false );
	}

	/**
	 * Action names accepted for a form's token.
	 *
	 * Every non-payment form additionally accepts 'submit', because that is what
	 * this plugin rendered for ALL non-payment forms before 2.21.2 and a page
	 * cached before the upgrade still carries it. Without the allowance the fix
	 * would keep rejecting real customers until every cache expired.
	 *
	 * This is not a bypass. Both names are strings we mint ourselves; the token
	 * must still be valid for our own site key, and must still clear the score
	 * threshold. An attacker gains nothing by preferring one of our labels over
	 * another. Payment forms get no latitude at all.
	 *
	 * REMOVE IN 2.23.0, by which point no page cached under 2.21.1 can survive.
	 *
	 * @param int|string $form_id Form identifier.
	 * @return string[] Accepted actions, the canonical one first.
	 */
	private function accepted_actions( $form_id ) {
		$action = $this->action_for( $form_id );

		if ( 'checkout' === $action || 'submit' === $action ) {
			return array( $action );
		}

		return array( $action, 'submit' );
	}

	/**
	 * The threshold context for a form.
	 *
	 * Until 2.22.0 every non-payment Gravity Form was scored against
	 * `gswp_threshold_wp_register` — the WordPress signup threshold. A site that
	 * raised that to keep fake accounts out was silently applying signup-grade
	 * strictness to its contact forms, and judging an already-authenticated user
	 * editing her profile by the standard set for anonymous strangers creating
	 * accounts. Each class of form now has its own dial.
	 *
	 * @param int|string $form_id Form identifier.
	 * @return string Context, resolving to option "gswp_threshold_{context}".
	 */
	private function context_for( $form_id ) {
		if ( $this->form_has_payment( $form_id ) ) {
			return 'checkout';
		}
		if ( $this->form_creates_account( $form_id ) ) {
			return 'gf_register';
		}
		if ( $this->form_changes_password( $form_id ) ) {
			return 'gf_password';
		}
		if ( $this->form_updates_account( $form_id ) ) {
			return 'gf_account_update';
		}

		return 'gf_submit';
	}

	/**
	 * Read a memoized classification for a form.
	 *
	 * @param string     $bucket  Cache bucket.
	 * @param int|string $form_id Form identifier.
	 * @return mixed Cached value, or null on a miss.
	 */
	private function memo_get( $bucket, $form_id ) {
		return isset( $this->memo[ $bucket ][ (int) $form_id ] ) ? $this->memo[ $bucket ][ (int) $form_id ] : null;
	}

	/**
	 * Store a memoized classification for a form.
	 *
	 * @param string     $bucket  Cache bucket.
	 * @param int|string $form_id Form identifier.
	 * @param mixed      $value   Value to cache and return.
	 * @return mixed The value, so callers can `return $this->memo_set( ... )`.
	 */
	private function memo_set( $bucket, $form_id, $value ) {
		$this->memo[ $bucket ][ (int) $form_id ] = $value;

		return $value;
	}

	/**
	 * {@inheritDoc}
	 *
	 * UNVERIFIED: the reCAPTCHA add-on's option name is a candidate list rather
	 * than a confirmed key, so a v3 integration this does not recognise reports
	 * 'unknown'. That is the safe direction — 'unknown' never lets the settings
	 * UI claim GF's reCAPTCHA is already off.
	 *
	 * The add-on's own state is checked FIRST, because its settings outlive it.
	 * Deactivating a WordPress plugin does not delete its options, so reading
	 * the stored keys alone reported a live reCAPTCHA for an add-on that had
	 * been switched off — configuration mistaken for behaviour.
	 */
	public function native_captcha_state( $form_id ) {
		$form = $this->form( $form_id );
		if ( null === $form ) {
			return 'unknown';
		}

		if ( false === self::native_addon_active() ) {
			return 'off';
		}

		// A CAPTCHA field on the form is the visible-challenge case.
		if ( ! empty( $form['fields'] ) && is_array( $form['fields'] ) ) {
			foreach ( $form['fields'] as $field ) {
				$type = is_object( $field ) && isset( $field->type ) ? $field->type : '';
				if ( 'captcha' !== $type ) {
					continue;
				}

				$captcha_type = isset( $field->captchaType ) ? (string) $field->captchaType : 'recaptcha'; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Gravity Forms property.

				// 'math' and 'simple_captcha' are GF's own non-reCAPTCHA
				// challenges; they do not load Google reCAPTCHA and do not
				// conflict, so they are not our concern.
				if ( in_array( $captcha_type, array( 'math', 'simple_captcha' ), true ) ) {
					continue;
				}

				return 'v2';
			}
		}

		// The reCAPTCHA add-on is configured site-wide, and keeps v2 and v3 keys
		// in the same option under separate, suffixed names.
		//
		// VERIFIED against a live install (Gravity Forms reCAPTCHA add-on 2.2.2):
		// the option is `gravityformsaddon_gravityformsrecaptcha_settings` and
		// the keys are `site_key_v3` / `secret_key_v3` / `site_key_v2` /
		// `secret_key_v2` / `type_v2`. Earlier versions of this class looked for
		// `site_key` and `public_key`, which exist in neither, so detection
		// reported 'unknown' for an add-on that was configured all along. The
		// unsuffixed names are retained only as a fallback for other add-on
		// versions.
		foreach ( $this->native_v3_option_candidates() as $option ) {
			// Read the row directly. Reporting on another plugin's settings must
			// not pass through any filter, ours or anyone else's.
			$settings = $this->raw_option( $option );
			if ( ! is_array( $settings ) ) {
				continue;
			}

			// A v2 checkbox is a visible challenge we cannot replace.
			if ( ! empty( $settings['site_key_v2'] ) ) {
				$type = isset( $settings['type_v2'] ) ? (string) $settings['type_v2'] : 'checkbox';
				if ( 'invisible' !== $type ) {
					return 'v2';
				}
			}

			foreach ( self::$native_site_key_names as $key ) {
				if ( ! empty( $settings[ $key ] ) ) {
					return 'v3';
				}
			}
		}

		return 'unknown';
	}

	/**
	 * Whether Gravity Forms' reCAPTCHA add-on is actually running.
	 *
	 * VERIFIED against a live install: the add-on registers itself with Gravity
	 * Forms as `Gravity_Forms\Gravity_Forms_RECAPTCHA\GF_RECAPTCHA`. Asking
	 * Gravity Forms for its registered add-ons rather than testing a class name
	 * is deliberate — that class is namespaced, and an unqualified
	 * class_exists() against it reported "not loaded" for an add-on that was
	 * active the whole time. Matching on the registered list needs no knowledge
	 * of the namespace and survives the add-on being renamed.
	 *
	 * @return bool|null True or false, or null when Gravity Forms itself is not
	 *                   loaded and the question cannot be answered.
	 */
	private static function native_addon_active() {
		if ( ! class_exists( 'GFAddOn' ) || ! method_exists( 'GFAddOn', 'get_registered_addons' ) ) {
			return null;
		}

		foreach ( (array) GFAddOn::get_registered_addons() as $class ) {
			if ( false !== stripos( (string) $class, 'recaptcha' ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Candidate option names for GF's v3 reCAPTCHA add-on settings.
	 *
	 * `gravityformsaddon_gravityformsrecaptcha_settings` is VERIFIED against a
	 * live install (add-on 2.2.2) and is listed first. The others are retained
	 * for other add-on versions. Filterable so a site can correct it without a
	 * code change.
	 *
	 * @return string[]
	 */
	private function native_v3_option_candidates() {
		return (array) apply_filters(
			'gswp_gf_native_recaptcha_options',
			array(
				'gravityformsaddon_gravityformsrecaptcha_settings',
				'gravityformsaddon_recaptcha_settings',
				'gravityformsaddon_gravityformsrecaptcha_v2_settings',
			)
		);
	}

	/**
	 * Fetch a form definition, or null when unavailable.
	 *
	 * @param int|string $form_id Form identifier.
	 * @return array|null
	 */
	private function form( $form_id ) {
		if ( ! $this->is_active() || ! method_exists( 'GFAPI', 'get_form' ) ) {
			return null;
		}

		$form = GFAPI::get_form( (int) $form_id );

		return is_array( $form ) ? $form : null;
	}

	/**
	 * Read one of GF's settings options straight from the database.
	 *
	 * Bypasses get_option(), and therefore bypasses our own blanking filter.
	 * Reporting that reads through that filter can only ever conclude that GF
	 * has no reCAPTCHA configured — which is what made the coverage table say
	 * "unknown" for every form while GF was in fact configured.
	 *
	 * @param string $option Option name.
	 * @return array|null Settings array, or null when absent/unreadable.
	 */
	private function raw_option( $option ) {
		global $wpdb;

		if ( ! $wpdb ) {
			return null;
		}

		$value = $wpdb->get_var( $wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s LIMIT 1", $option ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery

		if ( null === $value ) {
			return null;
		}

		$value = maybe_unserialize( $value );

		return is_array( $value ) ? $value : null;
	}

	/**
	 * {@inheritDoc}
	 */
	public function last_injection( $form_id ) {
		$log = get_option( self::INJECTION_OPTION, array() );

		return is_array( $log ) && isset( $log[ (int) $form_id ] ) ? (int) $log[ (int) $form_id ] : 0;
	}

	/**
	 * Record that a token field reached the browser for this form.
	 *
	 * Written at most once per form per day so a busy site does not turn every
	 * page view into an option write.
	 *
	 * @param int $form_id Form id.
	 */
	private function record_injection( $form_id ) {
		$form_id = (int) $form_id;
		$log     = get_option( self::INJECTION_OPTION, array() );
		$log     = is_array( $log ) ? $log : array();

		if ( isset( $log[ $form_id ] ) && ( time() - (int) $log[ $form_id ] ) < DAY_IN_SECONDS ) {
			return;
		}

		$log[ $form_id ] = time();
		update_option( self::INJECTION_OPTION, $log, false );
	}

	/**
	 * {@inheritDoc}
	 */
	public function register_hooks( GSWP_Verifier $verifier ) {
		$this->verifier = $verifier;

		// UNVERIFIED hook choice: gform_submit_button is the conventional
		// injection point inside the <form> element. Confirm it fires for every
		// render path (multi-page, AJAX, conditional logic) during staging —
		// scenario D of the test plan exists precisely to catch a miss here.
		add_filter( 'gform_submit_button', array( $this, 'inject_token_field' ), 10, 2 );

		// Coverage backstop. gform_submit_button is fast and clean when it
		// fires, but it depends on assumptions about GF's render paths and on
		// the theme not replacing the button markup. This filter receives the
		// complete rendered form HTML, so if the field is not already in it we
		// put it there — independent of which path produced the markup.
		add_filter( 'gform_get_form_filter', array( $this, 'inject_into_markup' ), 99, 2 );

		// UNVERIFIED hook choice: gform_validation is GF's canonical validation
		// filter and runs before payment feeds process. The critical unknown is
		// whether the card is authorised client-side before submission in the
		// configured Stripe mode; if so, a rejection here stops the entry but
		// not the authorisation.
		add_filter( 'gform_validation', array( $this, 'validate_submission' ), 20 );
		add_filter( 'gform_validation_message', array( $this, 'validation_message' ), 10, 2 );

		// Persist the assessment name and any fail-open flag onto the entry.
		add_action( 'gform_entry_created', array( $this, 'store_entry_meta' ), 10, 2 );

		// Payment lifecycle → Transaction Defense annotation.
		add_action( 'gform_post_payment_completed', array( $this, 'on_payment_completed' ), 10, 2 );
		add_action( 'gform_post_payment_refunded', array( $this, 'on_payment_refunded' ), 10, 2 );
	}

	/**
	 * Inject the hidden token field immediately before the submit button.
	 *
	 * @param string $button Submit button markup.
	 * @param array  $form   Form definition.
	 * @return string Button markup with our field prepended.
	 */
	public function inject_token_field( $button, $form ) {
		if ( ! is_array( $form ) || empty( $form['id'] ) ) {
			return $button;
		}
		if ( ! GSWP_Recaptcha_Loader::will_load() ) {
			return $button;
		}
		if ( ! $this->form_is_eligible( $form['id'] ) ) {
			return $button;
		}

		// Shares the page's single loader (2.18.0) and the footer bootstrap,
		// which fills every .g-recaptcha-response and refreshes it before the
		// 120-second expiry. No provider-specific JavaScript.
		GSWP_Recaptcha_Loader::enqueue();

		$this->record_injection( $form['id'] );

		return $this->token_field( $form['id'] ) . $button;
	}

	/**
	 * Coverage backstop: inject into the rendered form markup.
	 *
	 * gform_submit_button is the clean injection point, but it rests on
	 * assumptions about Gravity Forms' render paths and on the theme not
	 * replacing the button markup. This filter receives the finished HTML, so
	 * if the field is not already present we add it before the closing form
	 * tag — whatever produced the markup, and whether or not the primary hook
	 * fired.
	 *
	 * Without a staged rollout there is no discovery period in which to notice
	 * a missed render path, so coverage has to be answered here rather than in
	 * the logs six weeks from now.
	 *
	 * @param string $markup Rendered form HTML.
	 * @param array  $form   Form definition.
	 * @return string Markup guaranteed to carry the token field, when eligible.
	 */
	public function inject_into_markup( $markup, $form ) {
		if ( ! is_string( $markup ) || '' === $markup ) {
			return $markup;
		}
		if ( ! is_array( $form ) || empty( $form['id'] ) ) {
			return $markup;
		}
		if ( ! GSWP_Recaptcha_Loader::will_load() || ! $this->form_is_eligible( $form['id'] ) ) {
			return $markup;
		}

		// Already injected by the primary hook.
		if ( false !== strpos( $markup, 'name="' . self::TOKEN_FIELD . '"' ) ) {
			return $markup;
		}

		$close = strripos( $markup, '</form>' );
		if ( false === $close ) {
			// Rendered without a closing form tag: we cannot place the field,
			// and pretending otherwise would leave the form silently unscored.
			$this->log_error(
				sprintf(
					'COVERAGE GAP: Gravity Forms #%d rendered without a closing form tag, so no reCAPTCHA token field could be injected.',
					(int) $form['id']
				)
			);
			do_action( 'gswp_form_coverage_gap', $this->id(), (int) $form['id'] );

			return $markup;
		}

		GSWP_Recaptcha_Loader::enqueue();
		$this->record_injection( $form['id'] );

		return substr( $markup, 0, $close )
			. $this->token_field( $form['id'] )
			. substr( $markup, $close );
	}

	/**
	 * The hidden token field markup for a form.
	 *
	 * @param int|string $form_id Form id.
	 * @return string
	 */
	private function token_field( $form_id ) {
		return sprintf(
			'<input type="hidden" name="%s" class="g-recaptcha-response" data-recaptcha-action="%s" value="" />',
			esc_attr( self::TOKEN_FIELD ),
			// Same resolver validate_submission() uses. See action_for().
			esc_attr( $this->action_for( $form_id ) )
		);
	}

	/**
	 * Score a submission and reject it when warranted.
	 *
	 * @param array $validation_result GF validation result.
	 * @return array Filtered validation result.
	 */
	public function validate_submission( $validation_result ) {
		if ( ! is_array( $validation_result ) || empty( $validation_result['form'] ) ) {
			return $validation_result;
		}

		$form = $validation_result['form'];
		if ( ! is_array( $form ) || empty( $form['id'] ) ) {
			return $validation_result;
		}

		$form_id = (int) $form['id'];

		// Never re-judge a submission GF has already rejected.
		if ( isset( $validation_result['is_valid'] ) && ! $validation_result['is_valid'] ) {
			return $validation_result;
		}
		if ( ! $this->form_is_eligible( $form_id ) ) {
			return $validation_result;
		}

		$payment = $this->form_has_payment( $form_id );
		$strict  = $this->form_is_strict( $form_id );

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Gravity Forms validates its own nonce before this filter runs.
		$token = isset( $_POST[ self::TOKEN_FIELD ] ) ? sanitize_text_field( wp_unslash( $_POST[ self::TOKEN_FIELD ] ) ) : '';

		if ( '' === $token ) {
			// Declared programmatic: no browser, so no token, and neither a gap
			// nor an attack. Admit it without the alarm.
			//
			// This is the ONLY thing the declaration does. A submission that
			// DOES carry a token has already fallen past this branch and is
			// scored exactly like any other — so ticking "Not public" can never
			// silently unprotect a form somebody can actually reach.
			if ( $this->form_is_internal( $form_id ) ) {
				return $validation_result;
			}

			// Coverage assertion. A missing token means one of two very
			// different things, and they deserve opposite responses.
			if ( 0 === $this->last_injection( $form_id ) ) {
				// We have no record of ever getting a token field into this
				// form. That is our coverage bug, not an attack, and a visitor
				// must never be blocked for it. Fail open on every form type,
				// including payment forms, and make the gap loud.
				$this->pending_unverified[ $form_id ] = true;

				$this->log_error(
					sprintf(
						'COVERAGE GAP: Gravity Forms #%d was submitted with no reCAPTCHA token and this plugin has no record of ever injecting one into it. The submission was allowed through unscored. Check that the form renders our token field.',
						$form_id
					)
				);

				/**
				 * A form is not receiving its token field. Fires once per
				 * submission so the alert layer can surface a coverage gap the
				 * way it surfaces any other security-relevant event.
				 */
				do_action( 'gswp_form_coverage_gap', $this->id(), $form_id );

				return $validation_result;
			}

			// We do inject into this form, so a submission without a token is
			// adversarial or broken client-side. Asymmetric enforcement: the
			// decision is read from the stored form definition, never from the
			// request — a request-derived predicate would let a caller opt out
			// by omitting the field, the bypass class removed in 2.17.0.
			if ( $strict ) {
				$this->record_rejection( $form_id, 'missing token' );

				return $this->reject(
					$validation_result,
					__( 'We could not verify this submission. Please refresh the page and try again.', 'google-security-for-wordpress' ),
					$form_id
				);
			}

			$this->pending_unverified[ $form_id ] = true;
			$this->log(
				sprintf(
					'Gravity Forms #%d submitted with no reCAPTCHA token; admitted (takes no payment and creates no account, fail-open). If this repeats, token generation is broken on that page.',
					$form_id
				)
			);

			return $validation_result;
		}

		$context     = $this->context_for( $form_id );
		$actions     = $this->accepted_actions( $form_id );
		$event_extra = $payment ? $this->payment_context( $form, $form_id ) : array();

		$result = $this->verifier->verify_token( $context, $actions, $event_extra, null, $token );

		$name = $this->verifier->get_last_assessment_name();
		if ( '' !== $name ) {
			$this->pending_assessment[ $form_id ] = $name;
		}

		if ( is_wp_error( $result ) ) {
			// An action mismatch means the token was valid for this site key but
			// carried a different action name. That is a fault in this plugin or
			// a stale cached page — never evidence about the visitor — so it does
			// not get to block one on a form where the stakes do not justify it.
			// Google's actual score is still available and is still applied.
			if ( 'recaptcha_action_mismatch' === $result->get_error_code() && ! $strict ) {
				$score     = $this->verifier->get_last_score();
				$threshold = floatval( get_option( 'gswp_threshold_' . $context, '0.5' ) );

				// A cleared Transaction defense verdict outranks the score on a
				// payment form for the same reason it does at checkout. See
				// GSWP_Verifier::fraud_verdict_admits_low_score().
				if ( null !== $score && $score < $threshold && ! $this->verifier->fraud_verdict_admits_low_score() ) {
					$this->record_rejection( $form_id, 'low score' );

					return $this->reject(
						$validation_result,
						__( 'This submission did not pass our automated security check. Please refresh the page and try again, or contact us if the problem continues.', 'google-security-for-wordpress' ),
						$form_id
					);
				}

				$this->pending_unverified[ $form_id ] = true;

				$this->log_error(
					sprintf(
						'Gravity Forms #%d submitted a token whose action was "%s" but this form expects "%s". Admitted (takes no payment and creates no account) and flagged unverified. This is a plugin or caching fault, not a spam signal — if it persists, the form is rendering a stale action.',
						$form_id,
						$this->verifier->get_last_token_action(),
						implode( '" or "', $actions )
					)
				);

				return $validation_result;
			}

			$this->record_rejection( $form_id, $result->get_error_code() );

			return $this->reject( $validation_result, wp_strip_all_tags( $result->get_error_message() ), $form_id );
		}

		// Transaction Defense verdict on payment forms.
		if ( $payment ) {
			$risk = $this->verifier->get_last_fraud_risk();
			if ( null !== $risk ) {
				if ( '1' === get_option( 'gswp_verbose_logging', '0' ) ) {
					$this->log( sprintf( 'Gravity Forms #%d transaction risk %.2f.', $form_id, $risk ) );
				}

				if ( '1' === get_option( 'gswp_txn_block', '0' ) ) {
					$threshold = floatval( get_option( 'gswp_threshold_txn', '0.8' ) );
					if ( $risk >= $threshold ) {
						$this->log( sprintf( 'Gravity Forms #%d blocked: risk %.2f >= %.2f.', $form_id, $risk, $threshold ) );

						do_action(
							'gswp_checkout_blocked',
							$risk,
							$threshold,
							array(
								'source'     => 'gravity-forms',
								'assessment' => $name,
								'form_id'    => $form_id,
							)
						);

						$this->record_rejection( $form_id, 'transaction risk' );

						return $this->reject(
							$validation_result,
							__( 'This transaction was flagged as high risk and cannot be completed. Please contact us if you believe this is a mistake.', 'google-security-for-wordpress' ),
							$form_id
						);
					}
				}
			}
		}

		return $validation_result;
	}

	/**
	 * Mark a validation result as failed and record the message.
	 *
	 * @param array  $validation_result GF validation result.
	 * @param string $message           Customer-facing message.
	 * @param int    $form_id           Form id.
	 * @return array
	 */
	private function reject( $validation_result, $message, $form_id ) {
		$validation_result['is_valid'] = false;
		$this->errors[ $form_id ]      = $message;

		return $validation_result;
	}

	/**
	 * Record why a form's last submission was rejected.
	 *
	 * Surfaced per form in the coverage report so "why is this form rejecting?"
	 * has an answer in wp-admin. Only the cause and the time are kept — nothing
	 * about the person who submitted it.
	 *
	 * @param int    $form_id Form id.
	 * @param string $reason  Error code, e.g. 'recaptcha_low_score'.
	 */
	private function record_rejection( $form_id, $reason ) {
		$form_id = (int) $form_id;
		$reason  = (string) $reason;

		$log = get_option( self::REJECTION_OPTION, array() );
		$log = is_array( $log ) ? $log : array();

		// Throttled, like record_injection(). A payment form under a carding
		// run rejects continuously, and one option write per rejected attempt
		// would turn an attack into database load — the plugin amplifying the
		// thing it exists to absorb. The timestamp is only ever read to show
		// "why did this last reject", so a few minutes of staleness costs the
		// operator nothing. A CHANGE of reason always writes immediately: that
		// is new information.
		if ( isset( $log[ $form_id ] )
			&& isset( $log[ $form_id ]['reason'], $log[ $form_id ]['time'] )
			&& $log[ $form_id ]['reason'] === $reason
			&& ( time() - (int) $log[ $form_id ]['time'] ) < 5 * MINUTE_IN_SECONDS
		) {
			return;
		}

		$log[ $form_id ] = array(
			'reason' => $reason,
			'time'   => time(),
		);

		update_option( self::REJECTION_OPTION, $log, false );
	}

	/**
	 * Why a form's last submission was rejected, for the coverage report.
	 *
	 * @param int|string $form_id Form id.
	 * @return array{reason:string,time:int}|null Null when none recorded.
	 */
	public function last_rejection( $form_id ) {
		$log = get_option( self::REJECTION_OPTION, array() );

		if ( ! is_array( $log ) || ! isset( $log[ (int) $form_id ] ) ) {
			return null;
		}

		$entry = $log[ (int) $form_id ];

		return array(
			'reason' => isset( $entry['reason'] ) ? (string) $entry['reason'] : '',
			'time'   => isset( $entry['time'] ) ? (int) $entry['time'] : 0,
		);
	}

	/**
	 * The reCAPTCHA action and threshold context resolved for a form.
	 *
	 * Reporting surface for the coverage table. Not on the provider interface —
	 * callers must guard with method_exists().
	 *
	 * @param int|string $form_id Form identifier.
	 * @return array{action:string,context:string,account:string}
	 */
	public function form_policy( $form_id ) {
		return array(
			'action'  => $this->action_for( $form_id ),
			'context' => $this->context_for( $form_id ),
			'account'  => $this->account_feed_type( $form_id ),
			'password' => $this->form_changes_password( $form_id ),
			'internal' => $this->form_is_internal( $form_id ),
		);
	}

	/**
	 * Replace GF's generic validation message with ours when we rejected.
	 *
	 * @param string $message Existing message markup.
	 * @param array  $form    Form definition.
	 * @return string
	 */
	public function validation_message( $message, $form ) {
		$form_id = is_array( $form ) && isset( $form['id'] ) ? (int) $form['id'] : 0;

		if ( ! isset( $this->errors[ $form_id ] ) ) {
			return $message;
		}

		return '<div class="validation_error gswp-validation-error">'
			. esc_html( $this->errors[ $form_id ] )
			. '</div>';
	}

	/**
	 * Build transactionData for a payment form from its payment feed mapping.
	 *
	 * UNVERIFIED: feed meta keys are inferred. Returning an empty array is
	 * safe — GSWP_Verifier enforces Google's documented minimum (billing region
	 * + postal code + payment method) and omits transaction data entirely when
	 * it is unmet, degrading to a plain score rather than an API error.
	 *
	 * @param array $form    Form definition.
	 * @param int   $form_id Form id.
	 * @return array Event extras, or empty.
	 */
	private function payment_context( $form, $form_id ) {
		if ( 'enterprise' !== get_option( 'gswp_key_type', 'classic' ) ) {
			return array();
		}
		if ( '1' !== get_option( 'gswp_txn_defense', '0' ) ) {
			return array();
		}
		if ( ! method_exists( 'GFAPI', 'get_feeds' ) ) {
			return array();
		}

		$feeds = GFAPI::get_feeds( null, $form_id );
		if ( ! is_array( $feeds ) ) {
			return array();
		}

		$feed = null;
		foreach ( $feeds as $candidate ) {
			if ( empty( $candidate['is_active'] ) || empty( $candidate['meta'] ) ) {
				continue;
			}
			$slug = isset( $candidate['addon_slug'] ) ? (string) $candidate['addon_slug'] : '';
			if ( in_array( $slug, self::$payment_addons, true ) ) {
				$feed = $candidate;
				break;
			}
		}

		if ( null === $feed ) {
			return array();
		}

		$meta = is_array( $feed['meta'] ) ? $feed['meta'] : array();

		// The operator has already mapped these fields so the gateway knows who
		// is paying. Reusing that mapping avoids a second, drift-prone mapping
		// UI of our own.
		$billing = array_filter(
			array(
				'recipient'          => trim( $this->mapped( $meta, 'billingInformation_first_name' ) . ' ' . $this->mapped( $meta, 'billingInformation_last_name' ) ),
				'locality'           => $this->mapped( $meta, 'billingInformation_city' ),
				'administrativeArea' => $this->mapped( $meta, 'billingInformation_state' ),
				'regionCode'         => $this->mapped( $meta, 'billingInformation_country' ),
				'postalCode'         => $this->mapped( $meta, 'billingInformation_zip' ),
			),
			static function ( $value ) {
				return '' !== $value;
			}
		);

		$line1 = $this->mapped( $meta, 'billingInformation_address' );
		if ( '' !== $line1 ) {
			$billing['address'] = array( $line1 );
		}

		if ( empty( $billing['regionCode'] ) || empty( $billing['postalCode'] ) ) {
			return array();
		}

		$total = $this->order_total( $form );
		if ( null === $total ) {
			return array();
		}

		$transaction = array(
			'paymentMethod'  => isset( $feed['addon_slug'] ) ? str_replace( 'gravityforms', '', (string) $feed['addon_slug'] ) : 'unknown',
			'currencyCode'   => class_exists( 'GFCommon' ) && method_exists( 'GFCommon', 'get_currency' ) ? GFCommon::get_currency() : '',
			'value'          => (float) $total,
			'billingAddress' => $billing,
		);

		$email = $this->mapped( $meta, 'billingInformation_email' );
		if ( '' !== $email ) {
			$transaction['user'] = array( 'email' => $email );
		}

		return array(
			'transactionData' => $transaction,
			'fraudPrevention' => 'ENABLED',
		);
	}

	/**
	 * Resolve a feed mapping to its submitted value.
	 *
	 * @param array  $meta Feed meta.
	 * @param string $key  Mapping key.
	 * @return string Submitted value, or ''.
	 */
	private function mapped( $meta, $key ) {
		if ( empty( $meta[ $key ] ) ) {
			return '';
		}

		$field_id = $meta[ $key ];

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Gravity Forms validates its own nonce before validation runs.
		$posted = isset( $_POST[ 'input_' . str_replace( '.', '_', (string) $field_id ) ] )
			// phpcs:ignore WordPress.Security.NonceVerification.Missing
			? sanitize_text_field( wp_unslash( $_POST[ 'input_' . str_replace( '.', '_', (string) $field_id ) ] ) )
			: '';

		return $posted;
	}

	/**
	 * Order total for the submission being validated.
	 *
	 * @param array $form Form definition.
	 * @return float|null Total, or null when it cannot be determined.
	 */
	private function order_total( $form ) {
		if ( ! class_exists( 'GFCommon' ) || ! method_exists( 'GFCommon', 'get_order_total' ) ) {
			return null;
		}

		// GFCommon::get_order_total() accepts the submitted values during
		// validation via GF's own field-value resolution.
		$total = GFCommon::get_order_total( $form, array() );

		return is_numeric( $total ) ? (float) $total : null;
	}

	/**
	 * Persist the assessment name and any fail-open flag onto the new entry.
	 *
	 * @param array $entry Entry.
	 * @param array $form  Form definition.
	 */
	public function store_entry_meta( $entry, $form ) {
		$form_id  = is_array( $form ) && isset( $form['id'] ) ? (int) $form['id'] : 0;
		$entry_id = is_array( $entry ) && isset( $entry['id'] ) ? (int) $entry['id'] : 0;

		if ( ! $entry_id || ! function_exists( 'gform_update_meta' ) ) {
			return;
		}

		if ( ! empty( $this->pending_assessment[ $form_id ] ) ) {
			gform_update_meta( $entry_id, self::META_ASSESSMENT, $this->pending_assessment[ $form_id ] );
		}

		if ( ! empty( $this->pending_unverified[ $form_id ] ) ) {
			// Flagged rather than silent: a real breakage in token generation
			// shows up as a burst of unverified entries instead of nothing.
			gform_update_meta( $entry_id, self::META_UNVERIFIED, '1' );
		}
	}

	/**
	 * Annotate the assessment as legitimate once payment completes.
	 *
	 * @param array $entry  Entry.
	 * @param array $action Payment action data.
	 */
	public function on_payment_completed( $entry, $action ) {
		$this->annotate( $entry, 'LEGITIMATE', 'PAYMENT' );
	}

	/**
	 * Annotate the assessment as fraudulent on refund or chargeback.
	 *
	 * @param array $entry  Entry.
	 * @param array $action Payment action data.
	 */
	public function on_payment_refunded( $entry, $action ) {
		$this->annotate( $entry, 'FRAUDULENT', 'REFUND' );
	}

	/**
	 * Send an annotation for an entry's stored assessment.
	 *
	 * @param array  $entry      Entry.
	 * @param string $annotation LEGITIMATE or FRAUDULENT.
	 * @param string $event_type transactionEvent eventType.
	 */
	private function annotate( $entry, $annotation, $event_type ) {
		$entry_id = is_array( $entry ) && isset( $entry['id'] ) ? (int) $entry['id'] : 0;

		if ( ! $entry_id || ! function_exists( 'gform_get_meta' ) || ! function_exists( 'gform_update_meta' ) ) {
			return;
		}
		if ( ! class_exists( 'GSWP_Transaction_Defense' ) ) {
			return;
		}
		if ( gform_get_meta( $entry_id, self::META_ANNOTATED ) ) {
			return;
		}

		$name = gform_get_meta( $entry_id, self::META_ASSESSMENT );
		if ( empty( $name ) ) {
			return;
		}

		$sent = GSWP_Transaction_Defense::annotate_assessment( (string) $name, $annotation, $event_type );
		if ( $sent ) {
			gform_update_meta( $entry_id, self::META_ANNOTATED, $annotation );
		}
	}

	/**
	 * Log to the WooCommerce logger when available.
	 *
	 * @param string $message Log message.
	 */
	private function log( $message ) {
		GSWP_Log::warning( $message );
	}

	/**
	 * Log a coverage gap at error level.
	 *
	 * A form being submitted unscored is the loudest thing this class has to
	 * say, and on a site without WooCommerce there is no log viewer to find it
	 * in — so it goes to the PHP error log and the in-database tail as well.
	 *
	 * @param string $message Log message.
	 */
	private function log_error( $message ) {
		GSWP_Log::error( $message );
	}
}
