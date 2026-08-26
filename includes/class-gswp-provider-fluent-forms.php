<?php
/**
 * Fluent Forms Provider
 *
 * Makes this plugin the reCAPTCHA implementation for Fluent Forms, to the same
 * specification as GSWP_Provider_Gravity_Forms.
 *
 * Like the Gravity Forms provider, it NEVER switches Fluent Forms' own captcha
 * off and never writes to a Fluent Forms option. Detection drives the coverage
 * report and the operator notice; retiring the host plugin's captcha is the
 * operator's action. Reads of Fluent Forms' settings go straight to the
 * database rather than through get_option(), so nothing this plugin does can
 * colour what it reports about another plugin.
 *
 * ---------------------------------------------------------------------------
 * VERIFICATION STATUS
 *
 * Every binding in this file has been read directly from installed source:
 * Fluent Forms 6.2.9 (free) and Fluent Forms Pro 6.2.7. Nothing here should
 * be treated as verified for a different major version — 2.23.1 shipped a
 * defect that traced back to exactly that assumption (an option's TYPE
 * outliving the version it was confirmed against; see raw_option()).
 *
 * `FluentForm\App\Modules\Form\FormHandler::onSubmit()` is DEAD CODE — the
 * live AJAX submission path is
 * `SubmissionHandler::submit() -> SubmissionHandlerService::handleSubmission()`
 * (app/Hooks/Ajax.php). Do not re-derive a binding from onSubmit(); it is
 * commented out at its only call site and none of its behaviour runs.
 *
 * Every host-plugin binding below still fails to the pessimistic answer where
 * source did not settle the question outright:
 *
 *   - a form we cannot inspect is ineligible, so we do not claim to cover it;
 *   - a form we cannot classify is treated as a PAYMENT form, so it fails
 *     closed rather than silently fails open on a real payment;
 *   - a User Registration feed row we cannot decode is treated as 'create',
 *     the stricter reading (account_feed_type() now reads the verified feed
 *     shape first and falls back to this only when no feed row parses);
 *   - unreadable billing mappings yield no transactionData, which
 *     GSWP_Verifier already degrades to a plain score rather than an API error.
 *
 * Three Fluent Forms specifics carry more weight than any hook name:
 *
 *   1. SUBMISSION TRANSPORT. Fluent Forms submits over AJAX and serialises the
 *      form into a single request parameter. VERIFIED:
 *      SubmissionHandlerService::prepareHandler() filters $formData down to
 *      registered fields plus a fixed allow-list
 *      (Helper::getWhiteListedFields()) before it ever reaches the
 *      validation filter — an unregistered, unwhitelisted key is dropped.
 *      register_hooks() therefore whitelists TOKEN_FIELD via
 *      fluentform/white_listed_fields (whitelist_token_field()), which is
 *      what makes submitted_token()'s first transport genuinely work rather
 *      than assumed to. Reading the token from the request is fine — it is
 *      request data. What is never request-derived is the ENFORCEMENT
 *      DECISION: form_is_strict() reads the stored form definition, so a
 *      caller cannot opt out by omitting a field (the bypass class removed
 *      in 2.17.0).
 *
 *   2. REJECTION VISIBILITY. Fluent Forms attaches validation errors to keys,
 *      and VERIFIED: any key that resolves to no field in the DOM is
 *      rendered through its error-stack fallback under both
 *      `errorMessagePlacement` settings (assets/js/form-submission.js). Our
 *      token field IS a resolvable key, and attaching a rejection to it
 *      renders nothing — the opposite of the earlier assumption. reject()
 *      therefore uses a deliberately unresolvable key (see ERROR_KEY), which
 *      Fluent Forms itself does for its own form-level errors ('restricted').
 *
 *   3. NO WHOLE-MARKUP FILTER. Fluent Forms has no equivalent of
 *      gform_get_form_filter, so the coverage backstop is a gated output
 *      buffer. VERIFIED: FormBuilder::render() wraps its own body in
 *      ob_start()/ob_get_clean() with the two render actions always paired
 *      inside it, which is why the nesting-level guard in
 *      close_backstop_buffer() has held. It only opens for a form whose
 *      primary injection point has already been observed to miss, and it
 *      refuses to close a buffer it does not own.
 * ---------------------------------------------------------------------------
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class GSWP_Provider_Fluent_Forms implements GSWP_Form_Provider {

	/**
	 * Name of the hidden token field injected into Fluent Forms forms.
	 *
	 * Distinct from the Gravity Forms provider's field so the two never collide
	 * on a page carrying both. Deliberately NOT 'g-recaptcha-response': that
	 * name is read by GSWP_Verifier for WooCommerce and may be read by Fluent
	 * Forms for its own reCAPTCHA field. The class attribute is what matters —
	 * the shared footer bootstrap fills every .g-recaptcha-response on the page.
	 */
	const TOKEN_FIELD = 'gswp_ff_token';

	/**
	 * The errors key a rejection message is delivered under.
	 *
	 * Deliberately a name that matches NO element in the form. Fluent Forms'
	 * inline renderer (assets/js/form-submission.js, S() -> j()) falls back
	 * to the .ff-errors-in-stack container for any key it cannot resolve to
	 * a DOM node, and the stack renderer displays every key unconditionally
	 * — so an unresolvable key is the one delivery that is visible under
	 * both `errorMessagePlacement` settings. Fluent Forms uses this exact
	 * mechanism itself: core's rate limiter and Pro's user-registration
	 * guard both key form-level errors to 'restricted', a name that matches
	 * no field either (FormValidationService::preventMaliciousAttacks(),
	 * Pro UserRegistration/Getter::resetErrormessage()).
	 *
	 * It must NOT be TOKEN_FIELD. That name DOES resolve, to our own hidden
	 * input, which sends the message down the branch that appends a <div>
	 * into an <input> — rendering nothing and leaving the visitor with a
	 * stopped spinner. The invisible-rejection failure reject() exists to
	 * prevent is reachable only by naming our own field.
	 */
	const ERROR_KEY = 'gswp_verification';

	/**
	 * Submission meta key holding the assessment resource name.
	 */
	const META_ASSESSMENT = 'gswp_assessment_name';

	/**
	 * Submission meta key flagging a submission admitted without a verified
	 * token (fail-open on a non-strict form).
	 */
	const META_UNVERIFIED = 'gswp_unverified';

	/**
	 * Submission meta key guarding against double annotation.
	 */
	const META_ANNOTATED = 'gswp_annotated';

	/**
	 * Option recording, per form, when a token field was last successfully
	 * injected on a real front-end render.
	 *
	 * What turns a coverage gap from silent into loud: a submission with no
	 * token on a form we have never injected into is our bug, not an attack,
	 * and must not be punished.
	 */
	const INJECTION_OPTION = 'gswp_ff_injection_log';

	/**
	 * Option recording, per form, why the last submission was rejected.
	 */
	const REJECTION_OPTION = 'gswp_ff_last_rejection';

	/**
	 * Option listing form ids that are never submitted by a visitor.
	 *
	 * An operator declaration, never inferred from the request. It suppresses
	 * exactly one thing — the missing-token alarm (coverage gap, error log,
	 * operator email) — and nothing else. A submission carrying a token is
	 * scored whatever this says, so the declaration is inert on any form a
	 * human can actually reach.
	 *
	 * The Gravity Forms provider learned this the hard way: its first cut made
	 * an internal form ineligible, which silently stripped bot scoring from a
	 * password-change form reachable in a browser. A reporting preference must
	 * never be able to remove protection.
	 */
	const INTERNAL_OPTION = 'gswp_ff_internal_forms';

	/**
	 * Field elements that mean the form quotes or takes money.
	 *
	 * VERIFIED against the component constructors in Fluent Forms 6.2.9 and
	 * Fluent Forms Pro 6.2.7. `has_payment` is the authoritative signal; this
	 * is the fallback for it being unreadable, and a form we cannot classify
	 * at all is still treated as a payment form.
	 *
	 * @var string[]
	 */
	private static $payment_elements = array(
		'payment_method',
		'custom_payment_component',
		'multi_payment_component',
		'subscription_payment_component',
		'item_quantity_component',
		'payment_summary_component',
		'stripe_inline',
		'square_inline',
		'payment_coupon',
	);

	/**
	 * Field elements that carry a password.
	 *
	 * @var string[]
	 */
	private static $password_elements = array( 'input_password' );

	/**
	 * Captcha field elements, mapped to the state they imply.
	 *
	 * Fluent Forms ships three challenge products. Only reCAPTCHA maps onto the
	 * states this plugin has an opinion about; hCaptcha and Turnstile are
	 * reported as 'other' — a captcha we neither provide nor recognise — which
	 * makes the form ineligible without misnaming the product to the operator.
	 *
	 * PARTIAL.
	 *
	 * @var array<string,string>
	 */
	private static $captcha_elements = array(
		'recaptcha' => 'recaptcha',
		'hcaptcha'  => 'other',
		'turnstile' => 'other',
	);

	/**
	 * Per-request cache of derived form data and classification.
	 *
	 * Classification runs on the render path as well as the validation path
	 * (the action a form's token is minted with depends on it) and each answer
	 * costs a query. A page with several forms would repeat those per render
	 * hook without this.
	 *
	 * @var array<string,array<int,mixed>>
	 */
	private $memo = array();

	/**
	 * Shared verifier.
	 *
	 * @var GSWP_Verifier|null
	 */
	private $verifier = null;

	/**
	 * Output-buffer nesting level recorded when a backstop buffer was opened,
	 * keyed by form id. Used to refuse to close a buffer we do not own.
	 *
	 * @var array<int,int>
	 */
	private $buffer_level = array();

	/**
	 * Assessment name captured during validation, awaiting a submission to
	 * store it on. Keyed by form id.
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
		return 'fluent-forms';
	}

	/**
	 * {@inheritDoc}
	 */
	public function label() {
		return 'Fluent Forms';
	}

	/**
	 * {@inheritDoc}
	 *
	 * Deliberately NOT a namespaced class_exists() alone. That is the Phase 45
	 * defect verbatim: an unqualified class_exists() against a namespaced class
	 * reported "not loaded" for an add-on that was active the whole time. A
	 * constant plus the presence of the forms table answers the question
	 * without needing to know Fluent Forms' internal namespace.
	 */
	public function is_active() {
		$cached = $this->memo_get( 'active', 0 );
		if ( null !== $cached ) {
			return $cached;
		}

		$loaded = defined( 'FLUENTFORM' )
			|| defined( 'FLUENTFORM_VERSION' )
			|| function_exists( 'wpFluentForm' )
			|| function_exists( 'fluentFormApi' );

		if ( ! $loaded ) {
			return $this->memo_set( 'active', 0, false );
		}

		return $this->memo_set( 'active', 0, '' !== $this->forms_table() );
	}

	/**
	 * Name of the Fluent Forms forms table, when it exists.
	 *
	 * @return string Table name, or '' when absent or unreadable.
	 */
	private function forms_table() {
		return $this->table( 'fluentform_forms' );
	}

	/**
	 * Resolve a Fluent Forms table name, confirming it exists.
	 *
	 * @param string $suffix Unprefixed table name.
	 * @return string Prefixed table name, or '' when absent.
	 */
	private function table( $suffix ) {
		global $wpdb;

		if ( ! $wpdb ) {
			return '';
		}

		$cached = $this->memo_get( 'table_' . $suffix, 0 );
		if ( null !== $cached ) {
			return (string) $cached;
		}

		$table = $wpdb->prefix . $suffix;
		$found = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL

		return (string) $this->memo_set( 'table_' . $suffix, 0, $found === $table ? $table : '' );
	}

	/**
	 * {@inheritDoc}
	 */
	public function forms() {
		global $wpdb;

		$table = $this->is_active() ? $this->forms_table() : '';
		if ( '' === $table ) {
			return array();
		}

		$rows = $wpdb->get_results( "SELECT id, title FROM {$table} ORDER BY id ASC", ARRAY_A ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL

		if ( ! is_array( $rows ) ) {
			return array();
		}

		$out = array();
		foreach ( $rows as $row ) {
			if ( ! isset( $row['id'] ) ) {
				continue;
			}
			$id         = (int) $row['id'];
			$out[ $id ] = isset( $row['title'] ) && '' !== $row['title'] ? (string) $row['title'] : ( '#' . $id );
		}

		return $out;
	}

	/**
	 * Fetch a form row, or null when unavailable.
	 *
	 * @param int|string $form_id Form identifier.
	 * @return array|null Row with 'id', 'title', 'has_payment', 'fields'.
	 */
	private function form( $form_id ) {
		global $wpdb;

		$cached = $this->memo_get( 'form', $form_id );
		if ( null !== $cached ) {
			return false === $cached ? null : $cached;
		}

		$table = $this->is_active() ? $this->forms_table() : '';
		if ( '' === $table ) {
			$this->memo_set( 'form', $form_id, false );

			return null;
		}

		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE id = %d LIMIT 1", (int) $form_id ), ARRAY_A ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL

		if ( ! is_array( $row ) ) {
			$this->memo_set( 'form', $form_id, false );

			return null;
		}

		$row['fields'] = $this->decode_fields( isset( $row['form_fields'] ) ? $row['form_fields'] : '' );

		return $this->memo_set( 'form', $form_id, $row );
	}

	/**
	 * Flatten a form's field definition into a list of leaf fields.
	 *
	 * Fluent Forms nests fields inside container elements (columns), so a flat
	 * read of the top level misses everything inside a multi-column row — which
	 * on a real form is most of it, including the payment and password fields
	 * this class classifies on.
	 *
	 * PARTIAL: the JSON shape ({"fields": [ { "element": ..., "attributes": {
	 * "name": ... }, "columns": [ { "fields": [...] } ] } ]}) follows Fluent
	 * Forms' documented field structure. An undecodable definition yields an
	 * empty list, which routes every caller to its pessimistic branch.
	 *
	 * @param string $json Raw form_fields JSON.
	 * @return array<int,array{element:string,name:string}> Leaf fields, in order.
	 */
	private function decode_fields( $json ) {
		if ( ! is_string( $json ) || '' === $json ) {
			return array();
		}

		$decoded = json_decode( $json, true );
		if ( ! is_array( $decoded ) ) {
			return array();
		}

		$fields = isset( $decoded['fields'] ) && is_array( $decoded['fields'] ) ? $decoded['fields'] : array();

		$out = array();
		$this->walk_fields( $fields, $out );

		return $out;
	}

	/**
	 * Recursive body of decode_fields().
	 *
	 * @param array $fields Field nodes.
	 * @param array $out    Accumulator, by reference.
	 * @param int   $depth  Recursion depth guard.
	 */
	private function walk_fields( $fields, &$out, $depth = 0 ) {
		// A malformed or hostile definition must not recurse without bound.
		if ( $depth > 10 || ! is_array( $fields ) ) {
			return;
		}

		foreach ( $fields as $field ) {
			if ( ! is_array( $field ) ) {
				continue;
			}

			$element = isset( $field['element'] ) ? (string) $field['element'] : '';
			$name    = isset( $field['attributes']['name'] ) ? (string) $field['attributes']['name'] : '';

			if ( '' !== $element ) {
				$out[] = array(
					'element' => $element,
					'name'    => $name,
				);
			}

			// Container: {"columns": [ { "fields": [ ... ] } ]}.
			if ( isset( $field['columns'] ) && is_array( $field['columns'] ) ) {
				foreach ( $field['columns'] as $column ) {
					if ( isset( $column['fields'] ) ) {
						$this->walk_fields( $column['fields'], $out, $depth + 1 );
					}
				}
			}

			// Step / repeater: {"fields": [ ... ]}.
			if ( isset( $field['fields'] ) && is_array( $field['fields'] ) ) {
				$this->walk_fields( $field['fields'], $out, $depth + 1 );
			}
		}
	}

	/**
	 * {@inheritDoc}
	 *
	 * A form is ineligible when it carries a challenge we have no equivalent
	 * for: a visible v2 checkbox, or an hCaptcha / Turnstile widget. Our
	 * implementation is score-only, so replacing those would change both the UX
	 * and the threat model. Those forms keep Fluent Forms' own captcha —
	 * partial takeover is a supported end state, not a failure.
	 *
	 * Also ineligible: a conversational form. VERIFIED against
	 * FluentConversational\Classes\Form::renderFormHtml() (both plugins) —
	 * it renders into a Vue view and fires NONE of form_element_start /
	 * before_form_render / after_form_render, so there is no hook this
	 * provider can inject a token field on. A prior version left these
	 * eligible, which meant every submission took the never-injected
	 * fail-open branch and logged a COVERAGE GAP forever, on a form that was
	 * never coverable in the first place. See native_captcha_state()'s
	 * 'unsupported' state.
	 *
	 * An internal form is deliberately still eligible. See INTERNAL_OPTION.
	 */
	public function form_is_eligible( $form_id ) {
		if ( null === $this->form( $form_id ) ) {
			// Cannot inspect it, so do not claim to cover it.
			return false;
		}

		return ! in_array( $this->native_captcha_state( $form_id ), array( 'v2', 'other', 'unsupported' ), true );
	}

	/**
	 * Whether a form is a Fluent Forms conversational form.
	 *
	 * VERIFIED: marked by fluentform_form_meta.meta_key = 'is_conversion_form'
	 * with value 'yes', read the same way Fluent Forms' own
	 * Helper::isConversionForm() does.
	 *
	 * @param int|string $form_id Form identifier.
	 * @return bool
	 */
	private function form_is_conversational( $form_id ) {
		$cached = $this->memo_get( 'conversational', $form_id );
		if ( null !== $cached ) {
			return $cached;
		}

		return $this->memo_set(
			'conversational',
			$form_id,
			'yes' === $this->form_meta_value( $form_id, 'is_conversion_form' )
		);
	}

	/**
	 * Whether a form is driven programmatically rather than submitted by a
	 * visitor.
	 *
	 * @param int|string $form_id Form identifier.
	 * @return bool
	 */
	public function form_is_internal( $form_id ) {
		$listed = get_option( self::INTERNAL_OPTION, array() );
		$listed = is_array( $listed ) ? array_map( 'intval', $listed ) : array();

		$internal = in_array( (int) $form_id, $listed, true );

		/**
		 * Filter whether a Fluent Form is internal (never publicly submitted).
		 *
		 * @param bool $internal Whether the form is internal.
		 * @param int  $form_id  Form identifier.
		 */
		return (bool) apply_filters( 'gswp_ff_form_is_internal', $internal, (int) $form_id );
	}

	/**
	 * {@inheritDoc}
	 *
	 * Deliberately biased toward "yes". A form wrongly classified as payment
	 * fails closed on a missing token, which is an inconvenience. A payment
	 * form wrongly classified as non-payment fails open, which is a hole.
	 *
	 * Fluent Forms is easier here than Gravity Forms: the forms table carries a
	 * has_payment column, which is a direct answer where GF has to sniff add-on
	 * slugs. The field scan is kept as a fallback for the column being absent
	 * on an older schema.
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

		// PARTIAL: `has_payment` is documented on the fluentform_forms schema.
		// Present and truthy is authoritative; present and falsy still falls
		// through to the field scan, because a column we have misread must not
		// be able to clear a form that plainly contains a payment field.
		if ( isset( $form['has_payment'] ) && (int) $form['has_payment'] > 0 ) {
			return true;
		}

		foreach ( $form['fields'] as $field ) {
			if ( in_array( $field['element'], self::$payment_elements, true ) ) {
				return true;
			}
		}

		// A form whose fields could not be read at all is unclassifiable, and
		// unclassifiable means payment. An empty definition on a form row that
		// does exist is the signal that decode_fields() failed.
		if ( empty( $form['fields'] ) ) {
			return true;
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
	 * submitting it, so reCAPTCHA here is defence in depth, not the gate — see
	 * form_is_strict().
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
	 * VERIFIED against Fluent Forms Pro 6.2.7 source. Both feed kinds are
	 * stored under ONE meta_key, `user_registration_feeds`
	 * (FormIntegrationService::update(), `$metaKey = $integrationName . '_feeds'`).
	 * The discriminator is the `list_id` key inside the feed's JSON value, and
	 * the vendor's own test for it is
	 * `Arr::isTrue($feed,'enabled') && Arr::get($feed,'list_id') === 'user_update'`
	 * (UserUpdateFormHandler::isValidFeed()). Registration is the default
	 * branch: anything that is not `'user_update'` registers.
	 *
	 * A prior version of this method scanned for a meta_key CONTAINING
	 * 'user_registration' or 'user_update' and guessed the discriminator from
	 * four candidate keys (feedType, feed_type, userRegistrationType, type).
	 * None of those exists. Because both feed kinds share one meta_key, that
	 * scan read a User Update feed's row as a registration feed on every
	 * install — form_is_strict() then rejects a signed-in visitor's own
	 * profile edit on a missing token. Fixed by reading `list_id`.
	 *
	 * `_has_user_registration` / `_has_user_update` (read by Fluent Forms core
	 * itself, and consulted here as a fallback) are STICKY: written when a
	 * feed is saved, never cleared, and blind to `enabled`. They over-report,
	 * which is safe for a fallback and wrong for a primary signal — hence the
	 * feed rows are read first and the flags are only consulted when no feed
	 * row could be read at all.
	 *
	 * A form carrying both an active registration feed and an active update
	 * feed is a supported Fluent Forms configuration, and which behaviour
	 * fires depends on whether the visitor is logged in (core gates
	 * registration errors on `!get_current_user_id()` and update errors on
	 * `get_current_user_id()`). is_user_logged_in() here is not request data
	 * in the 2.17.0 sense — it is WordPress's authenticated identity from a
	 * verified auth cookie, not a value the submitter can assert — so mirroring
	 * the host's own gate does not reopen that bypass class.
	 *
	 * Feed `conditionals` are deliberately NOT evaluated: they are resolved
	 * against submitted data, and the enforcement decision may not be read
	 * from the request. A conditional feed counts as active.
	 *
	 * @param int|string $form_id Form identifier.
	 * @return string 'create', 'update', or '' when the form touches no account.
	 */
	private function account_feed_type( $form_id ) {
		$logged_in = is_user_logged_in();
		$bucket    = 'account_feed_type_' . ( $logged_in ? 'in' : 'out' );

		$cached = $this->memo_get( $bucket, $form_id );
		if ( null !== $cached ) {
			return $cached;
		}

		$creates  = false;
		$updates  = false;
		$saw_feed = false;

		foreach ( $this->form_meta_rows( $form_id ) as $row ) {
			if ( ! isset( $row['meta_key'] ) || 'user_registration_feeds' !== (string) $row['meta_key'] ) {
				continue;
			}

			$feed = json_decode( isset( $row['value'] ) ? (string) $row['value'] : '', true );

			if ( ! is_array( $feed ) ) {
				// A feed row we cannot read is a feed we must assume creates.
				$saw_feed = true;
				$creates  = true;
				continue;
			}

			$saw_feed = true;

			// A disabled feed does nothing. An unreadable enabled flag is
			// treated as enabled, which is the stricter reading.
			if ( array_key_exists( 'enabled', $feed ) && ! $feed['enabled'] ) {
				continue;
			}

			// VERIFIED: FluentFormPro\Integrations\UserRegistration\
			// UserUpdateFormHandler::isValidFeed(). 'user_update' is the only
			// special value; everything else registers, which matches the
			// vendor's own direction and keeps an unrecognised future value
			// on the stricter answer.
			if ( isset( $feed['list_id'] ) && 'user_update' === $feed['list_id'] ) {
				$updates = true;
			} else {
				$creates = true;
			}
		}

		if ( ! $saw_feed ) {
			// No readable feed rows. Fall back to the flags core itself reads
			// (FormValidationService::validateSubmission()). Sticky and
			// enabled-blind, so this branch only runs when nothing better
			// is available.
			$creates = 'yes' === $this->form_meta_value( $form_id, '_has_user_registration' );
			$updates = 'yes' === $this->form_meta_value( $form_id, '_has_user_update' );
		}

		if ( $creates && $updates ) {
			$type = $logged_in ? 'update' : 'create';
		} elseif ( $creates ) {
			$type = 'create';
		} elseif ( $updates ) {
			$type = 'update';
		} else {
			$type = '';
		}

		return $this->memo_set( $bucket, $form_id, $this->filter_account_type( $type, $form_id ) );
	}

	/**
	 * A single fluentform_form_meta value for a form, by meta_key.
	 *
	 * @param int|string $form_id  Form identifier.
	 * @param string     $meta_key Meta key to find.
	 * @return string Value, or '' when the key is absent or unreadable.
	 */
	private function form_meta_value( $form_id, $meta_key ) {
		foreach ( $this->form_meta_rows( $form_id ) as $row ) {
			if ( isset( $row['meta_key'] ) && (string) $row['meta_key'] === $meta_key ) {
				return isset( $row['value'] ) && is_scalar( $row['value'] ) ? (string) $row['value'] : '';
			}
		}

		return '';
	}

	/**
	 * Every fluentform_form_meta row for a form.
	 *
	 * @param int|string $form_id Form identifier.
	 * @return array<int,array<string,mixed>> Rows, or empty when unreadable.
	 */
	private function form_meta_rows( $form_id ) {
		global $wpdb;

		$cached = $this->memo_get( 'form_meta', $form_id );
		if ( null !== $cached ) {
			return $cached;
		}

		$table = $this->table( 'fluentform_form_meta' );
		if ( '' === $table ) {
			return $this->memo_set( 'form_meta', $form_id, array() );
		}

		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT meta_key, value FROM {$table} WHERE form_id = %d", (int) $form_id ), ARRAY_A ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL

		return $this->memo_set( 'form_meta', $form_id, is_array( $rows ) ? $rows : array() );
	}

	/**
	 * Let a site correct a form's account classification.
	 *
	 * The feed binding is unverified and misreading it is not cosmetic: a
	 * profile-edit form mistaken for a signup is scored under the stricter
	 * threshold and rejected outright when its token is missing. A site that
	 * hits this should not have to wait for a release:
	 *
	 *     add_filter( 'gswp_ff_account_feed_type', function ( $type, $form_id ) {
	 *         return in_array( $form_id, array( 7, 9 ), true ) ? 'update' : $type;
	 *     }, 10, 2 );
	 *
	 * Returning anything other than 'create' or 'update' means "this form
	 * touches no account". Every return path in account_feed_type() routes
	 * through here, including the 'create' fallback — which is the one an
	 * affected site would actually need to override.
	 *
	 * @param string $type    Derived type: 'create', 'update', or ''.
	 * @param int    $form_id Form identifier.
	 * @return string Filtered type.
	 */
	private function filter_account_type( $type, $form_id ) {
		$filtered = apply_filters( 'gswp_ff_account_feed_type', $type, (int) $form_id );

		return in_array( $filtered, array( 'create', 'update' ), true ) ? $filtered : '';
	}

	/**
	 * {@inheritDoc}
	 *
	 * Fail closed on anything that moves money or creates an account. Neither a
	 * contact form entry nor a signed-in user editing her own profile warrants
	 * it — WordPress has already authenticated her, and locking her out of her
	 * own account details is worse than admitting one unscored edit.
	 */
	public function form_is_strict( $form_id ) {
		return $this->form_has_payment( $form_id ) || $this->form_creates_account( $form_id );
	}

	/**
	 * Whether a form sets or changes a password.
	 *
	 * Read from the stored form definition, never the request. A password field
	 * is the signal: whether the change lands via an integration feed or the
	 * site's own handler, the form is a credential-changing surface either way.
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
		if ( null === $form ) {
			return $this->memo_set( 'password', $form_id, false );
		}

		foreach ( $form['fields'] as $field ) {
			if ( in_array( $field['element'], self::$password_elements, true ) ) {
				return $this->memo_set( 'password', $form_id, true );
			}
		}

		return $this->memo_set( 'password', $form_id, false );
	}

	/**
	 * The reCAPTCHA action a form's token is minted with and checked against.
	 *
	 * ONE resolver, called from both token_field() (which labels the token in
	 * the browser) and validate_submission() (which tells Google what to
	 * expect).
	 *
	 * This is not a stylistic preference. In 2.22.0 the Gravity Forms provider
	 * decided the action twice, in two separate ternaries, and they disagreed:
	 * a non-payment form with a User Registration feed rendered 'submit' but was
	 * validated as 'register'. Enterprise assessments reject on expectedAction
	 * mismatch before scoring, so every submission of every account form failed,
	 * for every visitor, with a message accusing them of being spam. The fix
	 * was not to correct one of the two expressions — it was to have only one.
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
	 * Action names accepted for a form's token.
	 *
	 * Exactly one, unlike the Gravity Forms provider. Its extra allowance
	 * exists only to tolerate pages cached under 2.21.1, which rendered a
	 * different action; this provider has no prior release and therefore no
	 * stale pages to forgive.
	 *
	 * @param int|string $form_id Form identifier.
	 * @return string[] Accepted actions.
	 */
	private function accepted_actions( $form_id ) {
		return array( $this->action_for( $form_id ) );
	}

	/**
	 * The threshold context for a form.
	 *
	 * Deliberately its own set of options rather than sharing the Gravity Forms
	 * ones. A site tuning its Gravity Forms registration threshold must not
	 * silently retune Fluent Forms — that is the same defect 2.22.0 fixed when
	 * GF forms stopped borrowing gswp_threshold_wp_register.
	 *
	 * @param int|string $form_id Form identifier.
	 * @return string Context, resolving to option "gswp_threshold_{context}".
	 */
	private function context_for( $form_id ) {
		if ( $this->form_has_payment( $form_id ) ) {
			return 'checkout';
		}
		if ( $this->form_creates_account( $form_id ) ) {
			return 'ff_register';
		}
		if ( $this->form_changes_password( $form_id ) ) {
			return 'ff_password';
		}
		if ( $this->form_updates_account( $form_id ) ) {
			return 'ff_account_update';
		}

		return 'ff_submit';
	}

	/**
	 * Read a memoized value.
	 *
	 * @param string     $bucket  Cache bucket.
	 * @param int|string $form_id Form identifier.
	 * @return mixed Cached value, or null on a miss.
	 */
	private function memo_get( $bucket, $form_id ) {
		return isset( $this->memo[ $bucket ][ (int) $form_id ] ) ? $this->memo[ $bucket ][ (int) $form_id ] : null;
	}

	/**
	 * Store a memoized value.
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
	 * Returns 'other' for a challenge that is neither ours nor Google's.
	 * Fluent Forms ships reCAPTCHA, hCaptcha and Turnstile, configured
	 * identically, and none of 'off' / 'v3' / 'v2' / 'unknown' can express the
	 * latter two: 'off' would be a lie, 'v2' misnames the product to an
	 * operator who then goes looking for reCAPTCHA settings that do not exist,
	 * and 'unknown' would leave the form eligible so we would take over a form
	 * that is also running Turnstile.
	 *
	 * Returns 'unsupported' for a conversational form — see
	 * form_is_conversational(). Checked first: a conversational form's field
	 * definition is irrelevant, because there is no hook to inject into.
	 *
	 * VERIFIED against FormValidationService::validateReCaptcha() /
	 * validateHCaptcha() / validateTurnstile() in Fluent Forms 6.2.9: a
	 * challenge is validated, and therefore live, if and only if the form
	 * carries the field OR the corresponding `fluentform/has_recaptcha` /
	 * `fluentform/has_hcaptcha` / `fluentform/has_turnstile` auto-include
	 * filter returns true. A prior version fell back to reporting the SITE'S
	 * global reCAPTCHA configuration whenever a form had no captcha field —
	 * so a site with reCAPTCHA v2 keys saved (extremely common; saved once
	 * and left) reported 'v2' for every form on the site, making all of them
	 * ineligible with no field anywhere explaining why. Fluent Forms' own gate
	 * makes 'off' provable rather than assumed, once the auto-include filters
	 * are also read.
	 *
	 * Reading `fluentform/has_recaptcha` etc. is a read of another plugin's
	 * filter, not a write, and registers nothing — it cannot change host
	 * behaviour, only what this method reports about it.
	 */
	public function native_captcha_state( $form_id ) {
		if ( $this->form_is_conversational( $form_id ) ) {
			return 'unsupported';
		}

		$form = $this->form( $form_id );
		if ( null === $form ) {
			return 'unknown';
		}

		$found = array(
			'recaptcha' => false,
			'other'     => false,
		);

		foreach ( $form['fields'] as $field ) {
			if ( ! isset( self::$captcha_elements[ $field['element'] ] ) ) {
				continue;
			}

			$found[ self::$captcha_elements[ $field['element'] ] ] = true;
		}

		if ( $found['other'] || $this->native_auto_include( 'hcaptcha' ) || $this->native_auto_include( 'turnstile' ) ) {
			return 'other';
		}

		$has_recaptcha = $found['recaptcha'] || $this->native_auto_include( 'recaptcha' );

		if ( ! $has_recaptcha ) {
			// Fluent Forms' own gate proves no challenge validates on this
			// form. 'off' is no longer an assumption.
			return 'off';
		}

		$settings = $this->native_recaptcha_settings();

		// A reCAPTCHA field or auto-include is a rendered widget. Whether it is
		// a visible challenge depends on the configured version, and an
		// unreadable version must not be assumed invisible.
		return 'v3' === $this->native_recaptcha_version( $settings ) ? 'v3' : 'v2';
	}

	/**
	 * Whether Fluent Forms will validate a captcha on every form regardless
	 * of whether the field is present, via its auto-include filter.
	 *
	 * VERIFIED: `apply_filters('fluentform/has_recaptcha', false)` and its
	 * hCaptcha / Turnstile equivalents, read in
	 * FormValidationService::validateReCaptcha() etc. A read of another
	 * plugin's filter; registers nothing, changes no host behaviour.
	 *
	 * @param string $type 'recaptcha', 'hcaptcha', or 'turnstile'.
	 * @return bool
	 */
	private function native_auto_include( $type ) {
		return (bool) apply_filters( 'fluentform/has_' . $type, false );
	}

	/**
	 * Fluent Forms' stored reCAPTCHA settings.
	 *
	 * VERIFIED against GlobalSettingsHelper::storeReCaptcha() in Fluent Forms
	 * 6.2.9: option name `_fluentform_reCaptcha_details`, stored as a PHP
	 * array (`update_option(..., $captchaData, 'no')`, never an object), with
	 * keys `siteKey`, `secretKey`, `api_version`. The other two candidates are
	 * retained as tolerance for a version this was not verified against.
	 * Filterable so a site can correct it without a code change.
	 *
	 * @return array Settings array, or empty when none found.
	 */
	private function native_recaptcha_settings() {
		$cached = $this->memo_get( 'native_recaptcha', 0 );
		if ( null !== $cached ) {
			return $cached;
		}

		$candidates = (array) apply_filters(
			'gswp_ff_native_captcha_options',
			array(
				'_fluentform_reCaptcha_details',
				'_fluentform_recaptcha_details',
				'fluentform_reCaptcha_details',
			)
		);

		foreach ( $candidates as $option ) {
			$settings = $this->raw_option( $option );
			if ( is_array( $settings ) && array() !== $settings ) {
				return $this->memo_set( 'native_recaptcha', 0, $settings );
			}
		}

		return $this->memo_set( 'native_recaptcha', 0, array() );
	}

	/**
	 * Which reCAPTCHA version Fluent Forms has configured.
	 *
	 * VERIFIED: the version lives at `api_version`, with exactly two literal
	 * values — `'v2_visible'` and `'v3_invisible'`
	 * (GlobalSettingsHelper::storeReCaptcha(), FormBuilder Recaptcha
	 * component). The other candidate keys and the substring match against
	 * 'v3'/'invisible'/'v2'/'checkbox' are kept as tolerance for a version
	 * this was not verified against; the two literal values are the expected
	 * path, not this fallback.
	 *
	 * @param array $settings Stored settings.
	 * @return string 'v2', 'v3', or ''.
	 */
	private function native_recaptcha_version( $settings ) {
		if ( ! is_array( $settings ) || array() === $settings ) {
			return '';
		}

		$has_key = false;
		foreach ( array( 'siteKey', 'site_key', 'secretKey', 'secret_key' ) as $key ) {
			if ( ! empty( $settings[ $key ] ) ) {
				$has_key = true;
				break;
			}
		}

		if ( ! $has_key ) {
			return '';
		}

		foreach ( array( 'api_version', 'apiVersion', 'version', 'type' ) as $key ) {
			if ( ! isset( $settings[ $key ] ) || ! is_scalar( $settings[ $key ] ) ) {
				continue;
			}

			$value = strtolower( (string) $settings[ $key ] );

			if ( false !== strpos( $value, 'v3' ) || false !== strpos( $value, 'invisible' ) ) {
				return 'v3';
			}
			if ( false !== strpos( $value, 'v2' ) || false !== strpos( $value, 'checkbox' ) ) {
				return 'v2';
			}
		}

		// Keys are configured but the version is unreadable. Report v2, the
		// answer that makes the form ineligible and leaves Fluent Forms' own
		// captcha running — an unverifiable answer must degrade to "we do not
		// cover this form", which loses no protection.
		return 'v2';
	}

	/**
	 * Read one of Fluent Forms' settings options straight from the database.
	 *
	 * Bypasses get_option(), and therefore bypasses every filter, ours or
	 * anyone else's. Reporting on another plugin's settings must not pass
	 * through anything that could colour it.
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

		// Fluent Forms stores some settings as JSON inside the option value.
		if ( is_string( $value ) ) {
			$decoded = json_decode( $value, true );
			$value   = is_array( $decoded ) ? $decoded : null;
		}

		// ...and some as a serialized OBJECT rather than an array.
		//
		// VERIFIED on Fluent Forms 6.2.9 (chunk 23):
		// `__fluentform_payment_module_settings` unserializes to a stdClass.
		// Before this branch existed, every such option fell past both cases
		// above and returned null — so a reCAPTCHA configuration stored as an
		// object would have made native_captcha_state() report 'unknown' for a
		// captcha that was configured all along, and form_is_eligible() would
		// then have let this plugin take the form over.
		//
		// That is the Phase 43/44 failure mode word for word: detection reading
		// "not configured" for a host plugin that was configured, because we
		// looked in a shape it does not use. It reached a request path here
		// because the reads were written against an option we had confirmed by
		// NAME without ever confirming its TYPE.
		//
		// Round-tripped through JSON rather than cast, so nested objects
		// flatten too — a shallow (array) cast would leave the second level as
		// stdClass and reintroduce the same silence one key deeper.
		if ( is_object( $value ) ) {
			$encoded = wp_json_encode( $value );
			$value   = is_string( $encoded ) ? json_decode( $encoded, true ) : null;
		}

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

		// VERIFIED against FormBuilder::render() in Fluent Forms 6.2.9:
		// fluentform/form_element_start runs before the form's input elements
		// are rendered, so echoing here places our field inside the <form>.
		// Chunk 21 confirms it fires on every render path. Gutenberg
		// (GutenbergBlock::render()), Elementor (FluentFormWidget) and Pro's
		// form modal (classes/FormModal.php) all emit
		// do_shortcode('[fluentform ...]'), so all three route through this
		// same FormBuilder::render() call. A conversational form does NOT —
		// see form_is_conversational() — and is excluded at the eligibility
		// check rather than relied on to reach this hook.
		add_action( 'fluentform/form_element_start', array( $this, 'inject_token_field' ), 10, 1 );

		// Coverage backstop. Fluent Forms has no equivalent of Gravity Forms'
		// gform_get_form_filter — no filter receives the finished form HTML —
		// so the backstop is an output buffer. It is deliberately narrow: see
		// open_backstop_buffer(). VERIFIED: FormBuilder::render() itself wraps
		// its own body in ob_start()/ob_get_clean() with both of these actions
		// fired inside that buffer and always paired, which is why the
		// nesting-level guard in close_backstop_buffer() has held.
		add_action( 'fluentform/before_form_render', array( $this, 'open_backstop_buffer' ), 1, 1 );
		add_action( 'fluentform/after_form_render', array( $this, 'close_backstop_buffer' ), 999, 1 );

		// VERIFIED: fluentform/validation_errors is Fluent Forms' canonical
		// validation filter (FormValidationService::validateSubmission()),
		// firing unconditionally as ($errors, $formData, $form, $fields).
		add_filter( 'fluentform/validation_errors', array( $this, 'validate_submission' ), 20, 4 );

		// Register our token field on Fluent Forms' own submission allow-list.
		// See whitelist_token_field() for why this is required, not optional.
		add_filter( 'fluentform/white_listed_fields', array( $this, 'whitelist_token_field' ), 10, 2 );

		// Persist the assessment name and any fail-open flag onto the entry.
		add_action( 'fluentform/submission_inserted', array( $this, 'store_submission_meta' ), 10, 3 );

		// Payment lifecycle -> Transaction Defense annotation. One hook covers
		// both directions, unlike Gravity Forms' pair.
		//
		// VERIFIED against BaseProcessor::changeSubmissionPaymentStatus() in
		// both Fluent Forms and Fluent Forms Pro: TWO arguments, status FIRST
		// — do_action('fluentform/after_payment_status_change', $newStatus,
		// $this->getSubmission()). A prior version registered this with 5
		// arguments in Gravity-Forms order ($submission, $transaction,
		// $form_id, $old_status, $new_status), so $submission received the
		// status string and $new_status was always '' — annotate() was never
		// once entered and nothing about it crashed to say so.
		add_action( 'fluentform/after_payment_status_change', array( $this, 'on_payment_status_change' ), 10, 2 );
	}

	/**
	 * Echo the hidden token field inside the form element.
	 *
	 * @param object|array $form Fluent Forms form object.
	 */
	public function inject_token_field( $form ) {
		$form_id = $this->form_id_of( $form );

		if ( ! $form_id || ! GSWP_Recaptcha_Loader::will_load() || ! $this->form_is_eligible( $form_id ) ) {
			return;
		}

		// Shares the page's single loader (2.18.0) and the footer bootstrap,
		// which fills every .g-recaptcha-response and refreshes it before the
		// 120-second expiry. No provider-specific JavaScript.
		//
		// Two parts of that bootstrap are load-bearing for Fluent Forms in a way
		// they never were for Gravity Forms, and neither is obvious from here:
		//
		//  - the MutationObserver, which populates a form rendered into the DOM
		//    after page load — in a modal, or by a conditional;
		//  - the post-submit token replacement added in 2.22.1. v3 tokens are
		//    single-use and a Fluent Form never leaves the page, so without it a
		//    visitor whose first submission was rejected for ANY reason would be
		//    rejected again on every retry for up to 100 seconds while Google
		//    returned DUPE. That is not a nicety this provider benefits from; it
		//    is a prerequisite, and it would have surfaced as a defect here.
		//
		// Neither is safe to weaken on the grounds that "the form plugin handles
		// it" — nothing in Fluent Forms knows this field exists.
		GSWP_Recaptcha_Loader::enqueue();

		$this->record_injection( $form_id );

		echo $this->token_field( $form_id ); // phpcs:ignore WordPress.Security.EscapingOutput.OutputNotEscaped -- token_field() escapes every interpolated value.
	}

	/**
	 * Open an output buffer around a form render, as a coverage backstop.
	 *
	 * Only for a form whose primary injection point has already been observed
	 * to miss. Buffering a third-party render is more invasive than a filter
	 * and can be left unbalanced by a fatal inside the render, so it is not the
	 * default path — it is the recovery path for a render route we failed to
	 * hook, which without a staged rollout has to be caught here rather than in
	 * the logs six weeks from now.
	 *
	 * @param object|array $form Fluent Forms form object.
	 */
	public function open_backstop_buffer( $form ) {
		$form_id = $this->form_id_of( $form );

		if ( ! $form_id || ! GSWP_Recaptcha_Loader::will_load() || ! $this->form_is_eligible( $form_id ) ) {
			return;
		}

		// The primary hook has worked for this form before, so there is nothing
		// to recover and no reason to buffer.
		if ( $this->last_injection( $form_id ) > 0 ) {
			return;
		}

		if ( ! ob_start() ) {
			return;
		}

		$this->buffer_level[ $form_id ] = ob_get_level();
	}

	/**
	 * Close the backstop buffer, injecting the field if the render did not.
	 *
	 * Refuses to close a buffer it does not own. If the nesting level does not
	 * match what we opened, something else opened or closed a buffer inside the
	 * form render, and unwinding blindly would emit a partial page. Reporting a
	 * coverage gap is the honest outcome.
	 *
	 * @param object|array $form Fluent Forms form object.
	 */
	public function close_backstop_buffer( $form ) {
		$form_id = $this->form_id_of( $form );

		if ( ! $form_id || ! isset( $this->buffer_level[ $form_id ] ) ) {
			return;
		}

		$expected = $this->buffer_level[ $form_id ];
		unset( $this->buffer_level[ $form_id ] );

		$level = ob_get_level();

		if ( $level !== $expected ) {
			// Something inside the render opened or closed a buffer of its own.
			// We can no longer identify our own content, so we inject nothing —
			// but we must still leave the buffer stack as we found it. Simply
			// returning here would abandon our own open buffer and swallow the
			// rest of the page, which is a far worse outcome than the missing
			// token field this branch exists to report.
			while ( ob_get_level() >= $expected ) {
				if ( ! ob_end_flush() ) {
					break;
				}
			}

			$this->log_error(
				sprintf(
					'COVERAGE GAP: Fluent Forms #%d changed the output buffer nesting during render (expected level %d, found %d), so this plugin could not safely inject a reCAPTCHA token field. The form may be submitted unscored.',
					$form_id,
					$expected,
					$level
				)
			);
			do_action( 'gswp_form_coverage_gap', $this->id(), $form_id );

			return;
		}

		$markup = ob_get_clean();
		if ( ! is_string( $markup ) ) {
			return;
		}

		// The primary hook fired after all; nothing to do.
		if ( false !== strpos( $markup, 'name="' . self::TOKEN_FIELD . '"' ) ) {
			echo $markup; // phpcs:ignore WordPress.Security.EscapingOutput.OutputNotEscaped -- unmodified third-party markup, passed through.

			return;
		}

		$close = strripos( $markup, '</form>' );
		if ( false === $close ) {
			$this->log_error(
				sprintf(
					'COVERAGE GAP: Fluent Forms #%d rendered without a closing form tag, so no reCAPTCHA token field could be injected.',
					$form_id
				)
			);
			do_action( 'gswp_form_coverage_gap', $this->id(), $form_id );

			echo $markup; // phpcs:ignore WordPress.Security.EscapingOutput.OutputNotEscaped -- unmodified third-party markup, passed through.

			return;
		}

		GSWP_Recaptcha_Loader::enqueue();
		$this->record_injection( $form_id );

		echo substr( $markup, 0, $close ) // phpcs:ignore WordPress.Security.EscapingOutput.OutputNotEscaped -- unmodified third-party markup, passed through.
			. $this->token_field( $form_id ) // phpcs:ignore WordPress.Security.EscapingOutput.OutputNotEscaped -- token_field() escapes every interpolated value.
			. substr( $markup, $close ); // phpcs:ignore WordPress.Security.EscapingOutput.OutputNotEscaped -- unmodified third-party markup, passed through.
	}

	/**
	 * The hidden token field markup for a form.
	 *
	 * @param int $form_id Form id.
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
	 * Extract a form id from whatever Fluent Forms hands a hook.
	 *
	 * PARTIAL: Fluent Forms passes its form as an object with an `id` property
	 * on the render hooks. Accepting an array and a bare id as well costs
	 * nothing and means a shape change does not silently disable injection —
	 * which is the failure mode that would leave forms live and unscored.
	 *
	 * @param mixed $form Form object, array, or id.
	 * @return int Form id, or 0 when it cannot be determined.
	 */
	private function form_id_of( $form ) {
		if ( is_object( $form ) && isset( $form->id ) ) {
			return (int) $form->id;
		}
		if ( is_array( $form ) && isset( $form['id'] ) ) {
			return (int) $form['id'];
		}
		if ( is_scalar( $form ) && is_numeric( $form ) ) {
			return (int) $form;
		}

		return 0;
	}

	/**
	 * Add our token field to Fluent Forms' own submission allow-list.
	 *
	 * VERIFIED: SubmissionHandlerService::prepareHandler() ends with
	 * `array_intersect_key($formData, $fields + array_flip(Helper::
	 * getWhiteListedFields($formId)))` — $formData is filtered down to
	 * REGISTERED FIELDS plus this fixed allow-list, and nothing else
	 * survives. A prior version of submitted_token() claimed our field
	 * arrived in $formData unfiltered, reasoning from two allow-listed keys
	 * (`_wp_http_referer`, the per-form nonce) observed in a capture — those
	 * are the two NAMED exceptions, not evidence that unregistered keys
	 * survive. gswp_ff_token has never once reached transport 1 through this
	 * filter; only registering it here makes that transport genuinely true.
	 *
	 * This is a read-path filter, not a settings write: nothing is persisted
	 * into Fluent Forms' own options or tables, so the "never write to
	 * another plugin's settings" rule is untouched. Fluent Forms Pro uses
	 * this exact filter for its own submitted keys
	 * (UserUpdateFormHandler::addWhiteListedFields()), which is the closest
	 * thing to a vendor endorsement of the approach available from source.
	 *
	 * Only whitelisted on an eligible form. Whitelisting unconditionally
	 * would register the field on a form we have declared out of scope (a v2
	 * checkbox form, a conversational form), which is pointless and, for a
	 * conversational form, would whitelist a field that is never rendered.
	 *
	 * Cost, stated rather than discovered later: a whitelisted key is
	 * included in $formData, which prepareInsertData() JSON-encodes into
	 * fluentform_submissions.response. The spent token is therefore stored
	 * on the entry — not displayed (SubmissionService::getSubmission()
	 * strips whitelisted fields before display) and inert: a v3 token is
	 * single-use and expires in 120 seconds. A deliberate trade for
	 * determinism over the private shape of $_POST['data'].
	 *
	 * @param mixed      $fields  Current whitelist.
	 * @param int|string $form_id Form identifier.
	 * @return array Filtered whitelist.
	 */
	public function whitelist_token_field( $fields, $form_id ) {
		$fields = is_array( $fields ) ? $fields : array();

		if ( $this->form_is_eligible( $form_id ) ) {
			$fields[] = self::TOKEN_FIELD;
		}

		return $fields;
	}

	/**
	 * The submitted reCAPTCHA token, from whichever transport carried it.
	 *
	 * VERIFIED on Fluent Forms 6.2.9 by capturing a real submission
	 * (chunk 22):
	 *
	 *   $_POST keys    : fluent_forms_admin_nonce, data, action, form_id
	 *   parsed $formData: __fluent_form_embded_post_id,
	 *                     _fluentform_3_fluentformnonce, _wp_http_referer,
	 *                     name_1, email_2, phone_5, comments_3,
	 *                     newsletter_signup_4
	 *
	 * Transport 1 — $form_data[TOKEN_FIELD] — is now the live one, because
	 * register_hooks() whitelists our field via
	 * fluentform/white_listed_fields (see whitelist_token_field()).
	 *
	 * RETRACTED, and recorded rather than deleted: this method previously
	 * claimed transport 1 already worked, reasoning that $formData carried
	 * two keys ($_wp_http_referer, the per-form nonce) that are not
	 * registered fields, and concluding the whole payload survives
	 * unfiltered. It does not — those two keys are on Fluent Forms' own
	 * allow-list by name (Helper::getWhiteListedFields()), and our field was
	 * never on it. Transport 1 returned empty on every submission, every
	 * form, from the day it was written; transport 2 caught it one line
	 * later, which is why nothing surfaced. The observation "the payload
	 * contains keys that are not fields" is not proof that ALL non-field
	 * keys survive — it is proof that the two enumerated ones do.
	 *
	 * Transports 2 and 3 are kept as a backstop for a request shape this has
	 * not been observed under (a future Fluent Forms release, a third-party
	 * submission path that bypasses the whitelist filter), not because they
	 * are expected to fire on 6.2.9.
	 *
	 * Returning '' routes the caller into the coverage-assertion branch, not
	 * into a rejection.
	 *
	 * @param array $form_data Parsed submission data handed to the validation filter.
	 * @return string Token, or ''.
	 */
	private function submitted_token( $form_data ) {
		// 1. The parsed data Fluent Forms itself assembled, if our key survived
		//    its mapping of submitted values against registered fields.
		if ( is_array( $form_data ) && ! empty( $form_data[ self::TOKEN_FIELD ] ) && is_scalar( $form_data[ self::TOKEN_FIELD ] ) ) {
			return sanitize_text_field( (string) $form_data[ self::TOKEN_FIELD ] );
		}

		// 2. The serialised envelope, parsed out by hand.
		foreach ( array( 'data', 'formData' ) as $envelope ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Fluent Forms validates its own nonce before this filter runs.
			if ( ! isset( $_POST[ $envelope ] ) || ! is_string( $_POST[ $envelope ] ) ) {
				continue;
			}

			// phpcs:ignore WordPress.Security.NonceVerification.Missing
			$raw = wp_unslash( $_POST[ $envelope ] );

			$parsed = array();
			parse_str( (string) $raw, $parsed );

			if ( ! empty( $parsed[ self::TOKEN_FIELD ] ) && is_scalar( $parsed[ self::TOKEN_FIELD ] ) ) {
				return sanitize_text_field( (string) $parsed[ self::TOKEN_FIELD ] );
			}
		}

		// 3. A plain POST, for any non-AJAX render path.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( isset( $_POST[ self::TOKEN_FIELD ] ) && is_scalar( $_POST[ self::TOKEN_FIELD ] ) ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Missing
			return sanitize_text_field( wp_unslash( $_POST[ self::TOKEN_FIELD ] ) );
		}

		return '';
	}

	/**
	 * Score a submission and reject it when warranted.
	 *
	 * @param array        $errors    Validation errors so far.
	 * @param array        $form_data Submitted data.
	 * @param object|array $form      Form.
	 * @param array        $fields    Form fields.
	 * @return array Filtered errors.
	 */
	public function validate_submission( $errors, $form_data = array(), $form = null, $fields = array() ) {
		if ( ! is_array( $errors ) ) {
			return $errors;
		}

		$form_id = $this->form_id_of( $form );
		if ( ! $form_id ) {
			return $errors;
		}

		// Never re-judge a submission Fluent Forms has already rejected.
		if ( ! empty( $errors ) ) {
			return $errors;
		}
		if ( ! $this->form_is_eligible( $form_id ) ) {
			return $errors;
		}

		$payment = $this->form_has_payment( $form_id );
		$strict  = $this->form_is_strict( $form_id );

		$token = $this->submitted_token( $form_data );

		if ( '' === $token ) {
			// Declared programmatic: no browser, so no token, and neither a gap
			// nor an attack. Admit it without the alarm.
			//
			// This is the ONLY thing the declaration does. A submission that
			// DOES carry a token has already fallen past this branch and is
			// scored exactly like any other, so ticking "Not public" can never
			// silently unprotect a form somebody can actually reach.
			if ( $this->form_is_internal( $form_id ) ) {
				return $errors;
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
						'COVERAGE GAP: Fluent Forms #%d was submitted with no reCAPTCHA token and this plugin has no record of ever injecting one into it. The submission was allowed through unscored. Check that the form renders our token field.',
						$form_id
					)
				);

				do_action( 'gswp_form_coverage_gap', $this->id(), $form_id );

				return $errors;
			}

			// We do inject into this form, so a submission without a token is
			// adversarial or broken client-side. Asymmetric enforcement: the
			// decision is read from the stored form definition, never from the
			// request — a request-derived predicate would let a caller opt out
			// by omitting the field, the bypass class removed in 2.17.0.
			if ( $strict ) {
				$this->record_rejection( $form_id, 'missing token' );

				return $this->reject(
					$errors,
					__( 'We could not verify this submission. Please refresh the page and try again.', 'google-security-for-wordpress' ),
					$form_id
				);
			}

			$this->pending_unverified[ $form_id ] = true;
			$this->log(
				sprintf(
					'Fluent Forms #%d submitted with no reCAPTCHA token; admitted (takes no payment and creates no account, fail-open). If this repeats, token generation is broken on that page.',
					$form_id
				)
			);

			return $errors;
		}

		$context     = $this->context_for( $form_id );
		$actions     = $this->accepted_actions( $form_id );
		$event_extra = $payment ? $this->payment_context( $form_id, $form_data ) : array();

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
						$errors,
						__( 'This submission did not pass our automated security check. Please refresh the page and try again, or contact us if the problem continues.', 'google-security-for-wordpress' ),
						$form_id
					);
				}

				$this->pending_unverified[ $form_id ] = true;

				$this->log_error(
					sprintf(
						'Fluent Forms #%d submitted a token whose action was "%s" but this form expects "%s". Admitted (takes no payment and creates no account) and flagged unverified. This is a plugin or caching fault, not a spam signal — if it persists, the form is rendering a stale action.',
						$form_id,
						$this->verifier->get_last_token_action(),
						implode( '" or "', $actions )
					)
				);

				return $errors;
			}

			$this->record_rejection( $form_id, $result->get_error_code() );

			return $this->reject( $errors, wp_strip_all_tags( $result->get_error_message() ), $form_id );
		}

		// Transaction Defense verdict on payment forms.
		if ( $payment ) {
			$risk = $this->verifier->get_last_fraud_risk();
			if ( null !== $risk ) {
				if ( '1' === get_option( 'gswp_verbose_logging', '0' ) ) {
					$this->log( sprintf( 'Fluent Forms #%d transaction risk %.2f.', $form_id, $risk ) );
				}

				if ( '1' === get_option( 'gswp_txn_block', '0' ) ) {
					$threshold = floatval( get_option( 'gswp_threshold_txn', '0.8' ) );

					if ( $risk >= $threshold && ! $this->may_block_payment() ) {
						// Scored, above threshold, and deliberately not blocked
						// — because a site has explicitly opted out via
						// gswp_ff_txn_block_allowed. See may_block_payment().
						$this->log_error(
							sprintf(
								'Fluent Forms #%d scored transaction risk %.2f (>= %.2f) but was NOT blocked: blocking is disabled for Fluent Forms on this site via the gswp_ff_txn_block_allowed filter.',
								$form_id,
								$risk,
								$threshold
							)
						);
					} elseif ( $risk >= $threshold ) {
						$this->log( sprintf( 'Fluent Forms #%d blocked: risk %.2f >= %.2f.', $form_id, $risk, $threshold ) );

						do_action(
							'gswp_checkout_blocked',
							$risk,
							$threshold,
							array(
								'source'     => 'fluent-forms',
								'assessment' => $name,
								'form_id'    => $form_id,
							)
						);

						$this->record_rejection( $form_id, 'transaction risk' );

						return $this->reject(
							$errors,
							__( 'This transaction was flagged as high risk and cannot be completed. Please contact us if you believe this is a mistake.', 'google-security-for-wordpress' ),
							$form_id
						);
					}
				}
			}
		}

		return $errors;
	}

	/**
	 * Whether high-risk transaction blocking is permitted on Fluent Forms.
	 *
	 * Defaults to TRUE. This inverts the answer this method carried before
	 * Fluent Forms Pro's gateway source was read. The open question was
	 * whether any gateway authorises a card in the browser before this
	 * plugin's validation runs — if one did, a server-side rejection here
	 * would stop the order but leave a hold standing on the customer's card.
	 *
	 * VERIFIED against every gateway shipped by Fluent Forms and Fluent
	 * Forms Pro 6.2.7: none does.
	 *  - Server side, every gateway charges from
	 *    fluentform/process_payment_{method}, dispatched by
	 *    PaymentHandler::maybeHandlePayment() on
	 *    fluentform/before_insert_payment_form — which runs AFTER
	 *    SubmissionHandlerService::handleValidation(). There is no charge
	 *    path that precedes this filter.
	 *  - Stripe Inline and Square Inline tokenise client-side
	 *    (createPaymentMethod / card.tokenize()); Square's follow-on
	 *    verifyBuyer() is a 3-D Secure CHALLENGE that yields a verification
	 *    token, not a charge or a hold.
	 *  - Authorize.Net's card-entry modal, and Paddle/Paystack/RazorPay's
	 *    equivalents, carry a submission_id/transaction_hash in their
	 *    config and so cannot open until the submission is already
	 *    accepted.
	 *  - PayPal Inline's button submits our form FIRST — its onClick handler
	 *    calls $form.trigger('submit') and does not call createOrder until
	 *    that promise resolves — and explicitly REJECTS that promise on
	 *    fluentform_validation_failed, so a rejection here means no PayPal
	 *    order is ever created.
	 *
	 * Leaving this false now would be the wrong default: gswp_txn_block is a
	 * switch an operator sets deliberately, on a site that also has
	 * Enterprise keys and Transaction Defense on, and silently vetoing it
	 * while logging that nothing was blocked is the plugin doing less than
	 * asked while reporting that it complied.
	 *
	 * Two residuals worth naming rather than hiding behind "false is safer":
	 * on Square Inline the buyer may complete a 3-D Secure challenge before
	 * we reject — an annoyance, not a charge, since the verification token
	 * simply goes unused; and a gateway added by a third-party add-on is
	 * outside everything read here. gswp_ff_txn_block_allowed is now the
	 * escape hatch for turning blocking back OFF on a site whose gateway is
	 * not one of the above.
	 *
	 * @return bool
	 */
	private function may_block_payment() {
		/**
		 * Permit or withhold high-risk Fluent Forms payment blocking.
		 *
		 * Defaults to true (see docblock above). Return false on a site using
		 * a payment gateway not covered by that verification — a third-party
		 * add-on, or a Fluent Forms release newer than 6.2.9/Pro 6.2.7 whose
		 * charge timing has not been re-checked.
		 *
		 * @param bool $allowed Whether blocking is permitted.
		 */
		return (bool) apply_filters( 'gswp_ff_txn_block_allowed', true );
	}

	/**
	 * Attach a rejection message to the errors array.
	 *
	 * VERIFIED: an errors key that matches no field is delivered visibly
	 * under both Fluent Forms `errorMessagePlacement` settings — see
	 * ERROR_KEY. A prior version attached the message to the first real
	 * field on the form instead, and admitted the submission unrejected when
	 * no field could be resolved. Both are unnecessary now that a channel
	 * exists that always resolves and is always visible, so reject() is
	 * unconditional.
	 *
	 * @param array  $errors  Errors so far.
	 * @param string $message Customer-facing message.
	 * @param int    $form_id Form id.
	 * @return array
	 */
	private function reject( $errors, $message, $form_id ) {
		$key = (string) apply_filters( 'gswp_ff_error_field', self::ERROR_KEY, (int) $form_id );

		// A site-supplied field name is honoured, but never our own token
		// field — see ERROR_KEY for why that specific name is the one that
		// renders nowhere.
		if ( '' === $key || self::TOKEN_FIELD === $key ) {
			$key = self::ERROR_KEY;
		}

		$errors[ $key ] = array( $message );

		return $errors;
	}

	/**
	 * Record why a form's last submission was rejected.
	 *
	 * Surfaced per form in the coverage report so "why is this form rejecting?"
	 * has an answer in wp-admin. Only the cause and the time are kept — nothing
	 * about the person who submitted it.
	 *
	 * Throttled, like record_injection(). A payment form under a carding run
	 * rejects continuously, and one option write per rejected attempt would turn
	 * an attack into database load — the plugin amplifying the thing it exists
	 * to absorb. A CHANGE of reason always writes immediately: that is new
	 * information.
	 *
	 * @param int    $form_id Form id.
	 * @param string $reason  Error code, e.g. 'recaptcha_low_score'.
	 */
	private function record_rejection( $form_id, $reason ) {
		$form_id = (int) $form_id;
		$reason  = (string) $reason;

		$log = get_option( self::REJECTION_OPTION, array() );
		$log = is_array( $log ) ? $log : array();

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
	 * @return array
	 */
	public function form_policy( $form_id ) {
		return array(
			'action'   => $this->action_for( $form_id ),
			'context'  => $this->context_for( $form_id ),
			'account'  => $this->account_feed_type( $form_id ),
			'password' => $this->form_changes_password( $form_id ),
			'internal' => $this->form_is_internal( $form_id ),
		);
	}

	/**
	 * Build transactionData for a payment form.
	 *
	 * Billing field mapping is now VERIFIED — see submitted_address().
	 * Returning an empty array is still the safe outcome for a form that
	 * genuinely does not carry enough billing data: GSWP_Verifier enforces
	 * Google's documented minimum (billing region + postal code + payment
	 * method) and omits transaction data entirely when it is unmet,
	 * degrading to a plain score rather than an API error.
	 *
	 * @param int   $form_id   Form id.
	 * @param array $form_data Submitted data.
	 * @return array Event extras, or empty.
	 */
	private function payment_context( $form_id, $form_data ) {
		if ( 'enterprise' !== get_option( 'gswp_key_type', 'classic' ) ) {
			return array();
		}
		if ( '1' !== get_option( 'gswp_txn_defense', '0' ) ) {
			return array();
		}
		if ( ! is_array( $form_data ) ) {
			return array();
		}

		$form = $this->form( $form_id );
		if ( null === $form ) {
			return array();
		}

		$address = $this->submitted_address( $form, $form_data );

		$billing = array_filter(
			array(
				'recipient'          => isset( $address['recipient'] ) ? $address['recipient'] : '',
				'locality'           => isset( $address['city'] ) ? $address['city'] : '',
				'administrativeArea' => isset( $address['state'] ) ? $address['state'] : '',
				'regionCode'         => isset( $address['country'] ) ? $address['country'] : '',
				'postalCode'         => isset( $address['zip'] ) ? $address['zip'] : '',
			),
			static function ( $value ) {
				return '' !== $value;
			}
		);

		if ( ! empty( $address['address_line_1'] ) ) {
			$billing['address'] = array( $address['address_line_1'] );
		}

		// Google's documented minimum. Below it, send nothing rather than a
		// partial object the API will reject.
		if ( empty( $billing['regionCode'] ) || empty( $billing['postalCode'] ) ) {
			return array();
		}

		$transaction = array(
			'paymentMethod'  => 'fluentforms',
			'currencyCode'   => $this->form_currency( $form ),
			'billingAddress' => $billing,
		);

		if ( ! empty( $address['email'] ) ) {
			$transaction['user'] = array( 'email' => $address['email'] );
		}

		return array(
			'transactionData' => $transaction,
			'fraudPrevention' => 'ENABLED',
		);
	}

	/**
	 * Pull billing details out of a submission using the form's field types.
	 *
	 * VERIFIED: Fluent Forms' address field submits a nested array keyed by
	 * component ('address_line_1', 'city', 'state', 'zip', 'country'), under
	 * the field's own submitted name — confirmed against the field's default
	 * definition (Services/FormBuilder/DefaultElements.php) and a real
	 * predefined form's stored JSON (Models/Traits/PredefinedForms.php). The
	 * name-field sub-keys ('first_name', 'middle_name', 'last_name') are
	 * nested the same way and confirmed against the same source. Anything
	 * that does not match yields no components, which routes
	 * payment_context() to its empty return.
	 *
	 * @param array $form      Form row.
	 * @param array $form_data Submitted data.
	 * @return array<string,string> Address components, empties dropped.
	 */
	private function submitted_address( $form, $form_data ) {
		$out = array();

		foreach ( $form['fields'] as $field ) {
			$name = $field['name'];
			if ( '' === $name || ! isset( $form_data[ $name ] ) ) {
				continue;
			}

			$value = $form_data[ $name ];

			if ( 'address' === $field['element'] && is_array( $value ) ) {
				foreach ( array( 'address_line_1', 'city', 'state', 'zip', 'country' ) as $part ) {
					if ( isset( $value[ $part ] ) && is_scalar( $value[ $part ] ) ) {
						$out[ $part ] = sanitize_text_field( (string) $value[ $part ] );
					}
				}
				continue;
			}

			if ( 'input_email' === $field['element'] && is_scalar( $value ) && empty( $out['email'] ) ) {
				$out['email'] = sanitize_email( (string) $value );
				continue;
			}

			if ( 'input_name' === $field['element'] && empty( $out['recipient'] ) ) {
				if ( is_array( $value ) ) {
					$parts = array();
					foreach ( array( 'first_name', 'middle_name', 'last_name' ) as $part ) {
						if ( ! empty( $value[ $part ] ) && is_scalar( $value[ $part ] ) ) {
							$parts[] = sanitize_text_field( (string) $value[ $part ] );
						}
					}
					$out['recipient'] = implode( ' ', $parts );
				} elseif ( is_scalar( $value ) ) {
					$out['recipient'] = sanitize_text_field( (string) $value );
				}
			}
		}

		return array_filter(
			$out,
			static function ( $value ) {
				return '' !== $value;
			}
		);
	}

	/**
	 * A form's payment currency.
	 *
	 * VERIFIED against PaymentHelper::getFormCurrency() / getFormSettings() /
	 * getPaymentSettings() in Fluent Forms 6.2.9: the form-level currency
	 * lives at fluentform_form_meta meta_key `_payment_settings`, key
	 * `currency`; when absent it falls back to the site-wide option
	 * `__fluentform_payment_module_settings`, same key; when that is also
	 * absent the vendor's own default is `'USD'`. Both are available at
	 * validation time, unlike `fluentform_transactions.currency` — that row
	 * is written only once a payment is TAKEN, after this method's caller
	 * has already needed the answer.
	 *
	 * The broader meta-key scan this method used before source was read is
	 * kept as a second-tier fallback, for a `_payment_settings` row that
	 * exists but does not decode, or a currency key this class does not yet
	 * know the vendor uses.
	 *
	 * @param array $form Form row.
	 * @return string Currency code. Never '' — 'USD' is the vendor's own
	 *                default and is returned as a real answer, not a punt.
	 */
	private function form_currency( $form ) {
		$primary = json_decode( $this->form_meta_value( $form['id'], '_payment_settings' ), true );
		if ( is_array( $primary ) && ! empty( $primary['currency'] ) && is_scalar( $primary['currency'] ) ) {
			return strtoupper( sanitize_text_field( (string) $primary['currency'] ) );
		}

		foreach ( $this->form_meta_rows( $form['id'] ) as $row ) {
			$key = isset( $row['meta_key'] ) ? strtolower( (string) $row['meta_key'] ) : '';
			if ( false === strpos( $key, 'payment' ) && false === strpos( $key, 'currency' ) ) {
				continue;
			}

			$meta = json_decode( isset( $row['value'] ) ? (string) $row['value'] : '', true );
			if ( ! is_array( $meta ) ) {
				continue;
			}

			foreach ( array( 'currency', 'payment_currency', 'paymentCurrency' ) as $candidate ) {
				if ( ! empty( $meta[ $candidate ] ) && is_scalar( $meta[ $candidate ] ) ) {
					return strtoupper( sanitize_text_field( (string) $meta[ $candidate ] ) );
				}
			}
		}

		$settings = $this->raw_option( '__fluentform_payment_module_settings' );

		if ( is_array( $settings ) ) {
			foreach ( array( 'currency', 'payment_currency', 'paymentCurrency', 'business_currency' ) as $candidate ) {
				if ( ! empty( $settings[ $candidate ] ) && is_scalar( $settings[ $candidate ] ) ) {
					return strtoupper( sanitize_text_field( (string) $settings[ $candidate ] ) );
				}
			}
		}

		return 'USD';
	}

	/**
	 * Persist the assessment name and any fail-open flag onto the new submission.
	 *
	 * VERIFIED against SubmissionHandlerService::processSubmissionData() and
	 * Helper::setSubmissionMeta() in Fluent Forms 6.2.9:
	 * fluentform/submission_inserted fires as ($insertId, $formData, $form)
	 * after the submission is stored, and setSubmissionMeta() takes
	 * ($submissionId, $metaKey, $value, $formId = false). When
	 * class_exists()/method_exists() still fails (a version this was not
	 * verified against) the meta is simply not written — which costs the
	 * Transaction Defense annotation and nothing else, and is preferable to
	 * writing into another plugin's tables by hand.
	 *
	 * @param int          $submission_id New submission id.
	 * @param array        $form_data     Submitted data.
	 * @param object|array $form          Form.
	 */
	public function store_submission_meta( $submission_id, $form_data = array(), $form = null ) {
		$submission_id = (int) $submission_id;
		$form_id       = $this->form_id_of( $form );

		if ( ! $submission_id || ! $form_id ) {
			return;
		}

		if ( ! empty( $this->pending_assessment[ $form_id ] ) ) {
			$this->set_submission_meta( $submission_id, self::META_ASSESSMENT, $this->pending_assessment[ $form_id ] );
		}

		if ( ! empty( $this->pending_unverified[ $form_id ] ) ) {
			// Flagged rather than silent: a real breakage in token generation
			// shows up as a burst of unverified submissions instead of nothing.
			$this->set_submission_meta( $submission_id, self::META_UNVERIFIED, '1' );
		}
	}

	/**
	 * Write a submission meta value through Fluent Forms' own helper.
	 *
	 * @param int    $submission_id Submission id.
	 * @param string $key           Meta key.
	 * @param string $value         Meta value.
	 * @return bool Whether it was written.
	 */
	private function set_submission_meta( $submission_id, $key, $value ) {
		$helper = '\FluentForm\App\Helpers\Helper';

		if ( ! class_exists( $helper ) || ! method_exists( $helper, 'setSubmissionMeta' ) ) {
			return false;
		}

		call_user_func( array( $helper, 'setSubmissionMeta' ), (int) $submission_id, $key, $value );

		return true;
	}

	/**
	 * Read a submission meta value through Fluent Forms' own helper.
	 *
	 * @param int    $submission_id Submission id.
	 * @param string $key           Meta key.
	 * @return string Value, or ''.
	 */
	private function get_submission_meta( $submission_id, $key ) {
		$helper = '\FluentForm\App\Helpers\Helper';

		if ( ! class_exists( $helper ) || ! method_exists( $helper, 'getSubmissionMeta' ) ) {
			return '';
		}

		$value = call_user_func( array( $helper, 'getSubmissionMeta' ), (int) $submission_id, $key );

		return is_scalar( $value ) ? (string) $value : '';
	}

	/**
	 * Annotate the assessment when a payment's status changes.
	 *
	 * One hook covers both directions, unlike Gravity Forms' pair. Only the two
	 * terminal states we have an opinion about are acted on; everything else
	 * (pending, processing) is left alone, because annotating an assessment
	 * with a verdict that has not been reached teaches Google the wrong thing.
	 *
	 * @param string       $new_status New payment status.
	 * @param object|array $submission Submission.
	 */
	public function on_payment_status_change( $new_status = '', $submission = null ) {
		$status = strtolower( (string) $new_status );

		if ( 'paid' === $status ) {
			$this->annotate( $submission, 'LEGITIMATE', 'PAYMENT' );

			return;
		}

		if ( in_array( $status, array( 'refunded', 'partially-refunded', 'partially_refunded' ), true ) ) {
			$this->annotate( $submission, 'FRAUDULENT', 'REFUND' );
		}
	}

	/**
	 * Send an annotation for a submission's stored assessment.
	 *
	 * @param object|array $submission Submission.
	 * @param string       $annotation LEGITIMATE or FRAUDULENT.
	 * @param string       $event_type transactionEvent eventType.
	 */
	private function annotate( $submission, $annotation, $event_type ) {
		$submission_id = 0;

		if ( is_object( $submission ) && isset( $submission->id ) ) {
			$submission_id = (int) $submission->id;
		} elseif ( is_array( $submission ) && isset( $submission['id'] ) ) {
			$submission_id = (int) $submission['id'];
		} elseif ( is_numeric( $submission ) ) {
			$submission_id = (int) $submission;
		}

		if ( ! $submission_id || ! class_exists( 'GSWP_Transaction_Defense' ) ) {
			return;
		}

		if ( '' !== $this->get_submission_meta( $submission_id, self::META_ANNOTATED ) ) {
			return;
		}

		$name = $this->get_submission_meta( $submission_id, self::META_ASSESSMENT );
		if ( '' === $name ) {
			return;
		}

		$sent = GSWP_Transaction_Defense::annotate_assessment( $name, $annotation, $event_type );
		if ( $sent ) {
			$this->set_submission_meta( $submission_id, self::META_ANNOTATED, $annotation );
		}
	}

	/**
	 * Log at warning level.
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
