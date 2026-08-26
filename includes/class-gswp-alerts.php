<?php
/**
 * Admin Email Alerts Class
 *
 * Turns already-detected security events into an email to the site operator:
 * reCAPTCHA Enterprise Account Defender flagging SUSPICIOUS_LOGIN_ACTIVITY on
 * an administrator-capable account, Account Defender flagging a registration
 * as SUSPICIOUS_ACCOUNT_CREATION, a checkout blocked as high risk by
 * Transaction defense, and Password Defense finding a username+password pair
 * in a known data breach. These events otherwise only reach the log; for an
 * agency running many sites this is the difference between finding out during
 * the incident and finding out from the client.
 *
 * Delivery is decoupled from detection: the detection sites fire the plain
 * actions gswp_suspicious_admin_login / gswp_suspicious_registration /
 * gswp_checkout_blocked / gswp_leaked_credentials, and this class is the only subscriber the plugin
 * ships (leaving the actions as a seam for Slack/webhook forwarding without
 * core changes).
 *
 * Throttling is the point of the feature. Two layers keep a credential-stuffing
 * run or a bot hammering checkout from becoming hundreds of emails:
 *   1. Per-event dedupe: a transient keyed to the event suppresses repeats of
 *      the same event within its window.
 *   2. Global circuit breaker: an hourly counter caps immediate sends; once the
 *      cap is hit, further events queue and the digest cron flushes them as one
 *      summary email.
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class GSWP_Alerts {

	/** Option holding the overflow/digest queue (autoload off). */
	const OPT_QUEUE = 'gswp_alert_queue';

	/** Option counting queue entries dropped when the queue is full. */
	const OPT_DROPPED = 'gswp_alert_dropped';

	/** Transient prefix for the per-event dedupe guard. */
	const DEDUPE_PREFIX = 'gswp_alert_dedupe_';

	/** Transient holding the rolling hourly immediate-send counter. */
	const COUNTER_KEY = 'gswp_alert_hourly_count';

	/** Cron hook that flushes the digest queue. */
	const DIGEST_HOOK = 'gswp_alerts_digest_event';

	/** Hard cap on queued entries so a burst can never bloat the option. */
	const QUEUE_MAX = 100;

	/**
	 * Events accepted for immediate send this request, mailed at shutdown so a
	 * slow mailer never delays the login or checkout response.
	 *
	 * @var array[]
	 */
	private $pending = array();

	/**
	 * Constructor. The cron manager and digest handler run regardless of the
	 * master toggle so a schedule is cleaned up when the feature is switched off
	 * and a still-scheduled digest can drain; the event listeners attach only
	 * when alerts are enabled.
	 */
	public function __construct() {
		add_action( 'init', array( $this, 'maybe_schedule_digest' ) );
		add_action( self::DIGEST_HOOK, array( $this, 'send_digest' ) );

		if ( ! self::enabled() ) {
			return;
		}

		add_action( 'gswp_suspicious_admin_login', array( $this, 'on_suspicious_login' ), 10, 3 );
		add_action( 'gswp_suspicious_registration', array( $this, 'on_suspicious_registration' ), 10, 3 );
		add_action( 'gswp_suspicious_lost_password', array( $this, 'on_suspicious_lost_password' ), 10, 3 );
		add_action( 'gswp_checkout_blocked', array( $this, 'on_checkout_blocked' ), 10, 3 );
		add_action( 'gswp_leaked_credentials', array( $this, 'on_leaked_credentials' ), 10, 3 );
		add_action( 'gswp_form_coverage_gap', array( $this, 'on_form_coverage_gap' ), 10, 2 );
		add_action( 'shutdown', array( $this, 'flush_immediate' ) );
	}

	/* ---------------------------------------------------------------------
	 * Settings helpers
	 * ------------------------------------------------------------------- */

	/**
	 * Whether the alerting feature is switched on.
	 *
	 * @return bool
	 */
	public static function enabled() {
		return '1' === get_option( 'gswp_alerts', '0' );
	}

	/**
	 * Delivery mode: immediate, hourly, or daily.
	 *
	 * @return string One of 'immediate', 'hourly', 'daily'.
	 */
	public static function mode() {
		$mode = get_option( 'gswp_alert_mode', 'immediate' );
		return in_array( $mode, array( 'immediate', 'hourly', 'daily' ), true ) ? $mode : 'immediate';
	}

	/**
	 * Dedupe window in seconds for an event type.
	 *
	 * @param string $type 'login', 'registration', or 'checkout'.
	 * @return int
	 */
	private static function dedupe_window( $type ) {
		$default = ( 'login' === $type ) ? 6 * HOUR_IN_SECONDS : HOUR_IN_SECONDS;
		return (int) apply_filters( 'gswp_alert_dedupe_window', $default, $type );
	}

	/**
	 * Maximum immediate emails per rolling hour before events overflow to the
	 * digest.
	 *
	 * @return int
	 */
	private static function hourly_cap() {
		return (int) apply_filters( 'gswp_alert_hourly_cap', 5 );
	}

	/**
	 * Resolve the alert recipients: the configured comma-separated list, each
	 * address validated, falling back to the site admin email.
	 *
	 * @return string[]
	 */
	public static function recipients() {
		$raw  = (string) get_option( 'gswp_alert_email', '' );
		$list = array();

		foreach ( explode( ',', $raw ) as $addr ) {
			$addr = sanitize_email( trim( $addr ) );
			if ( '' !== $addr && is_email( $addr ) ) {
				$list[] = $addr;
			}
		}

		if ( empty( $list ) ) {
			$fallback = get_option( 'admin_email' );
			if ( $fallback && is_email( $fallback ) ) {
				$list[] = $fallback;
			}
		}

		return array_values( array_unique( $list ) );
	}

	/* ---------------------------------------------------------------------
	 * Event intake
	 * ------------------------------------------------------------------- */

	/**
	 * Handle a suspicious admin-login flag.
	 *
	 * @param WP_User  $user    The administrator-capable account that was flagged.
	 * @param string[] $labels  Account Defender labels returned for the attempt.
	 * @param array    $context Extra flags: correct_password, step_up, assessment.
	 */
	public function on_suspicious_login( $user, $labels, $context = array() ) {
		if ( '1' !== get_option( 'gswp_alert_login', '1' ) ) {
			return;
		}
		if ( ! $user instanceof WP_User ) {
			return;
		}

		$data = array(
			'user_login'       => $user->user_login,
			'display_name'     => $user->display_name,
			'roles'            => implode( ', ', (array) $user->roles ),
			'correct_password' => ! empty( $context['correct_password'] ),
			'step_up'          => ! empty( $context['step_up'] ),
			'labels'           => implode( ', ', (array) $labels ),
			'assessment'       => isset( $context['assessment'] ) ? (string) $context['assessment'] : '',
			'ip'               => self::client_ip(),
			'ua'               => self::user_agent(),
		);

		$this->handle_event( 'login', 'login_' . $user->ID, $data );
	}

	/**
	 * Handle a registration flagged as a suspicious account creation.
	 *
	 * @param string   $email   Submitted registration email.
	 * @param string[] $labels  Account Defender labels returned for the signup.
	 * @param array    $context Extra flags: source, blocked, assessment.
	 */
	public function on_suspicious_registration( $email, $labels, $context = array() ) {
		if ( '1' !== get_option( 'gswp_alert_registration', '1' ) ) {
			return;
		}

		$email = (string) $email;
		$ip    = self::client_ip();

		$data = array(
			'email'      => $email,
			'labels'     => implode( ', ', (array) $labels ),
			'source'     => isset( $context['source'] ) ? (string) $context['source'] : '',
			'blocked'    => ! empty( $context['blocked'] ),
			'assessment' => isset( $context['assessment'] ) ? (string) $context['assessment'] : '',
			'ip'         => $ip,
			'ua'         => self::user_agent(),
		);

		// One email per signup identity per window: key on the submitted email
		// when present, otherwise the source IP.
		$identity = '' !== $email ? strtolower( $email ) : $ip;

		$this->handle_event( 'registration', 'registration_' . md5( $identity ), $data );
	}

	/**
	 * Handle a lost password request flagged as suspicious login activity.
	 *
	 * Reuses the alert_login toggle since a suspicious reset request is a
	 * login-adjacent event (credential-stuffing / account-takeover pattern).
	 *
	 * @param WP_User|false|null $user_data The user the reset was requested for.
	 * @param string[]           $labels    Account Defender labels.
	 * @param array              $context   Extra flags: source, blocked, assessment.
	 */
	public function on_suspicious_lost_password( $user_data, $labels, $context = array() ) {
		if ( '1' !== get_option( 'gswp_alert_login', '1' ) ) {
			return;
		}

		$identity = '';
		if ( $user_data instanceof WP_User ) {
			$identity = $user_data->user_login;
		}

		$ip = self::client_ip();

		$data = array(
			'user_login' => $identity,
			'labels'     => implode( ', ', (array) $labels ),
			'source'     => isset( $context['source'] ) ? (string) $context['source'] : '',
			'blocked'    => ! empty( $context['blocked'] ),
			'assessment' => isset( $context['assessment'] ) ? (string) $context['assessment'] : '',
			'ip'         => $ip,
			'ua'         => self::user_agent(),
		);

		$dedupe_id = '' !== $identity ? strtolower( $identity ) : $ip;

		$this->handle_event( 'login', 'lostpw_' . md5( $dedupe_id ), $data );
	}

	/**
	 * Handle a checkout blocked as high risk.
	 *
	 * @param float $risk      Transaction risk (0..1) that triggered the block.
	 * @param float $threshold Configured block threshold.
	 * @param array $context   source, assessment, billing_email, billing_name,
	 *                         total, currency.
	 */
	public function on_checkout_blocked( $risk, $threshold, $context = array() ) {
		if ( '1' !== get_option( 'gswp_alert_checkout', '1' ) ) {
			return;
		}

		$email = isset( $context['billing_email'] ) ? (string) $context['billing_email'] : '';
		$ip    = self::client_ip();

		// One email per attacker identity per hour, however many retries: key on
		// the billing email when present, otherwise the source IP.
		$identity = '' !== $email ? strtolower( $email ) : $ip;

		$data = array(
			'risk'          => is_numeric( $risk ) ? (float) $risk : null,
			'threshold'     => is_numeric( $threshold ) ? (float) $threshold : null,
			'source'        => isset( $context['source'] ) ? (string) $context['source'] : '',
			'billing_name'  => isset( $context['billing_name'] ) ? (string) $context['billing_name'] : '',
			'billing_email' => $email,
			'total'         => isset( $context['total'] ) ? (string) $context['total'] : '',
			'currency'      => isset( $context['currency'] ) ? (string) $context['currency'] : '',
			'assessment'    => isset( $context['assessment'] ) ? (string) $context['assessment'] : '',
			'ip'            => $ip,
		);

		$this->handle_event( 'checkout', 'checkout_' . md5( $identity ), $data );
	}

	/**
	 * Handle a form that was submitted without ever receiving a token field.
	 *
	 * This is an operational alert, not a security one: it means this plugin
	 * believes it is protecting a form but no token field is reaching the
	 * browser, so that form is being submitted unscored. Since replacement
	 * switched the form plugin's own reCAPTCHA off, nothing else is covering it
	 * either — which is exactly why it needs to be noisy rather than a log line
	 * nobody reads.
	 *
	 * Throttled to one alert per form per hour by the shared dedupe key so a
	 * busy broken form cannot flood the inbox.
	 *
	 * @param string     $provider_id Provider id, e.g. 'gravity-forms'.
	 * @param int|string $form_id     Form identifier.
	 */
	public function on_form_coverage_gap( $provider_id, $form_id ) {
		$data = array(
			'provider' => (string) $provider_id,
			'form_id'  => (string) $form_id,
			'ip'       => self::client_ip(),
		);

		$this->handle_event( 'coverage', 'coverage_' . md5( $provider_id . '|' . $form_id ), $data );
	}

	/**
	 * Handle credentials Password Defense flagged as appearing in a known
	 * data breach.
	 *
	 * @param WP_User|null $user    The affected account, when resolvable.
	 * @param string       $context 'login', 'password_reset', 'profile_update',
	 *                              'account_details', or 'registration'.
	 * @param array        $context_extra Extra flags: blocked.
	 */
	public function on_leaked_credentials( $user, $context, $context_extra = array() ) {
		if ( '1' !== get_option( 'gswp_alert_leak', '1' ) ) {
			return;
		}

		$login = $user instanceof WP_User ? $user->user_login : '';
		$ip    = self::client_ip();
		$identity = '' !== $login ? $login : $ip;

		$data = array(
			'user_login' => $login,
			'context'    => (string) $context,
			'blocked'    => ! empty( $context_extra['blocked'] ),
			'ip'         => $ip,
			'ua'         => self::user_agent(),
		);

		$this->handle_event( 'leak', 'leak_' . md5( $identity ), $data );
	}

	/**
	 * Run an event through the two-layer throttle pipeline.
	 *
	 * @param string $type 'login' or 'checkout'.
	 * @param string $key  Dedupe key for this event.
	 * @param array  $data Event payload (must survive serialization for digests).
	 */
	private function handle_event( $type, $key, $data ) {
		$event = array(
			'type' => $type,
			'time' => time(),
			'data' => $data,
		);

		// Layer 1: per-event dedupe. A repeat of the same event within its window
		// is suppressed; we bump a counter so a diagnostic can see the volume.
		$dedupe_key = self::DEDUPE_PREFIX . md5( $key );
		$existing   = get_transient( $dedupe_key );
		if ( false !== $existing ) {
			set_transient( $dedupe_key, (int) $existing + 1, self::dedupe_window( $type ) );
			return;
		}
		set_transient( $dedupe_key, 0, self::dedupe_window( $type ) );

		// Digest modes never send immediately: everything queues for the cron.
		if ( 'immediate' !== self::mode() ) {
			$this->enqueue( $event );
			$this->maybe_schedule_digest();
			return;
		}

		// Layer 2: global circuit breaker. Past the hourly cap, overflow to the
		// digest so distinct events can't produce unbounded mail either.
		$count = (int) get_transient( self::COUNTER_KEY );
		if ( $count >= self::hourly_cap() ) {
			$this->enqueue( $event );
			$this->maybe_schedule_digest();
			return;
		}

		$this->bump_counter();
		$this->pending[] = $event;
	}

	/**
	 * Raise the rolling hourly counter, preserving the window opened by the
	 * first send of the hour so a sustained burst does not keep resetting it.
	 */
	private function bump_counter() {
		$count = (int) get_transient( self::COUNTER_KEY );
		if ( $count < 1 ) {
			set_transient( self::COUNTER_KEY, 1, HOUR_IN_SECONDS );
			return;
		}

		$timeout = (int) get_option( '_transient_timeout_' . self::COUNTER_KEY, 0 );
		$ttl     = $timeout > time() ? $timeout - time() : HOUR_IN_SECONDS;
		set_transient( self::COUNTER_KEY, $count + 1, $ttl );
	}

	/**
	 * Append an event to the digest queue, capping its size and tracking drops.
	 *
	 * @param array $event Normalized event.
	 */
	private function enqueue( $event ) {
		$queue = get_option( self::OPT_QUEUE, array() );
		if ( ! is_array( $queue ) ) {
			$queue = array();
		}

		if ( count( $queue ) >= self::QUEUE_MAX ) {
			$dropped = (int) get_option( self::OPT_DROPPED, 0 );
			update_option( self::OPT_DROPPED, $dropped + 1, false );
			return;
		}

		$queue[] = $event;
		update_option( self::OPT_QUEUE, $queue, false );
	}

	/* ---------------------------------------------------------------------
	 * Delivery
	 * ------------------------------------------------------------------- */

	/**
	 * Send any events accepted for immediate delivery this request. Runs on
	 * shutdown so mailing never delays the response that produced the event.
	 */
	public function flush_immediate() {
		if ( empty( $this->pending ) ) {
			return;
		}

		$events        = $this->pending;
		$this->pending = array();

		$recipients = self::recipients();
		if ( empty( $recipients ) ) {
			return;
		}

		foreach ( $events as $event ) {
			list( $subject, $body ) = $this->format_event( $event );
			$this->mail( $recipients, $subject, $body );
		}
	}

	/**
	 * Flush the digest queue as one summary email. Cron handler.
	 */
	public function send_digest() {
		if ( ! self::enabled() ) {
			wp_clear_scheduled_hook( self::DIGEST_HOOK );
			return;
		}

		$queue = get_option( self::OPT_QUEUE, array() );
		if ( ! is_array( $queue ) ) {
			$queue = array();
		}

		// Clear immediately so events for the next period accumulate cleanly.
		update_option( self::OPT_QUEUE, array(), false );
		$dropped = (int) get_option( self::OPT_DROPPED, 0 );
		update_option( self::OPT_DROPPED, 0, false );

		if ( empty( $queue ) ) {
			// Nothing to report — an empty period sends nothing ("no news" is
			// spam too). Re-evaluate the schedule (an immediate-mode overflow
			// digest unschedules itself once drained).
			$this->maybe_schedule_digest();
			return;
		}

		$recipients = self::recipients();
		if ( ! empty( $recipients ) ) {
			list( $subject, $body ) = $this->format_digest( $queue, $dropped );
			$this->mail( $recipients, $subject, $body );
		}

		$this->maybe_schedule_digest();
	}

	/**
	 * Send one email, logging (but never surfacing) a failure.
	 *
	 * @param string[] $to      Recipients.
	 * @param string   $subject Subject line.
	 * @param string   $body    Plain-text body.
	 */
	private function mail( $to, $subject, $body ) {
		$sent = wp_mail( $to, $subject, $body );
		if ( ! $sent ) {
			self::log( 'Alert email failed to send: ' . $subject );
		}
	}

	/* ---------------------------------------------------------------------
	 * Cron scheduling
	 * ------------------------------------------------------------------- */

	/**
	 * Ensure the digest cron matches the current mode: scheduled at the mode's
	 * recurrence for digest modes, scheduled hourly only while an overflow queue
	 * exists in immediate mode, and cleared when the feature is off.
	 */
	public function maybe_schedule_digest() {
		if ( ! self::enabled() ) {
			wp_clear_scheduled_hook( self::DIGEST_HOOK );
			return;
		}

		$mode = self::mode();

		if ( 'immediate' === $mode ) {
			$queue = get_option( self::OPT_QUEUE, array() );
			if ( empty( $queue ) ) {
				wp_clear_scheduled_hook( self::DIGEST_HOOK );
				return;
			}
			$desired = 'hourly';
		} else {
			$desired = ( 'daily' === $mode ) ? 'daily' : 'hourly';
		}

		if ( wp_get_schedule( self::DIGEST_HOOK ) !== $desired ) {
			wp_clear_scheduled_hook( self::DIGEST_HOOK );
			wp_schedule_event( time() + HOUR_IN_SECONDS, $desired, self::DIGEST_HOOK );
		}
	}

	/* ---------------------------------------------------------------------
	 * Formatting
	 * ------------------------------------------------------------------- */

	/**
	 * Build the subject and body for a single event.
	 *
	 * @param array $event Normalized event.
	 * @return array{0:string,1:string} Subject, body.
	 */
	private function format_event( $event ) {
		if ( 'login' === $event['type'] ) {
			return $this->format_login( $event );
		}
		if ( 'registration' === $event['type'] ) {
			return $this->format_registration( $event );
		}
		if ( 'leak' === $event['type'] ) {
			return $this->format_leak( $event );
		}
		if ( 'coverage' === $event['type'] ) {
			return $this->format_coverage_gap( $event );
		}
		return $this->format_checkout( $event );
	}

	/**
	 * Format a form coverage-gap alert.
	 *
	 * @param array $event Normalized event.
	 * @return array{0:string,1:string}
	 */
	private function format_coverage_gap( $event ) {
		$d = $event['data'];

		$subject = sprintf(
			/* translators: 1: site name, 2: form identifier. */
			__( '[%1$s] A form is being submitted without bot protection (form %2$s)', 'google-security-for-wordpress' ),
			self::blogname(),
			isset( $d['form_id'] ) ? $d['form_id'] : '?'
		);

		$lines   = array();
		$lines[] = sprintf(
			/* translators: 1: provider name, 2: form identifier, 3: site URL. */
			__( 'A submission arrived for %1$s form %2$s at %3$s with no reCAPTCHA token, and this plugin has no record of ever placing a token field in that form.', 'google-security-for-wordpress' ),
			isset( $d['provider'] ) ? $d['provider'] : 'unknown',
			isset( $d['form_id'] ) ? $d['form_id'] : '?',
			home_url()
		);
		$lines[] = '';
		$lines[] = __( 'The submission was allowed through rather than blocked, because a form this plugin failed to reach is its own fault and not the visitor\'s. That form is currently being submitted unscored.', 'google-security-for-wordpress' );
		$lines[] = '';
		$lines[] = __( 'Since this plugin took over, the form plugin\'s own reCAPTCHA is switched off, so nothing else is covering it either.', 'google-security-for-wordpress' );
		$lines[] = '';
		$lines[] = __( 'What to check:', 'google-security-for-wordpress' );
		$lines[] = __( '  1. Load the form on the front end and view source for a hidden input named gswp_gf_token.', 'google-security-for-wordpress' );
		$lines[] = __( '  2. If it is absent, the form uses a render path this plugin does not reach.', 'google-security-for-wordpress' );
		$lines[] = __( '  3. Until it is fixed, re-enable that form plugin\'s own reCAPTCHA, or switch Form Protection off to restore it everywhere.', 'google-security-for-wordpress' );
		$lines[] = '';
		$lines[] = admin_url( 'options-general.php?page=gswp-admin' );

		return array( $subject, implode( "\n", $lines ) );
	}

	/**
	 * Format a leaked-credentials alert.
	 *
	 * @param array $event Normalized event.
	 * @return array{0:string,1:string}
	 */
	private function format_leak( $event ) {
		$d = $event['data'];

		$subject = sprintf(
			/* translators: 1: site name, 2: username. */
			__( '[%1$s] Leaked credentials detected for "%2$s"', 'google-security-for-wordpress' ),
			self::blogname(),
			'' !== $d['user_login'] ? $d['user_login'] : __( 'unknown account', 'google-security-for-wordpress' )
		);

		$lines   = array();
		$lines[] = sprintf(
			/* translators: %s: site URL. */
			__( 'reCAPTCHA Password defense found this username+password pair in a known data breach at %s.', 'google-security-for-wordpress' ),
			home_url()
		);
		$lines[] = '';
		$lines   = array_merge( $lines, $this->leak_detail_lines( $event ) );
		$lines[] = '';
		$lines[] = $d['blocked']
			? __( 'The password change was rejected and the account was told to choose a different password.', 'google-security-for-wordpress' )
			: __( 'The account was not blocked. Recommend the account owner change this password (and anywhere else they reused it) as soon as possible.', 'google-security-for-wordpress' );

		return array( $subject, implode( "\n", $lines ) );
	}

	/**
	 * Detail lines for a leaked-credentials event, shared by single and
	 * digest emails.
	 *
	 * @param array $event Normalized event.
	 * @return string[]
	 */
	private function leak_detail_lines( $event ) {
		$d     = $event['data'];
		$lines = array();

		$lines[] = sprintf( /* translators: %s: account login. */ __( 'Account: %s', 'google-security-for-wordpress' ), '' !== $d['user_login'] ? $d['user_login'] : '—' );
		$lines[] = sprintf( /* translators: %s: surface where the leak was found. */ __( 'Detected at: %s', 'google-security-for-wordpress' ), $d['context'] );
		$lines[] = sprintf(
			/* translators: %s: yes or no. */
			__( 'Change blocked: %s', 'google-security-for-wordpress' ),
			$d['blocked'] ? __( 'yes', 'google-security-for-wordpress' ) : __( 'no', 'google-security-for-wordpress' )
		);
		$lines[] = sprintf( /* translators: %s: IP address. */ __( 'IP address: %s', 'google-security-for-wordpress' ), $d['ip'] );
		$lines[] = sprintf( /* translators: %s: user agent string. */ __( 'User agent: %s', 'google-security-for-wordpress' ), $d['ua'] );
		$lines[] = sprintf( /* translators: %s: date and time. */ __( 'Time: %s', 'google-security-for-wordpress' ), self::format_time( $event['time'] ) );

		return $lines;
	}

	/**
	 * Format a suspicious-login alert.
	 *
	 * @param array $event Normalized event.
	 * @return array{0:string,1:string}
	 */
	private function format_login( $event ) {
		$d = $event['data'];

		$subject = sprintf(
			/* translators: 1: site name, 2: username. */
			__( '[%1$s] Suspicious login flagged on admin account "%2$s"', 'google-security-for-wordpress' ),
			self::blogname(),
			$d['user_login']
		);

		$lines   = array();
		$lines[] = sprintf(
			/* translators: %s: site URL. */
			__( 'reCAPTCHA Account Defender flagged a suspicious login attempt against an administrator-capable account at %s.', 'google-security-for-wordpress' ),
			home_url()
		);
		$lines[] = '';
		$lines   = array_merge( $lines, $this->login_detail_lines( $event ) );
		$lines[] = '';
		$lines[] = __( 'Review recent sign-ins and confirm this was the account owner. Repeated flags on this account are suppressed for a period so this alert does not become noise.', 'google-security-for-wordpress' );

		return array( $subject, implode( "\n", $lines ) );
	}

	/**
	 * Detail lines for a login event, shared by single and digest emails.
	 *
	 * @param array $event Normalized event.
	 * @return string[]
	 */
	private function login_detail_lines( $event ) {
		$d     = $event['data'];
		$name  = '' !== $d['display_name'] ? $d['user_login'] . ' (' . $d['display_name'] . ')' : $d['user_login'];
		$lines = array();

		$lines[] = sprintf( /* translators: %s: account name. */ __( 'Account: %s', 'google-security-for-wordpress' ), $name );
		$lines[] = sprintf( /* translators: %s: user roles. */ __( 'Roles: %s', 'google-security-for-wordpress' ), $d['roles'] );
		$lines[] = sprintf(
			/* translators: %s: yes or no. */
			__( 'Password entered correctly: %s', 'google-security-for-wordpress' ),
			$d['correct_password'] ? __( 'yes', 'google-security-for-wordpress' ) : __( 'no', 'google-security-for-wordpress' )
		);
		$lines[] = sprintf(
			/* translators: %s: yes or no. */
			__( '2FA step-up forced: %s', 'google-security-for-wordpress' ),
			$d['step_up'] ? __( 'yes', 'google-security-for-wordpress' ) : __( 'no', 'google-security-for-wordpress' )
		);
		$lines[] = sprintf( /* translators: %s: risk labels. */ __( 'Risk labels: %s', 'google-security-for-wordpress' ), $d['labels'] );
		$lines[] = sprintf( /* translators: %s: IP address. */ __( 'IP address: %s', 'google-security-for-wordpress' ), $d['ip'] );
		$lines[] = sprintf( /* translators: %s: user agent string. */ __( 'User agent: %s', 'google-security-for-wordpress' ), $d['ua'] );
		$lines[] = sprintf( /* translators: %s: date and time. */ __( 'Time: %s', 'google-security-for-wordpress' ), self::format_time( $event['time'] ) );
		if ( '' !== $d['assessment'] ) {
			$lines[] = sprintf( /* translators: %s: assessment resource name. */ __( 'Assessment: %s', 'google-security-for-wordpress' ), $d['assessment'] );
		}

		return $lines;
	}

	/**
	 * Format a suspicious-registration alert.
	 *
	 * @param array $event Normalized event.
	 * @return array{0:string,1:string}
	 */
	private function format_registration( $event ) {
		$d = $event['data'];

		$subject = sprintf(
			/* translators: 1: site name, 2: registration email. */
			__( '[%1$s] Suspicious sign-up flagged (%2$s)', 'google-security-for-wordpress' ),
			self::blogname(),
			'' !== $d['email'] ? $d['email'] : __( 'unknown email', 'google-security-for-wordpress' )
		);

		$lines   = array();
		$lines[] = sprintf(
			/* translators: %s: site URL. */
			__( 'reCAPTCHA Account Defender flagged a new-account registration as a suspicious account creation at %s.', 'google-security-for-wordpress' ),
			home_url()
		);
		$lines[] = '';
		$lines   = array_merge( $lines, $this->registration_detail_lines( $event ) );
		$lines[] = '';
		$lines[] = $d['blocked']
			? __( 'The sign-up was blocked before an account was created. Repeat attempts from the same email within the hour are suppressed so this alert does not become noise.', 'google-security-for-wordpress' )
			: __( 'The account was still created (suspicious sign-up blocking is off under Account Defender). Review the new user and delete it if it is spam — deleting it also reports the sign-up to Google as fraudulent so detection improves. Repeat flags for the same email within the hour are suppressed.', 'google-security-for-wordpress' );

		return array( $subject, implode( "\n", $lines ) );
	}

	/**
	 * Detail lines for a registration event, shared by single and digest emails.
	 *
	 * @param array $event Normalized event.
	 * @return string[]
	 */
	private function registration_detail_lines( $event ) {
		$d     = $event['data'];
		$lines = array();

		$lines[] = sprintf( /* translators: %s: registration email. */ __( 'Email: %s', 'google-security-for-wordpress' ), '' !== $d['email'] ? $d['email'] : '—' );
		$lines[] = sprintf( /* translators: %s: risk labels. */ __( 'Risk labels: %s', 'google-security-for-wordpress' ), $d['labels'] );
		$lines[] = sprintf(
			/* translators: %s: yes or no. */
			__( 'Sign-up blocked: %s', 'google-security-for-wordpress' ),
			$d['blocked'] ? __( 'yes', 'google-security-for-wordpress' ) : __( 'no', 'google-security-for-wordpress' )
		);
		if ( '' !== $d['source'] ) {
			$lines[] = sprintf( /* translators: %s: registration form source. */ __( 'Form: %s', 'google-security-for-wordpress' ), $d['source'] );
		}
		$lines[] = sprintf( /* translators: %s: IP address. */ __( 'IP address: %s', 'google-security-for-wordpress' ), $d['ip'] );
		$lines[] = sprintf( /* translators: %s: user agent string. */ __( 'User agent: %s', 'google-security-for-wordpress' ), $d['ua'] );
		$lines[] = sprintf( /* translators: %s: date and time. */ __( 'Time: %s', 'google-security-for-wordpress' ), self::format_time( $event['time'] ) );
		if ( '' !== $d['assessment'] ) {
			$lines[] = sprintf( /* translators: %s: assessment resource name. */ __( 'Assessment: %s', 'google-security-for-wordpress' ), $d['assessment'] );
		}

		return $lines;
	}

	/**
	 * Format a blocked-checkout alert.
	 *
	 * @param array $event Normalized event.
	 * @return array{0:string,1:string}
	 */
	private function format_checkout( $event ) {
		$d = $event['data'];

		$subject = sprintf(
			/* translators: 1: site name, 2: risk score. */
			__( '[%1$s] High-risk checkout blocked (risk %2$s)', 'google-security-for-wordpress' ),
			self::blogname(),
			null === $d['risk'] ? '—' : number_format_i18n( $d['risk'], 2 )
		);

		$lines   = array();
		$lines[] = sprintf(
			/* translators: %s: site URL. */
			__( 'reCAPTCHA Transaction defense blocked a checkout as high risk at %s.', 'google-security-for-wordpress' ),
			home_url()
		);
		$lines[] = '';
		$lines   = array_merge( $lines, $this->checkout_detail_lines( $event ) );
		$lines[] = '';
		$lines[] = __( 'This checkout was rejected before an order was placed. Repeat attempts from the same shopper within the hour are suppressed so this alert does not become noise.', 'google-security-for-wordpress' );

		return array( $subject, implode( "\n", $lines ) );
	}

	/**
	 * Detail lines for a checkout event, shared by single and digest emails.
	 *
	 * @param array $event Normalized event.
	 * @return string[]
	 */
	private function checkout_detail_lines( $event ) {
		$d     = $event['data'];
		$lines = array();

		$risk_line = ( null === $d['risk'] || null === $d['threshold'] )
			? ( null === $d['risk'] ? '—' : number_format_i18n( $d['risk'], 2 ) )
			: sprintf(
				/* translators: 1: risk score, 2: threshold. */
				__( '%1$s (threshold %2$s)', 'google-security-for-wordpress' ),
				number_format_i18n( $d['risk'], 2 ),
				number_format_i18n( $d['threshold'], 2 )
			);

		$lines[] = sprintf( /* translators: %s: risk score and threshold. */ __( 'Risk: %s', 'google-security-for-wordpress' ), $risk_line );
		if ( '' !== $d['billing_name'] ) {
			$lines[] = sprintf( /* translators: %s: billing name. */ __( 'Billing name: %s', 'google-security-for-wordpress' ), $d['billing_name'] );
		}
		if ( '' !== $d['billing_email'] ) {
			$lines[] = sprintf( /* translators: %s: billing email. */ __( 'Billing email: %s', 'google-security-for-wordpress' ), $d['billing_email'] );
		}
		if ( '' !== $d['total'] ) {
			$total = '' !== $d['currency'] ? $d['total'] . ' ' . $d['currency'] : $d['total'];
			$lines[] = sprintf( /* translators: %s: order total. */ __( 'Cart total: %s', 'google-security-for-wordpress' ), $total );
		}
		if ( '' !== $d['source'] ) {
			$source = 'block' === $d['source']
				? __( 'WooCommerce Checkout block', 'google-security-for-wordpress' )
				: __( 'classic checkout', 'google-security-for-wordpress' );
			$lines[] = sprintf( /* translators: %s: checkout type. */ __( 'Checkout type: %s', 'google-security-for-wordpress' ), $source );
		}
		$lines[] = sprintf( /* translators: %s: IP address. */ __( 'IP address: %s', 'google-security-for-wordpress' ), $d['ip'] );
		$lines[] = sprintf( /* translators: %s: date and time. */ __( 'Time: %s', 'google-security-for-wordpress' ), self::format_time( $event['time'] ) );
		if ( '' !== $d['assessment'] ) {
			$lines[] = sprintf( /* translators: %s: assessment resource name. */ __( 'Assessment: %s', 'google-security-for-wordpress' ), $d['assessment'] );
		}

		return $lines;
	}

	/**
	 * Format the periodic digest as one email grouping every queued event.
	 *
	 * @param array[] $queue   Queued events.
	 * @param int     $dropped How many entries were dropped when the queue was full.
	 * @return array{0:string,1:string}
	 */
	private function format_digest( $queue, $dropped ) {
		$logins        = array();
		$registrations = array();
		$checkouts     = array();
		$leaks         = array();
		foreach ( $queue as $event ) {
			if ( 'login' === $event['type'] ) {
				$logins[] = $event;
			} elseif ( 'registration' === $event['type'] ) {
				$registrations[] = $event;
			} elseif ( 'leak' === $event['type'] ) {
				$leaks[] = $event;
			} else {
				$checkouts[] = $event;
			}
		}

		$subject = sprintf(
			/* translators: 1: site name, 2: login count, 3: sign-up count, 4: checkout count, 5: leaked-credential count. */
			__( '[%1$s] Security alert digest: %2$d flagged logins, %3$d suspicious sign-ups, %4$d blocked checkouts, %5$d leaked credentials', 'google-security-for-wordpress' ),
			self::blogname(),
			count( $logins ),
			count( $registrations ),
			count( $checkouts ),
			count( $leaks )
		);

		$limit = 10;
		$lines = array();
		$lines[] = sprintf(
			/* translators: %s: site URL. */
			__( 'Security alert digest for %s.', 'google-security-for-wordpress' ),
			home_url()
		);
		$lines[] = '';

		if ( ! empty( $logins ) ) {
			$lines[] = sprintf(
				/* translators: %d: number of flagged logins. */
				_n( 'Suspicious admin login (%d):', 'Suspicious admin logins (%d):', count( $logins ), 'google-security-for-wordpress' ),
				count( $logins )
			);
			$lines = array_merge( $lines, $this->digest_section( $logins, $limit, 'login' ) );
			$lines[] = '';
		}

		if ( ! empty( $registrations ) ) {
			$lines[] = sprintf(
				/* translators: %d: number of flagged sign-ups. */
				_n( 'Suspicious sign-up (%d):', 'Suspicious sign-ups (%d):', count( $registrations ), 'google-security-for-wordpress' ),
				count( $registrations )
			);
			$lines = array_merge( $lines, $this->digest_section( $registrations, $limit, 'registration' ) );
			$lines[] = '';
		}

		if ( ! empty( $checkouts ) ) {
			$lines[] = sprintf(
				/* translators: %d: number of blocked checkouts. */
				_n( 'Blocked high-risk checkout (%d):', 'Blocked high-risk checkouts (%d):', count( $checkouts ), 'google-security-for-wordpress' ),
				count( $checkouts )
			);
			$lines = array_merge( $lines, $this->digest_section( $checkouts, $limit, 'checkout' ) );
			$lines[] = '';
		}

		if ( ! empty( $leaks ) ) {
			$lines[] = sprintf(
				/* translators: %d: number of leaked-credential detections. */
				_n( 'Leaked credentials detected (%d):', 'Leaked credentials detected (%d):', count( $leaks ), 'google-security-for-wordpress' ),
				count( $leaks )
			);
			$lines = array_merge( $lines, $this->digest_section( $leaks, $limit, 'leak' ) );
			$lines[] = '';
		}

		if ( $dropped > 0 ) {
			$lines[] = sprintf(
				/* translators: %d: number of events dropped. */
				_n( '%d further event was dropped after the queue filled.', '%d further events were dropped after the queue filled.', $dropped, 'google-security-for-wordpress' ),
				$dropped
			);
		}

		return array( $subject, implode( "\n", $lines ) );
	}

	/**
	 * Render up to $limit events of one type as indented digest blocks.
	 *
	 * @param array[] $events Events of a single type.
	 * @param int     $limit  Maximum detailed entries.
	 * @param string  $type   'login', 'registration', or 'checkout'.
	 * @return string[]
	 */
	private function digest_section( $events, $limit, $type ) {
		$lines = array();
		$shown = array_slice( $events, 0, $limit );

		foreach ( $shown as $event ) {
			if ( 'login' === $type ) {
				$details = $this->login_detail_lines( $event );
			} elseif ( 'registration' === $type ) {
				$details = $this->registration_detail_lines( $event );
			} elseif ( 'leak' === $type ) {
				$details = $this->leak_detail_lines( $event );
			} else {
				$details = $this->checkout_detail_lines( $event );
			}
			foreach ( $details as $detail ) {
				$lines[] = '  ' . $detail;
			}
			$lines[] = '';
		}

		$extra = count( $events ) - count( $shown );
		if ( $extra > 0 ) {
			$lines[] = sprintf(
				/* translators: %d: number of additional events not shown. */
				_n( '  …and %d more.', '  …and %d more.', $extra, 'google-security-for-wordpress' ),
				$extra
			);
		}

		return $lines;
	}

	/* ---------------------------------------------------------------------
	 * Small helpers
	 * ------------------------------------------------------------------- */

	/**
	 * The site name, HTML entities decoded for a plain-text email.
	 *
	 * @return string
	 */
	private static function blogname() {
		return wp_specialchars_decode( (string) get_option( 'blogname' ), ENT_QUOTES );
	}

	/**
	 * Format a timestamp in the site's timezone.
	 *
	 * @param int $ts Unix timestamp.
	 * @return string
	 */
	private static function format_time( $ts ) {
		return date_i18n( 'Y-m-d H:i:s', (int) $ts ) . ' ' . wp_timezone_string();
	}

	/**
	 * The requesting client's IP address.
	 *
	 * @return string
	 */
	private static function client_ip() {
		return GSWP_Client_IP::get();
	}

	/**
	 * The requesting client's user agent.
	 *
	 * @return string
	 */
	private static function user_agent() {
		return isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
	}

	/**
	 * Log a warning to the WooCommerce logger, or the error log under WP_DEBUG.
	 *
	 * @param string $message Log message.
	 */
	private static function log( $message ) {
		if ( '1' !== get_option( 'gswp_verbose_logging', '0' ) ) {
			return;
		}
		GSWP_Log::warning( $message );
	}
}
