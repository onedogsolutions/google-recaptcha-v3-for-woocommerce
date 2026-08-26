<?php
/**
 * Plugin Name: Google Security for WordPress
 * Description: A Google-powered security suite for WordPress: reCAPTCHA v3 scoring on the WordPress and WooCommerce login, registration, lost password, and checkout forms, plus two-factor authentication (TOTP) compatible with Google Authenticator. Works with or without WooCommerce.
 * Version: 2.28.0
 * Author: One Dog Solutions
 * Author URI: https://onedog.solutions/
 * Requires at least: 5.8
 * Requires PHP: 7.4
 * Text Domain: google-security-for-wordpress
 * Domain Path: /languages
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly.
}

// Check PHP version.
if ( version_compare( PHP_VERSION, '7.4', '<' ) ) {
	add_action( 'admin_notices', function() {
		echo '<div class="notice notice-error"><p>' . esc_html__( 'Google Security for WordPress requires PHP 7.4 or higher. The plugin has been deactivated.', 'google-security-for-wordpress' ) . '</p></div>';
		if ( isset( $_GET['activate'] ) ) {
			unset( $_GET['activate'] );
		}
	} );
	add_action( 'admin_init', function() {
		deactivate_plugins( plugin_basename( __FILE__ ) );
	} );
	return;
}

// Check WordPress version.
global $wp_version;
if ( version_compare( $wp_version, '5.8', '<' ) ) {
	add_action( 'admin_notices', function() {
		echo '<div class="notice notice-error"><p>' . esc_html__( 'Google Security for WordPress requires WordPress 5.8 or higher. The plugin has been deactivated.', 'google-security-for-wordpress' ) . '</p></div>';
		if ( isset( $_GET['activate'] ) ) {
			unset( $_GET['activate'] );
		}
	} );
	add_action( 'admin_init', function() {
		deactivate_plugins( plugin_basename( __FILE__ ) );
	} );
	return;
}

// Define plugin constants.
define( 'GSWP_VERSION', '2.28.0' );
define( 'GSWP_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'GSWP_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'GSWP_FILE', __FILE__ );

/**
 * Autoload classes or include them.
 */
// Owns the reCAPTCHA loader script: one tag per page, generic detection of
// third-party loaders, and the shared token bootstrap. Must load before
// GSWP_Assets, whose HANDLE constant aliases this class.
// Logging. Loaded first: everything else routes through it, and without
// WooCommerce there is no wc_get_logger() to fall back on.
require_once GSWP_PLUGIN_DIR . 'includes/class-gswp-log.php';
require_once GSWP_PLUGIN_DIR . 'includes/class-gswp-recaptcha-loader.php';
require_once GSWP_PLUGIN_DIR . 'includes/class-gswp-assets.php';
require_once GSWP_PLUGIN_DIR . 'includes/class-gswp-gravity-forms.php';
// Admin warnings for divergent-site-key loader conflicts.
require_once GSWP_PLUGIN_DIR . 'includes/class-gswp-loader-notices.php';
// Discovery of reCAPTCHA configured in other plugins, surfaced as a notice.
// Replaces the settings-takeover mechanism removed in 2.21.0.
require_once GSWP_PLUGIN_DIR . 'includes/class-gswp-foreign-recaptcha.php';
// Form providers: make this plugin the reCAPTCHA implementation for third-party
// form plugins so their own reCAPTCHA can be retired. Staged takeover, default
// off, with a coverage audit and a kill switch.
require_once GSWP_PLUGIN_DIR . 'includes/class-gswp-form-provider.php';
require_once GSWP_PLUGIN_DIR . 'includes/class-gswp-form-provider-registry.php';
require_once GSWP_PLUGIN_DIR . 'includes/class-gswp-provider-gravity-forms.php';
require_once GSWP_PLUGIN_DIR . 'includes/class-gswp-provider-fluent-forms.php';
require_once GSWP_PLUGIN_DIR . 'includes/class-gswp-conflict-guard.php';
require_once GSWP_PLUGIN_DIR . 'includes/class-gswp-verifier.php';
// reCAPTCHA Enterprise Transaction defense: annotates WooCommerce orders so
// Google's fraud model learns from outcomes. Hooks fire on the front end and
// via admin order actions, so it loads unconditionally (inert when off).
require_once GSWP_PLUGIN_DIR . 'includes/class-gswp-transaction-defense.php';
// WooCommerce Blocks / Store API checkout support: scores the token the modern
// Checkout block sends over the Store API (the classic checkout hooks never
// fire for block submissions). Hooks are Blocks-specific, so it loads
// unconditionally and is inert when Blocks is not present.
require_once GSWP_PLUGIN_DIR . 'includes/class-gswp-blocks.php';
// reCAPTCHA Enterprise Account Defender: interprets per-login account labels and
// annotates login/2FA outcomes. Hooks the authentication flow, so it loads
// unconditionally (inert unless enabled with an Enterprise key).
require_once GSWP_PLUGIN_DIR . 'includes/class-gswp-account-defender.php';
// Admin email alerts: turns a flagged suspicious admin login (Account Defender)
// or a blocked high-risk checkout (Transaction defense) into a throttled email.
// Subscribes to actions fired from the login flow, so it loads unconditionally.
require_once GSWP_PLUGIN_DIR . 'includes/class-gswp-alerts.php';
// The WordPress core login/registration/lost-password screens run outside the
// admin context (is_admin() is false on wp-login.php), so this class must load
// unconditionally for its hooks to fire.
require_once GSWP_PLUGIN_DIR . 'includes/class-gswp-login.php';
// Third-party login plugins authenticate through admin-ajax (is_admin() is
// true there), so their integrations must also load unconditionally.
require_once GSWP_PLUGIN_DIR . 'includes/class-gswp-xootix.php';
require_once GSWP_PLUGIN_DIR . 'includes/class-gswp-powerpack.php';
require_once GSWP_PLUGIN_DIR . 'includes/class-gswp-beaver-builder.php';
// REST requests are not admin context (is_admin() is false for /wp-json),
// so the REST API class must load unconditionally for its routes to exist.
require_once GSWP_PLUGIN_DIR . 'includes/class-gswp-rest-api.php';
// MainWP Child dispatches dashboard requests on the front end (is_admin() is
// false), so the bridge must load unconditionally; it is inert unless MainWP
// Child fires its filter.
require_once GSWP_PLUGIN_DIR . 'includes/class-gswp-mainwp-child.php';
// Two-factor authentication. The login challenge runs on wp-login.php (not an
// admin context) while enrollment runs in the profile screen, so the core class
// loads unconditionally.
require_once GSWP_PLUGIN_DIR . 'includes/class-gswp-totp.php';
require_once GSWP_PLUGIN_DIR . 'includes/class-gswp-two-factor.php';
// Password Defense (leaked-credential detection). Hooks the login flow and
// several account-modification screens, so it loads unconditionally (inert
// unless enabled with an Enterprise key and a supported bignum extension).
require_once GSWP_PLUGIN_DIR . 'includes/class-gswp-scrypt.php';
require_once GSWP_PLUGIN_DIR . 'includes/class-gswp-ec-cipher.php';
require_once GSWP_PLUGIN_DIR . 'includes/class-gswp-password-defense.php';

// Admin and Frontend classes are loaded unconditionally because is_admin()
// can differ between plugin file load time and the plugins_loaded hook (e.g.
// during WP-CLI boot). Instantiation remains gated in gswp_init().
require_once GSWP_PLUGIN_DIR . 'includes/class-gswp-admin.php';
require_once GSWP_PLUGIN_DIR . 'includes/class-gswp-frontend.php';
require_once GSWP_PLUGIN_DIR . 'includes/class-gswp-comments.php';

/**
 * Default option values, keyed by option name without the gswp_ prefix.
 *
 * Shared between activation and the legacy-settings migration so both stay in
 * sync.
 *
 * @return array<string,string> Map of option suffix => default value.
 */
function gswp_default_options() {
	return array(
		'site_key'                  => '',
		'secret_key'                => '',
		'key_type'                  => 'classic',
		'gcp_project_id'            => '',
		'gcp_api_key'               => '',
		'enable_login'              => '0',
		'enable_registration'       => '0',
		'enable_checkout'           => '0',
		'threshold_login'           => '0.5',
		'threshold_registration'    => '0.5',
		'threshold_checkout'        => '0.5',
		// reCAPTCHA Enterprise Transaction defense.
		'txn_defense'               => '0',
		'txn_block'                 => '0',
		'threshold_txn'             => '0.8',
		// reCAPTCHA Enterprise Account Defender.
		'account_defender'          => '0',
		'ad_step_up'                => '0',
		'ad_events'                 => '1',
		'ad_block_signup'           => '0',
		'ad_block_lostpw'           => '0',
		'ad_share_email'            => '0',
		'account_salt'              => '',
		// Admin email alerts on flagged events.
		'alerts'                    => '0',
		'alert_email'               => '',
		'alert_mode'                => 'immediate',
		'alert_login'               => '1',
		'alert_registration'        => '1',
		'alert_checkout'            => '1',
		// Diagnostics.
		'verbose_logging'           => '0',
		'enable_wp_login'           => '0',
		'enable_wp_register'        => '0',
		'enable_wp_lostpassword'    => '0',
		'threshold_wp_login'        => '0.5',
		'threshold_wp_register'     => '0.5',
		'threshold_wp_lostpassword' => '0.5',
		// WordPress comment form protection.
		'enable_comments'           => '0',
		'threshold_comments'        => '0.5',
		// Beaver Builder core module protection.
		'enable_bb_contact'         => '0',
		'threshold_bb_contact'      => '0.5',
		'enable_bb_subscribe'       => '0',
		'threshold_bb_subscribe'    => '0.5',
		// PowerPack module protection (Contact Form, Subscribe Form).
		'enable_pp_contact'         => '0',
		'threshold_pp_contact'      => '0.5',
		'enable_pp_subscribe'       => '0',
		'threshold_pp_subscribe'    => '0.5',
		'conflict_mode'             => 'off',
		// Form providers. The master switch is on; individual providers are
		// enabled on upgrade wherever replacement can work (see
		// GSWP_Form_Provider_Registry::maybe_migrate), so a fresh install with
		// no site key yet stays inert until one is configured.
		'form_providers_enabled'    => '1',
		'provider_gravity_forms_enabled' => '0',
		// Two-factor authentication.
		'2fa_enabled'               => '1',
		'2fa_enforced_roles'        => array(),
		'2fa_remember'              => '1',
		'2fa_grace_days'            => '14',
		'2fa_block_app_passwords'   => '0',
		'2fa_app_password_exempt_users' => '',
		'2fa_env_binding'           => '1',
		// Password Defense (leaked-credential detection).
		'password_defense'         => '0',
		'pd_login'                 => '1',
		'pd_block_choice'          => '1',
		'pd_force_reset'           => '0',
		'alert_leak'                => '1',
	);
}

/**
 * Activate the plugin.
 *
 * On activation we seed the default options, pull any credentials saved by the
 * predecessor "Google reCAPTCHA v3 for WooCommerce" plugin into the new option
 * keys, and then deactivate and delete that old plugin if it is still installed
 * so only this rebranded version remains.
 */
function gswp_activate() {
	foreach ( gswp_default_options() as $suffix => $default ) {
		add_option( 'gswp_' . $suffix, $default );
	}

	// Import keys/settings from the legacy plugin's options.
	gswp_import_legacy_options();

	// Remove the old plugin now that its settings have been carried over.
	gswp_remove_legacy_plugin();

	// Remove any other installation of this same plugin left under a
	// different folder slug (e.g. a manual ZIP upload that couldn't
	// overwrite the existing folder in place).
	gswp_remove_duplicate_installs();

	// Record the schema version so the migration routine is a no-op on fresh
	// installs.
	update_option( 'gswp_db_version', GSWP_VERSION );
}
register_activation_hook( __FILE__, 'gswp_activate' );

/**
 * Deactivate the plugin.
 *
 * Clears the alert-digest cron so no scheduled event is left dangling once the
 * plugin is switched off.
 */
function gswp_deactivate() {
	wp_clear_scheduled_hook( 'gswp_alerts_digest_event' );
}
register_deactivation_hook( __FILE__, 'gswp_deactivate' );

/**
 * Copy settings stored under the plugin's previous option prefix.
 *
 * Earlier releases (the "Google reCAPTCHA v3 for WooCommerce" plugin) stored
 * settings under the recaptcha_woo_ prefix. Copy any of those values over to the
 * new gswp_ prefix, so the install keeps its configuration after the rename,
 * then delete the legacy options so the database is left holding only the gswp_
 * keys.
 */
function gswp_import_legacy_options() {
	foreach ( gswp_default_options() as $suffix => $default ) {
		$new_key = 'gswp_' . $suffix;
		$old_key = 'recaptcha_woo_' . $suffix;

		$old_value = get_option( $old_key, null );
		if ( null !== $old_value ) {
			// Carry the legacy value over only when the new key is unset, then
			// remove the legacy option so no stale rows remain.
			if ( false === get_option( $new_key, false ) ) {
				update_option( $new_key, $old_value );
			}
			delete_option( $old_key );
		}

		// Ensure the new key exists with its default even when there was nothing
		// to migrate.
		add_option( $new_key, $default );
	}
}

/**
 * Deactivate and delete the predecessor reCAPTCHA v3 plugin if it is present.
 *
 * Matches the old plugin by its known file path, text domain, or plugin name so
 * a renamed install folder is still caught, while never touching this plugin's
 * own file.
 */
function gswp_remove_legacy_plugin() {
	if ( ! function_exists( 'get_plugins' ) || ! function_exists( 'deactivate_plugins' ) || ! function_exists( 'delete_plugins' ) ) {
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
	}
	// delete_plugins() relies on the filesystem abstraction.
	if ( ! function_exists( 'request_filesystem_credentials' ) ) {
		require_once ABSPATH . 'wp-admin/includes/file.php';
	}

	$self            = plugin_basename( GSWP_FILE );
	$known_basename  = 'google-recaptcha-v3-for-woocommerce/google-recaptcha-v3-for-woocommerce.php';
	$legacy_plugins  = array();

	foreach ( get_plugins() as $basename => $data ) {
		if ( $basename === $self ) {
			continue;
		}

		$name   = isset( $data['Name'] ) ? $data['Name'] : '';
		$domain = isset( $data['TextDomain'] ) ? $data['TextDomain'] : '';

		if ( $basename === $known_basename
			|| 'google-recaptcha-v3-for-woocommerce' === $domain
			|| 'Google reCAPTCHA v3 for WooCommerce' === $name ) {
			$legacy_plugins[] = $basename;
		}
	}

	if ( empty( $legacy_plugins ) ) {
		return;
	}

	// Deactivate silently (skip the deactivation hooks of the old plugin) and
	// then delete its files.
	deactivate_plugins( $legacy_plugins, true );
	delete_plugins( $legacy_plugins );
}

/**
 * Deactivate and delete any other installation of this same plugin.
 *
 * WordPress identifies a plugin by its folder path, not its display name, so
 * a ZIP uploaded into a differently-named plugins/ subfolder (because the
 * existing folder couldn't be overwritten in place) is invisible to the
 * normal in-place upgrade and lingers as a second row on the Plugins screen
 * under the old version. Anything else installed under this plugin's own
 * name or text domain is, by definition, exactly that: a stale duplicate.
 * Also swept from load-plugins.php so a site that activated before this
 * check existed gets cleaned up without needing to deactivate/reactivate.
 */
function gswp_remove_duplicate_installs() {
	if ( ! function_exists( 'get_plugins' ) || ! function_exists( 'deactivate_plugins' ) || ! function_exists( 'delete_plugins' ) ) {
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
	}
	// delete_plugins() relies on the filesystem abstraction.
	if ( ! function_exists( 'request_filesystem_credentials' ) ) {
		require_once ABSPATH . 'wp-admin/includes/file.php';
	}

	$self       = plugin_basename( GSWP_FILE );
	$duplicates = array();

	foreach ( get_plugins() as $basename => $data ) {
		if ( $basename === $self ) {
			continue;
		}

		$name   = isset( $data['Name'] ) ? $data['Name'] : '';
		$domain = isset( $data['TextDomain'] ) ? $data['TextDomain'] : '';

		if ( 'Google Security for WordPress' === $name || 'google-security-for-wordpress' === $domain ) {
			$duplicates[] = $basename;
		}
	}

	if ( empty( $duplicates ) ) {
		return;
	}

	// Deactivate silently (skip the deactivation hooks of the duplicate) and
	// then delete its files.
	deactivate_plugins( $duplicates, true );
	delete_plugins( $duplicates );
}
add_action( 'load-plugins.php', 'gswp_remove_duplicate_installs' );

/**
 * Migrate settings stored under the plugin's previous option prefix.
 *
 * Runs on every load as a safety net for upgrades that bypass the activation
 * hook, copying any lingering recaptcha_woo_ options into the gswp_ keys.
 */
function gswp_maybe_migrate() {
	if ( get_option( 'gswp_db_version' ) === GSWP_VERSION ) {
		return;
	}

	gswp_import_legacy_options();
	gswp_backfill_2fa_origin();

	update_option( 'gswp_db_version', GSWP_VERSION );
}
add_action( 'plugins_loaded', 'gswp_maybe_migrate', 5 );

/**
 * Stamp an origin site on existing 2FA enrolments that predate that check.
 *
 * A secret enrolled before the origin-binding feature shipped has no
 * `gswp_2fa_origin` user meta, so it is treated as not-foreign (grandfathered
 * in) until stamped. This backfill records the current site as that origin
 * the first time this version of the plugin runs here, so any *future* clone
 * of the database is then caught (it will carry this origin while running on
 * a different host). It cannot retroactively distinguish a clone that already
 * exists at the time of the upgrade — if the upgrade happens to run on that
 * clone first, the clone stamps itself as its own origin. Runs once per
 * version bump via the `gswp_db_version` gate in `gswp_maybe_migrate()`.
 */
function gswp_backfill_2fa_origin() {
	if ( ! class_exists( 'GSWP_Two_Factor' ) ) {
		return;
	}

	$users = get_users(
		array(
			'meta_query' => array( // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_query
				'relation' => 'AND',
				array(
					'key'   => GSWP_Two_Factor::META_ENABLED,
					'value' => '1',
				),
				array(
					'key'     => GSWP_Two_Factor::META_ORIGIN,
					'compare' => 'NOT EXISTS',
				),
			),
			'fields'     => 'ID',
		)
	);

	if ( empty( $users ) ) {
		return;
	}

	$origin = GSWP_Two_Factor::current_site_origin();

	foreach ( $users as $user_id ) {
		update_user_meta( $user_id, GSWP_Two_Factor::META_ORIGIN, $origin );
	}
}

/**
 * Initialize the plugin classes.
 */
function gswp_init() {
	// Initialize validation/verification first.
	$verifier = new GSWP_Verifier();

	// reCAPTCHA Enterprise Transaction defense order annotation. Inert unless
	// WooCommerce is active, an Enterprise key is set, and the feature is on.
	new GSWP_Transaction_Defense();

	// WooCommerce Blocks / Store API checkout. Registers the block token
	// integration and scores the checkout token. Inert unless Blocks is active;
	// shares the verifier so it reuses the same scoring and Transaction defense.
	new GSWP_Blocks( $verifier );

	// reCAPTCHA Enterprise Account Defender. Interprets per-login account labels
	// and annotates login/2FA outcomes. Inert unless enabled with an Enterprise
	// key. Shares the verifier so it can read the last assessment's labels.
	new GSWP_Account_Defender( $verifier );

	// Admin email alerts. Subscribes to the suspicious-login and blocked-checkout
	// actions and emails a throttled summary. Inert unless enabled.
	new GSWP_Alerts();

	// Protect the WordPress core login, registration, and lost password
	// screens, plus admin-initiated password reset links.
	new GSWP_Login( $verifier );

	// Extend the same protection to the Login/Signup Popup plugin's AJAX
	// forms. Inert unless that plugin is active.
	new GSWP_Xootix( $verifier );

	// Extend the same protection to the PowerPack (Beaver Builder) Login Form
	// module. Inert unless PowerPack is active.
	new GSWP_Powerpack( $verifier );

	// Extend protection to the Beaver Builder core Login Form, Contact Form,
	// and Subscribe Form modules. Inert unless BB is active.
	new GSWP_Beaver_Builder( $verifier );

	// Form providers. Inert unless a provider is advanced past 'off' and the
	// kill switch is clear.
	GSWP_Form_Provider_Registry::init( $verifier );

	// Own the reCAPTCHA loader: deduplicate tags carrying the same site key so
	// this plugin and any other reCAPTCHA consumer share one loader, print the
	// token bootstrap from the footer, and record divergent-key conflicts.
	GSWP_Recaptcha_Loader::init();

	// Suppress OTHER plugins' reCAPTCHA scripts only when they carry a
	// different site key. Inert unless a conflict mode is configured.
	new GSWP_Conflict_Guard();

	// Routes only register when rest_api_init fires, so this is a no-op
	// outside REST requests.
	new GSWP_Rest_Api();

	// MainWP child-side settings bridge. Inert unless MainWP Child is active
	// and dispatches an mwpgswp request over its signed dashboard channel.
	new GSWP_MainWP_Child();

	// Two-factor authentication (TOTP / Google Authenticator). Inert unless the
	// feature is enabled and a user has enrolled.
	new GSWP_Two_Factor();

	// Password Defense: checks credentials against Google's breach database on
	// login and password-choice surfaces. Inert unless enabled with an
	// Enterprise key and a GMP or BCMath extension is present.
	new GSWP_Password_Defense();

	if ( is_admin() ) {
		new GSWP_Admin();
		// Warn about divergent-site-key reCAPTCHA loaders observed on the
		// front end. Inert until one is actually detected.
		new GSWP_Loader_Notices();
		// Warn when reCAPTCHA is configured in another plugin. This is what
		// replaced switching it off automatically.
		new GSWP_Foreign_Recaptcha();
	} else {
		new GSWP_Frontend();
		// Comment form reCAPTCHA scoring. Inert unless the toggle is on.
		new GSWP_Comments( $verifier );
	}
}
add_action( 'plugins_loaded', 'gswp_init' );
