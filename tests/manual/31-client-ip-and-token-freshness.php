<?php
/**
 * Client IP resolution + checkout token freshness (v2.29.0)
 *
 * Runs inside a bootstrapped WordPress (`wp eval-file`), offline: no network
 * call, no assessment, no order. Sections A–D mutate `$_SERVER` for the current
 * request only and snapshot/restore the two options they touch, so the script is
 * idempotent and safe to re-run. Section E is a read-only source check.
 *
 * WHY THIS EXISTS. Two defects were left open by v2.28.0 and are closed here.
 *
 * 1. Every assessment carried `$_SERVER['REMOTE_ADDR']` and nothing else. On a
 *    site behind a CDN that is the edge node, so every visitor is reported to
 *    Google from one datacenter address — scores depressed site-wide, Account
 *    Defender learning that the whole site shares a network, and the wrong
 *    address in alert emails. The fix cannot be "read X-Forwarded-For": any
 *    client can send that header, and trusting it unconditionally lets an
 *    attacker launder a bad score by claiming a clean address. Sections C and D
 *    are the two spoofing shapes that must fail.
 *
 * 2. Nothing held a submission for a fresh token. A v3 token lives 120 seconds;
 *    the refresh interval is skipped while the tab is hidden and the browser
 *    suspends its timers on a locked phone. On 2026-08-26 a customer submitted
 *    one that was 10m36s old and was scored 0.2. The place-order veto caught an
 *    EMPTY field but never a stale one.
 *
 *   A. DEFAULT IS UNCHANGED. No trusted proxies configured -> REMOTE_ADDR, the
 *      pre-2.29.0 value, even when a forwarding header is present.
 *   B. CONFIGURED PROXY RESOLVES THE VISITOR. REMOTE_ADDR is a declared proxy ->
 *      the client address from the forwarded chain.
 *   C. SPOOF, PROXIED. An attacker behind the real proxy prepends a clean
 *      address; the rightmost untrusted hop must win, not the claim.
 *   D. SPOOF, DIRECT. A request that did NOT come through a trusted proxy must
 *      have its headers ignored entirely.
 *   E. THE FRESHNESS GUARD IS PRESENT in the generated bootstrap: tokens are
 *      stamped when minted, staleness is read from that stamp, and the veto
 *      fires on stale as well as empty.
 *
 * Expected output: every line PASS, and "5 sections, 0 failures".
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$fail = 0;
$out  = function ( $ok, $label ) use ( &$fail ) {
	if ( ! $ok ) {
		$fail++;
	}
	echo ( $ok ? '  PASS  ' : '  FAIL  ' ) . $label . "\n";
};

if ( ! class_exists( 'GSWP_Client_IP' ) ) {
	echo "FAIL: GSWP_Client_IP not loaded. Is the plugin active and >= 2.29.0?\n";
	return;
}

echo "Plugin version: " . ( defined( 'GSWP_VERSION' ) ? GSWP_VERSION : 'unknown' ) . "\n";

// Snapshot everything this script touches.
$restore = array(
	'gswp_trusted_proxies'  => get_option( 'gswp_trusted_proxies', '' ),
	'gswp_client_ip_header' => get_option( 'gswp_client_ip_header', 'X-Forwarded-For' ),
);
$server_backup = $_SERVER;

echo "Configured trusted proxies: " . ( '' === $restore['gswp_trusted_proxies'] ? '(none)' : $restore['gswp_trusted_proxies'] ) . "\n";
echo "Live resolution right now:  REMOTE_ADDR " . GSWP_Client_IP::remote_addr() . " -> sent to Google as " . GSWP_Client_IP::get() . "\n\n";

$request = function ( $remote, $headers = array(), $trusted = null ) {
	foreach ( array( 'HTTP_X_FORWARDED_FOR', 'HTTP_CF_CONNECTING_IP', 'HTTP_TRUE_CLIENT_IP', 'HTTP_X_REAL_IP' ) as $key ) {
		unset( $_SERVER[ $key ] );
	}
	$_SERVER['REMOTE_ADDR'] = $remote;
	foreach ( $headers as $key => $value ) {
		$_SERVER[ $key ] = $value;
	}
	update_option( 'gswp_trusted_proxies', null === $trusted ? '' : $trusted );
	delete_transient( 'gswp_proxy_warning_sent' );
};

echo "A. No trusted proxies configured\n";
$request( '203.0.113.9', array( 'HTTP_X_FORWARDED_FOR' => '198.51.100.7' ) );
$out( '203.0.113.9' === GSWP_Client_IP::get(), 'REMOTE_ADDR stands; the header is ignored' );

echo "\nB. A declared proxy in front\n";
$request( '159.100.171.53', array( 'HTTP_X_FORWARDED_FOR' => '98.59.120.187' ), '159.100.171.53' );
$out( '98.59.120.187' === GSWP_Client_IP::get(), 'the visitor address is resolved from the chain' );

echo "\nC. Spoof from behind the real proxy\n";
$request( '159.100.171.53', array( 'HTTP_X_FORWARDED_FOR' => '8.8.8.8, 45.13.99.1' ), '159.100.171.53' );
$out( '45.13.99.1' === GSWP_Client_IP::get(), 'rightmost untrusted hop wins, not the claimed 8.8.8.8' );

echo "\nD. Spoof from a direct connection\n";
$request( '45.13.99.1', array( 'HTTP_X_FORWARDED_FOR' => '8.8.8.8' ), '159.100.171.53' );
$out( '45.13.99.1' === GSWP_Client_IP::get(), 'headers ignored: REMOTE_ADDR is not a trusted proxy' );

echo "\nE. Freshness guard in the generated bootstrap\n";
$reflect = new ReflectionMethod( 'GSWP_Recaptcha_Loader', 'get_bootstrap_js' );
$reflect->setAccessible( true );
$js = (string) $reflect->invoke( null );
$out( false !== strpos( $js, "setAttribute('data-gswp-minted'" ), 'tokens are stamped when minted' );
$out( false !== strpos( $js, 'function isStale(' ), 'staleness is computed from the stamp' );
$out( false !== strpos( $js, 'isStale(input)' ) && false !== strpos( $js, 'checkout_place_order' ), 'the place-order veto tests staleness' );
$out( false !== strpos( $js, 'vetoBlockedUntil' ), 'veto suppression is keyed to mint failure' );

// Restore.
$_SERVER = $server_backup;
foreach ( $restore as $option => $value ) {
	update_option( $option, $value );
}
delete_transient( 'gswp_proxy_warning_sent' );

echo "\nOptions and \$_SERVER restored.\n";
echo "5 sections, " . $fail . " failures\n";
