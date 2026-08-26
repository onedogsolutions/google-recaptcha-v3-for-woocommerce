<?php
/**
 * Checkout: Transaction defense verdict outranks the bot score (v2.28.0)
 *
 * Runs inside a bootstrapped WordPress (`wp eval-file`), entirely offline: no
 * network call, no assessment, no order. Section A deliberately provokes the
 * admission log line and therefore appends one entry to the `gswp_log_tail`
 * option and the WooCommerce `gswp` log; nothing else is written. The
 * verifier is built with newInstanceWithoutConstructor() so this script does not
 * add a second copy of the WooCommerce validation hooks to the request, and the
 * assessment state it judges is seeded straight into the private properties by
 * reflection — the same technique chunk 26 section F uses for Fluent Forms feeds.
 *
 * WHY THIS EXISTS. On 2026-08-26 a customer of a live store could not check out.
 * He was told his order "did not pass" and, in the wording of the day, that he
 * looked like spam. The assessment behind it (Cloud Logging, 14:25:26Z) read:
 *
 *     riskAnalysis.score                        0.2
 *     riskAnalysis.reasons                      ["UNEXPECTED_ENVIRONMENT"]
 *     tokenProperties.valid                     true
 *     tokenProperties.createTime                14:14:49Z  (10m36s before use)
 *     fraudPreventionAssessment.transactionRisk 0.10000000149011612
 *
 * Nothing was wrong with the token. He was on a VPN, on a phone, returning to a
 * checkout tab he had left ten minutes earlier — which is what a 0.2 with
 * UNEXPECTED_ENVIRONMENT describes. Google's *payment* model, looking at the same
 * event with the transaction attached, scored the fraud risk at 0.10 and cleared
 * it. The plugin blocked him anyway, because the score gate ran first and
 * returned on its own.
 *
 * Section A replays that exact assessment. If it ever fails, that customer is
 * being turned away again.
 *
 *   A. THE REGRESSION CASE. score 0.2 / risk 0.10 is ADMITTED, and the admission
 *      is logged — a submission that would have been blocked and was not is the
 *      one event an operator must be able to find afterwards.
 *   B. CARDING IS STILL REFUSED. Low score AND high risk is refused. This is the
 *      case the score gate exists for, and deferring must not weaken it.
 *   C. BOUNDARY. The comparison is `risk >= threshold` refuses, matching
 *      process_fraud_prevention() so the two cannot disagree about one payment.
 *   D. NO SPILLOVER. Login, registration, comments and non-payment forms send no
 *      transactionData, so there is no verdict to defer to and the score still
 *      governs them exactly as before.
 *   E. NO ACCUSATION SURVIVES. The string that told a paying customer he was
 *      spam must not exist in the plugin any more, in any file.
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

if ( ! class_exists( 'GSWP_Verifier' ) ) {
	echo "FAIL: GSWP_Verifier not loaded. Is the plugin active?\n";
	return;
}

echo "Plugin version: " . ( defined( 'GSWP_VERSION' ) ? GSWP_VERSION : 'unknown' ) . "\n";
echo "gswp_threshold_txn: " . get_option( 'gswp_threshold_txn', '0.8' ) . "\n\n";

$ref      = new ReflectionClass( 'GSWP_Verifier' );
$verifier = $ref->newInstanceWithoutConstructor();

$seed = function ( $risk, $score, $context = 'checkout' ) use ( $ref, $verifier ) {
	$values = array(
		'last_fraud_assessment' => ( null === $risk ? null : array( 'transactionRisk' => $risk ) ),
		'last_score'            => $score,
		'last_context'          => $context,
		'last_assessment_name'  => 'projects/0/assessments/manual-test',
	);
	foreach ( $values as $name => $value ) {
		$prop = $ref->getProperty( $name );
		$prop->setAccessible( true );
		$prop->setValue( $verifier, $value );
	}
};

$threshold = floatval( get_option( 'gswp_threshold_txn', '0.8' ) );

echo "A. The 2026-08-26 assessment, replayed\n";
$seed( 0.10000000149011612, 0.2 );
$out( true === $verifier->fraud_verdict_admits_low_score(), 'score 0.2 / risk 0.10 admitted' );
$tail    = GSWP_Log::tail( 1 );
$latest  = ! empty( $tail ) ? reset( $tail ) : array();
$message = is_array( $latest ) && isset( $latest['message'] ) ? $latest['message'] : '';
$out( false !== strpos( $message, 'Transaction defense scored this payment' ), 'the admission was logged' );

echo "\nB. Carding run\n";
$seed( 0.95, 0.1 );
$out( false === $verifier->fraud_verdict_admits_low_score(), 'score 0.1 / risk 0.95 still refused' );

echo "\nC. Boundary at the blocking threshold\n";
$seed( $threshold, 0.2 );
$out( false === $verifier->fraud_verdict_admits_low_score(), 'risk == threshold refused' );
$seed( max( 0.0, $threshold - 0.01 ), 0.2 );
$out( true === $verifier->fraud_verdict_admits_low_score(), 'risk just below threshold admitted' );

echo "\nD. Contexts that send no transaction data\n";
foreach ( array( 'login', 'register', 'comment', 'submit' ) as $context ) {
	$seed( null, 0.1, $context );
	$out( false === $verifier->fraud_verdict_admits_low_score(), $context . ': score still governs' );
}

echo "\nE. The accusation is gone\n";
$hits = array();
foreach ( glob( GSWP_PLUGIN_DIR . 'includes/*.php' ) as $file ) {
	if ( false !== strpos( (string) file_get_contents( $file ), 'rejected as potential spam' ) ) {
		$hits[] = basename( $file );
	}
}
$out( empty( $hits ), 'no file accuses a visitor of spam' . ( empty( $hits ) ? '' : ': ' . implode( ', ', $hits ) ) );

echo "\n5 sections, " . $fail . " failures\n";
