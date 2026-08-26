<?php
/**
 * Client IP resolution.
 *
 * Every reCAPTCHA assessment this plugin creates carries a `userIpAddress`, and
 * Google weighs it. Until 2.29.0 that value was `$_SERVER['REMOTE_ADDR']` at six
 * call sites and nothing else, which is correct on a site that talks to browsers
 * directly and wrong on every site behind a CDN or reverse proxy: there
 * REMOTE_ADDR is the edge node, so every visitor is reported to Google from one
 * datacenter address. That depresses scores for everyone, teaches Account
 * Defender that the whole site shares one network, and puts the wrong address in
 * security alert emails.
 *
 * WHY THIS IS NOT SIMPLY "READ X-FORWARDED-FOR". Any client can send that header.
 * A plugin that trusts it unconditionally hands an attacker a way to launder a
 * bad score: submit from a flagged address, claim a clean residential one, and
 * the assessment is created against the claim. REMOTE_ADDR is the only value in
 * the request an attacker cannot choose, which is why it was the safe default
 * and why the fix cannot be to stop using it.
 *
 * So the header is read only when REMOTE_ADDR is itself a proxy the operator has
 * declared trusted, and the forwarded chain is walked from the RIGHT — the end
 * nearest this server, which each hop appends to — skipping trusted hops until
 * an address appears that no trusted proxy vouched for. That address is the
 * furthest-left value the trusted chain can actually attest to. Everything to
 * its left was written by something we do not trust, and is ignored.
 *
 * Default is an empty trusted list, so a site that upgrades keeps exactly the
 * pre-2.29.0 behaviour until an operator configures its proxies.
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class GSWP_Client_IP {

	/**
	 * Option holding trusted proxy addresses and CIDR ranges.
	 */
	const TRUSTED_OPTION = 'gswp_trusted_proxies';

	/**
	 * Option naming the header a trusted proxy forwards the client IP in.
	 */
	const HEADER_OPTION = 'gswp_client_ip_header';

	/**
	 * Transient guarding the "behind a proxy but unconfigured" warning.
	 */
	const WARNED_TRANSIENT = 'gswp_proxy_warning_sent';

	/**
	 * Supported forwarding headers, mapped to their $_SERVER keys.
	 *
	 * X-Forwarded-For carries a comma-separated chain; the rest carry a single
	 * address. QUIC.cloud, most load balancers and nginx proxies use the first;
	 * Cloudflare populates CF-Connecting-IP, Akamai and Cloudflare Enterprise
	 * True-Client-IP.
	 *
	 * @var array
	 */
	const HEADERS = array(
		'X-Forwarded-For'  => 'HTTP_X_FORWARDED_FOR',
		'CF-Connecting-IP' => 'HTTP_CF_CONNECTING_IP',
		'True-Client-IP'   => 'HTTP_TRUE_CLIENT_IP',
		'X-Real-IP'        => 'HTTP_X_REAL_IP',
	);

	/**
	 * The visitor's IP address.
	 *
	 * @param string $fallback Returned when REMOTE_ADDR is absent or unusable —
	 *                         a CLI or cron context, chiefly. The assessment
	 *                         callers pass '127.0.0.1' because Google rejects an
	 *                         empty userIpAddress.
	 * @return string IP address, or $fallback.
	 */
	public static function get( $fallback = '' ) {
		$remote = self::remote_addr();

		if ( '' === $remote ) {
			return $fallback;
		}

		$trusted = self::trusted_proxies();
		$ip      = $remote;

		if ( empty( $trusted ) ) {
			// Nothing declared: REMOTE_ADDR stands, exactly as before 2.29.0.
			// Say something if the request looks proxied anyway, because the
			// symptom of getting this wrong — every visitor scoring low for no
			// visible reason — gives an operator nothing to search for.
			self::maybe_warn_unconfigured( $remote );
		} elseif ( self::matches( $remote, $trusted ) ) {
			$forwarded = self::forwarded_ip( $trusted );

			if ( '' !== $forwarded ) {
				$ip = $forwarded;
			}
		}

		/**
		 * Filter the resolved client IP.
		 *
		 * Last word for a host whose proxy arrangement this class cannot
		 * express. Whatever is returned is sent to Google as userIpAddress.
		 *
		 * @param string $ip     Resolved address.
		 * @param string $remote REMOTE_ADDR for this request.
		 */
		$ip = (string) apply_filters( 'gswp_client_ip', $ip, $remote );

		return self::valid( $ip ) ? $ip : $remote;
	}

	/**
	 * REMOTE_ADDR, validated.
	 *
	 * @return string
	 */
	public static function remote_addr() {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotValidated
		$remote = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';

		return self::valid( $remote ) ? $remote : '';
	}

	/**
	 * The client address a trusted proxy chain vouches for.
	 *
	 * @param array $trusted Trusted proxy addresses and ranges.
	 * @return string Address, or '' when the header yields nothing usable.
	 */
	private static function forwarded_ip( array $trusted ) {
		$header = get_option( self::HEADER_OPTION, 'X-Forwarded-For' );
		$key    = isset( self::HEADERS[ $header ] ) ? self::HEADERS[ $header ] : 'HTTP_X_FORWARDED_FOR';

		if ( empty( $_SERVER[ $key ] ) ) {
			return '';
		}

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotValidated
		$raw = sanitize_text_field( wp_unslash( $_SERVER[ $key ] ) );

		if ( 'HTTP_X_FORWARDED_FOR' !== $key ) {
			// Single-address headers: a trusted proxy wrote the whole value.
			$candidate = trim( $raw );

			return self::valid( $candidate ) ? $candidate : '';
		}

		// Walk the chain from the right. Each hop appends the address it
		// received from, so the rightmost entries are the ones our own trusted
		// proxies wrote. Stop at the first address no trusted hop vouches for.
		$chain = array_reverse( array_map( 'trim', explode( ',', $raw ) ) );

		foreach ( $chain as $candidate ) {
			// An IPv6 address in a chain may be bracketed, with or without a port.
			$candidate = preg_replace( '/^\[|\](:\d+)?$/', '', $candidate );

			if ( ! self::valid( $candidate ) ) {
				// A malformed entry means the chain cannot be trusted past this
				// point: anything further left was vouched for by whatever
				// wrote this. Stop rather than skip.
				return '';
			}

			if ( ! self::matches( $candidate, $trusted ) ) {
				return $candidate;
			}
		}

		return '';
	}

	/**
	 * Trusted proxy addresses and CIDR ranges.
	 *
	 * @return array
	 */
	public static function trusted_proxies() {
		$raw = (string) get_option( self::TRUSTED_OPTION, '' );

		$entries = preg_split( '/[\s,]+/', $raw, -1, PREG_SPLIT_NO_EMPTY );
		$entries = is_array( $entries ) ? $entries : array();

		/**
		 * Filter the trusted proxy list.
		 *
		 * Addresses and CIDR ranges, IPv4 or IPv6. A host that ships its own
		 * edge-node list can supply it here instead of storing it.
		 *
		 * @param array $entries Trusted proxies.
		 */
		$entries = (array) apply_filters( 'gswp_trusted_proxies', $entries );

		return array_values( array_filter( array_map( 'trim', $entries ), 'strlen' ) );
	}

	/**
	 * Whether an address falls in any of the given addresses or ranges.
	 *
	 * @param string $ip     Address to test.
	 * @param array  $ranges Addresses and CIDR ranges.
	 * @return bool
	 */
	public static function matches( $ip, array $ranges ) {
		foreach ( $ranges as $range ) {
			if ( self::in_range( $ip, $range ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Whether an address falls within one address or CIDR range.
	 *
	 * Compares packed binary, so IPv4 and IPv6 use one code path and equivalent
	 * spellings of the same IPv6 address ('::1' and '0:0:0:0:0:0:0:1') match.
	 *
	 * @param string $ip    Address to test.
	 * @param string $range Address or CIDR range.
	 * @return bool
	 */
	public static function in_range( $ip, $range ) {
		$ip_packed = self::pack( $ip );

		if ( '' === $ip_packed ) {
			return false;
		}

		if ( false === strpos( $range, '/' ) ) {
			return $ip_packed === self::pack( $range );
		}

		list( $subnet, $bits ) = explode( '/', $range, 2 );

		$subnet_packed = self::pack( trim( $subnet ) );

		if ( '' === $subnet_packed || strlen( $subnet_packed ) !== strlen( $ip_packed ) ) {
			return false;
		}

		if ( ! is_numeric( trim( $bits ) ) ) {
			return false;
		}

		$bits = (int) trim( $bits );
		$max  = strlen( $ip_packed ) * 8;

		if ( $bits < 0 || $bits > $max ) {
			return false;
		}

		$whole     = intdiv( $bits, 8 );
		$remainder = $bits % 8;

		if ( $whole > 0 && substr( $ip_packed, 0, $whole ) !== substr( $subnet_packed, 0, $whole ) ) {
			return false;
		}

		if ( 0 === $remainder ) {
			return true;
		}

		$mask = chr( ( 0xFF << ( 8 - $remainder ) ) & 0xFF );

		return ( $ip_packed[ $whole ] & $mask ) === ( $subnet_packed[ $whole ] & $mask );
	}

	/**
	 * Whether a string is a usable trusted-proxy entry.
	 *
	 * An address or a CIDR range, IPv4 or IPv6. Used by the settings save path
	 * so a typo is dropped at the door rather than silently never matching.
	 *
	 * @param string $entry Candidate.
	 * @return bool
	 */
	public static function is_valid_range( $entry ) {
		$entry = trim( (string) $entry );

		if ( '' === $entry ) {
			return false;
		}

		if ( false === strpos( $entry, '/' ) ) {
			return self::valid( $entry );
		}

		list( $subnet, $bits ) = explode( '/', $entry, 2 );

		$subnet = trim( $subnet );
		$bits   = trim( $bits );

		if ( ! self::valid( $subnet ) || ! is_numeric( $bits ) ) {
			return false;
		}

		$max = strlen( (string) self::pack( $subnet ) ) * 8;

		return (int) $bits >= 0 && (int) $bits <= $max;
	}

	/**
	 * Pack an address to its binary form.
	 *
	 * @param string $ip Address.
	 * @return string Packed address, or '' when it is not one.
	 */
	private static function pack( $ip ) {
		if ( ! self::valid( $ip ) ) {
			return '';
		}

		$packed = @inet_pton( $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged

		return false === $packed ? '' : $packed;
	}

	/**
	 * Whether a string is an IP address.
	 *
	 * @param string $ip Candidate.
	 * @return bool
	 */
	private static function valid( $ip ) {
		return is_string( $ip ) && '' !== $ip && false !== filter_var( $ip, FILTER_VALIDATE_IP );
	}

	/**
	 * Warn once when the request looks proxied but no proxies are trusted.
	 *
	 * Deliberately throttled and hedged. Any client can send a forwarding
	 * header, so its presence is a hint rather than proof, and a site that is
	 * genuinely direct-served should not be nagged by whatever a passing scanner
	 * chose to send. Once every twelve hours is enough for the operator to find
	 * it while investigating scores; it is not enough to be noise.
	 *
	 * @param string $remote REMOTE_ADDR for this request.
	 */
	private static function maybe_warn_unconfigured( $remote ) {
		$present = '';

		foreach ( self::HEADERS as $name => $key ) {
			if ( ! empty( $_SERVER[ $key ] ) ) {
				$present = $name;
				break;
			}
		}

		if ( '' === $present || get_transient( self::WARNED_TRANSIENT ) ) {
			return;
		}

		set_transient( self::WARNED_TRANSIENT, 1, 12 * HOUR_IN_SECONDS );

		GSWP_Log::warning(
			sprintf(
				'This request carried a %1$s header, so the site may sit behind a CDN or reverse proxy, but no trusted proxies are configured. reCAPTCHA assessments are being sent REMOTE_ADDR (%2$s) as the visitor address. If that is the proxy rather than the visitor, every visitor is reported to Google from one address, which depresses scores site-wide. Set the %3$s option to your proxy addresses or CIDR ranges (or filter %4$s) to resolve the real client IP. Ignore this if %2$s is genuinely the visitor.',
				$present,
				$remote,
				self::TRUSTED_OPTION,
				'gswp_trusted_proxies'
			)
		);
	}
}
