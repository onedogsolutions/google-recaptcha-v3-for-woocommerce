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
	 * Known CDN providers whose edge IP lists can be trusted automatically.
	 *
	 * Each provider has an option that stores fetched ranges and a toggle
	 * option that decides whether those ranges are merged into the trusted
	 * proxy list at resolution time.
	 *
	 * @var array
	 */
	const CDN_PROVIDERS = array(
		'cloudflare' => array(
			'option' => 'gswp_cdn_ips_cloudflare',
			'toggle' => 'gswp_trusted_cloudflare',
			'url'    => 'https://api.cloudflare.com/client/v4/ips',
			'etag'   => 'gswp_cdn_etag_cloudflare',
		),
		'quiccloud'  => array(
			'option' => 'gswp_cdn_ips_quiccloud',
			'toggle' => 'gswp_trusted_quiccloud',
			'url'    => 'https://quic.cloud/ips',
		),
	);

	/**
	 * WordPress cron hook used to refresh CDN IP lists.
	 */
	const CDN_REFRESH_HOOK = 'gswp_refresh_cdn_ips';

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
	 * Returns the manually-declared list plus any ranges fetched for enabled
	 * CDN providers. CDN ranges are validated and de-duplicated with the manual
	 * list so a stale or malformed entry from an upstream source cannot break
	 * resolution.
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

		foreach ( array_keys( self::CDN_PROVIDERS ) as $provider ) {
			if ( self::cdn_enabled( $provider ) ) {
				$entries = array_merge( $entries, self::cdn_ranges( $provider ) );
			}
		}

		$entries = array_map( 'trim', $entries );
		$entries = array_filter( $entries, 'strlen' );
		$entries = array_unique( $entries );

		return array_values( $entries );
	}

	/**
	 * Whether a CDN provider toggle is enabled.
	 *
	 * @param string $provider Provider key (cloudflare|quiccloud).
	 * @return bool
	 */
	public static function cdn_enabled( $provider ) {
		$config = isset( self::CDN_PROVIDERS[ $provider ] ) ? self::CDN_PROVIDERS[ $provider ] : null;

		if ( ! $config ) {
			return false;
		}

		return '1' === (string) get_option( $config['toggle'], '0' );
	}

	/**
	 * Validated ranges stored for a CDN provider.
	 *
	 * @param string $provider Provider key (cloudflare|quiccloud).
	 * @return array
	 */
	public static function cdn_ranges( $provider ) {
		$config = isset( self::CDN_PROVIDERS[ $provider ] ) ? self::CDN_PROVIDERS[ $provider ] : null;

		if ( ! $config ) {
			return array();
		}

		$stored = (string) get_option( $config['option'], '' );
		if ( '' === $stored ) {
			return array();
		}

		$ranges = array();
		foreach ( preg_split( '/[\s,]+/', $stored, -1, PREG_SPLIT_NO_EMPTY ) as $entry ) {
			$entry = trim( (string) $entry );
			if ( self::is_valid_range( $entry ) ) {
				$ranges[] = $entry;
			}
		}

		return $ranges;
	}

	/**
	 * Count stored ranges for a CDN provider, split by address family.
	 *
	 * @param string $provider Provider key (cloudflare|quiccloud).
	 * @return array Array with 'ipv4', 'ipv6' and 'total' counts.
	 */
	public static function count_cdn_ranges( $provider ) {
		$ipv4 = 0;
		$ipv6 = 0;

		foreach ( self::cdn_ranges( $provider ) as $range ) {
			if ( false !== strpos( $range, ':' ) ) {
				++$ipv6;
			} else {
				++$ipv4;
			}
		}

		return array(
			'ipv4'  => $ipv4,
			'ipv6'  => $ipv6,
			'total' => $ipv4 + $ipv6,
		);
	}

	/**
	 * Refresh CDN edge IP lists from their public endpoints.
	 *
	 * @param string $provider Provider key (cloudflare|quiccloud) or empty to refresh all enabled providers.
	 * @return array Result per provider with 'success', 'count' and 'message'.
	 */
	public static function refresh_cdn_ips( $provider = '' ) {
		$providers = array_keys( self::CDN_PROVIDERS );
		if ( '' !== $provider && ! in_array( $provider, $providers, true ) ) {
			return array(
				$provider => array(
					'success' => false,
					'count'   => 0,
					'message' => 'Unknown CDN provider.',
				),
			);
		}

		$targets = '' === $provider ? $providers : array( $provider );
		$results = array();

		foreach ( $targets as $key ) {
			$results[ $key ] = self::refresh_provider_ips( $key );
		}

		$any_success = false;
		foreach ( $results as $result ) {
			if ( $result['success'] ) {
				$any_success = true;
				break;
			}
		}

		if ( $any_success ) {
			update_option( 'gswp_cdn_last_refresh', gmdate( 'Y-m-d H:i:s' ) . ' UTC' );
		}

		return $results;
	}

	/**
	 * Refresh a single provider's IP list.
	 *
	 * @param string $provider Provider key.
	 * @return array Result with 'success', 'count' and 'message'.
	 */
	private static function refresh_provider_ips( $provider ) {
		$config = self::CDN_PROVIDERS[ $provider ];

		$response = wp_remote_get(
			$config['url'],
			array(
				'timeout' => 15,
				'headers' => array(
					'User-Agent' => 'Google Security for WordPress/' . GSWP_VERSION . '; ' . get_bloginfo( 'url' ),
				),
			)
		);

		if ( is_wp_error( $response ) ) {
			self::maybe_seed_fallback( $provider );
			return array(
				'success' => false,
				'count'   => count( self::cdn_ranges( $provider ) ),
				'message' => $response->get_error_message(),
			);
		}

		$status = wp_remote_retrieve_response_code( $response );
		$body   = wp_remote_retrieve_body( $response );

		if ( 200 !== $status || '' === $body ) {
			self::maybe_seed_fallback( $provider );
			return array(
				'success' => false,
				'count'   => count( self::cdn_ranges( $provider ) ),
				'message' => 'HTTP ' . $status . ' or empty response.',
			);
		}

		$ranges = array();

		if ( 'cloudflare' === $provider ) {
			$json = json_decode( $body, true );

			if ( ! is_array( $json ) || empty( $json['success'] ) || ! isset( $json['result'] ) ) {
				self::maybe_seed_fallback( $provider );
				return array(
					'success' => false,
					'count'   => count( self::cdn_ranges( $provider ) ),
					'message' => 'Unexpected response format.',
				);
			}

			$etag = isset( $json['result']['etag'] ) ? sanitize_text_field( $json['result']['etag'] ) : '';
			if ( '' !== $etag && $etag === get_option( $config['etag'], '' ) ) {
				return array(
					'success' => true,
					'count'   => count( self::cdn_ranges( $provider ) ),
					'message' => 'No change since last refresh.',
				);
			}

			$ipv4 = isset( $json['result']['ipv4_cidrs'] ) ? (array) $json['result']['ipv4_cidrs'] : array();
			$ipv6 = isset( $json['result']['ipv6_cidrs'] ) ? (array) $json['result']['ipv6_cidrs'] : array();
			$ranges = array_merge( $ipv4, $ipv6 );

			if ( '' !== $etag ) {
				update_option( $config['etag'], $etag );
			}
		} else {
			// QUIC.cloud publishes one address or CIDR per line.
			foreach ( preg_split( '/\r\n|\r|\n/', $body, -1, PREG_SPLIT_NO_EMPTY ) as $line ) {
				$line = sanitize_text_field( trim( $line ) );
				if ( '' !== $line ) {
					$ranges[] = $line;
				}
			}
		}

		$valid = array();
		foreach ( $ranges as $range ) {
			if ( self::is_valid_range( $range ) ) {
				$valid[] = $range;
			}
		}

		if ( empty( $valid ) ) {
			self::maybe_seed_fallback( $provider );
			return array(
				'success' => false,
				'count'   => count( self::cdn_ranges( $provider ) ),
				'message' => 'No valid ranges found in response.',
			);
		}

		$valid = array_values( array_unique( $valid ) );
		update_option( $config['option'], implode( ', ', $valid ) );

		return array(
			'success' => true,
			'count'   => count( $valid ),
			'message' => 'Refreshed successfully.',
		);
	}

	/**
	 * Seed a provider's stored ranges from the bundled fallback when no stored
	 * list exists yet.
	 *
	 * @param string $provider Provider key.
	 */
	private static function maybe_seed_fallback( $provider ) {
		$config = self::CDN_PROVIDERS[ $provider ];

		if ( '' !== (string) get_option( $config['option'], '' ) ) {
			return;
		}

		$fallback = self::default_cdn_ranges( $provider );
		if ( ! empty( $fallback ) ) {
			update_option( $config['option'], implode( ', ', $fallback ) );
		}
	}

	/**
	 * Bundled fallback ranges for each supported CDN.
	 *
	 * These are used when a provider's public endpoint cannot be reached on the
	 * first refresh so the toggle still provides coverage immediately.
	 *
	 * @param string $provider Provider key.
	 * @return array
	 */
	public static function default_cdn_ranges( $provider ) {
		if ( 'cloudflare' === $provider ) {
			return array(
				'173.245.48.0/20',
				'103.21.244.0/22',
				'103.22.200.0/22',
				'103.31.4.0/22',
				'141.101.64.0/18',
				'108.162.192.0/18',
				'190.93.240.0/20',
				'188.114.96.0/20',
				'197.234.240.0/22',
				'198.41.128.0/17',
				'162.158.0.0/15',
				'104.16.0.0/13',
				'104.24.0.0/14',
				'172.64.0.0/13',
				'131.0.72.0/22',
				'2400:cb00::/32',
				'2606:4700::/32',
				'2803:f800::/32',
				'2405:b500::/32',
				'2405:8100::/32',
				'2a06:98c0::/29',
				'2c0f:f248::/32',
			);
		}

		if ( 'quiccloud' === $provider ) {
			return array(
				'102.221.36.98',
				'103.106.229.82',
				'103.106.229.94',
				'103.146.63.42',
				'103.152.118.219',
				'103.152.118.72',
				'103.164.203.163',
				'103.167.151.84',
				'103.72.163.222',
				'103.75.117.169',
				'104.244.77.37',
				'108.61.158.223',
				'108.61.200.94',
				'109.248.43.195',
				'135.125.104.145',
				'136.243.106.228',
				'139.84.230.39',
				'141.164.38.65',
				'141.227.158.131',
				'144.202.90.7',
				'146.88.239.197',
				'147.78.0.165',
				'147.78.3.161',
				'149.28.136.245',
				'149.28.47.113',
				'149.28.85.239',
				'15.204.231.24',
				'15.235.180.91',
				'15.235.181.227',
				'152.53.162.246',
				'152.53.167.143',
				'152.53.168.39',
				'152.53.169.106',
				'152.53.36.14',
				'152.53.38.14',
				'154.205.144.192',
				'155.138.221.81',
				'156.67.218.140',
				'158.51.123.249',
				'162.254.117.80',
				'162.254.118.29',
				'162.55.9.23',
				'163.182.174.161',
				'163.47.21.168',
				'164.52.202.100',
				'167.71.185.204',
				'167.88.61.211',
				'170.249.218.98',
				'173.234.26.74',
				'176.9.114.118',
				'178.17.171.177',
				'178.22.124.251',
				'178.255.220.12',
				'18.192.146.200',
				'185.116.60.231',
				'185.116.60.232',
				'185.126.237.51',
				'185.212.169.91',
				'185.228.26.40',
				'185.231.233.130',
				'185.53.57.40',
				'185.53.57.89',
				'188.172.228.182',
				'188.172.229.113',
				'188.64.184.71',
				'190.92.176.5',
				'191.96.101.140',
				'192.248.156.201',
				'192.248.191.135',
				'192.99.38.117',
				'193.203.191.189',
				'195.137.220.243',
				'195.231.17.141',
				'199.247.28.91',
				'199.59.247.242',
				'201.182.97.70',
				'209.124.84.191',
				'209.208.26.218',
				'211.23.143.87',
				'213.159.1.75',
				'213.183.48.170',
				'213.184.85.245',
				'216.106.177.77',
				'216.128.179.195',
				'216.238.104.48',
				'216.238.71.13',
				'23.160.56.125',
				'23.95.72.16',
				'31.131.4.244',
				'31.22.115.186',
				'31.40.212.152',
				'37.120.163.165',
				'38.114.121.40',
				'38.54.30.228',
				'38.54.79.187',
				'38.60.253.237',
				'40.160.225.31',
				'40.160.241.195',
				'41.185.29.210',
				'41.223.52.170',
				'45.124.65.86',
				'45.248.77.61',
				'45.32.123.201',
				'45.32.183.112',
				'45.32.203.144',
				'45.32.67.144',
				'45.32.77.223',
				'45.63.67.181',
				'45.76.252.131',
				'45.77.148.74',
				'45.77.165.216',
				'45.77.51.171',
				'46.250.220.133',
				'49.12.102.29',
				'5.134.119.103',
				'51.158.202.109',
				'51.161.196.212',
				'51.68.143.214',
				'51.89.11.45',
				'54.36.103.97',
				'57.129.146.219',
				'57.131.30.109',
				'61.219.247.87',
				'61.219.247.90',
				'64.176.165.8',
				'64.176.4.251',
				'64.227.16.93',
				'65.108.104.232',
				'65.109.39.175',
				'65.20.76.133',
				'65.21.81.51',
				'66.163.114.36',
				'66.42.124.101',
				'66.42.75.121',
				'67.219.99.102',
				'70.34.206.56',
				'74.91.25.147',
				'79.172.239.249',
				'81.31.156.245',
				'81.31.156.246',
				'83.138.12.246',
				'86.105.14.231',
				'86.105.14.232',
				'89.58.38.4',
				'91.148.135.53',
				'91.201.67.121',
				'91.228.7.67',
				'92.118.205.75',
				'93.95.231.22',
				'94.75.232.90',
				'95.179.145.87',
				'95.179.245.162',
				'95.216.116.209',
			);
		}

		return array();
	}

	/**
	 * Ensure the CDN refresh cron event is scheduled.
	 */
	public static function schedule_cdn_refresh() {
		if ( ! wp_next_scheduled( self::CDN_REFRESH_HOOK ) ) {
			wp_schedule_event( time(), 'daily', self::CDN_REFRESH_HOOK );
		}
	}

	/**
	 * Clear the CDN refresh cron event.
	 */
	public static function unschedule_cdn_refresh() {
		wp_clear_scheduled_hook( self::CDN_REFRESH_HOOK );
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
