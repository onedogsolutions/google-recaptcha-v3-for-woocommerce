/**
 * Google Security for WordPress — WooCommerce Blocks checkout token injector.
 *
 * The Checkout block submits over the Store API, so there is no hidden
 * `.g-recaptcha-response` field for the classic token-refresh bootstrap to keep
 * populated. Instead we render an invisible fill inside the checkout via the
 * ExperimentalOrderMeta slot, keep a fresh reCAPTCHA token in the checkout
 * extension data (`extensions.gswp.token`), and refresh it around each submit so
 * the single-use token is valid for the outgoing request and for any retry.
 *
 * The server (GSWP_Blocks::validate_store_checkout) enforces the policy: a
 * missing or low-scoring token blocks the checkout with a message. This script
 * only needs to make a valid token available; if reCAPTCHA fails to load, the
 * server-side missing-token block still applies (matching the classic checkout).
 *
 * Written against runtime globals (window.wp.*, window.wc.blocksCheckout) with
 * no build step, mirroring assets/js/gswp-2fa-modal.js.
 */
( function () {
	'use strict';

	var data = window.gswpBlocksData || {};

	if ( ! data.enabled || ! data.siteKey ) {
		return;
	}

	var wp = window.wp || {};
	var wc = window.wc || {};
	var element = wp.element;
	var plugins = wp.plugins;
	var wpData = wp.data;
	var blocksCheckout = wc.blocksCheckout;

	// Bail quietly if the block runtime is not what we expect.
	if ( ! element || ! plugins || ! blocksCheckout || ! blocksCheckout.ExperimentalOrderMeta ) {
		return;
	}

	var siteKey = data.siteKey;
	var isEnterprise = !! data.isEnterprise;
	// reCAPTCHA v3 tokens expire after 120 seconds; refresh before that.
	var REFRESH_INTERVAL = 90 * 1000;

	/**
	 * The active grecaptcha client (enterprise or classic), or null when the
	 * API script has not finished loading yet.
	 */
	function api() {
		if ( typeof window.grecaptcha === 'undefined' ) {
			return null;
		}
		return isEnterprise ? window.grecaptcha.enterprise : window.grecaptcha;
	}

	/**
	 * Execute reCAPTCHA and resolve with a token for the checkout action.
	 *
	 * @return {Promise<string>} Resolves with a token, rejects on failure.
	 */
	function fetchToken() {
		return new Promise( function ( resolve, reject ) {
			var client = api();
			if ( ! client ) {
				reject();
				return;
			}
			client.ready( function () {
				client.execute( siteKey, { action: 'checkout' } ).then( resolve, reject );
			} );
		} );
	}

	/**
	 * Resolve the setExtensionData function from the fill props, falling back to
	 * the checkout data store dispatcher.
	 *
	 * @param {Object} props ExperimentalOrderMeta fill props.
	 * @return {Function|null} setExtensionData(namespace, key, value) or null.
	 */
	function resolveSetter( props ) {
		if ( props && props.checkoutExtensionData && typeof props.checkoutExtensionData.setExtensionData === 'function' ) {
			return props.checkoutExtensionData.setExtensionData;
		}

		if ( wpData && typeof wpData.dispatch === 'function' ) {
			var store = wpData.dispatch( 'wc/store/checkout' );
			if ( store ) {
				if ( typeof store.setExtensionData === 'function' ) {
					return store.setExtensionData;
				}
				if ( typeof store.__internalSetExtensionData === 'function' ) {
					// __internalSetExtensionData( namespace, data ) takes an object.
					return function ( namespace, key, value ) {
						var payload = {};
						payload[ key ] = value;
						store.__internalSetExtensionData( namespace, payload );
					};
				}
			}
		}

		return null;
	}

	/**
	 * The invisible fill component. Renders nothing; its job is to keep a fresh
	 * token in the checkout extension data.
	 *
	 * @param {Object} props Fill props (cart, extensions, context, checkoutExtensionData).
	 * @return {null} No visible output.
	 */
	function TokenInjector( props ) {
		var useEffect = element.useEffect;
		var useRef = element.useRef;

		var fetching = useRef( false );
		var setter = resolveSetter( props );

		// Only run inside the Checkout block, not the Cart block's order summary.
		var context = props && props.context ? String( props.context ) : '';
		var isCheckout = context.indexOf( 'checkout' ) !== -1;

		useEffect( function () {
			if ( ! isCheckout || ! setter ) {
				return undefined;
			}

			var mounted = true;

			function refresh() {
				if ( fetching.current ) {
					return;
				}
				fetching.current = true;
				fetchToken().then(
					function ( token ) {
						fetching.current = false;
						if ( mounted && token ) {
							setter( 'gswp', 'token', token );
						}
					},
					function () {
						fetching.current = false;
					}
				);
			}

			// Prime a token immediately, then keep it fresh on an interval.
			refresh();
			var timer = window.setInterval( function () {
				if ( ! document.hidden ) {
					refresh();
				}
			}, REFRESH_INTERVAL );

			// The interval above is skipped while the tab is hidden, and the
			// browser suspends its timers anyway on a locked phone or a
			// backgrounded tab. Whatever token was current when that happened
			// keeps ageing, so refresh the moment the page is visible again
			// rather than waiting up to another 90 seconds for the interval.
			// The classic bootstrap has done this since 2.22.1; the block
			// checkout was missing it, which is the path a customer took on
			// 2026-08-26 when a ten-minute-old token reached an assessment.
			function onVisible() {
				if ( ! document.hidden ) {
					refresh();
				}
			}

			// A bfcache restore resurrects a page whose timers were frozen and
			// which was already visible when it froze, so visibilitychange
			// never fires for it.
			function onPageShow( event ) {
				if ( event.persisted ) {
					refresh();
				}
			}

			document.addEventListener( 'visibilitychange', onVisible );
			window.addEventListener( 'pageshow', onPageShow );

			// Refresh around each submit attempt: tokens are single use, so a
			// failed attempt (which returns checkout to idle) needs a new one,
			// and a fresh token minimises the chance of an expiry on retry.
			var unsubscribe = function () {};
			if ( wpData && typeof wpData.subscribe === 'function' ) {
				var wasProcessing = false;
				unsubscribe = wpData.subscribe( function () {
					var store = wpData.select( 'wc/store/checkout' );
					if ( ! store ) {
						return;
					}
					var processing = !! ( ( store.isProcessing && store.isProcessing() ) ||
						( store.isBeforeProcessing && store.isBeforeProcessing() ) );

					// Rising edge: submission started — best-effort fresh token.
					if ( processing && ! wasProcessing ) {
						refresh();
					}
					// Falling edge: attempt finished — refresh for a possible retry.
					if ( ! processing && wasProcessing ) {
						refresh();
					}
					wasProcessing = processing;
				}, 'wc/store/checkout' );
			}

			return function () {
				mounted = false;
				window.clearInterval( timer );
				document.removeEventListener( 'visibilitychange', onVisible );
				window.removeEventListener( 'pageshow', onPageShow );
				if ( typeof unsubscribe === 'function' ) {
					unsubscribe();
				}
			};
		}, [ isCheckout, setter ] );

		return null;
	}

	var render = function () {
		return element.createElement(
			blocksCheckout.ExperimentalOrderMeta,
			null,
			element.createElement( TokenInjector, null )
		);
	};

	plugins.registerPlugin( 'gswp-recaptcha-checkout', {
		render: render,
		scope: 'woocommerce-checkout',
	} );
} )();
