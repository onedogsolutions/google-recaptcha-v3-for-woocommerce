=== Google reCAPTCHA v3 for WooCommerce ===
Contributors: One Dog Solutions
Tags: recaptcha, woocommerce, captcha, spam, security
Requires at least: 5.8
Tested up to: 6.4
Requires PHP: 7.4
Stable tag: 1.1.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Google reCAPTCHA v3 integration for WooCommerce Login, Registration, and Checkout forms with page-specific thresholds and automated key discovery.

== Description ==

Google reCAPTCHA v3 for WooCommerce provides a seamless, invisible security layer to protect your WooCommerce customer endpoints from automated abuse. Shield customer registration, login, and checkout procedures from carding, credentials brute-forcing, and spam accounts.

= Features =
* **Complete Isolation**: Clean styling that matches modern admin dashboards without bleeding Tailwind resets into core WordPress screens.
* **Flexible Page-Specific Thresholds**: Configure custom score thresholds individually for WooCommerce Login, Registration, and Checkout forms.
* **Key Scavenging Onboarding**: Discovers existing reCAPTCHA keys registered by Gravity Forms, Fluent Forms, Beaver Builder, and PowerPack so you can import them with a single click.
* **Zero Overhead Frontend**: Only enqueues JavaScript files on active target pages to maintain optimal client-side page speed.

== Installation ==

1. Upload the plugin files to the `/wp-content/plugins/google-recaptcha-v3-for-woocommerce` directory, or install the plugin through the WordPress plugins screen directly.
2. Activate the plugin.
3. Navigate to **WooCommerce -> reCAPTCHA v3** to configure your site keys, protected forms, and score thresholds.

== Frequently Asked Questions ==

= Does this work with WooCommerce checkout blocks? =
Currently, this plugin supports the classic shortcode-based checkout pages.

= What score threshold should I use? =
We recommend a default threshold of 0.5. If you encounter spam submissions, increase the threshold closer to 1.0 (strict). If humans are blocked, lower it closer to 0.0 (lenient).

== Changelog ==

= 1.1.0 =
* Tokens are now fetched on page load and refreshed automatically before expiry (and on checkout updates/errors), so checkout submissions triggered by payment gateway scripts (Stripe, PayPal smart buttons, express checkout) always carry a valid token. Fixes "Anti-spam verification token is missing" errors.
* Added reCAPTCHA Enterprise support: select the Enterprise key type and verify tokens through the reCAPTCHA Enterprise assessments API using a Google Cloud project ID and API key.
* Credential misconfiguration (invalid secret key, bad API key/project) is now logged to WooCommerce > Status > Logs and no longer blocks customers from checking out.

= 1.0.0 =
* Initial release.
