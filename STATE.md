# State Tracker - Google reCAPTCHA v3 for WooCommerce

## Current Phase: Phase 5 (Project Finalization & Artifact Bundling)

### Modifications Done
- Created `.gitignore` to prevent tracking of development artifacts (like `node_modules` and compiled zips).
- Updated `package.json` to pin stable releases of Tailwind CSS (`^4.0.0`) and `@tailwindcss/postcss` (`^4.0.0`), and added linting scripts.
- Added `webpack.config.js` extending WordPress's default scripts configuration to bundle JavaScript and extract CSS correctly.
- Created `google-recaptcha-v3-for-woocommerce.php` (main bootstrap file).
- Created `includes/class-recaptcha-woo-key-scavenger.php` to scan and scavenge keys from Fluent Forms, Gravity Forms, Beaver Builder options, and Beaver Builder postmeta.
- Created `includes/class-recaptcha-woo-admin.php` to register the submenu under WooCommerce settings and enqueue React entrypoints using localizing scripts.
- Created `includes/class-recaptcha-woo-rest-api.php` exposing `GET /settings`, `POST /settings` (with page-specific score thresholds), and `GET /scavenge`.
- Created React components `src/components/App.jsx`, `src/components/SettingsPanel.jsx`, `src/components/PageToggles.jsx`, `src/components/KeyScavenger.jsx`, `src/components/StatusBadge.jsx`, and Webpack entrypoint `src/index.js`.
- Created `src/styles/index.css` defining the scoped Tailwind v4 styling.
- Installed node module dependencies (`npm install`).
- Compiled assets with webpack successfully (`npm run build`).
- Created `includes/class-recaptcha-woo-frontend.php` to inject the Google API scripts and hidden inputs onto WooCommerce login, registration, and checkout screens.
- Created `includes/class-recaptcha-woo-verifier.php` to validate incoming reCAPTCHA tokens server-side using Google API and WP_Error handling.
- Created standard plugin meta file `readme.txt`.
- Optimized the database key scavenger flow: replaced the automatic, on-load database scanning query with an explicit user-triggered manual scan (`POST /recaptcha-woo/v1/scan-keys`).
- Added check for `fluentform_settings` option within the key scavenger logic.
- Introduced interactive frontend states (`isScanning`, `scanPerformed`, `discoveredData`) with user controls styled using Tailwind v4.
- Reworked frontend token handling (v1.1.0): tokens are pre-fetched on page load and refreshed before the two-minute expiry, on `updated_checkout`, on `checkout_error`, and on tab refocus, so gateway-driven submissions (Stripe UPE, PayPal PPCP) always carry a valid token. Inline JS now attaches via `wp_add_inline_script` so it is never duplicated inside AJAX checkout fragments.
- Added reCAPTCHA Enterprise support (v1.1.0): new `key_type`, `gcp_project_id`, and `gcp_api_key` settings; frontend loads `enterprise.js` and uses `grecaptcha.enterprise`; verifier creates assessments via `recaptchaenterprise.googleapis.com` with expected-action checking.
- Hardened verification failure modes (v1.1.0): credential misconfiguration (invalid secret, bad API key/project) logs a warning to the WooCommerce logger and fails open instead of blocking customers; expired/duplicate tokens return a dedicated "verification expired" message.

### Files Created/Modified
- [x] [.gitignore](file:///Users/rwaterbury/Developer/google-recaptcha-v3-for-woocommerce/.gitignore)
- [x] [package.json](file:///Users/rwaterbury/Developer/google-recaptcha-v3-for-woocommerce/package.json)
- [x] [webpack.config.js](file:///Users/rwaterbury/Developer/google-recaptcha-v3-for-woocommerce/webpack.config.js)
- [x] [google-recaptcha-v3-for-woocommerce.php](file:///Users/rwaterbury/Developer/google-recaptcha-v3-for-woocommerce/google-recaptcha-v3-for-woocommerce.php)
- [x] [includes/class-recaptcha-woo-key-scavenger.php](file:///Users/rwaterbury/Developer/google-recaptcha-v3-for-woocommerce/includes/class-recaptcha-woo-key-scavenger.php)
- [x] [includes/class-recaptcha-woo-admin.php](file:///Users/rwaterbury/Developer/google-recaptcha-v3-for-woocommerce/includes/class-recaptcha-woo-admin.php)
- [x] [includes/class-recaptcha-woo-rest-api.php](file:///Users/rwaterbury/Developer/google-recaptcha-v3-for-woocommerce/includes/class-recaptcha-woo-rest-api.php)
- [x] [src/index.js](file:///Users/rwaterbury/Developer/google-recaptcha-v3-for-woocommerce/src/index.js)
- [x] [src/components/App.jsx](file:///Users/rwaterbury/Developer/google-recaptcha-v3-for-woocommerce/src/components/App.jsx)
- [x] [src/components/SettingsPanel.jsx](file:///Users/rwaterbury/Developer/google-recaptcha-v3-for-woocommerce/src/components/SettingsPanel.jsx)
- [x] [src/components/PageToggles.jsx](file:///Users/rwaterbury/Developer/google-recaptcha-v3-for-woocommerce/src/components/PageToggles.jsx)
- [x] [src/components/KeyScavenger.jsx](file:///Users/rwaterbury/Developer/google-recaptcha-v3-for-woocommerce/src/components/KeyScavenger.jsx)
- [x] [src/components/StatusBadge.jsx](file:///Users/rwaterbury/Developer/google-recaptcha-v3-for-woocommerce/src/components/StatusBadge.jsx)
- [x] [src/styles/index.css](file:///Users/rwaterbury/Developer/google-recaptcha-v3-for-woocommerce/src/styles/index.css)
- [x] [includes/class-recaptcha-woo-frontend.php](file:///Users/rwaterbury/Developer/google-recaptcha-v3-for-woocommerce/includes/class-recaptcha-woo-frontend.php)
- [x] [includes/class-recaptcha-woo-verifier.php](file:///Users/rwaterbury/Developer/google-recaptcha-v3-for-woocommerce/includes/class-recaptcha-woo-verifier.php)
- [x] [readme.txt](file:///Users/rwaterbury/Developer/google-recaptcha-v3-for-woocommerce/readme.txt)
- [x] [STATE.md](file:///Users/rwaterbury/Developer/google-recaptcha-v3-for-woocommerce/STATE.md)

### Current Status
- Assets successfully built.
- Manual scan integration for Smart Key Scavenger successfully completed and linted.
- Ready to compile final ZIP plugin package for distribution.
- Ready to push code to GitHub.
