import { __ } from '@wordpress/i18n';

export default function Compatibility( { settings, onChange } ) {
	const mode =
		settings.conflict_mode === 'active' || settings.conflict_mode === 'site'
			? settings.conflict_mode
			: 'off';

	const verbose =
		settings.verbose_logging === '1' || settings.verbose_logging === true;

	// Read-only, supplied by the settings endpoint: what this very request
	// resolved to. The point of showing both is that an operator can see a
	// mismatch without reading a log or guessing.
	const remoteAddr = settings.remote_addr || '';
	const resolvedIp = settings.resolved_client_ip || '';
	const trustedProxies = settings.trusted_proxies || '';
	const ipHeader = settings.client_ip_header || 'X-Forwarded-For';
	const proxiesDeclared = trustedProxies.trim() !== '';
	const unwrapping =
		remoteAddr !== '' && resolvedIp !== '' && remoteAddr !== resolvedIp;

	let ipNote;
	if ( unwrapping ) {
		ipNote = __(
			'These differ, so a declared proxy is being unwrapped and the visitor’s own address is what reaches Google. This is the correct state for a site behind a CDN.',
			'google-security-for-wordpress'
		);
	} else if ( proxiesDeclared ) {
		ipNote = __(
			'These match. Either this request did not arrive through one of the proxies declared below, or the address below is genuinely yours.',
			'google-security-for-wordpress'
		);
	} else {
		ipNote = __(
			'These match, which is correct for a site that serves browsers directly. If this address is your CDN rather than your own, declare it below — otherwise every visitor is being reported to Google from it.',
			'google-security-for-wordpress'
		);
	}

	const adminData =
		typeof window !== 'undefined' && window.gswpAdminData
			? window.gswpAdminData
			: {};
	const conflict = adminData.loaderConflict || null;
	const suppressing = !! ( conflict && conflict.suppressing );
	const ourKey = adminData.ourSiteKeyMasked || '';

	const modes = [
		{
			id: 'off',
			label: __( 'Disabled', 'google-security-for-wordpress' ),
			description: __(
				'Legacy setting, identical to the recommended option below. Nothing is removed.',
				'google-security-for-wordpress'
			),
		},
		{
			id: 'active',
			label: __( 'Share one loader', 'google-security-for-wordpress' ),
			description: __(
				'Recommended. Plugins using the same site key share a single reCAPTCHA loader. A plugin using a different site key is reported to you but never removed, so its forms keep working.',
				'google-security-for-wordpress'
			),
		},
		{
			id: 'site',
			label: __(
				'Remove other plugins’ reCAPTCHA',
				'google-security-for-wordpress'
			),
			description: __(
				'Destructive. Strips other plugins’ reCAPTCHA from every front-end page when it uses a different site key. Those plugins’ forms — including payment forms — may stop submitting. Use only after removing reCAPTCHA from them yourself.',
				'google-security-for-wordpress'
			),
		},
	];

	return (
		<div className="bg-white shadow-sm ring-1 ring-gray-900/5 rounded-xl">
			<div className="px-4 py-6 sm:p-8">
				<h2 className="text-base font-semibold leading-7 text-gray-900">
					{ __(
						'reCAPTCHA Conflict Handling',
						'google-security-for-wordpress'
					) }
				</h2>
				<p className="mt-1 text-sm leading-6 text-gray-600">
					{ __(
						'Google recommends loading reCAPTCHA only once per page, so plugins using the same site key as this one automatically share a single loader. Two different site keys cannot share one — these settings control what happens then.',
						'google-security-for-wordpress'
					) }
				</p>

				<fieldset className="mt-6">
					<legend className="sr-only">
						{ __(
							'Conflict handling mode',
							'google-security-for-wordpress'
						) }
					</legend>
					<div className="space-y-3">
						{ modes.map( ( option ) => (
							// eslint-disable-next-line jsx-a11y/label-has-associated-control -- the label wraps the radio input and its text, but the rule cannot resolve the dynamic text expression.
							<label
								key={ option.id }
								className={ `relative flex cursor-pointer rounded-lg border p-3 shadow-sm focus:outline-none transition ${
									mode === option.id
										? 'border-indigo-600 ring-1 ring-indigo-600 bg-indigo-50/50'
										: 'border-gray-300 bg-white hover:border-gray-400'
								}` }
							>
								<input
									type="radio"
									name="conflict-mode"
									value={ option.id }
									checked={ mode === option.id }
									onChange={ () =>
										onChange( 'conflict_mode', option.id )
									}
									className="sr-only"
								/>
								<span className="flex flex-col">
									<span className="block text-sm font-semibold text-gray-900">
										{ option.label }
									</span>
									<span className="mt-1 block text-xs leading-5 text-gray-500">
										{ option.description }
									</span>
								</span>
							</label>
						) ) }
					</div>
				</fieldset>

				{ conflict &&
				conflict.loaders &&
				conflict.loaders.length > 0 ? (
					<div
						className={ `mt-6 rounded-lg border p-4 ${
							suppressing
								? 'border-red-300 bg-red-50'
								: 'border-amber-300 bg-amber-50'
						}` }
					>
						<h3
							className={ `text-sm font-semibold ${
								suppressing ? 'text-red-800' : 'text-amber-800'
							}` }
						>
							{ suppressing
								? __(
										'Blocking another plugin’s reCAPTCHA',
										'google-security-for-wordpress'
								  )
								: __(
										'Conflicting reCAPTCHA site key detected',
										'google-security-for-wordpress'
								  ) }
						</h3>
						<p
							className={ `mt-1 text-xs leading-5 ${
								suppressing ? 'text-red-700' : 'text-amber-700'
							}` }
						>
							{ suppressing
								? __(
										'“Remove other plugins’ reCAPTCHA” is switched on and this plugin is stripping another plugin’s reCAPTCHA script because it uses a different site key. That plugin’s forms — including payment forms such as Gravity Forms with Stripe — may be failing to submit. Switch to “Share one loader” to stop this.',
										'google-security-for-wordpress'
								  )
								: __(
										'Another plugin loads reCAPTCHA with a different site key. Only one site key can be pre-rendered per page, so one of the two will fail to execute.',
										'google-security-for-wordpress'
								  ) }
						</p>
						<ul className="mt-3 space-y-1">
							{ conflict.loaders.map( ( loader ) => (
								<li
									key={ loader.handle }
									className={ `text-xs font-mono ${
										suppressing
											? 'text-red-800'
											: 'text-amber-800'
									}` }
								>
									{ loader.handle } — { loader.key }
								</li>
							) ) }
							<li className="text-xs font-mono text-gray-600">
								{ __(
									'this plugin',
									'google-security-for-wordpress'
								) }{ ' ' }
								— { ourKey }
							</li>
						</ul>
						<p
							className={ `mt-3 text-xs leading-5 ${
								suppressing ? 'text-red-700' : 'text-amber-700'
							}` }
						>
							{ __(
								'Set both plugins to the same reCAPTCHA site key. Matching keys are shared automatically — this plugin and the other one use a single loader, and neither is removed.',
								'google-security-for-wordpress'
							) }
						</p>
					</div>
				) : (
					<p className="mt-4 text-xs leading-5 text-gray-400">
						{ __(
							'No conflicting reCAPTCHA loaders have been observed. Other plugins using the same site key as this one share a single loader automatically and are never removed.',
							'google-security-for-wordpress'
						) }
					</p>
				) }

				{ /* Visitor IP address */ }
				<div className="mt-8 border-t border-gray-100 pt-6">
					<h3 className="text-sm font-semibold text-gray-900">
						{ __(
							'Visitor IP address',
							'google-security-for-wordpress'
						) }
					</h3>
					<p className="mt-1 text-sm text-gray-500">
						{ __(
							'Every reCAPTCHA assessment reports the visitor’s address to Google, and Google weighs it. If this site sits behind a CDN or reverse proxy, the address WordPress sees is the proxy’s — so every visitor is reported from one datacenter address, which depresses scores for all of them and gives Account Defender nothing to distinguish them by. Declare your proxies here and the real visitor address is used instead.',
							'google-security-for-wordpress'
						) }
					</p>

					<div className="mt-4 rounded-md bg-gray-50 border border-gray-200 p-4">
						<dl className="grid grid-cols-1 gap-y-3 sm:grid-cols-2 sm:gap-x-6">
							<div>
								<dt className="text-xs font-medium uppercase tracking-wide text-gray-500">
									{ __(
										'Seen by WordPress',
										'google-security-for-wordpress'
									) }
								</dt>
								<dd className="mt-1 font-mono text-sm text-gray-900">
									{ remoteAddr ||
										__(
											'unavailable',
											'google-security-for-wordpress'
										) }
								</dd>
							</div>
							<div>
								<dt className="text-xs font-medium uppercase tracking-wide text-gray-500">
									{ __(
										'Sent to Google',
										'google-security-for-wordpress'
									) }
								</dt>
								<dd className="mt-1 font-mono text-sm text-gray-900">
									{ resolvedIp ||
										__(
											'unavailable',
											'google-security-for-wordpress'
										) }
								</dd>
							</div>
						</dl>
						<p className="mt-3 text-xs leading-5 text-gray-500">
							{ ipNote }
						</p>
					</div>

					<div className="mt-6">
						<label
							htmlFor="gswp-trusted-proxies"
							className="block text-sm font-semibold text-gray-900"
						>
							{ __(
								'Trusted proxies',
								'google-security-for-wordpress'
							) }
						</label>
						<textarea
							id="gswp-trusted-proxies"
							rows="3"
							value={ trustedProxies }
							onChange={ ( e ) =>
								onChange( 'trusted_proxies', e.target.value )
							}
							placeholder="192.0.2.10, 198.51.100.0/24, 2400:cb00::/32"
							className="mt-2 block w-full rounded-md border-0 py-1.5 font-mono text-sm text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:leading-6"
						/>
						<p className="mt-2 text-sm text-gray-500">
							{ __(
								'Addresses or CIDR ranges, IPv4 or IPv6, separated by commas or line breaks. Leave empty — the default — and the address WordPress sees is used unchanged, exactly as before. Entries that are not a valid address or range are dropped when you save.',
								'google-security-for-wordpress'
							) }
						</p>
						<p className="mt-2 text-xs leading-5 text-gray-400">
							{ __(
								'Only list proxies you control. The forwarded address is read solely when a request actually arrives from one of these, because any client can claim any address in a forwarding header — trusting that unconditionally would let a low-scoring visitor pass off a clean address as their own.',
								'google-security-for-wordpress'
							) }
						</p>
					</div>

					<div className="mt-6">
						<label
							htmlFor="gswp-client-ip-header"
							className="block text-sm font-semibold text-gray-900"
						>
							{ __(
								'Forwarded address header',
								'google-security-for-wordpress'
							) }
						</label>
						<select
							id="gswp-client-ip-header"
							value={ ipHeader }
							onChange={ ( e ) =>
								onChange( 'client_ip_header', e.target.value )
							}
							className="mt-2 block w-full max-w-xs rounded-md border-0 py-1.5 pl-3 pr-10 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
						>
							<option value="X-Forwarded-For">
								X-Forwarded-For
							</option>
							<option value="CF-Connecting-IP">
								CF-Connecting-IP
							</option>
							<option value="True-Client-IP">
								True-Client-IP
							</option>
							<option value="X-Real-IP">X-Real-IP</option>
						</select>
						<p className="mt-2 text-sm text-gray-500">
							{ __(
								'Which header your proxy puts the visitor’s address in. X-Forwarded-For suits most CDNs and load balancers, including QUIC.cloud; Cloudflare populates CF-Connecting-IP. Ignored while no trusted proxies are declared.',
								'google-security-for-wordpress'
							) }
						</p>
					</div>
				</div>

				{ /* Diagnostics: verbose logging */ }
				<div className="mt-8 border-t border-gray-100 pt-6 flex flex-col gap-y-3 sm:flex-row sm:items-center sm:justify-between sm:gap-x-8">
					<div className="flex-1">
						<h3 className="text-sm font-semibold text-gray-900">
							{ __(
								'Verbose logging',
								'google-security-for-wordpress'
							) }
						</h3>
						<p className="mt-1 text-sm text-gray-500">
							{ __(
								'By default only anomalies and failures are written to the WooCommerce log (source “gswp”). Turn this on to also log every assessment — Transaction risk per checkout and Account Defender labels per login. Useful for debugging; leave off in production to keep the log small.',
								'google-security-for-wordpress'
							) }
						</p>
					</div>
					<div className="flex items-center gap-x-3">
						<span className="text-sm text-gray-600">
							{ verbose
								? __(
										'Enabled',
										'google-security-for-wordpress'
								  )
								: __(
										'Disabled',
										'google-security-for-wordpress'
								  ) }
						</span>
						<button
							type="button"
							aria-label={ __(
								'Verbose logging',
								'google-security-for-wordpress'
							) }
							className={ `relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-indigo-600 focus:ring-offset-2 ${
								verbose ? 'bg-indigo-600' : 'bg-gray-200'
							}` }
							onClick={ () =>
								onChange(
									'verbose_logging',
									verbose ? '0' : '1'
								)
							}
						>
							<span
								aria-hidden="true"
								className={ `pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${
									verbose ? 'translate-x-5' : 'translate-x-0'
								}` }
							/>
						</button>
					</div>
				</div>
			</div>
		</div>
	);
}
