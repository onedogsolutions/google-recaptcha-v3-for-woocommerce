import { __ } from '@wordpress/i18n';

const inputClass =
	'block w-full rounded-md border-0 py-1.5 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6 px-3';

export default function SettingsPanel( { settings, onChange } ) {
	const keyType =
		settings.key_type === 'enterprise' ? 'enterprise' : 'classic';
	const isEnterprise = keyType === 'enterprise';

	const keyTypes = [
		{
			id: 'classic',
			label: __( 'Classic v3', 'google-recaptcha-v3-for-woocommerce' ),
			description: __(
				'Site key + secret key. Also works with keys created in Google Cloud Console when using the legacy secret key.',
				'google-recaptcha-v3-for-woocommerce'
			),
		},
		{
			id: 'enterprise',
			label: __( 'Enterprise', 'google-recaptcha-v3-for-woocommerce' ),
			description: __(
				'reCAPTCHA Enterprise assessments via a Google Cloud project ID and API key.',
				'google-recaptcha-v3-for-woocommerce'
			),
		},
	];

	return (
		<div className="bg-white shadow-sm ring-1 ring-gray-900/5 rounded-xl md:col-span-2">
			<div className="px-4 py-6 sm:p-8">
				<h2 className="text-base font-semibold leading-7 text-gray-900">
					{ __(
						'API Credentials',
						'google-recaptcha-v3-for-woocommerce'
					) }
				</h2>
				<p className="mt-1 text-sm leading-6 text-gray-600">
					{ isEnterprise
						? __(
								'Enter your reCAPTCHA Enterprise site key, Google Cloud project ID, and an API key with access to the reCAPTCHA Enterprise API. Manage keys in the ',
								'google-recaptcha-v3-for-woocommerce'
						  )
						: __(
								'Enter your Google reCAPTCHA v3 API keys. You can register your site and generate keys in the ',
								'google-recaptcha-v3-for-woocommerce'
						  ) }
					<a
						href={
							isEnterprise
								? 'https://console.cloud.google.com/security/recaptcha'
								: 'https://www.google.com/recaptcha/admin'
						}
						target="_blank"
						rel="noopener noreferrer"
						className="font-medium text-indigo-600 hover:text-indigo-500 transition"
					>
						{ isEnterprise
							? __(
									'Google Cloud Console',
									'google-recaptcha-v3-for-woocommerce'
							  )
							: __(
									'Google reCAPTCHA Admin Console',
									'google-recaptcha-v3-for-woocommerce'
							  ) }
					</a>
					.
				</p>

				{ /* Key type selector */ }
				<fieldset className="mt-6">
					<legend className="block text-sm font-medium leading-6 text-gray-900">
						{ __(
							'Key Type',
							'google-recaptcha-v3-for-woocommerce'
						) }
					</legend>
					<div className="mt-1.5 grid grid-cols-1 gap-3 sm:grid-cols-2">
						{ keyTypes.map( ( type ) => (
							// eslint-disable-next-line jsx-a11y/label-has-associated-control -- the label wraps the radio input and its text, but the rule cannot resolve the dynamic text expression.
							<label
								key={ type.id }
								className={ `relative flex cursor-pointer rounded-lg border p-3 shadow-sm focus:outline-none transition ${
									keyType === type.id
										? 'border-indigo-600 ring-1 ring-indigo-600 bg-indigo-50/50'
										: 'border-gray-300 bg-white hover:border-gray-400'
								}` }
							>
								<input
									type="radio"
									name="key-type"
									value={ type.id }
									checked={ keyType === type.id }
									onChange={ () =>
										onChange( 'key_type', type.id )
									}
									className="sr-only"
								/>
								<span className="flex flex-col">
									<span className="block text-sm font-semibold text-gray-900">
										{ type.label }
									</span>
									<span className="mt-1 block text-xs leading-5 text-gray-500">
										{ type.description }
									</span>
								</span>
							</label>
						) ) }
					</div>
				</fieldset>

				<div className="mt-6 grid grid-cols-1 gap-x-6 gap-y-4 sm:grid-cols-6">
					<div className="sm:col-span-3">
						<label
							htmlFor="site-key"
							className="block text-sm font-medium leading-6 text-gray-900"
						>
							{ __(
								'Site Key',
								'google-recaptcha-v3-for-woocommerce'
							) }
						</label>
						<div className="mt-1.5">
							<input
								type="text"
								name="site-key"
								id="site-key"
								value={ settings.site_key }
								onChange={ ( e ) =>
									onChange( 'site_key', e.target.value )
								}
								placeholder="6Ld..."
								className={ inputClass }
							/>
						</div>
					</div>

					{ ! isEnterprise && (
						<div className="sm:col-span-3">
							<label
								htmlFor="secret-key"
								className="block text-sm font-medium leading-6 text-gray-900"
							>
								{ __(
									'Secret Key',
									'google-recaptcha-v3-for-woocommerce'
								) }
							</label>
							<div className="mt-1.5">
								<input
									type="password"
									name="secret-key"
									id="secret-key"
									value={ settings.secret_key }
									onChange={ ( e ) =>
										onChange( 'secret_key', e.target.value )
									}
									placeholder="••••••••••••••••••••••••••••••••••••••••"
									className={ inputClass }
								/>
							</div>
						</div>
					) }

					{ isEnterprise && (
						<>
							<div className="sm:col-span-3">
								<label
									htmlFor="gcp-project-id"
									className="block text-sm font-medium leading-6 text-gray-900"
								>
									{ __(
										'Google Cloud Project ID',
										'google-recaptcha-v3-for-woocommerce'
									) }
								</label>
								<div className="mt-1.5">
									<input
										type="text"
										name="gcp-project-id"
										id="gcp-project-id"
										value={ settings.gcp_project_id }
										onChange={ ( e ) =>
											onChange(
												'gcp_project_id',
												e.target.value
											)
										}
										placeholder="my-project-123456"
										className={ inputClass }
									/>
								</div>
							</div>

							<div className="sm:col-span-3">
								<label
									htmlFor="gcp-api-key"
									className="block text-sm font-medium leading-6 text-gray-900"
								>
									{ __(
										'Google Cloud API Key',
										'google-recaptcha-v3-for-woocommerce'
									) }
								</label>
								<div className="mt-1.5">
									<input
										type="password"
										name="gcp-api-key"
										id="gcp-api-key"
										value={ settings.gcp_api_key }
										onChange={ ( e ) =>
											onChange(
												'gcp_api_key',
												e.target.value
											)
										}
										placeholder="AIza..."
										className={ inputClass }
									/>
								</div>
								<p className="mt-1.5 text-xs leading-5 text-gray-500">
									{ __(
										'The API key must have the reCAPTCHA Enterprise API enabled. Restrict it to that API in Google Cloud Console.',
										'google-recaptcha-v3-for-woocommerce'
									) }
								</p>
							</div>
						</>
					) }
				</div>
			</div>
		</div>
	);
}
