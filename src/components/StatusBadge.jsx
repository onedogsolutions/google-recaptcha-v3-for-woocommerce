import { __ } from '@wordpress/i18n';

export default function StatusBadge( { settings } ) {
	const hasSite = !! settings.site_key;
	const hasSecret =
		settings.key_type === 'enterprise'
			? !! settings.gcp_project_id && !! settings.gcp_api_key
			: !! settings.secret_key;

	let label = __( 'Inactive', 'google-recaptcha-v3-for-woocommerce' );
	let badgeClass = 'bg-red-50 text-red-700 ring-red-600/10';
	let dotClass = 'bg-red-600';

	if ( hasSite && hasSecret ) {
		label = __( 'Active', 'google-recaptcha-v3-for-woocommerce' );
		badgeClass = 'bg-green-50 text-green-700 ring-green-600/20';
		dotClass = 'bg-green-600';
	} else if ( hasSite || hasSecret ) {
		label = __(
			'Incomplete Configuration',
			'google-recaptcha-v3-for-woocommerce'
		);
		badgeClass = 'bg-amber-50 text-amber-700 ring-amber-600/20';
		dotClass = 'bg-amber-600';
	}

	return (
		<div className="flex items-center gap-x-2">
			<span className="text-xs font-semibold text-gray-500 uppercase tracking-wider">
				{ __( 'Status:', 'google-recaptcha-v3-for-woocommerce' ) }
			</span>
			<span
				className={ `inline-flex items-center gap-x-1.5 rounded-md px-2 py-1 text-xs font-medium ring-1 ring-inset ${ badgeClass }` }
			>
				<svg
					className={ `h-1.5 w-1.5 ${ dotClass } rounded-full` }
					viewBox="0 0 6 6"
					aria-hidden="true"
				>
					<circle cx="3" cy="3" r="3" />
				</svg>
				{ label }
			</span>
		</div>
	);
}
