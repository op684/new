package jsrecon

import "regexp"

func rx(p string) *regexp.Regexp { return regexp.MustCompile(p) }

// secretSig pairs a human label with a detection pattern.
type secretSig struct {
	name string
	rx   *regexp.Regexp
}

// secretSigs is SPECTER's high-value credential/secret signature set, applied
// to every fetched JavaScript file and inline script.
var secretSigs = []secretSig{
	{"Google API Key", rx(`AIza[0-9A-Za-z_\-]{35}`)},
	{"Google OAuth Token", rx(`ya29\.[0-9A-Za-z_\-]+`)},
	{"Google reCAPTCHA Key", rx(`6L[0-9A-Za-z_\-]{38}`)},
	{"Firebase Cloud Messaging", rx(`AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}`)},
	{"Firebase DB URL", rx(`[a-z0-9-]+\.firebaseio\.com`)},
	{"AWS Access Key ID", rx(`(?:A3T[A-Z0-9]|AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}`)},
	{"AWS S3 Bucket (host)", rx(`[a-z0-9][a-z0-9.\-]{1,60}\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com`)},
	{"AWS S3 Bucket (s3://)", rx(`s3://[a-z0-9._/\-]{3,}`)},
	{"GCP Storage Bucket", rx(`[a-z0-9._\-]+\.storage\.googleapis\.com`)},
	{"Slack Token", rx(`xox[baprs]-[0-9a-zA-Z]{10,48}`)},
	{"Slack Webhook", rx(`https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9a-zA-Z]+`)},
	{"GitHub Token", rx(`gh[pousr]_[0-9A-Za-z]{36,}`)},
	{"GitLab PAT", rx(`glpat-[0-9A-Za-z_\-]{20}`)},
	{"Stripe Secret Key", rx(`sk_live_[0-9a-zA-Z]{24,}`)},
	{"Stripe Restricted Key", rx(`rk_live_[0-9a-zA-Z]{24,}`)},
	{"Square Access Token", rx(`sq0atp-[0-9A-Za-z_\-]{22}`)},
	{"Square OAuth Secret", rx(`sq0csp-[0-9A-Za-z_\-]{43}`)},
	{"PayPal/Braintree Token", rx(`access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`)},
	{"Twilio API Key", rx(`SK[0-9a-fA-F]{32}`)},
	{"Twilio Account SID", rx(`AC[a-z0-9]{32}`)},
	{"Mailgun API Key", rx(`key-[0-9a-zA-Z]{32}`)},
	{"Mailchimp API Key", rx(`[0-9a-f]{32}-us[0-9]{1,2}`)},
	{"SendGrid API Key", rx(`SG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}`)},
	{"NPM Access Token", rx(`npm_[0-9A-Za-z]{36}`)},
	{"Heroku API Key", rx(`(?i)heroku[a-z0-9_ .\-,]{0,25}['"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['"]`)},
	{"JSON Web Token", rx(`eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}`)},
	{"Private Key Block", rx(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----`)},
	{"Authorization: Bearer", rx(`(?i)bearer\s+[a-z0-9_.\-]{20,}`)},
	{"Authorization: Basic", rx(`(?i)basic\s+[a-z0-9=:_+/\-]{16,}`)},
	{"Generic API Key", rx(`(?i)(?:api[_-]?key|api[_-]?secret|access[_-]?token|client[_-]?secret|auth[_-]?token|secret[_-]?key)["'\s]*[:=]["'\s]*[0-9a-zA-Z_\-]{16,64}`)},
	{"Hardcoded Password", rx(`(?i)(?:password|passwd|pwd)["'\s]*[:=]\s*["'][^"'\s]{6,40}["']`)},
}

// Endpoint/path extraction patterns (LinkFinder-inspired, RE2-safe).
var (
	urlRX  = rx(`(?:https?:)?//[a-zA-Z0-9_.\-]+(?::\d+)?(?:/[a-zA-Z0-9_./?=&%#:+~@!$,;*'()\[\]\-]*)?`)
	pathRX = rx(`["'` + "`" + `]((?:/|\.\./|\./)[a-zA-Z0-9_./?=&%#:+~\-]{2,})["'` + "`" + `]`)
	fileRX = rx(`[a-zA-Z0-9_\-/]+\.(?:php|asp|aspx|jsp|jspx|do|action|json|xml|cgi|pl|rb|py|env|ya?ml|bak|sql|graphql|api)(?:\?[a-zA-Z0-9_=&%.\-]*)?`)
)
