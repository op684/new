package harvest

import "regexp"

func rx(p string) *regexp.Regexp { return regexp.MustCompile(p) }

type namedSig struct {
	name string
	rx   *regexp.Regexp
}

// highConfidenceSecrets are precise, low-false-positive credential patterns.
// These complement the entropy-based generic detector.
var highConfidenceSecrets = []namedSig{
	{"AWS Access Key ID", rx(`(?:A3T[A-Z0-9]|AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}`)},
	{"AWS Secret Access Key", rx(`(?i)aws(.{0,20})?(secret|sk)(.{0,20})?['"][0-9a-zA-Z/+]{40}['"]`)},
	{"Google API Key", rx(`AIza[0-9A-Za-z_\-]{35}`)},
	{"Google OAuth Token", rx(`ya29\.[0-9A-Za-z_\-]+`)},
	{"Google reCAPTCHA Key", rx(`6L[0-9A-Za-z_\-]{38}`)},
	{"Firebase Cloud Messaging", rx(`AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}`)},
	{"Slack Token", rx(`xox[baprs]-[0-9a-zA-Z\-]{10,60}`)},
	{"Slack Webhook", rx(`https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9a-zA-Z]+`)},
	{"GitHub Token", rx(`gh[pousr]_[0-9A-Za-z]{36,}`)},
	{"GitHub OAuth", rx(`(?i)github(.{0,20})?['"][0-9a-zA-Z]{35,40}['"]`)},
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
	{"Heroku API Key", rx(`(?i)heroku(.{0,15})?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)},
	{"JSON Web Token", rx(`eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}`)},
	{"RSA/EC/PGP Private Key", rx(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----`)},
	{"Authorization Bearer", rx(`(?i)bearer\s+[a-z0-9_.\-]{20,}`)},
	{"Authorization Basic", rx(`(?i)basic\s+[a-z0-9=:_+/\-]{16,}`)},
	{"Facebook Access Token", rx(`EAACEdEose0cBA[0-9A-Za-z]+`)},
	{"Twitter Bearer Token", rx(`(?i)twitter(.{0,20})?['"][0-9a-z]{35,44}['"]`)},
	{"Cloudinary URL", rx(`cloudinary://[0-9]{15}:[0-9A-Za-z_\-]+@[0-9a-z_\-]+`)},
	{"Firebase Database URL", rx(`[a-z0-9-]+\.firebaseio\.com`)},
	{"Artifactory Token", rx(`(?i)artifactory.{0,10}['"][0-9a-zA-Z=]{10,}['"]`)},
	{"Discord Bot Token", rx(`[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}`)},
	{"Telegram Bot Token", rx(`\d{8,10}:[0-9A-Za-z_\-]{35}`)},
	{"OpenAI API Key", rx(`sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}`)},
}

// keywordSecretRX matches "name = value" credential assignments. RE2 has no
// look-around, so the blacklist is applied in code (isBlacklisted).
var keywordSecretRX = rx(`(?i)["']?[\w\-]*(?:secret[_-]?key|secret[_-]?token|access[_-]?token|auth[_-]?token|api[_-]?key|api[_-]?secret|api[_-]?token|client[_-]?secret|client[_-]?key|client[_-]?id|encryption[_-]?key|consumer[_-]?key|consumer[_-]?secret|private[_-]?key|session[_-]?token|session[_-]?key|session[_-]?secret|slack[_-]?token|irc[_-]?pass|github[_-]?token|secret|token|password|passwd|authorization|bearer|access[_-]?key|auth[_-]?key|ssh[_-]?key)[\w\-]*["']?\s*(?:==|=>|=:|:|=)\s*["']?([\w\-/~!@#$%^*+.]{6,}={0,2})["']?`)

// secretBlacklist filters obvious framework noise out of keyword matches.
var secretBlacklist = []string{
	"proptypes.", "process.", "this.", "config.", "key.", "function", "return ",
	"require(", "module.", "window.", "document.", "typeof ",
}

// cloudRegexes detect cloud storage / CDN asset URLs. Ported from
// SubDomainizer and extended with more providers.
var cloudRegexes = []*regexp.Regexp{
	rx(`(?i)[\w]+\.cloudfront\.net`),
	rx(`(?i)s3[\w\-.]*\.?amazonaws\.com/?[\w\-.]+`),
	rx(`(?i)[\w\-]+\.s3[\w\-.]*\.?amazonaws\.com/?`),
	rx(`(?i)[\w\-.]+\.appspot\.com`),
	rx(`(?i)[\w\-.]*\.?digitaloceanspaces\.com/?[\w\-.]*`),
	rx(`(?i)storage\.cloud\.google\.com/[\w\-.]+`),
	rx(`(?i)[\w\-.]*\.?storage\.googleapis\.com/?[\w\-.]*`),
	rx(`(?i)[\w\-.]*\.?storage-download\.googleapis\.com/?[\w\-.]*`),
	rx(`(?i)[\w\-.]*\.?content-storage-upload\.googleapis\.com/?[\w\-.]*`),
	rx(`(?i)[\w\-.]*\.?1drv\.com/?[\w\-.]*`),
	rx(`(?i)onedrive\.live\.com/[\w.\-]+`),
	rx(`(?i)[\w\-.]*\.?blob\.core\.windows\.net/?[\w\-.]*`),
	rx(`(?i)[\w\-.]*\.?rackcdn\.com/?[\w\-.]*`),
	rx(`(?i)[\w\-.]*\.?objects\.cdn\.dream\.io/?[\w\-.]*`),
	rx(`(?i)[\w\-.]*\.?objects-us-west-1\.dream\.io/?[\w\-.]*`),
	rx(`(?i)[\w\-.]+\.firebaseio\.com`),
	// upgrades:
	rx(`(?i)[\w\-.]+\.r2\.cloudflarestorage\.com`),
	rx(`(?i)[\w\-.]+\.s3\.[\w\-]+\.backblazeb2\.com`),
	rx(`(?i)[\w\-.]+\.oss-[\w\-]+\.aliyuncs\.com`),
	rx(`(?i)[\w\-.]+\.cos\.[\w\-]+\.myqcloud\.com`),
	rx(`(?i)[\w\-.]+\.[\w\-]+\.wasabisys\.com`),
	rx(`(?i)[\w\-.]+\.objectstorage\.[\w\-]+\.oraclecloud\.com`),
	rx(`(?i)[\w\-.]+\.b-cdn\.net`),
	rx(`(?i)[\w\-.]+\.azureedge\.net`),
	rx(`(?i)[\w\-.]+\.web\.core\.windows\.net`),
}

// ipv4RX matches IPv4 addresses (the original SubDomainizer pattern was broken;
// this is a correct, anchored variant).
var ipv4RX = rx(`\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b`)
