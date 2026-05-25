package epanalyze

// Severity ranks how dangerous a signal is.
type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

func (s Severity) String() string {
	switch s {
	case Critical:
		return "CRITICAL"
	case High:
		return "HIGH"
	case Medium:
		return "MEDIUM"
	case Low:
		return "LOW"
	default:
		return "INFO"
	}
}

// Weight is the contribution of a severity to an endpoint's risk score.
func (s Severity) Weight() int {
	switch s {
	case Critical:
		return 10
	case High:
		return 6
	case Medium:
		return 3
	case Low:
		return 1
	default:
		return 0
	}
}

// paramSig maps a vulnerability class to the parameter names that commonly
// expose it. Matching is done on lowercased exact parameter names.
type paramSig struct {
	category string
	severity Severity
	desc     string
	params   []string
}

var paramSignatures = []paramSig{
	{"SSRF", High, "server-side request forgery via URL-bearing parameter", []string{
		"url", "uri", "link", "src", "source", "redirect", "redirect_uri", "redirecturl",
		"return", "returnurl", "return_url", "next", "continue", "dest", "destination",
		"target", "to", "out", "view", "domain", "host", "site", "feed", "callback",
		"webhook", "proxy", "fetch", "load", "open", "window", "resource", "file_url",
		"image_url", "imageurl", "remote", "path_url", "forward", "navigation"}},

	{"Open Redirect", Medium, "user-controlled redirect target", []string{
		"redirect", "redir", "redirect_uri", "redirecturl", "return", "returnurl",
		"return_url", "returnto", "return_to", "next", "continue", "goto", "go", "dest",
		"destination", "url", "u", "link", "out", "target", "checkout_url", "rurl",
		"forward", "login_url", "logout", "image_url", "callback", "success_url"}},

	{"LFI / Path Traversal", High, "local file inclusion / directory traversal", []string{
		"file", "filename", "filepath", "path", "page", "template", "doc", "document",
		"folder", "dir", "download", "read", "load", "include", "inc", "require", "view",
		"content", "name", "root", "pg", "style", "pdf", "img", "image", "php_path",
		"detail", "locate", "show", "site", "cat", "board", "layout", "mod", "conf"}},

	{"SQL Injection", High, "SQL injection via data parameter", []string{
		"id", "user_id", "userid", "uid", "pid", "cid", "cat", "catid", "category",
		"categoryid", "item", "itemid", "product", "product_id", "productid", "order",
		"orderid", "no", "number", "sort", "order_by", "orderby", "column", "field",
		"select", "from", "where", "query", "filter", "group", "limit", "offset",
		"year", "month", "day", "key", "ref", "prod", "report", "process"}},

	{"XSS", Medium, "reflected cross-site scripting via reflected parameter", []string{
		"q", "s", "search", "query", "keyword", "kw", "page", "name", "message", "msg",
		"comment", "content", "text", "title", "subject", "body", "desc", "description",
		"return", "redirect", "callback", "jsonp", "ref", "referer", "referrer", "lang",
		"language", "type", "style", "debug", "error", "err", "reason", "nick", "nickname"}},

	{"SSTI", High, "server-side template injection", []string{
		"name", "template", "tpl", "tmpl", "view", "preview", "page", "content", "subject",
		"message", "greeting", "description", "comment", "class", "profile", "format"}},

	{"RCE / Command Injection", Critical, "remote code / OS command execution", []string{
		"cmd", "exec", "command", "execute", "run", "ping", "system", "shell", "code",
		"func", "function", "arg", "args", "option", "do", "daemon", "process", "jump",
		"reg", "cli", "bash", "sh", "eval", "feature", "ip", "host", "exe"}},

	{"IDOR / BOLA", Medium, "broken object-level authorization (object reference)", []string{
		"id", "user_id", "userid", "uid", "account", "accountid", "acct", "number", "no",
		"doc", "docid", "document", "fileid", "invoice", "invoiceid", "order", "orderid",
		"profile", "profileid", "uuid", "guid", "key", "group", "groupid", "member",
		"memberid", "record", "row", "customer", "customerid", "client", "clientid",
		"ticket", "ticketid", "message_id", "msgid", "object_id", "objectid"}},

	{"Insecure Deserialization", High, "object deserialization sink", []string{
		"data", "input", "obj", "object", "json", "xml", "payload", "serialized", "state",
		"viewstate", "__viewstate", "rememberme", "remember_me", "session_data"}},

	{"Secret in URL", High, "credential / token leaked in query string", []string{
		"api_key", "apikey", "api-key", "key", "token", "access_token", "accesstoken",
		"auth", "authorization", "password", "passwd", "pwd", "secret", "client_secret",
		"clientsecret", "signature", "sig", "session", "sessionid", "session_id", "jwt",
		"id_token", "refresh_token", "private_key", "auth_token", "passkey", "otp", "totp"}},

	{"Mass Assignment / Privilege", Medium, "privilege-affecting parameter", []string{
		"role", "is_admin", "isadmin", "admin", "user_role", "userrole", "permission",
		"permissions", "access", "privilege", "is_active", "active", "status", "verified",
		"approved", "enabled", "superuser", "grant", "scope"}},

	{"Arbitrary File Upload", High, "file upload sink", []string{
		"file", "upload", "image", "avatar", "photo", "attachment", "document",
		"fileupload", "userfile", "uploadfile", "media", "import"}},
}

// pathSig maps a category to path *tokens* (matched per path segment, so
// "delete" matches /v1/delete but not /undeleted).
type pathSig struct {
	category string
	severity Severity
	desc     string
	tokens   []string
}

var pathSignatures = []pathSig{
	{"Auth Surface", High, "authentication / session endpoint", []string{
		"login", "signin", "logon", "oauth", "oauth2", "token", "authorize", "auth",
		"sso", "saml", "jwt", "session", "password", "passwd", "reset", "forgot",
		"register", "signup", "2fa", "mfa", "otp", "verify", "credentials"}},

	{"Admin Interface", High, "administrative interface", []string{
		"admin", "administrator", "manage", "management", "console", "dashboard",
		"backend", "cpanel", "panel", "superuser", "sysadmin", "root", "moderator"}},

	{"Internal / Debug", High, "internal, debug or diagnostic surface", []string{
		"internal", "debug", "trace", "actuator", "phpinfo", "heapdump", "env",
		"metrics", "monitor", "status", "healthz", "_debug", "diagnostic", "pprof",
		"prometheus", "telemetry", "intranet", "private"}},

	{"Dangerous Action", High, "state-changing / destructive verb", []string{
		"delete", "remove", "destroy", "drop", "exec", "execute", "run", "cmd",
		"command", "eval", "system", "shell", "kill", "terminate", "purge", "wipe",
		"reset", "revoke", "disable"}},

	{"GraphQL", Medium, "GraphQL endpoint (introspection / batching)", []string{
		"graphql", "graphiql", "gql", "playground", "altair"}},

	{"File Operation", High, "file read/write/transfer surface", []string{
		"upload", "download", "export", "import", "backup", "attachment", "fileupload",
		"getfile", "readfile", "writefile", "fetchfile", "downloadfile"}},

	{"Payment / Money", High, "financial transaction surface", []string{
		"payment", "pay", "checkout", "billing", "invoice", "charge", "refund", "card",
		"stripe", "paypal", "transaction", "wallet", "balance", "payout", "withdraw",
		"transfer", "subscription"}},

	{"Account Surface", Medium, "account / identity surface", []string{
		"account", "profile", "user", "users", "settings", "preferences", "me",
		"whoami", "identity", "member", "customer"}},

	{"API Surface", Low, "programmatic API surface", []string{
		"api", "rest", "v1", "v2", "v3", "v4", "soap", "rpc", "jsonrpc", "ajax", "graphql"}},

	{"API Docs", Medium, "API documentation / schema (maps the surface)", []string{
		"swagger", "openapi", "redoc", "api-docs", "apidocs", "wsdl", "schema"}},

	{"Webhook / Callback", Medium, "callback surface (SSRF / spoofing)", []string{
		"webhook", "webhooks", "callback", "callbacks", "notify", "hook", "ipn"}},
}

// dotfile / config path markers (matched as substrings, case-sensitive-ish).
var sensitivePathMarkers = []struct {
	marker   string
	severity Severity
	desc     string
}{
	{".env", Critical, "environment file (secrets)"},
	{".git", Critical, "exposed git metadata"},
	{".svn", High, "exposed svn metadata"},
	{".hg", High, "exposed mercurial metadata"},
	{".htaccess", High, "apache config"},
	{".htpasswd", Critical, "apache credentials"},
	{".aws", Critical, "AWS credentials directory"},
	{".ssh", Critical, "SSH key directory"},
	{"id_rsa", Critical, "private SSH key"},
	{"wp-config", Critical, "WordPress config (DB creds)"},
	{"web.config", High, "IIS config"},
	{"appsettings", High, ".NET config"},
	{"config.php", High, "PHP config"},
	{"settings.py", High, "Django settings"},
	{"credentials", High, "credentials file"},
	{"docker-compose", Medium, "docker-compose (env/secrets)"},
	{"dockerfile", Low, "Dockerfile"},
	{"backup", High, "backup artifact"},
	{"phpinfo", High, "PHP info disclosure"},
	{"server-status", High, "Apache server-status"},
}

// sensitive file extensions and their severities.
var sensitiveExt = map[string]struct {
	severity Severity
	desc     string
}{
	"env":      {Critical, "environment / secrets"},
	"sql":      {Critical, "database dump"},
	"bak":      {High, "backup file"},
	"backup":   {High, "backup file"},
	"old":      {High, "old / backup file"},
	"swp":      {High, "editor swap file (source)"},
	"swo":      {High, "editor swap file (source)"},
	"orig":     {Medium, "merge/backup remnant"},
	"save":     {Medium, "saved copy"},
	"config":   {High, "configuration file"},
	"conf":     {High, "configuration file"},
	"cfg":      {High, "configuration file"},
	"ini":      {Medium, "ini configuration"},
	"yml":      {Medium, "YAML config"},
	"yaml":     {Medium, "YAML config"},
	"log":      {Medium, "log file"},
	"zip":      {Medium, "archive"},
	"tar":      {Medium, "archive"},
	"gz":       {Medium, "archive"},
	"tgz":      {Medium, "archive"},
	"rar":      {Medium, "archive"},
	"7z":       {Medium, "archive"},
	"pem":      {Critical, "private key / cert"},
	"key":      {Critical, "private key"},
	"crt":      {Medium, "certificate"},
	"cer":      {Medium, "certificate"},
	"p12":      {High, "PKCS12 keystore"},
	"pfx":      {High, "PKCS12 keystore"},
	"jks":      {High, "Java keystore"},
	"keystore": {High, "keystore"},
	"db":       {High, "database file"},
	"sqlite":   {High, "SQLite database"},
	"sqlite3":  {High, "SQLite database"},
	"dump":     {High, "memory/db dump"},
	"csv":      {Low, "data export"},
	"xls":      {Low, "spreadsheet export"},
	"xlsx":     {Low, "spreadsheet export"},
	"htpasswd": {Critical, "credentials"},
	"git":      {Critical, "git metadata"},
}

// static asset extensions (low value on their own, used for classification).
var staticExt = map[string]bool{
	"css": true, "scss": true, "less": true, "png": true, "jpg": true, "jpeg": true,
	"gif": true, "svg": true, "ico": true, "webp": true, "bmp": true, "woff": true,
	"woff2": true, "ttf": true, "otf": true, "eot": true, "map": true, "mp4": true,
	"webm": true, "mp3": true, "wav": true, "avif": true,
}

// dynamic/script extensions hinting an application route.
var dynamicExt = map[string]bool{
	"php": true, "asp": true, "aspx": true, "jsp": true, "jspx": true, "do": true,
	"action": true, "cgi": true, "pl": true, "py": true, "rb": true, "cfm": true,
}
