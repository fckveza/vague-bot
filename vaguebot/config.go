package vaguebot

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Target      string
	AccountFile string

	AppVersion  string
	AppBuild    string
	AppRevision string
	AppName     string
	DeviceType  string

	Insecure      bool
	VerboseEvents bool
	UnaryTimeout  time.Duration
	PingInterval  time.Duration
}

func Contains(arr []string, str string) bool {
	for i := 0; i < len(arr); i++ {
		if arr[i] == str {
			return true
		}
	}
	return false
}
func LoadConfig() Config {
	return Config{
		Target:        firstNonEmpty(os.Getenv("VAGUE_BOT_GRPC_TARGET"), os.Getenv("BOT_GRPC_TARGET"), "svc.vague-infinity.com:443"),
		AccountFile:   firstNonEmpty(os.Getenv("VAGUE_BOT_ACCOUNT_FILE"), os.Getenv("BOT_ACCOUNT_FILE"), detectDefaultAccountFile()),
		AppVersion:    "1.1.4",
		AppBuild:      "33",
		AppRevision:   firstNonEmpty(os.Getenv("VAGUE_BOT_APP_REVISION"), os.Getenv("BOT_APP_REVISION"), os.Getenv("APP_CURRENT_REVISION"), "3"),
		AppName:       firstNonEmpty(os.Getenv("VAGUE_BOT_APP_NAME"), os.Getenv("BOT_APP_NAME"), firstCSVItem(os.Getenv("APP_NAME")), "ANDROID"),
		DeviceType:    firstNonEmpty(os.Getenv("VAGUE_BOT_DEVICE_TYPE"), os.Getenv("BOT_DEVICE_TYPE"), "bot"),
		Insecure:      envBool("VAGUE_BOT_GRPC_INSECURE", false),
		VerboseEvents: envBool("VAGUE_BOT_VERBOSE_EVENTS", false),
		UnaryTimeout:  envDuration("VAGUE_BOT_UNARY_TIMEOUT", 15*time.Second),
		PingInterval:  envDuration("VAGUE_BOT_PING_INTERVAL", 25*time.Second),
	}
}

func detectDefaultAccountFile() string {
	candidates := []string{
		"account.json",
		"accounts.json",
		filepath.Join("bot-client", "account.json"),
		filepath.Join("bot-client", "accounts.json"),
		filepath.Join("..", "bot-client", "account.json"),
		filepath.Join("..", "bot-client", "accounts.json"),
	}
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return filepath.Join("..", "bot-client", "accounts.json")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func firstCSVItem(value string) string {
	for _, item := range strings.Split(value, ",") {
		trimmed := strings.TrimSpace(item)
		if trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func envBool(key string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	switch strings.ToLower(value) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func envDuration(key string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err == nil && parsed > 0 {
		return parsed
	}
	if seconds, err := strconv.Atoi(value); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	return fallback
}
