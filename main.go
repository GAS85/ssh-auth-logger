package main

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

const appName = "ssh-auth-logger"

var errAuthenticationFailed = errors.New(":)")

var commonFields = logrus.Fields{
	"destinationServicename": "sshd",
	"product":                appName,
}
var logger = logrus.WithFields(commonFields)

var (
	sshd_bind    string
	sshd_key_key string
	rate         int
	maxAuthTries int
	rsaBits      int    // only used if hostKeyType == "rsa"
	profileScope string // "host" or "remote_ip"
)

// rateLimitedConn is a wrapper around net.Conn that limits the bandwidth.
type rateLimitedConn struct {
	net.Conn
	rate       int // bytes per second
	bufferSize int // buffer size for token bucket algorithm
	tokens     int // current tokens
	lastUpdate time.Time
}

// Currently state is not shared between connections
// multiple attackers can "reset” delays by opening new connections
type authState struct {
	attempts int
}

// Create profile to match banner and Server Version
type serverProfile struct {
	ServerVersion string
	LoginBanner   string
	HostKeyType   string // "rsa" or "ed25519"
}

// newRateLimitedConn returns a new rateLimitedConn.
func newRateLimitedConn(conn net.Conn, rate int) *rateLimitedConn {
	return &rateLimitedConn{
		Conn:       conn,
		rate:       rate,
		bufferSize: rate * 2, // Allow for bursts up to twice the rate
		tokens:     rate,
		lastUpdate: time.Now(),
	}
}

// Read implements the Read method of net.Conn.
func (r *rateLimitedConn) Read(p []byte) (n int, err error) {
	n, err = r.Conn.Read(p)
	if err != nil {
		return
	}

	// Limit the read based on the rate.
	r.limit(n)
	return
}

// Write implements the Write method of net.Conn.
func (r *rateLimitedConn) Write(p []byte) (n int, err error) {
	n, err = r.limitWrite(p)
	return
}

func (r *rateLimitedConn) limitWrite(p []byte) (int, error) {
	var totalWritten int
	for len(p) > 0 {
		// Calculate available tokens.
		now := time.Now()
		elapsed := now.Sub(r.lastUpdate).Seconds()
		r.tokens += int(elapsed * float64(r.rate))
		if r.tokens > r.bufferSize {
			r.tokens = r.bufferSize
		}
		r.lastUpdate = now

		// Determine how many bytes we can write.
		availableTokens := r.tokens
		if availableTokens > len(p) {
			availableTokens = len(p)
		}

		// Write data.
		n, err := r.Conn.Write(p[:availableTokens])
		totalWritten += n
		r.tokens -= n
		if err != nil {
			return totalWritten, err
		}

		// Adjust the buffer.
		p = p[n:]

		// If there are still bytes to write, sleep to accumulate tokens.
		if len(p) > 0 {
			time.Sleep(time.Duration(availableTokens) * time.Second / time.Duration(r.rate))
		}
	}
	return totalWritten, nil
}

func (r *rateLimitedConn) limit(n int) {
	// Simple sleep-based rate limiting for read.
	time.Sleep(time.Duration(n) * time.Second / time.Duration(r.rate))
}

func connLogParameters(conn net.Conn) logrus.Fields {
	src, spt, _ := net.SplitHostPort(conn.RemoteAddr().String())
	dst, dpt, _ := net.SplitHostPort(conn.LocalAddr().String())

	return logrus.Fields{
		"src": src,
		"spt": spt,
		"dst": dst,
		"dpt": dpt,
	}
}

func logParameters(conn ssh.ConnMetadata) logrus.Fields {

	src, spt, _ := net.SplitHostPort(conn.RemoteAddr().String())
	dst, dpt, _ := net.SplitHostPort(conn.LocalAddr().String())

	return logrus.Fields{
		"duser": conn.User(),
		//"session_id":          string(conn.SessionID()),
		"src":            src,
		"spt":            spt,
		"dst":            dst,
		"dpt":            dpt,
		"client_version": string(conn.ClientVersion()),
		"server_version": string(conn.ServerVersion()),
	}
}

func HashToInt64(message, key []byte) int64 {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	hash := mac.Sum(nil)
	i := binary.LittleEndian.Uint64(hash[:8])
	return int64(i)
}

func getHost(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		logrus.Fatal(err)
	}
	return host
}

func getHostKeySigner(host, keyType string) (ssh.Signer, error) {
	seed := HashToInt64([]byte(host+":"+keyType), []byte(sshd_key_key))
	// Fine for honeypot — no security issue. Do not use for real keys.
	rng := rand.New(rand.NewSource(seed))

	switch keyType {
	case "ed25519":
		_, priv, err := ed25519.GenerateKey(rng)
		if err != nil {
			return nil, err
		}
		return ssh.NewSignerFromKey(priv)

	case "rsa":
		key, err := rsa.GenerateKey(rng, rsaBits)
		if err != nil {
			return nil, err
		}
		return ssh.NewSignerFromKey(key)

	default:
		return nil, errors.New("unsupported host key type")
	}
}

var serverProfiles = []serverProfile{
	{
		ServerVersion: "SSH-2.0-OpenSSH_7.4",
		LoginBanner:   "CentOS Linux 7 (Core)\n\nAll connections are monitored.\n",
		HostKeyType:   "rsa",
	},
	{
		ServerVersion: "SSH-2.0-OpenSSH_7.9p1 Debian-10",
		LoginBanner:   "Debian GNU/Linux 10\n\nAuthorized users only.\n",
		HostKeyType:   "rsa",
	},
	{
		ServerVersion: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
		LoginBanner:   "Ubuntu 20.04.6 LTS\n\nUnauthorized access prohibited.\n",
		HostKeyType:   "ed25519",
	},
	{
		ServerVersion: "SSH-2.0-OpenSSH_8.4",
		LoginBanner:   "Debian GNU/Linux 11\n\nAuthorized users only.\n",
		HostKeyType:   "ed25519",
	},
	{
		ServerVersion: "SSH-2.0-dropbear_2019.78",
		LoginBanner:   "Welcome to Dropbear SSH Server\n\nUnauthorized access is prohibited.\n",
		HostKeyType:   "rsa",
	},
}

func getServerProfile(host string) serverProfile {
	seed := HashToInt64([]byte("profile:"+host), []byte(sshd_key_key))
	if seed < 0 {
		seed = -seed
	}
	return serverProfiles[int(seed)%len(serverProfiles)]
}

func makeSSHConfig(conn net.Conn) ssh.ServerConfig {
	state := &authState{}
	// per‑local host profile
//	profile := getServerProfile(host)
	// per‑IP profile
//	profile := getServerProfile(conn.RemoteAddr().String())
	// Determine the key for profile lookup
	var profileKey string
	if profileScope == "remote_ip" {
		profileKey = conn.RemoteAddr().String()
	} else { // default "host"
		profileKey = getHost(conn.LocalAddr().String())
	}

	profile := getServerProfile(profileKey)
	// Generate primary host key signer
	signer, err := getHostKeySigner(profileKey, profile.HostKeyType)
	if err != nil {
		logrus.Panic(err)
	}

	// Capture the actual host key type
	actualHostKeyType := signer.PublicKey().Type()

	config := ssh.ServerConfig{
		BannerCallback: func(conn ssh.ConnMetadata) string {
			time.Sleep(time.Duration(100+rand.Intn(200)) * time.Millisecond)
			return profile.LoginBanner
		},

		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			state.attempts++

			base := time.Duration(200*state.attempts) * time.Millisecond
			jitter := time.Duration(rand.Intn(400)) * time.Millisecond
			time.Sleep(base + jitter)

			logger.WithFields(logParameters(conn)).
				WithFields(logrus.Fields{
					"password": password,
					"server_key_type": actualHostKeyType,
				}).Info("Request with password")

			return nil, errAuthenticationFailed
		},

		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			state.attempts++

			base := time.Duration(200*state.attempts) * time.Millisecond
			jitter := time.Duration(rand.Intn(400)) * time.Millisecond
			time.Sleep(base + jitter)

			logger.WithFields(logParameters(conn)).
				WithFields(logrus.Fields{
					"keytype": key.Type(),
					"fingerprint": ssh.FingerprintSHA256(key),
					"server_key_type": actualHostKeyType,
				}).Info("Request with key")

			return nil, errAuthenticationFailed
		},

		ServerVersion: profile.ServerVersion,
		MaxAuthTries:  maxAuthTries + rand.Intn(5),
	}

	config.AddHostKey(signer)

	// Compatibility: add RSA fallback if primary is ED25519
	if profile.HostKeyType == "ed25519" {
		if rsaSigner, err := getHostKeySigner(profileKey, "rsa"); err == nil {
			config.AddHostKey(rsaSigner)
		}
	}

	return config
}

func handleConnection(conn net.Conn, config *ssh.ServerConfig) {
	_, _, _, err := ssh.NewServerConn(conn, config)
	if err == nil {
		// This should never happen because auth never succeeds
		logrus.Panic("Successful login? why!?")
	}
	if err != nil {
		// Auth failed or client closed connection — expected behavior
		return
	}
}

//getEnvWithDefault returns the environment value for key
//returning fallback instead if it is missing or blank
func getEnvWithDefault(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}

func init() {
	logrus.SetFormatter(&logrus.JSONFormatter{})

	sshd_bind = getEnvWithDefault("SSHD_BIND", ":22")
	sshd_key_key = getEnvWithDefault("SSHD_KEY_KEY", "Take me to your leader")
	rateStr := getEnvWithDefault("SSHD_RATE", "120") // default rate is 120 bytes per second very slow...
	var err error
	rate, err = strconv.Atoi(rateStr)
	if err != nil {
		logrus.Fatal("Invalid SSHD_RATE environment variable")
	}
	maxAuthTriesStr := getEnvWithDefault("SSHD_MAX_AUTH_TRIES", "6") // default amount of tries is 6-10.
	maxAuthTries, err = strconv.Atoi(maxAuthTriesStr)
	if err != nil {
		logrus.Fatal("Invalid SSHD_MAX_AUTH_TRIES environment variable")
	}
	rsaBitsStr := getEnvWithDefault("SSHD_RSA_BITS", "3072")
	rsaBits, err = strconv.Atoi(rsaBitsStr)
	if err != nil || rsaBits < 2048 {
		logrus.Fatal("Invalid SSHD_RSA_BITS (must be >= 2048)")
	}
	profileScope = getEnvWithDefault("SSHD_PROFILE_SCOPE", "host")
	// Seed for non-deterministic uses to avoid identical timing patterns across restarts
	// Fine for delays and banner selection — no security issue.
	rand.Seed(time.Now().UnixNano())
	// Show Configuration on Startup
	logrus.WithFields(logrus.Fields{
		"SSHD_BIND":           sshd_bind,
		"SSHD_KEY_KEY":        sshd_key_key,
		"SSHD_RATE":           rate,
		"SSHD_MAX_AUTH_TRIES": maxAuthTries,
		"SSHD_RSA_BITS":       rsaBitsStr,
		"SSHD_PROFILE_SCOPE":  profileScope,
	}).Info("Starting SSH Auth Logger")
}

func main() {
	socket, err := net.Listen("tcp", sshd_bind)
	if err != nil {
		panic(err)
	}
	for {
		conn, err := socket.Accept()
		if err != nil {
			log.Panic(err)
		}

		logger.WithFields(connLogParameters(conn)).Info("Connection")

		limitedConn := newRateLimitedConn(conn, rate)
		//host := getHost(conn.LocalAddr().String())

		config := makeSSHConfig(conn) // NEW CONFIG PER CONNECTION
		go handleConnection(limitedConn, &config)
	}

}