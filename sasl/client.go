package sasl

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"strings"
)

const (
	saslMD5NoneSize = 32
	saslDataMax     = 65536

	sealingClientServer = "Digest H(A1) to client-to-server sealing key magic constant"
	sealingServerClient = "Digest H(A1) to server-to-client sealing key magic constant"
	signingClientServer = "Digest session key to client-to-server signing key magic constant"
	signingServerClient = "Digest session key to server-to-client signing key magic constant"
)

type saslInfoCallback func([]CallbackRequestItem) error

type context struct {
	State int
	challenge
	KIReceive []byte
	KISend    []byte
	EncKey    []byte
	DecKey    []byte
	HA1       []byte
}

type client struct {
	LocalAddress  net.Addr
	RemoteAddress net.Addr
	Callback      saslInfoCallback
	context       *context
}

type challenge struct {
	Service    string
	Hostname   string
	DigestURI  string
	Username   string
	AuthzID    string
	NonceHex   string
	CNonceHex  string
	NC         uint32
	Algorithm  string
	QOP        string
	Realm      string
	Charset    string
	MaxBuf     uint32
	Response   string
	Method     string
	SessionKey string
	Ciphers    []string
	Cipher     string
	CipherType cipherType
}

// Client represents the client portion of the SASL protocol
type Client interface {
	FindMech(mechList []string) (mech string, err error)
	ApplyChallenge(challenge string)
	MakeResponse() string
	SetCNonce(string)
}

// NewClient creates a new instance of the client
func NewClient(service, hostname string, auth AuthInfo) Client {
	nonce := make([]byte, saslMD5NoneSize)
	rand.Read(nonce)
	return &client{
		Callback: auth.Callback,
		context: &context{
			State: 1,
			challenge: challenge{
				Service:   service,
				Hostname:  hostname,
				Realm:     "",
				NC:        0,
				CNonceHex: base64.StdEncoding.EncodeToString(nonce),
				MaxBuf:    saslDataMax,
				Charset:   "utf-8",
				Method:    "AUTHENTICATE",
			},
		},
	}
}

func (client *client) FindMech(mechList []string) (mech string, err error) {
	for _, entry := range mechList {
		// Eventually this would be the place to switch to different
		// mech variations, but for now we only support md5
		if entry == "DIGEST-MD5" {
			return entry, nil
		}
	}
	return "", fmt.Errorf("SASL: Requested mech not supported")
}

func md5Sum(a, b []byte) []byte {
	h := md5.New()
	h.Write(a)
	return h.Sum(b)
}

func (client *client) ApplyChallenge(challenge string) {
	parseChallenge(challenge, &client.context.challenge)
}

func minUint32(x, y uint32) uint32 {
	if x < y {
		return x
	}
	return y
}

func (client *client) calcSecretHash(password string) []byte {
	h := md5.New()
	h.Write([]byte(client.context.Username))
	h.Write([]byte(":"))
	h.Write([]byte(client.context.Realm))
	h.Write([]byte(":"))
	h.Write([]byte(password))
	x := h.Sum(nil)
	return x[:]
}

func (client *client) calcHA1(password string) []byte {
	ha1 := md5.New()
	tmp := client.calcSecretHash(password)
	if client.context.Algorithm == "md5-sess" {
		ha1.Write(tmp)
		ha1.Write([]byte(":"))
		ha1.Write([]byte(client.context.NonceHex))
		ha1.Write([]byte(":"))
		ha1.Write([]byte(client.context.CNonceHex))
		if client.context.AuthzID != "" {
			ha1.Write([]byte(":"))
			ha1.Write([]byte(client.context.AuthzID))
		}
	}
	client.context.HA1 = ha1.Sum(nil)
	client.context.SessionKey = fmt.Sprintf("%x", client.context.HA1)
	return client.context.HA1
}

func (client *client) calcHA2() string {
	digest := md5.New()
	digest.Write([]byte(client.context.Method))
	digest.Write([]byte(":"))
	digest.Write([]byte(client.context.DigestURI))
	if client.context.QOP != "auth" {
		digest.Write([]byte(":00000000000000000000000000000000"))
	}
	ha2 := digest.Sum(nil)
	return fmt.Sprintf("%x", ha2)
}

func (client *client) genResponse(username, password string) string {
	client.context.Username = username
	respHash := md5.New()
	client.calcHA1(password)
	respHash.Write([]byte(client.context.SessionKey))
	respHash.Write([]byte(":"))
	respHash.Write([]byte(client.context.NonceHex))
	respHash.Write([]byte(":"))
	if client.context.QOP != "" {
		respHash.Write([]byte(fmt.Sprintf("%.08x", client.context.NC)))
		respHash.Write([]byte(":"))
		respHash.Write([]byte(client.context.CNonceHex))
		respHash.Write([]byte(":"))
		respHash.Write([]byte(client.context.QOP))
		respHash.Write([]byte(":"))
	}
	respHash.Write([]byte(client.calcHA2()))
	return fmt.Sprintf("%x", respHash.Sum(nil))
}

func (client *client) requestInfo() string {
	password := ""
	items := []CallbackRequestItem{
		CallbackRequestItem{CredentialPassphrase, &password},
	}
	if client.context.Username == "" {
		items = append(items, CallbackRequestItem{CredentialUsername, &client.context.Username})
	}
	if client.Callback(items) == nil {
		return password
	}
	return ""
}

func (client *client) MakeResponse() string {
	client.context.NC++

	password := client.requestInfo()
	ciphers := ""
	if client.context.QOP == "auth-conf" {
		ciphers = fmt.Sprintf("cipher=%s,", client.context.Cipher)
	}

	return fmt.Sprintf(
		`username=%q,realm=%q,nonce="%s",cnonce="%s",nc=%.08x,qop=%s,maxbuf=%d,digest-uri=%q,%sresponse=%s`,
		client.context.Username,
		client.context.Realm,
		client.context.NonceHex,
		client.context.CNonceHex,
		client.context.NC,
		client.context.QOP,
		client.context.MaxBuf,
		client.context.DigestURI,
		ciphers,
		client.genResponse(client.context.Username, password))
}

func (client *client) SetCNonce(s string) {
	client.context.CNonceHex = s
}

func parseChallenge(serverChallenge string, ch *challenge) *challenge {
	if ch == nil {
		ch = &challenge{}
	}

	fieldMapper := map[string]func(string){
		"digest-uri": func(s string) {
			ch.DigestURI = s
		},
		"algorithm": func(s string) {
			ch.Algorithm = s
		},
		"qop": func(s string) {
			ch.QOP = s
		},
		"cipher": func(s string) {
			ch.Ciphers = strings.Split(s, ",")
			for _, cipher := range ch.Ciphers {
				switch cipher {
				case "rc4":
					ch.CipherType = cipherRC4
				case "des":
					ch.CipherType = cipherDES
				case "rc4-56":
					ch.CipherType = cipherRC4_56
				case "rc4-40":
					ch.CipherType = cipherRC4_40
				case "3des":
					ch.CipherType = cipher3DES
				default:
					continue
				}
				ch.Cipher = cipher
			}
		},
		"charset": func(s string) {
			ch.Charset = s
		},
		"realm": func(s string) {
			ch.Realm = s
		},
		"nonce": func(s string) {
			ch.NonceHex = s
		},
		"cnonce": func(s string) {
			ch.CNonceHex = s
		},
		"maxbuf": func(s string) {
			if v, e := strconv.ParseUint(s, 10, 32); e == nil {
				ch.MaxBuf = minUint32(ch.MaxBuf, uint32(v))
			}
		},
		"nc": func(s string) {
			if v, e := strconv.ParseUint("0x"+s, 16, 32); e == nil {
				ch.NC = uint32(v)
			}
		},
	}

	for _, field := range strings.Split(serverChallenge, ",") {
		kv := strings.SplitN(field, "=", 2)
		if len(kv) == 2 {
			kv[1] = strings.Trim(kv[1], `"`)
			if mapper, ok := fieldMapper[kv[0]]; ok {
				mapper(kv[1])
			}
		}
	}
	if ch.DigestURI == "" {
		ch.DigestURI = ch.Service + "/localhost"
	}

	return ch
}
