package enrol

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/jdpanderson/cheesecloth/internal/wire"
	"github.com/jdpanderson/cheesecloth/trust"
)

// Version identifies this exchange format; a mismatch fails closed.
const Version = 1

const (
	nonceLen     = 32
	maxFrame     = 1 << 20 // records for a large cluster fit comfortably
	exchangeTime = 15 * time.Second
	kdfInfo      = "cheesecloth/enroll/v1"
	labelMember  = "member"
	labelJoiner  = "joiner"
)

// hello is the joiner's first message, in the clear.
type hello struct {
	Version  int             `json:"version"`
	TokenID  []byte          `json:"tokenId"`
	Identity trust.PublicKey `json:"identity"`
	DH       trust.DHKey     `json:"dh"`
	Nonce    []byte          `json:"nonce"`
	Name     string          `json:"name"`
}

// challenge is the member's reply: its keys, nonce and proof of token knowledge.
type challenge struct {
	Identity trust.PublicKey `json:"identity"`
	DH       trust.DHKey     `json:"dh"`
	Nonce    []byte          `json:"nonce"`
	MAC      []byte          `json:"mac"`
}

// proof is the joiner's proof of token knowledge.
type proof struct {
	MAC []byte `json:"mac"`
}

// Welcome is what an admitted joiner receives; the transport's TLS protects it.
type Welcome struct {
	Root       trust.PublicKey `json:"root"`
	Records    trust.Records   `json:"records"`
	Admission  trust.Admission `json:"admission"`  // the joiner's own
	GossipAddr string          `json:"gossipAddr"` // member's ip:port for memberlist
	// Member is the identity of the member that ran the exchange, verified
	// against the connection by Join; it is not part of the message.
	Member trust.PublicKey `json:"-"`
}

// deriveKey derives the exchange's MAC key, mixing the DH secret and the token
// so that neither alone suffices.
func deriveKey(ss, token, nJ, nM []byte) []byte {
	salt := append(append([]byte(nil), nJ...), nM...)
	k, err := hkdf.Key(sha256.New, append(append([]byte(nil), ss...), token...), salt, kdfInfo, 32)
	if err != nil {
		panic("hkdf: " + err.Error()) // only for absurd output lengths
	}
	return k
}

// transcript binds both identities, both DH keys, both nonces and the name.
func transcript(j trust.PublicKey, jd trust.DHKey, m trust.PublicKey, md trust.DHKey, nJ, nM []byte, name string) []byte {
	return wire.Fields(j[:], jd[:], m[:], md[:], nJ, nM, []byte(name))
}

func mac(key []byte, label string, transcript []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(label))
	h.Write([]byte{0})
	h.Write(transcript)
	return h.Sum(nil)
}

// writeFrame sends a length-prefixed JSON message.
func writeFrame(w io.Writer, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(body) > maxFrame {
		return errors.New("frame too large")
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(body)))
	if _, err = w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(body)
	return err
}

// readFrame receives a length-prefixed JSON message.
func readFrame(r io.Reader, v any) error {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > maxFrame {
		return errors.New("frame too large")
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return err
	}
	return json.Unmarshal(body, v)
}

func randomNonce() ([]byte, error) {
	n := make([]byte, nonceLen)
	if _, err := rand.Read(n); err != nil {
		return nil, fmt.Errorf("reading random source: %w", err)
	}
	return n, nil
}

// setDeadline bounds the whole exchange.
func setDeadline(conn net.Conn) { _ = conn.SetDeadline(time.Now().Add(exchangeTime)) }
