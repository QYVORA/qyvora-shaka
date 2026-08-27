// Package ldap implements a minimal but complete read-only LDAPv3 client:
// simple bind and subtree searches with paging, used by the directory
// subsystem. It is self-contained (standard library only) and serves as an
// honest reference implementation of the LDAP wire protocol for both live
// assessments and deterministic simulator tests.
package ldap

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/QYVORA/qyvora-shaka/internal/transport"
)

// BER application tags and primitive tags used by LDAP PDUs.
const (
	opBindRequest      = 0x60
	opBindResponse     = 0x61
	opSearchRequest    = 0x63
	opSearchResult     = 0x64
	opSearchDone       = 0x65
	opUnbindRequest    = 0x42
	opExtendedRequest  = 0x77
	opExtendedResponse = 0x78
)

const (
	filterAnd     = 0xa0
	filterOr      = 0xa1
	filterNot     = 0xa2
	filterEq      = 0xa3
	filterPresent = 0x87
)

// Search scopes.
const (
	ScopeBase     = 0
	ScopeOneLevel = 1
	ScopeSubtree  = 2
)

// Known result codes for error mapping.
const (
	resultSuccess           = 0
	resultSizeLimitExceeded = 4
	resultTimeLimit         = 3
)

// OID for LDAP simple paged results control.
const pagedResultsOID = "1.2.840.113556.1.4.319"

// Client is a read-only LDAP client over TCP (optionally TLS).
type Client struct {
	conn     net.Conn
	msgID    int
	rootBase string
	timeout  time.Duration
	closed   bool
}

// Options configures a connection.
type Options struct {
	Address  string
	BaseDN   string
	UseTLS   bool
	Insecure bool
	Timeout  time.Duration
}

// Dial opens a connection without binding. Callers may then Bind or read the
// root DSE.
func Dial(ctx context.Context, opts Options) (*Client, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = 15 * time.Second
	}
	dialer := &net.Dialer{Timeout: opts.Timeout, Deadline: deadlineFrom(ctx, opts.Timeout)}
	var conn net.Conn
	var err error
	if opts.UseTLS {
		cfg := &tls.Config{InsecureSkipVerify: opts.Insecure}
		conn, err = tls.DialWithDialer(dialer, "tcp", opts.Address, cfg)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", opts.Address)
	}
	if err != nil {
		return nil, err
	}
	return &Client{conn: conn, timeout: opts.Timeout}, nil
}

func deadlineFrom(ctx context.Context, d time.Duration) time.Time {
	if dl, ok := ctx.Deadline(); ok {
		return dl
	}
	return time.Now().Add(d)
}

// Close closes the connection.
func (c *Client) Close() error {
	if c.closed {
		return nil
	}
	c.closed = true
	return c.conn.Close()
}

// BindError signals a rejected bind.
type BindError struct{ Result string }

func (e *BindError) Error() string { return "ldap: bind rejected: " + e.Result }

// Bind performs a LDAPv3 simple bind.
func (c *Client) Bind(ctx context.Context, user, password string) error {
	_ = c.conn.SetDeadline(deadlineFrom(ctx, c.timeout))
	var body []byte
	body = append(body, berInt(3)...) // LDAPv3
	body = append(body, berString(user)...)
	body = append(body, tagBytes(0x80, []byte(password))...)

	req, err := c.message(opBindRequest, body)
	if err != nil {
		return err
	}
	if err := c.write(req); err != nil {
		return err
	}
	resp, err := c.readMessage()
	if err != nil {
		return err
	}
	return c.parseBindResponse(resp)
}

func (c *Client) parseBindResponse(pkt []byte) error {
	body, _, err := readTLV(pkt, 0)
	if err != nil {
		return err
	}
	_, rl, rn, err := parseTLV(body, 0)
	if err != nil {
		return err
	}
	if rl == 1 && body[rn] == 0 {
		return nil
	}
	code, _ := decodeInt(body[rn : rn+rl])
	return &BindError{Result: codeName(code)}
}

// Search runs a subtree search and returns entries.
func (c *Client) Search(ctx context.Context, baseDN, filter string, attrs []string, pageSize int) ([]*transport.Entry, error) {
	if pageSize <= 0 {
		pageSize = 500
	}
	_ = c.conn.SetDeadline(deadlineFrom(ctx, c.timeout))
	f, err := c.filterBytes([]byte(filter))
	if err != nil {
		return nil, err
	}

	var out []*transport.Entry
	var cookie []byte
	for {
		body := c.searchBody(baseDN, ScopeSubtree, f, attrs, pageSize, cookie)
		req, err := c.message(opSearchRequest, body)
		if err != nil {
			return out, err
		}
		if err := c.write(req); err != nil {
			return out, err
		}
		entries, nextCookie, err := c.readSearchResponse()
		if err != nil {
			return out, err
		}
		out = append(out, entries...)
		if len(nextCookie) == 0 {
			return out, nil
		}
		cookie = nextCookie
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
	}
}

func (c *Client) searchBody(baseDN string, scope int, filter []byte, attrs []string, pageSize int, cookie []byte) []byte {
	var inner []byte
	inner = append(inner, berString(baseDN)...)
	inner = append(inner, berEnum(byte(scope))...)
	inner = append(inner, berEnum(0)...) // derefAliases: never
	inner = append(inner, berInt(0)...)  // sizeLimit: none
	inner = append(inner, berInt(0)...)  // timeLimit: none
	inner = append(inner, berBool(false)...)
	inner = append(inner, filter...)
	inner = append(inner, berStringSet(attrs)...)

	// Controls: simple paged results (OID 1.2.840.113556.1.4.319).
	if pageSize > 0 {
		inner = append(inner, pagedResultsControl(pageSize, cookie)...)
	}
	return inner
}

func (c *Client) readSearchResponse() ([]*transport.Entry, []byte, error) {
	var out []*transport.Entry
	var cookie []byte
	for {
		pkt, err := c.readMessage()
		if err != nil {
			return out, cookie, err
		}
		op := pkt[0]
		body, _, err := readTLV(pkt, 0)
		if err != nil {
			return out, cookie, err
		}
		switch op {
		case opSearchResult:
			e := parseSearchEntry(body)
			if e != nil {
				out = append(out, e)
			}
		case opSearchDone:
			code, cookieFrom := parseSearchDone(body)
			if code != resultSuccess && code != resultSizeLimitExceeded {
				return out, cookie, fmt.Errorf("ldap: search failed: %s", codeName(code))
			}
			return out, cookieFrom, nil
		default:
			return out, cookie, fmt.Errorf("ldap: unexpected op 0x%02x", op)
		}
	}
}

// RootDSE returns the root DSE entry (used to derive the default base DN).
func (c *Client) RootDSE(ctx context.Context) (*transport.Entry, error) {
	return c.rootDSEWithAttrs(ctx, []string{"defaultNamingContext", "rootDomainNamingContext", "namingContexts", "supportedControl"})
}

func (c *Client) rootDSEWithAttrs(ctx context.Context, attrs []string) (*transport.Entry, error) {
	_ = c.conn.SetDeadline(deadlineFrom(ctx, c.timeout))
	f := []byte{0x87, 0x00} // present(objectClass)
	body := c.searchBody("", ScopeBase, f, attrs, 0, nil)
	req, err := c.message(opSearchRequest, body)
	if err != nil {
		return nil, err
	}
	if err := c.write(req); err != nil {
		return nil, err
	}
	entries, _, err := c.readSearchResponse()
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, errors.New("ldap: empty root DSE")
	}
	return entries[0], nil
}

// berEncode helpers ----------------------------------------------------------

func berInt(n int) []byte { return appendTag(0x02, intBytes(n)) }

func berEnum(n byte) []byte { return appendTag(0x0a, []byte{n}) }

func berBool(b bool) []byte {
	if b {
		return appendTag(0x01, []byte{0xff})
	}
	return appendTag(0x01, []byte{0x00})
}

func berString(s string) []byte { return appendTag(0x04, []byte(s)) }

func berStringSet(ss []string) []byte {
	if len(ss) == 0 {
		return appendTag(0x30, nil)
	}
	var inner []byte
	for _, s := range ss {
		inner = append(inner, berString(s)...)
	}
	return appendTag(0x30, inner)
}

func tagBytes(tag byte, b []byte) []byte { return appendTag(tag, b) }

func appendTag(tag byte, content []byte) []byte {
	out := []byte{tag}
	ln := len(content)
	switch {
	case ln < 0x80:
		out = append(out, byte(ln))
	case ln <= 0xff:
		out = append(out, 0x81, byte(ln))
	case ln <= 0xffff:
		out = append(out, 0x82, byte(ln>>8), byte(ln))
	default:
		out = append(out, 0x83, byte(ln>>16), byte(ln>>8), byte(ln))
	}
	return append(out, content...)
}

func intBytes(n int) []byte {
	if n == 0 {
		return []byte{0}
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte(n & 0xff)}, b...)
		n >>= 8
	}
	if b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return b
}

func (c *Client) message(op byte, body []byte) ([]byte, error) {
	c.msgID++
	id := berInt(c.msgID)
	inner := append(append([]byte{}, id...), body...)
	tagged := appendTag(op, inner)
	ldapMsg := appendTag(0x30, tagged)
	return ldapMsg, nil
}

func (c *Client) write(b []byte) error {
	if c.closed {
		return errors.New("ldap: connection closed")
	}
	_, err := c.conn.Write(prefixLength(b))
	return err
}

func (c *Client) readMessage() ([]byte, error) {
	hdr := make([]byte, 2)
	if _, err := readFull(c.conn, hdr); err != nil {
		return nil, err
	}
	if hdr[0] != 0x30 {
		return nil, fmt.Errorf("ldap: bad message tag 0x%02x", hdr[0])
	}
	length, n, err := decodeLength(hdr, 1)
	if err != nil {
		return nil, err
	}
	body := make([]byte, length)
	if _, err := readFull(c.conn, body); err != nil {
		return nil, err
	}
	_ = n
	return body, nil
}

func prefixLength(b []byte) []byte {
	return b // length already encoded in the LDAP message tag header
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func decodeLength(b []byte, pos int) (int, int, error) {
	if pos >= len(b) {
		return 0, 0, errors.New("ldap: truncated length")
	}
	if b[pos] < 0x80 {
		return int(b[pos]), pos + 1, nil
	}
	numBytes := int(b[pos] & 0x7f)
	if numBytes == 0 || numBytes > 4 || pos+1+numBytes > len(b) {
		return 0, 0, errors.New("ldap: bad long length")
	}
	var ln int
	for i := 0; i < numBytes; i++ {
		ln = ln<<8 | int(b[pos+1+i])
	}
	return ln, pos + 1 + numBytes, nil
}

// readTLV strips the outer tag and returns its content bytes and consumed.
func readTLV(pkt []byte, pos int) (body []byte, next int, err error) {
	_, ln, n, err := parseTLV(pkt, pos)
	if err != nil {
		return nil, 0, err
	}
	start := n
	if start+ln > len(pkt) {
		return nil, 0, errors.New("ldap: truncated TLV")
	}
	return pkt[start : start+ln], start + ln, nil
}

func parseTLV(b []byte, pos int) (tag byte, length int, next int, err error) {
	if pos >= len(b) {
		return 0, 0, 0, errors.New("ldap: truncated tag")
	}
	tag = b[pos]
	ln, n, err := decodeLength(b, pos+1)
	if err != nil {
		return 0, 0, 0, err
	}
	return tag, ln, n, nil
}

// decodeInt decodes a BER INTEGER (assumed non-negative).
func decodeInt(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, errors.New("ber: empty integer")
	}
	v := 0
	for _, c := range b {
		v = v<<8 | int(c)
	}
	if b[0]&0x80 != 0 {
		return 0, errors.New("ber: negative integer")
	}
	return v, nil
}

func parseSearchEntry(body []byte) *transport.Entry {
	_, dl, dn, err := parseTLV(body, 0)
	if err != nil {
		return nil
	}
	dnBytes := body[dn : dn+dl]
	// Advance past objectName.
	start := dn + dl
	_, sl, sn, err := parseTLV(body, start)
	if err != nil {
		return nil
	}
	_ = sl
	attrsBytes := body[sn : sn+sl]
	e := &transport.Entry{
		DN:         string(dnBytes),
		Attributes: map[string][]string{},
	}
	parseAttributes(attrsBytes, e)
	return e
}

func parseAttributes(b []byte, e *transport.Entry) {
	pos := 0
	for pos < len(b) {
		_, al, an, err := parseTLV(b, pos)
		if err != nil {
			return
		}
		attrContent := b[an : an+al]
		pos = an + al
		// attrContent: type (OCTET STRING) then SET OF values.
		_, tl, tn, err := parseTLV(attrContent, 0)
		if err != nil {
			continue
		}
		attrName := string(attrContent[tn : tn+tl])
		valsStart := tn + tl
		_, _, vn, err := parseTLV(attrContent, valsStart)
		if err != nil {
			continue
		}
		// SET of values: each is an OCTET STRING.
		vs := attrContent[vn:]
		vals := parseValueSet(vs)
		e.Attributes[strings.ToLower(attrName)] = vals
	}
}

func parseValueSet(b []byte) []string {
	var out []string
	pos := 0
	for pos < len(b) {
		_, vl, vn, err := parseTLV(b, pos)
		if err != nil {
			break
		}
		tag := b[pos]
		if tag == 0x04 || tag == 0x80 {
			out = append(out, string(b[vn:vn+vl]))
		}
		pos = vn + vl
	}
	return out
}

// parseSearchDone decodes a SearchResultDone body: resultCode, optional
// matchedDN, optional diagnosticMessage, and optional controls containing a
// paged-results cookie.
func parseSearchDone(body []byte) (int, []byte) {
	pos := 0
	_, cl, cn, err := parseTLV(body, pos)
	if err != nil {
		return 0, nil
	}
	code, _ := decodeInt(body[cn : cn+cl])
	pos = cn + cl
	// Attempt to read the trailing controls (SET OF).
	for pos < len(body) {
		_, sl, sn, err := parseTLV(body, pos)
		if err != nil {
			break
		}
		control := body[sn : sn+sl]
		pos = sn + sl
		if cookie := extractPageCookie(control); len(cookie) > 0 {
			return code, cookie
		}
	}
	return code, nil
}

// extractPageCookie parses a paged-results control (SEQUENCE { controlType
// OID, criticality, controlValue }) and returns the paged cookie.
func extractPageCookie(control []byte) []byte {
	// control: SEQUENCE { controlType, [criticality], controlValue }
	_, _, vn, err := parseTLV(control, 0)
	if err != nil {
		return nil
	}
	rest := control[vn:]
	// Skip controlType OID string, optional criticality boolean, read value.
	pos := 0
	for pos < len(rest) {
		_, ln, n, err := parseTLV(rest, pos)
		if err != nil {
			return nil
		}
		tag := rest[pos]
		if tag == 0x04 && ln >= 8 {
			// controlValue = SEQUENCE { size INTEGER, cookie OCTET STRING }
			val := rest[n : n+ln]
			cookie := parsePageCookieValue(val)
			return cookie
		}
		pos = n + ln
	}
	return nil
}

func parsePageCookieValue(val []byte) []byte {
	// SEQUENCE { size INTEGER, cookie OCTET STRING }
	_, _, vn, err := parseTLV(val, 0)
	if err != nil {
		return nil
	}
	rest := val[vn:]
	// size INTEGER
	_, il, in, err := parseTLV(rest, 0)
	if err != nil {
		return nil
	}
	_ = il
	// cookie OCTET STRING
	_, _, cn, err := parseTLV(rest, in)
	if err != nil {
		return nil
	}
	_, cl, cnn, err := parseTLV(rest, cn)
	if err != nil {
		return nil
	}
	if tagIsString(rest[cn]) {
		return rest[cnn : cnn+cl]
	}
	return nil
}

func tagIsString(tag byte) bool { return tag == 0x04 || tag == 0x80 }

// filterBytes parses a full LDAP filter expression into BER bytes.
func (c *Client) filterBytes(f []byte) ([]byte, error) {
	expr := strings.TrimSpace(string(f))
	if expr == "" {
		return nil, errors.New("ldap: empty filter")
	}
	if !strings.HasPrefix(expr, "(") {
		expr = "(" + expr + ")"
	}
	return c.parseFilter(expr)
}

func (c *Client) parseFilter(expr string) ([]byte, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil, nil
	}
	switch {
	case strings.HasPrefix(expr, "(&"):
		inner, err := c.parseAndOr(expr[2:])
		if err != nil {
			return nil, err
		}
		return appendTag(filterAnd, inner), nil
	case strings.HasPrefix(expr, "(|"):
		inner, err := c.parseAndOr(expr[2:])
		if err != nil {
			return nil, err
		}
		return appendTag(filterOr, inner), nil
	case strings.HasPrefix(expr, "(!)"):
		inner, err := c.parseFilter(expr[3:])
		if err != nil {
			return nil, err
		}
		return appendTag(filterNot, inner), nil
	case strings.HasPrefix(expr, "("):
		return c.parseSimple(expr)
	}
	return nil, fmt.Errorf("ldap: unsupported filter %q", expr)
}

func (c *Client) parseAndOr(rest string) ([]byte, error) {
	var inner []byte
	// rest begins at the first '(' after the operator.
	idx := strings.Index(rest, "(")
	if idx < 0 {
		return nil, errors.New("ldap: empty and/or filter")
	}
	depth := 0
	current := rest[idx:]
	start := 0
	for i := 0; i < len(current); i++ {
		switch current[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				part := current[start : i+1]
				fb, err := c.parseFilter(part)
				if err != nil {
					return nil, err
				}
				inner = append(inner, fb...)
				if i+1 < len(current) && current[i+1] == '(' {
					start = i + 1
				} else {
					return inner, nil
				}
			}
		}
	}
	return inner, nil
}

func (c *Client) parseSimple(expr string) ([]byte, error) {
	body := strings.TrimPrefix(strings.TrimSuffix(expr, ")"), "(")
	// Attribute present: "(attr=*)" vs equality "(attr=value)".
	if strings.HasSuffix(body, "=*") {
		attr := strings.TrimSuffix(body, "=*")
		return appendTag(filterPresent, []byte(attr)), nil
	}
	if i := strings.IndexByte(body, '='); i > 0 {
		attr := body[:i]
		value := body[i+1:]
		value = strings.ReplaceAll(value, `\28`, "(")
		value = strings.ReplaceAll(value, `\29`, ")")
		value = strings.ReplaceAll(value, `\2a`, "*")
		inner := append(berString(attr), berString(value)...)
		return appendTag(filterEq, inner), nil
	}
	return nil, fmt.Errorf("ldap: malformed simple filter %q", body)
}

func pagedResultsControl(pageSize int, cookie []byte) []byte {
	// control: SEQUENCE { controlType, criticality?, controlValue? }
	var value []byte
	value = append(value, berInt(pageSize)...)
	value = append(value, berString(string(cookie))...)
	value = appendTag(0x30, value)

	var ctrl []byte
	ctrl = append(ctrl, berString(pagedResultsOID)...)
	ctrl = append(ctrl, berBool(false)...)
	ctrl = append(ctrl, appendTag(0x04, value)...)
	return appendTag(0x30, ctrl)
}

func codeName(code int) string {
	switch code {
	case 0:
		return "success"
	case 3:
		return "timeLimitExceeded"
	case 4:
		return "sizeLimitExceeded"
	case 32:
		return "noSuchObject"
	case 34:
		return "invalidDNSyntax"
	case 49:
		return "invalidCredentials"
	case 53:
		return "unwillingToPerform"
	default:
		return fmt.Sprintf("code %d", code)
	}
}
