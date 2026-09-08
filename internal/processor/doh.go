package processor

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// DoH/EDNS helpers mirroring the original implementation in
// Sub-Store-master/backend/src/utils/dns.js: DNS wire-format queries are sent
// over HTTPS GET with a base64url payload (`?dns=`) and an
// `application/dns-message` Accept header, with the EDNS client-subnet
// (ECS, option code 8) carried in an OPT additional record.

const (
	dnsTypeA     uint16 = 1
	dnsTypeAAAA  uint16 = 28
	dnsTypeOPT   uint16 = 41
	dnsClassINET uint16 = 1
	// udpPayloadSize used by the original OPT record.
	dnsUDPPayloadSize uint16 = 4096
	// EDNS0 CLIENT_SUBNET option code.
	ednsOptionClientSubnet uint16 = 8
	// Source prefix lengths used by the original for IPv4 / IPv6 ECS.
	ednsSourcePrefixV4 = 24
	ednsSourcePrefixV6 = 56
)

// answerTypeFor maps the operator level type ("IPv4"/"IPv6") to the DNS
// answer record type name, mirroring `type === 'IPv6' ? 'AAAA' : 'A'`.
func answerTypeFor(dnsType string) string {
	if dnsType == "IPv6" {
		return "AAAA"
	}
	return "A"
}

func wireQType(answerType string) (uint16, error) {
	switch answerType {
	case "A":
		return dnsTypeA, nil
	case "AAAA":
		return dnsTypeAAAA, nil
	}
	return 0, fmt.Errorf("unsupported DNS query type: %s", answerType)
}

func dnsName(domain string) (dnsmessage.Name, error) {
	name := strings.TrimSuffix(strings.TrimSpace(domain), ".") + "."
	return dnsmessage.NewName(name)
}

// buildClientSubnetOption builds the EDNS0 CLIENT_SUBNET option payload:
// family (2 bytes), source prefix length (1 byte), scope prefix length
// (1 byte), then the truncated address.
func buildClientSubnetOption(edns string) ([]byte, error) {
	addr, err := netip.ParseAddr(edns)
	if err != nil {
		return nil, fmt.Errorf("域名解析 EDNS 应为 IP")
	}
	if addr.Is4() {
		b := addr.As4()
		data := []byte{0x00, 0x01, ednsSourcePrefixV4, 0x00}
		data = append(data, b[:3]...) // 24 bits
		return data, nil
	}
	b := addr.As16()
	data := []byte{0x00, 0x02, ednsSourcePrefixV6, 0x00}
	data = append(data, b[:7]...) // 56 bits
	return data, nil
}

// buildDNSQuery encodes a recursive DNS query for domain/answerType with an
// optional EDNS client-subnet OPT record, mirroring buildDnsQuery in dns.js.
func buildDNSQuery(domain, answerType, edns string) ([]byte, error) {
	qtype, err := wireQType(answerType)
	if err != nil {
		return nil, err
	}
	name, err := dnsName(domain)
	if err != nil {
		return nil, err
	}

	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:               0,
		RecursionDesired: true,
	})
	if err := builder.StartQuestions(); err != nil {
		return nil, err
	}
	if err := builder.Question(dnsmessage.Question{
		Name:  name,
		Type:  dnsmessage.Type(qtype),
		Class: dnsmessage.Class(dnsClassINET),
	}); err != nil {
		return nil, err
	}
	if edns != "" {
		ecs, err := buildClientSubnetOption(edns)
		if err != nil {
			return nil, err
		}
		if err := builder.StartAdditionals(); err != nil {
			return nil, err
		}
		if err := builder.OPTResource(
			dnsmessage.ResourceHeader{
				Name:  dnsmessage.MustNewName("."),
				Type:  dnsmessage.Type(dnsTypeOPT),
				Class: dnsmessage.Class(dnsUDPPayloadSize),
			},
			dnsmessage.OPTResource{
				Options: []dnsmessage.Option{{
					Code: ednsOptionClientSubnet,
					Data: ecs,
				}},
			},
		); err != nil {
			return nil, err
		}
	}
	return builder.Finish()
}

// decodeDNSAnswers decodes a DNS wire-format message and returns the RDATA of
// every answer record whose type matches answerType ("A"/"AAAA"), mirroring
// `answers.filter(i => i?.type === answerType).map(i => i?.data)`.
func decodeDNSAnswers(body []byte, answerType string) ([]string, error) {
	qtype, err := wireQType(answerType)
	if err != nil {
		return nil, err
	}
	var msg dnsmessage.Message
	if err := msg.Unpack(body); err != nil {
		return nil, err
	}
	var out []string
	for _, ans := range msg.Answers {
		if uint16(ans.Header.Type) != qtype {
			continue
		}
		switch b := ans.Body.(type) {
		case *dnsmessage.AResource:
			addr := netip.AddrFrom4(b.A)
			out = append(out, addr.String())
		case *dnsmessage.AAAAResource:
			addr := netip.AddrFrom16(b.AAAA)
			out = append(out, addr.String())
		}
	}
	return out, nil
}

// dohResolve performs a DoH lookup exactly like the original `doh()`:
// GET `${url}?dns=${base64url(query)}` with Accept: application/dns-message.
func dohResolve(rawURL, domain, answerType, edns string, timeoutMS int, insecure bool) ([]string, error) {
	query, err := buildDNSQuery(domain, answerType, edns)
	if err != nil {
		return nil, err
	}
	b64 := base64.RawURLEncoding.EncodeToString(query)
	reqURL := rawURL + "?dns=" + url.QueryEscape(b64)
	body, err := httpGetString(reqURL, timeoutMS, insecure, map[string]string{
		"Accept": "application/dns-message",
	})
	if err != nil {
		return nil, err
	}
	answers, err := decodeDNSAnswers(body, answerType)
	if err != nil {
		return nil, err
	}
	if len(answers) == 0 {
		return nil, errors.New("No answers")
	}
	return answers, nil
}
