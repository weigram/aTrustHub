package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/mythologyli/zju-connect/log"
)

// QyWechatLogin is aTrust's WeCom QR login (auth/qywechat). The app opens
// WeCom's QR page, the user scans it, and the https callback the browser
// lands on is passed here; this method sends that callback from the login's
// own HTTP session, as the official client does, and completes with the
// portal ticket.
type QyWechatLogin struct {
	Domain string
	// Callback, when set, is the full https callback the QR flow landed
	// on. Open is used instead when the app must show the login page from
	// this same login session, so that the state in the URL is the one the
	// callback is checked against.
	Callback string
	// WebLogin uses WeCom's full web login page, which detects an already
	// logged-in desktop WeCom and lets the user confirm without scanning a
	// QR code.
	WebLogin bool
	Open     func(loginURL string) (callback string, err error)
}

func (m QyWechatLogin) AuthType() string { return "auth/qywechat" }

func (m QyWechatLogin) LoginDomain() string { return m.Domain }

func (m QyWechatLogin) login(s *Session, authInfo AuthInfo) error {
	callback := m.Callback
	if callback == "" {
		if m.Open == nil {
			return fmt.Errorf("qywechat login needs a callback or an opener")
		}
		var loginURL string
		var err error
		if m.WebLogin {
			loginURL, err = QyWechatWebLoginURL(authInfo)
		} else {
			loginURL, err = QyWechatLoginURL(s.baseURL, authInfo)
		}
		if err != nil {
			return err
		}
		callback, err = m.Open(loginURL)
		if err != nil {
			return err
		}
	}
	return s.loginAuthQyWechat(callback)
}

// QyWechatLoginURL builds WeCom's QR page from the configuration aTrust
// returned in this login's auth config. The older qyapi.weixin.qq.com
// endpoint in require_url refuses plain requests, while
// open.work.weixin.qq.com answers; both take the same appid, agentid,
// redirect_uri and state.
func QyWechatLoginURL(base string, info AuthInfo) (string, error) {
	conf := info.QyWechatQrcodeConf
	if conf.AppID == "" || conf.AgentID == "" {
		return "", fmt.Errorf("qywechat config is missing appid/agentid")
	}
	redirect := conf.RedirectURI
	if redirect == "" {
		domain := info.LoginDomain
		if domain == "" {
			domain = "wechat"
		}
		redirect = base + "/passport/v1/auth/qywechat?sfDomain=" + url.QueryEscape(domain)
	}
	endpoint := "https://open.work.weixin.qq.com/wwopen/sso/qrConnect"
	if u, err := url.Parse(strings.TrimSpace(conf.RequireURL)); err == nil && u.Host != "" {
		if strings.EqualFold(u.Host, "qyapi.weixin.qq.com") {
			u.Host = "open.work.weixin.qq.com"
		}
		endpoint = u.String()
	}
	params := url.Values{
		"appid":        {conf.AppID},
		"agentid":      {conf.AgentID},
		"redirect_uri": {redirect},
		"state":        {conf.State},
	}
	return endpoint + "?" + params.Encode(), nil
}

func (s *Session) loginAuthQyWechat(callback string) error {
	if callback == "" {
		return fmt.Errorf("qywechat callback is empty")
	}
	if err := s.qywechat(callback); err != nil {
		return err
	}
	if s.ticket != "" {
		_, _, err := s.authConfig(true, false)
		return err
	}
	// The QR callback often ends on qrcode_middle.html, whose session
	// cookies are already in the jar. Ask authConfig for the portal ticket.
	isLogin, _, err := s.authConfig(true, true)
	if err != nil {
		return err
	}
	if s.ticket == "" {
		if _, _, err := s.authConfig(false, true); err != nil {
			return err
		}
	}
	if s.ticket == "" {
		log.Printf("qywechat: callback did not yield a ticket (isLogin=%d)", isLogin)
	}
	return nil
}

func (s *Session) qywechat(callback string) error {
	log.Println("Perform GET /passport/v1/auth/qywechat")

	req, err := http.NewRequest("GET", callback, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("x-csrf-token", s.csrfToken)
	req.Header.Set("x-sdp-traceid", s.randSdpId())

	prevCheckRedirect := s.client.CheckRedirect
	s.client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	defer func() { s.client.CheckRedirect = prevCheckRedirect }()

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	body, _ := io.ReadAll(resp.Body)
	log.DebugPrintf("Received qywechat data: %s", string(body))

	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusSeeOther ||
		resp.StatusCode == http.StatusTemporaryRedirect || resp.StatusCode == http.StatusPermanentRedirect {
		location := resp.Header.Get("Location")
		log.Printf("qywechat callback: status=%d location=%s queryKeys=%v", resp.StatusCode, sanitizeURL(location), queryKeys(location))
		if t := ticketFromLocation(location); t != "" {
			s.ticket = t
			return nil
		}
		if u, perr := url.Parse(location); perr == nil {
			if u.Query().Get("type") == "common_error" || u.Query().Get("err_info") != "" {
				return fmt.Errorf("qywechat login failed: %s", sanitizeURL(location))
			}
		}
		if ticket, perr := parsePortalTicketFromRedirect(location, s.baseHost); perr == nil {
			s.ticket = ticket
			return nil
		}
		// A successful QR login lands on qrcode_middle.html, which carries
		// the new session cookies. Sometimes that page redirects again to
		// the portal shortcut that holds the ticket, so follow a few hops.
		if ticket, ferr := s.followQyWechatRedirects(location, 5); ferr == nil && ticket != "" {
			s.ticket = ticket
			return nil
		}
		return nil
	}

	// A few gateways answer the callback with JSON carrying the ticket.
	var re struct {
		Code int `json:"code"`
		Data struct {
			Ticket string `json:"ticket"`
		} `json:"data"`
		Ticket string `json:"ticket"`
	}
	if json.Unmarshal(body, &re) == nil {
		if re.Data.Ticket != "" {
			s.ticket = re.Data.Ticket
			return nil
		}
		if re.Ticket != "" {
			s.ticket = re.Ticket
			return nil
		}
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("qywechat callback returned status %d: %s", resp.StatusCode, string(body))
	}
	log.Printf("qywechat callback: status=%d no ticket in body (len=%d)", resp.StatusCode, len(body))
	return nil
}

// sanitizeURL keeps a URL's origin and path, dropping the query, which holds
// the authorization code and ticket.
func sanitizeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.RawQuery = ""
	return u.String()
}

func firstTicket(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// followQyWechatRedirects follows Location hops from the QR callback,
// looking for the portal shortcut page that carries the ticket. The jar
// already holds the new session cookies, so this stays on the same login.
func (s *Session) followQyWechatRedirects(location string, hops int) (string, error) {
	next := location
	for i := 0; i < hops; i++ {
		u, err := url.Parse(next)
		if err != nil {
			return "", err
		}
		if ticket, perr := parsePortalTicketFromRedirect(next, s.baseHost); perr == nil {
			return ticket, nil
		}
		if t := ticketFromLocation(next); t != "" {
			return t, nil
		}
		if u.Query().Get("type") == "common_error" {
			return "", fmt.Errorf("qywechat login failed at %s", sanitizeURL(next))
		}
		req, err := http.NewRequest("GET", next, nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("User-Agent", UserAgent)
		req.Header.Set("x-csrf-token", s.csrfToken)
		req.Header.Set("x-sdp-traceid", s.randSdpId())
		resp, err := s.client.Do(req)
		if err != nil {
			return "", err
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		if resp.StatusCode < 300 || resp.StatusCode >= 400 {
			return "", nil
		}
		next = resp.Header.Get("Location")
		if next == "" {
			return "", nil
		}
		log.Printf("qywechat follow: status=%d location=%s", resp.StatusCode, sanitizeURL(next))
	}
	return "", nil
}

// ticketFromLocation pulls a portal ticket out of a callback redirect. The
// qrcode_middle page carries it in a JSON "data" query parameter, and some
// servers use a plain ticket parameter.
func ticketFromLocation(location string) string {
	u, err := url.Parse(location)
	if err != nil {
		return ""
	}
	q := u.Query()
	for _, key := range []string{"ticket", "sidTicket", "authTicket"} {
		if v := q.Get(key); v != "" {
			return v
		}
	}
	if raw := q.Get("data"); raw != "" {
		var m map[string]any
		if json.Unmarshal([]byte(raw), &m) == nil {
			if t := ticketFromMap(m); t != "" {
				return t
			}
			if inner, ok := m["data"].(map[string]any); ok {
				if t := ticketFromMap(inner); t != "" {
					return t
				}
			}
		} else if vals, err := url.ParseQuery(raw); err == nil {
			for _, key := range []string{"ticket", "sidTicket", "authTicket"} {
				if v := vals.Get(key); v != "" {
					return v
				}
			}
		}
	}
	return ""
}

// queryKeys lists a URL's query parameter names, never their values.
func queryKeys(location string) []string {
	u, err := url.Parse(location)
	if err != nil {
		return nil
	}
	q := u.Query()
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	return keys
}

// QyWechatWebLoginURL builds WeCom's full web login page. When the desktop
// WeCom client is logged in, that page detects it and offers a quick confirm
// (onCheckWeComLogin), so the user need not scan a QR code; otherwise it
// falls back to the QR code on the same page.
func QyWechatWebLoginURL(info AuthInfo) (string, error) {
	conf := info.QyWechatQrcodeConf
	if conf.AppID == "" || conf.AgentID == "" {
		return "", fmt.Errorf("qywechat config is missing appid/agentid")
	}
	redirect := conf.RedirectURI
	if redirect == "" {
		return "", fmt.Errorf("qywechat config is missing redirect_uri")
	}
	params := url.Values{
		"login_type":    {"CorpApp"},
		"appid":         {conf.AppID},
		"agentid":       {conf.AgentID},
		"redirect_uri":  {redirect},
		"state":         {conf.State},
		"redirect_type": {"top"},
	}
	return "https://login.work.weixin.qq.com/wwlogin/sso/login?" + params.Encode(), nil
}
