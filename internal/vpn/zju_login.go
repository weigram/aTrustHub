package vpn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"

	atrustclient "github.com/mythologyli/zju-connect/client/atrust"
	"github.com/mythologyli/zju-connect/client/atrust/auth"

	"github.com/qy/easyconnect/internal/model"
)

// zjuLoginMethod builds what ZJU-Connect's Setup needs for this access
// point: a password login, or the callback of an external login such as
// the WeCom QR code.
func zjuLoginMethod(ctx context.Context, point model.AccessPoint, creds Credentials) (auth.LoginMethod, error) {
	switch model.AuthMode(point.AuthMode) {
	case model.AuthModeAuto:
		return autoLoginMethod(ctx, point, creds)
	case model.AuthModeWeCom:
		return externalLoginMethod(ctx, point, creds)
	default:
		return passwordLoginMethod(point, creds, point.LoginDomain)
	}
}

// autoLoginMethod asks the server what it offers: a stored password and
// auth/psw win, otherwise the first WeCom/enterprise external login.
func autoLoginMethod(ctx context.Context, point model.AccessPoint, creds Credentials) (auth.LoginMethod, error) {
	infos, err := authInfoList(ctx, point)
	if err != nil {
		// A stored password still lets the login proceed without the
		// discovery call.
		if strings.TrimSpace(creds.Login) != "" {
			return passwordLoginMethod(point, creds, point.LoginDomain)
		}
		return nil, fmt.Errorf("获取登录方式失败：%w", err)
	}
	if strings.TrimSpace(creds.Login) != "" {
		if info, ok := pickPasswordAuthInfo(infos, point.LoginDomain); ok {
			return passwordLoginMethod(point, creds, info.LoginDomain)
		}
	}
	if strings.TrimSpace(creds.Login) == "" && strings.TrimSpace(point.Username) != "" {
		if _, ok := pickPasswordAuthInfo(infos, point.LoginDomain); ok {
			return nil, errors.New("该接入点填了用户名但没有保存密码：请在编辑里填写密码；不想用密码就把用户名清空")
		}
	}
	if info, ok := pickExternalAuthInfo(infos, point.LoginDomain); ok {
		return externalLoginMethodFromInfo(ctx, point, creds, info)
	}
	if _, ok := pickPasswordAuthInfo(infos, point.LoginDomain); ok {
		return nil, errors.New("服务器支持账号密码认证，但没有保存密码；请填写密码，或把认证方式改成扫码")
	}
	return nil, fmt.Errorf("服务器没有可用的登录方式；可用：%s", describeAuthInfo(infos))
}

func passwordLoginMethod(point model.AccessPoint, creds Credentials, domain string) (auth.LoginMethod, error) {
	if domain == "" {
		domain = "Radius"
	}
	return auth.NewLoginMethod(auth.LoginMethodOptions{
		AuthType: "auth/psw",
		Username: point.Username,
		Password: creds.Login,
		Domain:   domain,
	})
}

func pickPasswordAuthInfo(infos []auth.AuthInfo, preferredDomain string) (auth.AuthInfo, bool) {
	var first *auth.AuthInfo
	for i := range infos {
		info := infos[i]
		if info.AuthType != "auth/psw" {
			continue
		}
		if preferredDomain != "" && strings.EqualFold(info.LoginDomain, preferredDomain) {
			return info, true
		}
		if first == nil {
			first = &info
		}
	}
	if first == nil {
		return auth.AuthInfo{}, false
	}
	return *first, true
}

// externalLoginMethod asks the server which external login methods it
// offers, opens the first WeCom/enterprise one, and turns the callback the
// provider redirected to into the login method ZJU-Connect takes.
func externalLoginMethod(ctx context.Context, point model.AccessPoint, creds Credentials) (auth.LoginMethod, error) {
	if creds.ExternalLogin == nil {
		return nil, errors.New("扫码登录需要主窗口")
	}
	infos, err := authInfoList(ctx, point)
	if err != nil {
		return nil, fmt.Errorf("获取登录方式失败：%w", err)
	}
	info, ok := pickExternalAuthInfo(infos, point.LoginDomain)
	if !ok {
		return nil, fmt.Errorf("服务器没有可用的企业微信/外部登录方式；可用：%s", describeAuthInfo(infos))
	}
	if info.AuthType != "auth/qywechat" && strings.TrimSpace(info.LoginURL) == "" {
		return nil, fmt.Errorf("服务器没有给出 %s 的登录地址", info.AuthType)
	}

	return externalLoginMethodFromInfo(ctx, point, creds, info)
}

func externalLoginMethodFromInfo(ctx context.Context, point model.AccessPoint, creds Credentials, info auth.AuthInfo) (auth.LoginMethod, error) {
	if creds.ExternalLogin == nil {
		return nil, errors.New("扫码登录需要主窗口")
	}
	if info.AuthType == "auth/qywechat" {
		// Let the login method build the QR URL from its own session's
		// auth config: the state in that URL is the one the callback is
		// checked against.
		return auth.QyWechatLogin{Domain: info.LoginDomain, WebLogin: true, Open: func(loginURL string) (string, error) {
			return creds.ExternalLogin(ctx, loginURL)
		}}, nil
	}
	loginURL, err := authLoginURL(info, point)
	if err != nil {
		return nil, err
	}
	callback, err := creds.ExternalLogin(ctx, loginURL)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		return nil, fmt.Errorf("扫码登录未完成：%w", err)
	}
	return loginMethodFromCallback(info, callback, point.Server)
}

type authInfoResult struct {
	infos []auth.AuthInfo
	err   error
}

// authInfoList fetches the server's authentication methods. ZJU-Connect's
// call has no context, so it runs beside it and the context can abandon the
// wait.
func authInfoList(ctx context.Context, point model.AccessPoint) ([]auth.AuthInfo, error) {
	ch := make(chan authInfoResult, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				ch <- authInfoResult{err: fmt.Errorf("获取登录方式崩溃：%v", r)}
			}
		}()
		infos, err := atrustclient.GetAuthInfoList(point.Server, point.Port, "", true, "114.114.114.114", "")
		ch <- authInfoResult{infos: infos, err: err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-ch:
		return res.infos, res.err
	}
}

// pickExternalAuthInfo chooses the WeCom/enterprise external login among
// what the server offers. The server's authName ("企业微信认证") is the
// clearest signal; the login domain breaks ties.
func pickExternalAuthInfo(infos []auth.AuthInfo, preferredDomain string) (auth.AuthInfo, bool) {
	type scored struct {
		info  auth.AuthInfo
		score int
	}
	var candidates []scored
	for _, info := range infos {
		if info.AuthType != "auth/httpsOauth2" && info.AuthType != "auth/cas" && info.AuthType != "auth/qywechat" {
			continue
		}
		name := strings.ToLower(info.AuthName)
		score := 0
		switch {
		case containsAny(name, "企业微信", "wework", "wecom", "wxwork"):
			score += 20
		case containsAny(name, "微信", "wechat"):
			score += 8
		}
		switch info.AuthType {
		case "auth/qywechat":
			score += 10
		case "auth/httpsOauth2":
			score += 2
		case "auth/cas":
			score++
		}
		if preferredDomain != "" && strings.EqualFold(info.LoginDomain, preferredDomain) {
			score++
		}
		candidates = append(candidates, scored{info: info, score: score})
	}
	if len(candidates) == 0 {
		return auth.AuthInfo{}, false
	}
	sort.SliceStable(candidates, func(i, j int) bool { return candidates[i].score > candidates[j].score })
	return candidates[0].info, true
}

func containsAny(s string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}

func describeAuthInfo(infos []auth.AuthInfo) string {
	if len(infos) == 0 {
		return "（无）"
	}
	parts := make([]string, 0, len(infos))
	for _, info := range infos {
		label := info.AuthType
		if info.AuthName != "" {
			label += "（" + info.AuthName + "）"
		}
		if info.LoginDomain != "" {
			label += " 域=" + info.LoginDomain
		}
		parts = append(parts, label)
	}
	return strings.Join(parts, "；")
}

// loginMethodFromCallback validates the callback against the configured
// server and builds the matching ZJU-Connect login method. The callback's
// code or ticket is what the aTrust server exchanges for a portal ticket.
func loginMethodFromCallback(info auth.AuthInfo, callback, server string) (auth.LoginMethod, error) {
	u, err := url.Parse(callback)
	if err != nil {
		return nil, fmt.Errorf("回调地址无效：%w", err)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return nil, errors.New("回调地址不是 https")
	}
	if !strings.EqualFold(u.Hostname(), server) {
		return nil, fmt.Errorf("回调地址的主机是 %s，不是配置的服务器 %s", u.Hostname(), server)
	}
	domain := info.LoginDomain
	if domain == "" {
		domain = "Radius"
	}
	path := strings.TrimSuffix(u.Path, "/")
	switch info.AuthType {
	case "auth/httpsOauth2":
		if path != "/passport/v1/auth/httpsOauth2" || u.Query().Get("code") == "" {
			return nil, errors.New("回调地址缺少 code")
		}
		return auth.HTTPSOauth2Login{Domain: domain, Callback: callback}, nil
	case "auth/qywechat":
		if path != "/passport/v1/auth/qywechat" || u.Query().Get("code") == "" {
			return nil, errors.New("回调地址缺少 code")
		}
		return auth.QyWechatLogin{Domain: domain, Callback: callback}, nil
	case "auth/cas":
		if path != "/passport/v1/auth/cas" || u.Query().Get("ticket") == "" {
			return nil, errors.New("回调地址缺少 ticket")
		}
		return auth.CASLogin{Domain: domain, Ticket: u.Query().Get("ticket")}, nil
	default:
		return nil, fmt.Errorf("不支持的登录方式：%s", info.AuthType)
	}
}

// authLoginURL opens the page the identity provider shows: WeCom's QR page
// for auth/qywechat, or the server's login page for OAuth2/CAS. aTrust
// returns some of these relative to its own origin.
func authLoginURL(info auth.AuthInfo, point model.AccessPoint) (string, error) {
	host := point.Server
	if point.Port != 0 && point.Port != 443 {
		host = net.JoinHostPort(point.Server, strconv.Itoa(point.Port))
	}
	base := "https://" + host

	if info.AuthType == "auth/qywechat" {
		return auth.QyWechatLoginURL(base, info)
	}
	raw := strings.TrimSpace(info.LoginURL)
	if raw == "" {
		return "", fmt.Errorf("服务器没有给出 %s 的登录地址", info.AuthType)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("登录地址无效：%w", err)
	}
	if !u.IsAbs() {
		u, err = url.Parse(base + "/" + strings.TrimPrefix(raw, "/"))
		if err != nil {
			return "", fmt.Errorf("登录地址无效：%w", err)
		}
	}
	return u.String(), nil
}

// AuthMethod is one login method the server offers, for the editor's
// "detect" button.
type AuthMethod struct {
	Type   string
	Domain string
	Name   string
}

// Label is the method as the UI lists it.
func (m AuthMethod) Label() string {
	name := m.Name
	if name == "" {
		name = m.Type
	}
	if m.Domain != "" {
		return name + "（" + m.Domain + "）"
	}
	return name
}

// DetectAuthMethods asks the server which login methods it offers. It does
// not log in.
func DetectAuthMethods(ctx context.Context, point model.AccessPoint) ([]AuthMethod, error) {
	infos, err := authInfoList(ctx, point)
	if err != nil {
		return nil, err
	}
	out := make([]AuthMethod, 0, len(infos))
	for _, info := range infos {
		out = append(out, AuthMethod{Type: info.AuthType, Domain: info.LoginDomain, Name: info.AuthName})
	}
	return out, nil
}
