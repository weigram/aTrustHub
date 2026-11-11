package auth

import (
	"fmt"
	"log"
)

type CodeKind int

const (
	CodeSMS       CodeKind = iota // 短信验证码
	CodeCustomSMS                 // 部署自己的短信页面的验证码
	CodeTOTP                      // 动态口令（用户名下没有保存密钥时才会问）
	CodeRADIUS                    // RADIUS / challenge 令牌
)

type CodeRequest struct {
	Kind CodeKind
	Tip  string // 服务器发码时说的话，如 验证码已发送到您的手机：138****0000, 请查收！
}

// CodePrompter asks the user for one code. nil reads a line from the terminal.
type CodePrompter func(CodeRequest) (string, error)

// askCode asks for one code. Without a prompter it keeps the terminal prompt
// the CLI has always shown for that kind.
func (s *Session) askCode(req CodeRequest) (string, error) {
	if s.promptCode != nil {
		return s.promptCode(req)
	}

	switch req.Kind {
	case CodeTOTP:
		log.Print("Please enter the TOTP token: ")
	case CodeRADIUS:
		log.Print("Please enter the RADIUS token: ")
	default:
		log.Print("Please enter the SMS verification code: ")
	}

	code := ""
	if _, err := fmt.Scanln(&code); err != nil {
		return "", err
	}
	return code, nil
}
