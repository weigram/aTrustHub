package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/egoist/mygo"
)

// projectRepo is the GitHub repository this build comes from.
const projectRepo = "weigram/aTrustHub"

// projectURL is the repository home page, opened by the footer icon.
const projectURL = "https://github.com/" + projectRepo

// ghMirrorPrefix is the mirror that serves github.com pages when the direct
// site is unreachable (the office network blocks it).
const ghMirrorPrefix = "https://gh-proxy.com/"

// updateInfo describes a release newer than this build.
type updateInfo struct {
	Version string // without the leading "v"
	URL     string // release page
	Notes   string // first line of the release body
	Source  string // which endpoint answered
}

// releaseSources are tried in order. The direct GitHub API usually works at
// home but is blocked or very slow from the office network, so the mirrors
// behind it are what makes the check useful there.
func releaseSources() []string {
	api := "https://api.github.com/repos/" + projectRepo + "/releases/latest"
	// Reachability measured on the office machine: api.github.com and
	// gh-proxy.com answer; mirror.ghproxy.com times out and ghproxy.net /
	// ghfast.top reply 403, so they are not worth a request. The jsDelivr
	// family serves the version out of mygo.json and is the fallback that
	// actually works behind the Great Firewall.
	manifest := projectRepo + "@main/mygo.json"
	return []string{
		api,
		"https://gh-proxy.com/" + api,
		"https://testingcf.jsdelivr.net/gh/" + manifest,
		"https://gcore.jsdelivr.net/gh/" + manifest,
		"https://cdn.jsdelivr.net/gh/" + manifest,
		"https://raw.githubusercontent.com/" + projectRepo + "/main/mygo.json",
	}
}

// checkForUpdate asks GitHub for the newest release once per start. It runs in
// the background: a blocked mirror must never delay or freeze the window.
func (a *app) checkForUpdate() {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	client := &http.Client{Timeout: 5 * time.Second}
	var failures []string
	for i, url := range releaseSources() {
		direct := i == 0
		info, err := fetchLatest(ctx, client, url)
		if err != nil {
			failures = append(failures, shortHost(url)+": "+err.Error())
			continue
		}
		if info == nil {
			continue
		}
		// 直达 GitHub 成功，说明浏览器也打得开；否则后面的镜像都可用，
		// 那么「GitHub 图标」也应当跳到镜像上，否则点了是白屏。
		a.markGitHubReach(direct)
		if !versionGreater(info.Version, appBuild) {
			a.noteUpdate("已是最新版本 "+appBuild+"（来源 "+info.Source+"）")
			return
		}
		a.win.Update(func() {
			a.update = info
			a.toast = fmt.Sprintf("发现新版本 v%s，点右下角 GitHub 图标下载", info.Version)
		})
		a.noteUpdate(fmt.Sprintf("发现新版本 v%s（当前 v%s，来源 %s）", info.Version, appBuild, info.Source))
		return
	}
	a.noteUpdate("检查更新失败：" + strings.Join(failures, " ｜ "))
}

// markGitHubReach remembers whether github.com itself answered, which decides
// where the footer icon sends the browser.
func (a *app) markGitHubReach(direct bool) {
	if a.win != nil {
		a.win.Update(func() { a.ghReachable = direct })
	} else {
		a.ghReachable = direct
	}
	if !direct {
		a.noteUpdate("github.com 直连不可用，链接改走镜像 " + ghMirrorPrefix)
	}
}

// githubPage returns a github.com page URL that this machine can open: the
// mirror prefix is added when the direct site did not answer.
func (a *app) githubPage(url string) string {
	if a.ghReachable {
		return url
	}
	return ghMirrorPrefix + url
}

// noteUpdate records the outcome in the app log without alarming the user.
func (a *app) noteUpdate(line string) {
	if a.bus != nil {
		a.bus.Add("app", "更新检查："+line)
	}
}

// fetchLatest reads one endpoint and returns the release it describes, or nil
// when the answer is unusable.
func fetchLatest(ctx context.Context, client *http.Client, url string) (*updateInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "aTrustHub/"+appBuild)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body := make([]byte, 1<<20)
	n, _ := resp.Body.Read(body)
	raw := strings.TrimSpace(string(body[:n]))
	if raw == "" {
		return nil, fmt.Errorf("空响应")
	}
	if strings.Contains(url, "releases/latest") {
		return parseRelease(raw, url)
	}
	return parseManifest(raw, url)
}

// parseRelease reads GitHub's release JSON.
func parseRelease(raw, url string) (*updateInfo, error) {
	var r struct {
		TagName string `json:"tag_name"`
		HTMLURL string `json:"html_url"`
		Body    string `json:"body"`
	}
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		return nil, fmt.Errorf("解析发布：%w", err)
	}
	v := strings.TrimPrefix(strings.TrimSpace(r.TagName), "v")
	if v == "" {
		return nil, fmt.Errorf("没有版本号")
	}
	return &updateInfo{
		Version: v,
		URL:     orDefault(r.HTMLURL, projectURL+"/releases/tag/v"+v),
		Notes:   firstLine(r.Body),
		Source:  shortHost(url),
	}, nil
}

// parseManifest falls back to the version field of mygo.json served through a
// CDN, which is bumped with every release.
func parseManifest(raw, url string) (*updateInfo, error) {
	var m struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil, fmt.Errorf("解析清单：%w", err)
	}
	v := strings.TrimPrefix(strings.TrimSpace(m.Version), "v")
	if v == "" {
		return nil, fmt.Errorf("清单里没有版本号")
	}
	return &updateInfo{
		Version: v,
		URL:     projectURL + "/releases/tag/v" + v,
		Source:  shortHost(url),
	}, nil
}

// versionGreater reports whether a is a newer release than b. Missing parts
// count as zero, so "0.25" beats "0.24.9".
func versionGreater(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) || i < len(pb); i++ {
		x, y := num(part(pa, i)), num(part(pb, i))
		if x != y {
			return x > y
		}
	}
	return false
}

func part(s []string, i int) string {
	if i < len(s) {
		return s[i]
	}
	return "0"
}

// num reads the leading integer of a version part, ignoring any suffix.
func num(s string) int {
	digits := strings.TrimFunc(s, func(r rune) bool { return r < '0' || r > '9' })
	if i := strings.IndexFunc(digits, func(r rune) bool { return r < '0' || r > '9' }); i >= 0 {
		digits = digits[:i]
	}
	v, err := strconv.Atoi(digits)
	if err != nil {
		return 0
	}
	return v
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	if len([]rune(s)) > 80 {
		s = string([]rune(s)[:80]) + "…"
	}
	return s
}

func orDefault(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

// shortHost names an endpoint in one word for the log.
func shortHost(url string) string {
	rest := url
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		rest = rest[:i]
	}
	if rest == "api.github.com" {
		return "GitHub"
	}
	return rest
}

// openProject opens the repository page in the default browser.
func (a *app) openProject() {
	if err := mygo.Shell.OpenExternal(a.githubPage(projectURL)); err != nil {
		a.toast = "打不开 GitHub：" + err.Error()
	}
}

// openUpdate opens the release page of the newer version, falling back to the
// repository when the check only knew a version number.
func (a *app) openUpdate() {
	url := projectURL + "/releases"
	if a.update != nil && a.update.URL != "" {
		url = a.update.URL
	}
	if err := mygo.Shell.OpenExternal(a.githubPage(url)); err != nil {
		a.toast = "打不开下载页：" + err.Error()
	}
}
