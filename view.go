package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"

	"github.com/qy/easyconnect/internal/model"
	"github.com/qy/easyconnect/internal/vpn"
)

// logIcon is a small document-with-lines glyph for the TUN log button.
// githubIcon is the repository mark shown in the footer.
var githubIcon = ui.MustParseSVG([]byte(`<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 .3a12 12 0 0 0-3.8 23.4c.6.1.8-.3.8-.6v-2c-3.3.7-4-1.6-4-1.6-.6-1.4-1.3-1.7-1.3-1.7-1.1.7 0 0 0 0 1.2-.1 1.8 1.2 1.8 1.2 1.1 1.8 2.8 1.3 3.5 1 .1-.8.4-1.3.8-1.6-2.7-.3-5.5-1.3-5.5-5.9 0-1.3.5-2.4 1.2-3.2-.1-.3-.5-1.5.1-3.2 0 0 1-.3 3.3 1.2a11.5 11.5 0 0 1 6 0C17.3 4.7 18.3 5 18.3 5c.6 1.7.2 2.9.1 3.2.8.8 1.2 1.9 1.2 3.2 0 4.6-2.8 5.6-5.5 5.9.4.4.8 1.1.8 2.2v3.3c0 .3.2.7.8.6A12 12 0 0 0 12 .3"/></svg>`))

// copyIcon is two overlapping sheets, for "copy this address".
var copyIcon = ui.MustParseSVG([]byte(`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>`))

// refreshIcon is the two-arrow refresh glyph used by aTrust's own console, for
// "check this session again".
var refreshIcon = ui.MustParseSVG([]byte(`<svg viewBox="0 0 1024 1024" fill="currentColor"><path d="M168 504.2c1-43.7 10-86.1 26.9-126 17.3-41 42.1-77.7 73.7-109.4S337 212.3 378 195c42.4-17.9 87.4-27 133.9-27s91.5 9.1 133.8 27c40.9 17.3 77.7 42.1 109.3 73.8 9.9 9.9 19.2 20.4 27.8 31.4l-60.2 47c-5.3 4.1-3.5 12.5 3 14.1l175.7 43c5 1.2 9.9-2.6 9.9-7.7l0.8-180.9c0-6.7-7.7-10.5-12.9-6.3l-56.4 44.1C765.8 155.1 646.2 92 511.8 92 282.7 92 96.3 275.6 92 503.8c-0.1 4.5 3.5 8.2 8 8.2h60c4.4 0 7.9-3.5 8-7.8z m756 7.8h-60c-4.4 0-7.9 3.5-8 7.8-1 43.7-10 86.1-26.9 126-17.3 41-42.1 77.8-73.7 109.4S687 811.7 646 829c-42.4 17.9-87.4 27-133.9 27s-91.5-9.1-133.9-27c-40.9-17.3-77.7-42.1-109.3-73.8-9.9-9.9-19.2-20.4-27.8-31.4l60.2-47c5.3-4.1 3.5-12.5-3-14.1l-175.7-43c-5-1.2-9.9 2.6-9.9 7.7l-0.7 181c0 6.7 7.7 10.5 12.9 6.3l56.4-44.1C258.2 868.9 377.8 932 512.2 932c229.2 0 415.5-183.7 419.8-411.8 0.1-4.5-3.5-8.2-8-8.2z"/></svg>`))

// iconButton draws a small clickable glyph, the same shape as the TUN log
// button, so one-row actions do not take a full button's width.
func iconButton(c *ui.Context, icon *ui.SVG, tooltip string, onClick func()) {
	ui.Row(c).Padding(4).Radius(8).AlignItems(ui.Center).
		OnClick(onClick).Tooltip(tooltip).Children(func() {
		ui.Icon(c, icon).Size(15, 15)
	})
}

var logIcon = ui.MustParseSVG([]byte(`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><path d="M14 3v6h6"/><path d="M8 13h8"/><path d="M8 17h8"/></svg>`))

// view builds one frame of the window: the header, the aggregate proxy,
// the access points and their log.
func (a *app) view(c *ui.Context) {
	t := c.Theme()
	if a.toast != "" {
		c.Toast(a.toast)
		a.toast = ""
	}
	root := ui.Column(c).Fill().Padding(22).Gap(14).Background(t.Background)
	root.OnShortcut(ui.Cmd, ui.KeyN, a.openNewEditor)
	root.OnShortcut(ui.Cmd, ui.KeyR, func() { a.mgr.ConnectAll(false) })
	root.Children(func() {
		a.header(c)
		a.tabBar(c)
		switch a.tab {
		case 1:
			a.appsSection(c)
		case 2:
			a.accessSection(c)
		default:
			a.aggregateCard(c)
			a.pointsSection(c)
		}
		if a.logsOpen {
			a.logPanel(c)
		}
		a.footer(c)
	})
	a.editorView(c)
	a.settingsView(c)
	a.deleteView(c)
	a.logoutView(c)
	a.quitView(c)
	a.appDetailView(c)
}

// qrCard was removed: WeCom's QR login now uses a WebView popup.

func (a *app) tabBar(c *ui.Context) {
	ui.Tabs(c, &a.tab, "接入点", appTabLabel(a.appCount()), accessTabLabel())
}

func accessTabLabel() string {
	return "访问日志"
}

func appTabLabel(n int) string {
	if n > 0 {
		return fmt.Sprintf("应用 %d", n)
	}
	return "应用"
}

// appEntry is one application of one online access point.
type appEntry struct {
	PointID   string
	PointName string
	App       vpn.App
}

// allApps returns the applications of every online access point, in the
// access points' order.
func (a *app) allApps() []appEntry {
	var out []appEntry
	for _, v := range a.mgr.Views() {
		if v.State != vpn.StateOnline {
			continue
		}
		for _, app := range v.Apps {
			out = append(out, appEntry{PointID: v.ID, PointName: v.Name, App: app})
		}
	}
	return out
}

func (a *app) appCount() int {
	n := 0
	for _, v := range a.mgr.Views() {
		if v.State == vpn.StateOnline {
			n += len(v.Apps)
		}
	}
	return n
}

func (a *app) appsSection(c *ui.Context) {
	t := c.Theme()
	all := a.allApps()
	query := strings.ToLower(strings.TrimSpace(a.appQuery))
	shown := make([]appEntry, 0, len(all))
	for _, entry := range all {
		if query != "" && !appMatches(entry, query) {
			continue
		}
		switch a.appFilter {
		case "on":
			if !a.appEnabled(entry.PointID, entry.App.ID) {
				continue
			}
		case "off":
			if a.appEnabled(entry.PointID, entry.App.ID) {
				continue
			}
		}
		shown = append(shown, entry)
	}

	ui.Row(c).AlignItems(ui.Center).Gap(10).Children(func() {
		ui.Text(c, "应用中心").FontSize(14).Bold()
		ui.Text(c, fmt.Sprintf("%d 个", len(all))).FontSize(12).TextColor(t.TextMuted)
		ui.Row(c).Grow(1)
		// 只看已启用 / 未启用的应用，排查时不用在 158 个里翻。
		ui.Select(c, &a.appFilterLabel, []string{"所有", "已启用", "未启用"}).
			Label("过滤应用").Width(120)
		a.appFilter = appFilterValue(a.appFilterLabel)
		ui.SearchField(c, &a.appQuery).Placeholder("搜索应用名称、地址或标签").
			Label("搜索应用").Width(240)
	})

	scroll := ui.Scroll(c).Grow(1).MinHeight(0)
	scroll.Children(func() {
		ui.Column(c).Gap(14).Children(func() {
			if len(all) == 0 {
				a.appsEmpty(c)
				return
			}
			if len(shown) == 0 {
				ui.Column(c).Padding(40).Center().Children(func() {
					ui.Text(c, "没有匹配「"+a.appQuery+"」的应用").
						FontSize(13).TextColor(t.TextMuted)
				})
				return
			}
			// Group by access point, in the order the points appear.
			var order []string
			groups := map[string][]appEntry{}
			names := map[string]string{}
			for _, entry := range shown {
				if _, ok := groups[entry.PointID]; !ok {
					order = append(order, entry.PointID)
				}
				groups[entry.PointID] = append(groups[entry.PointID], entry)
				names[entry.PointID] = entry.PointName
			}
			if a.appCollapsed == nil {
				a.appCollapsed = map[string]bool{}
			}
			for _, pid := range order {
				entries := groups[pid]
				collapsed := a.appCollapsed[pid]
				ui.Column(c).Gap(8).Children(func() {
					// Clickable header to expand/collapse this point's group.
					header := ui.Row(c).Gap(8).AlignItems(ui.Center).Justify(ui.SpaceBetween).Padding(6, 8).
						Radius(8).Background(t.Surface).Border(1, t.Border)
					header.OnClick(func() {
						a.appCollapsed[pid] = !collapsed
						a.invalidate()
					})
					// 左边的名字与数量贴在一起，右边单独一组按钮。
					header.Children(func() {
						ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
							arrow := "▸"
							if !collapsed {
								arrow = "▾"
							}
							ui.Text(c, arrow).FontSize(12).TextColor(t.TextMuted)
							ui.Text(c, names[pid]).FontSize(13).Bold()
							ui.Text(c, fmt.Sprintf("%d 个应用", len(entries))).
								FontSize(11).TextColor(t.TextMuted)
						})
						// 该接入点的全部应用一次启停，靠右放，不必展开。
						ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
							if ui.Button(c, "启用所有").Label("启用所有 " + names[pid]).Clicked() {
								a.setAllAppsEnabled(pid, true)
							}
							if ui.Button(c, "停用所有").Label("停用所有 " + names[pid]).Clicked() {
								a.setAllAppsEnabled(pid, false)
							}
						})
					})
					if !collapsed {
						for _, entry := range entries {
							a.appCard(c, entry)
						}
					}
				})
			}
		})
	})
}

func (a *app) appsEmpty(c *ui.Context) {
	t := c.Theme()
	online, _, _ := a.mgr.Counts()
	card := ui.Column(c).Padding(40).Gap(10).Center().Radius(12).
		Border(1, t.Border).Background(t.Surface)
	card.Children(func() {
		if online == 0 {
			ui.Text(c, "还没有登录的接入点").FontSize(16).Bold()
			ui.Text(c, "登录后，服务器下发的应用会显示在这里；"+
				"隧道应用沿用登录后的分流规则。").FontSize(12).TextColor(t.TextMuted)
			if ui.PrimaryButton(c, "去登录接入点").Clicked() {
				a.tab = 0
			}
			return
		}
		ui.Text(c, "已登录，服务器没有下发应用").FontSize(16).Bold()
		ui.Text(c, "有些 aTrust 服务器不返回应用列表；代理仍然可以按节点组使用。").
			FontSize(12).TextColor(t.TextMuted)
	})
}

func (a *app) appCard(c *ui.Context, entry appEntry) {
	t := c.Theme()
	app := entry.App
	card := ui.Column(c).Padding(12).Gap(8).Radius(12).
		Border(1, t.Border).Background(t.Surface)
	card.Children(func() {
		ui.Row(c).Gap(12).AlignItems(ui.Center).Children(func() {
			a.appIcon(c, app.Name)
			ui.Column(c).Gap(3).Grow(1).MinWidth(0).Children(func() {
				ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
					ui.Text(c, app.Name).FontSize(14).Bold()
					if app.GroupName != "" {
						ui.Text(c, app.GroupName).FontSize(10).TextColor(t.TextMuted)
					}
				})
				if app.Description != "" {
					ui.Text(c, app.Description).FontSize(11).TextColor(t.TextMuted).
						Ellipsis("…")
				}
				ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
					ui.Text(c, app.TypeLabel()).FontSize(10).TextColor(t.Accent)
					if !a.appEnabled(entry.PointID, app.ID) {
						ui.Text(c, "已停用代理").FontSize(10).TextColor(t.Danger)
					}
					ui.Text(c, app.AddressSummary()).Font("monospace").
						FontSize(10).TextColor(t.Text).Grow(1).Ellipsis("…")
				})
			})
			// One switch per application: turning it off keeps that app's
			// addresses out of the tunnel, which is the only way to settle an
			// IP range clash with the local network or another point.
			ui.Row(c).Gap(6).AlignItems(ui.Center).Children(func() {
				ui.Text(c, "隧道代理").FontSize(11).TextColor(t.TextMuted)
				// 开关必须绑定到堆上的稳定变量：绑局部变量时点击写回的是
				// 已经失效的地址，状态既不会保存也不会还原。
				key := entry.PointID + "/" + app.ID
				on := a.appEnabled(entry.PointID, app.ID)
				sw, ok := a.appSwitch[key]
				if !ok {
					v := on
					sw = &v
					if a.appSwitch == nil {
						a.appSwitch = map[string]*bool{}
					}
					a.appSwitch[key] = sw
				}
				ui.Switch(c, sw).Label("隧道代理 " + app.Name).OnChange(func() {
					a.setAppEnabled(entry.PointID, app.ID, *sw)
				})
			})
			if ui.Button(c, "详情").Label("应用详情 " + app.Name).Clicked() {
				a.openAppDetail(entry)
			}
		})
	})
}

func (a *app) appIcon(c *ui.Context, name string) {
	ui.Row(c).Size(40, 40).Radius(10).Background(appColor(name)).
		AlignItems(ui.Center).Justify(ui.Center).Children(func() {
		ui.Text(c, firstRune(name)).FontSize(18).Bold().
			TextColor(ui.RGBA(255, 255, 255, 1))
	})
}

func (a *app) openAppDetail(entry appEntry) {
	a.detailApp = entry.App
	a.detailPoint = entry.PointName
	a.detailPointID = entry.PointID
	a.appTestFor = ""
	a.appTestMsg = ""
	a.appTesting = false
	a.detailOpen = true
}

func (a *app) appDetailView(c *ui.Context) {
	if !a.detailOpen {
		return
	}
	t := c.Theme()
	app := a.detailApp
	ui.Modal(c, &a.detailOpen, func() {
		ui.Column(c).Width(560).Gap(10).Children(func() {
			ui.Row(c).Gap(12).AlignItems(ui.Center).Children(func() {
				a.appIcon(c, app.Name)
				ui.Column(c).Gap(2).Grow(1).Children(func() {
					ui.Text(c, app.Name).FontSize(18).Bold()
					ui.Text(c, a.detailPoint).FontSize(11).TextColor(t.TextMuted)
				})
			})
			ui.Divider(c)
			ui.Field(c, "应用名称", func() { ui.Text(c, app.Name).FontSize(13) })
			ui.Field(c, "描述", func() {
				desc := app.Description
				if desc == "" {
					desc = "—"
				}
				ui.Text(c, desc).FontSize(13)
			})
			ui.Field(c, "应用类型", func() { ui.Text(c, app.TypeLabel()).FontSize(13) })
			if app.GroupName != "" {
				ui.Field(c, "分类", func() { ui.Text(c, app.GroupName).FontSize(13) })
			}
			if app.NodeGroupName != "" || app.NodeGroupID != "" {
				node := app.NodeGroupName
				if node == "" {
					node = app.NodeGroupID
				}
				ui.Field(c, "节点组", func() { ui.Text(c, node).FontSize(13) })
			}
			if len(app.Addresses) > 0 || app.AppAddress != "" || app.AccessAddress != "" {
				ui.Field(c, "服务器地址", func() {
					ui.Scroll(c).MaxHeight(92).Children(func() {
						ui.Column(c).Gap(4).Children(func() {
							for _, line := range app.AddressLines() {
								ui.Text(c, line).Font("monospace").FontSize(12)
							}
						})
					})
					if ui.Button(c, "复制全部地址").Clicked() {
						a.copyText(strings.Join(app.AddressLines(), "\n"))
					}
				})
			}
			if app.Host() != "" {
				ui.Field(c, "访问方式", func() {
					ui.Column(c).Gap(6).Children(func() {
						proxy := a.proxyFor(a.detailPointID)
						if proxy != "" {
							ui.Text(c, "这是隧道应用，需要用本应用的代理访问（SOCKS5 或 HTTP）："+proxy).
								FontSize(12)
							ui.Text(c, "浏览器里代理协议建议选 HTTP（其次 SOCKS5），地址端口用上面这个，再打开该地址。").
								FontSize(11).TextColor(t.TextMuted)
							ui.Row(c).Gap(8).Children(func() {
								if ui.Button(c, "复制代理").Clicked() {
									a.copyText(proxy)
								}
								if ui.Button(c, "测试全部地址").Disabled(a.appTesting).Clicked() {
									a.testAppConnectivity(app)
								}
								if ui.Button(c, "用代理浏览器打开").Clicked() {
									if err := openProxyBrowser(proxy, appOpenURL(app)); err != nil {
										a.copyText(proxyBrowserCommand(proxy, appOpenURL(app)))
										a.toast = "没能直接启动浏览器，已复制命令：" + err.Error()
									}
								}
							})
							if a.appTestMsg != "" {
								ui.Scroll(c).MaxHeight(66).Children(func() {
									ui.Column(c).Gap(1).Children(func() {
										for _, line := range strings.Split(a.appTestMsg, "\n") {
											if line == "" {
												continue
											}
											col := t.TextMuted
											if strings.HasPrefix(line, "✅") {
												col = t.Success
											} else if strings.HasPrefix(line, "❌") {
												col = t.Danger
											}
											ui.Text(c, line).FontSize(11).TextColor(col)
										}
									})
								})
							}
						} else {
							ui.Text(c, "接入点在线后，用本应用的 SOCKS5 代理访问。").
								FontSize(11).TextColor(t.TextMuted)
						}
					})
				})
			}
			if app.AccessEntry != "" {
				ui.Field(c, "浏览器打开地址", func() {
					ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
						ui.Text(c, app.AccessEntry).FontSize(11).Grow(1).Ellipsis("…")
						if ui.Button(c, "打开").Clicked() {
							if err := mygo.Shell.OpenExternal(app.AccessEntry); err != nil {
								a.toast = "打不开地址：" + err.Error()
							}
						}
					})
				})
			}
			ui.Row(c).Gap(8).Justify(ui.End).Children(func() {
				if ui.PrimaryButton(c, "关闭").Clicked() {
					a.detailOpen = false
				}
			})
		})
	})
}

func (a *app) proxyFor(pointID string) string {
	if agg := a.mgr.Aggregate(); agg.Running && agg.Addr != "" {
		return displayAddr(agg.Addr)
	}
	if p := a.cfg.Find(pointID); p != nil && p.SocksPort > 0 {
		return fmt.Sprintf("127.0.0.1:%d", p.SocksPort)
	}
	return ""
}

// testAppConnectivity dials the app's backend through the tunnel and reports
// whether it is reachable, which separates a tunnel problem from a browser
// proxy that is not set.
func (a *app) testAppConnectivity(app vpn.App) {
	id := a.detailPointID
	ips := app.ProbeHosts()
	ports := app.TestPorts()
	if len(ips) == 0 || len(ports) == 0 {
		a.appTestMsg = "该应用没有可直接测试的地址"
		return
	}
	// Bound the work for large ranges.
	if len(ips) > 64 {
		ips = ips[:64]
	}
	if len(ips) > 24 && len(ports) > 5 {
		ports = ports[:5]
	}
	type hostJob struct {
		host  string
		ports []int
	}
	jobs := make([]hostJob, 0, len(ips))
	for _, ip := range ips {
		jobs = append(jobs, hostJob{host: ip, ports: ports})
	}
	a.appTesting = true
	a.appTestFor = id
	a.appTestMsg = fmt.Sprintf("正在测试 %d 个 IP…", len(jobs))
	a.invalidate()
	go func() {
		lines := make([]string, len(jobs))
		var wg sync.WaitGroup
		for i, j := range jobs {
			wg.Add(1)
			go func(i int, j hostJob) {
				defer wg.Done()
				lines[i] = a.probeHostText(id, j.host, j.ports)
			}(i, j)
		}
		wg.Wait()
		// 一个应用可能有多个地址：先给结论，再列明细，避免一条不通
		// 让人以为整个应用不可用。
		ok, total := 0, len(lines)
		for _, line := range lines {
			if strings.HasPrefix(line, "✅") {
				ok++
			}
		}
		summary := fmt.Sprintf("该应用可用：%d/%d 个地址可达", ok, total)
		if ok == 0 {
			summary = fmt.Sprintf("该应用当前不可用：%d 个地址都不可达", total)
		}
		body := summary + "\n" + strings.Join(lines, "\n")
		a.win.Update(func() {
			a.appTesting = false
			a.appTestMsg = body
		})
	}()
}

// probeHostText dials one host on its candidate ports (concurrently) through
// the tunnel and returns a one-line result.
func (a *app) probeHostText(id, host string, ports []int) string {
	if len(ports) == 0 {
		ports = []int{443, 80}
	}
	// 全局 TUN 接管时，本地的拨号在 TUN 栈里就完成了握手，测出来永远是
	// 「可达 2ms」。这时让 helper 用真实隧道连一次。
	if a.tunOn && hostInTun(a.tunPoints, id) {
		if point := a.cfg.Find(id); point != nil {
			for _, p := range ports {
				addr := net.JoinHostPort(host, strconv.Itoa(p))
				ok, ms, errText, answered := a.probeTunnel(point.Name, addr, 6*time.Second)
				if !answered {
					return fmt.Sprintf("⚠️ %s 无法通过隧道确认（helper 没有回应）", addr)
				}
				if ok {
					return fmt.Sprintf("✅ %s 可达（%d ms，经隧道）", addr, ms)
				}
				if errText != "" {
					return fmt.Sprintf("❌ %s 不可达（%s）", addr, errText)
				}
			}
		}
	}
	type result struct {
		port int
		d    time.Duration
		err  error
	}
	ch := make(chan result, len(ports))
	for _, p := range ports {
		go func(p int) {
			addr := net.JoinHostPort(host, strconv.Itoa(p))
			// The tunnel dialer may not honor its context when the backend
			// never answers (a silent SYN drop), so enforce the timeout here
			// too: a probe must always return, never leave the UI "测试中".
			type dialOut struct {
				d   time.Duration
				err error
			}
			out := make(chan dialOut, 1)
			go func() {
				d, err := a.mgr.TestDialTimeout(id, "tcp", addr, 2500*time.Millisecond)
				out <- dialOut{d: d, err: err}
			}()
			select {
			case o := <-out:
				ch <- result{port: p, d: o.d, err: o.err}
			case <-time.After(3 * time.Second):
				ch <- result{port: p, err: errors.New("连接超时")}
			}
		}(p)
	}
	var lastErr error
	for i := 0; i < len(ports); i++ {
		r := <-ch
		if r.err == nil {
			return fmt.Sprintf("✅ %s:%d 可达（%d ms）", host, r.port, r.d.Milliseconds())
		}
		lastErr = r.err
	}
	if len(ports) == 1 {
		return fmt.Sprintf("❌ %s:%d 不可达（%s）", host, ports[0], shortErr(lastErr))
	}
	return fmt.Sprintf("❌ %s 不可达（%s）", host, shortErr(lastErr))
}

func shortErr(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if len(s) > 60 {
		s = s[:60] + "…"
	}
	return s
}

func appMatches(entry appEntry, query string) bool {
	app := entry.App
	fields := []string{app.Name, app.Description, app.GroupName, app.NodeGroupName,
		entry.PointName, app.TypeLabel(), app.AppAddress, app.AccessAddress, app.AccessEntry}
	fields = append(fields, app.AddressLines()...)
	for _, field := range fields {
		if strings.Contains(strings.ToLower(field), query) {
			return true
		}
	}
	return false
}

func firstRune(s string) string {
	for _, r := range s {
		return string(r)
	}
	return "应"
}

func appColor(name string) ui.Color {
	palette := []ui.Color{
		ui.RGBA(0x4F, 0x8C, 0xFF, 1),
		ui.RGBA(0x2F, 0xB3, 0x7A, 1),
		ui.RGBA(0xE0, 0x8A, 0x2E, 1),
		ui.RGBA(0x8E, 0x6C, 0xE8, 1),
		ui.RGBA(0x2A, 0xA8, 0xB8, 1),
	}
	if name == "" {
		return palette[0]
	}
	h := 0
	for _, r := range name {
		h = (h*31 + int(r)) & 0x7fffffff
	}
	return palette[h%len(palette)]
}

func (a *app) header(c *ui.Context) {
	t := c.Theme()
	ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(16).Children(func() {
		ui.Row(c).Gap(12).AlignItems(ui.Center).Children(func() {
			if a.icon != nil {
				ui.Image(c, a.icon).Size(42, 42)
			}
			ui.Column(c).Gap(3).Children(func() {
				ui.Text(c, "aTrust Hub").FontSize(24).Bold()
				ui.Text(c, "同时登录多个 aTrust 接入点").
					FontSize(12).TextColor(t.TextMuted)
			})
		})
		ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
			chip := ui.Row(c).Padding(5, 10).Radius(999).Background(t.Surface).
				Border(1, t.Border).AlignItems(ui.Center).Gap(6)
			chip.Children(func() {
				online, _, _ := a.mgr.Counts()
				color := t.TextMuted
				if online > 0 {
					color = t.Success
				}
				ui.Row(c).Size(7, 7).Radius(3.5).Background(color)
				ui.Text(c, a.describeProgress()).FontSize(12).TextColor(t.TextMuted)
			})
			// Global TUN switch: always shown; toggling starts or stops TUN
			// with the first online point. The position is remembered.
			{
				shown := a.tunOn || a.tunPending
				// Bind the switch to a persistent field: the framework writes
				// the clicked value into the *bool after this frame builds, so
				// a stack copy would lose it. Compare against `shown` next
				// frame to detect the toggle.
				a.tunSwitch = shown
				ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
					ui.Text(c, "全局 TUN").FontSize(13)
					ui.Switch(c, &a.tunSwitch).Disabled(a.tunPending)
					if a.tunPending {
						ui.Text(c, "处理中…").FontSize(12).TextColor(t.TextMuted)
					}
				})
				if a.tunSwitch != shown {
					// 用户亲手拨动开关：把自动恢复的失败计数清掉，
					// 让下一次登录仍按这次的选择还原。
					a.tunResumeFails = 0
					a.tunResumeAt = time.Time{}
					a.tunPending = true
					a.tunLogf("TUN开关点击: on=%v shown=%v", a.tunSwitch, shown)
					if a.tunSwitch {
						if pid := a.firstOnlinePoint(); pid != "" {
							go a.startTUNSerialized(pid)
						} else {
							a.tunPending = false
							a.toast = "没有在线接入点，先登录再开 TUN"
						}
					} else {
						go a.stopTUNSerialized()
					}
					a.invalidate()
				}
			}
			ui.Row(c).Padding(6).Radius(8).AlignItems(ui.Center).
				OnClick(a.openTUNLog).Tooltip("TUN 日志").Children(func() {
				ui.Icon(c, logIcon).Size(16, 16)
			})
			// Always shown, like the TUN switch: hidden controls make the app
			// look broken. It is only disabled while the aggregate is down.
			if supportsSystemProxy() {
				agg := a.mgr.Aggregate()
				a.sysProxySwitch = a.sysProxyOn
				ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
					ui.Text(c, "系统代理").FontSize(13).TextColor(t.Text)
					ui.Switch(c, &a.sysProxySwitch).Disabled(!agg.Running)
				})
				if a.sysProxySwitch != a.sysProxyOn {
					a.toggleSystemProxy()
				}
			}
			if ui.Button(c, "设置").Clicked() {
				a.openSettings()
			}
			if ui.PrimaryButton(c, "＋ 添加接入点").Clicked() {
				a.openNewEditor()
			}
		})
	})
}

func (a *app) aggregateCard(c *ui.Context) {
	t := c.Theme()
	card := ui.Column(c).Padding(14).Gap(10).Radius(12).
		Border(1, t.Border).Background(t.Surface)
	card.Children(func() {
		ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
			ui.Text(c, "统一入口").FontSize(14).Bold()
			agg := a.mgr.Aggregate()
			dot := t.TextMuted
			if agg.Running {
				dot = t.Success
			}
			ui.Row(c).Size(8, 8).Radius(4).Background(dot)
			if agg.Running {
				addr := "socks5://" + displayAddr(agg.Addr)
				ui.Row(c).Gap(5).AlignItems(ui.Center).Children(func() {
					ui.Text(c, addr).Font("monospace").FontSize(13).TextColor(t.Text)
					ui.Row(c).Padding(3).Radius(6).AlignItems(ui.Center).
						OnClick(func() { a.copyText(addr) }).
						Tooltip("复制统一入口地址").Children(func() {
						ui.Icon(c, copyIcon).Size(13, 13)
					})
				})
			} else if agg.Error != "" {
				ui.Text(c, "未监听："+agg.Error).FontSize(12).TextColor(t.Danger)
			} else {
				ui.Text(c, "未开启").FontSize(12).TextColor(t.TextMuted)
			}
			ui.Row(c).Grow(1)
			ui.Text(c, "分流").FontSize(12).TextColor(t.TextMuted)
			mode := a.cfg.Settings.Routing.Label()
			sel := ui.Select(c, &mode, routingLabelStrings()).Width(130)
			if sel.Changed() {
				a.setRouting(routingFromLabel(mode))
			}
			ui.Text(c, "端口 "+strconv.Itoa(a.cfg.Settings.AggregatePort)).
				FontSize(12).TextColor(t.TextMuted)
		})
		ui.Text(c, "客户端连接这个 SOCKS5 地址，按上面的模式在在线接入点之间分配；"+
			"某个接入点拨号失败时会自动换下一个。").FontSize(12).TextColor(t.TextMuted)
	})
}

func (a *app) pointsSection(c *ui.Context) {
	t := c.Theme()
	views := a.mgr.Views()
	ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
		ui.Text(c, "接入点").FontSize(14).Bold()
		ui.Text(c, fmt.Sprintf("%d 个", len(views))).FontSize(12).TextColor(t.TextMuted)
		ui.Row(c).Grow(1)
		if len(views) > 0 {
			ui.Text(c, "每个接入点可单独开一个 SOCKS5 端口，也可只加入统一入口").
				FontSize(11).TextColor(t.TextMuted)
		}
	})
	scroll := ui.Scroll(c).Grow(1).MinHeight(0)
	scroll.Children(func() {
		ui.Column(c).Gap(10).Children(func() {
			if len(views) == 0 {
				a.emptyState(c)
				return
			}
			for _, v := range views {
				a.pointCard(c, v)
			}
		})
	})
}

func (a *app) emptyState(c *ui.Context) {
	t := c.Theme()
	ui.Column(c).Padding(40).Gap(10).Center().Radius(12).
		Border(1, t.Border).Background(t.Surface).Children(func() {
		ui.Text(c, "还没有接入点").FontSize(16).Bold()
		ui.Text(c, "添加 aTrust 服务器地址、用户名和密码。应用会为每个接入点"+
			"单独登录，并保留各自的设备 ID 和会话。").FontSize(12).
			TextColor(t.TextMuted).MaxWidth(460)
		ui.Text(c, "多个接入点可以填同一账号的不同网关，也可以填不同账号。").
			FontSize(12).TextColor(t.TextMuted)
		if ui.PrimaryButton(c, "添加第一个接入点").Clicked() {
			a.openNewEditor()
		}
	})
}

func (a *app) pointCard(c *ui.Context, v vpn.View) {
	t := c.Theme()
	card := ui.Column(c).Key("point:"+v.ID).Padding(14).Gap(8).Radius(12).
		Border(1, t.Border).Background(t.Surface)
	card.Children(func() {
		ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
			ui.Row(c).Size(10, 10).Radius(5).Background(stateColor(t, v.State))
			ui.Column(c).Gap(2).Grow(1).MinWidth(0).Children(func() {
				ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
					ui.Text(c, v.Name).FontSize(15).Bold()
					ui.Text(c, addrOf(v)).Font("monospace").FontSize(11).
						TextColor(t.TextMuted)
				})
				ui.Text(c, subtitleOf(v)).FontSize(12).TextColor(t.TextMuted)
			})
			a.stateBadge(c, v.State)
			a.pointButtons(c, v)
		})

		ui.Row(c).Gap(16).Children(func() {
			if v.ClientIP != "" {
				meta(c, t, "隧道 IP", v.ClientIP)
			}
			if v.SocksPort > 0 {
				addr := "127.0.0.1:" + strconv.Itoa(v.SocksPort)
				socks := "socks5://" + addr
				metaCopy(c, t, "独立 SOCKS5", addr, "复制独立 SOCKS5 地址",
					func() { a.copyText(socks) })
			}
			meta(c, t, "连接", fmt.Sprintf("%d 当前 / %d 累计", v.Active, v.Total))
			if len(v.Apps) > 0 {
				meta(c, t, "应用", fmt.Sprintf("%d 个", len(v.Apps)))
			}
			if v.Latency >= time.Millisecond {
				meta(c, t, "拨号延迟", v.Latency.Round(time.Millisecond).String())
			} else if v.LoginDuration >= time.Millisecond {
				meta(c, t, "登录耗时", v.LoginDuration.Round(time.Millisecond).String())
			}
			if v.Failed > 0 {
				meta(c, t, "失败", fmt.Sprintf("%d 次", v.Failed))
			}
			if v.InPool {
				meta(c, t, "统一入口", "参与分流")
			}
		})

		if v.State == vpn.StateError && v.Error != "" {
			ui.Text(c, v.Error).FontSize(12).TextColor(t.Danger)
		}
		summary := vpn.NodeSummary(v)
		showMonitor := v.State == vpn.StateOnline && v.MonitorOn
		// The node summary and the session monitor share one row: the summary
		// on the left, the monitor state and its refresh button on the right.
		if (len(summary) > 0 && v.State == vpn.StateOnline) || showMonitor {
			ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
				if len(summary) > 0 && v.State == vpn.StateOnline {
					ui.Text(c, "节点组 "+strings.Join(summary, " · ")).
						FontSize(11).TextColor(t.TextMuted).Grow(1).Ellipsis("…")
				} else {
					ui.Row(c).Grow(1)
				}
				if showMonitor {
					a.sessionMonitor(c, v)
				}
			})
		}
	})
}

// sessionMonitor draws the validity state and the manual check button.
func (a *app) sessionMonitor(c *ui.Context, v vpn.View) {
	t := c.Theme()
	colour := t.TextMuted
	switch v.Alive {
	case "有效":
		colour = t.Success
	case "已失效":
		colour = t.Danger
	case "无法确认":
		colour = t.Warning
	}
	state := v.Alive
	if state == "" {
		state = "待检测"
	}
	ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
		ui.Text(c, "会话监测："+state).FontSize(11).TextColor(colour)
		if v.AliveErr != "" && v.Alive != "有效" {
			ui.Text(c, v.AliveErr).FontSize(11).TextColor(t.TextMuted).Ellipsis("…")
		}
		iconButton(c, refreshIcon, "立即检测会话是否仍有效", func() {
			if !a.mgr.CheckNow(v.ID) {
				a.toast = "只有在线的接入点可以检测"
			} else {
				a.toast = "已发起会话有效性检测"
			}
		})
	})
}

func (a *app) pointButtons(c *ui.Context, v vpn.View) {
	switch v.State {
	case vpn.StateOnline:
		if ui.Button(c, "断开").Label("断开 " + v.Name).Clicked() {
			go a.mgr.Disconnect(v.ID)
		}
		// Only the WeCom login keeps a session worth discarding by hand: it is
		// the one where "退出登录" means "sign in as someone else next time".
		if p := a.cfg.Find(v.ID); canLogout(p) {
			if ui.Button(c, "退出登录").Label("退出登录 " + v.Name).Clicked() {
				a.askLogout(v)
			}
		}
	case vpn.StateConnecting:
		if ui.Button(c, "取消").Label("取消 " + v.Name).Clicked() {
			go a.mgr.Disconnect(v.ID)
		}
	default:
		// One button, and the configured auth mode decides what it does:
		// password logs in by itself, WeCom opens the QR popup, single
		// sign-on needs the browser.
		if ui.PrimaryButton(c, "登录").Label("登录 " + v.Name).Clicked() {
			a.tunLogf("登录点击：%s（%s）", v.Name, v.ID)
			a.mgr.Connect(v.ID)
		}
	}
	if ui.Button(c, "编辑").Label("编辑 " + v.Name).Clicked() {
		a.openEditor(v)
	}
}

func (a *app) logPanel(c *ui.Context) {
	t := c.Theme()
	entries := a.bus.Tail(200)
	ui.Column(c).Gap(6).Children(func() {
		ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
			ui.Text(c, "运行日志").FontSize(13).Bold()
			ui.Text(c, fmt.Sprintf("最近 %d 条", len(entries))).FontSize(11).
				TextColor(t.TextMuted)
			ui.Row(c).Grow(1)
			if ui.Button(c, "复制全部").Clicked() {
				var b strings.Builder
				for _, e := range entries {
					fmt.Fprintf(&b, "%s [%s] %s\n", e.At.Format("15:04:05"), e.Source, e.Line)
				}
				a.copyText(b.String())
			}
			if ui.Button(c, "清空").Clicked() {
				a.bus.Clear()
			}
		})
		box := ui.Scroll(c).Height(170).Radius(8).Border(1, t.Border).
			Background(t.Background).Padding(8)
		box.Children(func() {
			ui.Column(c).Gap(2).Children(func() {
				if len(entries) == 0 {
					ui.Text(c, "还没有日志。登录、断开和连接失败都会记在这里。").
						FontSize(11).TextColor(t.TextMuted)
					return
				}
				for _, e := range entries {
					ui.Row(c).Gap(8).AlignItems(ui.Start).Children(func() {
						ui.Text(c, e.At.Format("15:04:05")).Font("monospace").
							FontSize(10).TextColor(t.TextMuted)
						ui.Text(c, "["+e.Source+"]").Font("monospace").FontSize(10).
							TextColor(t.Accent)
						ui.Text(c, e.Line).Font("monospace").FontSize(10).
							TextColor(t.Text).Grow(1).Wrap()
					})
				}
			})
		})
	})
}

// accessSection shows the access log tab: each proxied target with the
// access point and application it went through.
func (a *app) accessSection(c *ui.Context) {
	t := c.Theme()
	var entries []vpn.LogEntry
	for _, e := range a.bus.Tail(600) {
		if e.Source == vpn.AccessOK || e.Source == vpn.AccessFail {
			entries = append(entries, e)
		}
	}
	ui.Row(c).AlignItems(ui.Center).Gap(10).Children(func() {
		ui.Text(c, "访问日志").FontSize(14).Bold()
		ui.Text(c, fmt.Sprintf("%d 条", len(entries))).FontSize(12).TextColor(t.TextMuted)
		ui.Row(c).Grow(1)
		if ui.Button(c, "复制全部").Clicked() {
			var b strings.Builder
			for _, e := range entries {
				mark := "✔"
				if e.Source == vpn.AccessFail {
					mark = "✘"
				}
				fmt.Fprintf(&b, "%s %s %s\n", e.At.Format("15:04:05"), mark, e.Line)
			}
			a.copyText(b.String())
		}
		if ui.Button(c, "清空").Clicked() {
			a.bus.Clear()
		}
	})
	scroll := ui.Scroll(c).Grow(1).MinHeight(0)
	scroll.Children(func() {
		box := ui.Column(c).Padding(10).Radius(10).Border(1, t.Border).
			Background(t.Surface)
		box.Children(func() {
			ui.Column(c).Gap(4).Children(func() {
				if len(entries) == 0 {
					ui.Column(c).Padding(30).Center().Children(func() {
						ui.Text(c, "还没有访问记录").FontSize(13).Bold()
						ui.Text(c, "通过统一入口代理的连接会显示在这里，"+
							"并标注走了哪个接入点、属于哪个应用。").
							FontSize(11).TextColor(t.TextMuted)
					})
					return
				}
				for _, e := range entries {
					ok := e.Source == vpn.AccessOK
					ui.Row(c).Gap(8).AlignItems(ui.Start).Children(func() {
						ui.Text(c, e.At.Format("15:04:05")).Font("monospace").
							FontSize(11).TextColor(t.TextMuted)
						dot := t.Danger
						if ok {
							dot = t.Success
						}
						// Center the dot on the first text line, so it lines up
						// with the text instead of hugging the top edge.
						ui.Row(c).Height(15).AlignItems(ui.Center).Children(func() {
							ui.Row(c).Size(8, 8).Radius(4).Background(dot)
						})
						ui.Text(c, e.Line).Font("monospace").FontSize(11).
							TextColor(t.Text).Grow(1).Wrap()
					})
				}
			})
		})
	})
}

func (a *app) footer(c *ui.Context) {
	t := c.Theme()
	ui.Row(c).AlignItems(ui.Center).Gap(10).Children(func() {
		if ui.Button(c, "退出").FontSize(11).Background(t.Danger).
			TextColor(ui.Hex("#ffffff")).Clicked() {
			a.askQuit()
		}
		ui.Row(c).Grow(1)
		ui.Text(c, "当前版本 "+appBuild).FontSize(10).TextColor(t.TextMuted)
		if a.update != nil {
			ui.Row(c).Padding(3, 8).Radius(8).AlignItems(ui.Center).Gap(5).
				Tooltip("下载 v"+a.update.Version).
				OnClick(func() { a.openUpdate() }).Children(func() {
				ui.Text(c, "新版本 v"+a.update.Version).FontSize(11)
			})
		}
		ui.Row(c).Padding(4).Radius(8).AlignItems(ui.Center).
			Tooltip("项目主页："+projectURL).
			OnClick(func() { a.openProject() }).Children(func() {
			ui.Icon(c, githubIcon).Size(15, 15)
		})
		if ui.Button(c, logLabel(a.logsOpen)).FontSize(11).Clicked() {
			a.logsOpen = !a.logsOpen
		}
		if ui.Button(c, "打开数据目录").FontSize(11).Clicked() {
			if err := mygo.Shell.OpenPath(a.dir); err != nil {
				a.toast = "打不开数据目录：" + err.Error()
			}
		}
	})
}

func logLabel(open bool) string {
	if open {
		return "收起日志"
	}
	return "运行日志"
}

// metaCopy draws "key value" with the copy glyph right next to the value: a
// loose row gap left the icon floating far from what it copies.
func metaCopy(c *ui.Context, t *ui.Theme, key, value, tooltip string, onClick func()) {
	ui.Row(c).Gap(5).AlignItems(ui.Center).Children(func() {
		ui.Text(c, key).FontSize(11).TextColor(t.TextMuted)
		ui.Text(c, value).FontSize(11).Font("monospace").TextColor(t.Text)
		ui.Row(c).Padding(3).Radius(6).AlignItems(ui.Center).
			OnClick(onClick).Tooltip(tooltip).Children(func() {
			ui.Icon(c, copyIcon).Size(13, 13)
		})
	})
}

func meta(c *ui.Context, t *ui.Theme, key, value string) {
	ui.Row(c).Gap(5).AlignItems(ui.Center).Children(func() {
		ui.Text(c, key).FontSize(11).TextColor(t.TextMuted)
		ui.Text(c, value).FontSize(11).Font("monospace").TextColor(t.Text)
	})
}

// stateBadge draws the access point state as a filled badge: green for
// online, grey for not connected, red for failed.
func (a *app) stateBadge(c *ui.Context, state vpn.State) {
	t := c.Theme()
	white := ui.RGBA(255, 255, 255, 1)
	var bg, fg ui.Color
	switch state {
	case vpn.StateOnline:
		bg, fg = t.Success, white
	case vpn.StateError:
		bg, fg = t.Danger, white
	case vpn.StateConnecting:
		bg, fg = t.Warning, white
	default:
		bg, fg = t.Surface, t.TextMuted
	}
	badge := ui.Badge(c, state.Label()).Background(bg).TextColor(fg)
	if state != vpn.StateOnline && state != vpn.StateError && state != vpn.StateConnecting {
		badge = badge.Border(1, t.Border)
	}
}

func stateColor(t *ui.Theme, state vpn.State) ui.Color {
	switch state {
	case vpn.StateOnline:
		return t.Success
	case vpn.StateConnecting:
		return t.Warning
	case vpn.StateError:
		return t.Danger
	default:
		return t.TextMuted
	}
}

func addrOf(v vpn.View) string {
	return model.FormatAccessAddress(v.Server, v.Port)
}

func subtitleOf(v vpn.View) string {
	parts := []string{}
	switch model.AuthMode(v.AuthMode) {
	case model.AuthModeAuto:
		parts = append(parts, "自动识别（旧）")
	case model.AuthModeWeCom:
		parts = append(parts, "企业微信弹窗登录")
	case model.AuthModeSSO:
		parts = append(parts, "单点登录（浏览器）")
	default:
		if v.Username != "" {
			user := v.Username
			if v.LoginDomain != "" {
				user += "@" + v.LoginDomain
			}
			parts = append(parts, user)
		}
	}
	if v.SocksPort > 0 {
		parts = append(parts, "SOCKS5 :"+strconv.Itoa(v.SocksPort))
	} else {
		parts = append(parts, "仅统一入口")
	}
	if v.AutoConnect {
		parts = append(parts, "启动时自动登录")
	}
	return strings.Join(parts, " · ")
}

func displayAddr(addr string) string {
	return strings.Replace(addr, "0.0.0.0", "127.0.0.1", 1)
}

func authModeLabels() []string {
	out := make([]string, 0, len(model.AuthModeLabels))
	for _, entry := range model.AuthModeLabels {
		out = append(out, entry.Label)
	}
	return out
}

func authModeFromLabel(label string) model.AuthMode {
	for _, entry := range model.AuthModeLabels {
		if entry.Label == label {
			return entry.Value
		}
	}
	// The editor no longer offers "自动识别", so an unknown label falls back
	// to the mode that needs the least explanation.
	return model.AuthModePassword
}

func routingLabelStrings() []string {
	out := make([]string, 0, len(model.RoutingLabels))
	for _, entry := range model.RoutingLabels {
		out = append(out, entry.Label)
	}
	return out
}

func routingFromLabel(label string) model.Routing {
	for _, entry := range model.RoutingLabels {
		if entry.Label == label {
			return entry.Value
		}
	}
	return model.RoutingLatency
}

func (a *app) setRouting(r model.Routing) {
	if r == a.cfg.Settings.Routing {
		return
	}
	if _, err := a.store.Update(func(cfg *model.Config) error {
		cfg.Settings.Routing = r
		return nil
	}); err != nil {
		a.toast = err.Error()
		return
	}
	if err := a.saveConfig(); err != nil {
		a.toast = "保存设置失败：" + err.Error()
		return
	}
	a.toast = "分流模式已改为「" + r.Label() + "」"
}

// ---- dialogs ----

func (a *app) editorView(c *ui.Context) {
	if !a.editor.open {
		return
	}
	t := c.Theme()
	d := &a.editor
	ui.Modal(c, &d.open, func() {
		ui.Column(c).Width(600).Gap(10).Children(func() {
			ui.Text(c, editorTitle(d)).FontSize(18).Bold()
			ui.Field(c, "名称", func() {
				ui.TextInput(c, &d.name).Placeholder("例如：主网关 / 教育网线路")
			})
			ui.Row(c).Gap(10).AlignItems(ui.End).Children(func() {
				ui.Field(c, "认证方式", func() {
					ui.Select(c, &d.authModeLabel, authModeLabels()).Width(220)
					d.authMode = string(authModeFromLabel(d.authModeLabel))
				})
				if ui.Button(c, "检测").Disabled(d.detecting).Clicked() {
					a.detectEditor()
				}
			})
			if d.detecting {
				ui.Row(c).Gap(6).AlignItems(ui.Center).Children(func() {
					ui.Spinner(c)
					ui.Text(c, "正在读取服务器支持的认证方式…").FontSize(11).TextColor(t.TextMuted)
				})
			}
			if d.detectErr != "" {
				ui.Text(c, d.detectErr).FontSize(11).TextColor(t.Danger)
			}
			if len(d.detected) > 0 {
				ui.Text(c, "服务器支持："+strings.Join(d.detected, "、")).FontSize(11).
					TextColor(t.TextMuted)
			}
			ui.Field(c, "接入地址", func() {
				ui.TextInput(c, &d.address).
					Placeholder("例如：https://vpn.example.com:443").Grow(1)
			})
			switch d.authMode {
			case string(model.AuthModeWeCom):
				// 企业微信：登录域用来在服务器提供多个外部登录时挑一个。
				ui.Field(c, "登录域（可选）", func() {
					ui.TextInput(c, &d.domain).Placeholder("服务器有多个外部登录方式时用来区分").Width(240)
				})
			case string(model.AuthModeSSO):
				// 单点登录：账号密码在对方页面上完成，这里只说明流程。
				ui.Text(c, "保存后点卡片上的「登录」会打开浏览器完成单点登录，"+
					"登录成功后自动取回会话并连接。").
					FontSize(11).TextColor(t.TextMuted)
			default:
				ui.Field(c, "用户名", func() {
					ui.TextInput(c, &d.username).Placeholder("登录 aTrust 的账号")
				})
				ui.Row(c).Gap(10).AlignItems(ui.End).Children(func() {
					ui.Field(c, "密码", func() {
						in := ui.TextInput(c, &d.cred).Password().Grow(1)
						if d.hasPassword {
							in.Placeholder("已保存，留空则沿用")
						} else {
							in.Placeholder("登录密码")
						}
					})
					ui.Field(c, "登录域", func() {
						ui.TextInput(c, &d.domain).Placeholder("默认 Radius").Width(180)
					})
				})
				ui.Field(c, "TOTP 密钥（可选）", func() {
					ui.TextInput(c, &d.totp).Placeholder("Base32 密钥，留空则不用动态口令")
				})
				if d.hasTOTP {
					ui.Checkbox(c, &d.clearTOTP, "清除已保存的 TOTP 密钥")
				}
			}
			ui.Field(c, "密码存储方式", func() {
				ui.Select(c, &d.secretStore, secretStoreLabels()).Width(220)
			})
			ui.Divider(c)
			ui.Row(c).Gap(14).AlignItems(ui.Start).Children(func() {
				ui.Field(c, "独立 SOCKS5 端口", func() {
					ui.TextInput(c, &d.socksPort).Width(100)
				})
				// The two boxes follow the field's own rhythm: the first lines
				// up with the "独立 SOCKS5 端口" caption, the second with the
				// input under it.
				ui.Column(c).Gap(9).Children(func() {
					ui.Checkbox(c, &d.inPool, "加入统一入口分流")
					ui.Checkbox(c, &d.autoConnect, "应用启动时自动登录")
				})
			})
			ui.Row(c).Gap(14).AlignItems(ui.Center).Children(func() {
				ui.Checkbox(c, &d.monitor, "监测会话是否仍有效")
				if d.monitor {
					// Label and box on one line: the stacked field wrapped the
					// caption onto two lines and looked out of place here.
					ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
						ui.Text(c, "监测间隔（秒）").FontSize(12)
						ui.TextInput(c, &d.monitorEvery).Width(90)
					})
				}
			})
			if d.err != "" {
				ui.Text(c, d.err).FontSize(12).TextColor(t.Danger)
			}
			// Bottom row: delete on the left, cancel/save on the right.
			ui.Row(c).Gap(8).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
				if d.editingID != "" {
					if ui.Button(c, "删除此接入点").Background(t.Danger).
						TextColor(ui.Hex("#ffffff")).
						TextColor(ui.RGBA(255, 255, 255, 1)).Label("删除接入点 " + d.name).Clicked() {
						a.deleting = d.editingID
						d.open = false
					}
				} else {
					ui.Row(c)
				}
				ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
					if ui.Button(c, "取消").Clicked() {
						d.open = false
					}
					if ui.PrimaryButton(c, "保存").Clicked() {
						a.saveEditor()
					}
				})
			})
		})
	})
}

func editorTitle(d *editorDraft) string {
	if d.editingID == "" {
		return "添加接入点"
	}
	return "编辑接入点"
}

func (a *app) settingsView(c *ui.Context) {
	if !a.settings.open {
		return
	}
	t := c.Theme()
	d := &a.settings
	ui.Modal(c, &d.open, func() {
		ui.Column(c).Width(520).Gap(10).Children(func() {
			ui.Text(c, "设置").FontSize(18).Bold()
			ui.Field(c, "监听地址", func() {
				ui.TextInput(c, &d.host).Placeholder("127.0.0.1").Width(180)
			})
			ui.Row(c).Gap(10).AlignItems(ui.End).Children(func() {
				ui.Field(c, "统一入口端口", func() {
					ui.TextInput(c, &d.port).Width(110)
				})
				ui.Field(c, "健康检查间隔（秒）", func() {
					ui.TextInput(c, &d.interval).Width(110)
				})
			})
			ui.Field(c, "分流模式", func() {
				ui.Select(c, &d.routing, routingLabelStrings()).Width(160)
			})
			ui.Column(c).Gap(4).Children(func() {
				ui.Checkbox(c, &d.aggregate, "开启统一入口 SOCKS5")
				ui.Checkbox(c, &d.autoReconnect, "连接断开时自动重连")
				if supportsDockToggle() {
					ui.Checkbox(c, &d.hideDock, "关闭后隐藏 Dock 图标")
				}
			})
			ui.Text(c, "监听 127.0.0.1 只有本机能用；要让局域网里的设备用，"+
				"改成 0.0.0.0，但 SOCKS5 没有认证，请只在自己信任的网络里这样做。").
				FontSize(11).TextColor(t.TextMuted)
			if d.err != "" {
				ui.Text(c, d.err).FontSize(12).TextColor(t.Danger)
			}
			ui.Row(c).Gap(8).Justify(ui.End).Children(func() {
				if ui.Button(c, "取消").Clicked() {
					d.open = false
				}
				if ui.PrimaryButton(c, "保存").Clicked() {
					a.saveSettings()
				}
			})
		})
	})
}

func (a *app) deleteView(c *ui.Context) {
	if a.deleting == "" {
		return
	}
	t := c.Theme()
	var p *model.AccessPoint
	for i := range a.cfg.Points {
		if a.cfg.Points[i].ID == a.deleting {
			p = &a.cfg.Points[i]
			break
		}
	}
	open := a.deleting != ""
	ui.Modal(c, &open, func() {
		ui.Column(c).Width(420).Gap(10).Children(func() {
			ui.Text(c, "删除接入点").FontSize(17).Bold()
			name := "这个接入点"
			if p != nil {
				name = "「" + p.Name + "」"
			}
			ui.Text(c, "删除 "+name+" 会断开它的登录，并删除保存的密码和 TOTP 密钥。").
				FontSize(12).TextColor(t.Text)
			ui.Row(c).Gap(8).Justify(ui.End).Children(func() {
				if ui.Button(c, "取消").Clicked() {
					a.deleting = ""
				}
				if ui.PrimaryButton(c, "确认删除").Clicked() {
					a.removePoint(a.deleting)
					a.deleting = ""
				}
			})
		})
	})
	if !open {
		a.deleting = ""
	}
}

// canLogout reports whether "退出登录" is offered for a point. Only the WeCom
// login leaves a session worth discarding by hand; the other modes either keep
// a password or a browser session the user manages elsewhere.
func canLogout(p *model.AccessPoint) bool {
	return p != nil && model.AuthMode(p.AuthMode) == model.AuthModeWeCom
}

// askLogout refuses while the global TUN owns the session, then opens the
// confirmation: forgetting the authentication forces a new QR scan.
func (a *app) askLogout(v vpn.View) {
	if a.tunOn {
		for _, id := range splitIDs(a.tunPoints) {
			if id == v.ID {
				a.toast = "这个接入点正被全局 TUN 使用，先关闭 TUN 再退出登录"
				return
			}
		}
	}
	a.win.Update(func() { a.logoutAsk = v.ID })
}

// logoutView confirms forgetting a point's saved login.
func (a *app) logoutView(c *ui.Context) {
	if a.logoutAsk == "" {
		return
	}
	t := c.Theme()
	name := "这个接入点"
	for _, p := range a.cfg.Points {
		if p.ID == a.logoutAsk {
			name = "「" + p.Name + "」"
		}
	}
	open := a.logoutAsk != ""
	ui.Modal(c, &open, func() {
		ui.Column(c).Width(440).Gap(10).Children(func() {
			ui.Text(c, "退出登录").FontSize(17).Bold()
			ui.Text(c, "退出 "+name+" 会清除保存的认证信息，下次登录需要重新扫码。").
				FontSize(12).TextColor(t.Text)
			ui.Text(c, "如果只是想暂时断开、稍后继续用同一个账号，点「断开」即可，"+
				"那样下次登录会直接复用这次认证，不会弹二维码。").
				FontSize(11).TextColor(t.TextMuted)
			ui.Row(c).Gap(8).Justify(ui.End).Children(func() {
				if ui.Button(c, "取消").Clicked() {
					a.logoutAsk = ""
				}
				if ui.Button(c, "确认退出登录").Background(t.Danger).
					TextColor(ui.Hex("#ffffff")).Clicked() {
					id := a.logoutAsk
					a.logoutAsk = ""
					go a.mgr.Logout(id)
					a.toast = "已退出登录，下次登录需要重新扫码"
				}
			})
		})
	})
	if !open {
		a.logoutAsk = ""
	}
}

// quitView asks before closing the app: quitting drops every tunnel and, with
// the global TUN on, restores the system DNS.
func (a *app) quitView(c *ui.Context) {
	if !a.quitAsk {
		return
	}
	t := c.Theme()
	open := a.quitAsk
	ui.Modal(c, &open, func() {
		ui.Column(c).Width(420).Gap(10).Children(func() {
			ui.Text(c, "退出 aTrust Hub").FontSize(17).Bold()
			online, _, _ := a.mgr.Counts()
			line := "退出会断开所有隧道。"
			if a.tunOn {
				line += "全局 TUN 会关闭，系统 DNS 与代理恢复原状。"
			}
			if online > 0 {
				line += fmt.Sprintf("当前有 %d 个接入点在线。", online)
			}
			ui.Text(c, line).FontSize(12).TextColor(t.Text)
			ui.Text(c, "窗口上的关闭按钮只是隐藏到后台，不会退出。").
				FontSize(11).TextColor(t.TextMuted)
			ui.Row(c).Gap(8).Justify(ui.End).Children(func() {
				if ui.Button(c, "取消").Clicked() {
					a.quitAsk = false
				}
				if ui.Button(c, "确认退出").Background(t.Danger).
					TextColor(ui.Hex("#ffffff")).Clicked() {
					a.quitAsk = false
					a.doQuit()
				}
			})
		})
	})
	if !open {
		a.quitAsk = false
	}
}

// ---- actions ----

func (a *app) openNewEditor() {
	a.editor = editorDraft{
		open:          true,
		address:       "",
		authMode:      string(model.AuthModePassword),
		authModeLabel: model.AuthModePassword.Label(),
		socksPort:     strconv.Itoa(a.cfg.NextSocksPort()),
		inPool:        true,
		autoConnect:   false,
		monitor:       true,
		monitorEvery:  "300",
		secretStore:   secretStoreLabel(a.cfg.Settings.SecretStore),
	}
}

func (a *app) openEditor(v vpn.View) {
	p := a.cfg.Find(v.ID)
	if p == nil {
		return
	}
	mode := model.AuthMode(p.AuthMode)
	if mode == model.AuthModeAuto {
		// "自动识别" is gone from the editor: show what the old point has
		// actually been doing, so saving turns it into an explicit mode.
		if a.hasPassword(p.ID) {
			mode = model.AuthModePassword
		} else {
			mode = model.AuthModeWeCom
		}
	}
	a.editor = editorDraft{
		open:          true,
		editingID:     p.ID,
		name:          p.Name,
		address:       model.FormatAccessAddress(p.Server, p.Port),
		username:      p.Username,
		authMode:      string(mode),
		authModeLabel: mode.Label(),
		domain:        p.LoginDomain,
		socksPort:     strconv.Itoa(p.SocksPort),
		inPool:        p.InPool,
		autoConnect:   p.AutoConnect,
		monitor:       p.MonitorEnabled(),
		monitorEvery:  strconv.Itoa(p.MonitorIntervalSeconds()),
		secretStore:   secretStoreLabel(a.cfg.Settings.SecretStore),
		hasPassword:   a.hasPassword(p.ID),
		detected:      nil,
	}
	a.editor.hasTOTP = a.hasTOTP(p.ID)
	// A point saved before the mode was a choice gets the mode the server
	// actually offers, picked by detection instead of a "detect yourself"
	// dropdown entry.
	if strings.TrimSpace(p.AuthMode) == "" || model.AuthMode(p.AuthMode) == model.AuthModeAuto {
		a.editor.autoPick = true
	}
	if a.editor.autoPick {
		a.detectEditor()
	}
}

func (a *app) saveEditor() {
	d := &a.editor
	server, port, err := model.ParseAccessAddress(d.address)
	if err != nil {
		d.err = err.Error()
		return
	}
	socksPort, err := parseOptionalPort(d.socksPort)
	if err != nil {
		d.err = "独立 SOCKS5 端口：" + err.Error()
		return
	}
	if strings.TrimSpace(server) == "" {
		d.err = "服务器地址不能为空"
		return
	}
	mode := string(authModeFromLabel(d.authModeLabel))
	if mode == "" {
		mode = d.authMode
	}
	switch model.AuthMode(mode) {
	case model.AuthModeWeCom, model.AuthModeSSO:
		// Neither needs a username or a stored password: WeCom shows a QR
		// code, single sign-on runs on the portal's own page.
	case model.AuthModeAuto:
		if strings.TrimSpace(d.cred) != "" && strings.TrimSpace(d.username) == "" {
			d.err = "填了密码就要填用户名"
			return
		}
	default:
		if strings.TrimSpace(d.username) == "" {
			d.err = "用户名不能为空"
			return
		}
		if strings.TrimSpace(d.cred) == "" && !d.hasPassword {
			d.err = "请填写密码"
			return
		}
	}
	if !d.inPool && socksPort == 0 {
		d.err = "至少勾选统一入口，或填一个独立 SOCKS5 端口"
		return
	}
	// Switching away from the password mode leaves no one to use a
	// username: drop it so the card does not show an account that is never
	// sent.
	username := strings.TrimSpace(d.username)
	if model.AuthMode(mode) != model.AuthModePassword && model.AuthMode(mode) != model.AuthModeAuto {
		username = ""
	}
	p := model.AccessPoint{
		ID:          d.editingID,
		Name:        strings.TrimSpace(d.name),
		Server:      server,
		Port:        port,
		Username:    username,
		AuthMode:    mode,
		LoginDomain: strings.TrimSpace(d.domain),
		SocksPort:   socksPort,
		InPool:      d.inPool,
		AutoConnect: d.autoConnect,
	}
	monitor := d.monitor
	p.Monitor = &monitor
	if every, err := strconv.Atoi(strings.TrimSpace(d.monitorEvery)); err == nil && every > 0 {
		p.MonitorInterval = every
	} else {
		p.MonitorInterval = 300
	}
	p.Normalize()
	if p.ID == "" {
		p.ID = model.NewID()
	}
	if err := p.Validate(); err != nil {
		d.err = err.Error()
		return
	}
	if socksPort == a.cfg.Settings.AggregatePort {
		d.err = "独立 SOCKS5 端口不能和统一入口端口相同"
		return
	}

	// Secrets first, so that a point is never saved without the creds it
	// needs when the user typed new ones.
	if strings.TrimSpace(d.cred) != "" {
		if err := a.store.SetPassword(p.ID, d.cred); err != nil {
			d.err = "保存密码失败：" + err.Error()
			return
		}
	}
	if d.clearTOTP {
		if err := a.store.SetTOTP(p.ID, ""); err != nil {
			d.err = "清除 TOTP 失败：" + err.Error()
			return
		}
	} else if strings.TrimSpace(d.totp) != "" {
		if err := a.store.SetTOTP(p.ID, strings.TrimSpace(d.totp)); err != nil {
			d.err = "保存 TOTP 失败：" + err.Error()
			return
		}
	}

	_, err = a.store.Update(func(cfg *model.Config) error {
		for _, other := range cfg.Points {
			if other.ID != p.ID && socksPort > 0 && other.SocksPort == socksPort {
				return fmt.Errorf("SOCKS5 端口 %d 已被「%s」使用", socksPort, other.Name)
			}
		}
		if d.editingID == "" {
			added := cfg.Add(p)
			// Add assigns a free port for callers that do not care; the
			// editor's explicit 0 means "no per-point proxy".
			added.SocksPort = socksPort
			p.ID = added.ID
			return nil
		}
		_, err := cfg.Update(p)
		return err
	})
	if err != nil {
		d.err = err.Error()
		return
	}
	if err := a.saveConfig(); err != nil {
		d.err = "保存配置失败：" + err.Error()
		return
	}
	// The password store is a global setting, chosen here for convenience.
	if newStore := secretStoreFromLabel(d.secretStore); newStore != a.cfg.Settings.SecretStore {
		if _, err := a.store.Update(func(cfg *model.Config) error {
			cfg.Settings.SecretStore = newStore
			return nil
		}); err != nil {
			d.err = "保存密码存储方式失败：" + err.Error()
			return
		}
		if err := a.saveConfig(); err != nil {
			d.err = "保存密码存储方式失败：" + err.Error()
			return
		}
		a.toast = "已保存「" + p.Name + "」，密码存储方式改为「" + d.secretStore + "」，重启后生效"
		d.open = false
		return
	}
	d.open = false
	a.toast = "已保存「" + p.Name + "」"
}

// detectEditor asks the server which login methods it offers, for the
// editor's "detect" button. It runs beside the view and updates the draft
// on the main thread.
func (a *app) detectEditor() {
	d := &a.editor
	server, port, err := model.ParseAccessAddress(d.address)
	if err != nil {
		d.detectErr = err.Error()
		d.detected = nil
		return
	}
	d.detecting = true
	d.detectErr = ""
	d.detected = nil
	d.detectGen++
	gen := d.detectGen
	domain := d.domain
	mode := d.authMode
	a.invalidate()

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		methods, err := vpn.DetectAuthMethods(ctx, model.AccessPoint{
			Server: server, Port: port, LoginDomain: domain,
		})
		update := func() {
			if d.detectGen != gen || !d.open {
				return
			}
			d.detecting = false
			if err != nil {
				d.detectErr = "检测失败：" + err.Error()
				return
			}
			labels := make([]string, 0, len(methods))
			hasExternal, hasPassword := false, false
			for _, m := range methods {
				labels = append(labels, m.Label())
				switch m.Type {
				case "auth/qywechat", "auth/httpsOauth2", "auth/cas":
					hasExternal = true
				case "auth/psw":
					hasPassword = true
				}
			}
			d.detected = labels
			if len(labels) == 0 {
				d.detectErr = "服务器没有返回可用的认证方式"
				return
			}
			if d.autoPick {
				// 企业微信优先（有扫码就用扫码），其次是单点登录，
				// 最后才是账号密码：这正是服务器给出的顺序所意味的。
				picked := model.AuthModePassword
				switch {
				case hasWeCom(methods):
					picked = model.AuthModeWeCom
				case hasSSO(methods):
					picked = model.AuthModeSSO
				}
				d.authMode = string(picked)
				d.authModeLabel = picked.Label()
				d.autoPick = false
			}
			// 账号密码模式下，服务器只提供密码登录而表单还没填密码时，
			// 直接把下一步说清楚，省得保存后才报错。
			if mode == string(model.AuthModePassword) && !hasExternal && hasPassword && !d.hasPassword && strings.TrimSpace(d.cred) == "" {
				d.detectErr = "服务器只支持账号密码，请填写用户名和密码"
			}
		}
		if a.win != nil {
			a.win.Update(update)
		} else {
			update()
		}
	}()
}

// toggleSystemProxy points the macOS system proxy at the unified entry, or
// clears it, so browsers need no manual proxy setup.
// firstOnlinePoint returns the ID of the first online access point.
func (a *app) openTUNLog() {
	path := filepath.Join(a.dir, "tun.log")
	if _, err := os.Stat(path); err != nil {
		a.toast = "还没有 TUN 日志（先开启一次全局 TUN）"
		return
	}
	if err := mygo.Shell.OpenPath(path); err != nil {
		a.toast = "打开日志失败：" + err.Error()
	}
}

func (a *app) firstOnlinePoint() string {
	for _, v := range a.mgr.Views() {
		if v.State == vpn.StateOnline {
			return v.ID
		}
	}
	return ""
}

func (a *app) toggleSystemProxy() {
	agg := a.mgr.Aggregate()
	if !agg.Running || agg.Addr == "" {
		a.toast = "统一入口还没启动"
		return
	}
	port := agg.Addr
	if i := strings.LastIndex(port, ":"); i >= 0 {
		port = port[i+1:]
	}
	target := "127.0.0.1:" + port
	on := !a.sysProxyOn
	a.toast = "正在修改系统代理，请授权…"
	a.invalidate()
	go func() {
		err := applySystemProxy(target, on)
		a.win.Update(func() {
			if err != nil {
				a.toast = "系统代理设置失败：" + err.Error()
				return
			}
			a.sysProxyOn = on
			if on {
				a.toast = "已把系统代理设为 " + target
			} else {
				a.toast = "已取消系统代理"
			}
		})
	}()
}

func (a *app) openSettings() {
	s := a.cfg.Settings
	a.settings = settingsDraft{
		open:          true,
		host:          s.ListenHost,
		port:          strconv.Itoa(s.AggregatePort),
		interval:      strconv.Itoa(s.HealthIntervalSec),
		routing:       s.Routing.Label(),
		aggregate:     s.AggregateEnabled,
		autoReconnect: s.AutoReconnect,
		secretStore:   secretStoreLabel(s.SecretStore),
		hideDock:      s.HideDock,
	}
}

func (a *app) saveSettings() {
	d := &a.settings
	port, err := parsePort(d.port, "统一入口端口")
	if err != nil {
		d.err = err.Error()
		return
	}
	interval, err := strconv.Atoi(strings.TrimSpace(d.interval))
	if err != nil || interval < 0 {
		d.err = "健康检查间隔必须是不小于 0 的整数"
		return
	}
	host := strings.TrimSpace(d.host)
	if host == "" {
		d.err = "监听地址不能为空"
		return
	}
	for _, p := range a.cfg.Points {
		if p.SocksPort == port {
			d.err = fmt.Sprintf("端口 %d 已被「%s」的独立代理使用", port, p.Name)
			return
		}
	}
	_, err = a.store.Update(func(cfg *model.Config) error {
		cfg.Settings.ListenHost = host
		cfg.Settings.AggregatePort = port
		cfg.Settings.HealthIntervalSec = interval
		cfg.Settings.Routing = routingFromLabel(d.routing)
		cfg.Settings.AggregateEnabled = d.aggregate
		cfg.Settings.AutoReconnect = d.autoReconnect
		cfg.Settings.HideDock = d.hideDock
		cfg.Settings.SecretStore = secretStoreFromLabel(d.secretStore)
		return cfg.Settings.Validate()
	})
	if err != nil {
		d.err = err.Error()
		return
	}
	if err := a.saveConfig(); err != nil {
		d.err = "保存配置失败：" + err.Error()
		return
	}
	d.open = false
	a.toast = "设置已保存"

}

func (a *app) removePoint(id string) {
	if _, err := a.store.Update(func(cfg *model.Config) error {
		cfg.Remove(id)
		return nil
	}); err != nil {
		a.toast = err.Error()
		return
	}
	if err := a.saveConfig(); err != nil {
		a.toast = "保存配置失败：" + err.Error()
		return
	}
	_ = a.store.DeleteSecrets(id)
	a.toast = "已删除接入点"
}

func parsePort(s, what string) (int, error) {
	port, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("%s必须是 1–65535 的整数", what)
	}
	return port, nil
}

func parseOptionalPort(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	port, err := strconv.Atoi(s)
	if err != nil || port < 0 || port > 65535 {
		return 0, fmt.Errorf("必须是 0–65535 的整数")
	}
	return port, nil
}

func secretStoreLabels() []string {
	return []string{"本地文件（推荐）", "系统钥匙串"}
}

func secretStoreLabel(v string) string {
	if v == model.SecretStoreKeychain {
		return "系统钥匙串"
	}
	return "本地文件（推荐）"
}

func secretStoreFromLabel(label string) string {
	if label == "系统钥匙串" {
		return model.SecretStoreKeychain
	}
	return model.SecretStoreFile
}

// hasWeCom reports whether the server offers the WeCom QR login, which the
// app completes in its own popup.
func hasWeCom(methods []vpn.AuthMethod) bool {
	for _, m := range methods {
		if m.Type == "auth/qywechat" {
			return true
		}
	}
	return false
}

// hasSSO reports whether the server offers a single sign-on that only finishes
// in a real browser.
func hasSSO(methods []vpn.AuthMethod) bool {
	for _, m := range methods {
		switch m.Type {
		case "auth/cas", "auth/httpsOauth2":
			return true
		}
	}
	return false
}

// hostInTun reports whether a point is one the running helper serves. The
// snapshot is a comma-joined list of point IDs.
func hostInTun(points, id string) bool {
	for _, p := range strings.Split(points, ",") {
		if strings.TrimSpace(p) == id {
			return true
		}
	}
	return false
}

// appFilterValue maps the dropdown label to the filter used by the list.
func appFilterValue(label string) string {
	switch label {
	case "已启用":
		return "on"
	case "未启用":
		return "off"
	default:
		return "all"
	}
}
