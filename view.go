package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"

	"github.com/qy/easyconnect/internal/model"
	"github.com/qy/easyconnect/internal/store"
	"github.com/qy/easyconnect/internal/vpn"
)

// githubIcon is the repository mark shown in the footer.
var githubIcon = ui.MustParseSVG([]byte(`<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 .3a12 12 0 0 0-3.8 23.4c.6.1.8-.3.8-.6v-2c-3.3.7-4-1.6-4-1.6-.6-1.4-1.3-1.7-1.3-1.7-1.1.7 0 0 0 0 1.2-.1 1.8 1.2 1.8 1.2 1.1 1.8 2.8 1.3 3.5 1 .1-.8.4-1.3.8-1.6-2.7-.3-5.5-1.3-5.5-5.9 0-1.3.5-2.4 1.2-3.2-.1-.3-.5-1.5.1-3.2 0 0 1-.3 3.3 1.2a11.5 11.5 0 0 1 6 0C17.3 4.7 18.3 5 18.3 5c.6 1.7.2 2.9.1 3.2.8.8 1.2 1.9 1.2 3.2 0 4.6-2.8 5.6-5.5 5.9.4.4.8 1.1.8 2.2v3.3c0 .3.2.7.8.6A12 12 0 0 0 12 .3"/></svg>`))

// copyIcon is two overlapping sheets, for "copy this address".
var copyIcon = ui.MustParseSVG([]byte(`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>`))

// refreshIcon is the two-arrow refresh glyph used by aTrust's own console, for
// "check this session again".
var refreshIcon = ui.MustParseSVG([]byte(`<svg viewBox="0 0 1024 1024" fill="currentColor"><path d="M168 504.2c1-43.7 10-86.1 26.9-126 17.3-41 42.1-77.7 73.7-109.4S337 212.3 378 195c42.4-17.9 87.4-27 133.9-27s91.5 9.1 133.8 27c40.9 17.3 77.7 42.1 109.3 73.8 9.9 9.9 19.2 20.4 27.8 31.4l-60.2 47c-5.3 4.1-3.5 12.5 3 14.1l175.7 43c5 1.2 9.9-2.6 9.9-7.7l0.8-180.9c0-6.7-7.7-10.5-12.9-6.3l-56.4 44.1C765.8 155.1 646.2 92 511.8 92 282.7 92 96.3 275.6 92 503.8c-0.1 4.5 3.5 8.2 8 8.2h60c4.4 0 7.9-3.5 8-7.8z m756 7.8h-60c-4.4 0-7.9 3.5-8 7.8-1 43.7-10 86.1-26.9 126-17.3 41-42.1 77.8-73.7 109.4S687 811.7 646 829c-42.4 17.9-87.4 27-133.9 27s-91.5-9.1-133.9-27c-40.9-17.3-77.7-42.1-109.3-73.8-9.9-9.9-19.2-20.4-27.8-31.4l60.2-47c5.3-4.1 3.5-12.5-3-14.1l-175.7-43c-5-1.2-9.9 2.6-9.9 7.7l-0.7 181c0 6.7 7.7 10.5 12.9 6.3l56.4-44.1C258.2 868.9 377.8 932 512.2 932c229.2 0 415.5-183.7 419.8-411.8 0.1-4.5-3.5-8.2-8-8.2z"/></svg>`))

// iconButton draws a small clickable glyph, the same shape as the TUN log
// button, so one-row actions do not take a full button's width.
// iconButtonAt is iconButton with a chosen glyph size.
func iconButtonAt(c *ui.Context, icon *ui.SVG, tooltip string, size float32, onClick func()) {
	ui.Row(c).Padding(5).Radius(8).AlignItems(ui.Center).
		OnClick(onClick).Tooltip(tooltip).Children(func() {
		ui.Icon(c, icon).Size(size, size)
	})
}

func iconButton(c *ui.Context, icon *ui.SVG, tooltip string, onClick func()) {
	ui.Row(c).Padding(4).Radius(8).AlignItems(ui.Center).
		OnClick(onClick).Tooltip(tooltip).Children(func() {
		ui.Icon(c, icon).Size(15, 15)
	})
}

var settingsIcon = ui.MustParseSVG([]byte(`<svg viewBox="0 0 1024 1024" fill="currentColor"><path d="M439.816 101.851c-8.631-16.952-28.007-25.48-46.337-20.396-70.066 19.435-133.165 55.501-184.82 103.628-12.909 12.028-16.413 31.094-8.623 46.926 5.374 10.92 8.414 23.234 8.414 36.376 0 45.555-36.833 82.347-82.1 82.347-0.381 0-0.762-0.003-1.142-0.008-17.691-0.253-33.448 11.147-38.74 28.031C73.159 421.209 66 466.344 66 513.078c0 30.844 3.118 61.001 9.07 90.156 4.1 20.082 22.714 33.816 43.111 31.808a83.069 83.069 0 0 1 8.169-0.399c45.267 0 82.1 36.791 82.1 82.346 0 20.276-7.254 38.74-19.334 53.086-13.177 15.649-12.423 38.718 1.748 53.472 52.742 54.916 119.403 96.417 194.376 118.784 20.888 6.231 42.918-5.408 49.543-26.174 10.616-33.275 41.714-57.212 78.217-57.212s67.601 23.937 78.217 57.212c6.625 20.766 28.655 32.405 49.543 26.174 74.973-22.367 141.634-63.868 194.376-118.784 14.17-14.755 14.924-37.823 1.748-53.471-12.08-14.346-19.334-32.811-19.334-53.087 0-45.554 36.834-82.346 82.1-82.346 2.773 0 5.496 0.135 8.169 0.399 20.397 2.008 39.011-11.726 43.111-31.808 5.951-29.155 9.07-59.312 9.07-90.156 0-46.734-7.16-91.869-20.468-134.323-5.292-16.884-21.049-28.285-38.741-28.031-0.379 0.005-0.76 0.008-1.141 0.008-45.266 0-82.1-36.792-82.1-82.347 0-13.142 3.04-25.456 8.414-36.376 7.79-15.832 4.286-34.898-8.623-46.926-51.655-48.127-114.754-84.193-184.82-103.628-18.33-5.084-37.706 3.444-46.337 20.396-13.648 26.806-41.357 44.97-73.184 44.97-31.827 0-59.536-18.164-73.184-44.97zM288.45 268.385c0-14.471-1.9-28.535-5.47-41.936 31.114-25.118 66.377-45.232 104.576-59.156 29.686 36.285 74.82 59.528 125.444 59.528 50.624 0 95.758-23.243 125.444-59.528 38.199 13.924 73.462 34.038 104.576 59.156a162.748 162.748 0 0 0-5.47 41.936c0 79.513 57.113 145.772 132.604 159.667 6.434 27.261 9.846 55.723 9.846 85.026 0 14.581-0.845 28.951-2.485 43.065-79.109 10.814-139.965 78.769-139.965 160.846 0 26.162 6.201 50.922 17.202 72.84-30.829 27.076-66.197 49.043-104.786 64.612-28.717-45.337-79.271-75.496-136.966-75.496-57.695 0-108.249 30.159-136.966 75.496-38.589-15.569-73.957-37.536-104.787-64.612 11.002-21.918 17.203-46.678 17.203-72.84 0-82.077-60.856-150.032-139.965-160.846A373.007 373.007 0 0 1 146 513.078c0-29.304 3.411-57.765 9.845-85.026 75.492-13.894 132.605-80.154 132.605-159.667zM513 336c-97.202 0-176 78.798-176 176s78.798 176 176 176 176-78.798 176-176-78.798-176-176-176zM409 512c0-57.438 46.562-104 104-104s104 46.562 104 104-46.562 104-104 104-104-46.562-104-104z"/></svg>`))

// logIcon is the document-with-lines glyph for the TUN log button.
var logIcon = ui.MustParseSVG([]byte(`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><path d="M14 3v6h6"/><path d="M8 13h8"/><path d="M8 17h8"/></svg>`))

// accessIcon is a list glyph for the access-log button.
var accessIcon = ui.MustParseSVG([]byte(`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M8 6h13"/><path d="M8 12h13"/><path d="M8 18h13"/><path d="M3 6h.01"/><path d="M3 12h.01"/><path d="M3 18h.01"/></svg>`))

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
		case 3:
			a.clashSection(c)
		default:
			// 系统代理没开时，统一入口没有参与任何转发，整块隐藏；
			// 需要手动配置端口时在「设置」里看。
			// 统一入口始终显示：它也是手动配置浏览器/IDE 时会用到的地址，
			// 藏起来会让人找不到连接入口。
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
	a.mapSettingsView(c)
	a.deleteView(c)
	a.logoutView(c)
	a.quitView(c)
	a.appDetailView(c)
}

// qrCard was removed: WeCom's QR login now uses a WebView popup.

func (a *app) tabBar(c *ui.Context) {
	ui.Tabs(c, &a.tab, "接入点", appTabLabel(a.appCount()), accessTabLabel(), clashTabLabel())
}

func accessTabLabel() string {
	return "访问日志"
}

func clashTabLabel() string {
	return "分流规则"
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
		ui.Segmented(c, &a.appFilterIndex, "所有", "已启用", "未启用").
			Label("过滤应用")
		a.appFilter = appFilterValue(a.appFilterIndex)
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
	// 「可达 2ms」。这时让 helper 用真实隧道连一次；helper 不支持时退回直连。
	if a.tunOn && hostInTun(a.tunPoints, id) {
		if point := a.cfg.Find(id); point != nil {
			for _, p := range ports {
				addr := net.JoinHostPort(host, strconv.Itoa(p))
				ok, ms, errText, answered, skip := a.probeTunnel(point.Name, addr, 2*time.Second)
				if !answered || skip {
					return a.directProbeText(id, host, ports)
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
	return a.directProbeText(id, host, ports)
}

// directProbeText dials one host through the local dialer, which is all that is
// possible when the helper cannot answer probes.
func (a *app) directProbeText(id, host string, ports []int) string {
	if len(ports) == 0 {
		ports = []int{443, 80}
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
						} else if a.hasMappings() {
							// No access point, but port mappings are enough to
							// bring TUN up in mapping-only mode.
							go a.startTUNSerialized("")
						} else {
							a.tunPending = false
							a.toast = "没有在线接入点，先登录再开 TUN（或先在端口映射里配一条映射）"
						}
					} else {
						go a.stopTUNSerialized()
					}
					a.invalidate()
				}
			}
			ui.Row(c).Padding(6).Radius(8).AlignItems(ui.Center).
				OnClick(a.openMapSettings).Tooltip("端口映射 / TUN 日志").Children(func() {
				ui.Icon(c, settingsIcon).Size(17, 17)
			})
			// Always shown, like the TUN switch: hidden controls make the app
			// look broken. It is only disabled while the aggregate is down.
			if supportsSystemProxy() {
				agg := a.mgr.Aggregate()
				a.sysProxySwitch = a.sysProxyOn
				ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
					ui.Text(c, "系统代理").FontSize(13).TextColor(t.Text)
					// TUN 接管时应用侧代理已经停了，再把系统指过去就是整机没网。
					ui.Switch(c, &a.sysProxySwitch).Disabled(!agg.Running || a.tunOn)
				})
				if a.sysProxySwitch != a.sysProxyOn {
					a.toggleSystemProxy()
				}
			}
			// 只用齿轮图标，不占一个按钮的宽度。
			iconButtonAt(c, settingsIcon, "设置", 17, a.openSettings)
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
				ui.Text(c, addr).Font("monospace").FontSize(13).TextColor(t.Text)
				if ui.Button(c, "复制统一入口地址").Label("复制").Clicked() {
					a.copyText(addr)
				}
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
		// A dead tunnel with a valid login looks "online" everywhere else, so
		// the probe result needs its own line.
		if v.TunnelState != "" && v.State != vpn.StateError {
			colour := t.Warning
			label := "隧道保活探测失败"
			if v.TunnelFails > 0 {
				label += "（" + strconv.Itoa(v.TunnelFails) + " 次）"
			}
			if v.TunnelState == "dead" {
				colour = t.Danger
				label = "隧道已失效（登录仍有效），正在重建"
			}
			text := label
			if v.TunnelErr != "" {
				text += "：" + v.TunnelErr
			}
			ui.Text(c, text).FontSize(12).TextColor(colour).Ellipsis("…")
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
		if p := a.cfg.Find(v.ID); a.canLogout(p) {
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

// clashPoints reduces the current views to what the rule generator needs.
func (a *app) clashPoints() []clashPoint {
	views := a.mgr.Views()
	out := make([]clashPoint, 0, len(views))
	for _, v := range views {
		out = append(out, clashPoint{
			Name: v.Name, SocksPort: v.SocksPort,
			Online: v.State == vpn.StateOnline, Apps: v.Apps,
		})
	}
	return out
}

// clashSection shows the generated Clash configuration for every access
// point, ready to paste into a Clash profile.
func (a *app) clashSection(c *ui.Context) {
	t := c.Theme()
	points := a.clashPoints()
	plan := buildClashPlan(points)
	yaml := generateClashMerge(points)

	ui.Row(c).AlignItems(ui.Center).Gap(10).Children(func() {
		ui.Text(c, "分流规则").FontSize(14).Bold()
		ui.Text(c, fmt.Sprintf("%d 条规则", plan.Rules)).FontSize(12).TextColor(t.TextMuted)
		ui.Row(c).Grow(1)
		if ui.Button(c, "复制全部").Clicked() {
			a.copyText(yaml)
			a.toast = "已复制，粘贴到 Clash Verge 的「全局扩展覆写配置」后保存"
		}
	})
	if note := clashSkippedNote(plan); note != "" {
		ui.Text(c, note).FontSize(11).TextColor(t.TextMuted)
	}
	box := ui.Scroll(c).Grow(1).MinHeight(0).Radius(8).Border(1, t.Border).
		Background(t.Surface).Padding(10)
	box.Children(func() {
		ui.Column(c).Gap(1).Children(func() {
			for _, line := range strings.Split(strings.TrimRight(yaml, "\n"), "\n") {
				color := t.Text
				trimmed := strings.TrimSpace(line)
				switch {
				case strings.HasPrefix(trimmed, "#"):
					color = t.TextMuted
				case strings.HasSuffix(trimmed, ":"):
					color = t.Accent
				}
				ui.Text(c, line).Font("monospace").FontSize(11).TextColor(color)
			}
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
				Tooltip("下载 v" + a.update.Version).
				OnClick(func() { a.openUpdate() }).Children(func() {
				ui.Text(c, "新版本 v"+a.update.Version).FontSize(11)
			})
		}
		ui.Row(c).Padding(4).Radius(8).AlignItems(ui.Center).
			Tooltip("项目主页：" + projectURL).
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
			// 接入地址先填，检测按钮紧跟着它，点检测时地址已经在上方。
			ui.Field(c, "接入地址", func() {
				ui.TextInput(c, &d.address).
					Placeholder("例如：https://vpn.example.com:443").Grow(1)
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

// mapSettingsView is the port-mapping dialog opened from the header button:
// a list of 目标IP/目标端口 -> 映射IP/映射端口 rows, plus the TUN log entry.
func (a *app) mapSettingsView(c *ui.Context) {
	d := &a.mapSettings
	if !d.open {
		return
	}
	t := c.Theme()
	ui.Modal(c, &d.open, func() {
		ui.Column(c).Width(600).Gap(10).Children(func() {
			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
				ui.Text(c, "端口映射").FontSize(18).Bold()
				// The two log entries live in the dialog's top-right corner.
				ui.Row(c).Gap(2).AlignItems(ui.Center).Children(func() {
					iconButton(c, accessIcon, "访问日志", a.openAccessLog)
					iconButton(c, logIcon, "TUN 日志", a.openTUNLog)
				})
			})
			ui.Row(c).Gap(6).AlignItems(ui.Center).Children(func() {
				ui.Text(c, "启用").FontSize(11).TextColor(t.TextMuted).Width(40)
				ui.Text(c, "目标 IP").FontSize(11).TextColor(t.TextMuted).Width(110)
				ui.Text(c, "端口").FontSize(11).TextColor(t.TextMuted).Width(64)
				ui.Text(c, "映射 IP").FontSize(11).TextColor(t.TextMuted).Width(110)
				ui.Text(c, "端口").FontSize(11).TextColor(t.TextMuted).Width(64)
			})
			ui.Scroll(c).Grow(1).Height(180).Children(func() {
				ui.Column(c).Gap(6).Children(func() {
					for i := range d.rows {
						row := &d.rows[i]
						ui.Row(c).Gap(6).AlignItems(ui.Center).Children(func() {
							// 这一行自己的开关：关掉只是不生效，值仍然保留。
							ui.Row(c).Width(40).AlignItems(ui.Center).Children(func() {
								ui.Switch(c, &row.Enabled)
							})
							ui.TextInput(c, &row.TargetIP).Placeholder("127.0.0.1").Width(110)
							ui.TextInput(c, &row.TargetPort).Placeholder("8080").Width(64)
							ui.Text(c, "→").FontSize(12).TextColor(t.TextMuted)
							ui.TextInput(c, &row.LocalIP).Placeholder("127.0.0.1").Width(110)
							ui.TextInput(c, &row.LocalPort).Placeholder("8080").Width(64)
							idx := i
							if ui.Button(c, "删除").FontSize(11).Clicked() {
								d.rows = append(d.rows[:idx], d.rows[idx+1:]...)
							}
						})
					}
				})
			})
			if ui.Button(c, "＋ 添加一条映射").FontSize(12).Clicked() {
				d.rows = append(d.rows, mapRow{Enabled: true, LocalIP: "127.0.0.1"})
			}
			if d.err != "" {
				ui.Text(c, d.err).FontSize(12).TextColor(t.Danger)
			}
			ui.Row(c).Gap(8).Justify(ui.End).Children(func() {
				if ui.Button(c, "取消").Clicked() {
					d.open = false
				}
				if ui.PrimaryButton(c, "保存").Clicked() {
					a.saveMapSettings()
				}
			})
		})
	})
}

// openMapSettings loads the saved mappings into four-field rows.
func (a *app) openMapSettings() {
	d := &a.mapSettings
	d.open = true
	d.err = ""
	d.rows = nil
	d.rows = append(d.rows, mappingsToRows(
		a.cfg.Settings.LocalMappings, a.cfg.Settings.DisabledMappings)...)
	// Start with one empty row so the dialog is usable straight away.
	if len(d.rows) == 0 {
		d.rows = []mapRow{{Enabled: true, LocalIP: "127.0.0.1"}}
	}
}

// saveMapSettings turns the rows back into the redirect table. Empty rows are
// skipped; a partially filled row is an error so nothing is silently dropped.
func (a *app) saveMapSettings() {
	d := &a.mapSettings
	enabled := map[string]string{}
	disabled := map[string]string{}
	for i, r := range d.rows {
		tIP := strings.TrimSpace(r.TargetIP)
		tPort := strings.TrimSpace(r.TargetPort)
		lIP := strings.TrimSpace(r.LocalIP)
		lPort := strings.TrimSpace(r.LocalPort)
		if tIP == "" && tPort == "" && lIP == "" && lPort == "" {
			continue // fully empty: ignore
		}
		if tIP == "" || lIP == "" || lPort == "" {
			d.err = fmt.Sprintf("第 %d 条：目标 IP、映射 IP、映射端口都要填", i+1)
			return
		}
		key, err := joinHostPort(tIP, tPort)
		if err != nil {
			d.err = fmt.Sprintf("第 %d 条：%v", i+1, err)
			return
		}
		val, err := joinHostPort(lIP, lPort)
		if err != nil || strings.Contains(val, ":") == false {
			d.err = fmt.Sprintf("第 %d 条：映射端口无效", i+1)
			return
		}
		if r.Enabled {
			enabled[key] = val
		} else {
			disabled[key] = val
		}
	}
	if _, err := a.store.Update(func(cfg *model.Config) error {
		cfg.Settings.LocalMappings = enabled
		cfg.Settings.DisabledMappings = disabled
		return nil
	}); err != nil {
		d.err = err.Error()
		return
	}
	if err := a.saveConfig(); err != nil {
		d.err = "保存配置失败：" + err.Error()
		return
	}
	d.open = false
	if n := len(enabled); n > 0 {
		a.toast = fmt.Sprintf("端口映射已保存，%d 条生效", n)
	} else {
		a.toast = "端口映射已保存，当前没有启用的映射"
	}
}

// joinHostPort builds "ip:port" (or just "ip" when port is blank) after
// validating both halves, so a typo is caught at save time.
func joinHostPort(ip, port string) (string, error) {
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("不是有效 IP：%s", ip)
	}
	if port == "" {
		return ip, nil
	}
	n, err := strconv.Atoi(port)
	if err != nil || n <= 0 || n > 65535 {
		return "", fmt.Errorf("端口无效：%s", port)
	}
	return fmt.Sprintf("%s:%d", ip, n), nil
}

// mappingsToRows splits a redirect table into four-field rows, preserving a
// stable order (sorted by key).
func mappingsToRows(enabled, disabled map[string]string) []mapRow {
	rows := make([]mapRow, 0, len(enabled)+len(disabled))
	add := func(m map[string]string, on bool) {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			tIP, tPort := k, ""
			if h, p, err := net.SplitHostPort(k); err == nil {
				tIP, tPort = h, p
			}
			lIP, lPort := m[k], ""
			if h, p, err := net.SplitHostPort(m[k]); err == nil {
				lIP, lPort = h, p
			}
			rows = append(rows, mapRow{
				Enabled: on, TargetIP: tIP, TargetPort: tPort,
				LocalIP: lIP, LocalPort: lPort,
			})
		}
	}
	// Enabled rows first: the active set is what the user cares about.
	add(enabled, true)
	add(disabled, false)
	return rows
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

// canLogout reports whether "退出登录" is offered for a point: only a login
// that came from an external page leaves a session worth discarding by hand.
// That is the WeCom QR login, single sign-on, and the legacy "auto" mode —
// which, without a stored password, is the WeCom login too. A point that logs
// in with a password has nothing to discard, so it shows no such button.
func (a *app) canLogout(p *model.AccessPoint) bool {
	if p == nil {
		return false
	}
	switch model.AuthMode(p.AuthMode) {
	case model.AuthModeWeCom, model.AuthModeSSO:
		return true
	case model.AuthModeAuto:
		// 老配置的 auto：有密码就走密码，没有密码才落到企业微信。
		_, err := a.store.Password(p.ID)
		return errors.Is(err, store.ErrSecretNotFound)
	}
	return false
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
	var point *model.AccessPoint
	for i := range a.cfg.Points {
		if a.cfg.Points[i].ID == a.logoutAsk {
			name = "「" + a.cfg.Points[i].Name + "」"
			point = &a.cfg.Points[i]
		}
	}
	// 只有单点登录的会话存在浏览器里，才需要连浏览器数据一起清掉。
	usesBrowser := point != nil && model.AuthMode(point.AuthMode) == model.AuthModeSSO
	body := "退出 " + name + " 会清除本地暂存的认证信息，下次登录需要重新认证。"
	hint := "如果只是想暂时断开、稍后继续用同一个账号，点「断开」即可，" +
		"那样下次登录会直接复用这次认证，不用重新扫码。"
	if usesBrowser {
		body = "退出 " + name + " 会清除本地暂存的认证信息与浏览器登录数据（cookie），下次登录需要重新认证。"
		hint = "如果只是想暂时断开、稍后继续用同一个账号，点「断开」即可，" +
			"那样下次登录会直接复用这次认证，不会重新打开浏览器认证。"
	}
	open := a.logoutAsk != ""
	ui.Modal(c, &open, func() {
		ui.Column(c).Width(440).Gap(10).Children(func() {
			ui.Text(c, "退出登录").FontSize(17).Bold()
			ui.Text(c, body).FontSize(12).TextColor(t.Text)
			ui.Text(c, hint).FontSize(11).TextColor(t.TextMuted)
			ui.Row(c).Gap(8).Justify(ui.End).Children(func() {
				if ui.Button(c, "取消").Clicked() {
					a.logoutAsk = ""
				}
				if ui.Button(c, "确认退出登录").Background(t.Danger).
					TextColor(ui.Hex("#ffffff")).Clicked() {
					id := a.logoutAsk
					a.logoutAsk = ""
					go func() {
						a.mgr.Logout(id)
						// 企业微信的认证不在浏览器里，清配置目录反而会丢掉
						// 有用的东西；只有单点登录需要连浏览器会话一起清。
						if p := a.cfg.Find(id); p != nil && logoutClearsBrowser(model.AuthMode(p.AuthMode)) {
							a.clearBrowserLoginProfile(id)
						}
					}()
					a.toast = "已退出登录，下次登录需要重新认证"
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

// openAccessLog opens the helper's access log: one line per connection the TUN
// carried.
func (a *app) openAccessLog() {
	path := a.accessLogPath()
	if _, err := os.Stat(path); err != nil {
		a.toast = "还没有访问日志（先开启一次全局 TUN）"
		return
	}
	if err := mygo.Shell.OpenPath(path); err != nil {
		a.toast = "打开访问日志失败：" + err.Error()
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
	if a.tunOn && !a.sysProxyOn {
		a.toast = "全局 TUN 已经接管流量，先关掉 TUN 再用系统代理"
		a.sysProxySwitch = a.sysProxyOn
		return
	}
	agg := a.mgr.Aggregate()
	if !agg.Running || agg.Addr == "" {
		a.toast = "统一入口还没启动"
		a.sysProxySwitch = a.sysProxyOn
		return
	}
	// 先确认代理端口真的在监听：指到一个没人听的端口会让整台机器断网。
	if conn, err := net.DialTimeout("tcp", agg.Addr, 2*time.Second); err != nil {
		a.toast = "统一入口没有在监听，先别开系统代理"
		a.sysProxySwitch = a.sysProxyOn
		return
	} else {
		_ = conn.Close()
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
		err := applySystemProxyFn(target, on)
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

// appFilterValue maps the segmented control's choice to the filter used by the
// list: 0 所有, 1 已启用, 2 未启用.
func appFilterValue(index int) string {
	switch index {
	case 1:
		return "on"
	case 2:
		return "off"
	default:
		return "all"
	}
}

// logoutClearsBrowser reports whether discarding a login must also wipe the
// browser data. Only single sign-on keeps its session in a browser; the WeCom
// login lives in the app's own window and its files are not worth touching.
func logoutClearsBrowser(mode model.AuthMode) bool {
	return mode == model.AuthModeSSO
}

// parseRedirects turns the editor's multi-line text into a redirect map. Each
// non-blank line is "目标 -> 本地", where 目标 is an IP ("210.76.17.0", any
// port) or "IP:端口", and 本地 is a local "host:port" the connection should
// actually reach over the plain network. The arrow also accepts "->" written
// with any surrounding spaces, or a single "=".
func parseRedirects(text string) (map[string]string, error) {
	out := map[string]string{}
	for i, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		sep := ""
		switch {
		case strings.Contains(line, "->"):
			sep = "->"
		case strings.Contains(line, "→"):
			sep = "→"
		case strings.Contains(line, "="):
			sep = "="
		default:
			return nil, fmt.Errorf("第 %d 行缺少 -> （格式：目标 -> 本地）", i+1)
		}
		parts := strings.SplitN(line, sep, 2)
		from := strings.TrimSpace(parts[0])
		to := strings.TrimSpace(parts[1])
		if from == "" || to == "" {
			return nil, fmt.Errorf("第 %d 行的目标或本地为空", i+1)
		}
		// 目标必须是 IP 或 IP:端口。
		host := from
		if h, p, err := net.SplitHostPort(from); err == nil {
			host = h
			if n, perr := strconv.Atoi(p); perr != nil || n <= 0 || n > 65535 {
				return nil, fmt.Errorf("第 %d 行端口无效：%s", i+1, from)
			}
		}
		if net.ParseIP(host) == nil {
			return nil, fmt.Errorf("第 %d 行目标不是有效 IP：%s", i+1, from)
		}
		// 本地必须带端口。
		if _, _, err := net.SplitHostPort(to); err != nil {
			return nil, fmt.Errorf("第 %d 行本地需要是 host:端口：%s", i+1, to)
		}
		out[from] = to
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// formatRedirects renders a redirect map back to the editor's line format,
// sorted so the text is stable between openings.
func formatRedirects(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(k)
		b.WriteString(" -> ")
		b.WriteString(m[k])
	}
	return b.String()
}
