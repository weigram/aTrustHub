package atrust

import (
	"encoding/json"
	"net"
	"strconv"
	"strings"

	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/internal/ipresource"
	"github.com/mythologyli/zju-connect/log"
	"inet.af/netaddr"
)

type ClientResource struct {
	Data struct {
		AppList struct {
			Data struct {
				AppInfo []struct {
					ID          string `json:"id"`
					Name        string `json:"name"`
					AppName     string `json:"appName"`
					Description string `json:"description"`
					AppDesc     string `json:"appDesc"`
					IconPath    string `json:"iconPath"`
					AppIconPath string `json:"appIconPath"`
					GroupID     string `json:"groupId"`
					GroupName   string `json:"groupName"`
					Apps        []resourceApp
				}

				Config struct {
					NodeGroupConf struct {
						MajorNodeGroup struct {
							ID string
						}
						NodeGroupList []struct {
							AddressInfo []struct {
								Address string
								Type    string
							}
							ID string
						}
					}
				}
			}
		}

		SDPPolicy struct {
			Data struct {
				ClientOption struct {
					Tun0RTT struct {
						MaxIdleConnNum    int64 `json:"maxIdleConnNum"`
						MaxIdleLingerTime int64 `json:"maxIdleLingerTime"`
						MinIdleConnNum    int64 `json:"minIdleConnNum"`
						Enable            bool  `json:"enable"`
						PreConnNum        int64 `json:"preConnNum"`
					} `json:"tun0rtt"`

					DNSOption struct {
						FirstDNS  string
						SecondDNS string
					}

					DNSOptionV2 struct {
						FirstDNS  string
						SecondDNS string
					}
				}
			}
		}
	}
}

type resourceApp struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	AppName         string `json:"appName"`
	Description     string `json:"description"`
	AppDesc         string `json:"appDesc"`
	AccessModel     string `json:"accessModel"`
	SubModel        string `json:"subModel"`
	GroupID         string `json:"groupId"`
	GroupName       string `json:"groupName"`
	NodeGroupID     string `json:"nodeGroupId"`
	NodeGroupName   string `json:"nodeGroupName"`
	EnableTCPPrefL3 bool   `json:"enableTCPPrefL3"`
	AddrPretend     any    `json:"addrPretend"`
	AddressList     []resourceAddress
	AppAddress      string `json:"appAddress"`
	AccessAddress   string `json:"accessAddress"`
	AccessEntry     string `json:"accessEntry"`
	IconID          string `json:"iconId"`
	IconPath        string `json:"iconPath"`
	AppIconPath     string `json:"appIconPath"`
	IconType        string `json:"iconType"`
	Status          int    `json:"status"`
}

type resourceAddress struct {
	Protocol string   `json:"protocol"`
	Port     string   `json:"port"`
	Host     string   `json:"host"`
	IP       []string `json:"ip"`
}

// App is one application the server published to this user, as the
// workbench shows it.
type App struct {
	ID              string
	Name            string
	Description     string
	AccessModel     string
	SubModel        string
	GroupID         string
	GroupName       string
	NodeGroupID     string
	NodeGroupName   string
	IconID          string
	IconPath        string
	IconType        string
	AppAddress      string
	AccessAddress   string
	AccessEntry     string
	EnableTCPPrefL3 bool
	Addresses       []AppAddress
}

// AppAddress is one backend address of a tunnel application.
type AppAddress struct {
	Protocol string
	Host     string
	Port     string
}

// ParseApps returns the applications in a clientResource response, for
// callers that want the workbench list without logging in.
func ParseApps(data []byte) ([]App, error) {
	var clientResource ClientResource
	if err := json.Unmarshal(data, &clientResource); err != nil {
		return nil, err
	}
	return appsFromResource(&clientResource), nil
}

func appsFromResource(clientResource *ClientResource) []App {
	var apps []App
	for _, group := range clientResource.Data.AppList.Data.AppInfo {
		for _, appItem := range group.Apps {
			name := firstNonEmptyString(appItem.Name, appItem.AppName, group.Name, group.AppName)
			description := firstNonEmptyString(appItem.Description, appItem.AppDesc, group.Description, group.AppDesc)
			iconPath := firstNonEmptyString(appItem.IconPath, appItem.AppIconPath, group.IconPath, group.AppIconPath)
			app := App{
				ID:              appItem.ID,
				Name:            name,
				Description:     description,
				AccessModel:     appItem.AccessModel,
				SubModel:        appItem.SubModel,
				GroupID:         firstNonEmptyString(appItem.GroupID, group.GroupID),
				GroupName:       firstNonEmptyString(appItem.GroupName, group.GroupName),
				NodeGroupID:     appItem.NodeGroupID,
				NodeGroupName:   appItem.NodeGroupName,
				IconID:          appItem.IconID,
				IconPath:        iconPath,
				IconType:        appItem.IconType,
				AppAddress:      appItem.AppAddress,
				AccessAddress:   appItem.AccessAddress,
				AccessEntry:     appItem.AccessEntry,
				EnableTCPPrefL3: appItem.EnableTCPPrefL3,
			}
			for _, addr := range appItem.AddressList {
				host := addr.Host
				if host == "" && len(addr.IP) > 0 {
					host = addr.IP[0]
				}
				app.Addresses = append(app.Addresses, AppAddress{
					Protocol: addr.Protocol,
					Host:     host,
					Port:     addr.Port,
				})
			}
			if app.Name == "" && len(app.Addresses) > 0 {
				app.Name = app.Addresses[0].Host
			}
			apps = append(apps, app)
		}
	}
	return apps
}

func firstNonEmptyString(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func resourceAddrPretend(value any) bool {
	if value, ok := value.(bool); ok {
		return value
	}
	return true
}

func (c *Client) parseResource(resource []byte) error {
	log.Println("Parsing resource...")

	var clientResource ClientResource
	err := json.Unmarshal(resource, &clientResource)
	if err != nil {
		return err
	}
	c.resourceData = append([]byte(nil), resource...)
	c.apps = appsFromResource(&clientResource)

	ipSetBuilder := netaddr.IPSetBuilder{}
	c.ipResources = make([]client.IPResource, 0)
	c.domainResources = make(client.DomainResources)
	c.dnsResource = make(map[string][]net.IP)

	for _, app := range clientResource.Data.AppList.Data.AppInfo {
		for _, appItem := range app.Apps {
			if appItem.AccessModel != "L3VPN" {
				log.DebugPrintf("Ignore unsupported aTrust access model %q for app %s", appItem.AccessModel, appItem.ID)
				continue
			}
			for _, address := range appItem.AddressList {
				if address.Protocol == "tcp" || address.Protocol == "udp" || address.Protocol == "all" {
					// Handle port
					portStr := address.Port
					var portMin, portMax int
					if strings.Contains(portStr, "-") {
						// Handle port range
						ports := strings.Split(portStr, "-")
						if len(ports) != 2 {
							log.DebugPrintf("invalid port range: %s", portStr)
							continue
						}
						portMin, err = strconv.Atoi(ports[0])
						if err != nil {
							log.DebugPrintf("invalid port range: %s", portStr)
							continue
						}
						portMax, err = strconv.Atoi(ports[1])
						if err != nil {
							log.DebugPrintf("invalid port range: %s", portStr)
							continue
						}
					} else {
						// Handle single port
						portMin, err = strconv.Atoi(portStr)
						if err != nil {
							log.DebugPrintf("invalid port: %s", portStr)
							continue
						}
						portMax = portMin // Single port means min and max are the same
					}

					// Handle host
					hostStr := address.Host
					isDomain := false
					// First, try to parse the host as an IP address
					ip := net.ParseIP(hostStr)
					if ip == nil {
						// Try to parse as CIDR notation (e.g. 10.13.0.0/16)
						if _, ipNet, cidrErr := net.ParseCIDR(hostStr); cidrErr == nil {
							ip4 := ipNet.IP.To4()
							if ip4 != nil {
								ipMax4 := make(net.IP, len(ip4))
								for i := range ip4 {
									ipMax4[i] = ip4[i] | ^ipNet.Mask[i]
								}
								ipSetBuilder.AddPrefix(netaddr.MustParseIPPrefix(hostStr))

								c.ipResources = append(c.ipResources, client.IPResource{
									IPMin:           ip4.To16(),
									IPMax:           ipMax4.To16(),
									PortMin:         portMin,
									PortMax:         portMax,
									Protocol:        address.Protocol,
									AppID:           appItem.ID,
									NodeGroupID:     appItem.NodeGroupID,
									EnableTCPPrefL3: appItem.EnableTCPPrefL3,
								})

								log.DebugPrintf("Add CIDR: %s (%s ~ %s), Port range: %d ~ %d, [%s]", hostStr, ip4, ipMax4, portMin, portMax, address.Protocol)
							} else {
								log.DebugPrintf("IPv6 CIDR found: %s, skipping", hostStr)
							}
						} else if ipParts := strings.Split(hostStr, "-"); len(ipParts) == 2 {
							ipMin := net.ParseIP(ipParts[0])
							ipMax := net.ParseIP(ipParts[1])
							if ipMin != nil && ipMax != nil {
								// It's a range of IP addresses
								if ipMin.To4() != nil {
									ipSetBuilder.AddRange(netaddr.IPRangeFrom(netaddr.MustParseIP(ipMin.String()), netaddr.MustParseIP(ipMax.String())))

									c.ipResources = append(c.ipResources, client.IPResource{
										IPMin:           ipMin,
										IPMax:           ipMax,
										PortMin:         portMin,
										PortMax:         portMax,
										Protocol:        address.Protocol,
										AppID:           appItem.ID,
										NodeGroupID:     appItem.NodeGroupID,
										EnableTCPPrefL3: appItem.EnableTCPPrefL3,
									})

									log.DebugPrintf("Add IP range: %s ~ %s, Port range: %d ~ %d, [%s]", ipMin, ipMax, portMin, portMax, address.Protocol)
								} else {
									log.DebugPrintf("IPv6 address range found: %s ~ %s, skipping", ipMin, ipMax)
								}
							} else {
								isDomain = true
							}
						} else {
							isDomain = true
						}
					} else {
						// It's an IP address
						if ip.To4() != nil {
							ipSetBuilder.Add(netaddr.MustParseIP(ip.String()))

							c.ipResources = append(c.ipResources, client.IPResource{
								IPMin:           ip,
								IPMax:           ip,
								PortMin:         portMin,
								PortMax:         portMax,
								Protocol:        address.Protocol,
								AppID:           appItem.ID,
								NodeGroupID:     appItem.NodeGroupID,
								EnableTCPPrefL3: appItem.EnableTCPPrefL3,
							})

							log.DebugPrintf("Add IP: %s, Port range: %d ~ %d, [%s]", ip, portMin, portMax, address.Protocol)
						} else {
							log.DebugPrintf("IPv6 address found: %s, skipping", ip)
						}
					}

					if isDomain {
						domain := normalizePolicyDomain(hostStr)
						if domain == "" {
							log.DebugPrintf("Ignore unsupported domain pattern: %s", hostStr)
							continue
						}
						c.domainResources[domain] = append(c.domainResources[domain], client.DomainResource{
							PortMin:         portMin,
							PortMax:         portMax,
							Protocol:        address.Protocol,
							AppID:           appItem.ID,
							NodeGroupID:     appItem.NodeGroupID,
							EnableTCPPrefL3: appItem.EnableTCPPrefL3,
							AddrPretend:     resourceAddrPretend(appItem.AddrPretend),
						})

						log.DebugPrintf("Add domain: %s, Port range: %d ~ %d, [%s]", hostStr, portMin, portMax, address.Protocol)
					}

					// Handle DNS rules
					if address.IP != nil {
						if !isDomain {
							log.DebugPrintln("IP address found, but no domain name, skipping")
							continue
						}

						for _, ipStr := range address.IP {
							ip := net.ParseIP(ipStr)
							if ip != nil {
								if ip.To4() != nil {
									ipSetBuilder.Add(netaddr.MustParseIP(ip.String()))
									c.dnsResource[hostStr] = append(c.dnsResource[hostStr], ip)
									c.ipResources = append(c.ipResources, client.IPResource{
										IPMin: ip, IPMax: ip, PortMin: portMin, PortMax: portMax,
										Protocol: address.Protocol, AppID: appItem.ID, NodeGroupID: appItem.NodeGroupID,
										EnableTCPPrefL3: appItem.EnableTCPPrefL3,
									})
									log.DebugPrintf("Add DNS rule: %s -> %s", hostStr, ipStr)
								} else {
									log.DebugPrintf("IPv6 address found: %s, skipping", ip)
								}
							} else {
								log.DebugPrintf("Invalid IP: %s", ipStr)
							}
						}
					}
				}
			}
		}
	}

	dnsOption := clientResource.Data.SDPPolicy.Data.ClientOption.DNSOption
	if dnsOption.FirstDNS == "" {
		dnsOption = clientResource.Data.SDPPolicy.Data.ClientOption.DNSOptionV2
	}
	c.dnsServers = c.dnsServers[:0]
	for _, server := range []string{dnsOption.FirstDNS, dnsOption.SecondDNS} {
		if server != "" {
			c.dnsServers = append(c.dnsServers, server)
		}
	}
	if len(c.dnsServers) > 0 {
		c.dnsServer = c.dnsServers[0]
		log.DebugPrintf("Set DNS servers: %v", c.dnsServers)
	} else {
		c.dnsServer = ""
		log.DebugPrintf("No DNS server found")
	}
	c.MajorNodeGroup = clientResource.Data.AppList.Data.Config.NodeGroupConf.MajorNodeGroup.ID
	c.NodeGroups = make(map[string]NodeGroup)
	for _, nodeGroup := range clientResource.Data.AppList.Data.Config.NodeGroupConf.NodeGroupList {
		addresses := NodeGroup{}
		for _, addressInfo := range nodeGroup.AddressInfo {
			address := addressInfo.Address
			if address == "{{sdpcHost}}" {
				address = c.serverAddress
			}
			if !strings.Contains(address, ":") {
				address += ":441"
			}
			switch strings.ToLower(addressInfo.Type) {
			case "wan":
				addresses.WAN = append(addresses.WAN, address)
			case "lan":
				addresses.LAN = append(addresses.LAN, address)
			default:
				log.DebugPrintf("Ignore node with unsupported type %q: %s", addressInfo.Type, address)
			}

			// Remove ip from ipSetBuilder to prevent circular routing
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				continue
			}
			ip := net.ParseIP(host)
			if ip != nil && ip.To4() != nil {
				ipSetBuilder.Remove(netaddr.MustParseIP(ip.String()))
				log.DebugPrintf("Remove IP from IP set to prevent circular routing: %s", ip)
			}
		}
		c.NodeGroups[nodeGroup.ID] = addresses
		log.DebugPrintf(
			"Node Group ID: %s, WAN Addresses: %v, LAN Addresses: %v",
			nodeGroup.ID,
			addresses.WAN,
			addresses.LAN,
		)
	}

	c.ipSet, _ = ipSetBuilder.IPSet()
	c.resourceIndex = ipresource.New(c.ipResources)

	return nil
}

func normalizePolicyDomain(domain string) string {
	domain = strings.TrimSpace(domain)
	if strings.HasPrefix(domain, "*.") {
		return domain[1:]
	}
	if strings.Contains(domain, "*") {
		return ""
	}
	return domain
}
