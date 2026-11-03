package vpn

import (
	zcclient "github.com/mythologyli/zju-connect/client"
)

// dropDisabledApps removes the addresses of applications the user took out of
// the tunnel. Their IP ranges can clash with the local network or with another
// access point, and then the only fix is not to route them at all.
func dropDisabledApps(disabled []string, ips []zcclient.IPResource, domains zcclient.DomainResources) ([]zcclient.IPResource, zcclient.DomainResources) {
	if len(disabled) == 0 {
		return ips, domains
	}
	off := make(map[string]bool, len(disabled))
	for _, id := range disabled {
		off[id] = true
	}
	keptIP := make([]zcclient.IPResource, 0, len(ips))
	for _, r := range ips {
		if !off[r.AppID] {
			keptIP = append(keptIP, r)
		}
	}
	keptDomain := zcclient.DomainResources{}
	for name, list := range domains {
		keep := make([]zcclient.DomainResource, 0, len(list))
		for _, r := range list {
			if !off[r.AppID] {
				keep = append(keep, r)
			}
		}
		// A domain whose every entry was disabled must not be answered at
		// all, so it is left out instead of registered with an empty list.
		if len(keep) > 0 {
			keptDomain[name] = keep
		}
	}
	return keptIP, keptDomain
}
