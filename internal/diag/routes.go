package diag

import (
	"os/exec"
	"strings"
)

// RouteEntry represents a single routing table entry.
type RouteEntry struct {
	Destination string `json:"destination"`
	Gateway     string `json:"gateway"`
	Interface   string `json:"interface"`
	Flags       string `json:"flags"`
}

// GetRoutingTable returns the current OS routing table.
func GetRoutingTable() ([]RouteEntry, error) {
	return getRoutesDarwinFull()
}

func getRoutesDarwinFull() ([]RouteEntry, error) {
	out, err := exec.Command("netstat", "-rn", "-f", "inet").CombinedOutput()
	if err != nil {
		return nil, err
	}
	var routes []RouteEntry
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		// Skip header lines
		if fields[0] == "Destination" || fields[0] == "Routing" || fields[0] == "Internet:" {
			continue
		}
		entry := RouteEntry{
			Destination: fields[0],
			Gateway:     fields[1],
		}
		if len(fields) > 2 {
			entry.Flags = fields[2]
		}
		if len(fields) > 3 {
			entry.Interface = fields[3]
		}
		routes = append(routes, entry)
	}
	return routes, nil
}
