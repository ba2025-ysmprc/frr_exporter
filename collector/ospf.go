package collector

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	ospfSubsystem     = "ospf"
	frrOSPFInstances  = kingpin.Flag("collector.ospf.instances", "Comma-separated list of instance IDs if using multiple OSPF instances").Default("").String()
	ospfExportDetails = kingpin.Flag("collector.ospf.export-details", "Export detailed OSPF LSA and route information").Default("true").Bool()
)

func init() {
	registerCollector(ospfSubsystem, enabledByDefault, NewOSPFCollector)
}

type ospfCollector struct {
	logger        *slog.Logger
	descriptions  map[string]*prometheus.Desc
	instanceIDs   []int
	lastRoutes    []OSFRoute
	lastLSAs      []OSFLSA
	lastNeighbors []OSFNeighbor
	lastChange    time.Time
	mu            sync.Mutex
}

type OSFRoute struct {
	VRF       string `json:"vrf"`
	Area      string `json:"area"`
	Prefix    string `json:"prefix"`
	NextHop   string `json:"nextHop"`
	Interface string `json:"interface"`
	Cost      int    `json:"cost"`
	Type      string `json:"type"`
	Tag       int    `json:"tag"`
}

type OSFLSA struct {
	VRF       string `json:"vrf"`
	Area      string `json:"area"`
	Type      string `json:"type"`
	ID        string `json:"id"`
	AdvRouter string `json:"advRouter"`
	Sequence  int    `json:"sequence"`
	Checksum  string `json:"checksum"`
	Age       int    `json:"age"`
}

type OSFNeighbor struct {
	VRF        string `json:"vrf"`
	Area       string `json:"area"`
	Interface  string `json:"interface"`
	NeighborID string `json:"neighborId"`
	IPAddress  string `json:"ipAddress"`
	State      string `json:"state"`
}

type ospfIface struct {
	NbrCount          uint32 `json:"nbrCount"`
	NbrAdjacentCount  uint32 `json:"nbrAdjacentCount"`
	Area              string `json:"area"`
	TimerPassiveIface bool   `json:"timerPassiveInterface"`
}

func NewOSPFCollector(logger *slog.Logger) (Collector, error) {
	var instanceIDs []int
	if len(*frrOSPFInstances) > 0 {
		if *vtyshEnable {
			return nil, fmt.Errorf("cannot use --frr.vtysh with --collector.ospf.instances")
		}
		instances := strings.Split(*frrOSPFInstances, ",")
		for _, id := range instances {
			i, err := strconv.Atoi(id)
			if err != nil {
				return nil, fmt.Errorf("unable to parse instance ID %s: %w", id, err)
			}
			instanceIDs = append(instanceIDs, i)
		}
	}

	return &ospfCollector{
		logger:       logger,
		instanceIDs:  instanceIDs,
		descriptions: getOSPFDesc(),
		lastChange:   time.Now(),
	}, nil
}

func getOSPFDesc() map[string]*prometheus.Desc {
	baseLabels := []string{"vrf", "iface", "area"}
	if len(*frrOSPFInstances) > 0 {
		baseLabels = append(baseLabels, "instance")
	}

	return map[string]*prometheus.Desc{
		// Original interface metrics
		"ospfIfaceNeigh": colPromDesc(
			ospfSubsystem,
			"neighbors_total",
			"Number of neighbors detected",
			baseLabels,
		),
		"ospfIfaceNeighAdj": colPromDesc(
			ospfSubsystem,
			"neighbor_adjacencies_total",
			"Number of neighbor adjacencies formed",
			baseLabels,
		),

		// Enhanced neighbor metrics
		"neighbor_state": colPromDesc(
			ospfSubsystem,
			"neighbor_state",
			"OSPF neighbor state (1=Full, 2=Down, etc)",
			append(baseLabels, "neighbor_id", "neighbor_ip"),
		),

		// LSA metrics
		"lsa_count": colPromDesc(
			ospfSubsystem,
			"lsa_count_total",
			"Count of LSAs by type",
			[]string{"vrf", "area", "lsa_type"},
		),
		"lsa_detail": colPromDesc(
			ospfSubsystem,
			"lsa_detail",
			"Detailed LSA information",
			[]string{"vrf", "area", "lsa_type", "lsa_id", "adv_router", "sequence"},
		),

		// Route metrics
		"route_count": colPromDesc(
			ospfSubsystem,
			"route_count_total",
			"Count of routes by type",
			[]string{"vrf", "area", "route_type"},
		),
		"route_detail": colPromDesc(
			ospfSubsystem,
			"route_detail",
			"Detailed route information",
			[]string{"vrf", "area", "prefix", "next_hop", "interface", "route_type"},
		),
		"route_changes": colPromDesc(
			ospfSubsystem,
			"route_changes_total",
			"Route changes since last scrape",
			[]string{"vrf", "area", "change_type"},
		),
	}
}

func (c *ospfCollector) Update(ch chan<- prometheus.Metric) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// First collect interface metrics (original functionality)
	if err := c.collectInterfaceMetrics(ch); err != nil {
		return fmt.Errorf("interface metrics collection failed: %w", err)
	}

	// Then collect enhanced metrics
	var wg sync.WaitGroup
	var errs []error
	var errMu sync.Mutex

	collectFunc := func(f func(chan<- prometheus.Metric) error) {
		defer wg.Done()
		if err := f(ch); err != nil {
			errMu.Lock()
			errs = append(errs, err)
			errMu.Unlock()
		}
	}

	wg.Add(3)
	go collectFunc(c.collectNeighborMetrics)
	go collectFunc(c.collectLSAMetrics)
	go collectFunc(c.collectRouteMetrics)
	wg.Wait()

	if len(errs) > 0 {
		return fmt.Errorf("OSPF collection completed with errors: %v", errs)
	}

	return nil
}

// Original interface metrics collection
func (c *ospfCollector) collectInterfaceMetrics(ch chan<- prometheus.Metric) error {
	cmd := "show ip ospf vrf all interface json"

	if len(c.instanceIDs) > 0 {
		for _, id := range c.instanceIDs {
			jsonOSPFInterface, err := executeOSPFMultiInstanceCommand(cmd, id)
			if err != nil {
				return err
			}

			if err = c.processOSPFInterface(ch, jsonOSPFInterface, id); err != nil {
				return cmdOutputProcessError(cmd, string(jsonOSPFInterface), err)
			}
		}
		return nil
	}

	jsonOSPFInterface, err := executeOSPFCommand(cmd)
	if err != nil {
		return err
	}

	if err = c.processOSPFInterface(ch, jsonOSPFInterface, 0); err != nil {
		return cmdOutputProcessError(cmd, string(jsonOSPFInterface), err)
	}
	return nil
}

func (c *ospfCollector) processOSPFInterface(ch chan<- prometheus.Metric, jsonOSPFInterface []byte, instanceID int) error {
	var jsonMap map[string]json.RawMessage
	if err := json.Unmarshal(jsonOSPFInterface, &jsonMap); err != nil {
		return fmt.Errorf("cannot unmarshal ospf interface json: %s", err)
	}

	for vrfName, vrfData := range jsonMap {
		var vrfInstance map[string]json.RawMessage
		if err := json.Unmarshal(vrfData, &vrfInstance); err != nil {
			return fmt.Errorf("cannot unmarshal VRF instance json: %s", err)
		}

		for key, value := range vrfInstance {
			switch key {
			case "vrfName", "vrfId":
				continue
			case "interfaces":
				var ifaces map[string]json.RawMessage
				if err := json.Unmarshal(value, &ifaces); err != nil {
					return fmt.Errorf("cannot unmarshal interfaces: %s", err)
				}
				for ifaceName, ifaceData := range ifaces {
					var iface ospfIface
					if err := json.Unmarshal(ifaceData, &iface); err != nil {
						return fmt.Errorf("cannot unmarshal interface %s: %s", ifaceName, err)
					}
					if !iface.TimerPassiveIface {
						labels := []string{strings.ToLower(vrfName), ifaceName, iface.Area}
						c.ospfInterfaceMetrics(ch, iface, labels, instanceID)
					}
				}
			default:
				// Handle direct interface entries
				var iface ospfIface
				if err := json.Unmarshal(value, &iface); err != nil {
					return fmt.Errorf("cannot unmarshal interface %s: %s", key, err)
				}
				if !iface.TimerPassiveIface {
					labels := []string{strings.ToLower(vrfName), key, iface.Area}
					c.ospfInterfaceMetrics(ch, iface, labels, instanceID)
				}
			}
		}
	}
	return nil
}

func (c *ospfCollector) ospfInterfaceMetrics(ch chan<- prometheus.Metric, iface ospfIface, labels []string, instanceID int) {
	// Ensure we don't modify the original slice
	metricLabels := make([]string, len(labels))
	copy(metricLabels, labels)

	if instanceID != 0 {
		// Only add instance label if enabled
		if len(*frrOSPFInstances) > 0 {
			metricLabels = append(metricLabels, strconv.Itoa(instanceID))
		}
	}
	newGauge(ch, c.descriptions["ospfIfaceNeigh"], float64(iface.NbrCount), metricLabels...)
	newGauge(ch, c.descriptions["ospfIfaceNeighAdj"], float64(iface.NbrAdjacentCount), metricLabels...)
}

// Enhanced metrics collection
func (c *ospfCollector) collectNeighborMetrics(ch chan<- prometheus.Metric) error {
	cmd := "show ip ospf vrf all neighbor detail json"
	output, err := executeOSPFCommand(cmd)
	if err != nil {
		return fmt.Errorf("executing neighbor command: %w", err)
	}

	var neighbors []OSFNeighbor
	if err := json.Unmarshal(output, &neighbors); err != nil {
		return fmt.Errorf("parsing neighbor JSON: %w", err)
	}

	for _, n := range neighbors {
		stateValue := mapOSPFStateToValue(n.State)
		labels := []string{n.VRF, n.Interface, n.Area, n.NeighborID, n.IPAddress}
		if len(*frrOSPFInstances) > 0 {
			labels = append(labels, "0")
		}
		newGauge(ch, c.descriptions["neighbor_state"], stateValue, labels...)
	}

	c.lastNeighbors = neighbors
	return nil
}

func (c *ospfCollector) collectLSAMetrics(ch chan<- prometheus.Metric) error {
	cmd := "show ip ospf vrf all database json"
	output, err := executeOSPFCommand(cmd)
	if err != nil {
		return fmt.Errorf("executing LSA command: %w", err)
	}

	var lsas []OSFLSA
	if err := json.Unmarshal(output, &lsas); err != nil {
		return fmt.Errorf("parsing LSA JSON: %w", err)
	}

	typeCount := make(map[string]int)
	for _, lsa := range lsas {
		typeCount[lsa.Type]++

		if *ospfExportDetails {
			labels := []string{lsa.VRF, lsa.Area, lsa.Type, lsa.ID, lsa.AdvRouter, strconv.Itoa(lsa.Sequence)}
			newGauge(ch, c.descriptions["lsa_detail"], 1, labels...)
		}
	}

	for lsaType, count := range typeCount {
		labels := []string{"default", "0.0.0.0", lsaType}
		newGauge(ch, c.descriptions["lsa_count"], float64(count), labels...)
	}

	c.lastLSAs = lsas
	return nil
}

func (c *ospfCollector) collectRouteMetrics(ch chan<- prometheus.Metric) error {
	cmd := "show ip ospf vrf all route json"
	output, err := executeOSPFCommand(cmd)
	if err != nil {
		return fmt.Errorf("executing route command: %w", err)
	}

	var routes []OSFRoute
	if err := json.Unmarshal(output, &routes); err != nil {
		return fmt.Errorf("parsing route JSON: %w", err)
	}

	typeCount := make(map[string]int)
	var added, removed int

	if c.lastRoutes != nil {
		added, removed = diffRoutes(c.lastRoutes, routes)
	}

	for _, route := range routes {
		typeCount[route.Type]++

		if *ospfExportDetails {
			labels := []string{route.VRF, route.Area, route.Prefix, route.NextHop, route.Interface, route.Type}
			newGauge(ch, c.descriptions["route_detail"], 1, labels...)
		}
	}

	for routeType, count := range typeCount {
		labels := []string{"default", "0.0.0.0", routeType}
		newGauge(ch, c.descriptions["route_count"], float64(count), labels...)
	}

	if added > 0 || removed > 0 {
		changeLabels := []string{"default", "0.0.0.0"}
		newCounter(ch, c.descriptions["route_changes"], float64(added), append(changeLabels, "added")...)
		newCounter(ch, c.descriptions["route_changes"], float64(removed), append(changeLabels, "removed")...)
		c.lastChange = time.Now()
	}

	c.lastRoutes = routes
	return nil
}

func diffRoutes(prev, current []OSFRoute) (added, removed int) {
	prevMap := make(map[string]struct{})
	for _, r := range prev {
		prevMap[r.Prefix] = struct{}{}
	}

	currentMap := make(map[string]struct{})
	for _, r := range current {
		currentMap[r.Prefix] = struct{}{}
		if _, exists := prevMap[r.Prefix]; !exists {
			added++
		}
	}

	for prefix := range prevMap {
		if _, exists := currentMap[prefix]; !exists {
			removed++
		}
	}

	return added, removed
}

func mapOSPFStateToValue(state string) float64 {
	switch strings.ToLower(state) {
	case "full":
		return 1
	case "down":
		return 2
	case "attempt":
		return 3
	case "init":
		return 4
	case "2way":
		return 5
	case "exstart":
		return 6
	case "exchange":
		return 7
	case "loading":
		return 8
	default:
		return 0
	}
}
