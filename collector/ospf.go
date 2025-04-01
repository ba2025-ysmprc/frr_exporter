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
	logger       *slog.Logger
	descriptions map[string]*prometheus.Desc
	instanceIDs  []int
	lastRoutes   []OSFRoute
	lastChange   time.Time
	mu           sync.Mutex
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
	Type2Cost int    `json:"type2cost,omitempty"`
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

// Response structs that match FRR's JSON output
type OSPFNeighborResponse struct {
	Default struct {
		VRFName   string `json:"vrfName"`
		Neighbors map[string][]struct {
			IfaceName string `json:"ifaceName"`
			AreaID    string `json:"areaId"`
			NbrState  string `json:"nbrState"`
			IPAddress string `json:"ifaceAddress"`
		} `json:"neighbors"`
	} `json:"default"`
}

type OSPFLSAResponse struct {
	Default struct {
		VRFName string `json:"vrfName"`
		Areas   map[string]struct {
			RouterLinkStates []struct {
				LSID             string `json:"lsId"`
				AdvertisedRouter string `json:"advertisedRouter"`
				LsaAge           int    `json:"lsaAge"`
				SequenceNumber   string `json:"sequenceNumber"`
				Checksum         string `json:"checksum"`
			} `json:"routerLinkStates"`
			NetworkLinkStates []struct {
				LSID             string `json:"lsId"`
				AdvertisedRouter string `json:"advertisedRouter"`
				LsaAge           int    `json:"lsaAge"`
			} `json:"networkLinkStates"`
			SummaryLinkStates []struct {
				LSID             string `json:"lsId"`
				AdvertisedRouter string `json:"advertisedRouter"`
				SummaryAddress   string `json:"summaryAddress"`
			} `json:"summaryLinkStates"`
		} `json:"areas"`
		ASExternalLinkStates []struct {
			LSID             string `json:"lsId"`
			AdvertisedRouter string `json:"advertisedRouter"`
			Route            string `json:"route"`
			LsaAge           int    `json:"lsaAge"`
		} `json:"asExternalLinkStates"`
	} `json:"default"`
}

/*
- I needed to go for another approach because by mapping the response like
- in OSPFLSAResponse, I always got an silent error.
*/
type OSPFRouteResponse struct {
	Default map[string]interface{} `json:"default"`
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
		"neighbor_state": colPromDesc(
			ospfSubsystem,
			"neighbor_state",
			"OSPF neighbor state (1=Full, 2=Down, etc)",
			append(baseLabels, "neighbor_id", "neighbor_ip"),
		),
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

	if err := c.collectInterfaceMetrics(ch); err != nil {
		return fmt.Errorf("interface metrics collection failed: %w", err)
	}

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
	metricLabels := make([]string, len(labels))
	copy(metricLabels, labels)

	if instanceID != 0 && len(*frrOSPFInstances) > 0 {
		metricLabels = append(metricLabels, strconv.Itoa(instanceID))
	}
	newGauge(ch, c.descriptions["ospfIfaceNeigh"], float64(iface.NbrCount), metricLabels...)
	newGauge(ch, c.descriptions["ospfIfaceNeighAdj"], float64(iface.NbrAdjacentCount), metricLabels...)
}

func (c *ospfCollector) collectNeighborMetrics(ch chan<- prometheus.Metric) error {
	cmd := "show ip ospf vrf all neighbor detail json"
	output, err := executeOSPFCommand(cmd)
	if err != nil {
		return fmt.Errorf("executing neighbor command: %w", err)
	}

	var response OSPFNeighborResponse
	if err := json.Unmarshal(output, &response); err != nil {
		c.logger.Error("Failed to parse OSPF neighbor JSON", "error", err, "output", string(output))
		return fmt.Errorf("parsing neighbor JSON: %w", err)
	}

	for neighborID, neighbors := range response.Default.Neighbors {
		for _, n := range neighbors {
			stateValue := mapOSPFStateToValue(n.NbrState)
			labels := []string{"default", n.IfaceName, n.AreaID, neighborID, n.IPAddress}
			if len(*frrOSPFInstances) > 0 {
				labels = append(labels, "0")
			}
			newGauge(ch, c.descriptions["neighbor_state"], stateValue, labels...)
		}
	}
	return nil
}

func (c *ospfCollector) collectLSAMetrics(ch chan<- prometheus.Metric) error {
	cmd := "show ip ospf vrf all database json"
	output, err := executeOSPFCommand(cmd)
	if err != nil {
		return fmt.Errorf("executing LSA command: %w", err)
	}

	var response OSPFLSAResponse
	if err := json.Unmarshal(output, &response); err != nil {
		c.logger.Error("Failed to parse OSPF LSA JSON", "error", err, "output", string(output))
		return fmt.Errorf("parsing LSA JSON: %w", err)
	}

	typeCount := make(map[string]int)
	for _, area := range response.Default.Areas {
		for _, lsa := range area.RouterLinkStates {
			typeCount["router"]++
			if *ospfExportDetails {
				labels := []string{"default", lsa.LSID[:strings.Index(lsa.LSID, ".")], "router", lsa.LSID, lsa.AdvertisedRouter, lsa.SequenceNumber}
				newGauge(ch, c.descriptions["lsa_detail"], 1, labels...)
			}
		}
		for _, lsa := range area.NetworkLinkStates {
			typeCount["network"]++
			if *ospfExportDetails {
				labels := []string{"default", lsa.LSID[:strings.Index(lsa.LSID, ".")], "network", lsa.LSID, lsa.AdvertisedRouter, "0"}
				newGauge(ch, c.descriptions["lsa_detail"], 1, labels...)
			}
		}
		for _, lsa := range area.SummaryLinkStates {
			typeCount["summary"]++
			if *ospfExportDetails {
				labels := []string{"default", lsa.LSID[:strings.Index(lsa.LSID, ".")], "summary", lsa.LSID, lsa.AdvertisedRouter, "0"}
				newGauge(ch, c.descriptions["lsa_detail"], 1, labels...)
			}
		}
	}
	for _, lsa := range response.Default.ASExternalLinkStates {
		typeCount["external"]++
		if *ospfExportDetails {
			labels := []string{"default", "0.0.0.0", "external", lsa.LSID, lsa.AdvertisedRouter, "0"}
			newGauge(ch, c.descriptions["lsa_detail"], 1, labels...)
		}
	}

	for lsaType, count := range typeCount {
		labels := []string{"default", "0.0.0.0", lsaType}
		newGauge(ch, c.descriptions["lsa_count"], float64(count), labels...)
	}

	return nil
}

func (c *ospfCollector) collectRouteMetrics(ch chan<- prometheus.Metric) error {
	cmd := "show ip ospf vrf all route json"
	output, err := executeOSPFCommand(cmd)
	if err != nil {
		return fmt.Errorf("executing route command: %w", err)
	}

	var response OSPFRouteResponse
	if err := json.Unmarshal(output, &response); err != nil {
		c.logger.Error("Failed to parse OSPF route JSON", "error", err, "output", string(output))
		return fmt.Errorf("parsing route JSON: %w", err)
	}

	if response.Default == nil {
		c.logger.Warn("No default VRF found in OSPF route output")
		return nil
	}

	vrfName, _ := response.Default["vrfName"].(string)
	if vrfName == "" {
		vrfName = "default"
	}

	typeCount := make(map[string]int)
	var currentRoutes []OSFRoute

	for key, value := range response.Default {
		if key == "vrfName" || key == "vrfId" {
			continue
		}

		routeDetails, ok := value.(map[string]interface{})
		if !ok {
			continue
		}

		routeType, _ := routeDetails["routeType"].(string)
		routeType = strings.TrimSpace(routeType)
		typeCount[routeType]++

		cost := 0
		if costVal, ok := routeDetails["cost"].(float64); ok {
			cost = int(costVal)
		}

		area, _ := routeDetails["area"].(string)

		tag := 0
		if tagVal, ok := routeDetails["tag"].(float64); ok {
			tag = int(tagVal)
		}

		type2Cost := 0
		if type2CostVal, ok := routeDetails["type2cost"].(float64); ok {
			type2Cost = int(type2CostVal)
		}

		nextHop := ""
		iface := ""
		if nexthops, ok := routeDetails["nexthops"].([]interface{}); ok && len(nexthops) > 0 {
			if nh, ok := nexthops[0].(map[string]interface{}); ok {
				nextHop, _ = nh["ip"].(string)
				nextHop = strings.TrimSpace(nextHop)

				if directlyAttached, ok := nh["directlyAttachedTo"].(string); ok && directlyAttached != "" {
					iface = directlyAttached
				} else if via, ok := nh["via"].(string); ok {
					iface = via
				}
			}
		}

		currentRoutes = append(currentRoutes, OSFRoute{
			VRF:       vrfName,
			Area:      area,
			Prefix:    key,
			NextHop:   nextHop,
			Interface: iface,
			Cost:      cost,
			Type:      routeType,
			Tag:       tag,
			Type2Cost: type2Cost,
		})

		if *ospfExportDetails {
			labels := []string{
				vrfName,
				area,
				key,
				nextHop,
				iface,
				routeType,
			}
			newGauge(ch, c.descriptions["route_detail"], float64(cost), labels...)
		}
	}

	for routeType, count := range typeCount {
		labels := []string{vrfName, "0.0.0.0", routeType}
		newGauge(ch, c.descriptions["route_count"], float64(count), labels...)
	}

	var added, removed int
	if c.lastRoutes != nil {
		added, removed = diffRoutes(c.lastRoutes, currentRoutes)
		newCounter(ch, c.descriptions["route_changes"], float64(added), vrfName, "0.0.0.0", "added")
		newCounter(ch, c.descriptions["route_changes"], float64(removed), vrfName, "0.0.0.0", "removed")
	}

	c.lastRoutes = currentRoutes
	return nil
}

func diffRoutes(prev, current []OSFRoute) (added, removed int) {
	prevMap := make(map[string]OSFRoute)
	for _, r := range prev {
		prevMap[r.Prefix] = r
	}

	currentMap := make(map[string]OSFRoute)
	for _, r := range current {
		currentMap[r.Prefix] = r
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
	// Extract just the state part (before / if present)
	baseState := strings.Split(state, "/")[0]
	switch strings.ToLower(baseState) {
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
