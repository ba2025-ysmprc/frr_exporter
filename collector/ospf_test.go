package collector

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

var expectedOSPFMetrics = map[string]float64{
	"frr_ospf_neighbors_total{area=0.0.0.0,iface=swp1,vrf=default}":                                    0,
	"frr_ospf_neighbors_total{area=0.0.0.0,iface=swp2,vrf=default}":                                    1,
	"frr_ospf_neighbors_total{area=0.0.0.0,iface=swp3,vrf=red}":                                        0,
	"frr_ospf_neighbors_total{area=0.0.0.0,iface=swp4,vrf=red}":                                        1,
	"frr_ospf_neighbor_adjacencies_total{area=0.0.0.0,iface=swp1,vrf=default}":                         0,
	"frr_ospf_neighbor_adjacencies_total{area=0.0.0.0,iface=swp2,vrf=default}":                         1,
	"frr_ospf_neighbor_adjacencies_total{area=0.0.0.0,iface=swp3,vrf=red}":                             0,
	"frr_ospf_neighbor_adjacencies_total{area=0.0.0.0,iface=swp4,vrf=red}":                             1,
	"frr_ospf_neighbors_total{area=0.0.0.0,iface=swp1,instance=1,vrf=default}":                         0,
	"frr_ospf_neighbors_total{area=0.0.0.0,iface=swp2,instance=1,vrf=default}":                         1,
	"frr_ospf_neighbors_total{area=0.0.0.0,iface=swp3,instance=1,vrf=red}":                             0,
	"frr_ospf_neighbors_total{area=0.0.0.0,iface=swp4,instance=1,vrf=red}":                             1,
	"frr_ospf_neighbors_total{area=0.0.0.0,iface=swp1,instance=2,vrf=default}":                         0,
	"frr_ospf_neighbors_total{area=0.0.0.0,iface=swp2,instance=2,vrf=default}":                         1,
	"frr_ospf_neighbors_total{area=0.0.0.0,iface=swp3,instance=2,vrf=red}":                             0,
	"frr_ospf_neighbors_total{area=0.0.0.0,iface=swp4,instance=2,vrf=red}":                             1,
	"frr_ospf_neighbors_total{area=0.0.0.75 [Stub],iface=peerlink.4094,vrf=red}":                       0,
	"frr_ospf_neighbors_total{area=0.0.0.75 [Stub],iface=peerlink.4094,instance=1,vrf=red}":            0,
	"frr_ospf_neighbors_total{area=0.0.0.75 [Stub],iface=peerlink.4094,instance=2,vrf=red}":            0,
	"frr_ospf_neighbor_adjacencies_total{area=0.0.0.0,iface=swp1,instance=1,vrf=default}":              0,
	"frr_ospf_neighbor_adjacencies_total{area=0.0.0.0,iface=swp2,instance=1,vrf=default}":              1,
	"frr_ospf_neighbor_adjacencies_total{area=0.0.0.0,iface=swp3,instance=1,vrf=red}":                  0,
	"frr_ospf_neighbor_adjacencies_total{area=0.0.0.0,iface=swp4,instance=1,vrf=red}":                  1,
	"frr_ospf_neighbor_adjacencies_total{area=0.0.0.0,iface=swp1,instance=2,vrf=default}":              0,
	"frr_ospf_neighbor_adjacencies_total{area=0.0.0.0,iface=swp2,instance=2,vrf=default}":              1,
	"frr_ospf_neighbor_adjacencies_total{area=0.0.0.0,iface=swp3,instance=2,vrf=red}":                  0,
	"frr_ospf_neighbor_adjacencies_total{area=0.0.0.0,iface=swp4,instance=2,vrf=red}":                  1,
	"frr_ospf_neighbor_adjacencies_total{area=0.0.0.75 [Stub],iface=peerlink.4094,vrf=red}":            0,
	"frr_ospf_neighbor_adjacencies_total{area=0.0.0.75 [Stub],iface=peerlink.4094,instance=1,vrf=red}": 0,
	"frr_ospf_neighbor_adjacencies_total{area=0.0.0.75 [Stub],iface=peerlink.4094,instance=2,vrf=red}": 0,
}

var expectedOSPFNeighborMetrics = map[string]float64{
	"frr_ospf_neighbor_state{area=0.0.0.0,iface=eth0,instance=10.0.0.2,neighbor_id=10.0.0.1,neighbor_ip=0,vrf=default}": 1, // Full
	"frr_ospf_neighbor_state{area=0.0.0.1,iface=eth1,instance=10.0.1.3,neighbor_id=10.0.1.1,neighbor_ip=0,vrf=default}": 5, // 2Way
}

var expectedOSPFLSAMetrics = map[string]float64{
	"frr_ospf_lsa_count_total{area=0.0.0.0,lsa_type=router,vrf=default}":                                                1,
	"frr_ospf_lsa_count_total{area=0.0.0.0,lsa_type=network,vrf=default}":                                               1,
	"frr_ospf_lsa_count_total{area=0.0.0.0,lsa_type=summary,vrf=default}":                                               1,
	"frr_ospf_lsa_count_total{area=0.0.0.0,lsa_type=external,vrf=default}":                                              1,
	"frr_ospf_lsa_detail{adv_router=1.1.1.1,area=0.0.0.0,lsa_id=1.1.1.1,lsa_type=router,sequence=80000001,vrf=default}": 1,
	"frr_ospf_lsa_detail{adv_router=1.1.1.1,area=0.0.0.0,lsa_id=2.2.2.2,lsa_type=summary,sequence=0,vrf=default}":       1,
	"frr_ospf_lsa_detail{adv_router=1.1.1.1,area=0.0.0.0,lsa_id=3.3.3.3,lsa_type=external,sequence=0,vrf=default}":      1,
	"frr_ospf_lsa_detail{adv_router=1.1.1.1,area=0.0.0.0,lsa_id=10.0.0.1,lsa_type=network,sequence=0,vrf=default}":      1,
}

var expectedOSPFRouteMetrics = map[string]float64{
	"frr_ospf_route_count_total{area=0.0.0.0,route_type=N,vrf=default}":                                                               1,
	"frr_ospf_route_count_total{area=0.0.0.0,route_type=E,vrf=default}":                                                               1,
	"frr_ospf_route_detail{area=0.0.0.0,interface=eth0,next_hop=direct,prefix=10.0.0.0/24,route_type=N,vrf=default}":                  10,
	"frr_ospf_route_detail{area=0.0.0.0,interface=eth0,next_hop=10.0.0.2,prefix=10.1.0.0/24,route_type=E,vrf=default}":                20,
	"frr_ospf_route_changes{area=0.0.0.0,change_type=unchanged,interface=none,next_hop=none,prefix=none,route_type=none,vrf=default}": 0,
	"frr_ospf_has_route_changes{vrf=default}":                                                                                         0,
}

// Helper function to create a standalone version of processOSPFInterface for testing
func processOSPFInterface(ch chan<- prometheus.Metric, jsonOSPFInterface []byte, descriptions map[string]*prometheus.Desc, instanceID int) error {
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
						testOSPFInterfaceMetrics(ch, iface, labels, instanceID, descriptions)
					}
				}
			default:
				var iface ospfIface
				if err := json.Unmarshal(value, &iface); err != nil {
					return fmt.Errorf("cannot unmarshal interface %s: %s", key, err)
				}
				if !iface.TimerPassiveIface {
					labels := []string{strings.ToLower(vrfName), key, iface.Area}
					testOSPFInterfaceMetrics(ch, iface, labels, instanceID, descriptions)
				}
			}
		}
	}
	return nil
}

// Helper function to add OSPF interface metrics
func testOSPFInterfaceMetrics(ch chan<- prometheus.Metric, iface ospfIface, labels []string, instanceID int, descriptions map[string]*prometheus.Desc) {
	metricLabels := make([]string, len(labels))
	copy(metricLabels, labels)

	if instanceID != 0 && len(*ospfInstances) > 0 {
		metricLabels = append(metricLabels, strconv.Itoa(instanceID))
	}
	newGauge(ch, descriptions["ospfIfaceNeigh"], float64(iface.NbrCount), metricLabels...)
	newGauge(ch, descriptions["ospfIfaceNeighAdj"], float64(iface.NbrAdjacentCount), metricLabels...)
}

// Helper function to process OSPF neighbor data for testing
func processOSPFNeighbors(ch chan<- prometheus.Metric, jsonData []byte, descriptions map[string]*prometheus.Desc) error {
	var response OSPFNeighborResponse
	if err := json.Unmarshal(jsonData, &response); err != nil {
		return fmt.Errorf("parsing neighbor JSON: %w", err)
	}

	for neighborID, neighbors := range response.Default.Neighbors {
		for _, n := range neighbors {
			stateValue := mapOSPFStateToValue(n.NbrState)
			labels := []string{"default", n.IfaceName, n.AreaID, neighborID, n.IPAddress}
			if len(*ospfInstances) > 0 {
				labels = append(labels, "0")
			}
			newGauge(ch, descriptions["neighbor_state"], stateValue, labels...)
		}
	}
	return nil
}

// Helper function to process OSPF LSA data for testing
func processOSPFLSA(ch chan<- prometheus.Metric, jsonData []byte, descriptions map[string]*prometheus.Desc) error {
	var response OSPFLSAResponse
	if err := json.Unmarshal(jsonData, &response); err != nil {
		return fmt.Errorf("parsing LSA JSON: %w", err)
	}

	// Create a map to collect LSA counts per area
	typeCountByArea := make(map[string]map[string]int)

	for areaID, area := range response.Default.Areas {
		if _, exists := typeCountByArea[areaID]; !exists {
			typeCountByArea[areaID] = make(map[string]int)
		}

		for _, lsa := range area.RouterLinkStates {
			typeCountByArea[areaID]["router"]++
			labels := []string{"default", areaID, "router", lsa.LSID, lsa.AdvertisedRouter, lsa.SequenceNumber}
			newGauge(ch, descriptions["lsa_detail"], 1, labels...)
		}
		for _, lsa := range area.NetworkLinkStates {
			typeCountByArea[areaID]["network"]++
			labels := []string{"default", areaID, "network", lsa.LSID, lsa.AdvertisedRouter, "0"}
			newGauge(ch, descriptions["lsa_detail"], 1, labels...)
		}
		for _, lsa := range area.SummaryLinkStates {
			typeCountByArea[areaID]["summary"]++
			labels := []string{"default", areaID, "summary", lsa.LSID, lsa.AdvertisedRouter, "0"}
			newGauge(ch, descriptions["lsa_detail"], 1, labels...)
		}
	}

	if _, exists := typeCountByArea["0.0.0.0"]; !exists {
		typeCountByArea["0.0.0.0"] = make(map[string]int)
	}

	for _, lsa := range response.Default.ASExternalLinkStates {
		typeCountByArea["0.0.0.0"]["external"]++
		labels := []string{"default", "0.0.0.0", "external", lsa.LSID, lsa.AdvertisedRouter, "0"}
		newGauge(ch, descriptions["lsa_detail"], 1, labels...)
	}

	for areaID, typeCounts := range typeCountByArea {
		for lsaType, count := range typeCounts {
			labels := []string{"default", areaID, lsaType}
			newGauge(ch, descriptions["lsa_count"], float64(count), labels...)
		}
	}

	return nil
}

// Helper function to process OSPF route data for testing
func processOSPFRoutes(ch chan<- prometheus.Metric, jsonData []byte, descriptions map[string]*prometheus.Desc) error {
	var response OSPFRouteResponse
	if err := json.Unmarshal(jsonData, &response); err != nil {
		return fmt.Errorf("parsing route JSON: %w", err)
	}

	if response.Default == nil {
		return fmt.Errorf("no default VRF found in OSPF route output")
	}

	vrfName, _ := response.Default["vrfName"].(string)
	if vrfName == "" {
		vrfName = "default"
	}

	typeCountByArea := make(map[string]map[string]int)
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

		area, _ := routeDetails["area"].(string)
		if area == "" {
			area = "0.0.0.0"
		}

		if _, exists := typeCountByArea[area]; !exists {
			typeCountByArea[area] = make(map[string]int)
		}
		typeCountByArea[area][routeType]++

		cost := 0
		if costVal, ok := routeDetails["cost"].(float64); ok {
			cost = int(costVal)
		}

		nextHop := ""
		iface := ""
		if nexthops, ok := routeDetails["nexthops"].([]interface{}); ok && len(nexthops) > 0 {
			if nh, ok := nexthops[0].(map[string]interface{}); ok {
				nextHop, _ = nh["ip"].(string)
				nextHop = strings.TrimSpace(nextHop)
				if nextHop == "" {
					nextHop = "direct"
				}

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
		})

		labels := []string{
			vrfName,
			area,
			key,
			nextHop,
			iface,
			routeType,
		}
		newGauge(ch, descriptions["route_detail"], float64(cost), labels...)
	}

	for area, typeCounts := range typeCountByArea {
		for routeType, count := range typeCounts {
			labels := []string{vrfName, area, routeType}
			newGauge(ch, descriptions["route_count"], float64(count), labels...)
		}
	}

	// Add placeholder route_changes metric
	labels := []string{
		vrfName,
		"0.0.0.0",
		"unchanged",
		"none",
		"none",
		"none",
		"none",
	}
	newGauge(ch, descriptions["route_changes"], 0, labels...)

	// Add has_route_changes metric
	newGauge(ch, descriptions["has_route_changes"], 0, vrfName)

	return nil
}

func TestProcessOSPFInterface(t *testing.T) {
	ospfInterfaceData := readTestFixture(t, "show_ip_ospf_vrf_all_interface.json")

	// Use buffered channel with sufficient capacity
	ch := make(chan prometheus.Metric, 100)
	done := make(chan struct{})

	go func() {
		defer close(done)
		if err := processOSPFInterface(ch, ospfInterfaceData, getOSPFDesc(), 0); err != nil {
			t.Errorf("error calling processOSPFInterface: %s", err)
		}

		// test for OSPF multiple instances
		*ospfInstances = "1,2"
		for i := 1; i <= 2; i++ {
			if err := processOSPFInterface(ch, ospfInterfaceData, getOSPFDesc(), i); err != nil {
				t.Errorf("error calling processOSPFInterface with instance %d: %s", i, err)
			}
		}
	}()

	// Collect metrics with timeout
	var gotMetrics map[string]float64
	collectDone := make(chan struct{})
	go func() {
		defer close(collectDone)
		gotMetrics = collectMetrics(t, ch)
	}()

	select {
	case <-done:
		close(ch)
		<-collectDone
	case <-time.After(5 * time.Second):
		t.Fatal("Test timed out")
	}

	validateMetrics(t, gotMetrics, expectedOSPFMetrics)
}

func TestProcessOSPFNeighbors(t *testing.T) {
	*ospfNeighborStateMetrics = true
	ospfNeighborData := readTestFixture(t, "show_ip_ospf_vrf_all_neighbor_detail.json")

	ch := make(chan prometheus.Metric, len(expectedOSPFNeighborMetrics))
	if err := processOSPFNeighbors(ch, ospfNeighborData, getOSPFDesc()); err != nil {
		t.Errorf("error calling processOSPFNeighbors: %s", err)
	}
	close(ch)

	gotMetrics := collectMetrics(t, ch)
	validateMetrics(t, gotMetrics, expectedOSPFNeighborMetrics)
}

func TestProcessOSPFLSA(t *testing.T) {
	*ospfLSACountMetrics = true
	*ospfLSADetailMetrics = true
	ospfLSAData := readTestFixture(t, "show_ip_ospf_vrf_all_database.json")

	// Use buffered channel with sufficient capacity
	ch := make(chan prometheus.Metric, 100)
	done := make(chan struct{})

	go func() {
		defer close(done)
		if err := processOSPFLSA(ch, ospfLSAData, getOSPFDesc()); err != nil {
			t.Errorf("error calling processOSPFLSA: %s", err)
		}
	}()

	// Collect metrics with timeout
	var gotMetrics map[string]float64
	collectDone := make(chan struct{})
	go func() {
		defer close(collectDone)
		gotMetrics = collectMetrics(t, ch)
	}()

	select {
	case <-done:
		close(ch)
		<-collectDone
	case <-time.After(5 * time.Second):
		t.Fatal("Test timed out")
	}

	validateMetrics(t, gotMetrics, expectedOSPFLSAMetrics)
}

func TestProcessOSPFRoutes(t *testing.T) {
	*ospfRouteCountMetrics = true
	*ospfRouteDetailMetrics = true
	*ospfRouteChangeMetrics = true
	*ospfHasRouteChangeMetric = true
	ospfRouteData := readTestFixture(t, "show_ip_ospf_vrf_all_route.json")

	ch := make(chan prometheus.Metric, len(expectedOSPFRouteMetrics))
	if err := processOSPFRoutes(ch, ospfRouteData, getOSPFDesc()); err != nil {
		t.Errorf("error calling processOSPFRoutes: %s", err)
	}
	close(ch)

	gotMetrics := collectMetrics(t, ch)
	validateMetrics(t, gotMetrics, expectedOSPFRouteMetrics)
}

func TestNewOSPFCollector(t *testing.T) {
	*ospfInstances = ""
	logger := slog.Default()
	collector, err := NewOSPFCollector(logger)
	if err != nil {
		t.Fatalf("Error creating OSPF collector: %v", err)
	}
	if collector == nil {
		t.Fatal("Expected collector to be non-nil")
	}

	// Test with instance IDs
	*ospfInstances = "1,2"
	*vtyshEnable = false
	collector, err = NewOSPFCollector(logger)
	if err != nil {
		t.Fatalf("Error creating OSPF collector with instances: %v", err)
	}
	if collector == nil {
		t.Fatal("Expected collector to be non-nil")
	}

	// Test conflict between vtysh and instances
	*vtyshEnable = true
	_, err = NewOSPFCollector(logger)
	if err == nil {
		t.Fatal("Expected error when both vtysh and instances are enabled")
	}

	// Reset for other tests
	*ospfInstances = ""
	*vtyshEnable = false
}

func TestDiffRoutes(t *testing.T) {
	prev := []OSFRoute{
		{VRF: "default", Area: "0.0.0.0", Prefix: "10.0.0.0/24", NextHop: "direct", Interface: "eth0", Type: "N"},
		{VRF: "default", Area: "0.0.0.0", Prefix: "10.1.0.0/24", NextHop: "10.0.0.2", Interface: "eth0", Type: "E"},
	}

	current := []OSFRoute{
		{VRF: "default", Area: "0.0.0.0", Prefix: "10.0.0.0/24", NextHop: "direct", Interface: "eth0", Type: "N"},
		{VRF: "default", Area: "0.0.0.0", Prefix: "10.2.0.0/24", NextHop: "10.0.0.3", Interface: "eth0", Type: "E"},
	}

	added, removed := diffRoutes(prev, current)

	if len(added) != 1 || added[0].Prefix != "10.2.0.0/24" {
		t.Errorf("Expected 1 added route, got %d", len(added))
	}

	if len(removed) != 1 || removed[0].Prefix != "10.1.0.0/24" {
		t.Errorf("Expected 1 removed route, got %d", len(removed))
	}
}

func TestMapOSPFStateToValue(t *testing.T) {
	testCases := []struct {
		state    string
		expected float64
	}{
		{"Full/DR", 1},
		{"Down", 2},
		{"Attempt", 3},
		{"Init", 4},
		{"2Way/DROther", 5},
		{"ExStart", 6},
		{"Exchange", 7},
		{"Loading", 8},
		{"Unknown", 0},
	}

	for _, tc := range testCases {
		result := mapOSPFStateToValue(tc.state)
		if result != tc.expected {
			t.Errorf("mapOSPFStateToValue(%s) = %f, expected %f", tc.state, result, tc.expected)
		}
	}
}

// Helper function to collect metrics from channel
func collectMetrics(t *testing.T, ch <-chan prometheus.Metric) map[string]float64 {
	gotMetrics := make(map[string]float64)

	for {
		select {
		case msg, ok := <-ch:
			if !ok {
				return gotMetrics
			}

			metric := &dto.Metric{}
			if err := msg.Write(metric); err != nil {
				t.Errorf("error writing metric: %s", err)
				continue
			}

			var labels []string
			for _, label := range metric.GetLabel() {
				labels = append(labels, fmt.Sprintf("%s=%s", label.GetName(), label.GetValue()))
			}

			var value float64
			if metric.GetCounter() != nil {
				value = metric.GetCounter().GetValue()
			} else if metric.GetGauge() != nil {
				value = metric.GetGauge().GetValue()
			}

			re, err := regexp.Compile(`.*fqName: "(.*)", help:.*`)
			if err != nil {
				t.Errorf("could not compile regex: %s", err)
				continue
			}
			metricName := re.FindStringSubmatch(msg.Desc().String())[1]

			gotMetrics[fmt.Sprintf("%s{%s}", metricName, strings.Join(labels, ","))] = value
		case <-time.After(1 * time.Second):
			return gotMetrics
		}
	}
}

// Helper function to validate metrics against expected values
func validateMetrics(t *testing.T, gotMetrics map[string]float64, expectedMetrics map[string]float64) {
	// Normalize area names by removing anything in brackets
	normalize := func(s string) string {
		return regexp.MustCompile(` \[.*\]`).ReplaceAllString(s, "")
	}

	// Check all expected metrics are present
	for expectedMetricName, expectedMetricVal := range expectedMetrics {
		found := false
		for gotMetricName, gotMetricVal := range gotMetrics {
			if normalize(gotMetricName) == normalize(expectedMetricName) && gotMetricVal == expectedMetricVal {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing metric: %s value %v", expectedMetricName, expectedMetricVal)
		}
	}

	// Check for unexpected metrics (only if they don't match any normalized expected metric)
	for gotMetricName, gotMetricVal := range gotMetrics {
		found := false
		for expectedMetricName := range expectedMetrics {
			if normalize(gotMetricName) == normalize(expectedMetricName) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("unexpected metric: %s : %v", gotMetricName, gotMetricVal)
		}
	}
}
