package collector

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

var (
	expectedOSPFInterfaceMetrics = map[string]float64{
		"frr_ospf_neighbors_total{area=\"0.0.0.0\",iface=\"swp1\",vrf=\"default\"}":            0,
		"frr_ospf_neighbors_total{area=\"0.0.0.0\",iface=\"swp2\",vrf=\"default\"}":            1,
		"frr_ospf_neighbors_total{area=\"0.0.0.0\",iface=\"swp3\",vrf=\"red\"}":                0,
		"frr_ospf_neighbors_total{area=\"0.0.0.0\",iface=\"swp4\",vrf=\"red\"}":                1,
		"frr_ospf_neighbor_adjacencies_total{area=\"0.0.0.0\",iface=\"swp1\",vrf=\"default\"}": 0,
		"frr_ospf_neighbor_adjacencies_total{area=\"0.0.0.0\",iface=\"swp2\",vrf=\"default\"}": 1,
		"frr_ospf_neighbor_adjacencies_total{area=\"0.0.0.0\",iface=\"swp3\",vrf=\"red\"}":     0,
		"frr_ospf_neighbor_adjacencies_total{area=\"0.0.0.0\",iface=\"swp4\",vrf=\"red\"}":     1,
	}

	expectedOSPFNeighborMetrics = map[string]float64{
		"frr_ospf_neighbor_state{area=\"0.0.0.0\",iface=\"eth0\",neighbor_id=\"10.0.0.2\",neighbor_ip=\"10.0.0.1\",vrf=\"default\"}": 1,
		"frr_ospf_neighbor_state{area=\"0.0.0.1\",iface=\"eth1\",neighbor_id=\"10.0.1.3\",neighbor_ip=\"10.0.1.1\",vrf=\"default\"}": 5,
	}

	expectedOSPFLSAMetrics = map[string]float64{
		"frr_ospf_lsa_count_total{area=\"0.0.0.0\",lsa_type=\"router\",vrf=\"default\"}":   1,
		"frr_ospf_lsa_count_total{area=\"0.0.0.0\",lsa_type=\"network\",vrf=\"default\"}":  1,
		"frr_ospf_lsa_count_total{area=\"0.0.0.0\",lsa_type=\"summary\",vrf=\"default\"}":  1,
		"frr_ospf_lsa_count_total{area=\"0.0.0.0\",lsa_type=\"external\",vrf=\"default\"}": 1,
	}

	expectedOSPFLSADetailMetrics = map[string]float64{
		"frr_ospf_lsa_detail{adv_router=\"1.1.1.1\",area=\"0.0.0.0\",lsa_id=\"1.1.1.1\",lsa_type=\"router\",sequence=\"80000001\",vrf=\"default\"}": 1,
		"frr_ospf_lsa_detail{adv_router=\"1.1.1.1\",area=\"0.0.0.0\",lsa_id=\"10.0.0.1\",lsa_type=\"network\",sequence=\"0\",vrf=\"default\"}":      1,
		"frr_ospf_lsa_detail{adv_router=\"1.1.1.1\",area=\"0.0.0.0\",lsa_id=\"2.2.2.2\",lsa_type=\"summary\",sequence=\"0\",vrf=\"default\"}":       1,
		"frr_ospf_lsa_detail{adv_router=\"1.1.1.1\",area=\"0.0.0.0\",lsa_id=\"3.3.3.3\",lsa_type=\"external\",sequence=\"0\",vrf=\"default\"}":      1,
	}

	expectedOSPFRouteMetrics = map[string]float64{
		"frr_ospf_route_count_total{area=\"0.0.0.0\",route_type=\"N\",vrf=\"default\"}":                                                            1,
		"frr_ospf_route_count_total{area=\"0.0.0.0\",route_type=\"E\",vrf=\"default\"}":                                                            1,
		"frr_ospf_route_detail{area=\"0.0.0.0\",interface=\"eth0\",next_hop=\"\",prefix=\"10.0.0.0/24\",route_type=\"N\",vrf=\"default\"}":         10,
		"frr_ospf_route_detail{area=\"0.0.0.0\",interface=\"eth0\",next_hop=\"10.0.0.2\",prefix=\"10.1.0.0/24\",route_type=\"E\",vrf=\"default\"}": 20,
	}

	expectedOSPFRouteChangeMetrics = map[string]float64{
		"frr_ospf_route_changes{area=\"0.0.0.0\",change_type=\"added\",interface=\"eth0\",next_hop=\"\",prefix=\"10.0.0.0/24\",route_type=\"N\",vrf=\"default\"}":         1,
		"frr_ospf_route_changes{area=\"0.0.0.0\",change_type=\"added\",interface=\"eth0\",next_hop=\"10.0.0.2\",prefix=\"10.1.0.0/24\",route_type=\"E\",vrf=\"default\"}": 1,
	}
)

func prepareOSPFMetrics(ch chan prometheus.Metric, t *testing.T) map[string]float64 {
	gotMetrics := make(map[string]float64)

	for {
		msg, more := <-ch
		if !more {
			break
		}
		metric := &dto.Metric{}
		if err := msg.Write(metric); err != nil {
			t.Errorf("error writing metric: %s", err)
		}

		var labels []string
		for _, label := range metric.GetLabel() {
			labels = append(labels, fmt.Sprintf("%s=\"%s\"", label.GetName(), label.GetValue()))
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
		}
		metricName := re.FindStringSubmatch(msg.Desc().String())[1]

		gotMetrics[fmt.Sprintf("%s{%s}", metricName, strings.Join(labels, ","))] = value
	}
	return gotMetrics
}

func compareOSPFMetrics(t *testing.T, gotMetrics map[string]float64, expectedMetrics map[string]float64) {
	for metricName, metricVal := range gotMetrics {
		if strings.Contains(metricName, "peerlink.4094") {
			continue // Skip passive interface metrics
		}
		if expectedMetricVal, ok := expectedMetrics[metricName]; ok {
			if expectedMetricVal != metricVal {
				t.Errorf("metric %s expected value %v got %v", metricName, expectedMetricVal, metricVal)
			}
		} else if !strings.Contains(metricName, "peerlink.4094") {
			t.Errorf("unexpected metric: %s : %v", metricName, metricVal)
		}
	}

	for expectedMetricName, expectedMetricVal := range expectedMetrics {
		if _, ok := gotMetrics[expectedMetricName]; !ok {
			t.Errorf("missing metric: %s value %v", expectedMetricName, expectedMetricVal)
		}
	}
}

func TestOSPFCollectorInterface(t *testing.T) {
	jsonInput := readTestFixture(t, "show_ip_ospf_vrf_all_interface.json")

	logger := slog.Default()
	c := &ospfCollector{
		logger:       logger,
		descriptions: getOSPFDesc(),
	}
	ch := make(chan prometheus.Metric, 100)
	err := c.processOSPFInterface(ch, jsonInput, 0)
	if err != nil {
		t.Fatalf("processOSPFInterface failed: %v", err)
	}
	close(ch)

	gotMetrics := prepareOSPFMetrics(ch, t)
	compareOSPFMetrics(t, gotMetrics, expectedOSPFInterfaceMetrics)
}

func TestOSPFCollectorNeighbor(t *testing.T) {
	jsonInput := readTestFixture(t, "show_ip_ospf_vrf_all_neighbor_detail.json")

	logger := slog.Default()
	c := &ospfCollector{
		logger:       logger,
		descriptions: getOSPFDesc(),
	}
	ch := make(chan prometheus.Metric, 10)

	var response OSPFNeighborResponse
	if err := json.Unmarshal(jsonInput, &response); err != nil {
		t.Fatalf("Failed to parse test JSON: %v", err)
	}

	for neighborID, neighbors := range response.Default.Neighbors {
		for _, n := range neighbors {
			stateValue := mapOSPFStateToValue(n.NbrState)
			labels := []string{"default", n.IfaceName, n.AreaID, neighborID, n.IPAddress}
			newGauge(ch, c.descriptions["neighbor_state"], stateValue, labels...)
		}
	}
	close(ch)

	gotMetrics := prepareOSPFMetrics(ch, t)
	compareOSPFMetrics(t, gotMetrics, expectedOSPFNeighborMetrics)
}

func TestOSPFCollectorLSA(t *testing.T) {
	jsonInput := readTestFixture(t, "show_ip_ospf_vrf_all_database.json")

	logger := slog.Default()
	c := &ospfCollector{
		logger:       logger,
		descriptions: getOSPFDesc(),
	}
	ch := make(chan prometheus.Metric, 20)

	var response OSPFLSAResponse
	if err := json.Unmarshal(jsonInput, &response); err != nil {
		t.Fatalf("Failed to parse test JSON: %v", err)
	}

	// Create a map to collect LSA counts per area
	typeCountByArea := make(map[string]map[string]int)

	for areaID, area := range response.Default.Areas {
		if _, exists := typeCountByArea[areaID]; !exists {
			typeCountByArea[areaID] = make(map[string]int)
		}

		for _, lsa := range area.RouterLinkStates {
			typeCountByArea[areaID]["router"]++
			if *ospfLSADetailMetrics {
				labels := []string{"default", areaID, "router", lsa.LSID, lsa.AdvertisedRouter, lsa.SequenceNumber}
				newGauge(ch, c.descriptions["lsa_detail"], 1, labels...)
			}
		}
		for _, lsa := range area.NetworkLinkStates {
			typeCountByArea[areaID]["network"]++
			if *ospfLSADetailMetrics {
				labels := []string{"default", areaID, "network", lsa.LSID, lsa.AdvertisedRouter, "0"}
				newGauge(ch, c.descriptions["lsa_detail"], 1, labels...)
			}
		}
		for _, lsa := range area.SummaryLinkStates {
			typeCountByArea[areaID]["summary"]++
			if *ospfLSADetailMetrics {
				labels := []string{"default", areaID, "summary", lsa.LSID, lsa.AdvertisedRouter, "0"}
				newGauge(ch, c.descriptions["lsa_detail"], 1, labels...)
			}
		}
	}

	// External LSAs are associated with backbone area
	if _, exists := typeCountByArea["0.0.0.0"]; !exists {
		typeCountByArea["0.0.0.0"] = make(map[string]int)
	}

	for _, lsa := range response.Default.ASExternalLinkStates {
		typeCountByArea["0.0.0.0"]["external"]++
		if *ospfLSADetailMetrics {
			labels := []string{"default", "0.0.0.0", "external", lsa.LSID, lsa.AdvertisedRouter, "0"}
			newGauge(ch, c.descriptions["lsa_detail"], 1, labels...)
		}
	}

	if *ospfLSACountMetrics {
		for areaID, typeCounts := range typeCountByArea {
			for lsaType, count := range typeCounts {
				labels := []string{"default", areaID, lsaType}
				newGauge(ch, c.descriptions["lsa_count"], float64(count), labels...)
			}
		}
	}
	close(ch)

	gotMetrics := prepareOSPFMetrics(ch, t)
	// Test count metrics
	compareOSPFMetrics(t, gotMetrics, expectedOSPFLSAMetrics)
	// Test detail metrics
	compareOSPFMetrics(t, gotMetrics, expectedOSPFLSADetailMetrics)
}

func TestOSPFCollectorRoute(t *testing.T) {
	jsonInput := readTestFixture(t, "show_ip_ospf_vrf_all_route.json")

	logger := slog.Default()
	c := &ospfCollector{
		logger:       logger,
		descriptions: getOSPFDesc(),
		lastRoutes:   []OSFRoute{}, // Empty to simulate first run
	}
	ch := make(chan prometheus.Metric, 20)

	var response OSPFRouteResponse
	if err := json.Unmarshal(jsonInput, &response); err != nil {
		t.Fatalf("Failed to parse test JSON: %v", err)
	}

	// Create a map to track route counts by area and type
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
			area = "0.0.0.0" // Default to backbone area if not specified
		}

		// Initialize the area map if needed
		if _, exists := typeCountByArea[area]; !exists {
			typeCountByArea[area] = make(map[string]int)
		}
		typeCountByArea[area][routeType]++

		cost := 0
		if costVal, ok := routeDetails["cost"].(float64); ok {
			cost = int(costVal)
		}

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

		route := OSFRoute{
			VRF:       "default",
			Area:      area,
			Prefix:    key,
			NextHop:   nextHop,
			Interface: iface,
			Cost:      cost,
			Type:      routeType,
			Tag:       tag,
			Type2Cost: type2Cost,
		}
		currentRoutes = append(currentRoutes, route)

		if *ospfRouteDetailMetrics {
			labels := []string{
				"default",
				area,
				key,
				nextHop,
				iface,
				routeType,
			}
			newGauge(ch, c.descriptions["route_detail"], float64(cost), labels...)
		}
	}

	if *ospfRouteCountMetrics {
		for area, typeCounts := range typeCountByArea {
			for routeType, count := range typeCounts {
				labels := []string{"default", area, routeType}
				newGauge(ch, c.descriptions["route_count"], float64(count), labels...)
			}
		}
	}

	if *ospfRouteChangeMetrics {
		added, removed := diffRoutes(c.lastRoutes, currentRoutes)

		for _, route := range added {
			labels := []string{
				route.VRF,
				route.Area,
				"added",
				route.Prefix,
				route.Type,
				route.NextHop,
				route.Interface,
			}
			newGauge(ch, c.descriptions["route_changes"], 1, labels...)
		}

		for _, route := range removed {
			labels := []string{
				route.VRF,
				route.Area,
				"removed",
				route.Prefix,
				route.Type,
				route.NextHop,
				route.Interface,
			}
			newGauge(ch, c.descriptions["route_changes"], 1, labels...)
		}
	}

	close(ch)

	gotMetrics := prepareOSPFMetrics(ch, t)
	// Test route count metrics
	compareOSPFMetrics(t, gotMetrics, expectedOSPFRouteMetrics)
	// Test route change metrics
	compareOSPFMetrics(t, gotMetrics, expectedOSPFRouteChangeMetrics)
}

func TestDiffRoutes(t *testing.T) {
	prevRoutes := []OSFRoute{
		{
			VRF:       "default",
			Area:      "0.0.0.0",
			Prefix:    "10.0.0.0/24",
			NextHop:   "10.0.0.1",
			Interface: "eth0",
			Cost:      10,
			Type:      "N",
		},
	}

	currentRoutes := []OSFRoute{
		{
			VRF:       "default",
			Area:      "0.0.0.0",
			Prefix:    "10.0.0.0/24",
			NextHop:   "10.0.0.2",
			Interface: "eth0",
			Cost:      10,
			Type:      "N",
		},
		{
			VRF:       "default",
			Area:      "0.0.0.0",
			Prefix:    "10.1.0.0/24",
			NextHop:   "10.0.0.1",
			Interface: "eth0",
			Cost:      20,
			Type:      "E",
		},
	}

	added, removed := diffRoutes(prevRoutes, currentRoutes)

	if len(added) != 2 {
		t.Errorf("Expected 2 added routes, got %d", len(added))
	}

	if len(removed) != 1 {
		t.Errorf("Expected 1 removed route, got %d", len(removed))
	}

	// Check that routes are properly identified as different even with same prefix
	foundDifferentNextHop := false
	for _, route := range added {
		if route.Prefix == "10.0.0.0/24" && route.NextHop == "10.0.0.2" {
			foundDifferentNextHop = true
			break
		}
	}

	if !foundDifferentNextHop {
		t.Errorf("Route with same prefix but different next-hop was not detected as changed")
	}
}

func TestMapOSPFStateToValue(t *testing.T) {
	tests := []struct {
		state string
		want  float64
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

	for _, tt := range tests {
		t.Run(tt.state, func(t *testing.T) {
			if got := mapOSPFStateToValue(tt.state); got != tt.want {
				t.Errorf("mapOSPFStateToValue() = %v, want %v", got, tt.want)
			}
		})
	}
}
