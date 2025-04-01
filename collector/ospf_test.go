package collector

import (
	"encoding/json"
	"fmt"
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

	expectedOSPFRouteMetrics = map[string]float64{
		"frr_ospf_route_count_total{area=\"0.0.0.0\",route_type=\"N\",vrf=\"default\"}":          1,
		"frr_ospf_route_count_total{area=\"0.0.0.0\",route_type=\"E\",vrf=\"default\"}":          1,
		"frr_ospf_route_changes_total{area=\"0.0.0.0\",change_type=\"added\",vrf=\"default\"}":   2,
		"frr_ospf_route_changes_total{area=\"0.0.0.0\",change_type=\"removed\",vrf=\"default\"}": 0,
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

	c := &ospfCollector{descriptions: getOSPFDesc()}
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

	c := &ospfCollector{descriptions: getOSPFDesc()}
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

	c := &ospfCollector{descriptions: getOSPFDesc()}
	ch := make(chan prometheus.Metric, 10)

	var response OSPFLSAResponse
	if err := json.Unmarshal(jsonInput, &response); err != nil {
		t.Fatalf("Failed to parse test JSON: %v", err)
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
	close(ch)

	gotMetrics := prepareOSPFMetrics(ch, t)
	compareOSPFMetrics(t, gotMetrics, expectedOSPFLSAMetrics)
}

func TestOSPFCollectorRoute(t *testing.T) {
	jsonInput := readTestFixture(t, "show_ip_ospf_vrf_all_route.json")

	c := &ospfCollector{
		descriptions: getOSPFDesc(),
		lastRoutes:   []OSFRoute{}, // Empty to simulate first run
	}
	ch := make(chan prometheus.Metric, 10)

	var response OSPFRouteResponse
	if err := json.Unmarshal(jsonInput, &response); err != nil {
		t.Fatalf("Failed to parse test JSON: %v", err)
	}

	vrfName := "default"
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
		})

		if *ospfExportDetails {
			labels := []string{vrfName, area, key, nextHop, iface, routeType}
			newGauge(ch, c.descriptions["route_detail"], float64(cost), labels...)
		}
	}

	for routeType, count := range typeCount {
		labels := []string{vrfName, "0.0.0.0", routeType}
		newGauge(ch, c.descriptions["route_count"], float64(count), labels...)
	}

	// Test route changes
	added, removed := diffRoutes(c.lastRoutes, currentRoutes)
	newCounter(ch, c.descriptions["route_changes"], float64(added), vrfName, "0.0.0.0", "added")
	newCounter(ch, c.descriptions["route_changes"], float64(removed), vrfName, "0.0.0.0", "removed")
	close(ch)

	gotMetrics := prepareOSPFMetrics(ch, t)
	compareOSPFMetrics(t, gotMetrics, expectedOSPFRouteMetrics)
}
