package collector

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestProcessOSPFInterface(t *testing.T) {
	tests := []struct {
		name        string
		jsonInput   string
		instanceID  int
		expected    map[string]float64
		expectCount int
		wantErr     bool
		errMsg      string
	}{
		{
			name: "SingleInstance",
			jsonInput: `{
				"default": {
					"swp1": {"nbrCount":0,"nbrAdjacentCount":0,"area":"0.0.0.0","timerPassiveInterface":false},
					"swp2": {"nbrCount":1,"nbrAdjacentCount":1,"area":"0.0.0.0","timerPassiveInterface":false},
					"interfaces": {
						"swp3": {"nbrCount":0,"nbrAdjacentCount":0,"area":"0.0.0.0","timerPassiveInterface":false},
						"swp4": {"nbrCount":1,"nbrAdjacentCount":1,"area":"0.0.0.0","timerPassiveInterface":false}
					}
				},
				"red": {
					"swp5": {"nbrCount":0,"nbrAdjacentCount":0,"area":"0.0.0.0","timerPassiveInterface":true}
				}
			}`,
			instanceID: 0,
			expected: map[string]float64{
				"frr_ospf_neighbors_total{area=0.0.0.0,iface=swp1,vrf=default}":            0,
				"frr_ospf_neighbors_total{area=0.0.0.0,iface=swp2,vrf=default}":            1,
				"frr_ospf_neighbors_total{area=0.0.0.0,iface=swp3,vrf=default}":            0,
				"frr_ospf_neighbors_total{area=0.0.0.0,iface=swp4,vrf=default}":            1,
				"frr_ospf_neighbor_adjacencies_total{area=0.0.0.0,iface=swp1,vrf=default}": 0,
				"frr_ospf_neighbor_adjacencies_total{area=0.0.0.0,iface=swp2,vrf=default}": 1,
				"frr_ospf_neighbor_adjacencies_total{area=0.0.0.0,iface=swp3,vrf=default}": 0,
				"frr_ospf_neighbor_adjacencies_total{area=0.0.0.0,iface=swp4,vrf=default}": 1,
			},
			expectCount: 8,
			wantErr:     false,
		},
		{
			name: "MultiInstanceWithInstanceLabel",
			jsonInput: `{
				"default": {
					"swp1": {"nbrCount":2,"nbrAdjacentCount":1,"area":"0.0.0.0","timerPassiveInterface":false}
				}
			}`,
			instanceID: 1,
			expected: map[string]float64{
				"frr_ospf_neighbors_total{area=0.0.0.0,iface=swp1,instance=1,vrf=default}":            2,
				"frr_ospf_neighbor_adjacencies_total{area=0.0.0.0,iface=swp1,instance=1,vrf=default}": 1,
			},
			expectCount: 2,
			wantErr:     false,
		},
		{
			name: "PassiveInterfaceSkipped",
			jsonInput: `{
				"default": {
					"swp1": {"nbrCount":0,"nbrAdjacentCount":0,"area":"0.0.0.0","timerPassiveInterface":true}
				}
			}`,
			instanceID:  0,
			expected:    map[string]float64{},
			expectCount: 0,
			wantErr:     false,
		},
		{
			name: "EmptyJSON",
			jsonInput: `{
				"default": {}
			}`,
			instanceID:  0,
			expected:    map[string]float64{},
			expectCount: 0,
			wantErr:     false,
		},
		{
			name:        "MalformedJSON",
			jsonInput:   `{"default": {"swp1": {"nbrCount":0,}}`,
			instanceID:  0,
			expected:    map[string]float64{},
			expectCount: 0,
			wantErr:     true,
			errMsg:      "cannot unmarshal ospf interface json",
		},
		{
			name: "MissingRequiredFields",
			jsonInput: `{
				"default": {
					"swp1": {"area":"0.0.0.0","timerPassiveInterface":false}
				}
			}`,
			instanceID:  0,
			expected:    map[string]float64{},
			expectCount: 0,
			wantErr:     true,
			errMsg:      "cannot unmarshal interface",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup test
			c := &ospfCollector{descriptions: getOSPFDesc()}
			ch := make(chan prometheus.Metric, 10)

			// Run function
			err := c.processOSPFInterface(ch, []byte(tt.jsonInput), tt.instanceID)

			// Verify error conditions
			if (err != nil) != tt.wantErr {
				t.Fatalf("processOSPFInterface() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("Expected error to contain %q, got %q", tt.errMsg, err.Error())
			}
			close(ch)

			// Collect metrics
			gotMetrics := make(map[string]float64)
			metricsCount := 0

			for msg := range ch {
				metricsCount++
				metric := &dto.Metric{}
				if err := msg.Write(metric); err != nil {
					t.Errorf("Error writing metric: %v", err)
					continue
				}

				var labels []string
				for _, label := range metric.GetLabel() {
					labels = append(labels, fmt.Sprintf("%s=%s", label.GetName(), label.GetValue()))
				}

				var value float64
				if metric.Gauge != nil {
					value = metric.Gauge.GetValue()
				} else if metric.Counter != nil {
					value = metric.Counter.GetValue()
				}

				re := regexp.MustCompile(`fqName: "([^"]+)"`)
				matches := re.FindStringSubmatch(msg.Desc().String())
				if len(matches) < 2 {
					t.Error("Could not extract metric name")
					continue
				}
				metricName := matches[1]

				gotMetrics[fmt.Sprintf("%s{%s}", metricName, strings.Join(labels, ","))] = value
			}

			// Verify metrics count
			if metricsCount != tt.expectCount {
				t.Errorf("Expected %d metrics, got %d", tt.expectCount, metricsCount)
			}

			// Verify expected metrics
			for metricName, expectedValue := range tt.expected {
				if gotValue, ok := gotMetrics[metricName]; !ok {
					t.Errorf("Missing metric: %s", metricName)
				} else if gotValue != expectedValue {
					t.Errorf("Metric %s: expected %v, got %v", metricName, expectedValue, gotValue)
				}
			}
		})
	}
}

func TestEnhancedOSPFMetrics(t *testing.T) {
	tests := []struct {
		name       string
		testFunc   func(*testing.T)
		metricName string
	}{
		{
			name:       "NeighborState",
			testFunc:   testNeighborState,
			metricName: "frr_ospf_neighbor_state",
		},
		{
			name:       "LSAMetrics",
			testFunc:   testLSAMetrics,
			metricName: "frr_ospf_lsa_count_total",
		},
		{
			name:       "LSADetails",
			testFunc:   testLSAMetrics,
			metricName: "frr_ospf_lsa_detail",
		},
		{
			name:       "RouteMetrics",
			testFunc:   testRouteMetrics,
			metricName: "frr_ospf_route_count_total",
		},
		{
			name:       "RouteDetails",
			testFunc:   testRouteMetrics,
			metricName: "frr_ospf_route_detail",
		},
		{
			name:       "RouteChanges",
			testFunc:   testRouteMetrics,
			metricName: "frr_ospf_route_changes_total",
		},
	}

	// Track which metrics were tested
	testedMetrics := make(map[string]bool)
	for _, metric := range expectedEnhancedMetrics {
		testedMetrics[metric] = false
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.testFunc(t)
			testedMetrics[tt.metricName] = true
		})
	}

	// Verify all expected metrics were tested
	t.Run("VerifyAllMetricsTested", func(t *testing.T) {
		for metric, found := range testedMetrics {
			if !found {
				t.Errorf("Expected metric %s was not tested", metric)
			}
		}
	})
}

func testNeighborState(t *testing.T) {
	neighbors := []OSFNeighbor{
		{
			VRF:        "default",
			Area:       "0.0.0.0",
			Interface:  "eth0",
			NeighborID: "1.1.1.1",
			IPAddress:  "10.0.0.1",
			State:      "Full",
		},
	}

	ch := make(chan prometheus.Metric, 1)
	for _, n := range neighbors {
		labels := []string{n.VRF, n.Interface, n.Area, n.NeighborID, n.IPAddress}
		if len(*frrOSPFInstances) > 0 {
			labels = append(labels, "0")
		}
		newGauge(ch, getOSPFDesc()["neighbor_state"], mapOSPFStateToValue(n.State), labels...)
	}
	close(ch)

	found := false
	for msg := range ch {
		desc := msg.Desc().String()
		if strings.Contains(desc, "frr_ospf_neighbor_state") {
			found = true
		}
	}

	if !found {
		t.Error("Neighbor state metric not found")
	}
}

func testLSAMetrics(t *testing.T) {
	lsas := []OSFLSA{
		{
			VRF:       "default",
			Area:      "0.0.0.0",
			Type:      "Router",
			ID:        "1.1.1.1",
			AdvRouter: "1.1.1.1",
			Sequence:  1,
		},
	}

	ch := make(chan prometheus.Metric, 2)
	newGauge(ch, getOSPFDesc()["lsa_count"], float64(len(lsas)), "default", "0.0.0.0", "Router")
	for _, lsa := range lsas {
		labels := []string{lsa.VRF, lsa.Area, lsa.Type, lsa.ID, lsa.AdvRouter, strconv.Itoa(lsa.Sequence)}
		newGauge(ch, getOSPFDesc()["lsa_detail"], 1, labels...)
	}
	close(ch)

	foundCount := false
	foundDetail := false
	for msg := range ch {
		desc := msg.Desc().String()
		if strings.Contains(desc, "frr_ospf_lsa_count_total") {
			foundCount = true
		}
		if strings.Contains(desc, "frr_ospf_lsa_detail") {
			foundDetail = true
		}
	}

	if !foundCount {
		t.Error("LSA count metric not found")
	}
	if !foundDetail {
		t.Error("LSA detail metric not found")
	}
}

func testRouteMetrics(t *testing.T) {
	routes := []OSFRoute{
		{
			VRF:       "default",
			Area:      "0.0.0.0",
			Prefix:    "10.0.0.0/24",
			NextHop:   "192.168.1.1",
			Interface: "eth0",
			Type:      "intra",
			Cost:      10,
		},
	}

	ch := make(chan prometheus.Metric, 3)
	newGauge(ch, getOSPFDesc()["route_count"], float64(len(routes)), "default", "0.0.0.0", "intra")
	for _, route := range routes {
		labels := []string{route.VRF, route.Area, route.Prefix, route.NextHop, route.Interface, route.Type}
		newGauge(ch, getOSPFDesc()["route_detail"], 1, labels...)
	}
	newCounter(ch, getOSPFDesc()["route_changes"], 1, "default", "0.0.0.0", "added")
	close(ch)

	foundCount := false
	foundDetail := false
	foundChanges := false
	for msg := range ch {
		desc := msg.Desc().String()
		if strings.Contains(desc, "frr_ospf_route_count_total") {
			foundCount = true
		}
		if strings.Contains(desc, "frr_ospf_route_detail") {
			foundDetail = true
		}
		if strings.Contains(desc, "frr_ospf_route_changes_total") {
			foundChanges = true
		}
	}

	if !foundCount {
		t.Error("Route count metric not found")
	}
	if !foundDetail {
		t.Error("Route detail metric not found")
	}
	if !foundChanges {
		t.Error("Route changes metric not found")
	}
}

var (
	expectedEnhancedMetrics = []string{
		"frr_ospf_neighbor_state",
		"frr_ospf_lsa_count_total",
		"frr_ospf_lsa_detail",
		"frr_ospf_route_count_total",
		"frr_ospf_route_detail",
		"frr_ospf_route_changes_total",
	}
)
