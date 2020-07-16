package routing

import (
	"context"
	"errors"
	"github.com/golang/glog"
	"strconv"

	"github.com/cloudnativelabs/kube-router/pkg/utils"
	gobgpapi "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/pkg/config"

	v1core "k8s.io/api/core/v1"
)

// First create all prefix and neighbor sets
// Then apply export policies
// Then apply import policies
func (nrc *NetworkRoutingController) AddPolicies() error {
	// we are rr server do not add export policies
	if nrc.bgpRRServer {
		return nil
	}

	definedSet := &gobgpapi.DefinedSet{
		DefinedType: gobgpapi.DefinedType_PREFIX,
		Name:        "podcidrprefixset",
		Prefixes: []*gobgpapi.Prefix{
			&gobgpapi.Prefix{
				IpPrefix: nrc.podCidr,
			},
		},
	}

	err2 := nrc.bgpServer.AddDefinedSet(context.Background(), &gobgpapi.AddDefinedSetRequest{DefinedSet: definedSet})
	if err2 != nil {
		glog.Errorf("Failed to add podCidrPrefixSet: %s", err2)
	}

	// creates prefix set to represent all the advertisable IP associated with the services
	advIPPrefixList := make([]*gobgpapi.Prefix, 0)
	advIps, _, _ := nrc.getAllVIPs()
	for _, ip := range advIps {
		advIPPrefixList = append(advIPPrefixList, &gobgpapi.Prefix{IpPrefix: ip + "/32"})
	}
	clusterIPPrefixSet := &gobgpapi.DefinedSet{
		DefinedType: gobgpapi.DefinedType_PREFIX,
		Name:        "clusteripprefixset",
		Prefixes:    advIPPrefixList,
	}

	err2 = nrc.bgpServer.AddDefinedSet(context.Background(), &gobgpapi.AddDefinedSetRequest{DefinedSet: clusterIPPrefixSet})
	if err2 != nil {
		glog.Errorf("Failed to add clusterIPPrefixSet: %s", err2)
	}

	iBGPPeers := make([]*gobgpapi.Prefix, 0)
	if nrc.bgpEnableInternal {
		// Get the current list of the nodes from the local cache
		nodes := nrc.nodeLister.List()
		for _, node := range nodes {
			nodeObj := node.(*v1core.Node)
			nodeIP, err := utils.GetNodeIP(nodeObj)
			if err != nil {
				glog.Errorf("Failed to find a node IP and therefore cannot add internal BGP Peer: %v", err)
				continue
			}
			iBGPPeers = append(iBGPPeers, &gobgpapi.Prefix{IpPrefix: nodeIP.String()})
		}

		iBGPPeerNS := &gobgpapi.DefinedSet{
			DefinedType: gobgpapi.DefinedType_NEIGHBOR,
			Name:        "iBGPpeerset",
			Prefixes:    iBGPPeers,
		}
		err2 := nrc.bgpServer.AddDefinedSet(context.Background(), &gobgpapi.AddDefinedSetRequest{DefinedSet: iBGPPeerNS})
		if err2 != nil {
			glog.Errorf("Failed to add iBGPPeerNS: %s", err2)
		}
	}

	externalBgpPeers := make([]*gobgpapi.Prefix, 0)
	if len(nrc.globalPeerRouters) > 0 {
		for _, peer := range nrc.globalPeerRouters {
			externalBgpPeers = append(externalBgpPeers, &gobgpapi.Prefix{IpPrefix: peer.Conf.NeighborAddress})
		}
	}
	if len(nrc.nodePeerRouters) > 0 {
		for _, peer := range nrc.nodePeerRouters {
			externalBgpPeers = append(externalBgpPeers, &gobgpapi.Prefix{IpPrefix: peer})
		}
	}
	if len(externalBgpPeers) > 0 {
		eBGPPeerNS := &gobgpapi.DefinedSet{
			DefinedType: gobgpapi.DefinedType_NEIGHBOR,
			Name:        "externalpeerset",
			Prefixes:    externalBgpPeers,
		}
		err2 := nrc.bgpServer.AddDefinedSet(context.Background(), &gobgpapi.AddDefinedSetRequest{DefinedSet: eBGPPeerNS})
		if err2 != nil {
			glog.Errorf("Failed to add iBGPPeerNS: %s", err2)
		}
	}

	// a slice of all peers is used as a match condition for reject statement of clusteripprefixset import polcy
	allBgpPeers := append(externalBgpPeers, iBGPPeers...)
	allPeerNS := &gobgpapi.DefinedSet{
		DefinedType: gobgpapi.DefinedType_NEIGHBOR,
		Name:        "allpeerset",
		Prefixes:    allBgpPeers,
	}
	err2 = nrc.bgpServer.AddDefinedSet(context.Background(), &gobgpapi.AddDefinedSetRequest{DefinedSet: allPeerNS})
	if err2 != nil {
		glog.Errorf("Failed to add ns: %s", err2)
	}

	err := nrc.addExportPolicies()
	if err != nil {
		return err
	}

	err = nrc.addImportPolicies()
	if err != nil {
		return err
	}

	return nil
}

// BGP export policies are added so that following conditions are met:
//
// - by default export of all routes from the RIB to the neighbour's is denied, and explicity statements are added i
//   to permit the desired routes to be exported
// - each node is allowed to advertise its assigned pod CIDR's to all of its iBGP peer neighbours with same ASN if --enable-ibgp=true
// - each node is allowed to advertise its assigned pod CIDR's to all of its external BGP peer neighbours
//   only if --advertise-pod-cidr flag is set to true
// - each node is NOT allowed to advertise its assigned pod CIDR's to all of its external BGP peer neighbours
//   only if --advertise-pod-cidr flag is set to false
// - each node is allowed to advertise service VIP's (cluster ip, load balancer ip, external IP) ONLY to external
//   BGP peers
// - each node is NOT allowed to advertise service VIP's (cluster ip, load balancer ip, external IP) to
//   iBGP peers
// - an option to allow overriding the next-hop-address with the outgoing ip for external bgp peers
func (nrc *NetworkRoutingController) addExportPolicies() error {
	statements := make([]*gobgpapi.Statement, 0)

	var bgpActions gobgpapi.Actions
	if nrc.pathPrepend {
		prependAsn, err := strconv.ParseUint(nrc.pathPrependAS, 10, 32)
		if err != nil {
			return errors.New("Invalid value for kube-router.io/path-prepend.as: " + err.Error())
		}
		bgpActions = gobgpapi.Actions{
			AsPrepend: &gobgpapi.AsPrependAction{
				Asn:    uint32(prependAsn),
				Repeat: uint32(nrc.pathPrependCount),
			},
		}
	}

	if nrc.bgpEnableInternal {
		actions := gobgpapi.Actions{
			RouteAction: gobgpapi.RouteAction_ACCEPT,
		}
		if nrc.overrideNextHop {
			actions.Nexthop = &gobgpapi.NexthopAction{Self: true}
		}
		// statement to represent the export policy to permit advertising node's pod CIDR
		statements = append(statements,
			&gobgpapi.Statement{
				Conditions: &gobgpapi.Conditions{
					PrefixSet: &gobgpapi.MatchSet{
						MatchType: gobgpapi.MatchType_ANY,
						Name:      "podcidrprefixset",
					},
					NeighborSet: &gobgpapi.MatchSet{
						MatchType: gobgpapi.MatchType_ANY,
						Name:      "iBGPpeerset",
					},
				},
				Actions: &actions,
			})
	}

	if len(nrc.globalPeerRouters) > 0 || len(nrc.nodePeerRouters) > 0 {
		actions := gobgpapi.Actions{
			RouteAction: gobgpapi.RouteAction_ACCEPT,
		}
		if nrc.overrideNextHop {
			actions.Nexthop = &gobgpapi.NexthopAction{Self: true}
		}

		// statement to represent the export policy to permit advertising cluster IP's
		// only to the global BGP peer or node specific BGP peer
		statements = append(statements, &gobgpapi.Statement{
			Conditions: &gobgpapi.Conditions{
				PrefixSet: &gobgpapi.MatchSet{
					MatchType: gobgpapi.MatchType_ANY,
					Name:      "clusteripprefixset",
				},
				NeighborSet: &gobgpapi.MatchSet{
					MatchType: gobgpapi.MatchType_ANY,
					Name:      "externalpeerset",
				},
			},
			Actions: &actions,
		})

		if nrc.advertisePodCidr {
			actions := gobgpapi.Actions{
				RouteAction: gobgpapi.RouteAction_ACCEPT,
			}
			if nrc.overrideNextHop {
				actions.Nexthop = &gobgpapi.NexthopAction{Self: true}
			}
			statements = append(statements, &gobgpapi.Statement{
				Conditions: &gobgpapi.Conditions{
					PrefixSet: &gobgpapi.MatchSet{
						MatchType: gobgpapi.MatchType_ANY,
						Name:      "podcidrprefixset",
					},
					NeighborSet: &gobgpapi.MatchSet{
						MatchType: gobgpapi.MatchType_ANY,
						Name:      "externalpeerset",
					},
				},
				Actions: &actions,
			})
		}
	}

	definition := gobgpapi.Policy{
		Name:       "kube_router_export",
		Statements: statements,
	}

	policyAlreadyExists := false
	checkExistingPolicy := func(existingPolicy *gobgpapi.Policy) {
		if existingPolicy.Name == "kube_router_export" {
			policyAlreadyExists = true
		}
	}
	err := nrc.bgpServer.ListPolicy(context.Background(), &gobgpapi.ListPolicyRequest{}, checkExistingPolicy)
	if err != nil {
		return errors.New("Failed to verify if kube-router BGP export policy exists: " + err.Error())
	}

	if !policyAlreadyExists {
		err = nrc.bgpServer.AddPolicy(context.Background(), &gobgpapi.AddPolicyRequest{Policy: &definition})
		if err != nil {
			return errors.New("Failed to add policy: " + err.Error())
		}
	}

	policyAssignmentExists := false
	checkExistingPolicyAssignment := func(existingPolicyAssignment *gobgpapi.PolicyAssignment) {
		if existingPolicyAssignment.Name == "kube_router_export" {
			policyAssignmentExists = true
		}
	}
	err = nrc.bgpServer.ListPolicyAssignment(context.Background(),
		&gobgpapi.ListPolicyAssignmentRequest{Name: "kube_router_export", Direction: gobgpapi.PolicyDirection_EXPORT}, checkExistingPolicyAssignment)
	if err == nil {
		return errors.New("Failed to verify if kube-router BGP export policy assignment exists: " + err.Error())
	}

	policyAssignment := gobgpapi.PolicyAssignment{
		Name:          "kube_router_export",
		Direction:     gobgpapi.PolicyDirection_EXPORT,
		Policies:      []*gobgpapi.Policy{&definition},
		DefaultAction: gobgpapi.RouteAction_REJECT,
	}
	if !policyAssignmentExists {
		err = nrc.bgpServer.AddPolicyAssignment(context.Background(), &gobgpapi.AddPolicyAssignmentRequest{Assignment: &policyAssignment})
		if err != nil {
			return errors.New("Failed to add policy assignment: " + err.Error())
		}
	}

	return nil
}

// BGP import policies are added so that the following conditions are met:
// - do not import Service VIPs advertised from any peers, instead each kube-router originates and injects Service VIPs into local rib.
func (nrc *NetworkRoutingController) addImportPolicies() error {
	statements := make([]*gobgpapi.Statement, 0)

	actions := gobgpapi.Actions{
		RouteAction: gobgpapi.RouteAction_REJECT,
	}
	statements = append(statements, &gobgpapi.Statement{
		Conditions: &gobgpapi.Conditions{
			PrefixSet: &gobgpapi.MatchSet{
				MatchType: gobgpapi.MatchType_ANY,
				Name:      "clusteripprefixset",
			},
			NeighborSet: &gobgpapi.MatchSet{
				MatchType: gobgpapi.MatchType_ANY,
				Name:      "allpeerset",
			},
		},
		Actions: &actions,
	})

	definition := gobgpapi.Policy{
		Name:       "kube_router_import",
		Statements: statements,
	}

	policyAlreadyExists := false
	checkExistingPolicy := func(existingPolicy *gobgpapi.Policy) {
		if existingPolicy.Name == "kube_router_import" {
			policyAlreadyExists = true
		}
	}
	err := nrc.bgpServer.ListPolicy(context.Background(), &gobgpapi.ListPolicyRequest{}, checkExistingPolicy)
	if err != nil {
		return errors.New("Failed to verify if kube-router BGP import policy exists: " + err.Error())
	}

	if !policyAlreadyExists {
		err = nrc.bgpServer.AddPolicy(context.Background(), &gobgpapi.AddPolicyRequest{Policy: &definition})
		if err != nil {
			return errors.New("Failed to add policy: " + err.Error())
		}
	}

	policyAssignmentExists := false
	checkExistingPolicyAssignment := func(existingPolicyAssignment *gobgpapi.PolicyAssignment) {
		if existingPolicyAssignment.Name == "kube_router_import" {
			policyAssignmentExists = true
		}
	}
	err = nrc.bgpServer.ListPolicyAssignment(context.Background(),
		&gobgpapi.ListPolicyAssignmentRequest{Name: "kube_router_export", Direction: gobgpapi.PolicyDirection_EXPORT}, checkExistingPolicyAssignment)
	if err == nil {
		return errors.New("Failed to verify if kube-router BGP import policy assignment exists: " + err.Error())
	}

	policyAssignment := gobgpapi.PolicyAssignment{
		Name:          "kube_router_import",
		Direction:     gobgpapi.PolicyDirection_IMPORT,
		Policies:      []*gobgpapi.Policy{&definition},
		DefaultAction: gobgpapi.RouteAction_ACCEPT,
	}
	if !policyAssignmentExists {
		err = nrc.bgpServer.AddPolicyAssignment(context.Background(), &gobgpapi.AddPolicyAssignmentRequest{Assignment: &policyAssignment})
		if err != nil {
			return errors.New("Failed to add policy assignment: " + err.Error())
		}
	}

	return nil
}
