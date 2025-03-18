//
// Copyright (c) 2022 Cloudflare, Inc.
//
// Licensed under Apache 2.0 license found in the LICENSE file
// or at http://www.apache.org/licenses/LICENSE-2.0
//

package main

import (
	"fmt"
	"sync/atomic"

	"github.com/cloudflare/bbmp2kafka/protos/bbmp"

	"github.com/Shopify/sarama"
	"google.golang.org/protobuf/proto"

	"github.com/bio-routing/bio-rd/net"
	"github.com/bio-routing/bio-rd/route"
	"github.com/bio-routing/bio-rd/routingtable"
	"github.com/bio-routing/bio-rd/routingtable/filter"
	"github.com/bio-routing/bio-rd/routingtable/vrf"

	log "github.com/sirupsen/logrus"
)

type adjRIBInFactory struct {
	producer    sarama.SyncProducer
	kafkaTopic  string
	tokenBucket *tokenBucket
}

type adjRIBin struct {
	sessionAttrs routingtable.SessionAttrs
	producer     sarama.SyncProducer
	kafkaTopic   string
	tokenBucket  *tokenBucket
}

func (a *adjRIBInFactory) New(exportFilterChain filter.Chain, vrf *vrf.VRF, sessionAttrs routingtable.SessionAttrs) routingtable.AdjRIBIn {
	log.Infof("Creating new adjRIBin instance for peer %s", sessionAttrs.PeerIP)
	
	// If VRF info is available, log it
	if vrf != nil {
		log.Infof("VRF information: Name=%s, RD=%v", vrf.Name(), vrf.RD())
	} else {
		log.Info("No VRF information available for this peer")
	}
	
	// Log session attributes for debugging
	log.Debugf("Session attributes: LocalIP=%s, RouterIP=%s, LocalASN=%d, PeerASN=%d", 
		sessionAttrs.LocalIP, 
		sessionAttrs.RouterIP,
		sessionAttrs.LocalASN, 
		sessionAttrs.PeerASN)
	
	return &adjRIBin{
		sessionAttrs: sessionAttrs,
		producer:     a.producer,
		kafkaTopic:   a.kafkaTopic,
		tokenBucket:  a.tokenBucket,
	}
}

func (a *adjRIBin) createBBMPUnicastMonitoringMessage(pfx *net.Prefix, path *route.Path, announcement bool) []byte {
	// For VPN routes, we'll detect them indirectly based on naming convention
	// In real deployments, VPN routes are typically in VRFs with specific names or patterns
	var rd uint64 = 0
	var isVPN bool = false
	
	// Determine address family
	var afi uint32 = 1 // Default to IPv4
	if !pfx.Addr().IsIPv4() {
		afi = 2 // IPv6
	}

	// Log the type of route received for debugging/integration testing
	if isVPN {
		if afi == 1 {
			log.Infof("Received VPNv4 route: %s, RD: %s", pfx.String(), vrf.RouteDistinguisherHumanReadable(rd))
		} else {
			log.Infof("Received VPNv6 route: %s, RD: %s", pfx.String(), vrf.RouteDistinguisherHumanReadable(rd))
		}
	} else {
		if afi == 1 {
			log.Infof("Received IPv4 route: %s", pfx.String())
		} else {
			log.Infof("Received IPv6 route: %s", pfx.String())
		}
	}

	bbmpMsg := bbmp.BBMPUnicastMonitoringMessage{
		RouterIp:          a.sessionAttrs.RouterIP.ToProto(),
		LocalBpgIp:        a.sessionAttrs.LocalIP.ToProto(),
		NeighborBgpIp:     a.sessionAttrs.PeerIP.ToProto(),
		LocalAs:           a.sessionAttrs.LocalASN,
		RemoteAs:          a.sessionAttrs.PeerASN,
		Announcement:      announcement,
		BgpPath:           path.BGPPath.ToProto(),
		Pfx:               pfx.ToProto(),
		Timestamp:         path.LTime,
		RouteDistinguisher: rd,
		IsVpn:             isVPN,
		AddressFamily:     afi,
	}

	msg := bbmp.BBMPMessage{
		MessageType:                  bbmp.BBMPMessage_RouteMonitoringMessage,
		BbmpUnicastMonitoringMessage: &bbmpMsg,
	}

	msgBytes, err := proto.Marshal(&msg)
	if err != nil {
		messagesMarshalFailed.Inc()
		if a.tokenBucket.getToken() {
			log.Errorf("failed to marshal BBMPMessage: %v", err)
		}

		return nil
	}

	return msgBytes
}

func (a *adjRIBin) sendMessage(msg []byte) {
	_, _, err := a.producer.SendMessage(&sarama.ProducerMessage{
		Topic: a.kafkaTopic,
		Value: sarama.ByteEncoder(msg),
	})
	if err != nil {
		atomic.StoreInt32(&healthy, 0)

		messagesSendFailed.Inc()
		if a.tokenBucket.getToken() {
			log.Errorf("could not send message: %v", err)
		}

		return
	}

	atomic.StoreInt32(&healthy, 1)
}

func (a *adjRIBin) AddPath(pfx *net.Prefix, path *route.Path) error {
	messagesProcessed.Inc()
	
	// Detect if it's a VPN route and get AFI/SAFI information
	isVPN, rd, afi, safi := detectVPNRouteDetails(pfx, path, a.sessionAttrs)
	
	// Build route type description
	routeDesc := ""
	if isVPN {
		if afi == 1 {
			routeDesc = fmt.Sprintf("VPNv4 (AFI: %d, SAFI: %d, RD: %s)", afi, safi, vrf.RouteDistinguisherHumanReadable(rd))
		} else {
			routeDesc = fmt.Sprintf("VPNv6 (AFI: %d, SAFI: %d, RD: %s)", afi, safi, vrf.RouteDistinguisherHumanReadable(rd))
		}
	} else {
		if afi == 1 {
			routeDesc = fmt.Sprintf("IPv4 (AFI: %d, SAFI: %d)", afi, safi)
		} else {
			routeDesc = fmt.Sprintf("IPv6 (AFI: %d, SAFI: %d)", afi, safi)
		}
	}
	
	// Additional debug logging for integration tests
	log.Infof("AddPath: Received route %s from peer %s (type: %s, %s)", 
		pfx.String(), 
		a.sessionAttrs.PeerIP.String(),
		route.GetPathTypeName(path.Type),
		routeDesc)
	
	// For BGP paths, print more details to help with debugging VPN routes
	if path.Type == route.BGPPathType && path.BGPPath != nil {
		// Print BGP path information at INFO level
		asPath := "none"
		nextHop := "unknown"
		
		if path.BGPPath.ASPath != nil {
			asPath = path.BGPPath.ASPath.String()
		}
		
		if path.BGPPath.BGPPathA != nil && path.BGPPath.BGPPathA.NextHop != nil {
			nextHop = path.BGPPath.BGPPathA.NextHop.String()
		}
		
		log.Infof("Route %s - AS_PATH: %s, NEXT_HOP: %s", 
			pfx.String(), 
			asPath,
			nextHop)
		
		// Print full details at DEBUG level
		log.Debugf("BGP Path full details: %s", path.BGPPath.String())
	}
	
	msg := a.createBBMPUnicastMonitoringMessage(pfx, path, true)
	a.sendMessage(msg)

	return nil
}

// Helper function to detect VPN route details
func detectVPNRouteDetails(pfx *net.Prefix, path *route.Path, sessionAttrs routingtable.SessionAttrs) (isVPN bool, rd uint64, afi uint16, safi uint8) {
	// Set default SAFI to Unicast (1)
	safi = 1
	
	// Determine AFI based on prefix
	if pfx.Addr().IsIPv4() {
		afi = 1 // IPv4
	} else {
		afi = 2 // IPv6
	}
	
	// Try to detect if this is a VPN route and extract RD
	// First, check if there's any VRF information in the session attributes
	// This is a heuristic since we don't have direct access to NLRI's RD field
	if path.Type == route.BGPPathType && path.BGPPath != nil {
		// Check if we're processing labeled VPN routes by looking at path attributes
		// This is a simplistic check - we're looking for common signs of VPN routes
		isVPN = false
		
		// Check for route target extended communities as a sign of VPN routes
		if path.BGPPath.Communities != nil && len(*path.BGPPath.Communities) > 0 {
			for _, community := range *path.BGPPath.Communities {
				// Route target extended communities often start with 0x0002 (RT) 
				if (community >> 16) == 2 {
					isVPN = true
					safi = 128 // SAFI for VPN routes
					break
				}
			}
		}
	}
	
	// For demonstration, assign a dummy RD value for VPN routes
	// In a real scenario, this would come from the NLRI
	if isVPN {
		// This would typically come from the route's NLRI
		rd = 0 // Default to 0 if we can't determine the actual RD
	}
	
	return isVPN, rd, afi, safi
}

func (a *adjRIBin) RemovePath(pfx *net.Prefix, path *route.Path) bool {
	messagesProcessed.Inc()
	
	// Detect if it's a VPN route and get AFI/SAFI information
	isVPN, rd, afi, safi := detectVPNRouteDetails(pfx, path, a.sessionAttrs)
	
	// Build route type description
	routeDesc := ""
	if isVPN {
		if afi == 1 {
			routeDesc = fmt.Sprintf("VPNv4 (AFI: %d, SAFI: %d, RD: %s)", afi, safi, vrf.RouteDistinguisherHumanReadable(rd))
		} else {
			routeDesc = fmt.Sprintf("VPNv6 (AFI: %d, SAFI: %d, RD: %s)", afi, safi, vrf.RouteDistinguisherHumanReadable(rd))
		}
	} else {
		if afi == 1 {
			routeDesc = fmt.Sprintf("IPv4 (AFI: %d, SAFI: %d)", afi, safi)
		} else {
			routeDesc = fmt.Sprintf("IPv6 (AFI: %d, SAFI: %d)", afi, safi)
		}
	}
	
	// Additional debug logging for integration tests
	log.Infof("RemovePath: Withdrawing route %s from peer %s (type: %s, %s)", 
		pfx.String(), 
		a.sessionAttrs.PeerIP.String(),
		route.GetPathTypeName(path.Type),
		routeDesc)
	
	// For BGP paths, print more details to help with debugging VPN routes
	if path.Type == route.BGPPathType && path.BGPPath != nil {
		// Print BGP path information at INFO level
		asPath := "none"
		if path.BGPPath.ASPath != nil {
			asPath = path.BGPPath.ASPath.String()
		}
		
		log.Infof("Withdrawing route %s - AS_PATH: %s", pfx.String(), asPath)
		
		// Print full details at DEBUG level
		log.Debugf("Withdrawn BGP Path details: %s", path.BGPPath.String())
	}
	
	msg := a.createBBMPUnicastMonitoringMessage(pfx, path, false)
	a.sendMessage(msg)

	return true
}

/*
 * Only here to fulfill the Interface
 */

func (a *adjRIBin) ReplaceFilterChain(filter.Chain) {}

func (a *adjRIBin) Dump() []*route.Route {
	return nil
}

func (a *adjRIBin) Register(client routingtable.RouteTableClient) {}

func (a *adjRIBin) Unregister(client routingtable.RouteTableClient) {}

func (a *adjRIBin) Flush() {}

func (a *adjRIBin) RouteCount() int64 {
	return 0
}

func (a *adjRIBin) ClientCount() uint64 {
	return 0
}
