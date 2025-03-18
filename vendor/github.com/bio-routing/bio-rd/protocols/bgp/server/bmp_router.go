package server

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	bnet "github.com/bio-routing/bio-rd/net"
	"github.com/bio-routing/bio-rd/protocols/bgp/packet"
	bmppkt "github.com/bio-routing/bio-rd/protocols/bmp/packet"
	"github.com/bio-routing/bio-rd/routingtable"
	"github.com/bio-routing/bio-rd/routingtable/filter"
	"github.com/bio-routing/bio-rd/routingtable/vrf"
	"github.com/bio-routing/bio-rd/util/log"
	"github.com/bio-routing/tflow2/convert"
)

type RouterInterface interface {
	Name() string
	Address() net.IP
	GetVRF(vrfID uint64) *vrf.VRF
	GetVRFs() []*vrf.VRF
	Ready(vrf uint64, afi uint16) (bool, error)
}

// RouterConfig represents the configuration required for BMP router
type RouterConfig struct {
	Passive          bool
	IgnorePeerASNs   []uint32
	IgnorePrePolicy  bool
	IgnorePostPolicy bool
}

// Router represents a BMP enabled route in BMP context
type Router struct {
	name             string
	nameMu           sync.RWMutex
	address          net.IP
	port             uint16
	passive          bool
	con              net.Conn
	established      uint32
	reconnectTimeMin int
	reconnectTimeMax int
	reconnectTime    int
	dialTimeout      time.Duration
	reconnectTimer   *time.Timer
	vrfRegistry      *vrf.VRFRegistry
	neighborManager  *neighborManager
	runMu            sync.Mutex
	stop             chan struct{}

	ribClients       map[afiClient]struct{}
	ribClientsMu     sync.Mutex
	adjRIBInFactory  adjRIBInFactoryI
	ignorePeerASNs   []uint32
	ignoredPeers     map[bnet.IP]struct{}
	ignorePrePolicy  bool
	ignorePostPolicy bool

	counters routerCounters
}

type routerCounters struct {
	routeMonitoringMessages      uint64
	statisticsReportMessages     uint64
	peerDownNotificationMessages uint64
	peerUpNotificationMessages   uint64
	initiationMessages           uint64
	terminationMessages          uint64
	routeMirroringMessages       uint64
}

type neighbor struct {
	vrfID       uint64
	peerAddress [16]byte
	localAS     uint32
	peerAS      uint32
	routerID    uint32
	fsm         *FSM
	opt         *packet.DecodeOptions
}

func newRouter(addr net.IP, port uint16, arif adjRIBInFactoryI, config RouterConfig) *Router {
	return &Router{
		address:          addr,
		port:             port,
		passive:          config.Passive,
		reconnectTimeMin: 30,  // Suggested by RFC 7854
		reconnectTimeMax: 720, // Suggested by RFC 7854
		reconnectTimer:   time.NewTimer(time.Duration(0)),
		dialTimeout:      time.Second * 5,
		vrfRegistry:      vrf.NewVRFRegistry(),
		neighborManager:  newNeighborManager(),
		stop:             make(chan struct{}),
		ribClients:       make(map[afiClient]struct{}),
		adjRIBInFactory:  arif,
		ignorePeerASNs:   config.IgnorePeerASNs,
		ignoredPeers:     make(map[bnet.IP]struct{}),
		ignorePrePolicy:  config.IgnorePrePolicy,
		ignorePostPolicy: config.IgnorePostPolicy,
	}
}

func (r *Router) Ready(vrf uint64, afi uint16) (bool, error) {
	neighbors := r.neighborManager.list()
	if len(neighbors) == 0 {
		return false, fmt.Errorf("no neighbor present")
	}

	if !neighborsIncludeVRF(neighbors, vrf) {
		return false, fmt.Errorf("vrf not present for neighbor")
	}

	for _, n := range neighbors {
		if n.vrfID != vrf {
			continue
		}

		var fsmAfi *fsmAddressFamily
		if afi == 4 {
			fsmAfi = n.fsm.ipv4Unicast
			// Check VPNv4 if available
			if n.fsm.ipv4VPNUnicast != nil && !n.fsm.ipv4VPNUnicast.endOfRIBMarkerReceived.Load() {
				return false, fmt.Errorf("VPNv4 end of rib not yet received")
			}
		} else {
			fsmAfi = n.fsm.ipv6Unicast
			// Check VPNv6 if available
			if n.fsm.ipv6VPNUnicast != nil && !n.fsm.ipv6VPNUnicast.endOfRIBMarkerReceived.Load() {
				return false, fmt.Errorf("VPNv6 end of rib not yet received")
			}
		}

		if !fsmAfi.endOfRIBMarkerReceived.Load() {
			return false, fmt.Errorf("end of rib not yet received")
		}
	}

	return true, nil
}

func neighborsIncludeVRF(neighbors []*neighbor, vrfID uint64) bool {
	for _, n := range neighbors {
		if n.vrfID == vrfID {
			return true
		}
	}

	return false
}

// GetVRF get's a VRF
func (r *Router) GetVRF(rd uint64) *vrf.VRF {
	return r.vrfRegistry.GetVRFByName(vrf.RouteDistinguisherHumanReadable(rd))
}

// GetVRFs gets all VRFs
func (r *Router) GetVRFs() []*vrf.VRF {
	return r.vrfRegistry.List()
}

// Name gets a routers name
func (r *Router) Name() string {
	r.nameMu.RLock()
	defer r.nameMu.RUnlock()
	return r.name
}

// Address gets a routers address
func (r *Router) Address() net.IP {
	return r.address
}

func (r *Router) serve(con net.Conn) error {
	defer r.cleanup()

	r.con = con
	r.runMu.Lock()
	defer r.con.Close()
	defer r.runMu.Unlock()

	for {
		select {
		case <-r.stop:
			return nil
		default:
		}

		msg, err := recvBMPMsg(r.con)
		if err != nil {
			return fmt.Errorf("unable to get message: %w", err)
		}

		r.processMsg(msg)
	}
}

func (r *Router) cleanup() {
	r.vrfRegistry.DisposeAll()
	r.neighborManager.disposeAll()
}

func (r *Router) processMsg(msg []byte) {
	bmpMsg, err := bmppkt.Decode(msg)
	if err != nil {
		log.Errorf("unable to decode BMP message: %v", err)
		return
	}

	switch bmpMsg.MsgType() {
	case bmppkt.PeerUpNotificationType:
		err = r.processPeerUpNotification(bmpMsg.(*bmppkt.PeerUpNotification))
		if err != nil {
			log.Errorf("unable to process peer up notification: %v", err)
		}
	case bmppkt.PeerDownNotificationType:
		r.processPeerDownNotification(bmpMsg.(*bmppkt.PeerDownNotification))
	case bmppkt.InitiationMessageType:
		r.processInitiationMsg(bmpMsg.(*bmppkt.InitiationMessage))
	case bmppkt.TerminationMessageType:
		r.processTerminationMsg(bmpMsg.(*bmppkt.TerminationMessage))
		return
	case bmppkt.RouteMonitoringType:
		r.processRouteMonitoringMsg(bmpMsg.(*bmppkt.RouteMonitoringMsg))
	case bmppkt.RouteMirroringMessageType:
		atomic.AddUint64(&r.counters.routeMirroringMessages, 1)
	}
}

func (r *Router) processRouteMonitoringMsg(msg *bmppkt.RouteMonitoringMsg) {
	atomic.AddUint64(&r.counters.routeMonitoringMessages, 1)

	// Ignore pre / post policy messages if configured
	if r.ignorePrePolicy && !msg.PerPeerHeader.GetLFlag() || r.ignorePostPolicy && msg.PerPeerHeader.GetLFlag() {
		return
	}

	// Ignore messages for peers with ASN found in ignorePeerASNs
	if _, exists := r.ignoredPeers[peerAddrToBNetAddr(msg.PerPeerHeader.PeerAddress, msg.PerPeerHeader.GetIPVersion())]; exists {
		return
	}

	n := r.neighborManager.getNeighbor(msg.PerPeerHeader.PeerDistinguisher, msg.PerPeerHeader.PeerAddress)
	if n == nil {
		log.Errorf("Received route monitoring message for non-existent neighbor %d/%v on %s", msg.PerPeerHeader.PeerDistinguisher, msg.PerPeerHeader.PeerAddress, r.address.String())
		return
	}

	s := n.fsm.state.(*establishedState)
	opt := s.fsm.decodeOptions()
	opt.Use32BitASN = !msg.PerPeerHeader.GetAFlag()

	// Make sure timestamp is set even if the router didn't set it
	ts := msg.PerPeerHeader.Timestamp
	if ts == 0 {
		ts = uint32(time.Now().Unix())
	}

	s.msgReceived(msg.BGPUpdate, opt, msg.PerPeerHeader.GetLFlag(), ts)
}

func (r *Router) processInitiationMsg(msg *bmppkt.InitiationMessage) {
	atomic.AddUint64(&r.counters.initiationMessages, 1)

	r.nameMu.Lock()
	defer r.nameMu.Unlock()

	const (
		stringType   = 0
		sysDescrType = 1
		sysNameType  = 2
	)

	logMsg := fmt.Sprintf("Received initiation message from %s:", r.address.String())

	for _, tlv := range msg.TLVs {
		switch tlv.InformationType {
		case stringType:
			logMsg += fmt.Sprintf(" Message: %q", string(tlv.Information))
		case sysDescrType:
			logMsg += fmt.Sprintf(" sysDescr.: %s", string(tlv.Information))
		case sysNameType:
			r.name = string(tlv.Information)
			logMsg += fmt.Sprintf(" sysName.: %s", string(tlv.Information))
		}
	}

	log.Info(logMsg)
}

func (r *Router) processTerminationMsg(msg *bmppkt.TerminationMessage) {
	const (
		stringType = 0
		reasonType = 1

		adminDown     = 0
		unspecReason  = 1
		outOfRes      = 2
		redundantCon  = 3
		permAdminDown = 4
	)

	atomic.AddUint64(&r.counters.terminationMessages, 1)
	logMsg := fmt.Sprintf("Received termination message from %s: ", r.address.String())
	for _, tlv := range msg.TLVs {
		switch tlv.InformationType {
		case stringType:
			logMsg += fmt.Sprintf("Message: %q", string(tlv.Information))
		case reasonType:
			reason := convert.Uint16b(tlv.Information[:1])
			switch reason {
			case adminDown:
				logMsg += "Session administratively down"
			case unspecReason:
				logMsg += "Unspecified reason"
			case outOfRes:
				logMsg += "Out of resources"
			case redundantCon:
				logMsg += "Redundant connection"
			case permAdminDown:
				logMsg += "Session permanently administratively closed"
			}
		}
	}

	log.Info(logMsg)

	r.con.Close()
	r.neighborManager.disposeAll()
}

func (r *Router) processPeerDownNotification(msg *bmppkt.PeerDownNotification) {
	atomic.AddUint64(&r.counters.peerDownNotificationMessages, 1)

	peerAddr := peerAddrToBNetAddr(msg.PerPeerHeader.PeerAddress, msg.PerPeerHeader.GetIPVersion())
	if _, exists := r.ignoredPeers[peerAddr]; exists {
		delete(r.ignoredPeers, peerAddr)
		logPeerUpDownNotification(r, msg.PerPeerHeader.PeerAddress, msg.PerPeerHeader.PeerDistinguisher, false, true)
		return
	}

	logPeerUpDownNotification(r, msg.PerPeerHeader.PeerAddress, msg.PerPeerHeader.PeerDistinguisher, false, false)

	err := r.neighborManager.neighborDown(msg.PerPeerHeader.PeerDistinguisher, msg.PerPeerHeader.PeerAddress)
	if err != nil {
		log.Errorf("Failed to process peer down notification: %v", err)
	}
}

func peerAddrToBNetAddr(a [16]byte, ipVersion uint8) bnet.IP {
	addrLen := net.IPv4len
	if ipVersion == 6 {
		addrLen = net.IPv6len
	}

	// bnet.IPFromBytes can only fail if length of argument is not 4 or 16. However, length is ensured here.
	ip, _ := bnet.IPFromBytes(a[16-addrLen:])
	return ip
}

func (r *Router) isIgnoredPeerASN(asn uint32) bool {
	for _, x := range r.ignorePeerASNs {
		if x == asn {
			return true
		}
	}

	return false
}

func (r *Router) processPeerUpNotification(msg *bmppkt.PeerUpNotification) error {
	atomic.AddUint64(&r.counters.peerUpNotificationMessages, 1)

	peerAddress := peerAddrToBNetAddr(msg.PerPeerHeader.PeerAddress, msg.PerPeerHeader.GetIPVersion())
	localAddress := peerAddrToBNetAddr(msg.LocalAddress, msg.PerPeerHeader.GetIPVersion())

	if r.isIgnoredPeerASN(msg.PerPeerHeader.PeerAS) {
		r.ignoredPeers[peerAddress] = struct{}{}
		logPeerUpDownNotification(r, msg.PerPeerHeader.PeerAddress, msg.PerPeerHeader.PeerDistinguisher, true, true)
		return nil
	}

	logPeerUpDownNotification(r, msg.PerPeerHeader.PeerAddress, msg.PerPeerHeader.PeerDistinguisher, true, false)

	if len(msg.SentOpenMsg) < packet.MinOpenLen {
		return fmt.Errorf("received peer up notification for %v: Invalid sent open message: %v", msg.PerPeerHeader.PeerAddress, msg.SentOpenMsg)
	}

	sentOpen, err := packet.DecodeOpenMsg(bytes.NewBuffer(msg.SentOpenMsg[packet.HeaderLen:]))
	if err != nil {
		return fmt.Errorf("unable to decode sent open message sent from %v to %v: %w", r.address.String(), msg.PerPeerHeader.PeerAddress, err)
	}

	if len(msg.ReceivedOpenMsg) < packet.MinOpenLen {
		return fmt.Errorf("received peer up notification for %v: Invalid received open message: %v", msg.PerPeerHeader.PeerAddress, msg.ReceivedOpenMsg)
	}

	recvOpen, err := packet.DecodeOpenMsg(bytes.NewBuffer(msg.ReceivedOpenMsg[packet.HeaderLen:]))
	if err != nil {
		return fmt.Errorf("unable to decode received open message sent from %v to %v: %w", msg.PerPeerHeader.PeerAddress, r.address.String(), err)
	}

	fsm := &FSM{
		isBMP:            true,
		ribsInitialized:  true,
		bmpRouterAddress: r.address,
		peer: &peer{
			routerID:        sentOpen.BGPIdentifier,
			addr:            peerAddress.Dedup(),
			localAddr:       localAddress.Dedup(),
			peerASN:         msg.PerPeerHeader.PeerAS,
			localASN:        uint32(sentOpen.ASN),
			ipv4:            &peerAddressFamily{},
			ipv6:            &peerAddressFamily{},
			vrf:             r.vrfRegistry.CreateVRFIfNotExists(vrf.RouteDistinguisherHumanReadable(msg.PerPeerHeader.PeerDistinguisher), msg.PerPeerHeader.PeerDistinguisher),
			adjRIBInFactory: r.adjRIBInFactory,
		},
	}

	fsm.peer.fsms = []*FSM{
		fsm,
	}

	fsm.peer.configureBySentOpen(sentOpen)

	// Initialize IPv4 unicast RIB
	rib4, found := fsm.peer.vrf.RIBByName("inet.0")
	if !found {
		return fmt.Errorf("unable to get inet RIB")
	}
	fsm.ipv4Unicast = newFSMAddressFamily(packet.AFIIPv4, packet.SAFIUnicast, &peerAddressFamily{
		rib:               rib4,
		importFilterChain: filter.NewAcceptAllFilterChain(),
	}, fsm)
	fsm.ipv4Unicast.bmpInit()

	// Initialize IPv6 unicast RIB
	rib6, found := fsm.peer.vrf.RIBByName("inet6.0")
	if !found {
		return fmt.Errorf("unable to get inet6 RIB")
	}
	fsm.ipv6Unicast = newFSMAddressFamily(packet.AFIIPv6, packet.SAFIUnicast, &peerAddressFamily{
		rib:               rib6,
		importFilterChain: filter.NewAcceptAllFilterChain(),
	}, fsm)
	fsm.ipv6Unicast.bmpInit()
	
	// Check if peer advertises VPNv4 or VPNv6 capability
	var hasVPNv4Capability, hasVPNv6Capability bool
	capsList := getCaps(recvOpen.OptParams)
	for _, caps := range capsList {
		for _, cap := range caps {
			if cap.Code == packet.MultiProtocolCapabilityCode {
				mpCap := cap.Value.(packet.MultiProtocolCapability)
				if mpCap.AFI == packet.AFIIPv4 && mpCap.SAFI == packet.SAFIVPNUnicast {
					hasVPNv4Capability = true
				}
				if mpCap.AFI == packet.AFIIPv6 && mpCap.SAFI == packet.SAFIVPNUnicast {
					hasVPNv6Capability = true
				}
			}
		}
	}
	
	// If peer has VPNv4 capability, initialize VPNv4 RIB
	if hasVPNv4Capability {
		// Create dedicated RIB for VPNv4 routes
		vpnv4RIB, found := fsm.peer.vrf.RIBByName("vpnv4.0")
		if !found {
			// If RIB doesn't exist, create it
			var err error
			vpnv4RIB, err = fsm.peer.vrf.CreateVPNv4UnicastLocRIB("vpnv4.0")
			if err != nil {
				log.Errorf("Unable to create VPNv4 RIB: %v", err)
			}
		}
		
		// Create VPNv4 address family
		fsm.ipv4VPNUnicast = newFSMAddressFamily(packet.AFIIPv4, packet.SAFIVPNUnicast, &peerAddressFamily{
			rib:               vpnv4RIB,
			importFilterChain: filter.NewAcceptAllFilterChain(),
		}, fsm)
		fsm.ipv4VPNUnicast.bmpInit()
	}
	
	// If peer has VPNv6 capability, initialize VPNv6 RIB
	if hasVPNv6Capability {
		// Create dedicated RIB for VPNv6 routes
		vpnv6RIB, found := fsm.peer.vrf.RIBByName("vpnv6.0")
		if !found {
			// If RIB doesn't exist, create it
			var err error
			vpnv6RIB, err = fsm.peer.vrf.CreateVPNv6UnicastLocRIB("vpnv6.0")
			if err != nil {
				log.Errorf("Unable to create VPNv6 RIB: %v", err)
			}
		}
		
		// Create VPNv6 address family
		fsm.ipv6VPNUnicast = newFSMAddressFamily(packet.AFIIPv6, packet.SAFIVPNUnicast, &peerAddressFamily{
			rib:               vpnv6RIB,
			importFilterChain: filter.NewAcceptAllFilterChain(),
		}, fsm)
		fsm.ipv6VPNUnicast.bmpInit()
	}

	fsm.state = newOpenSentState(fsm)
	openSent := fsm.state.(*openSentState)
	openSent.openMsgReceived(recvOpen)

	fsm.state = newEstablishedState(fsm)
	n := &neighbor{
		vrfID:       msg.PerPeerHeader.PeerDistinguisher,
		localAS:     fsm.peer.localASN,
		peerAS:      msg.PerPeerHeader.PeerAS,
		peerAddress: msg.PerPeerHeader.PeerAddress,
		routerID:    recvOpen.BGPIdentifier,
		fsm:         fsm,
		opt:         fsm.decodeOptions(),
	}

	err = r.neighborManager.addNeighbor(n)
	if err != nil {
		return fmt.Errorf("unable to add neighbor: %w", err)
	}

	r.ribClientsMu.Lock()
	defer r.ribClientsMu.Unlock()
	n.registerClients(r.ribClients)

	return nil
}

func (n *neighbor) registerClients(clients map[afiClient]struct{}) {
	for ac := range clients {
		if ac.afi == packet.AFIIPv4 {
			// Register for IPv4 unicast
			if n.fsm.ipv4Unicast != nil {
				n.fsm.ipv4Unicast.adjRIBIn.Register(ac.client)
			}
			
			// Register for IPv4 VPN unicast if available
			if n.fsm.ipv4VPNUnicast != nil {
				n.fsm.ipv4VPNUnicast.adjRIBIn.Register(ac.client)
			}
		}
		
		if ac.afi == packet.AFIIPv6 {
			// Register for IPv6 unicast
			if n.fsm.ipv6Unicast != nil {
				n.fsm.ipv6Unicast.adjRIBIn.Register(ac.client)
			}
			
			// Register for IPv6 VPN unicast if available
			if n.fsm.ipv6VPNUnicast != nil {
				n.fsm.ipv6VPNUnicast.adjRIBIn.Register(ac.client)
			}
		}
	}
}

func (p *peer) configureBySentOpen(msg *packet.BGPOpen) {
	capsList := getCaps(msg.OptParams)
	for _, caps := range capsList {
		for _, cap := range caps {
			switch cap.Code {
			case packet.AddPathCapabilityCode:
				addPathCap := cap.Value.(packet.AddPathCapability)
				for _, addPathCapTuple := range addPathCap {
					peerFamily := p.addressFamily(addPathCapTuple.AFI, addPathCapTuple.SAFI)
					if peerFamily == nil {
						continue
					}
					switch addPathCapTuple.SendReceive {
					case packet.AddPathSend:
						peerFamily.addPathSend = routingtable.ClientOptions{
							MaxPaths: 10,
						}
					case packet.AddPathReceive:
						peerFamily.addPathReceive = true
					case packet.AddPathSendReceive:
						peerFamily.addPathReceive = true
						peerFamily.addPathSend = routingtable.ClientOptions{
							MaxPaths: 10,
						}
					}
				}
			case packet.ASN4CapabilityCode:
				if p.localASN == packet.ASTransASN {
					p.localASN = cap.Value.(packet.ASN4Capability).ASN4
				}
			}
		}
	}
}

func getCaps(optParams []packet.OptParam) []packet.Capabilities {
	res := make([]packet.Capabilities, 0)
	for _, optParam := range optParams {
		if optParam.Type != packet.CapabilitiesParamType {
			continue
		}

		res = append(res, optParam.Value.(packet.Capabilities))
	}

	return res
}

func addrToNetIP(a [16]byte) net.IP {
	for i := 0; i < 12; i++ {
		if a[i] != 0 {
			return net.IP(a[:])
		}
	}

	return net.IP(a[12:])
}

func logPeerUpDownNotification(r *Router, peerAddr [16]byte, RD uint64, up bool, ignored bool) {
	msg := "peer down notification received"
	if up {
		msg = "peer up notification received"
	}

	log.WithFields(log.Fields{
		"address":            r.address.String(),
		"router":             r.name,
		"peer_address":       addrToNetIP(peerAddr).String(),
		"peer_distinguisher": vrf.RouteDistinguisherHumanReadable(RD),
		"ignored":            ignored,
	}).Infof(msg)
}
