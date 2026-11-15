package mapper

import (
	"fmt"
	"net"
	"sync"

	"github.com/databeast/goatherd/internal/discovery"
)

// LocalMapper owns independent discovery state for each capture point.
type LocalMapper struct {
	mu     sync.RWMutex
	points map[uint32]*LocalCapturePoint
}

func NewLocalMapper() *LocalMapper {
	return &LocalMapper{points: make(map[uint32]*LocalCapturePoint)}
}

// AddCapturePoint registers an ID and returns its observation sink.
func (m *LocalMapper) AddCapturePoint(id uint32, maxHops uint8) (*LocalCapturePoint, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.points[id]; exists {
		return nil, fmt.Errorf("capture point %d already registered", id)
	}
	point := &LocalCapturePoint{analyzer: discovery.New(maxHops)}
	m.points[id] = point
	return point, nil
}

// CapturePoint looks up the sink and report source for a registered ID.
func (m *LocalMapper) CapturePoint(id uint32) (*LocalCapturePoint, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	point, exists := m.points[id]
	if !exists {
		return nil, fmt.Errorf("unknown capture point %d", id)
	}
	return point, nil
}

// LocalCapturePoint serializes access to its discovery evidence and reports.
type LocalCapturePoint struct {
	mu       sync.Mutex
	analyzer *discovery.Analyzer
}

func (p *LocalCapturePoint) ObserveARP(mac net.HardwareAddr, ip net.IP) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.analyzer.ObserveARP(mac, ip)
}

func (p *LocalCapturePoint) ObserveIPv4(dstMAC net.HardwareAddr, srcIP, dstIP net.IP, ttl uint8) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.analyzer.ObserveIPv4(dstMAC, srcIP, dstIP, ttl)
}

func (p *LocalCapturePoint) ObserveIPv4Ethernet(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, ttl uint8) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.analyzer.ObserveIPv4Ethernet(srcMAC, dstMAC, srcIP, dstIP, ttl)
}

// Report returns a snapshot of this capture point's evidence.
func (p *LocalCapturePoint) Report(upstream net.HardwareAddr) (discovery.Report, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.analyzer.Report(upstream)
}

// ReportWithEvidence takes both snapshots while holding the same lock.
func (p *LocalCapturePoint) ReportWithEvidence(upstream net.HardwareAddr) (discovery.Report, discovery.Evidence, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	report, err := p.analyzer.Report(upstream)
	selected := ""
	if len(upstream) != 0 {
		selected = upstream.String()
	}
	if err == nil {
		selected = report.UpstreamMAC
	}
	return report, p.analyzer.Evidence(selected), err
}
