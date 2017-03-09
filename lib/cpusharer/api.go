/*
	Package cpusharer implements co-operative CPU sharing between goroutines.

	Package cpusharer may be used by groups of co-operating goroutines to share
	CPU resources so that blocking operations are fully concurrent but avoiding
	the thundering herd problem when large numbers of goroutines need the CPU,
	impacting the responsiveness of other goroutines such as dashboards and
	health checks.
	Each goroutine calls the GrabCpu method when it starts and wraps blocking
	operations with a pair of ReleaseCpu/GrabCpu calls.
	A typical programming pattern is:
		cpuSharer := cpusharer.New*CpuSharer() // Pick your sharer of choice.
		for work := range workChannel {
			cpuSharer.Go(func(work workType) {
				work.compute()
				cpuSharer.ReleaseCpu()
				work.block()
				cpuSharer.GrabCpu()
				work.moreCompute()
			}(work)
		}
*/
package cpusharer

import (
	"runtime"
	"sync"
	"time"
)

type CpuSharer interface {
	GrabCpu()
	ReleaseCpu()
}

type FifoCpuSharer struct {
	semaphore     chan struct{}
	mutex         sync.Mutex
	lastIdleEvent time.Time
	numIdleEvents uint64
	Statistics    Statistics
}

// NewFifoCpuSharer creates a simple FIFO CpuSharer. CPU access is granted in
// the order in which they are requested.
func NewFifoCpuSharer() *FifoCpuSharer {
	return &FifoCpuSharer{semaphore: make(chan struct{}, runtime.NumCPU())}
}

// GetStatistics will update and return the Statistics.
func (s *FifoCpuSharer) GetStatistics() Statistics {
	return s.getStatistics()
}

func (s *FifoCpuSharer) Go(goFunc func()) {
	startGoroutine(s, goFunc)
}

func (s *FifoCpuSharer) GrabCpu() {
	s.grabCpu()
}

func (s *FifoCpuSharer) ReleaseCpu() {
	<-s.semaphore
}

func (s *FifoCpuSharer) Sleep(duration time.Duration) {
	sleep(s, duration)
}

type Statistics struct {
	LastIdleEvent time.Time
	NumCpuRunning uint
	NumCpu        uint
	NumIdleEvents uint64
}
