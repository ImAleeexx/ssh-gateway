// Package limit implements limits on concurrent connections.
package limit

import "sync"

// Connections limits the number of concurrent connections, both in total and
// per remote IP. A zero limit means unlimited.
type Connections struct {
	Max      int
	MaxPerIP int

	mu    sync.Mutex
	total int
	perIP map[string]int
}

// Acquire reserves a connection slot for the given IP. It returns false if a
// limit is reached. Every successful Acquire must be followed by Release.
func (c *Connections) Acquire(ip string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.perIP == nil {
		c.perIP = make(map[string]int)
	}
	if c.Max > 0 && c.total >= c.Max {
		return false
	}
	if c.MaxPerIP > 0 && c.perIP[ip] >= c.MaxPerIP {
		return false
	}
	c.total++
	c.perIP[ip]++
	return true
}

// Release frees a connection slot that was reserved for the given IP.
func (c *Connections) Release(ip string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.perIP[ip] <= 1 {
		delete(c.perIP, ip)
	} else {
		c.perIP[ip]--
	}
	if c.total > 0 {
		c.total--
	}
}
