// 批量扫描：并发探测多个目标
package quicprobe

import (
	"bufio"
	"context"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Scan 并发探测多个目标
func Scan(targets []Target, cfg Config) []Result {
	if len(targets) == 0 {
		return nil
	}
	workers := cfg.Concurrency
	if workers < 1 {
		workers = 1
	}
	if workers > len(targets) {
		workers = len(targets)
	}

	results := make([]Result, len(targets))
	jobs := make(chan int, len(targets))
	var wg sync.WaitGroup
	var done int64

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				results[idx] = Probe(targets[idx], cfg)
				n := atomic.AddInt64(&done, 1)
				if OnProgress != nil {
					OnProgress(int(n), len(targets), results[idx])
				}
			}
		}()
	}

	ctx, cancel := context.WithTimeout(context.Background(),
		time.Duration(len(targets)/workers+1)*cfg.Timeout+30*time.Second)
	defer cancel()

	go func() {
		defer close(jobs)
		for i := range targets {
			select {
			case <-ctx.Done():
				return
			case jobs <- i:
			}
		}
	}()

	wg.Wait()

	// 排序：确认 QUIC 的排前面，然后按 host/port
	sort.SliceStable(results, func(i, j int) bool {
		if results[i].IsQUIC() != results[j].IsQUIC() {
			return results[i].IsQUIC()
		}
		if results[i].Host != results[j].Host {
			return results[i].Host < results[j].Host
		}
		return results[i].Port < results[j].Port
	})
	return results
}

// OnProgress 进度回调（可选，由 CLI 设置）
var OnProgress func(done, total int, r Result)

// LoadTargets 从文件读取目标列表（每行一个）
func LoadTargets(path string, defaultPort int) ([]Target, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var targets []Target
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if t, ok := ParseTargetLine(sc.Text(), defaultPort); ok {
			targets = append(targets, t)
		}
	}
	return targets, sc.Err()
}

// Summary 统计汇总
type Summary struct {
	Total           int            `json:"total"`
	QuicConfirmed   int            `json:"quic_confirmed"`
	NonQUIC         int            `json:"udp_resp"`
	OpenOrFiltered  int            `json:"open_or_filtered"`
	VendorBreakdown map[string]int `json:"vendor_breakdown,omitempty"`
}

// Summarize 统计结果分布
func Summarize(results []Result) Summary {
	s := Summary{Total: len(results), VendorBreakdown: map[string]int{}}
	for _, r := range results {
		switch r.State {
		case StateQuicConfirmed:
			s.QuicConfirmed++
			if r.StackHint != "" {
				s.VendorBreakdown[r.StackHint]++
			}
		case StateNonQUIC:
			s.NonQUIC++
		default:
			s.OpenOrFiltered++
		}
	}
	if len(s.VendorBreakdown) == 0 {
		s.VendorBreakdown = nil
	}
	return s
}
