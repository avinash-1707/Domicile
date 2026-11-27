// Command transportbench measures the QUIC tunnel on a lossy, delayed link:
// stream-open latency, page-style loads and bulk throughput. It picked the
// tunnel transport and is kept for re-measuring QUIC tuning. It runs the
// server and the exit in one process over
// 127.0.0.1; run.sh shapes loopback with tc netem before each run, so it is
// only meaningful inside the Linux container started by `make bench-transport`.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"
)

func main() {
	var opts options
	flag.StringVar(&opts.label, "label", "unshaped", "scenario label printed in the results row")
	trials := flag.Int("trials", 5, "independent sessions")
	flag.IntVar(&opts.openIters, "open-iters", 20, "sequential stream-open round trips per trial")
	flag.IntVar(&opts.pageIters, "page-iters", 5, "page-style loads per trial")
	flag.IntVar(&opts.pageStreams, "page-streams", 30, "parallel streams per page load")
	flag.IntVar(&opts.pageObjectSize, "page-object-size", 20<<10, "bytes fetched per page stream")
	flag.DurationVar(&opts.bulkDuration, "bulk-duration", 5*time.Second, "single-stream bulk transfer duration per trial")
	header := flag.Bool("header", false, "print the table header and exit")
	flag.Parse()

	if *header {
		fmt.Println("| scenario | transport | open p50 | page p50 | page p95 (min–max) | bulk Mbit/s (min–max) |")
		fmt.Println("|---|---|---|---|---|---|")
		return
	}

	results := make([]result, 0, *trials)
	for i := range *trials {
		res, err := run(context.Background(), opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s / trial %d: %v\n", opts.label, i+1, err)
			os.Exit(1)
		}
		results = append(results, res)
	}

	s := summarizeTrials(results)
	fmt.Printf("| %s | quic | %s | %s | %s (%s–%s) | %.1f (%.1f–%.1f) |\n",
		opts.label,
		ms(s.openP50), ms(s.pageP50),
		ms(s.pageP95.median), ms(s.pageP95.min), ms(s.pageP95.max),
		s.bulk.median, s.bulk.min, s.bulk.max)
}

func ms(d time.Duration) string {
	return fmt.Sprintf("%.0f ms", float64(d)/float64(time.Millisecond))
}
