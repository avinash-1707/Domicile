// Command transportbench measures tunnel transports on a lossy, delayed link:
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
	"slices"
	"strings"
	"time"
)

func main() {
	var opts options
	flag.StringVar(&opts.label, "label", "unshaped", "scenario label printed in the results row")
	transportList := flag.String("transports", "quic", "comma-separated transports to run")
	trials := flag.Int("trials", 5, "independent sessions per transport; order alternates between trials")
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

	names := strings.Split(*transportList, ",")
	for _, name := range names {
		if _, ok := transports[name]; !ok {
			fmt.Fprintf(os.Stderr, "unknown transport %q\n", name)
			os.Exit(2)
		}
	}

	// Alternating the order cancels out drift in the shared link and
	// machine between the first and second transport of each trial.
	results := make(map[string][]result, len(names))
	for i := range *trials {
		order := slices.Clone(names)
		if i%2 == 1 {
			slices.Reverse(order)
		}
		for _, name := range order {
			res, err := run(context.Background(), transports[name], opts)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s / %s / trial %d: %v\n", opts.label, name, i+1, err)
				os.Exit(1)
			}
			results[name] = append(results[name], res)
		}
	}

	for _, name := range names {
		s := summarizeTrials(results[name])
		fmt.Printf("| %s | %s | %s | %s | %s (%s–%s) | %.1f (%.1f–%.1f) |\n",
			opts.label, name,
			ms(s.openP50), ms(s.pageP50),
			ms(s.pageP95.median), ms(s.pageP95.min), ms(s.pageP95.max),
			s.bulk.median, s.bulk.min, s.bulk.max)
	}
}

func ms(d time.Duration) string {
	return fmt.Sprintf("%.0f ms", float64(d)/float64(time.Millisecond))
}
