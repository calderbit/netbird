//go:build scion && cgo && (linux || darwin) && !android && !ios

// Path diversity selection adapted from netsys-lab/tailscale-scion, BSD-3-Clause.
package scion

import (
	"sort"
	"time"

	"github.com/scionproto/scion/pkg/snet"
)

func selectDiversePaths(paths []snet.Path, limit int, threshold time.Duration) []snet.Path {
	if limit <= 0 || len(paths) == 0 {
		return nil
	}
	remaining := append([]snet.Path(nil), paths...)
	sort.SliceStable(remaining, func(i, j int) bool { return announcedLatency(remaining[i]) < announcedLatency(remaining[j]) })
	selected := make([]snet.Path, 0, min(limit, len(remaining)))
	used := make(map[string]struct{})
	latencyScale := max(threshold, time.Millisecond)
	for len(remaining) > 0 && len(selected) < limit {
		bestIndex := 0
		bestScore := -1e100
		fastest := announcedLatency(remaining[0])
		for i, candidate := range remaining {
			interfaces := candidate.Metadata().Interfaces
			overlap := 0
			for _, intf := range interfaces {
				if _, ok := used[intf.String()]; ok {
					overlap++
				}
			}
			novelty := 1.0
			if len(interfaces) > 0 {
				novelty -= float64(overlap) / float64(len(interfaces))
			}
			latencyPenalty := float64(announcedLatency(candidate)-fastest) / float64(latencyScale)
			score := novelty - latencyPenalty
			if score > bestScore {
				bestIndex, bestScore = i, score
			}
		}
		chosen := remaining[bestIndex]
		selected = append(selected, chosen)
		for _, intf := range chosen.Metadata().Interfaces {
			used[intf.String()] = struct{}{}
		}
		remaining = append(remaining[:bestIndex], remaining[bestIndex+1:]...)
	}
	return selected
}
