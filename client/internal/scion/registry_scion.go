//go:build scion && cgo && (linux || darwin) && !android && !ios

// Stable path reconciliation is adapted from netsys-lab/tailscale-scion,
// BSD-3-Clause.
package scion

func reconcileCandidates(old, discovered []*pathCandidate, active *pathCandidate) ([]*pathCandidate, *pathCandidate) {
	previous := make(map[PathID]*pathCandidate, len(old))
	for _, candidate := range old {
		previous[candidate.id] = candidate
	}

	var nextActive *pathCandidate
	for i, candidate := range discovered {
		if existing := previous[candidate.id]; existing != nil && existing.fingerprint == candidate.fingerprint {
			existing.remote = candidate.remote
			existing.expires = candidate.expires
			discovered[i] = existing
			candidate = existing
		}
		if active != nil && candidate.id == active.id && candidate.fingerprint == active.fingerprint {
			nextActive = candidate
		}
	}
	return discovered, nextActive
}
