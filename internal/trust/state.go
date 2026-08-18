package trust

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// State is what a consumer remembers between bundle fetches: the highest epoch
// it has accepted per domain, and the key it pinned for each.
//
// Without this, epoch numbers would be decoration. A signed bundle stays valid
// forever as a signed artifact, so the only thing standing between a consumer
// and a replayed older one is a memory of how far it has already come. That
// memory has to survive restarts, so it is a file.
type State struct {
	path    string
	Domains map[string]DomainState `json:"domains"`
}

type DomainState struct {
	// PinnedSPKI is the fingerprint learned out of band at bootstrap. Once set
	// it is not changed by anything a bundle says — rotating a root is an
	// out-of-band event by construction, because a key that could authorize its
	// own replacement would make pinning meaningless (E-01 FED-3).
	PinnedSPKI string `json:"pinned_spki"`
	LastEpoch  uint64 `json:"last_epoch"`
	UpdatedAt  int64  `json:"updated_at"`
	// Bundle is the domain's last accepted bundle, kept verbatim so it can be
	// re-verified rather than re-fetched. A consumer that federates with
	// several domains holds one of these per domain and never merges them.
	Bundle []byte `json:"bundle,omitempty"`
}

// LoadState reads consumer state, returning an empty one if the file is absent.
func LoadState(path string) (*State, error) {
	s := &State{path: path, Domains: map[string]DomainState{}}
	blob, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(blob, s); err != nil {
		return nil, fmt.Errorf(
			"trust: %s is not readable as trust state: %w. Refusing to continue rather than "+
				"starting from a blank slate, which would forget every epoch already seen and "+
				"reopen the rollback this file exists to prevent", path, err)
	}
	if s.Domains == nil {
		s.Domains = map[string]DomainState{}
	}
	s.path = path
	return s, nil
}

// Pin records the fingerprint a consumer was told to trust for a domain.
//
// Re-pinning a domain to a different key is refused. Changing an anchor is a
// deliberate act with real consequences, and it should look like one — deleting
// the state file — rather than happening quietly inside a routine update.
func (s *State) Pin(domain, spki string) error {
	cur, ok := s.Domains[domain]
	if ok && cur.PinnedSPKI != "" && cur.PinnedSPKI != spki {
		return fmt.Errorf(
			"trust: domain %q is already pinned to %s and this would change it to %s. If the root "+
				"really did rotate, confirm the new fingerprint out of band and remove %s to "+
				"re-bootstrap; if it did not, something is trying to move your trust",
			domain, cur.PinnedSPKI, spki, s.path)
	}
	cur.PinnedSPKI = spki
	s.Domains[domain] = cur
	return nil
}

// Accept records a verified bundle as the newest seen.
func (s *State) Accept(domain string, epoch uint64, atSec int64) {
	cur := s.Domains[domain]
	if epoch >= cur.LastEpoch {
		cur.LastEpoch = epoch
		cur.UpdatedAt = atSec
		s.Domains[domain] = cur
	}
}

func (s *State) Get(domain string) DomainState { return s.Domains[domain] }

// Save writes the state atomically. A half-written state file would leave a
// consumer with no record of where it had got to.
func (s *State) Save() error {
	if s.path == "" {
		return errors.New("trust: no state path")
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	blob, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, blob, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// DomainNames returns the pinned domains in a stable order.
func (s *State) DomainNames() []string {
	out := make([]string, 0, len(s.Domains))
	for d := range s.Domains {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}
