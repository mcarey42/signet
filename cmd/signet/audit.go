package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/mcarey42/signet/internal/audit"
	"github.com/mcarey42/signet/internal/store"
)

// The audit log is hash-chained, so an edit breaks every link after it. That is
// only half the story: an attacker who holds the node can recompute the chain,
// or simply truncate it, and what remains verifies perfectly. What defeats that
// is a checkpoint held somewhere they do not control (internal/audit).
//
//	signet audit verify     re-derive the chain and report the first break
//	signet audit checkpoint sign a statement of the current head
//	signet audit witness    hand a peer's checkpoint to this node, verified
//	signet audit witnessed  what this node holds on other domains

const auditUsage = `signet audit — tamper-evident history

  verify      re-derive the hash chain and report the first break
  checkpoint  produce a signed statement of the current chain head
  witness     verify and record another domain's checkpoint here
  witnessed   what this node holds on the domains it witnesses
`

func cmdAudit(args []string) error {
	if len(args) < 1 {
		fmt.Fprint(os.Stderr, auditUsage)
		return errors.New("audit: expected a subcommand")
	}
	switch args[0] {
	case "verify":
		return auditVerify(args[1:])
	case "checkpoint":
		return auditCheckpoint(args[1:])
	case "witness":
		return auditWitness(args[1:])
	case "witnessed":
		return auditWitnessed(args[1:])
	case "-h", "--help", "help":
		fmt.Print(auditUsage)
		return nil
	}
	return fmt.Errorf("audit: unknown subcommand %q — run `signet audit help`", args[0])
}

func auditVerify(args []string) error {
	fs := flag.NewFlagSet("audit verify", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "data directory (the server must be stopped)")
	sealKey := fs.String("seal", "", "seal (default DATA-DIR/seal.key)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dataDir == "" {
		return errors.New("audit verify: -data-dir is required")
	}
	node, k, err := openNode(*dataDir, sealURI(*dataDir, *sealKey))
	if err != nil {
		return err
	}
	defer node.Close()

	count, head, err := k.VerifyAudit(context.Background())
	if err != nil {
		fmt.Printf("audit chain FAILED after %d entries\n  %v\n", count, err)
		fmt.Println("\nThe chain is a local check: it proves nobody edited an entry in place.")
		fmt.Println("It cannot prove nothing was removed from the end, or that the whole log was")
		fmt.Println("not rebuilt — for that, compare against a witness (`signet audit witnessed`")
		fmt.Println("on the peer that holds this domain's checkpoints).")
		return errors.New("audit chain does not verify")
	}
	fmt.Printf("audit chain intact\n  entries: %d\n  head:    %s\n", count, head)
	if count == 0 {
		fmt.Println("\nAn empty chain verifies trivially. That is not evidence of anything.")
	}
	return nil
}

func auditCheckpoint(args []string) error {
	fs := flag.NewFlagSet("audit checkpoint", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "data directory (the server must be stopped)")
	addr := fs.String("addr", "", "a running node's API instead")
	sealKey := fs.String("seal", "", "seal (default DATA-DIR/seal.key)")
	domain := fs.String("domain", "", "this trust domain's name")
	nodeName := fs.String("node", "", "this node's name")
	out := fs.String("out", "", "write the signed checkpoint here")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var blob []byte
	if *addr != "" {
		body, err := httpGet(strings.TrimSuffix(*addr, "/") + "/v1/audit/checkpoint")
		if err != nil {
			return fmt.Errorf("audit checkpoint: %w", err)
		}
		blob = body
	} else {
		if *dataDir == "" {
			return errors.New("audit checkpoint: pass -addr for a running node, or -data-dir with it stopped")
		}
		node, k, err := openNode(*dataDir, sealURI(*dataDir, *sealKey))
		if err != nil {
			return err
		}
		defer node.Close()
		c, err := k.Checkpoint(context.Background(), *domain, *nodeName)
		if err != nil {
			return fmt.Errorf("audit checkpoint: %w", err)
		}
		if blob, err = json.MarshalIndent(c, "", "  "); err != nil {
			return err
		}
	}

	var signed audit.Signed
	if err := json.Unmarshal(blob, &signed); err != nil {
		return fmt.Errorf("audit checkpoint: %w", err)
	}
	claim, err := signed.Claim()
	if err != nil {
		return err
	}
	fmt.Printf("checkpoint\n  domain:  %s\n  entries: %d\n  head:    %s\n  at:      %s\n",
		claim.Domain, claim.Count, claim.Head, time.Unix(claim.AtSec, 0).UTC().Format(time.RFC3339))
	if *out != "" {
		if err := os.WriteFile(*out, blob, 0o644); err != nil {
			return err
		}
		fmt.Printf("\nwritten to %s\n", *out)
	}
	fmt.Println("\nA checkpoint is worth only as much as where it is held. Give it to a witness")
	fmt.Println("this node cannot reach: `signet audit witness` on a peer domain.")
	return nil
}

// auditWitness is the anchoring step: fetch a peer's checkpoint, the entries
// that justify it, and hand both to a witness that verifies before recording.
func auditWitness(args []string) error {
	fs := flag.NewFlagSet("audit witness", flag.ExitOnError)
	subject := fs.String("subject", "", "the domain to witness, e.g. https://home.example.net:8200")
	subjectToken := fs.String("subject-token", "", "token with read authority at / on the subject (to fetch entries)")
	witness := fs.String("witness", "", "the node that will hold the evidence")
	witnessToken := fs.String("witness-token", "", "token with write authority at / on the witness")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *subject == "" || *witness == "" {
		return errors.New("audit witness: -subject and -witness are both required")
	}
	if *witnessToken == "" {
		return errors.New("audit witness: -witness-token is required")
	}
	sub := strings.TrimSuffix(*subject, "/")
	wit := strings.TrimSuffix(*witness, "/")

	cpBlob, err := httpGet(sub + "/v1/audit/checkpoint")
	if err != nil {
		return fmt.Errorf("audit witness: fetching the checkpoint: %w", err)
	}
	var signed audit.Signed
	if err := json.Unmarshal(cpBlob, &signed); err != nil {
		return fmt.Errorf("audit witness: %w", err)
	}
	claim, err := signed.Claim()
	if err != nil {
		return err
	}
	keyBlob, err := httpGet(sub + "/v1/audit/pubkey")
	if err != nil {
		return fmt.Errorf("audit witness: fetching the checkpoint key: %w", err)
	}
	var keyResp struct {
		PEM string `json:"pem"`
	}
	if err := json.Unmarshal(keyBlob, &keyResp); err != nil {
		return err
	}

	// Ask the witness how far it has already seen, so we send exactly the
	// entries it needs to verify the extension itself.
	from := uint64(0)
	if held, err := httpGet(wit + "/v1/audit/witnessed?domain=" + claim.Domain); err == nil {
		var w audit.Witnessed
		if json.Unmarshal(held, &w) == nil {
			from = w.Count
		}
	}
	var entries []store.AuditEntry
	if claim.Count > from {
		if *subjectToken == "" {
			return fmt.Errorf(
				"audit witness: the witness is at %d entries and the subject claims %d, so %d entries "+
					"are needed to justify the extension. Pass -subject-token with read authority at "+
					"/ so they can be fetched — a witness verifies extensions rather than trusting them",
				from, claim.Count, claim.Count-from)
		}
		body, err := httpGetAuth(fmt.Sprintf("%s/v1/audit/entries?after=%d&up_to=%d", sub, from, claim.Count), *subjectToken)
		if err != nil {
			return fmt.Errorf("audit witness: fetching entries: %w", err)
		}
		var er struct {
			Entries []store.AuditEntry `json:"entries"`
		}
		if err := json.Unmarshal(body, &er); err != nil {
			return err
		}
		entries = er.Entries
	}

	req, _ := json.Marshal(map[string]any{
		"checkpoint": &signed, "entries": entries, "pubkey": keyResp.PEM,
	})
	code, body, err := httpPost(wit+"/v1/audit/witness", *witnessToken, req)
	if err != nil {
		return fmt.Errorf("audit witness: %w", err)
	}
	if code == http.StatusConflict {
		fmt.Printf("CONFLICT — the witness holds evidence that %s rewrote its log\n\n", claim.Domain)
		var out map[string]any
		_ = json.Unmarshal(body, &out)
		if c, ok := out["conflict"].(map[string]any); ok {
			fmt.Printf("  %v\n", c["reason"])
		}
		fmt.Println("\nThis is the anchored audit working. The witness keeps what it saw before,")
		fmt.Println("and will not accept a history that contradicts it.")
		return errors.New("audit chain conflict")
	}
	if code != http.StatusOK {
		return fmt.Errorf("audit witness: the witness refused (%d): %s", code, strings.TrimSpace(string(body)))
	}
	fmt.Printf("witnessed\n  domain:  %s\n  entries: %d\n  head:    %s\n", claim.Domain, claim.Count, claim.Head)
	if claim.Count > from {
		fmt.Printf("  verified %d new entries by replaying them onto the head it already held\n", claim.Count-from)
	}
	return nil
}

func auditWitnessed(args []string) error {
	fs := flag.NewFlagSet("audit witnessed", flag.ExitOnError)
	addr := fs.String("addr", "", "the witness node")
	dataDir := fs.String("data-dir", "", "data directory instead (the server must be stopped)")
	sealKey := fs.String("seal", "", "seal (default DATA-DIR/seal.key)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var records []*audit.Witnessed
	if *addr != "" {
		body, err := httpGet(strings.TrimSuffix(*addr, "/") + "/v1/audit/witnessed")
		if err != nil {
			return err
		}
		var resp struct {
			Witnessed []*audit.Witnessed `json:"witnessed"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return err
		}
		records = resp.Witnessed
	} else {
		if *dataDir == "" {
			return errors.New("audit witnessed: pass -addr or -data-dir")
		}
		node, k, err := openNode(*dataDir, sealURI(*dataDir, *sealKey))
		if err != nil {
			return err
		}
		defer node.Close()
		if records, err = k.AllWitnessed(context.Background()); err != nil {
			return err
		}
	}
	if len(records) == 0 {
		fmt.Println("this node witnesses no domains")
		fmt.Println("\nA domain that witnesses nobody and is witnessed by nobody has a hash chain")
		fmt.Println("and nothing anchoring it.")
		return nil
	}
	fmt.Printf("%-26s %-8s %-10s %s\n", "DOMAIN", "ENTRIES", "STATE", "HEAD")
	bad := false
	for _, w := range records {
		state := "ok"
		if w.Conflict != nil {
			state, bad = "CONFLICT", true
		}
		fmt.Printf("%-26s %-8d %-10s %s\n", w.Domain, w.Count, state, short(w.Head))
	}
	for _, w := range records {
		if w.Conflict != nil {
			fmt.Printf("\n%s: %s\n", w.Domain, w.Conflict.Reason)
			fmt.Printf("  detected %s\n", time.Unix(w.Conflict.DetectedAt, 0).UTC().Format(time.RFC3339))
		}
	}
	if bad {
		return errors.New("a witnessed domain is in conflict")
	}
	return nil
}

func httpGet(url string) ([]byte, error) { return httpGetAuth(url, "") }

func httpGetAuth(url, token string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned %s: %s", url, resp.Status, strings.TrimSpace(string(body)))
	}
	return body, nil
}

func httpPost(url, token string, payload []byte) (int, []byte, error) {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	resp, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return resp.StatusCode, body, nil
}
