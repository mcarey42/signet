package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mcarey42/signet/internal/kernel"
)

// Privileged access: being eligible for an authority is not holding it.
//
//	signet pam eligible   what I could hold, and what is switched on now
//	signet pam activate   switch one on, for a reason and a bounded time
//	signet pam pending    requests I could decide
//	signet pam approve|deny|kill
//
// The reason field is not bureaucracy. An activation record without a reason
// tells you an authority was used and nothing about why, which is the half that
// matters when you are reading it back six months later.

const pamUsage = `signet pam — privileged access (eligible vs held)

  eligible   what this principal may hold, and what is active now
  activate   request an authority, giving a reason and a duration
  pending    activation requests this principal could decide
  approve    approve a pending request (never your own)
  deny       refuse a pending request
  kill       end an active activation early
`

func cmdPAM(args []string) error {
	if len(args) < 1 {
		fmt.Fprint(os.Stderr, pamUsage)
		return errors.New("pam: expected a subcommand")
	}
	switch args[0] {
	case "eligible":
		return pamEligible(args[1:])
	case "activate":
		return pamActivate(args[1:])
	case "pending":
		return pamPending(args[1:])
	case "approve", "deny", "kill":
		return pamDecide(args[0], args[1:])
	case "-h", "--help", "help":
		fmt.Print(pamUsage)
		return nil
	}
	return fmt.Errorf("pam: unknown subcommand %q — run `signet pam help`", args[0])
}

type pamFlags struct {
	addr  *string
	token *string
}

func pamCommon(fs *flag.FlagSet) pamFlags {
	return pamFlags{
		addr:  fs.String("addr", "http://127.0.0.1:8200", "a running node"),
		token: fs.String("token", "", "this principal's token"),
	}
}

func (f pamFlags) check() error {
	if *f.token == "" {
		return errors.New("pam: -token is required")
	}
	return nil
}

func pamEligible(args []string) error {
	fs := flag.NewFlagSet("pam eligible", flag.ExitOnError)
	c := pamCommon(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := c.check(); err != nil {
		return err
	}
	body, err := httpGetAuth(strings.TrimSuffix(*c.addr, "/")+"/v1/pam/eligible", *c.token)
	if err != nil {
		return fmt.Errorf("pam eligible: %w", err)
	}
	var resp struct {
		Data struct {
			Eligible []kernel.Eligibility `json:"eligible"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return err
	}
	if len(resp.Data.Eligible) == 0 {
		fmt.Println("this principal holds no authority anywhere")
		return nil
	}
	fmt.Printf("%-10s %-14s %-26s %-10s %s\n", "STATE", "ROLE", "SCOPE", "EXPIRES", "BINDING")
	for _, e := range resp.Data.Eligible {
		state, expires := "eligible", "-"
		switch {
		case e.Held && !e.Binding.ActivationRequired:
			state = "held"
			if e.Binding.NotAfter != 0 {
				expires = time.Unix(e.Binding.NotAfter, 0).Format("15:04:05")
			}
		case e.Held:
			state = "ACTIVE"
			expires = time.Unix(e.Activation.Expiry, 0).Format("15:04:05")
		case e.Activation != nil && e.Activation.State == kernel.ActivationPending:
			state = "pending"
		}
		fmt.Printf("%-10s %-14s %-26s %-10s %s\n", state, e.Binding.Role, e.Binding.Scope, expires, e.Binding.ID)
	}
	fmt.Println("\n'eligible' means the authority exists but is switched off. Activating it is a")
	fmt.Println("logged, time-bounded act — that is the difference from simply holding it.")
	return nil
}

func pamActivate(args []string) error {
	fs := flag.NewFlagSet("pam activate", flag.ExitOnError)
	c := pamCommon(fs)
	binding := fs.String("binding", "", "the binding to activate (see `signet pam eligible`)")
	reason := fs.String("reason", "", "why this authority is needed now (required)")
	forDur := fs.Duration("for", 0, "how long to hold it (clamped by policy)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := c.check(); err != nil {
		return err
	}
	if *binding == "" {
		return errors.New("pam activate: -binding is required")
	}
	if *reason == "" {
		return errors.New(
			"pam activate: -reason is required. An activation record with no reason tells you an " +
				"authority was switched on and nothing about why, which is the half that matters " +
				"when someone reads it back later")
	}
	payload, _ := json.Marshal(map[string]any{
		"binding": *binding, "reason": *reason, "for_seconds": int64(forDur.Seconds()),
	})
	code, body, err := httpPost(strings.TrimSuffix(*c.addr, "/")+"/v1/pam/activate", *c.token, payload)
	if err != nil {
		return fmt.Errorf("pam activate: %w", err)
	}
	if code != 200 {
		return fmt.Errorf("pam activate: %s", strings.TrimSpace(string(body)))
	}
	var resp struct {
		Data struct {
			ID     string `json:"id"`
			State  string `json:"state"`
			Expiry int64  `json:"expiry"`
			Role   string `json:"role"`
			Scope  string `json:"scope"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return err
	}
	d := resp.Data
	switch d.State {
	case string(kernel.ActivationActive):
		fmt.Printf("active\n  %s at %s\n  until %s\n  id    %s\n",
			d.Role, d.Scope, time.Unix(d.Expiry, 0).Format(time.RFC3339), d.ID)
		fmt.Println("\nThis expires on its own. Nothing needs to revoke it, and every renewal")
		fmt.Println("re-checks both this activation and the eligibility beneath it.")
	case string(kernel.ActivationPending):
		fmt.Printf("pending approval\n  %s at %s\n  id %s\n", d.Role, d.Scope, d.ID)
		fmt.Println("\nSomeone with admin authority at that scope must approve — and it cannot")
		fmt.Println("be you. That is what requiring approval was for.")
	default:
		fmt.Printf("%s\n  id %s\n", d.State, d.ID)
	}
	return nil
}

func pamPending(args []string) error {
	fs := flag.NewFlagSet("pam pending", flag.ExitOnError)
	c := pamCommon(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := c.check(); err != nil {
		return err
	}
	body, err := httpGetAuth(strings.TrimSuffix(*c.addr, "/")+"/v1/pam/pending", *c.token)
	if err != nil {
		return fmt.Errorf("pam pending: %w", err)
	}
	var resp struct {
		Data struct {
			Pending []kernel.Activation `json:"pending"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return err
	}
	if len(resp.Data.Pending) == 0 {
		fmt.Println("nothing awaiting your decision")
		return nil
	}
	fmt.Printf("%-14s %-24s %-20s %s\n", "ROLE", "SCOPE", "REQUESTED", "REASON")
	for _, a := range resp.Data.Pending {
		fmt.Printf("%-14s %-24s %-20s %s\n", a.Role, a.Scope,
			time.Unix(a.RequestedAt, 0).Format(time.RFC3339), a.Reason)
		fmt.Printf("  subject %s  id %s\n", a.Subject, a.ID)
	}
	return nil
}

func pamDecide(verb string, args []string) error {
	fs := flag.NewFlagSet("pam "+verb, flag.ExitOnError)
	c := pamCommon(fs)
	subject := fs.String("subject", "", "the requesting principal's id")
	id := fs.String("id", "", "the activation id")
	reason := fs.String("reason", "", "why")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := c.check(); err != nil {
		return err
	}
	if *subject == "" || *id == "" {
		return fmt.Errorf("pam %s: -subject and -id are both required (see `signet pam pending`)", verb)
	}
	payload, _ := json.Marshal(map[string]any{
		"subject": *subject, "id": *id, "verb": verb, "reason": *reason,
	})
	code, body, err := httpPost(strings.TrimSuffix(*c.addr, "/")+"/v1/pam/decide", *c.token, payload)
	if err != nil {
		return fmt.Errorf("pam %s: %w", verb, err)
	}
	if code != 200 {
		return fmt.Errorf("pam %s: %s", verb, strings.TrimSpace(string(body)))
	}
	past := map[string]string{"approve": "approved", "deny": "denied", "kill": "killed"}[verb]
	fmt.Printf("%s %s\n", past, *id)
	return nil
}
