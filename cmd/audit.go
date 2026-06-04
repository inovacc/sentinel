package cmd

import (
	"fmt"
	"io"

	jsonpkg "encoding/json"

	"github.com/inovacc/sentinel/internal/audit"
	"github.com/inovacc/sentinel/internal/datadir"
	"github.com/inovacc/sentinel/internal/settings"
	"github.com/spf13/cobra"
)

// jsonNewEncoder is a thin alias so the encoder helper reads cleanly.
func jsonNewEncoder(w io.Writer) *jsonpkg.Encoder { return jsonpkg.NewEncoder(w) }

// auditFilterFlags carries the shared filter flags for tail/query/export.
type auditFilterFlags struct {
	since     string
	until     string
	eventType string
	actor     string
	outcome   string
	n         int
	jsonOut   bool
}

func (f auditFilterFlags) toFilter() audit.Filter {
	return audit.Filter{
		Since:     f.since,
		Until:     f.until,
		EventType: f.eventType,
		Actor:     f.actor,
		Outcome:   audit.Outcome(f.outcome),
		Limit:     f.n,
	}
}

// auditDBPath returns the configured audit db path, falling back to the datadir
// default when the config is unset or unreadable.
func auditDBPath() string {
	cfg, err := settings.Load(datadir.ConfigPath())
	if err == nil && cfg.Audit.DBPath != "" {
		return cfg.Audit.DBPath
	}
	return datadir.AuditDBPath()
}

func newAuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Inspect and verify the security audit log",
		Long: `Read-only access to the tamper-evident security audit log at
~/.sentinel/audit.db. Use 'verify' to check chain integrity (exit non-zero on any
break), 'tail'/'query' to inspect events, and 'export' to produce an offline
artifact.`,
		SilenceUsage: true,
	}
	cmd.AddCommand(newAuditTailCmd(), newAuditQueryCmd(), newAuditVerifyCmd(), newAuditExportCmd())
	return cmd
}

func newAuditTailCmd() *cobra.Command {
	var f auditFilterFlags
	cmd := &cobra.Command{
		Use:   "tail",
		Short: "Show the most recent audit events",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runAuditTail(cmd.OutOrStdout(), auditDBPath(), f)
		},
	}
	cmd.Flags().StringVar(&f.eventType, "type", "", "filter by event type")
	cmd.Flags().StringVar(&f.actor, "actor", "", "filter by actor device id")
	cmd.Flags().IntVar(&f.n, "n", 50, "number of events to show")
	cmd.Flags().BoolVar(&f.jsonOut, "json", false, "output as JSON")
	return cmd
}

func newAuditQueryCmd() *cobra.Command {
	var f auditFilterFlags
	cmd := &cobra.Command{
		Use:   "query",
		Short: "Query audit events in a time range",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runAuditQuery(cmd.OutOrStdout(), auditDBPath(), f)
		},
	}
	cmd.Flags().StringVar(&f.since, "since", "", "RFC3339 lower bound (inclusive)")
	cmd.Flags().StringVar(&f.until, "until", "", "RFC3339 upper bound (inclusive)")
	cmd.Flags().StringVar(&f.eventType, "type", "", "filter by event type")
	cmd.Flags().StringVar(&f.outcome, "outcome", "", "filter by outcome (allow|deny|error)")
	cmd.Flags().BoolVar(&f.jsonOut, "json", false, "output as JSON")
	return cmd
}

func newAuditVerifyCmd() *cobra.Command {
	var fromSegment int
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify audit-log chain integrity (exit non-zero on first break)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runAuditVerify(cmd.OutOrStdout(), auditDBPath(), fromSegment)
		},
	}
	cmd.Flags().IntVar(&fromSegment, "from-segment", 0, "start verification at this sealed segment (0 = genesis)")
	return cmd
}

func newAuditExportCmd() *cobra.Command {
	var format string
	var f auditFilterFlags
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export audit events as JSON or CSV to stdout",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runAuditExport(cmd.OutOrStdout(), auditDBPath(), format, f)
		},
	}
	cmd.Flags().StringVar(&format, "format", "json", "output format (json|csv)")
	cmd.Flags().StringVar(&f.since, "since", "", "RFC3339 lower bound (inclusive)")
	cmd.Flags().StringVar(&f.eventType, "type", "", "filter by event type")
	return cmd
}

func openAuditReader(path string) (*audit.SQLiteLogger, error) {
	l, err := audit.Open(audit.Options{DBPath: path})
	if err != nil {
		return nil, fmt.Errorf("open audit db: %w", err)
	}
	return l, nil
}

func runAuditTail(w io.Writer, path string, f auditFilterFlags) error {
	l, err := openAuditReader(path)
	if err != nil {
		return err
	}
	defer func() { _ = l.Close() }()

	rows, err := l.Tail(f.toFilter())
	if err != nil {
		return err
	}
	return writeAuditRows(w, rows, f.jsonOut)
}

func runAuditQuery(w io.Writer, path string, f auditFilterFlags) error {
	l, err := openAuditReader(path)
	if err != nil {
		return err
	}
	defer func() { _ = l.Close() }()

	rows, err := l.Query(f.toFilter())
	if err != nil {
		return err
	}
	return writeAuditRows(w, rows, f.jsonOut)
}

func runAuditVerify(w io.Writer, path string, fromSegment int) error {
	l, err := openAuditReader(path)
	if err != nil {
		return err
	}
	defer func() { _ = l.Close() }()

	brk, err := l.Verify(fromSegment)
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	if brk != nil {
		_, _ = fmt.Fprintf(w, "INTEGRITY FAILURE: %s\n", brk.Error())
		return fmt.Errorf("audit chain broken at seq %d (%s)", brk.Seq, brk.Kind)
	}
	_, _ = fmt.Fprintln(w, "audit chain OK")
	return nil
}

func runAuditExport(w io.Writer, path, format string, f auditFilterFlags) error {
	l, err := openAuditReader(path)
	if err != nil {
		return err
	}
	defer func() { _ = l.Close() }()

	return l.Export(w, format, f.toFilter())
}

func writeAuditRows(w io.Writer, rows []audit.Row, jsonOut bool) error {
	if jsonOut {
		// Reuse the JSON exporter shape for a single consistent format.
		enc := newJSONEncoder(w)
		return enc.Encode(rows)
	}
	for _, r := range rows {
		_, _ = fmt.Fprintf(w, "%d\t%s\t%s\t%s/%s\t%s\t%s\n",
			r.Seq, r.TS, r.EventType, r.ActorDeviceID, r.ActorRole, r.Outcome, r.Target)
	}
	return nil
}

func newJSONEncoder(w io.Writer) *jsonEncoder { return &jsonEncoder{w: w} }

type jsonEncoder struct{ w io.Writer }

func (e *jsonEncoder) Encode(v any) error {
	enc := jsonNewEncoder(e.w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return fmt.Errorf("encode json: %w", err)
	}
	return nil
}
