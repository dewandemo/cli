// Copyright © 2026 Harness Inc.
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/harness/cli/v3/modules/platform/projectcopy"
	"github.com/harness/cli/v3/pkg/cmdctx"
)

func projectCopy(ctx *cmdctx.Ctx) error {
	scope, err := projectCopyScope(ctx)
	if err != nil {
		return err
	}
	report, copyErr := projectcopy.Copy(ctx.Context, projectcopy.NewTransport(ctx.Auth), scope, cmdctx.GetBool(ctx.FlagValues, "apply"))
	if err := writeProjectCopyReport(ctx, report); err != nil {
		return err
	}
	return copyErr
}

func projectCopyScope(ctx *cmdctx.Ctx) (projectcopy.Scope, error) {
	if ctx.ProvidedFlags["dry-run"] && !cmdctx.GetBool(ctx.FlagValues, "dry-run") && !cmdctx.GetBool(ctx.FlagValues, "apply") {
		return projectcopy.Scope{}, errors.New("pass --apply to copy; --dry-run=false does not write")
	}
	if cmdctx.GetString(ctx.FlagValues, "resources") != "cd-core" {
		return projectcopy.Scope{}, errors.New("select --resources cd-core")
	}
	if ctx.Auth == nil {
		return projectcopy.Scope{}, errors.New("resolved authentication required")
	}
	if f := ctx.FormatFlags.Format; f != "" && f != "text" && f != "json" {
		return projectcopy.Scope{}, errors.New("project planning supports --format text or json")
	}
	if ctx.ProvidedFlags["project"] || (ctx.Level != "" && ctx.Level != "project") {
		return projectcopy.Scope{}, errors.New("use explicit --from/--to projects, not --project or a different --level")
	}
	if len(ctx.Args) > 0 || ctx.Id != "" {
		return projectcopy.Scope{}, errors.New("project planning accepts flags only")
	}
	scope := projectcopy.Scope{Account: ctx.Auth.AccountID, Org: ctx.Auth.OrgID, Source: ctx.MigrateFrom, Destination: ctx.MigrateTo}
	return scope, scope.Validate()
}

func writeProjectCopyReport(ctx *cmdctx.Ctx, report projectcopy.Report) error {
	format := ctx.FormatFlags.Format
	if format == "" {
		format = "text"
	}
	if format != "text" && format != "json" {
		return errors.New("project planning supports --format text or json")
	}
	var w io.Writer = os.Stdout
	if ctx.FormatFlags.OutFile != "" {
		// Exclusive creation also rejects symlinks/hardlinks to profiles or other inputs.
		f, err := os.OpenFile(ctx.FormatFlags.OutFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return errors.New("cannot create report: --out must name a new file")
		}
		writeErr := renderProjectCopyReport(f, format, report)
		closeErr := f.Close()
		if writeErr != nil || closeErr != nil {
			return errors.New("cannot write project planning report")
		}
		return nil
	}
	if err := renderProjectCopyReport(w, format, report); err != nil {
		return errors.New("cannot write project planning report")
	}
	return nil
}

func renderProjectCopyReport(w io.Writer, format string, r projectcopy.Report) error {
	if format == "json" {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	}
	if r.Coverage == "cd-core" {
		return renderCDCoreReport(w, r)
	}
	if _, err := fmt.Fprintf(w, "PARTIAL — read-only secret planning; apply unavailable\nAccount: %s; org: %s; source: %s; destination: %s\nSecret inventory complete: %t\nReadiness: %s\nNOT INVENTORIED: connectors, pipelines and all other project resources\n", r.Scope.Account, r.Scope.Org, r.Scope.Source, r.Scope.Destination, r.InventoryComplete, r.Readiness); err != nil {
		return err
	}
	for _, item := range r.Secrets {
		if _, err := fmt.Fprintf(w, "Secret #%d: %s — %s (%s)\n", item.Number, item.Type, item.Capability, item.Reason); err != nil {
			return err
		}
	}
	return nil
}

func renderCDCoreReport(w io.Writer, r projectcopy.Report) error {
	if _, err := fmt.Fprintf(w, "cd-core %s\nAccount: %s; org: %s; source: %s; destination: %s\nReadiness: %s\n", r.Mode, r.Scope.Account, r.Scope.Org, r.Scope.Source, r.Scope.Destination, r.Readiness); err != nil {
		return err
	}
	for _, item := range r.Results {
		if _, err := fmt.Fprintf(w, "%s %s: %s", item.Kind, item.Identifier, item.Action); err != nil {
			return err
		}
		if item.Reason != "" {
			if _, err := fmt.Fprintf(w, " — %s", item.Reason); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(w); err != nil {
			return err
		}
	}
	for _, item := range r.DelegateSelectors {
		if _, err := fmt.Fprintf(w, "delegate selector %s: %s — %s\n", item.Identifier, item.Action, item.Reason); err != nil {
			return err
		}
	}
	if len(r.SecretsPendingValue) > 0 {
		if _, err := fmt.Fprintf(w, "Inline secrets were stored with placeholder value %s. Update each one before running the destination project:\n", projectcopy.InlineSecretPlaceholder); err != nil {
			return err
		}
		for _, id := range r.SecretsPendingValue {
			if _, err := fmt.Fprintf(w, "harness update secret %s --org %s --project %s --set value='...'\n", id, r.Scope.Org, r.Scope.Destination); err != nil {
				return err
			}
		}
	}
	return nil
}
