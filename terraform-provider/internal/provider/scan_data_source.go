// Package provider — the `tfanalyze_scan` data source.
//
// Runs `detect.py --target <path> --format json` at plan time and
// surfaces the engine's `summary` block plus the `findings` list as
// Terraform values. Plans can then react to the score with `precondition`
// blocks or `null_resource` triggers — gating apply on a clean scan
// without external CI.
//
// Worked example (in `examples/data-sources/tfanalyze_scan/data-source.tf`):
//
//	data "tfanalyze_scan" "this" {
//	  target = path.module
//	}
//
//	resource "null_resource" "fail_below_threshold" {
//	  count = data.tfanalyze_scan.this.score < 80 ? "abort" : 0
//	}
//
package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Compile-time interface check.
var _ datasource.DataSource = &ScanDataSource{}

// ScanDataSource is the implementation of `data "tfanalyze_scan"`.
type ScanDataSource struct {
	cfg *providerConfig
}

// NewScanDataSource is the factory passed to provider.DataSources.
func NewScanDataSource() datasource.DataSource {
	return &ScanDataSource{}
}

// ScanDataSourceModel mirrors the HCL data source block.
type ScanDataSourceModel struct {
	// Inputs
	Target       types.String `tfsdk:"target"`
	Mode         types.String `tfsdk:"mode"`
	ShowInfo     types.Bool   `tfsdk:"show_info"`
	AttackGraph  types.Bool   `tfsdk:"attack_graph"`
	ScriptPath   types.String `tfsdk:"script_path"`

	// Outputs
	Score           types.Int64  `tfsdk:"score"`
	Grade           types.String `tfsdk:"grade"`
	ScoringVersion  types.Int64  `tfsdk:"scoring_version"`
	TotalFindings   types.Int64  `tfsdk:"total_findings"`
	CriticalCount   types.Int64  `tfsdk:"critical_count"`
	HighCount       types.Int64  `tfsdk:"high_count"`
	MediumCount     types.Int64  `tfsdk:"medium_count"`
	LowCount        types.Int64  `tfsdk:"low_count"`
	InfoCount       types.Int64  `tfsdk:"info_count"`
	FindingsJSON    types.String `tfsdk:"findings_json"`
	JSONReport      types.String `tfsdk:"json_report"`
}

// Metadata sets the data source's HCL type name (`tfanalyze_scan`).
func (d *ScanDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_scan"
}

// Schema describes the inputs (target/mode/...) and outputs (score/grade/...).
func (d *ScanDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Run a tf-analyze scan over a Terraform workspace at " +
			"plan time. Returns the engine's score / grade / counts plus the " +
			"full findings JSON. Use the score in `precondition` blocks or " +
			"as a `count` expression to gate apply on a clean scan.",
		Attributes: map[string]schema.Attribute{
			// ---------- inputs ----------
			"target": schema.StringAttribute{
				MarkdownDescription: "Workspace path to scan (absolute or " +
					"relative to the calling module).",
				Required: true,
			},
			"mode": schema.StringAttribute{
				MarkdownDescription: "Scan mode. One of `static` (default), " +
					"`diff`, `plan`, `pr-review`. `fleet` and `trend` are " +
					"not currently supported by the data source.",
				Optional: true,
			},
			"show_info": schema.BoolAttribute{
				MarkdownDescription: "Include INFO-tier findings (Module " +
					"Reuse advisories, etc.) in the output. Default `false`.",
				Optional: true,
			},
			"attack_graph": schema.BoolAttribute{
				MarkdownDescription: "Build the internet → crown-jewels " +
					"attack graph and promote critical-path findings.",
				Optional: true,
			},
			"script_path": schema.StringAttribute{
				MarkdownDescription: "Per-data-source override for the path " +
					"to `detect.py`. Falls back to the provider-block setting.",
				Optional: true,
			},

			// ---------- outputs ----------
			"score": schema.Int64Attribute{
				MarkdownDescription: "Workspace score, 0–100. Higher is better.",
				Computed:            true,
			},
			"grade": schema.StringAttribute{
				MarkdownDescription: "Letter grade — `A`, `B`, `B-`, `C`, `D`, or `F`.",
				Computed:            true,
			},
			"scoring_version": schema.Int64Attribute{
				MarkdownDescription: "Engine scoring formula version. Pinned " +
					"so a downstream gate can detect a formula change.",
				Computed: true,
			},
			"total_findings": schema.Int64Attribute{
				MarkdownDescription: "Total finding count (sum of all tiers).",
				Computed:            true,
			},
			"critical_count": schema.Int64Attribute{Computed: true},
			"high_count":     schema.Int64Attribute{Computed: true},
			"medium_count":   schema.Int64Attribute{Computed: true},
			"low_count":      schema.Int64Attribute{Computed: true},
			"info_count":     schema.Int64Attribute{Computed: true},
			"findings_json": schema.StringAttribute{
				MarkdownDescription: "Full findings list as a JSON string. " +
					"Use `jsondecode()` to inspect individual findings.",
				Computed: true,
			},
			"json_report": schema.StringAttribute{
				MarkdownDescription: "Full engine JSON output (summary + " +
					"findings + optional graph). `jsondecode()` to consume.",
				Computed: true,
			},
		},
	}
}

// Configure receives the provider-level configuration set in
// `Provider.Configure` and stashes it for `Read` to use.
func (d *ScanDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, _ *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	if cfg, ok := req.ProviderData.(*providerConfig); ok {
		d.cfg = cfg
	}
}

// Read runs the engine and populates the state.
func (d *ScanDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data ScanDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Resolve the engine command + script path. Per-data-source
	// `script_path` wins over the provider-level setting.
	engineCmd := "python3"
	scriptPath := ""
	if d.cfg != nil {
		engineCmd = d.cfg.EngineCommand
		scriptPath = d.cfg.ScriptPath
	}
	if !data.ScriptPath.IsNull() && data.ScriptPath.ValueString() != "" {
		scriptPath = data.ScriptPath.ValueString()
	}
	if scriptPath == "" {
		resp.Diagnostics.AddError(
			"tf-analyze engine path unresolved",
			"Set `script_path` in the data source or provider block, or "+
				"export `TFA_DETECT_PY` to point at `detect.py`.",
		)
		return
	}

	target := data.Target.ValueString()
	if target == "" {
		resp.Diagnostics.AddError(
			"target is required",
			"Set `target = path.module` (or another workspace path).",
		)
		return
	}
	// Resolve the target so symlinks / relative paths produce stable output.
	absTarget, err := filepath.Abs(target)
	if err != nil {
		resp.Diagnostics.AddError("could not resolve target path", err.Error())
		return
	}

	mode := data.Mode.ValueString()
	if mode == "" {
		mode = "static"
	}

	args := []string{
		scriptPath,
		"--target", absTarget,
		"--mode", mode,
		"--format", "json",
	}
	if !data.ShowInfo.IsNull() && data.ShowInfo.ValueBool() {
		args = append(args, "--show-info")
	}
	if !data.AttackGraph.IsNull() && data.AttackGraph.ValueBool() {
		args = append(args, "--attack-graph")
	}

	cmd := exec.CommandContext(ctx, engineCmd, args...)
	stdout, err := cmd.Output()
	if err != nil {
		// Wrap exit errors with stderr so users see the engine's
		// actual complaint (e.g. "no .tf files in target").
		stderr := ""
		if exitErr, ok := err.(*exec.ExitError); ok {
			stderr = string(exitErr.Stderr)
		}
		// Engine exits 1 when findings are present — that's success
		// for our purposes. Treat exit code > 1 as a real error.
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			// fall through; stdout still holds the JSON
		} else {
			resp.Diagnostics.AddError(
				"tf-analyze engine failed",
				fmt.Sprintf("invocation: %s %s\nstderr:\n%s\nerr: %s",
					engineCmd, strings.Join(args, " "), stderr, err.Error()),
			)
			return
		}
	}
	if len(stdout) == 0 {
		resp.Diagnostics.AddError("engine produced no output",
			"detect.py emitted nothing to stdout — common cause is a stderr-only crash. "+
				"Run the same command directly to see the failure.")
		return
	}

	var report struct {
		Summary struct {
			Score          int64  `json:"score"`
			Grade          string `json:"grade"`
			ScoringVersion int64  `json:"scoring_version"`
			Counts         struct {
				CRITICAL int64 `json:"CRITICAL"`
				HIGH     int64 `json:"HIGH"`
				MEDIUM   int64 `json:"MEDIUM"`
				LOW      int64 `json:"LOW"`
				INFO     int64 `json:"INFO"`
			} `json:"counts"`
		} `json:"summary"`
		Findings []json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal(stdout, &report); err != nil {
		resp.Diagnostics.AddError(
			"engine returned invalid JSON",
			fmt.Sprintf("could not parse stdout: %s\nfirst 500 bytes: %s",
				err.Error(), truncate(string(stdout), 500)),
		)
		return
	}

	data.Score = types.Int64Value(report.Summary.Score)
	data.Grade = types.StringValue(report.Summary.Grade)
	data.ScoringVersion = types.Int64Value(report.Summary.ScoringVersion)
	data.TotalFindings = types.Int64Value(int64(len(report.Findings)))
	data.CriticalCount = types.Int64Value(report.Summary.Counts.CRITICAL)
	data.HighCount = types.Int64Value(report.Summary.Counts.HIGH)
	data.MediumCount = types.Int64Value(report.Summary.Counts.MEDIUM)
	data.LowCount = types.Int64Value(report.Summary.Counts.LOW)
	data.InfoCount = types.Int64Value(report.Summary.Counts.INFO)

	findingsJSON, _ := json.Marshal(report.Findings)
	data.FindingsJSON = types.StringValue(string(findingsJSON))
	data.JSONReport = types.StringValue(string(stdout))

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
