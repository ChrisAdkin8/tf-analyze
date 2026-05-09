// Package provider implements the tfanalyze Terraform provider.
//
// Surface today: a single data source `tfanalyze_scan` that runs the
// engine over a workspace and returns the score, grade, counts, and
// findings.  This lets a Terraform plan emit warnings or fail outright
// when the workspace's tf-analyze grade drops below a threshold —
// covering the same gate the CI Action does, but without external
// infrastructure.
//
// Roadmap (not in v1):
//   - `tfanalyze_gate` resource: declarative pass/fail gate on the score
//     that fails `terraform apply` when below threshold.
//   - `tfanalyze_apply_fixes` resource: runs `--apply-fixes` as a
//     declarative remediation step.
package provider

import (
	"context"
	"os"
	"os/exec"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Compile-time interface checks.
var _ provider.Provider = &TfanalyzeProvider{}

// TfanalyzeProvider is the root provider.
type TfanalyzeProvider struct {
	// Version is the provider's semver. Set at build time.
	Version string
}

// New constructs the provider used by main.go.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &TfanalyzeProvider{Version: version}
	}
}

// TfanalyzeProviderModel mirrors the provider configuration block
// `provider "tfanalyze" { ... }`. All fields are optional; sane
// defaults are derived from the host environment when absent.
type TfanalyzeProviderModel struct {
	// EngineCommand is the executable used to invoke the engine.
	// Default: `python3` (relies on PATH lookup of detect.py via the
	// `script_path` field on the data source). Engine-developer
	// escape hatch.
	EngineCommand types.String `tfsdk:"engine_command"`
	// ScriptPath is the absolute path to detect.py. Default: looks
	// for `$TFA_DETECT_PY` env var, then falls back to
	// `~/.tf-analyze/scripts/detect.py`. The data source's own
	// `script_path` argument overrides this.
	ScriptPath types.String `tfsdk:"script_path"`
}

// Metadata declares the provider's source address and version.
func (p *TfanalyzeProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "tfanalyze"
	resp.Version = p.Version
}

// Schema declares the provider configuration block.
func (p *TfanalyzeProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Provider for the tf-analyze Terraform static analysis engine. " +
			"Exposes a `tfanalyze_scan` data source that runs the engine " +
			"over a workspace and returns the score / grade / findings, " +
			"so plans and applies can be gated on a clean scan without " +
			"external CI infrastructure.",
		Attributes: map[string]schema.Attribute{
			"engine_command": schema.StringAttribute{
				MarkdownDescription: "Executable used to run the engine. Defaults to `python3`.",
				Optional:            true,
			},
			"script_path": schema.StringAttribute{
				MarkdownDescription: "Absolute path to `detect.py`. Defaults to " +
					"`$TFA_DETECT_PY` if set, else `~/.tf-analyze/scripts/detect.py`. " +
					"The `script_path` argument on the data source overrides this.",
				Optional: true,
			},
		},
	}
}

// providerConfig is what Configure stashes for downstream data sources.
type providerConfig struct {
	EngineCommand string
	ScriptPath    string
}

// Configure validates + resolves the provider block at plan time.
func (p *TfanalyzeProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data TfanalyzeProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	cfg := &providerConfig{
		EngineCommand: data.EngineCommand.ValueString(),
		ScriptPath:    data.ScriptPath.ValueString(),
	}
	if cfg.EngineCommand == "" {
		cfg.EngineCommand = "python3"
	}
	if cfg.ScriptPath == "" {
		if envPath := os.Getenv("TFA_DETECT_PY"); envPath != "" {
			cfg.ScriptPath = envPath
		} else if home, err := os.UserHomeDir(); err == nil {
			cfg.ScriptPath = home + "/.tf-analyze/scripts/detect.py"
		}
	}
	// Surface a clear warning at provider-config time if the engine
	// can't be found — beats a cryptic exec error per data source.
	if cfg.ScriptPath == "" {
		resp.Diagnostics.AddWarning(
			"tf-analyze engine path unresolved",
			"Set `script_path` in the provider block, or export "+
				"`TFA_DETECT_PY` so the data source knows where detect.py lives.",
		)
	} else if _, err := os.Stat(cfg.ScriptPath); err != nil {
		resp.Diagnostics.AddWarning(
			"tf-analyze engine not found at resolved path",
			"Looked at "+cfg.ScriptPath+": "+err.Error(),
		)
	}
	if _, err := exec.LookPath(cfg.EngineCommand); err != nil {
		resp.Diagnostics.AddWarning(
			"engine_command not on PATH",
			"Looked for "+cfg.EngineCommand+": "+err.Error(),
		)
	}
	resp.DataSourceData = cfg
	resp.ResourceData = cfg
}

// DataSources lists the data sources the provider exposes.
func (p *TfanalyzeProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewScanDataSource,
	}
}

// Resources lists the resources the provider exposes.
// v1 is data-source-only.
func (p *TfanalyzeProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{}
}
