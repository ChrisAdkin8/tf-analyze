// Package main is the binary entry point for terraform-provider-tfanalyze.
//
// Run by Terraform via the plugin protocol; not invoked directly by users.
// The provider exposes the tf-analyze engine as Terraform-native data
// sources so plans / applies can be gated on a clean scan without external
// CI infrastructure.
package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/ChrisAdkin8/terraform-provider-tfanalyze/internal/provider"
)

// version is the provider version string. Overridden at build time via
// `-ldflags "-X main.version=$(git describe --tags)"`.
var version = "dev"

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "set to true to run the provider with support for debuggers like delve")
	flag.Parse()

	opts := providerserver.ServeOpts{
		// The address Terraform looks for on the registry; consumers
		// declare `source = "ChrisAdkin8/tfanalyze"` in their
		// terraform { required_providers { } } block.
		Address: "registry.terraform.io/ChrisAdkin8/tfanalyze",
		Debug:   debug,
	}

	if err := providerserver.Serve(context.Background(), provider.New(version), opts); err != nil {
		log.Fatal(err.Error())
	}
}
