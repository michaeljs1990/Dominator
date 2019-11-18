package main

import (
	"errors"
	"strings"

	"github.com/Symantec/Dominator/lib/log"
	"github.com/Symantec/Dominator/lib/mdb"
	"gopkg.in/tumblr/go-collins.v0/collins"
)

// collinsInstance takes the path to a collins config file and a CQL Query
// that lets you limit what is returned from collins before trying to generate
// the mdb file.
type collinsInstance struct {
	configFile string
	cql        string
}

// Example entry in mdb.sources.list might look like the following
//
// collins /etc/collins.yaml
// collins /etc/collins.yaml HOSTNAME=some.host.example.com AND RACK_POSITION=DC1
func newCollinsGenerator(args []string, logger log.DebugLogger) (generator, error) {
	cql := ""
	if len(args) > 1 {
		cql = strings.Join(args[1:], " ")
	}

	return &collinsGeneratorType{instance: collinsInstance{args[0], cql}}, nil
}

type collinsGeneratorType struct {
	instance collinsInstance
}

func (g *collinsGeneratorType) Generate(_ string, logger log.Logger) (*mdb.Mdb, error) {

	client, err := collins.NewClientFromFiles(g.instance.configFile)
	if err != nil {
		return nil, errors.New("Error creating collins client: " + err.Error())
	}

	// Collect all assets that are needed from collins
	opts := collins.AssetFindOpts{
		Query: g.instance.cql,
		PageOpts: collins.PageOpts{
			Size: 100,
		},
	}

	var allAssets []collins.Asset
	for {
		assets, resp, err := client.Assets.Find(&opts)
		if err != nil {
			return nil, errors.New("Error when trying to fetch assets: " + err.Error())
		}

		allAssets = append(allAssets, assets...)

		if resp.NextPage == resp.CurrentPage {
			break
		} else {
			opts.PageOpts.Page++
		}
	}

	var outMdb mdb.Mdb
	for _, asset := range allAssets {
		var outMachine mdb.Machine
		// We only care about machines with host names
		if atts, ok := asset.Attributes["0"]; ok && atts["HOSTNAME"] != "" {
			outMachine.Hostname = atts["HOSTNAME"]
			outMachine.OwnerGroup = atts["CONTACT"]
			outMachine.RequiredImage = atts["REQUIRED_IMG"]
			outMachine.PlannedImage = atts["PLANNED_IMG"]

			// Something is very wrong if we don't have an IP for the asset
			if len(asset.Addresses) < 1 {
				continue
			} else {
				outMachine.IpAddress = asset.Addresses[0].Address
			}

			// If the machine has been placed in maintenance we turn off updates
			if asset.Metadata.Status == "Maintenance" {
				outMachine.DisableUpdates = true
			} else {
				outMachine.DisableUpdates = false
			}

			outMachine.Tags = map[string]string{
				"NODECLASS":      atts["NODECLASS"],
				"RACK_POSITION":  atts["RACK_POSITION"],
				"POOL":           atts["POOL"],
				"PRIMARY_ROLE":   atts["PRIMARY_ROLE"],
				"SECONDARY_ROLE": atts["SECONDARY_ROLE"],
				"CLASSIFICATION": asset.Classification.Tag,
				"STATUS":         asset.Metadata.Status,
				"STATE":          asset.Metadata.State.Name,
			}
			outMdb.Machines = append(outMdb.Machines, outMachine)
		}
	}

	return &outMdb, nil
}
