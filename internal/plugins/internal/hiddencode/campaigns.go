package hiddencode

import (
	_ "embed"
	"fmt"
	"regexp"

	"gopkg.in/yaml.v3"
)

//go:embed campaigns.yaml
var campaignsYAML []byte

// campaign is a known campaign and the markers of its code.
type campaign struct {
	name    string
	markers []*regexp.Regexp
}

var campaigns = mustCampaigns(campaignsYAML)

func mustCampaigns(data []byte) []campaign {
	var doc struct {
		Campaigns []struct {
			Name    string   `yaml:"name"`
			Markers []string `yaml:"markers"`
		} `yaml:"campaigns"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		panic(fmt.Sprintf("hiddencode: campaigns.yaml: %v", err))
	}
	out := make([]campaign, 0, len(doc.Campaigns))
	for _, c := range doc.Campaigns {
		k := campaign{name: c.Name}
		for _, m := range c.Markers {
			k.markers = append(k.markers, regexp.MustCompile(m))
		}
		out = append(out, k)
	}
	return out
}

// campaignOf returns the name of the first campaign whose marker the data
// holds, or "".
func campaignOf(data []byte) string {
	for _, c := range campaigns {
		for _, m := range c.markers {
			if m.Match(data) {
				return c.name
			}
		}
	}
	return ""
}

// named sets the campaign of each signal of a file.
func named(signals []Signal, data []byte) []Signal {
	if len(signals) == 0 {
		return nil
	}
	name := campaignOf(data)
	for i := range signals {
		signals[i].Campaign = name
	}
	return signals
}
