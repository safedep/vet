package py

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

// Set difference: A - B
func difference(a, b []string) (diff []string) {
	m := make(map[string]bool)

	for _, item := range b {
		m[item] = true
	}

	for _, item := range a {
		if _, ok := m[item]; !ok {
			diff = append(diff, item)
		}
	}
	return diff
}

func TestGetDependencies(t *testing.T) {
	tests := []struct {
		filepath     string
		expectedDeps []string
	}{
		{
			filepath: "./fixtures/setuppy/setup1.py", // Path to your test file
			expectedDeps: []string{
				"food-exceptions>=0.4.4",
				"food-models>=3.3.1",
				"dateutils>=0.6.6",
				"publicsuffixlist>=0.6.2",
				"dnspython",
				"netaddr>=0.7.18",
				"validators>=0.12.2",
				"fqdn>=1.1.0",
				"tld>=0.9.1",
				"cchardet>=2.1.4",
				"urllib3>=1.22",
				"tldextract>=2.2.0",
				"filetype>=1.0.5",
				"pyunpack>=0.1.2",
				"patool>=1.12",
				"wordninja>=2.0.0",
				"iocextract>=1.13.1",
				"pyparsing>=3.0.8",
				"ioc-fanger",
				"titlecase>=0.12.0",
				"furl>=2.1.0",
				"pathlib2>=2.3.3",
				"lxml>=4.5.0",
				"fuzzywuzzy>=0.18.0", "PySocks>=1.7.0", "truffleHogRegexes>=0.0.7", "soupsieve>=1.9.1",
				"iptools>=0.7.0", "parsedatetime>=2.4", "beautifulsoup4>=4.7.1",
			},
		},
		{
			filepath: "./fixtures/setuppy/setup2.py", // Path to your test file
			expectedDeps: []string{
				"google-cloud-storage",
				"google-cloud-pubsub>=2.0",
				"knowledge-graph>=3.12.0",
				"food_exceptions>=0.4.3",
				"food-models>=3.48.6",
				"food-utils>=6.54.32",
				"food-convertor>=0.62.2",
				"food_dorks>=0.4",
				"food_social>=0.2",
				"xx_client>=1.4.5",
				"exploration-events>=3.4",
				"http-parser",
				"simplejson",
				"titlecase",
				"cpe",
				"addict",
				"GitPython",
				"feedparser",
				"nessus-client>=0.13.12",
				"vulners>=1.5.0",
				"retrying",
				"ipwhois>=1.1.0",
				"ratelimit",
				"vulners>=1.5.0",
				"gpapi==0.4.4",
				"shodan",
				"python-libnmap",
				"GitPython",
				"PyGithub==1.54.1",
				"python-whois",
				"retry",
				"pytrie",
				"python-whois>=0.7.3",
				"sh>=1.14.1",
				"GitPython",
				"unidiff",
				"feedparser",
				"OTXv2>=1.5.10",
				"certstream>=1.11",
				"protobuf<4",
				"inflect",
				"colorama>=0.4.1",
				"ipaddress>=1.0.22",
				"packaging>=19.2",
				"prettytable>=0.7.2",
				"pyfiglet>=0.8.post1",
				"requests>=2.22.0",
				"termcolor>=1.1.0",
				"beautifulsoup4>=4.8.1",
				"censys",
				"favicon",
				"mmh3",
				"xxwhispers>=2.1.7",
				"func-timeout",
				"ipinfo",
				"tqdm",
				"gvm-tools>=21.6.0",
				"cloud_ip_info>=1.3.3",
				"pymetasploit3",
				"Jinja2>=3.0.3",
				"configobj==5.0.6",
				"cloud_recon>=0.2.7",
				"credovergeneric>=1.6.7",
				"pycryptodome==3.12.0",
				"azure-mgmt-resource==20.0.0",
				"xx-cloud-storage-client>=0.0.14",
				"azure-identity==1.7.1",
				"dnsdb==0.2.5",
				"google-cloud-resource-manager",
				"xx_kb_auth_proxy_client>=0.0.3",
				"statistics",
			},
		},
		// Add more test cases here
	}

	for _, test := range tests {
		t.Run(test.filepath, func(t *testing.T) {
			dependencies, err := getDependencies(test.filepath)
			assert.Nil(t, err)

			if len(dependencies) != len(test.expectedDeps) {
				t.Fatalf("Expected %d dependencies, but got %d", len(test.expectedDeps), len(dependencies))
			}

			dep_diff1 := difference(dependencies, test.expectedDeps)
			dep_diff2 := difference(test.expectedDeps, dependencies)
			assert.Equal(t, 0, len(dep_diff1))
			assert.Equal(t, 0, len(dep_diff2))
			if len(dep_diff1) > 0 {
				t.Fatalf("More Dependencies in test set %v", dep_diff1)
			}
			if len(dep_diff2) > 0 {
				t.Fatalf("More Dependencies in test set %v", dep_diff2)
			}
		})
	}
}
