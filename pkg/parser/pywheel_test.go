package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParsePythonPackageSpec(t *testing.T) {
	cases := []struct {
		name string

		// Input
		pkgSpec string

		// Output
		pkgName    string
		pkgVersion string
	}{
		{
			"Exact version spec",
			"botocore (==1.29.88)",
			"botocore",
			"1.29.88",
		},
		{
			"Version range",
			"docutils (<0.17,>=0.10)",
			"docutils",
			"0.10",
		},
		{
			"Version range without upper bound",
			"PyYAML (>=0.2.3)",
			"PyYAML",
			"0.2.3",
		},
		{
			"Year like version",
			"certifi (>=2017.4.17)",
			"certifi",
			"2017.4.17",
		},
		{
			"Spec has platform",
			"chardet (<5,>=3.0.2) ; python_version < \"3\"",
			"chardet",
			"3.0.2",
		},
		{
			"Spec with tilda",
			"charset-normalizer (~=2.0.0) ; python_version >= \"3\"",
			"charset-normalizer",
			"2.0.0",
		},
		{
			"Spec without version",
			"chardet (); python_version < \"3\"",
			"chardet",
			"0.0.0",
		},
		{
			"Spec with name only without version",
			"censys",
			"censys",
			"0.0.0",
		},
		{
			"Version with exclusion",
			"PySocks (!=1.5.7,>=1.5.6) ; extra == 'socks'",
			"PySocks",
			"1.5.6",
		},
		{
			"Spec without version but with platform",
			"win-inet-pton ; (sys_platform == \"win32\" and python_version == \"2.7\") and extra == 'socks'",
			"win-inet-pton",
			"0.0.0",
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			details, _ := parsePythonPackageSpec(test.pkgSpec)
			assert.Equal(t, test.pkgName, details.Name)
			assert.Equal(t, test.pkgVersion, details.Version)
		})
	}
}
