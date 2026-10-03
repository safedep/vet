package cyclonedx

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/report"
)

func TestCryptoProperties(t *testing.T) {
	cases := []struct {
		name string
		c    report.Capability
		want *cdx.CryptoProperties
	}{
		{"not crypto", report.Capability{Tags: []string{"ai", "llm"}}, nil},
		{"hash algorithm", report.Capability{Product: "SHA-2", Tags: []string{"cryptography", "hash"}}, &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeAlgorithm, AlgorithmProperties: &cdx.CryptoAlgorithmProperties{Primitive: cdx.CryptoPrimitiveHash, AlgorithmFamily: "SHA-2"},
		}},
		{"authenticated encryption", report.Capability{Product: "ChaCha20", Tags: []string{"cryptography", "ae"}}, &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeAlgorithm, AlgorithmProperties: &cdx.CryptoAlgorithmProperties{Primitive: cdx.CryptoPrimitiveAE, AlgorithmFamily: "ChaCha20"},
		}},
		{"family outside the registry", report.Capability{Product: "RSA", Tags: []string{"cryptography", "pke", "signature"}}, &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeAlgorithm, AlgorithmProperties: &cdx.CryptoAlgorithmProperties{Primitive: cdx.CryptoPrimitiveSignature},
		}},
		{"tls", report.Capability{Tags: []string{"cryptography", "protocol", "tls"}}, &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeProtocol, ProtocolProperties: &cdx.CryptoProtocolProperties{Type: cdx.CryptoProtocolTypeTLS},
		}},
		{"certificate", report.Capability{Tags: []string{"cryptography", "certificate"}}, &cdx.CryptoProperties{AssetType: cdx.CryptoAssetTypeCertificate}},
		{"token", report.Capability{Tags: []string{"cryptography", "token", "jwt"}}, &cdx.CryptoProperties{
			AssetType:                       cdx.CryptoAssetTypeRelatedCryptoMaterial,
			RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{Type: cdx.RelatedCryptoMaterialTypeToken},
		}},
		{"unknown primitive", report.Capability{Tags: []string{"cryptography"}}, &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeAlgorithm, AlgorithmProperties: &cdx.CryptoAlgorithmProperties{Primitive: cdx.CryptoPrimitiveUnknown},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, cryptoProperties(&tc.c))
		})
	}
}

func TestCryptoCapabilityIsACryptographicAsset(t *testing.T) {
	c := capabilityComponent(&report.Capability{ID: "crypto.md5", Product: "MD5", Service: "MD5", Tags: []string{"cryptography", "hash", "weak"}})
	assert.Equal(t, cdx.ComponentTypeCryptographicAsset, c.Type)
	assert.Equal(t, "MD5", c.Name)
	require.NotNil(t, c.Properties)
	assert.Contains(t, *c.Properties, cdx.Property{Name: "safedep:tag", Value: "weak"})

	ai := capabilityComponent(&report.Capability{ID: "openai.client", Product: "OpenAI", Service: "AI client", Tags: []string{"ai"}})
	assert.Equal(t, cdx.ComponentTypeLibrary, ai.Type)
	assert.Nil(t, ai.CryptoProperties)
}
