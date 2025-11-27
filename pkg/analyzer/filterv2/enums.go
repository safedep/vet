package filterv2

import (
	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
)

// EnumRegistration contains all the information needed to generate enum constants
type EnumRegistration struct {
	Name     string           // Name used in CEL expressions (e.g., "ProjectSourceType")
	Prefix   string           // Common prefix to strip from constant names
	ValueMap map[string]int32 // Reference to protobuf-generated enum value map
}

// RegisteredEnums contains all enum types that should be exposed to CEL
// Uses the protobuf-generated Type_value maps to avoid manual maintenance and drift
var RegisteredEnums = []EnumRegistration{
	{
		Name:     "ProjectSourceType",
		Prefix:   "PROJECT_SOURCE_TYPE_",
		ValueMap: packagev1.ProjectSourceType_value,
	},
	{
		Name:     "Ecosystem",
		Prefix:   "ECOSYSTEM_",
		ValueMap: packagev1.Ecosystem_value,
	},
}
