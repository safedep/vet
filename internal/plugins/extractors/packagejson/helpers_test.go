package packagejson

import (
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
)

func simpleAPI(p string) filesystem.FileAPI { return simplefileapi.New(p, nil) }
