package entities

import "github.com/safedep/vet/pkg/storage/graph"

const (
	// The entity type
	PackageEntity = "package"

	// Entity specific constants
	PackageEntitySourceTypeApp    = "app"
	PackageEntitySourceTypeImport = "import"

	// Property names
	PackagePropertyName           = "name"
	PackagePropertySourceFilePath = "sourceFilePath"
	PackagePropertySourceFileType = "sourceFileType"

	// Relationship names
	PackageRelationshipImports          = "imports"
	PackageRelationshipDeclaresFunction = "declares_function"
)

type Package struct {
	Id             string
	Name           string
	SourceFilePath string
	SourceFileType string
}

func (p *Package) Properties() map[string]string {
	return map[string]string{
		PackagePropertyName:           p.Name,
		PackagePropertySourceFilePath: p.SourceFilePath,
		PackagePropertySourceFileType: p.SourceFileType,
	}
}

func (p *Package) Imports(anotherPackage *Package) *graph.Edge {
	return &graph.Edge{
		Name: PackageRelationshipImports,
		From: &graph.Node{
			ID:         p.Id,
			Label:      PackageEntity,
			Properties: p.Properties(),
		},
		To: &graph.Node{
			ID:         anotherPackage.Id,
			Label:      PackageEntity,
			Properties: anotherPackage.Properties(),
		},
	}
}

func (p *Package) DeclaresFunction(fn *FunctionDecl) *graph.Edge {
	return &graph.Edge{
		Name: PackageRelationshipDeclaresFunction,
		From: &graph.Node{
			ID:         p.Id,
			Label:      PackageEntity,
			Properties: p.Properties(),
		},
		To: &graph.Node{
			ID:         fn.Id,
			Label:      FunctionDeclEntity,
			Properties: fn.Properties(),
		},
	}
}
