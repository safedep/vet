package entities

const (
	FunctionDeclEntity = "function_decl"

	FunctionDeclPropertyName           = "name"
	FunctionDeclPropertyContainerName  = "containerName"
	FunctionDeclPropertySourceFilePath = "sourceFilePath"
	FunctionDeclPropertySourceFileType = "sourceFileType"
)

type FunctionDecl struct {
	Id string

	ContainerName  string
	FunctionName   string
	SourceFilePath string
	SourceFileType string
}

func (f *FunctionDecl) Properties() map[string]string {
	return map[string]string{
		FunctionDeclPropertyName:           f.FunctionName,
		FunctionDeclPropertyContainerName:  f.ContainerName,
		FunctionDeclPropertySourceFilePath: f.SourceFilePath,
		FunctionDeclPropertySourceFileType: f.SourceFileType,
	}
}
