package code

import (
	"fmt"

	"github.com/spf13/cobra"

	xbomsig "github.com/safedep/vet/pkg/xbom/signatures"
	_ "github.com/safedep/vet/signatures" // triggers embed registration
)

func newValidateCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "validate",
		Short: "Validate all embedded xBOM signatures",
		RunE: func(cmd *cobra.Command, args []string) error {
			sigs, err := xbomsig.LoadAllSignatures()
			if err != nil {
				fmt.Println("Signatures invalid:", err)
				return err
			}
			fmt.Printf("All %d signatures valid\n", len(sigs))
			return nil
		},
	}
}
