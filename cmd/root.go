package cmd

import (
	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "initz",
	Short: "initialize scan on git repository.",
	Long:  `initialize scan on git repository.`,
	// Run: func(cmd *cobra.Command, args []string) { },
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		return
	}
}
func init() {
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
