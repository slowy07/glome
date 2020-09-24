package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "LoginServer",
	Short: "LoginServer",

	// Run: func(cmd *cobra.Command, args []string) {
	// 	cmd.Help()
	// 	os.Exit(0)
	// },
}

func Execute() {
	rootCmd.AddCommand(runCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
