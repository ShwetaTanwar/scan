package cmd

import (
	"fmt"
	"initz/config"
	"initz/models"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Initiate a scan on  Git repository.",
	Long:  `Initiate a scan on Git repository to check for exposed application secrets, such as API tokens or passwords.`,
	Run: func(cmd *cobra.Command, args []string) {
		scan(cmd)
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.PersistentFlags().BoolP("verbose", "v", false, "show verbose output from scan (which file, where in the file, what secret).")
	scanCmd.Flags().Bool("no-git", false, "scan on directory /files")
	scanCmd.PersistentFlags().StringP("source", "s", ".", "give a source path for scan, it will scan on that source")
}

func scan(cmd *cobra.Command) {
	currentTime := time.Now()
	fmt.Printf("%s %s scanning for exposed secrets...\n", currentTime.Format("03:04PM"), config.Green("INF"))

	var (
		vc       config.ViperConfig
		findings []models.Finding
		err      error
	)

	viper.AddConfigPath("./config")
	viper.SetConfigName(config.DefaultConfig)
	viper.SetConfigType("toml")
	if err := viper.ReadConfig(strings.NewReader(config.DefaultConfig)); err != nil {
		fmt.Printf("Unable to load scan config.")
		return
	}
	if err := viper.Unmarshal(&vc); err != nil {
		fmt.Printf("Unable to unmarshal scan config.")
		return
	}
	cfg, err := vc.Translate()
	if err != nil {
		fmt.Printf("Failed to load config.")
		return
	}
	cfg.Path, _ = cmd.Flags().GetString("config")
	detector := NewDetector(cfg)
	detector.Verbose, _ = cmd.Flags().GetBool("verbose")
	noGit, err := cmd.Flags().GetBool("no-git")
	if err != nil {
		log.Fatal().Err(err).Msg("could not call GetBool() for no-git")
	}
	source, err := cmd.Flags().GetString("source")
	if source == "" {
		source, err = os.Getwd()
		if err != nil {
			fmt.Println("Error getting current working directory:", err)
			return
		}
	}
	if noGit {
		findings, err = detector.DetectFiles(source)
	}
	if !noGit {
		findings, err = detector.DetectGit(source)
	}
	if err == nil {
		fmt.Printf("%s %s scan completed in %dms\n", currentTime.Format("03:04PM"), config.Green("INF"), time.Since(currentTime).Milliseconds())
		if len(findings) != 0 {
			fmt.Printf("%s %s leaks found: %d", currentTime.Format("03:04PM"), config.Yellow("WAR"), len(findings))
		}
	}
}
