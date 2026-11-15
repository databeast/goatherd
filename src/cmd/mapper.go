/*
Copyright © 2020 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import "github.com/spf13/cobra"

// mapperCmd represents the mapper command
var mapperCmd = &cobra.Command{
	Use:   "mapper",
	Short: "run a central discovery coordinator",
	RunE:  runCoordinator,
}

func init() {
	rootCmd.AddCommand(mapperCmd)
	mapperCmd.Flags().String("listen", "127.0.0.1:8432", "coordinator listen address")
	mapperCmd.Flags().Bool("evidence", false, "write full diagnostic evidence at shutdown")
	tlsFlags(mapperCmd)
	reports := &cobra.Command{Use: "reports", Short: "retrieve coordinator reports", RunE: runCoordinatorReports}
	reports.Flags().String("coordinator", "", "coordinator host:port")
	reports.Flags().Bool("evidence", false, "retrieve full diagnostic evidence instead of summaries")
	tlsFlags(reports)
	mapperCmd.AddCommand(reports)
	inventory := &cobra.Command{Use: "inventory", Short: "retrieve consolidated address evidence", RunE: runCoordinatorInventory}
	inventory.Flags().String("coordinator", "", "coordinator host:port")
	tlsFlags(inventory)
	mapperCmd.AddCommand(inventory)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// mapperCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// mapperCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
