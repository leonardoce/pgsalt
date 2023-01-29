/*
Copyright © 2023 Leonardo Cecchi <leonardo.cecchi@gmail.com>

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program. If not, see <https://www.gnu.org/licenses/>.
*/

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/leonardoce/pgsalt/internal/scram"
)

// generateCmd represents the generate command
var generateCmd = &cobra.Command{
	Use:   "generate [plaintext]",
	Short: "Create a SCRAM password",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		salt, _ := cmd.Flags().GetString("salt")

		options := scram.GenerateOptions{
			Salt:      salt,
			PlainText: args[0],
		}
		if err := options.Defaults(); err != nil {
			return fmt.Errorf("while defaulting the SCRAM parameters: %w", err)
		}

		pwd, err := options.Generate()
		if err != nil {
			return fmt.Errorf("while calculating the SCRAM password: %w", err)
		}

		fmt.Println(pwd)
		return nil
	},
}

func init() {
	generateCmd.Flags().String(
		"salt",
		"",
		`The pre-generated salt to be used. If not passed a new
salt will be generated automatically`,
	)
	rootCmd.AddCommand(generateCmd)
}
