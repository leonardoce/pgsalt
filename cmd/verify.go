/*
Copyright © 2023 Leonardo Cecchi <leonardo.cecchi@gmail.com>

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

This program is distribyuted in the hope that it will be useful, but WITHOUT ANY
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

// verifyCmd represents the verify command
var verifyCmd = &cobra.Command{
	Use:   "verify [hash] [plaintext]",
	Short: "Check a SCRAM hash against the plain text password",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		hash := args[0]
		plainText := args[1]

		status, expected, err := scram.Verify(hash, plainText)
		if err != nil {
			return fmt.Errorf("while verifying hash: %w", err)
		}

		if status {
			fmt.Println(
				"verification succeeded",
			)
		} else {
			fmt.Printf(
				"verification failed: expected (same salt) %s\n", expected,
			)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(verifyCmd)
}
