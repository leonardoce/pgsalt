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

package scram

import (
	"encoding/base64"
	"fmt"

	"github.com/xdg-go/scram"
)

// DefaultPostgresIterations is the default number of iterations used by
// PostgreSQL
const DefaultPostgresIterations = 4096

// DefaultSaltLength is the default salt length as used by PostgreSQL
const DefaultSaltLength = 16

// GenerateOptions are information needed to generate a SCRAM hash
type GenerateOptions struct {
	// The salt to be used. If empty, a new salt long DefaultSaltLength
	// will be automatically generated
	Salt string

	// The number of iterations. PostgreSQL uses 4096
	Iterations int

	// The plain password
	PlainText string
}

// Defaults fills the default values into the options if they
// have not have been already defined
func (options *GenerateOptions) Defaults() error {
	if options.Iterations == 0 {
		options.Iterations = DefaultPostgresIterations
	}

	if len(options.Salt) == 0 {
		rawSalt, err := makeSalt(DefaultSaltLength)
		if err != nil {
			return fmt.Errorf("while generating raw SALT: %w", err)
		}

		options.Salt = base64.StdEncoding.EncodeToString(rawSalt)
	}

	return nil
}

// Generate generates a SCRAM hash from the options
func (options *GenerateOptions) Generate() (string, error) {
	client, err := scram.SHA256.NewClient("", options.PlainText, "")
	if err != nil {
		return "", fmt.Errorf("generating scram/SHA256 client: %w", err)
	}

	rawSalt, err := base64.StdEncoding.DecodeString(options.Salt)
	if err != nil {
		return "", fmt.Errorf("decoding SALT from base64: %w", err)
	}

	kf := scram.KeyFactors{
		Salt:  string(rawSalt),
		Iters: options.Iterations,
	}
	credentials := client.GetStoredCredentials(kf)

	// SCRAM-SHA-256$<iter>:<salt>$<StoredKey>:<ServerKey>
	hashed := fmt.Sprintf("SCRAM-SHA-256$%d:%s$%s:%s",
		credentials.Iters,
		base64.StdEncoding.EncodeToString([]byte(credentials.Salt)),
		base64.StdEncoding.EncodeToString(credentials.StoredKey),
		base64.StdEncoding.EncodeToString(credentials.ServerKey),
	)
	return hashed, nil
}
