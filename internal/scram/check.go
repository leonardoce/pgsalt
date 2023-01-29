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
	"strconv"
	"strings"

	"github.com/xdg-go/scram"
)

var (
	// ErrWrongComponents is raised when the proposed hash has not the
	// right number of components
	ErrWrongComponents = fmt.Errorf("wrong number of components in password hash: expected 3 sections divided by '$'")

	// ErrWrongHashType is raised when the hash type is not correct
	ErrWrongHashType = fmt.Errorf("wrong hash type (expected SCRAM-SHA-256)")

	// ErrWrongHashConfig is raised when the hashing function configuration
	// is not the expected one
	ErrWrongHashConfig = fmt.Errorf("wrong hash config (expected 2 sections diveded by ':' in the first block)")

	// ErrWrongKeyComponents is raised when the key components in the SCRAM
	// hash are not formatted correctly
	ErrWrongKeyComponents = fmt.Errorf("wrong key components (expected 2 sections diveded by ':' in the second block)")
)

// ParsedHash contains the parsed PostgreSQL hash
type ParsedHash struct {
	Iterations   int
	RawSalt      []byte
	RawStoredKey []byte
	RawServerKey []byte
}

// Verify checks if the passed SCRAM HASH, in the format used by PostgreSQL,
// corresponds to the given plain text
func Verify(hash string, plainText string) (bool, string, error) {
	parsedHash, err := parsePostgreSQLHash(hash)
	if err != nil {
		return false, "", fmt.Errorf("while parsing SCRAM hash: %w", err)
	}

	client, err := scram.SHA256.NewClient("", plainText, "")
	if err != nil {
		return false, "", fmt.Errorf("generating scram/SHA256 client: %w", err)
	}

	kf := scram.KeyFactors{
		Salt:  string(parsedHash.RawSalt),
		Iters: parsedHash.Iterations,
	}
	credentials := client.GetStoredCredentials(kf)

	// SCRAM-SHA-256$<iter>:<salt>$<StoredKey>:<ServerKey>
	computed := fmt.Sprintf("SCRAM-SHA-256$%d:%s$%s:%s",
		credentials.Iters,
		base64.StdEncoding.EncodeToString([]byte(credentials.Salt)),
		base64.StdEncoding.EncodeToString(credentials.StoredKey),
		base64.StdEncoding.EncodeToString(credentials.ServerKey),
	)

	return hash == computed, computed, nil
}

// parsePostgreSQLHash parses a PostgreSQL SCRAM hash into its
// components
func parsePostgreSQLHash(hash string) (*ParsedHash, error) {
	// SCRAM-SHA-256$<iter>:<salt>$<StoredKey>:<ServerKey>

	components := strings.Split(hash, "$")
	if len(components) != 3 {
		return nil, ErrWrongComponents
	}

	if components[0] != "SCRAM-SHA-256" {
		return nil, ErrWrongHashType
	}

	hashConfig := strings.Split(components[1], ":")
	if len(hashConfig) != 2 {
		return nil, ErrWrongHashConfig
	}

	keys := strings.Split(components[2], ":")
	if len(keys) != 2 {
		return nil, ErrWrongKeyComponents
	}

	iterations, err := strconv.Atoi(hashConfig[0])
	if err != nil {
		return nil, fmt.Errorf("while reading the number of iterations: %w", err)
	}

	rawSalt, err := base64.StdEncoding.DecodeString(hashConfig[1])
	if err != nil {
		return nil, fmt.Errorf("while base64-decoding salt: %w", err)
	}

	rawStoredKey, err := base64.StdEncoding.DecodeString(keys[0])
	if err != nil {
		return nil, fmt.Errorf("while base64-decoding stored key: %w", err)
	}

	rawServerKey, err := base64.StdEncoding.DecodeString(keys[1])
	if err != nil {
		return nil, fmt.Errorf("while base64-decoding stored key: %w", err)
	}

	return &ParsedHash{
		Iterations:   iterations,
		RawSalt:      rawSalt,
		RawStoredKey: rawStoredKey,
		RawServerKey: rawServerKey,
	}, nil
}
