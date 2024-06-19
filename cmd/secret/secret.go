package secret

import (
	"errors"

	"github.com/Encrypto07/star-secret-keeper/pkg/decryption"
	"github.com/Encrypto07/star-secret-keeper/pkg/encryption"
	"github.com/spf13/cobra"
)

var encryptionKey string

func Execute() error {
	rootCmd := &cobra.Command{
		Use:   "secret",
		Short: "A CLI Secrets Manager Tool",
	}

	setCmd := &cobra.Command{
		Use:   "set",
		Short: "Set a secret",
		RunE:  handleSetSecret,
	}
	rootCmd.AddCommand(setCmd)

	getCmd := &cobra.Command{
		Use:   "get",
		Short: "Get a secret",
		RunE:  handleGetSecret,
	}
	rootCmd.AddCommand(getCmd)

	rootCmd.PersistentFlags().StringVar(&encryptionKey, "key", "", "AES encryption key")

	return rootCmd.Execute()
}

func handleSetSecret(cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		return errors.New("invalid number of arguments")
	}

	secretValue := args[0]

	return encryption.StoreSecret(secretValue, encryptionKey)
}

func handleGetSecret(cmd *cobra.Command, args []string) error {
	return decryption.RetrieveSecret(encryptionKey)
}
