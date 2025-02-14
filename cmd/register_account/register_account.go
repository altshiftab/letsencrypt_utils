package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	motmedelLog "github.com/Motmedel/utils_go/pkg/log"
	"golang.org/x/crypto/acme"
	letsencryptUtilsTypes "letsencrypt_utils/pkg/types"
	"log/slog"
	"net/mail"
	"os"
)

func main() {
	logger := slog.Default()

	var emailAddress string
	flag.StringVar(&emailAddress, "email", "", "The email address to be used for contact.")

	var accountCredentialsOutPath string
	flag.StringVar(&accountCredentialsOutPath,
		"output",
		"account_credentials.json",
		"The path where the account credentials file is to be written.",
	)

	var useStaging bool
	flag.BoolVar(&useStaging, "staging", false, "Whether to use the staging environment.")

	flag.Parse()

	if emailAddress == "" {
		motmedelLog.LogFatalWithExitingMessage("The email address is empty.", nil, logger)
	}

	// Best-effort email address validation.
	if _, err := mail.ParseAddress(emailAddress); err != nil {
		msg := "The email address is invalid."
		motmedelLog.LogFatalWithExitingMessage(
			msg,
			&motmedelErrors.InputError{Message: msg, Cause: err, Input: emailAddress},
			logger,
		)
	}

	// Produce an account key.

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		msg := "An error occurred when generating an account key."
		motmedelLog.LogFatalWithExitingMessage(msg, &motmedelErrors.CauseError{Message: msg, Cause: err}, logger)
	}

	keyDerData, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		msg := "An error occurred when marshalling the account key data."
		motmedelLog.LogFatalWithExitingMessage(msg, &motmedelErrors.CauseError{Message: msg, Cause: err}, logger)
	}

	keyPemData := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDerData})

	// Register an account with Let's Encrypt.

	directoryUrl := acme.LetsEncryptURL
	if useStaging {
		directoryUrl = "https://acme-staging-v02.api.letsencrypt.org/directory"
	}

	contactAddress := "mailto:" + emailAddress
	client := &acme.Client{Key: key, DirectoryURL: directoryUrl}
	account, err := client.Register(
		context.Background(),
		&acme.Account{Contact: []string{contactAddress}},
		acme.AcceptTOS,
	)
	if err != nil {
		msg := "An error occurred when registering the account."
		motmedelLog.LogFatalWithExitingMessage(
			msg,
			&motmedelErrors.InputError{
				Message: msg,
				Cause:   err,
				Input:   []any{contactAddress, directoryUrl},
			},
			logger,
		)
	}
	if account == nil {
		motmedelLog.LogFatalWithExitingMessage("The account is nil.", nil, logger)
	}

	accountUri := account.URI
	if accountUri == "" {
		motmedelLog.LogFatalWithExitingMessage("The account URI is empty.", nil, logger)
	}

	accountCredentials := letsencryptUtilsTypes.AccountCredentials{
		Uri: accountUri,
		Key: string(keyPemData),
	}

	accountCredentialsData, err := json.Marshal(accountCredentials)
	if err != nil {
		msg := "An error occurred when marshalling the account credentials."
		motmedelLog.LogFatalWithExitingMessage(msg, &motmedelErrors.CauseError{Message: msg, Cause: err}, logger)
	}

	if err := os.WriteFile(accountCredentialsOutPath, accountCredentialsData, 0600); err != nil {
		msg := "An error occurred when writing the account credentials data to disk."
		motmedelLog.LogFatalWithExitingMessage(
			msg,
			&motmedelErrors.InputError{Message: msg, Cause: err, Input: accountCredentialsOutPath},
			logger,
		)
	}
}
