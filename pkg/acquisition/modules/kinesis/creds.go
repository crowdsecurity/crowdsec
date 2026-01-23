package kinesisacquisition

import "github.com/aws/aws-sdk-go-v2/aws"

var defaultCredsFunc = func() aws.CredentialsProvider {
	return nil
}

func defaultCreds() aws.CredentialsProvider {
	return defaultCredsFunc()
}
