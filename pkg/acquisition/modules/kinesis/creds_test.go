package kinesisacquisition

import "github.com/aws/aws-sdk-go-v2/aws"

//nolint:gochecknoinits
func init() {
	defaultCredsFunc = func() aws.CredentialsProvider {
		return aws.AnonymousCredentials{}
	}
}
