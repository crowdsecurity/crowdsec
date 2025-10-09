package kinesisacquisition

import "github.com/aws/aws-sdk-go-v2/aws"

func init() {
	defaultCredsFunc = func() aws.CredentialsProvider {
		return aws.AnonymousCredentials{}
	}
}
