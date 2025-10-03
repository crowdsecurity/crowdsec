//go:build !test

package kinesisacquisition

import "github.com/aws/aws-sdk-go-v2/aws"

func defaultCreds() aws.CredentialsProvider {
    return nil
}
