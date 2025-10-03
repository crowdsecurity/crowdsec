//go:build test

package s3acquisition

import "github.com/aws/aws-sdk-go-v2/aws"

func defaultCreds() aws.CredentialsProvider {
    return aws.AnonymousCredentials{}
}
