// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.

package events

// LambdaFunctionURLRequest contains data coming from the HTTP request to a Lambda Function URL.
type LambdaFunctionURLRequest struct {
	Version               string                          `json:"version"` // Version is expected to be `"2.0"`
	RawPath               string                          `json:"rawPath"`
	RawQueryString        string                          `json:"rawQueryString"`
	Cookies               []string                        `json:"cookies,omitempty"`
	Headers               map[string]string               `json:"headers"`
	QueryStringParameters map[string]string               `json:"queryStringParameters,omitempty"`
	RequestContext        LambdaFunctionURLRequestContext `json:"requestContext"`
	Body                  string                          `json:"body,omitempty"`
	IsBase64Encoded       bool                            `json:"isBase64Encoded"`
}

// LambdaFunctionURLRequestContext contains the information to identify the AWS account and resources invoking the Lambda function.
type LambdaFunctionURLRequestContext struct {
	AccountID    string                                                `json:"accountId"`
	RequestID    string                                                `json:"requestId"`
	Authorizer   *LambdaFunctionURLRequestContextAuthorizerDescription `json:"authorizer,omitempty"`
	APIID        string                                                `json:"apiId"`        // APIID is the Lambda URL ID
	DomainName   string                                                `json:"domainName"`   // DomainName is of the format `"<url-id>.lambda-url.<region>.on.aws"`
	DomainPrefix string                                                `json:"domainPrefix"` // DomainPrefix is the Lambda URL ID
	Time         string                                                `json:"time"`
	TimeEpoch    int64                                                 `json:"timeEpoch"`
	HTTP         LambdaFunctionURLRequestContextHTTPDescription        `json:"http"`
}

// LambdaFunctionURLRequestContextAuthorizerDescription contains authorizer information for the request context.
type LambdaFunctionURLRequestContextAuthorizerDescription struct {
	IAM *LambdaFunctionURLRequestContextAuthorizerIAMDescription `json:"iam,omitempty"`
}

// LambdaFunctionURLRequestContextAuthorizerIAMDescription contains IAM information for the request context.
type LambdaFunctionURLRequestContextAuthorizerIAMDescription struct {
	AccessKey string `json:"accessKey"`
	AccountID string `json:"accountId"`
	CallerID  string `json:"callerId"`
	UserARN   string `json:"userArn"`
	UserID    string `json:"userId"`
}

// LambdaFunctionURLRequestContextHTTPDescription contains HTTP information for the request context.
type LambdaFunctionURLRequestContextHTTPDescription struct {
	Method    string `json:"method"`
	Path      string `json:"path"`
	Protocol  string `json:"protocol"`
	SourceIP  string `json:"sourceIp"`
	UserAgent string `json:"userAgent"`
}

// LambdaFunctionURLResponse configures the HTTP response to be returned by Lambda Function URL for the request.
type LambdaFunctionURLResponse struct {
	StatusCode      int               `json:"statusCode"`
	Headers         map[string]string `json:"headers"`
	Body            string            `json:"body"`
	IsBase64Encoded bool              `json:"isBase64Encoded"`
	Cookies         []string          `json:"cookies"`
}
