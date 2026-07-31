// Package secrets — AWS Secrets Manager provider stub.
// TODO: Implement using github.com/aws/aws-sdk-go-v2/service/secretsmanager
//
// Wire this provider by setting SECRET_PROVIDER=aws and providing:
//   AWS_REGION, AWS_SECRET_PREFIX
//
// Implementation sketch:
//   cfg, _ := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
//   client := secretsmanager.NewFromConfig(cfg)
//   out, _ := client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
//       SecretId: aws.String(prefix + key),
//   })
//   return aws.ToString(out.SecretString), nil
package secrets

import "context"

// AWSProvider retrieves secrets from AWS Secrets Manager.
type AWSProvider struct {
	// TODO: add *secretsmanager.Client field
	region       string
	secretPrefix string
}

// NewAWSProvider creates an AWSProvider.
// TODO: initialise the AWS SDK client with the default credential chain.
func NewAWSProvider(region, secretPrefix string) (*AWSProvider, error) {
	return &AWSProvider{region: region, secretPrefix: secretPrefix}, nil
}

func (p *AWSProvider) Get(_ context.Context, key string) (string, error) {
	// TODO: implement GetSecretValue
	return "", &ErrSecretNotFound{Key: key}
}

func (p *AWSProvider) Set(_ context.Context, key, value string) error {
	// TODO: implement PutSecretValue
	return nil
}

func (p *AWSProvider) Rotate(_ context.Context, key string) (string, error) {
	// TODO: implement RotateSecret
	return "", nil
}
