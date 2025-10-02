#!/bin/sh
set -e

runtime=nodejs20.x
region=$AWS_DEFAULT_REGION

# Create KMS signing keys
keyId=$(aws --endpoint-url=http://localhost:4566 kms create-key --key-usage SIGN_VERIFY --customer-master-key-spec RSA_2048 --output text --query 'KeyMetadata.KeyId')
# Set key alias
aws --endpoint-url=http://localhost:4566 kms create-alias --alias-name alias/signing-key --target-key-id $keyId

# Output public key
aws --endpoint-url=http://localhost:4566 kms get-public-key --key-id $keyId --output text --query PublicKey | base64 -d > pubkey.der
openssl rsa -pubin -inform DER -outform PEM -in pubkey.der -pubout -out pubkey.pem
cat pubkey.pem

# Create user data in DynamoDB
aws --endpoint-url=http://localhost:4566 dynamodb create-table \
    --table-name Users \
    --attribute-definitions AttributeName=Username,AttributeType=S AttributeName=Password,AttributeType=S \
    --key-schema AttributeName=Username,KeyType=HASH AttributeName=Password,KeyType=RANGE \
    --provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5

# Add user to DynamoDB table
aws --endpoint-url=http://localhost:4566 dynamodb put-item \
    --table-name Users \
    --item '{
        "Username": {"S": "admin"},
        "Password": {"S": "admin"}
    }'

# List records in DynamoDB table
aws --endpoint-url=http://localhost:4566 dynamodb scan --table-name Users

# Create lambda
aws --endpoint-url=http://localhost:4566 lambda create-function \
    --function-name token \
    --runtime $runtime \
    --role arn:aws:iam::123456789012:role/unsafe \
    --handler index.handler \
    --zip-file fileb:///etc/localstack/init/build/token_function.zip

# Wait for function to be provisioned
aws --endpoint-url=http://localhost:4566 lambda wait function-active --function-name token

# Execute Lambda function
aws --endpoint-url=http://localhost:4566 lambda invoke \
    --function-name arn:aws:lambda:$region:000000000000:function:token \
    --payload '{ }' \
    output.txt

# Create API Gateway endpoint
apiId=$(aws --endpoint-url=http://localhost:4566 apigateway create-rest-api --name 'TokenAPI' --output text --query 'id')
rootResourceId=$(aws --endpoint-url=http://localhost:4566 apigateway get-resources --rest-api-id $apiId --output text --query 'items[0].id')
aws --endpoint-url=http://localhost:4566 apigateway create-resource \
    --rest-api-id $apiId \
    --parent-id $rootResourceId \
    --path-part token

# Get resource ID for /token
resourceId=$(aws --endpoint-url=http://localhost:4566 apigateway get-resources --rest-api-id $apiId --output text --query 'items[1].id')

# Create GET method for /token
aws --endpoint-url=http://localhost:4566 apigateway put-method \
    --rest-api-id $apiId \
    --resource-id $resourceId \
    --http-method POST \
    --authorization-type NONE

# Get Lambda ARN
lambdaArn=$(aws --endpoint-url=http://localhost:4566 lambda get-function --function-name token --output text --query 'Configuration.FunctionArn')
# Set integration for /token GET method
aws --endpoint-url=http://localhost:4566 apigateway put-integration \
    --rest-api-id $apiId \
    --resource-id $resourceId \
    --http-method POST \
    --type AWS_PROXY \
    --integration-http-method POST \
    --uri "arn:aws:apigateway:$region:lambda:path/2015-03-31/functions/$lambdaArn/invocations" \
    --passthrough-behavior WHEN_NO_MATCH

# Deploy API Gateway
aws --endpoint-url=http://localhost:4566 apigateway create-deployment \
    --rest-api-id $apiId \
    --stage-name dev
