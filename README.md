# JWTGenaration
Personal project that implements an OAuth 2.0 Client Credentials token endpoint using API Gateway → Lambda → DynamoDB → KMS, all running locally with Docker + Localstack. The endpoint validates clients (via Basic Auth) against a Users table and returns a JWT signed by AWS KMS (RS256).
