CURL-JQ := docker compose run --rm curl-jq
MAKEFLAGS += --no-print-directory --always-make

package:
	# Create a zip file with the lambda code to ./build/token_function.zip
	docker compose run --rm packager bash -c 'mkdir -p /src/build && rm -f /build/token_function.zip && cd /src/lambda && zip -r /src/build/token_function.zip *'

up: package
	docker compose up -d localstack

down:
	docker compose down

logs:
	docker compose logs

reset: package
	docker compose down
	make up

list-runtimes:
	@$(CURL-JQ) curl -s http://localstack:4566/_aws/lambda/runtimes | jq '.Runtimes|sort'

get-init-state:
	@$(CURL-JQ) curl -s http://localstack:4566/_localstack/init | jq -r '.scripts[] | .stage'

check-init-state:
	(make get-init-state | grep -q 'READY') || (echo "Error: Initialization not ready" && exit 1)

update-lambda: package
	docker compose run --rm aws-cli --endpoint-url=http://localstack:4566 lambda update-function-code --function-name token --zip-file fileb:///build/token_function.zip --no-cli-pager

token-get:
	@API_ID=$$(docker compose run --rm aws-cli --endpoint-url=http://localstack:4566 apigateway get-rest-apis --output text --query 'items[0].id') && \
	$(CURL-JQ) curl -s --request POST \
		--url "http://localstack:4566/restapis/$$API_ID/dev/_user_request_/token" \
		--user admin:admin \
		--header 'content-type: application/x-www-form-urlencoded' \
		--data grant_type=client_credentials \
		--data scope=public \
		--data = | jq -r .access_token

token-verify:
	@TOKEN=$$(make token-get) && \
	docker compose run --rm token-verifier $$TOKEN
