Fork Notes
==========

I forked this so I could use the SSO capabilities of the v2 version of the AWS SDK (I use 
identity center locally).

This isn't fully tested, but the /creds endpoint works (which is all my use case needs).

I run with the following commands:

```shell
go build .
go AWS_PROFILE=<my profile> ECS_LOCAL_METADATA_PORT=51679 go run main.go
```

Then I run this to validate:

```shell
curl -X GET http://127.0.0.1:51679/creds
```

I didn't need to run docker, but I assume you can build the docker image with the Makefile.

Amazon ECS Local Container Endpoints
====================================

A container that provides local versions of the [ECS Task IAM Roles endpoint](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html) and the [ECS Task Metadata Endpoints](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-metadata-endpoint.html). This project will help you test applications locally before you deploy to ECS/Fargate.

This repository contains the source code for the project. To use it, pull the [amazon/amazon-ecs-local-container-endpoints:latest image from Docker Hub](https://hub.docker.com/r/amazon/amazon-ecs-local-container-endpoints/).

#### Table of Contents
* [Tutorial](https://aws.amazon.com/blogs/compute/a-guide-to-locally-testing-containers-with-amazon-ecs-local-endpoints-and-docker-compose/)
* [Setup Networking](docs/setup-networking.md)
  * [Option 1: Use a User Defined Docker Bridge Network](docs/setup-networking.md#option-1-use-a-user-defined-docker-bridge-network-recommended)
  * [Option 2: Set up iptables rules](docs/setup-networking.md#option-2-set-up-iptables-rules)
* [Configuration](docs/configuration.md)
  * [Credentials](docs/configuration.md#credentials)
  * [Custom IAM and STS Endpoints](docs/configuration.md#custom-iam-and-sts-endpoints)
  * [Docker](docs/configuration.md#docker)
  * [Environment Variables](docs/configuration.md#environment-variables)
* [Features](docs/features.md)
  * [Vend Credentials to Containers](docs/features.md#vend-credentials-to-containers)
  * [Metadata](docs/features.md#metadata)
    * [Task Metadata V2](docs/features.md#task-metadata-v2)
    * [Task Metadata V3](docs/features.md#task-metadata-v3)
    * [Task Metadata V4](docs/features.md#task-metadata-v4)
    * [Generic Metadata](docs/features.md#generic-metadata-injection)

#### Security disclosures

If you think you’ve found a potential security issue, please do not post it in the Issues.  Instead, please follow the instructions [here](https://aws.amazon.com/security/vulnerability-reporting/) or email AWS security directly at [aws-security@amazon.com](mailto:aws-security@amazon.com).

#### License

This library is licensed under the Apache 2.0 License.
