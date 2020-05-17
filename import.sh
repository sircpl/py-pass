#!/bin/bash
source .import
aws --profile $AWS_PROFILE s3 cp s3://$S3_OBJECT - | gpg2 -d -r "$GPG_USER" | PYTHONPATH=. python3 pypass/main.py import
