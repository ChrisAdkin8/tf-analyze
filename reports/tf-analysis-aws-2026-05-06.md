OPS-AWS-TAGS-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/01_broken_access_control.tf:49 aws_s3_bucket.no_block
ROB-AWS-LIFECYCLE-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/01_broken_access_control.tf:49 aws_s3_bucket.no_block
ROB-AWS-S3-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/01_broken_access_control.tf:49 aws_s3_bucket.no_block
SEC-AWS-IAM-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/01_broken_access_control.tf:38 
SEC-AWS-IAM-002 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/01_broken_access_control.tf:61 
SEC-AWS-S3-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/01_broken_access_control.tf:49 aws_s3_bucket.no_block
SEC-AWS-ACCESSKEY-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/07_identification_auth.tf:36 aws_iam_access_key.human
OPS-AWS-TAGS-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/05_security_misconfiguration.tf:46 aws_instance.public
OPS-AWS-TAGS-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/05_security_misconfiguration.tf:55 aws_db_instance.public_db
ROB-AWS-LIFECYCLE-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/05_security_misconfiguration.tf:55 aws_db_instance.public_db
ROB-AWS-RDS-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/05_security_misconfiguration.tf:55 aws_db_instance.public_db
ROB-AWS-RDS-002 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/05_security_misconfiguration.tf:55 aws_db_instance.public_db
SEC-AWS-RDS-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/05_security_misconfiguration.tf:55 aws_db_instance.public_db
SEC-AWS-SG-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/05_security_misconfiguration.tf:34 
SEC-AWS-SG-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/05_security_misconfiguration.tf:41 
SEC-AWS-SSRF-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/05_security_misconfiguration.tf:46 aws_instance.public
OPS-AWS-TAGS-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/10_ssrf.tf:38 aws_instance.imds_v1
OPS-AWS-TAGS-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/10_ssrf.tf:47 aws_instance.imds_v1_explicit
SEC-AWS-SSRF-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/10_ssrf.tf:38 aws_instance.imds_v1
SEC-AWS-SSRF-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/10_ssrf.tf:47 aws_instance.imds_v1_explicit
ROB-VERSION-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/versions.tf:9 
MOD-PIN-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/06_vulnerable_components.tf:50 module.unpinned_vpc
OPS-AWS-TAGS-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/06_vulnerable_components.tf:44 aws_instance.frozen_ami
OPS-AWS-TAGS-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/06_vulnerable_components.tf:29 aws_lambda_function.eol_runtime
SEC-AWS-SSRF-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/06_vulnerable_components.tf:44 aws_instance.frozen_ami
STK-AWS-LAMBDA-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/06_vulnerable_components.tf:29 aws_lambda_function.eol_runtime
COST-AWS-RISK-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/09_logging_monitoring.tf:59 aws_cloudwatch_log_group.no_retention
OPS-AWS-TAGS-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/09_logging_monitoring.tf:53 aws_s3_bucket.unlogged
ROB-AWS-LIFECYCLE-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/09_logging_monitoring.tf:53 aws_s3_bucket.unlogged
ROB-AWS-S3-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/09_logging_monitoring.tf:53 aws_s3_bucket.unlogged
SEC-AWS-CLOUDTRAIL-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/09_logging_monitoring.tf:35 aws_cloudtrail.single_region
SEC-AWS-S3-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/09_logging_monitoring.tf:53 aws_s3_bucket.unlogged
OPS-AWS-TAGS-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/02_cryptographic_failures.tf:35 aws_s3_bucket.no_sse
OPS-AWS-TAGS-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/02_cryptographic_failures.tf:40 aws_db_instance.unencrypted
ROB-AWS-LIFECYCLE-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/02_cryptographic_failures.tf:40 aws_db_instance.unencrypted
ROB-AWS-LIFECYCLE-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/02_cryptographic_failures.tf:35 aws_s3_bucket.no_sse
ROB-AWS-RDS-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/02_cryptographic_failures.tf:40 aws_db_instance.unencrypted
ROB-AWS-RDS-002 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/02_cryptographic_failures.tf:40 aws_db_instance.unencrypted
ROB-AWS-S3-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/02_cryptographic_failures.tf:35 aws_s3_bucket.no_sse
SEC-AWS-EBS-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/02_cryptographic_failures.tf:54 aws_ebs_volume.unencrypted
SEC-AWS-KMS-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/02_cryptographic_failures.tf:61 aws_kms_key.no_rotation
SEC-AWS-RDS-002 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/02_cryptographic_failures.tf:40 aws_db_instance.unencrypted
SEC-AWS-S3-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/02_cryptographic_failures.tf:35 aws_s3_bucket.no_sse
SEC-SECRETS-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/02_cryptographic_failures.tf:47 
OPS-AWS-TAGS-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/08_data_integrity.tf:36 aws_s3_bucket.no_versioning
OPS-AWS-TAGS-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/08_data_integrity.tf:44 aws_db_instance.no_backups
ROB-AWS-LIFECYCLE-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/08_data_integrity.tf:44 aws_db_instance.no_backups
ROB-AWS-LIFECYCLE-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/08_data_integrity.tf:36 aws_s3_bucket.no_versioning
ROB-AWS-RDS-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/08_data_integrity.tf:44 aws_db_instance.no_backups
ROB-AWS-RDS-002 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/08_data_integrity.tf:44 aws_db_instance.no_backups
ROB-AWS-S3-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/08_data_integrity.tf:36 aws_s3_bucket.no_versioning
SEC-AWS-ECR-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/08_data_integrity.tf:59 aws_ecr_repository.unscanned
SEC-AWS-S3-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/08_data_integrity.tf:36 aws_s3_bucket.no_versioning
SEC-AWS-SNS-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/08_data_integrity.tf:72 aws_sns_topic.unencrypted
SEC-AWS-SQS-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/08_data_integrity.tf:66 aws_sqs_queue.unencrypted
SEC-SECRETS-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/08_data_integrity.tf:51 
OPS-AWS-TAGS-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/04_insecure_design.tf:62 aws_dynamodb_table.stateful
ROB-AWS-LIFECYCLE-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/04_insecure_design.tf:62 aws_dynamodb_table.stateful
SEC-SECRETS-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/04_insecure_design.tf:37 
SEC-SECRETS-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/04_insecure_design.tf:37 
OPS-AWS-TAGS-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/03_injection.tf:37 aws_instance.ec2_user_data_injection
SEC-AWS-SSRF-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/03_injection.tf:37 aws_instance.ec2_user_data_injection
SEC-PROVISIONER-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/03_injection.tf:51 
CI-TEST-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/01_broken_access_control.tf:1 <module:aws>
ROB-AWS-BACKEND-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws/versions.tf:12 backend.s3
SEC-AWS-S3-PUBLIC-BLOCK-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws:0 <absent: aws_s3_bucket_public_access_block>
SEC-AWS-VPC-FLOWLOGS-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/aws:0 <absent: aws_flow_log>
