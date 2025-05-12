#!/usr/bin/env python3
"""
AWS Hunter - Advanced AWS credential checker and resource discovery tool
"""

import argparse
import boto3
import botocore
import concurrent.futures
import json
import os
import re
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Union, Any

# Terminal colors for better readability
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class AWSHunter:
    def __init__(self, access_key: str = None, secret_key: str = None, session_token: str = None, 
                 region: str = None, profile: str = None, output_file: str = None):
        self.access_key = access_key
        self.secret_key = secret_key
        self.session_token = session_token
        self.region = region or 'us-east-1'
        self.profile = profile
        self.output_file = output_file
        self.results = {
            "metadata": {
                "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "aws_hunter_version": "1.0.0",
            },
            "credentials": {},
            "account_info": {},
            "resources": {},
            "security_issues": []
        }
        self.session = None
        self.sts_client = None
        self.scanned_services = []
        self.MAX_WORKERS = 10

    def setup_session(self) -> bool:
        """Establish AWS session with provided credentials"""
        try:
            if self.profile:
                self.session = boto3.Session(profile_name=self.profile, region_name=self.region)
            else:
                self.session = boto3.Session(
                    aws_access_key_id=self.access_key,
                    aws_secret_access_key=self.secret_key,
                    aws_session_token=self.session_token,
                    region_name=self.region
                )
            
            # Test if credentials are valid
            self.sts_client = self.session.client('sts')
            identity = self.sts_client.get_caller_identity()
            
            self.results["credentials"] = {
                "valid": True,
                "access_key": self.access_key,
                "account_id": identity['Account'],
                "arn": identity['Arn'],
                "user_id": identity['UserId']
            }
            
            print(f"{Colors.GREEN}✓ Valid AWS credentials detected{Colors.ENDC}")
            print(f"  Account ID: {Colors.BOLD}{identity['Account']}{Colors.ENDC}")
            print(f"  User ARN: {identity['Arn']}")
            
            return True
        except botocore.exceptions.ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            error_msg = e.response.get('Error', {}).get('Message', 'Unknown error')
            
            self.results["credentials"] = {
                "valid": False,
                "error_code": error_code,
                "error_message": error_msg
            }
            
            print(f"{Colors.RED}✗ Invalid AWS credentials{Colors.ENDC}")
            print(f"  Error: {error_code} - {error_msg}")
            
            return False
        except Exception as e:
            self.results["credentials"] = {
                "valid": False,
                "error": str(e)
            }
            
            print(f"{Colors.RED}✗ Error validating credentials: {str(e)}{Colors.ENDC}")
            return False

    def get_account_info(self) -> None:
        """Gather basic account information"""
        print(f"\n{Colors.HEADER}Gathering Account Information...{Colors.ENDC}")
        
        try:
            # Get organization information if available
            try:
                org_client = self.session.client('organizations')
                org_details = org_client.describe_organization()
                self.results["account_info"]["organization"] = {
                    "id": org_details['Organization']['Id'],
                    "arn": org_details['Organization']['Arn'],
                    "master_account_id": org_details['Organization']['MasterAccountId'],
                    "master_account_email": org_details['Organization']['MasterAccountEmail']
                }
                print(f"{Colors.GREEN}✓ Organization information retrieved{Colors.ENDC}")
                print(f"  Organization ID: {org_details['Organization']['Id']}")
                print(f"  Master Account: {org_details['Organization']['MasterAccountEmail']}")
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'AWSOrganizationsNotInUseException':
                    print(f"{Colors.YELLOW}ℹ Account not part of an AWS Organization{Colors.ENDC}")
                else:
                    print(f"{Colors.YELLOW}ℹ Cannot access organization details: {e.response['Error']['Message']}{Colors.ENDC}")
            
            # Get IAM account details
            iam_client = self.session.client('iam')
            account_summary = iam_client.get_account_summary()
            account_aliases = iam_client.list_account_aliases()
            
            self.results["account_info"]["iam"] = {
                "summary": account_summary['SummaryMap'],
                "aliases": account_aliases.get('AccountAliases', [])
            }
            
            alias_info = f" ({', '.join(account_aliases['AccountAliases'])})" if account_aliases['AccountAliases'] else ""
            print(f"{Colors.GREEN}✓ IAM account details retrieved{Colors.ENDC}")
            print(f"  Account{alias_info}")
            print(f"  Users: {account_summary['SummaryMap'].get('Users', 0)}")
            print(f"  Groups: {account_summary['SummaryMap'].get('Groups', 0)}")
            print(f"  Roles: {account_summary['SummaryMap'].get('Roles', 0)}")
            print(f"  Policies: {account_summary['SummaryMap'].get('Policies', 0)}")
            
        except botocore.exceptions.ClientError as e:
            print(f"{Colors.YELLOW}ℹ Cannot retrieve account information: {e.response['Error']['Message']}{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.RED}✗ Error gathering account info: {str(e)}{Colors.ENDC}")

    def check_iam_permissions(self) -> None:
        """Check permissions of the current IAM user/role"""
        print(f"\n{Colors.HEADER}Checking IAM Permissions...{Colors.ENDC}")
        
        try:
            # Get identity information
            identity = self.sts_client.get_caller_identity()
            arn = identity['Arn']
            
            # Determine if this is a user, role, or assumed role
            iam_type = "user" if "/user/" in arn else "role" if "/role/" in arn else "assumed-role" if ":assumed-role/" in arn else "unknown"
            print(f"  Identity type: {iam_type}")
            
            if iam_type == "user":
                # Extract username from ARN
                username = arn.split("/")[-1]
                
                # Get user details
                iam_client = self.session.client('iam')
                user = iam_client.get_user(UserName=username)
                
                # Get attached policies
                attached_policies = iam_client.list_attached_user_policies(UserName=username)
                inline_policies = iam_client.list_user_policies(UserName=username)
                
                # Get groups the user belongs to
                groups = iam_client.list_groups_for_user(UserName=username)
                
                self.results["account_info"]["current_identity"] = {
                    "type": "user",
                    "username": username,
                    "arn": arn,
                    "created": user['User']['CreateDate'].strftime("%Y-%m-%d"),
                    "attached_policies": [p['PolicyName'] for p in attached_policies.get('AttachedPolicies', [])],
                    "inline_policies": inline_policies.get('PolicyNames', []),
                    "groups": [g['GroupName'] for g in groups.get('Groups', [])]
                }
                
                print(f"{Colors.GREEN}✓ User information retrieved{Colors.ENDC}")
                print(f"  Username: {username}")
                print(f"  Created: {user['User']['CreateDate'].strftime('%Y-%m-%d')}")
                print(f"  Attached policies: {len(attached_policies.get('AttachedPolicies', []))}")
                print(f"  Inline policies: {len(inline_policies.get('PolicyNames', []))}")
                print(f"  Groups: {', '.join([g['GroupName'] for g in groups.get('Groups', [])]) or 'None'}")
                
            elif iam_type == "role" or iam_type == "assumed-role":
                # For roles, we'll need to get info differently
                role_name = arn.split("/")[-1] if iam_type == "role" else arn.split("/")[1]
                
                self.results["account_info"]["current_identity"] = {
                    "type": iam_type,
                    "role_name": role_name,
                    "arn": arn
                }
                
                # If it's a standard role, we can get more details
                if iam_type == "role":
                    try:
                        iam_client = self.session.client('iam')
                        role = iam_client.get_role(RoleName=role_name)
                        attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)
                        inline_policies = iam_client.list_role_policies(RoleName=role_name)
                        
                        self.results["account_info"]["current_identity"].update({
                            "created": role['Role']['CreateDate'].strftime("%Y-%m-%d"),
                            "attached_policies": [p['PolicyName'] for p in attached_policies.get('AttachedPolicies', [])],
                            "inline_policies": inline_policies.get('PolicyNames', [])
                        })
                        
                        print(f"{Colors.GREEN}✓ Role information retrieved{Colors.ENDC}")
                        print(f"  Role name: {role_name}")
                        print(f"  Created: {role['Role']['CreateDate'].strftime('%Y-%m-%d')}")
                        print(f"  Attached policies: {len(attached_policies.get('AttachedPolicies', []))}")
                        print(f"  Inline policies: {len(inline_policies.get('PolicyNames', []))}")
                    except Exception as e:
                        print(f"{Colors.YELLOW}ℹ Cannot retrieve detailed role information: {str(e)}{Colors.ENDC}")
                
                print(f"{Colors.GREEN}✓ Identity information retrieved{Colors.ENDC}")
                print(f"  Type: {iam_type}")
                print(f"  Name: {role_name}")
                print(f"  ARN: {arn}")
            
            # Test common permissions
            self._test_common_permissions()
            
        except botocore.exceptions.ClientError as e:
            print(f"{Colors.YELLOW}ℹ Cannot retrieve identity permissions: {e.response['Error']['Message']}{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.RED}✗ Error checking permissions: {str(e)}{Colors.ENDC}")
    
    def _test_common_permissions(self) -> None:
        """Test for common permissions using simple API calls"""
        permissions = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.MAX_WORKERS) as executor:
            permission_tests = [
                self._check_permission("S3 List", lambda: self.session.client('s3').list_buckets()),
                self._check_permission("EC2 Describe Instances", lambda: self.session.client('ec2').describe_instances(MaxResults=5)),
                self._check_permission("IAM List Users", lambda: self.session.client('iam').list_users(MaxItems=1)),
                self._check_permission("RDS Describe Instances", lambda: self.session.client('rds').describe_db_instances(MaxRecords=20)),
                self._check_permission("Lambda List Functions", lambda: self.session.client('lambda').list_functions(MaxItems=1)),
                self._check_permission("DynamoDB List Tables", lambda: self.session.client('dynamodb').list_tables(Limit=1)),
                self._check_permission("CloudFormation List Stacks", lambda: self.session.client('cloudformation').list_stacks()),
                self._check_permission("CloudWatch List Metrics", lambda: self.session.client('cloudwatch').list_metrics(MaxResults=1)),
                self._check_permission("SecurityHub List Findings", lambda: self.session.client('securityhub').get_findings(MaxResults=1)),
                self._check_permission("KMS List Keys", lambda: self.session.client('kms').list_keys(Limit=1))
            ]
            
            for result in concurrent.futures.as_completed(permission_tests):
                try:
                    perm = result.result()
                    if perm:
                        permissions.append(perm)
                except Exception as e:
                    print(f"{Colors.RED}Error checking permission: {str(e)}{Colors.ENDC}")
        
        self.results["account_info"]["permissions_check"] = permissions
        
        print(f"{Colors.GREEN}✓ Tested {len(permission_tests)} common permissions{Colors.ENDC}")
        for perm in permissions:
            print(f"  ✓ Has permission: {perm}")
    
    def _check_permission(self, description, api_call) -> Optional[str]:
        """Test a single permission by making an API call"""
        try:
            api_call()
            return description
        except botocore.exceptions.ClientError:
            return None
        except Exception:
            return None

    def scan_s3_buckets(self) -> None:
        """Scan S3 buckets and check for common misconfigurations"""
        print(f"\n{Colors.HEADER}Scanning S3 Buckets...{Colors.ENDC}")
        
        try:
            s3_client = self.session.client('s3')
            buckets = s3_client.list_buckets()
            
            print(f"  Found {len(buckets['Buckets'])} buckets")
            self.results["resources"]["s3"] = {"buckets": []}
            
            for bucket in buckets['Buckets']:
                bucket_name = bucket['Name']
                print(f"  Scanning bucket: {bucket_name}...")
                
                bucket_details = {
                    "name": bucket_name,
                    "creation_date": bucket['CreationDate'].strftime("%Y-%m-%d"),
                    "issues": []
                }
                
                # Check bucket region
                try:
                    location = s3_client.get_bucket_location(Bucket=bucket_name)
                    region = location['LocationConstraint'] or 'us-east-1'
                    bucket_details["region"] = region
                except Exception:
                    bucket_details["region"] = "unknown"
                
                # Check bucket ACL
                try:
                    acl = s3_client.get_bucket_acl(Bucket=bucket_name)
                    bucket_details["acl"] = []
                    
                    for grant in acl['Grants']:
                        grantee = grant['Grantee']
                        permission = grant['Permission']
                        
                        # Check for public access
                        if 'URI' in grantee and grantee['URI'] == 'http://acs.amazonaws.com/groups/global/AllUsers':
                            issue = f"S3 bucket '{bucket_name}' has public {permission} access"
                            bucket_details["issues"].append({"severity": "HIGH", "issue": issue})
                            self.results["security_issues"].append({"severity": "HIGH", "service": "S3", "issue": issue})
                            print(f"    {Colors.RED}! Public {permission} access detected{Colors.ENDC}")
                        
                        bucket_details["acl"].append({
                            "type": grantee.get('Type', 'Unknown'),
                            "identifier": grantee.get('URI', grantee.get('ID', 'Unknown')),
                            "permission": permission
                        })
                except Exception as e:
                    print(f"    {Colors.YELLOW}Cannot check ACL: {str(e)}{Colors.ENDC}")
                
                # Check bucket policy
                try:
                    policy = s3_client.get_bucket_policy(Bucket=bucket_name)
                    bucket_details["has_policy"] = True
                    
                    # Simple policy analysis for public access
                    policy_json = json.loads(policy['Policy'])
                    for statement in policy_json.get('Statement', []):
                        principal = statement.get('Principal', {})
                        if principal == '*' or principal.get('AWS') == '*':
                            effect = statement.get('Effect', '')
                            if effect.upper() == 'ALLOW':
                                issue = f"S3 bucket '{bucket_name}' may have public access via bucket policy"
                                bucket_details["issues"].append({"severity": "HIGH", "issue": issue})
                                self.results["security_issues"].append({"severity": "HIGH", "service": "S3", "issue": issue})
                                print(f"    {Colors.RED}! Potential public access via bucket policy{Colors.ENDC}")
                except botocore.exceptions.ClientError as e:
                    error_code = e.response['Error']['Code']
                    if error_code == 'NoSuchBucketPolicy':
                        bucket_details["has_policy"] = False
                    else:
                        print(f"    {Colors.YELLOW}Cannot check policy: {e.response['Error']['Message']}{Colors.ENDC}")
                except Exception as e:
                    print(f"    {Colors.YELLOW}Error checking policy: {str(e)}{Colors.ENDC}")
                
                # Check for encryption
                try:
                    encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
                    rules = encryption['ServerSideEncryptionConfiguration']['Rules']
                    bucket_details["encryption"] = rules
                except botocore.exceptions.ClientError:
                    bucket_details["encryption"] = None
                    issue = f"S3 bucket '{bucket_name}' does not have default encryption"
                    bucket_details["issues"].append({"severity": "MEDIUM", "issue": issue})
                    self.results["security_issues"].append({"severity": "MEDIUM", "service": "S3", "issue": issue})
                    print(f"    {Colors.YELLOW}! No default encryption{Colors.ENDC}")
                
                # Check versioning
                try:
                    versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
                    status = versioning.get('Status', 'Disabled')
                    bucket_details["versioning"] = status
                    
                    if status != 'Enabled':
                        issue = f"S3 bucket '{bucket_name}' does not have versioning enabled"
                        bucket_details["issues"].append({"severity": "LOW", "issue": issue})
                        self.results["security_issues"].append({"severity": "LOW", "service": "S3", "issue": issue})
                        print(f"    {Colors.YELLOW}! Versioning not enabled{Colors.ENDC}")
                except Exception:
                    bucket_details["versioning"] = "Unknown"
                
                self.results["resources"]["s3"]["buckets"].append(bucket_details)
            
            # Summary
            high_issues = sum(1 for b in self.results["resources"]["s3"]["buckets"] 
                             for i in b.get("issues", []) if i["severity"] == "HIGH")
            
            if high_issues > 0:
                print(f"\n{Colors.RED}! Found {high_issues} high severity S3 bucket issues{Colors.ENDC}")
            else:
                print(f"\n{Colors.GREEN}✓ No high severity S3 bucket issues found{Colors.ENDC}")
            
        except botocore.exceptions.ClientError as e:
            print(f"{Colors.YELLOW}ℹ Cannot scan S3 buckets: {e.response['Error']['Message']}{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.RED}✗ Error scanning S3 buckets: {str(e)}{Colors.ENDC}")

    def scan_ec2_instances(self) -> None:
        """Scan EC2 instances and related resources"""
        print(f"\n{Colors.HEADER}Scanning EC2 Resources...{Colors.ENDC}")
        
        try:
            ec2_client = self.session.client('ec2')
            
            # Check if we can describe regions
            regions = [self.region]
            try:
                regions_response = ec2_client.describe_regions()
                regions = [region['RegionName'] for region in regions_response['Regions']]
                print(f"  Scanning across {len(regions)} regions")
            except Exception:
                print(f"  Limited to scanning in {self.region} only")
            
            self.results["resources"]["ec2"] = {
                "instances": [],
                "security_groups": [],
                "volumes": []
            }
            
            for region in regions:
                try:
                    regional_ec2 = self.session.client('ec2', region_name=region)
                    
                    # Get instances
                    instances_paginator = regional_ec2.get_paginator('describe_instances')
                    instance_count = 0
                    
                    for page in instances_paginator.paginate():
                        for reservation in page['Reservations']:
                            for instance in reservation['Instances']:
                                instance_count += 1
                                instance_id = instance['InstanceId']
                                
                                instance_details = {
                                    "instance_id": instance_id,
                                    "region": region,
                                    "instance_type": instance['InstanceType'],
                                    "state": instance['State']['Name'],
                                    "launch_time": instance.get('LaunchTime', '').strftime("%Y-%m-%d") 
                                                  if 'LaunchTime' in instance else "Unknown",
                                    "vpc_id": instance.get('VpcId', 'Unknown'),
                                    "subnet_id": instance.get('SubnetId', 'Unknown')
                                }
                                
                                # Get instance tags if any
                                if 'Tags' in instance:
                                    instance_details["tags"] = {tag['Key']: tag['Value'] for tag in instance['Tags']}
                                
                                # Check for public IP
                                if 'PublicIpAddress' in instance:
                                    instance_details["public_ip"] = instance['PublicIpAddress']
                                    
                                    # Check if it has security group allowing inbound from 0.0.0.0/0
                                    for sg in instance.get('SecurityGroups', []):
                                        try:
                                            sg_details = regional_ec2.describe_security_groups(
                                                GroupIds=[sg['GroupId']]
                                            )
                                            
                                            for security_group in sg_details['SecurityGroups']:
                                                for rule in security_group.get('IpPermissions', []):
                                                    for ip_range in rule.get('IpRanges', []):
                                                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                                                            from_port = rule.get('FromPort', 'All')
                                                            to_port = rule.get('ToPort', 'All')
                                                            
                                                            issue = (f"EC2 instance '{instance_id}' in {region} has public IP "
                                                                     f"and security group allowing inbound from 0.0.0.0/0 "
                                                                     f"on ports {from_port}-{to_port}")
                                                            
                                                            self.results["security_issues"].append({
                                                                "severity": "HIGH", 
                                                                "service": "EC2", 
                                                                "issue": issue
                                                            })
                                                            print(f"    {Colors.RED}! Public instance with open security group{Colors.ENDC}")
                                                            break
                                        except Exception:
                                            pass
                                
                                self.results["resources"]["ec2"]["instances"].append(instance_details)
                    
                    print(f"  Found {instance_count} EC2 instances in {region}")
                    
                    # Get security groups with open rules
                    try:
                        sgs = regional_ec2.describe_security_groups()
                        for sg in sgs['SecurityGroups']:
                            sg_id = sg['GroupId']
                            
                            # Check for overly permissive rules
                            for rule in sg.get('IpPermissions', []):
                                for ip_range in rule.get('IpRanges', []):
                                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                                        from_port = rule.get('FromPort', 'All')
                                        to_port = rule.get('ToPort', 'All')
                                        
                                        # Critical services like SSH (22), RDP (3389)
                                        if from_port in [22, 3389] or (isinstance(from_port, int) and isinstance(to_port, int) and 
                                                                      from_port <= 22 <= to_port or from_port <= 3389 <= to_port):
                                            issue = (f"Security group '{sg_id}' in {region} allows unrestricted "
                                                     f"access to critical port {from_port}")
                                            
                                            self.results["security_issues"].append({
                                                "severity": "CRITICAL", 
                                                "service": "EC2", 
                                                "issue": issue
                                            })
                                            print(f"    {Colors.RED}! Critical: Open {from_port} from internet in SG {sg_id}{Colors.ENDC}")
                            
                            # Store security group details
                            self.results["resources"]["ec2"]["security_groups"].append({
                                "group_id": sg_id,
                                "region": region,
                                "name": sg.get('GroupName', 'Unknown'),
                                "description": sg.get('Description', ''),
                                "vpc_id": sg.get('VpcId', 'Unknown'),
                                "inbound_rules": sg.get('IpPermissions', []),
                                "outbound_rules": sg.get('IpPermissionsEgress', [])
                            })
                    except Exception as e:
                        print(f"    {Colors.YELLOW}Cannot list security groups in {region}: {str(e)}{Colors.ENDC}")
                    
                except botocore.exceptions.ClientError as e:
                    print(f"  {Colors.YELLOW}Cannot scan EC2 in {region}: {e.response['Error']['Message']}{Colors.ENDC}")
                except Exception as e:
                    print(f"  {Colors.RED}Error scanning EC2 in {region}: {str(e)}{Colors.ENDC}")
            
            # Summary
            critical_issues = sum(1 for i in self.results["security_issues"] 
                                if i["service"] == "EC2" and i["severity"] == "CRITICAL")
            high_issues = sum(1 for i in self.results["security_issues"] 
                             if i["service"] == "EC2" and i["severity"] == "HIGH")
            
            if critical_issues > 0:
                print(f"\n{Colors.RED}! Found {critical_issues} critical EC2 security issues{Colors.ENDC}")
            elif high_issues > 0:
                print(f"\n{Colors.RED}! Found {high_issues} high severity EC2 security issues{Colors.ENDC}")
            else:
                print(f"\n{Colors.GREEN}✓ No critical or high severity EC2 issues found{Colors.ENDC}")
            
        except botocore.exceptions.ClientError as e:
            print(f"{Colors.YELLOW}ℹ Cannot scan EC2 resources: {e.response['Error']['Message']}{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.RED}✗ Error scanning EC2 resources: {str(e)}{Colors.ENDC}")

    def scan_iam_resources(self) -> None:
        """Scan IAM users, roles, and policies for security issues"""
        print(f"\n{Colors.HEADER}Scanning IAM Resources...{Colors.ENDC}")
        
        try:
            iam_client = self.session.client('iam')
            
            self.results["resources"]["iam"] = {
                "users": [],
                "roles": [],
                "policies": []
            }
            
            # Get users
            try:
                users_paginator = iam_client.get_paginator('list_users')
                user_count = 0
                
                for page in users_paginator.paginate():
                    for user in page['Users']:
                        user_count += 1
                        username = user['UserName']
                        
                        user_details = {
                            "username": username,
                            "user_id": user['UserId'],
                            "arn": user['Arn'],
                            "created": user['CreateDate'].strftime("%Y-%m-%d"),
                            "console_access": False,
                            "mfa_enabled": False,
                            "access_keys": []
                        }
                        
                        # Check for console access
                        try:
                            login_profile = iam_client.get_login_profile(UserName=username)
                            user_details["console_access"] = True
                            
                            # Check for MFA
                            mfa_devices = iam_client.list_mfa_devices(UserName=username)
                            user_details["mfa_enabled"] = len(mfa_devices['MFADevices']) > 0
                            
                            if user_details["console_access"] and not user_details["mfa_enabled"]:
                                issue = f"IAM user '{username}' has console access without MFA"
                                self.results["security_issues"].append({
                                    "severity": "HIGH", 
                                    "service": "IAM", 
                                    "issue": issue
                                })
                                print(f"    {Colors.RED}! User {username} has console access without MFA{Colors.ENDC}")
                        except botocore.exceptions.ClientError:
                            # No login profile means no console access
                            pass
                        
                        # Check for access keys
                        access_keys = iam_client.list_access_keys(UserName=username)
                        for key in access_keys['AccessKeyMetadata']:
                            key_id = key['AccessKeyId']
                            status = key['Status']
                            created = key['CreateDate'].strftime("%Y-%m-%d")
                            
                            # Check key age
                            key_age_days = (datetime.now() - key['CreateDate'].replace(tzinfo=None)).days
                            
                            user_details["access_keys"].append({
                                "access_key_id": key_id,
                                "status": status,
                                "created": created,
                                "age_days": key_age_days
                            })
                            
                            if key_age_days > 90 and status == 'Active':
                                issue = f"IAM user '{username}' has active access key older than 90 days"
                                self.results["security_issues"].append({
                                    "severity": "MEDIUM", 
                                    "service": "IAM", 
                                    "issue": issue
                                })
                                print(f"    {Colors.YELLOW}! User {username} has access key older than 90 days{Colors.ENDC}")
                        
                        self.results["resources"]["iam"]["users"].append(user_details)
                
                print(f"  Found {user_count} IAM users")
                
                # Check root account
                try:
                    root_keys = iam_client.get_account_summary()
                    if root_keys['SummaryMap'].get('AccountAccessKeysPresent', 0) > 0:
                        issue = "Root account has active access keys"
                        self.results["security_issues"].append({
                            "severity": "CRITICAL", 
                            "service": "IAM", 
                            "issue": issue
                        })
                        print(f"    {Colors.RED}! CRITICAL: Root account has active access keys{Colors.ENDC}")
                except Exception:
                    pass
                
            except Exception as e:
                print(f"    {Colors.YELLOW}Cannot list IAM users: {str(e)}{Colors.ENDC}")
            
            # Get roles with risky trust policies
            try:
                roles_paginator = iam_client.get_paginator('list_roles')
                role_count = 0
                
                for page in roles_paginator.paginate():
                    for role in page['Roles']:
                        role_count += 1
                        role_name = role['RoleName']
                        
                        role_details = {
                            "role_name": role_name,
                            "role_id": role['RoleId'],
                            "arn": role['Arn'],
                            "created": role['CreateDate'].strftime("%Y-%m-%d"),
                            "trust_policy": role['AssumeRolePolicyDocument']
                        }
                        
                        # Check for overly permissive trust relationships
                        trust_policy = role['AssumeRolePolicyDocument']
                        for statement in trust_policy.get('Statement', []):
                            principal = statement.get('Principal', {})
                            
                            # Check for wildcards in principals
                            aws_principal = principal.get('AWS', '')
                            if aws_principal == '*' or (isinstance(aws_principal, list) and '*' in aws_principal):
                                issue = f"IAM role '{role_name}' trusts any AWS account"
                                self.results["security_issues"].append({
                                    "severity": "HIGH", 
                                    "service": "IAM", 
                                    "issue": issue
                                })
                                print(f"    {Colors.RED}! Role {role_name} trusts any AWS account{Colors.ENDC}")
                        
                        self.results["resources"]["iam"]["roles"].append(role_details)
                
                print(f"  Found {role_count} IAM roles")
                
            except Exception as e:
                print(f"    {Colors.YELLOW}Cannot list IAM roles: {str(e)}{Colors.ENDC}")
            
            # Check for policies with full admin privileges
            try:
                policies_paginator = iam_client.get_paginator('list_policies')
                custom_admin_policies = 0
                
                for page in policies_paginator.paginate(Scope='Local'):
                    for policy in page['Policies']:
                        policy_arn = policy['Arn']
                        policy_name = policy['PolicyName']
                        
                        policy_details = {
                            "policy_name": policy_name,
                            "policy_id": policy['PolicyId'],
                            "arn": policy_arn
                        }
                        
                        # Check policy document for admin privileges
                        try:
                            policy_version = iam_client.get_policy_version(
                                PolicyArn=policy_arn,
                                VersionId=policy['DefaultVersionId']
                            )
                            
                            policy_doc = policy_version['PolicyVersion']['Document']
                            policy_details["document"] = policy_doc
                            
                            for statement in policy_doc.get('Statement', []):
                                effect = statement.get('Effect', '')
                                action = statement.get('Action', [])
                                resource = statement.get('Resource', '')
                                
                                if effect.upper() == 'ALLOW':
                                    if action == '*' and resource == '*':
                                        custom_admin_policies += 1
                                        issue = f"Customer-managed policy '{policy_name}' has full administrative privileges"
                                        self.results["security_issues"].append({
                                            "severity": "HIGH", 
                                            "service": "IAM", 
                                            "issue": issue
                                        })
                                        print(f"    {Colors.RED}! Policy {policy_name} grants full admin privileges{Colors.ENDC}")
                                    elif isinstance(action, list) and '*' in action and resource == '*':
                                        custom_admin_policies += 1
                                        issue = f"Customer-managed policy '{policy_name}' has overly permissive privileges"
                                        self.results["security_issues"].append({
                                            "severity": "HIGH", 
                                            "service": "IAM", 
                                            "issue": issue
                                        })
                                        print(f"    {Colors.RED}! Policy {policy_name} is overly permissive{Colors.ENDC}")
                        except Exception:
                            policy_details["document"] = "Could not retrieve policy document"
                        
                        self.results["resources"]["iam"]["policies"].append(policy_details)
                
                if custom_admin_policies > 0:
                    print(f"  Found {custom_admin_policies} customer-managed policies with admin privileges")
                
            except Exception as e:
                print(f"    {Colors.YELLOW}Cannot analyze IAM policies: {str(e)}{Colors.ENDC}")
            
            # Summary
            critical_issues = sum(1 for i in self.results["security_issues"] 
                                if i["service"] == "IAM" and i["severity"] == "CRITICAL")
            high_issues = sum(1 for i in self.results["security_issues"] 
                             if i["service"] == "IAM" and i["severity"] == "HIGH")
            
            if critical_issues > 0:
                print(f"\n{Colors.RED}! Found {critical_issues} critical IAM security issues{Colors.ENDC}")
            elif high_issues > 0:
                print(f"\n{Colors.RED}! Found {high_issues} high severity IAM security issues{Colors.ENDC}")
            else:
                print(f"\n{Colors.GREEN}✓ No critical or high severity IAM issues found{Colors.ENDC}")
            
        except botocore.exceptions.ClientError as e:
            print(f"{Colors.YELLOW}ℹ Cannot scan IAM resources: {e.response['Error']['Message']}{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.RED}✗ Error scanning IAM resources: {str(e)}{Colors.ENDC}")

    def scan_lambda_functions(self) -> None:
        """Scan Lambda functions for security issues"""
        print(f"\n{Colors.HEADER}Scanning Lambda Functions...{Colors.ENDC}")
        
        try:
            lambda_client = self.session.client('lambda')
            
            # Check if we can describe regions to scan all regions
            regions = [self.region]
            try:
                ec2_client = self.session.client('ec2')
                regions_response = ec2_client.describe_regions()
                regions = [region['RegionName'] for region in regions_response['Regions']]
                print(f"  Scanning across {len(regions)} regions")
            except Exception:
                print(f"  Limited to scanning in {self.region} only")
            
            self.results["resources"]["lambda"] = {
                "functions": []
            }
            
            total_functions = 0
            
            for region in regions:
                try:
                    regional_lambda = self.session.client('lambda', region_name=region)
                    
                    # Get Lambda functions
                    functions_paginator = regional_lambda.get_paginator('list_functions')
                    region_function_count = 0
                    
                    for page in functions_paginator.paginate():
                        for function in page['Functions']:
                            region_function_count += 1
                            total_functions += 1
                            function_name = function['FunctionName']
                            
                            function_details = {
                                "function_name": function_name,
                                "arn": function['FunctionArn'],
                                "runtime": function.get('Runtime', 'Unknown'),
                                "role": function.get('Role', 'Unknown'),
                                "handler": function.get('Handler', 'Unknown'),
                                "region": region,
                                "last_modified": function.get('LastModified', 'Unknown'),
                                "memory_size": function.get('MemorySize', 0),
                                "timeout": function.get('Timeout', 0),
                                "vpc_config": function.get('VpcConfig', {})
                            }
                            
                            # Check for environment variables
                            if 'Environment' in function and 'Variables' in function['Environment']:
                                env_vars = function['Environment']['Variables']
                                var_names = list(env_vars.keys())
                                function_details["environment_variables"] = var_names
                                
                                # Check for sensitive data in environment variables
                                sensitive_patterns = ['key', 'secret', 'password', 'token', 'credential']
                                for var_name in var_names:
                                    for pattern in sensitive_patterns:
                                        if pattern.lower() in var_name.lower():
                                            issue = f"Lambda function '{function_name}' in {region} may have sensitive data in environment variables"
                                            self.results["security_issues"].append({
                                                "severity": "MEDIUM", 
                                                "service": "Lambda", 
                                                "issue": issue
                                            })
                                            print(f"    {Colors.YELLOW}! Function {function_name} may expose sensitive data in env vars{Colors.ENDC}")
                                            break
                            
                            # Check for old runtimes
                            deprecated_runtimes = [
                                'nodejs6.10', 'nodejs8.10', 'nodejs10.x', 
                                'python2.7', 'python3.6',
                                'ruby2.5',
                                'dotnetcore2.0', 'dotnetcore2.1'
                            ]
                            
                            if function.get('Runtime') in deprecated_runtimes:
                                issue = f"Lambda function '{function_name}' in {region} uses deprecated runtime {function.get('Runtime')}"
                                self.results["security_issues"].append({
                                    "severity": "MEDIUM", 
                                    "service": "Lambda", 
                                    "issue": issue
                                })
                                print(f"    {Colors.YELLOW}! Function {function_name} uses deprecated runtime {function.get('Runtime')}{Colors.ENDC}")
                            
                            # Check permissions
                            try:
                                policy = regional_lambda.get_policy(FunctionName=function_name)
                                if 'Policy' in policy:
                                    policy_json = json.loads(policy['Policy'])
                                    function_details["policy"] = policy_json
                                    
                                    for statement in policy_json.get('Statement', []):
                                        principal = statement.get('Principal', {})
                                        
                                        # Check for public access
                                        if isinstance(principal, dict) and principal.get('Service') == 'apigateway.amazonaws.com':
                                            # This is normal for API Gateway integrations, but check if source ARN is specified
                                            condition = statement.get('Condition', {})
                                            if 'ArnLike' not in condition and 'StringEquals' not in condition:
                                                issue = f"Lambda function '{function_name}' in {region} may be publicly accessible via API Gateway without source ARN restriction"
                                                self.results["security_issues"].append({
                                                    "severity": "MEDIUM", 
                                                    "service": "Lambda", 
                                                    "issue": issue
                                                })
                                                print(f"    {Colors.YELLOW}! Function {function_name} may be publicly exposed{Colors.ENDC}")
                            except Exception:
                                function_details["policy"] = "Could not retrieve policy"
                            
                            self.results["resources"]["lambda"]["functions"].append(function_details)
                    
                    if region_function_count > 0:
                        print(f"  Found {region_function_count} Lambda functions in {region}")
                
                except botocore.exceptions.ClientError as e:
                    print(f"  {Colors.YELLOW}Cannot scan Lambda in {region}: {e.response['Error']['Message']}{Colors.ENDC}")
                except Exception as e:
                    print(f"  {Colors.RED}Error scanning Lambda in {region}: {str(e)}{Colors.ENDC}")
            
            # Summary
            print(f"  Total Lambda functions across all regions: {total_functions}")
            medium_issues = sum(1 for i in self.results["security_issues"] 
                              if i["service"] == "Lambda" and i["severity"] == "MEDIUM")
            
            if medium_issues > 0:
                print(f"\n{Colors.YELLOW}! Found {medium_issues} medium severity Lambda security issues{Colors.ENDC}")
            else:
                print(f"\n{Colors.GREEN}✓ No significant Lambda security issues found{Colors.ENDC}")
            
        except botocore.exceptions.ClientError as e:
            print(f"{Colors.YELLOW}ℹ Cannot scan Lambda functions: {e.response['Error']['Message']}{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.RED}✗ Error scanning Lambda functions: {str(e)}{Colors.ENDC}")

    def generate_report(self) -> None:
        """Generate a detailed security report"""
        print(f"\n{Colors.HEADER}Generating Security Report...{Colors.ENDC}")
        
        # Add summary to results
        critical_issues = sum(1 for i in self.results["security_issues"] if i["severity"] == "CRITICAL")
        high_issues = sum(1 for i in self.results["security_issues"] if i["severity"] == "HIGH")
        medium_issues = sum(1 for i in self.results["security_issues"] if i["severity"] == "MEDIUM")
        low_issues = sum(1 for i in self.results["security_issues"] if i["severity"] == "LOW")
        
        self.results["summary"] = {
            "total_issues": len(self.results["security_issues"]),
            "critical_issues": critical_issues,
            "high_issues": high_issues,
            "medium_issues": medium_issues,
            "low_issues": low_issues,
            "scanned_services": self.scanned_services,
            "resources_found": {
                "s3_buckets": len(self.results.get("resources", {}).get("s3", {}).get("buckets", [])),
                "ec2_instances": len(self.results.get("resources", {}).get("ec2", {}).get("instances", [])),
                "iam_users": len(self.results.get("resources", {}).get("iam", {}).get("users", [])),
                "iam_roles": len(self.results.get("resources", {}).get("iam", {}).get("roles", [])),
                "lambda_functions": len(self.results.get("resources", {}).get("lambda", {}).get("functions", []))
            }
        }
        
        # Print summary
        print(f"\n{Colors.BOLD}Summary:{Colors.ENDC}")
        print(f"  Total issues found: {len(self.results['security_issues'])}")
        if critical_issues > 0:
            print(f"  {Colors.RED}Critical issues: {critical_issues}{Colors.ENDC}")
        if high_issues > 0:
            print(f"  {Colors.RED}High severity issues: {high_issues}{Colors.ENDC}")
        if medium_issues > 0:
            print(f"  {Colors.YELLOW}Medium severity issues: {medium_issues}{Colors.ENDC}")
        if low_issues > 0:
            print(f"  Low severity issues: {low_issues}")
        
        # Print resources scanned
        print(f"\n{Colors.BOLD}Resources scanned:{Colors.ENDC}")
        for service, count in self.results["summary"]["resources_found"].items():
            print(f"  {service}: {count}")
        
        # Write output to file if specified
        if self.output_file:
            try:
                with open(self.output_file, 'w') as f:
                    json.dump(self.results, f, indent=2, default=str)
                print(f"\n{Colors.GREEN}✓ Report saved to {self.output_file}{Colors.ENDC}")
            except Exception as e:
                print(f"\n{Colors.RED}✗ Error saving report to {self.output_file}: {str(e)}{Colors.ENDC}")
                # Try to save with a default filename
                try:
                    default_filename = f"aws_hunter_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                    with open(default_filename, 'w') as f:
                        json.dump(self.results, f, indent=2, default=str)
                    print(f"{Colors.GREEN}✓ Report saved to {default_filename} instead{Colors.ENDC}")
                except Exception:
                    print(f"{Colors.RED}✗ Could not save report to file{Colors.ENDC}")
    
    def run(self) -> None:
        """Run the AWS Hunter scan"""
        print(f"\n{Colors.BOLD}AWS Hunter - Advanced AWS credential checker and resource discovery tool{Colors.ENDC}")
        print(f"Scan started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        # Setup AWS session and validate credentials
        if not self.setup_session():
            return
        
        # Get basic account information
        self.get_account_info()
        self.scanned_services.append("account")
        
        # Check IAM permissions
        self.check_iam_permissions()
        self.scanned_services.append("iam_permissions")
        
        # Scan resources
        self.scan_s3_buckets()
        self.scanned_services.append("s3")
        
        self.scan_ec2_instances()
        self.scanned_services.append("ec2")
        
        self.scan_iam_resources()
        self.scanned_services.append("iam")
        
        self.scan_lambda_functions()
        self.scanned_services.append("lambda")
        
        # Generate report
        self.generate_report()
        
        print(f"\n{Colors.BOLD}Scan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.ENDC}")

def parse_arguments():
    parser = argparse.ArgumentParser(description='AWS Hunter - Advanced AWS credential checker and resource discovery tool')
    
    credentials_group = parser.add_argument_group('AWS Credentials')
    credentials_group.add_argument('--access-key', '-a', help='AWS Access Key ID')
    credentials_group.add_argument('--secret-key', '-s', help='AWS Secret Access Key')
    credentials_group.add_argument('--session-token', '-t', help='AWS Session Token (optional)')
    credentials_group.add_argument('--region', '-r', default='us-east-1', help='AWS Region (default: us-east-1)')
    credentials_group.add_argument('--profile', '-p', help='AWS Profile name (uses ~/.aws/credentials)')
    
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument('--output', '-o', help='Output file for JSON report')
    
    # Check for credentials file with multiple sets
    parser.add_argument('--credentials-file', '-c', help='File containing AWS credentials (one per line)')
    
    args = parser.parse_args()
    
    # If using credentials file, it overrides other credentials
    if args.credentials_file:
        process_credentials_file(args.credentials_file, args.region, args.output)
        sys.exit(0)
    
    # Check if credentials are provided via environment variables
    if not args.access_key and not args.profile and 'AWS_ACCESS_KEY_ID' in os.environ:
        args.access_key = os.environ['AWS_ACCESS_KEY_ID']
        args.secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
        args.session_token = os.environ.get('AWS_SESSION_TOKEN')
        print(f"{Colors.BLUE}Using AWS credentials from environment variables{Colors.ENDC}")
    
    # Validate credentials are provided
    if not args.profile and (not args.access_key or not args.secret_key):
        parser.error("Either --profile or both --access-key and --secret-key are required")
    
    return args

def process_credentials_file(file_path, region, output_file):
    """Process a file with multiple AWS credentials"""
    try:
        with open(file_path, 'r') as f:
            lines = f.readlines()
        
        valid_credentials = 0
        
        for i, line in enumerate(lines):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            parts = line.split(',')
            if len(parts) < 2:
                print(f"{Colors.YELLOW}Skipping invalid line {i+1}: {line}{Colors.ENDC}")
                continue
            
            access_key = parts[0].strip()
            secret_key = parts[1].strip()
            session_token = parts[2].strip() if len(parts) > 2 else None
            
            print(f"\n{Colors.BOLD}Processing credentials set {i+1}{Colors.ENDC}")
            print(f"Access Key: {access_key[:4]}...{access_key[-4:]}")
            
            # Create a unique output file name if output was specified
            current_output = f"{output_file.rsplit('.', 1)[0]}_{i+1}.{output_file.rsplit('.', 1)[1]}" if output_file else None
            
            # Run scan with these credentials
            scanner = AWSHunter(access_key, secret_key, session_token, region, None, current_output)
            if scanner.setup_session():
                valid_credentials += 1
                scanner.run()
            
        print(f"\n{Colors.BOLD}Completed processing {valid_credentials} valid credential sets out of {len(lines)} total.{Colors.ENDC}")
        
    except Exception as e:
        print(f"{Colors.RED}Error processing credentials file: {str(e)}{Colors.ENDC}")

if __name__ == "__main__":
    try:
        args = parse_arguments()
        
        scanner = AWSHunter(
            access_key=args.access_key,
            secret_key=args.secret_key,
            session_token=args.session_token,
            region=args.region,
            profile=args.profile,
            output_file=args.output
        )
        
        scanner.run()
        
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Scan interrupted by user{Colors.ENDC}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.RED}Error: {str(e)}{Colors.ENDC}")
        sys.exit(1)