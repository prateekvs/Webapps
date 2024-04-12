import boto3
import json
from botocore.exceptions import ClientError

def get_policy_arn(iam_client, policy_name, policy_document):
    try:
        response = iam_client.list_policies(Scope='Local')  # 'AWS' for AWS-managed, 'Local' for customer created
        for policy in response['Policies']:
            if policy['PolicyName'] == policy_name:
                return policy['Arn']
        return None
    except ClientError as e:
        print(f"Error retrieving policy ARN: {e}")
        return None

'''
def create_iam_policy(iam_client, policy_name, policy_document):
    try:
        policy_json = json.dumps(policy_document)  # Convert dictionary to JSON string properly
        response = iam_client.create_policy(
            PolicyName=policy_name,
            PolicyDocument=policy_json
        )
        return response['Policy']['Arn']
    except ClientError as e:
        print(f"Error creating policy: {e}")
        return None
'''

def attach_policy_to_role(iam_client, role_name, policy_arn):
    try:
        iam_client.attach_role_policy(
            RoleName=role_name,
            PolicyArn=policy_arn
        )
        print(f"Policy attached to role {role_name} successfully.")
    except ClientError as e:
        print(f"Error attaching policy to role: {e}")

def create_codebuild_project(codebuild_client, project_name, source_repo, environment_image, eks_cluster_name, service_role_arn):
    try:
        response = codebuild_client.create_project(
            name=project_name,
            source={
                'type': 'GITHUB',
                'location': source_repo
            },
            artifacts={
                'type': 'NO_ARTIFACTS',
            },
            environment={
                'type': 'LINUX_CONTAINER',
                'image': environment_image,
                'computeType': 'BUILD_GENERAL1_SMALL',
                'environmentVariables': [
                    {
                        'name': 'EKS_CLUSTER_NAME',
                        'value': eks_cluster_name,
                        'type': 'PLAINTEXT'
                    }
                ]
            },
            serviceRole=service_role_arn,
            timeoutInMinutes=60,
            queuedTimeoutInMinutes=30,
            buildBatchConfig={
                'serviceRole': service_role_arn,
            }
        )
        return response
    except ClientError as e:
        print(f"An error occurred creating the CodeBuild project: {e}")
        return None

def start_build(codebuild_client, project_name):
    try:
        response = codebuild_client.start_build(projectName=project_name)
        return response
    except ClientError as e:
        print(f"An error occurred starting the build: {e}")
        return None

def main():
    iam_client = boto3.client('iam')
    codebuild_client = boto3.client('codebuild')

    project_name = "WebAppBuild"
    source_repo = "https://github.com/prateekvs/Webapps.git"
    environment_image = "aws/codebuild/standard:4.0"
    eks_cluster_name = "kube32neweks"
    service_role_arn = 'arn:aws:iam::026894909295:role/CodeBuildServiceRole'
    policy_name = "CodeBuildEKSAccessRole"

    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "ecr:GetAuthorizationToken",
                    "ecr:BatchCheckLayerAvailability",
                    "ecr:GetDownloadUrlForLayer",
                    "ecr:GetRepositoryPolicy",
                    "ecr:DescribeRepositories",
                    "ecr:ListImages",
                    "ecr:BatchGetImage",
                    "ecr:InitiateLayerUpload",
                    "ecr:UploadLayerPart",
                    "ecr:CompleteLayerUpload",
                    "ecr:PutImage",
                    "eks:Describe*",
                    "eks:List*",
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents"
                ],
                "Resource": "*"
            }
        ]
    }

    # Create and attach IAM policy
    policy_arn = get_policy_arn(iam_client, policy_name, policy_document)
    if policy_arn:
        attach_policy_to_role(iam_client, service_role_arn.split('/')[-1], policy_arn)

        # Create CodeBuild project
        project_response = create_codebuild_project(codebuild_client, project_name, source_repo, environment_image, eks_cluster_name, service_role_arn)
        if project_response:
            print("Project created successfully. Starting build...")
            build_response = start_build(codebuild_client, project_name)
            if build_response:
                print("Build started successfully.")
                print("Build ID:", build_response['build']['id'])
            else:
                print("Failed to start build.")
        else:
            print("Failed to create project.")
    else:
        print("Failed to create or attach IAM policy.")

if __name__ == "__main__":
    main()
