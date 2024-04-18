provider "aws" {
  region = "ap-south-1"  # Adjust this to your AWS region
}

# Create an IAM policy for CodeBuild access to EKS and other resources
resource "aws_iam_policy" "codebuild_eks_access" {
  name        = "CodeBuildEKSAccessPolicyTwo"
  path        = "/"
  description = "Policy allowing CodeBuild to interact with EKS and other AWS services."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
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
        Resource = "*"
      }
    ]
  })
}

# Create an IAM role for AWS CodeBuild
resource "aws_iam_role" "codebuild_role" {
  name = "CodeBuildServiceRoleTwo"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "codebuild.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

# Attach the policy to the IAM role
resource "aws_iam_role_policy_attachment" "codebuild_policy_attach" {
  role       = aws_iam_role.codebuild_role.name
  policy_arn = aws_iam_policy.codebuild_eks_access.arn
}

# Create an AWS CodeBuild project
resource "aws_codebuild_project" "example" {
  name          = "WebAppBuildTwo"
  description   = "CodeBuild project for EKS"
  build_timeout = 60
  service_role  = aws_iam_role.codebuild_role.arn

  artifacts {
    type = "NO_ARTIFACTS"
  }

  environment {
    compute_type                = "BUILD_GENERAL1_SMALL"
    image                       = "aws/codebuild/standard:4.0"
    type                        = "LINUX_CONTAINER"
    environment_variable {
      name  = "EKS_CLUSTER_NAME"
      value = "kube32neweks"
    }
  }

  source {
    type     = "GITHUB"
    location = "https://github.com/prateekvs/Webapps.git"
  }

  tags = {
    Environment = "test"
  }
}
