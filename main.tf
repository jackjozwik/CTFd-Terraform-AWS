terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

#CREDENTIALS (access keys, db username/password, ect...)
#REPLACE - DO NOT HARDCODE
provider "aws" {
  region     = var.region
  access_key = var.access_key
  secret_key = var.secret_key
}

locals {
  env_variables = {
    "DATABASE_URL" = "mysql+pymysql://${aws_ssm_parameter.db_username.value}:${aws_ssm_parameter.db_password.value}@${aws_db_instance.mysql_instance.endpoint}/ctfd"
    # "REDIS_URL"             = "redis://${aws_elasticache_cluster.redis_cache.cache_nodes[0].address}:6379"
    "UPLOAD_PROVIDER"       = "s3"
    "AWS_ACCESS_KEY_ID"     = var.access_key
    "AWS_SECRET_ACCESS_KEY" = var.secret_key
    "AWS_S3_BUCKET"         = "${aws_s3_bucket.s3_bucket_ctfd_uploads.id}"
    "AWS_S3_ENDPOINT_URL"   = "https://${aws_s3_bucket.s3_bucket_ctfd_uploads.bucket_regional_domain_name}"
    # "REVERSE_PROXY" = "2,1,0,0,0" # for cloudflare proxy and app engine NEG load balancer
  }
}

resource "random_password" "password" {
  length  = 16
  special = false
}

resource "random_string" "secret_key" {
  length  = 32
  special = false
}

resource "aws_ssm_parameter" "db_username" {
  name  = "/ctfd/database/username"
  type  = "SecureString"
  value = "admin"
}

resource "aws_ssm_parameter" "db_password" {
  name  = "/ctfd/database/password"
  type  = "SecureString"
  value = random_password.password.result
}



#NETWORKING
#VPC and Subnets
resource "aws_vpc" "private_network" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    Name = "ctfd-vpc"
  }
}

resource "aws_subnet" "public_subnet_a" {
  vpc_id                  = aws_vpc.private_network.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = true
  tags = {
    Name = "public_ctfd-subnet_a"
  }
}

resource "aws_subnet" "public_subnet_b" {
  vpc_id                  = aws_vpc.private_network.id
  cidr_block              = "10.0.4.0/24"
  availability_zone       = "us-east-1b"
  map_public_ip_on_launch = true
  tags = {
    Name = "public_ctfd-subnet_b"
  }
}

resource "aws_subnet" "private_subnet_a" {
  vpc_id            = aws_vpc.private_network.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "us-east-1a"
  tags = {
    Name = "private_ctfd-subnet_a"
  }
}

resource "aws_subnet" "private_subnet_b" {
  vpc_id            = aws_vpc.private_network.id
  cidr_block        = "10.0.3.0/24"
  availability_zone = "us-east-1b"
  tags = {
    Name = "private_ctfd-subnet_b"
  }
}


#Internet Gateway, NAT Gateway, Route Tables, Routes, and Associations
resource "aws_internet_gateway" "internet_gateway" {
  vpc_id = aws_vpc.private_network.id
  tags = {
    Name = "ctfd-internet-gateway"
  }
}

resource "aws_eip" "nat_eip_a" {
  domain = "vpc"

  tags = {
    Name = "nat-eip"
  }
}

resource "aws_eip" "nat_eip_b" {
  domain = "vpc"

  tags = {
    Name = "nat-eip"
  }
}

resource "aws_nat_gateway" "nat_gateway_a" {
  subnet_id     = aws_subnet.public_subnet_a.id
  allocation_id = aws_eip.nat_eip_a.id
}

resource "aws_nat_gateway" "nat_gateway_b" {
  subnet_id     = aws_subnet.public_subnet_b.id
  allocation_id = aws_eip.nat_eip_b.id
}


resource "aws_route_table" "public_route_table" {
  vpc_id = aws_vpc.private_network.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.internet_gateway.id
  }

  tags = {
    Name = "public-route-table"
  }
}

resource "aws_route_table" "private_route_table_a" {
  vpc_id = aws_vpc.private_network.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat_gateway_a.id
  }

  tags = {
    Name = "private-route-table"
  }
}


resource "aws_route_table" "private_route_table_b" {
  vpc_id = aws_vpc.private_network.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat_gateway_b.id
  }

  tags = {
    Name = "private-route-table"
  }
}


resource "aws_route_table_association" "public_route_table_assoc_a" {
  subnet_id      = aws_subnet.public_subnet_a.id
  route_table_id = aws_route_table.public_route_table.id
}

resource "aws_route_table_association" "public_route_table_assoc_b" {
  subnet_id      = aws_subnet.public_subnet_b.id
  route_table_id = aws_route_table.public_route_table.id
}

resource "aws_route_table_association" "private_route_table_assoc_a" {
  subnet_id      = aws_subnet.private_subnet_a.id
  route_table_id = aws_route_table.private_route_table_a.id
}

resource "aws_route_table_association" "private_route_table_assoc_b" {
  subnet_id      = aws_subnet.private_subnet_b.id
  route_table_id = aws_route_table.private_route_table_b.id
}



#Security Groups
resource "aws_security_group" "main_security_group" {
  name_prefix = "main_security_group-"
  vpc_id      = aws_vpc.private_network.id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = "main_security_group"
  }
}

resource "aws_security_group" "ToRDSFromECS" {
  name_prefix = "ToRDSFromECS-"
  description = "Allow MySQL traffic from ECS instances"
  vpc_id      = aws_vpc.private_network.id

  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = [aws_subnet.private_subnet_a.cidr_block, aws_subnet.private_subnet_b.cidr_block]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "ToRDSFromECS"
  }
}

resource "aws_security_group" "ToRedisFromECS" {
  name_prefix = "ToRedisFromECS-"
  description = "Allow MySQL traffic from ECS instances"
  vpc_id      = aws_vpc.private_network.id

  ingress {
    from_port   = 6379
    to_port     = 6379
    protocol    = "tcp"
    cidr_blocks = [aws_subnet.private_subnet_a.cidr_block, aws_subnet.private_subnet_b.cidr_block]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "ToRedisFromECS"
  }
}

resource "aws_security_group" "ToApplicationLoadBalancerFromAnywhere" {
  name_prefix = "ToApplicationLoadBalancerFromAnywhere-"
  description = "Allow inbound traffic on port 80"
  vpc_id      = aws_vpc.private_network.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port        = 80
    to_port          = 80
    protocol         = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "ToApplicationLoadBalancerFromAnywhere"
  }
}

resource "aws_security_group" "ToContainerFromApplicationLoadBalancer" {
  name_prefix = "ToContainerFromALB-"
  description = "Allow all inbound TCP traffic from ALB security group"
  vpc_id      = aws_vpc.private_network.id

  ingress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    security_groups = [aws_security_group.ToApplicationLoadBalancerFromAnywhere.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "ToContainerFromApplicationLoadBalancer"
  }
}

resource "aws_security_group" "ToContainerFromPrivate" {
  name        = "ToContainerFromPrivate"
  description = "Allow inbound traffic from 10.0.0.0/16 on all ports for MySQL and Redis"
  vpc_id      = aws_vpc.private_network.id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [aws_subnet.private_subnet_a.cidr_block, aws_subnet.private_subnet_b.cidr_block]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "ToContainerFromPrivate"
  }
}


#SERVICES
#Database, Redis, ECS, ECR, ELB, ect...
resource "random_id" "db_name_suffix" {
  byte_length = 2
}

resource "aws_db_subnet_group" "subnetgroupdb" {
  name       = "ctfd-database-subnet-group"
  subnet_ids = [aws_subnet.private_subnet_a.id, aws_subnet.private_subnet_b.id]
  tags = {
    Name = "ctfd-database-subnet-group"
  }
}

resource "aws_db_instance" "mysql_instance" {
  identifier_prefix = "mysql-database-${random_id.db_name_suffix.hex}"
  engine            = "mysql"
  engine_version    = "8.0.28"
  instance_class    = "db.t2.micro"
  allocated_storage = 20

  username = aws_ssm_parameter.db_username.value
  password = aws_ssm_parameter.db_password.value

  # CONFIGURE SECURITY GROUPS AND "PUBLICLY ACCESSIBLE" (for testing purposes only)
  skip_final_snapshot    = true
  vpc_security_group_ids = [aws_security_group.ToRDSFromECS.id]
  publicly_accessible    = false
  multi_az               = false
  db_subnet_group_name   = aws_db_subnet_group.subnetgroupdb.name
}

resource "aws_elasticache_subnet_group" "subnetgroupcache" {
  name       = "subnetcache"
  subnet_ids = [aws_subnet.private_subnet_a.id, aws_subnet.private_subnet_b.id]
}

#CHANGE TO MATCH VPC REGION AND AZs!!
#Redis
# resource "aws_elasticache_cluster" "redis_cache" {
#   cluster_id           = "ctfd-redis-cache"
#   engine               = "redis"
#   node_type            = "cache.t2.micro"
#   num_cache_nodes      = 1
#   parameter_group_name = "default.redis4.0"
#   engine_version       = "4.0.10"
#   port                 = 6379
#   security_group_ids   = [aws_security_group.aws_security_group.main_security_group.id]

#   subnet_group_name = aws_elasticache_subnet_group.subnetgroupcache.name
# }

resource "aws_elasticache_parameter_group" "default" {
  name   = "cache-params"
  family = "redis7"
}

resource "aws_elasticache_replication_group" "redis_cache_group" {
  replication_group_id       = "ctfd-cache-cluster"
  description                = "Cache replication group for CTFd"
  node_type                  = "cache.t2.micro"
  port                       = 6379
  parameter_group_name       = aws_elasticache_parameter_group.default.name
  subnet_group_name          = aws_elasticache_subnet_group.subnetgroupcache.name
  automatic_failover_enabled = true
  security_group_ids         = [aws_security_group.main_security_group.id]
  num_cache_clusters         = 2
}

#ECR
resource "aws_ecr_repository" "ctfd-ecr-repo" {
  name = "ctfd-ecr-repo"
  tags = {
    Name        = "ctfd-ecr-repo"
    Environment = "Dev"
  }
}



# S3 Bucket and Config
resource "aws_s3_bucket" "s3_bucket_ctfd_uploads" {
  bucket = "s3-bucket-ctfd-uploads"

  tags = {
    Name        = "s3_bucket_ctfd_uploads"
    Environment = "Dev"
  }
}

resource "aws_s3_bucket_ownership_controls" "bucket_ownership" {
  bucket = aws_s3_bucket.s3_bucket_ctfd_uploads.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_public_access_block" "bucket_access" {
  bucket = aws_s3_bucket.s3_bucket_ctfd_uploads.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_acl" "bucket_acl" {
  depends_on = [
    aws_s3_bucket_ownership_controls.bucket_ownership,
    aws_s3_bucket_public_access_block.bucket_access,
  ]

  bucket = aws_s3_bucket.s3_bucket_ctfd_uploads.id
  acl    = "public-read"
}



#ELB
resource "aws_lb" "alb" {
  name               = "ctfd-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.ToApplicationLoadBalancerFromAnywhere.id]
  subnets            = [aws_subnet.public_subnet_a.id, aws_subnet.public_subnet_b.id]

  enable_deletion_protection = false

  tags = {
    Name = "ctfd-alb"
  }
}

# ALB Listener
resource "aws_lb_listener" "alb_listener" {
  load_balancer_arn = aws_lb.alb.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.target_group.arn
  }
}

# Target Group
resource "aws_lb_target_group" "target_group" {
  name        = "ctfd-target-group"
  port        = 80
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = aws_vpc.private_network.id

  health_check {
    healthy_threshold   = 2
    unhealthy_threshold = 5
    matcher             = "200,302,304"
    timeout             = 15
  }
}



#ECS
resource "aws_ecs_cluster" "ecs_cluster" {
  name = "ctfd-ecs-cluster"
}

resource "aws_ecs_task_definition" "ecs_task" {
  family                   = "ctfd-ecs-task"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "2048"                                                # 1 vCPU
  memory                   = "4096"                                                # 2GB RAM
  execution_role_arn       = "arn:aws:iam::837592798451:role/ecsTaskExecutionRole" #default

  container_definitions = jsonencode([{
    name      = "ctfd"
    image     = "837592798451.dkr.ecr.us-east-1.amazonaws.com/ctfd-ecr-repo:latest"
    essential = true

    runtime_platform = {
      operating_system_family = "LINUX"
      cpu_architecture        = "X86_64"
    }

    portMappings = [{
      containerPort = 8000
      hostPort      = 8000
    }]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = "/ecs/ctfd-ecs-task"
        "awslogs-region"        = "us-east-1"
        "awslogs-stream-prefix" = "ecs"
        "awslogs-create-group"  = "true"
      }
    }

    environment = [
      {
        name  = "SECRET_KEY",
        value = random_string.secret_key.result
      },
      {
        name  = "DATABASE_URL",
        value = "mysql+pymysql://${aws_ssm_parameter.db_username.value}:${aws_ssm_parameter.db_password.value}@${aws_db_instance.mysql_instance.endpoint}/ctfd"
      },
      {
        name  = "REDIS_URL",
        value = "redis://${aws_elasticache_replication_group.redis_cache_group.primary_endpoint_address}:6379"
      }
    ]


  }])
}

# ECS Service
resource "aws_ecs_service" "ecs_service" {
  name            = "ctfd-ecs-service"
  cluster         = aws_ecs_cluster.ecs_cluster.id
  task_definition = aws_ecs_task_definition.ecs_task.arn
  launch_type     = "FARGATE"
  desired_count   = 3 #UPDATE TO SCALE - can also select auto-scale 

  network_configuration {
    subnets         = [aws_subnet.private_subnet_a.id, aws_subnet.private_subnet_b.id]
    security_groups = [aws_security_group.ToContainerFromApplicationLoadBalancer.id, aws_security_group.ToContainerFromPrivate.id] # DATABASE CONNECTION ISSUE HERE
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.target_group.arn
    container_name   = "ctfd"
    container_port   = 8000
  }
}