# Dirty fixture for ROB-COUNTNAME-001.
# Three resources where the external name interpolates count.index.
# Decrementing count from 3→2 here destroys "web-2" / the third
# bucket / the third user in real infrastructure.

resource "aws_instance" "web" {
  count         = 3
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"
  tags = {
    Name = "web-${count.index}"
  }
}

resource "aws_s3_bucket" "data" {
  count  = 2
  bucket = "myapp-data-${count.index}"
}

resource "aws_iam_user" "service" {
  count = 4
  name  = "svc-${count.index}"
}
