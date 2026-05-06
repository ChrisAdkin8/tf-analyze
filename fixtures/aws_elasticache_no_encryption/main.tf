resource "aws_elasticache_replication_group" "app" {
  replication_group_id = "app"
  description          = "App cache"
  node_type            = "cache.t3.micro"
  num_cache_clusters   = 1
  # missing at_rest_encryption_enabled = true
  # missing transit_encryption_enabled = true
}
