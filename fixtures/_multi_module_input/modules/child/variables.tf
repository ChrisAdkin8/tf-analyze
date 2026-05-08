variable "encrypted" {
  type    = bool
  default = true   # Default would mask the violation; parent's override unmasks it.
}
