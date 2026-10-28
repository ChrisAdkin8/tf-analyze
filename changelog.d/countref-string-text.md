## Count rules read references, not text that names a resource

- **`ROB-COUNTREF-001` / `ROB-COUNTREF-002`**: a resource named in plain
  string text, such as `description = "see aws_instance.a[0].id"`, was read
  as an unguarded reference. String text is now blanked before the search;
  `${...}` interpolations, in strings and heredocs, still count.
- **Text fallback**: when a file can't be parsed, an argument whose value
  opens a bracket partway along the line and closes it on a later one
  (`bucket = format(\n  "x-%d",\n  count.index)`) was read as its first line
  only. The value now runs on to the closing bracket, so
  `ROB-COUNTNAME-001` sees `count.index` there as it does on the parse tree.
