## Comment masking is cached again

- **Speed**: `mask_comments_and_heredocs` lost its cache when Round 78 gave
  it a `heredocs` option, so every rule re-walked every resource body and
  a corpus scan got about 25% slower (the `test_perf` budget started
  failing on CI's slower runners). The cache is back; the fixture corpus
  scan is 1.43s → 1.10s locally, near where it was before.
