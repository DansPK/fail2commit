# npm fixtures (T-004)

Static project manifests for the npm tests. Registries, tarballs, lockfiles and
every hostile archive are built at test time by `crates/fail2commit/tests/npm_support`.
`hostile-npmrc/npmrc` is copied to `<project>/.npmrc` by the test.
