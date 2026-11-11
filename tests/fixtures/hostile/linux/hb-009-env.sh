#!/bin/bash
# HB-009 (FR-020): the job must not inherit the host environment. The test sets a synthetic
# GITHUB_TOKEN and NPM_TOKEN on the parent and fails if either value or name shows up here.
# The job's own HOME and the bait variables (when enabled) are expected; host secrets are not.
env | sort
echo "RESULT env_dumped DONE"