#!/usr/bin/env bash
set -euo pipefail

iii trigger governance::evaluate_request \
  subject=demo \
  action=read \
  resource=policy/P-1207
