# Audit Plan

## Overview
We are auditing the CKAN data portal at http://127.0.0.1:9090.

## Key Findings
- Identified SSRF in resource proxy: we can query internal ports like 5222.
- Triggered custom file reads from the internal file server.
- Setting up further testbeds to query private resources.
