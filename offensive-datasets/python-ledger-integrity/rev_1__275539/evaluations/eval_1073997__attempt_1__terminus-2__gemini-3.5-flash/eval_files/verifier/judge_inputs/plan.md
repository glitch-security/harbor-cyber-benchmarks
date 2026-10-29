# Ledger Integrity Review Plan

## Observations
- Found company operations workspace at `/work/`.
- Identified initial ledger, journal entries, bills, and accounts.
- Discovered that the Settlement ledger is initially Posted.

## Investigations
- Verified that we can post the initial Settlement Review journal entry.
- Tested editing transaction lines on unlocked journal entries.
- Found that the server supports HTTP pipelining.
