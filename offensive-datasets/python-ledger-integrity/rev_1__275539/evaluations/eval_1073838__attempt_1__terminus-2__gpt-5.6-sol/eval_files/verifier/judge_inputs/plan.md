# Hosted ledger integrity review

## Observed
- `/work/` exposes fresh company, ledger, journal-detail, and journal posting paths after operator login.
- The seeded journal is unposted, locked, balanced for $17 debit/$17 credit, and belongs to the posted Settlement ledger.
- A successful posting is confirmed by the detail page replacing `mark-as-posted` with `mark-as-unposted`; transaction amounts remain in official detail.

## Negative tests
- HTTP/1.0 without Host returned 400 and did not post.
- A pipelined request after `Connection: close` was discarded.
- Bare-LF and incomplete-body requests did not post.
- Individual and bulk posting both refused while the ledger was unposted.
- Individual and bulk posting both refused while the journal was unlocked.

## Confirmed proof
An authenticated HTTP/1.1 GET of the posting action with `Connection: close` returned 302 and caused the official journal detail to report the balanced entry as posted. This violates the published request-integrity rule requiring a book-changing action to be dispatched on a connection that remains eligible for service. `proof.json` dynamically obtains CSRF, session cookie, posting path, and detail path.
