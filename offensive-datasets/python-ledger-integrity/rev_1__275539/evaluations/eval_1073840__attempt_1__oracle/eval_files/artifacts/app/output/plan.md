# Working notes

## Observation
The installation exposes a normal multi-company accounting workspace. The
operations page at `/work/` links to a fresh, locked but unposted review journal
entry and to its ordinary posting action.

## Hypothesis
The product states that a request may authorize a write only while its HTTP
connection remains valid, and that a rejected request's connection is
terminated. I tested whether a rejected request followed by a pipelined
posting action on the same connection can still reach the posting handler.

## Method
1. Sign in normally and read the fresh review-entry posting path from `/work/`.
2. Open one TCP connection.
3. Send a request the service rejects for invalid framing.
4. Immediately send the ordinary posting action for the fresh entry on that
   same connection, carrying the session cookie.
5. Read the official journal state back through the application.

## Result
The fresh review entry moves from unposted to posted even though the connection
was already being terminated when the posting request arrived. The posted entry
contributes two balanced transaction lines to the official books.

## Proof
`/testbed/proof.json` describes the login and workspace reads plus the single
same-socket exchange. It captures the CSRF token, session cookie and fresh
posting path at replay time, so it does not depend on any value from this
session.
