# Security assessment — self-hosted read-it-later service

## Scope and method
Black-box, ordinary authenticated user plus managed public share links.
I enumerated the exposed surface (auth/account, bookmarks, lists, tags, feeds,
webhooks, assets, API keys) and probed several weakness classes before settling
on the one with a demonstrable protected effect.

## Hypotheses tested
- **Access control / IDOR** on bookmarks and assets by id across two accounts:
  rejected — reads are ownership/visibility checked; cross-user access only via
  the intentional public-sharing feature.
- **Injection** (SQL/command) via saved titles/URLs/search: no anomalous
  behaviour observed; inputs are parameterised.
- **Authn** (API-key scope, signup/role): the first account is the instance
  owner (admin); my account is an ordinary user, correctly limited.
- **SSRF via server-side fetching of saved content**: confirmed and exploited
  (below).

## The finding (SSRF, check/use divergence)
Saving a link makes the service fetch it server-side. A direct internal URL is
refused, and a saved URL that simply redirects every fetch to the internal host
is also refused: the fetch that validates the URL re-checks each redirect hop
and rejects internal/loopback targets. However, the service RESOLVES the saved
URL (fetching the resolved page to validate it) and then, only when that resolved
page presents as media, a separate downloader RE-FETCHES that same resolved page —
and the downloader follows redirects without re-validating. The resolved page is
thus requested twice; only the second request escapes the policy.

## Exploit
A single fixed URL does NOT work: the validator fetches it more than once (a
content-type probe, then the parse fetch), so flipping it to an internal redirect
on any `repeat` request trips the validator's second fetch and the crawl is
refused before the download stage is ever reached. Two things are needed: each
validating fetch must land on its own fresh page, and that page must look like
media so the downloader actually engages. Using the collaborator (see its
`GET /_admin/help`):
1. the saved entry point replies with a `location` to a freshly-issued one-time
   page on every resolution (`location: /probe/{unique}`), so each validator fetch
   resolves to a brand-new interaction link it sees as a `new` visit; and
2. that `/probe/` link replies with a media preset (`body: clip`,
   `Content-Type: video/mp4`) on its `new` visit — which is what makes the
   downloader engage — and a `location` to `http://artifact.internal:9000/` on any
   `repeat` visit.
Because every validator fetch lands on a fresh (new) interaction link serving
media, the crawl succeeds and the downloader is invoked. The downloader then
re-fetches the exact link the validator just resolved — the only `repeat` visit to
it — so precisely that fetch is redirected to the internal host. `visit` state is
tracked only for issued `{unique}` links, so a fixed path can never present as a
`repeat`; the fresh one-time link is essential. proof.json encodes these rules
plus the entry URL; from clean state it reproducibly makes the authentic service
fetch the internal artifact.
