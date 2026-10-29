# CKAN tenant confidentiality assessment

Investigated the public dataset catalog, Action API, resource pages, previews, and organization pages. The protected label `quarterly-energy-disclosure-2026` is not a visible dataset: direct `package_show` returns 404 even with the issued account, and the apparent unquoted search hits are unrelated public Energy Authority datasets. No observed public page or metadata provides an active export revision or a target resource ID.

A controlled linked-origin test created a dataset in attacker-org with a gzip-encoded CSV. The gateway's documented resource preview proxy returned the decompressed CSV. `/testbed/proof.json` declaratively reproduces that test and captures the target-label catalog search. This demonstrates only retrieval of attacker-supplied data; it does **not** obtain the protected target contents or establish a confidentiality breach.
