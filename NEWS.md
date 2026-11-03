# ssrfr 1.0.0

First release: an SSRF guard for R code that fetches URLs an attacker can influence.

## Requirements

* `ssrfr` requires R >= 4.1.0, as `pslr`, which it needs through `rurl`, does (`SEOR-rcpzfhgx`).
* `ssrfr` requires `pslr` (>= 1.2.2), which fixes loading the public suffix list under Turkish and Azerbaijani locales (SSRF-mspjpegk).

## Guarded fetch

* `ssrf_prepare_hop()` checks one hop against the policy, resolves the name once, and returns a refusal, a failure, or a binding pinned to the validated addresses (SSRF-rgcijatt).
* The request plan is validated when the hop is prepared: a transport-owned field or a metadata-service marker raises `ssrfr_error_invalid_request`, unless `allow_ranges` names the provider endpoint (SSRF-rgcijatt).
* `ssrf_fetch()` connects only to a pinned, validated address, with `Host`, SNI and certificate checks bound to the hostname (SSRF-rgcijatt).
* `ssrf_fetch()` keeps certificate verification, ignores proxy variables, allows only `http` and `https` over HTTP/1.1, and sends each request at most once (SSRF-rgcijatt).
* A binding is single-use, and a response is read in full within the policy's limits; its `print()` never shows the body (SSRF-rgcijatt).
* Response limits count decoded bytes, interim `1xx` responses and trailer fields, so a compression bomb stops at the limit (SSRF-itqfcyrw).
* `ssrf_prepare_hop(from = binding)` prepares a redirect hop, applying the method rules of `301` to `308` and dropping the body and fields not named in `carry` across origins; `Authorization`, `Proxy-Authorization` and `Cookie` never cross (SSRF-fvtqbanc).
* A redirect refuses an `https` to `http` downgrade and any hop past `max_redirects`; `max_redirects` and `total_timeout` bind the whole chain (SSRF-fvtqbanc).
* A redirect hop's `from` must be a fetched redirect binding and its `url` that binding's `Location`, or `ssrfr_error_invalid_from` is raised (SSRF-fvtqbanc).
* `ssrf_fetch_chain()` follows a redirect chain and returns its last outcome (SSRF-bvuwvcnh).

## Inspection

* `ssrf_inspect_url()` reports what a URL is under a policy, with no network I/O (SSRF-uxmxqufj).
* A URL refuses as `"parse"` unless libcurl gets printable ASCII, so a U-label host reaches it only as its A-label (SSRF-afpkreyj).
* A host with an `xn--` label that is not a genuine A-label refuses as `"parse"`; `ssrfr` requires `rurl` >= 3.1.0 (SSRF-imtdxdym).
* A host with an empty label, such as `evil.example..`, refuses as `"parse"` before the scheme, credential and port checks, instead of passing the hostname rules (SSRF-qopriinc).
* `ssrf_inspect_url(layer = "L1")` also resolves the name and classifies every address (SSRF-ifldwmnc).

## Policy

* `ssrf_policy()` builds a guard policy, by default `http` and `https` on ports 80 and 443 to public addresses, and raises `ssrfr_error_invalid_policy` on a malformed entry (SSRF-upyqnwmv).
* A hostname rule with an empty label, or an `xn--` label that is not a genuine A-label, raises `ssrfr_error_invalid_policy` instead of matching nothing (SSRF-gtpebxfi).

## Results and vocabularies

* Refusals, failures and responses are values; misuse of the API raises a classed `ssrfr_error` (SSRF-upyqnwmv).
* `ssrf_public_reason()` gives the one value an untrusted party may see (SSRF-upyqnwmv).
* Refusals, failures and conditions never print userinfo, header values, bodies or proxy values (SSRF-upyqnwmv).
* A failure's `detail` lists each address tried and how the attempt ended (SSRF-dmmcitul).
* A body over `max_response_size` fails with the response's `status`, also recorded on the binding, and the decoded `observed_bytes` reached in `detail` (SSRF-hotiouqk).
* `ssrf_vocabulary()` lists the closed, versioned reason codes, operational causes, condition classes and default-refused metadata endpoints (SSRF-upyqnwmv).
* The bare host `metadata` refuses as `"cloud-metadata"` before resolution (SSRF-figjvukt).
