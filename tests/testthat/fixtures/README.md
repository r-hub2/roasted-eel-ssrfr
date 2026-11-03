# Conformance corpus

The three corpus files of `design/specs/ssrfr-v1.md` §7. That section is
normative for what each component contains and §7.2 for what counts as a pass;
this file describes only the file format.

| File | §7 component | Rows written by |
|---|---|---|
| `verdict-vectors.tsv` | 1, verdict vectors | hand, derived from the spec |
| `parse-vectors.tsv` | 2, parse vectors | hand for the first six columns; the rest by `design/evidence/2026-09-25-parse-vectors.R` |
| `requirements.tsv` | 3, requirement coverage | hand |
| `corpus-manifest.tsv` | §7.2 row count and MD5 of each file | `scripts/corpus-manifest.R` |

`tests/testthat/test-corpus.R` checks each file against the manifest before
it reads a row. After editing a corpus file, run
`Rscript scripts/corpus-manifest.R` and commit both. After a `rurl`, `curl` or
libcurl update, run the parse-vector script, which also rewrites the manifest.

Rows are never deleted (§7.2). A row whose expectation no longer holds gets
`superseded:<reason>` in `status` and stays. New rows take the next free id.

## Format

UTF-8, tab-separated, one header row, LF line endings, no quoting. A field
never holds a raw TAB, LF or CR.

`input`, and the measured columns of `parse-vectors.tsv`, use these escapes and
no others: `\\` for a backslash, `\t`, `\n`, `\r`, `\0` for NUL, and `\u{XXXX}`
for any other control, format or invisible code point (U+00AD, U+200B–U+200F,
U+FEFF and the like). Printable non-ASCII characters are written as themselves.
Percent-escapes such as `%0d` are URL text, not escapes of this format. So
`http:\\\\evil.example/` is the URL `http:\\evil.example/`.

`status` is `active`; `pending:<issue>` when the spec's expectation cannot hold
with today's dependencies (the row names the upstream issue); or
`superseded:<reason>`.

`source` is public provenance: a CVE or GHSA id, an RFC section, an advisory,
paper or project URL, an upstream file, a committed evidence script, or the
spec section that mandates the row. Several are joined with ` ; `.

## `verdict-vectors.tsv`

| Column | Content |
|---|---|
| `id` | `V` and four digits |
| `group` | the bypass class |
| `input` | the URL the guard receives, escaped |
| `answers` | the mocked resolver answer, comma-separated addresses; `-` when nothing is resolved (an address literal, or a refusal before §12 step 7); `empty`; `error`; or `unparseable:<text>` |
| `policy` | `default`, or `;`-separated overrides of §5.3 fields, with `\|` between the values of one field: `deny_hosts=.corp\|evil.example;allow_ranges=10.0.0.0/8` |
| `hop` | `first`, or `redirect:<URL of the previous hop>` |
| `verdict` | `refuse` (a §6.5 reason code), `fail` (a §6.6 operational cause) or `admit` |
| `code` | the reason code or cause; `-` for `admit` |
| `layer` | the guard layer (§1) that must decide the row, at that layer or earlier (§7). For `admit`, the layer after which nothing refuses it |
| `status`, `source` | above |
| `note` | what the row tests |

## `parse-vectors.tsv`

Hand-written: `id` (`P` and four digits), `input`, `expect` (the spec's
outcome at §12 steps 1–3 under the default policy: `parse`, `scheme` or
`agree`), `status`, `source`, `note`.

Measured, never hand-edited:

| Column | Content |
|---|---|
| `rurl_l1`, `rurl_l2` | `rurl`'s layer-1 and layer-2 verdicts, under `ssrfr`'s fixed bundle (`r-binding.md` §2.1) |
| `rurl_numeric` | `rurl`'s numeric-literal shape diagnostics for the host, or `-` |
| `rurl_scheme`, `rurl_userinfo`, `rurl_host`, `rurl_port` | `rurl`'s parse, host in A-label form; userinfo as `user:password`, `-` for an absent part |
| `wire` | `rurl`'s WHATWG serialization: the string libcurl is handed |
| `curl_scheme`, `curl_userinfo`, `curl_host`, `curl_port` | `curl_parse_url()` of `wire` |
| `raw_curl_host` | `curl_parse_url()` of the unmodified input: what a caller that skipped `rurl` would dial |
| `host_agree` | whether `rurl_host` and `curl_host` are one value: addresses compared as `raddr` values, names as lowercase strings (§4.1) |
| `measured` | the outcome those columns give: `parse`, `scheme` or `agree` |
| `dial` | the address and port in libcurl's `Trying` line, measured only for an `http` or `https` URL whose host is a loopback or unspecified literal; `-` otherwise |

`error` in a measured column means the call raised an error.

## `requirements.tsv`

| Column | Content |
|---|---|
| `id` | `REQ-` and three digits |
| `framework` | `OWASP-CS`, `ASVS-5.0`, `CWE-918`, `CAPEC-664`, `WSTG`, `RFC` or `other` |
| `external_id` | the framework's own id or item |
| `requirement` | the requirement, paraphrased |
| `class` | `enforced-by-library`, `enforced-by-application` or `out-of-scope` (§7 component 3) |
| `spec` | the section that decides it |
| `evidence` | what demonstrates it: `verdict:<group>`, `parse-vectors`, an `r-binding.md` §7 behavior row, or a test as `test-<file>.R: <test_that name>`, several joined by ` ; `; `-` if nothing in `ssrfr` does |
| `source` | the requirement's published text |
| `note` | why the class differs from the first mapping (`reclassified:`), a content correction (`corrected:`), or a gap |
