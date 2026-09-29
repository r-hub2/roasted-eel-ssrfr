# Closed domains (ssrfr-v1.md §6.1): reason codes (§6.5), operational causes
# (§6.6), misuse condition classes (§6.6), and the policy-data tables of
# R/policy-data.R: the provider endpoints (§5 gate 2), the metadata hostnames
# (§5 gate 5) and the metadata-service request headers (§2.3). Each is a data
# frame whose first column is the key, stamped with a version.
# tests/testthat/test-vocabulary.R pins every version to its key set in both
# directions, so changing a domain's keys means bumping its version here and
# pinning the new set there.
#
# To add a domain: write a `domain_<name>()` builder that returns
# closed_domain(), add it to closed_domains(), and add its pin history to
# test-vocabulary.R.

# Stamps a data frame as a closed domain. The first column is the key: a
# character vector with no missing or repeated value.
closed_domain <- function(name, version, entries) {
  key <- entries[[1L]]
  stopifnot(
    is.character(name),
    length(name) == 1L,
    is.numeric(version),
    length(version) == 1L,
    version >= 1,
    version == trunc(version),
    is.data.frame(entries),
    is.character(key),
    !anyNA(key),
    anyDuplicated(key) == 0L
  )
  rownames(entries) <- NULL
  attr(entries, "domain") <- name
  attr(entries, "version") <- as.integer(version)
  entries
}

domain_reason_codes <- function() {
  closed_domain(
    "reason_codes",
    1L,
    data.frame(
      code = c(
        "loopback",
        "private",
        "link-local",
        "cloud-metadata",
        "shared",
        "unspecified",
        "this-network",
        "ipv4-mapped",
        "ipv4-translated",
        "ipv4-compatible",
        "nat64",
        "6to4",
        "teredo",
        "isatap",
        "malformed-address",
        "numeric-literal",
        "scheme",
        "downgrade",
        "userinfo",
        "port",
        "host-denied",
        "range-denied",
        "parse",
        "multicast",
        "redirect-limit",
        "reserved"
      ),
      meaning = c(
        "loopback address",
        "private or internal address space",
        "link-local address",
        "a known provider endpoint, by address or by hostname",
        "shared address space (RFC 6598, CGNAT)",
        "the unspecified address",
        "0.0.0.0/8 other than the unspecified address",
        "IPv4-mapped IPv6 with a prohibited embedded address",
        "IPv4-translated IPv6 with a prohibited embedded address",
        "deprecated IPv4-compatible IPv6 with a prohibited embedded address",
        "NAT64 address with a prohibited embedded address",
        "6to4 address",
        "Teredo address",
        "ISATAP address with a prohibited embedded address",
        "an address that could not be decoded or classified",
        "ambiguous numeric host encoding",
        "scheme not permitted",
        "redirect from a secure to an insecure scheme",
        "embedded credentials in the URL",
        "port not permitted",
        "matched a caller deny_hosts rule",
        "matched a caller deny_ranges rule",
        "syntax failure, or the two parsers disagree on the host",
        "multicast address",
        "a redirect arrived after the redirect budget was spent",
        "reserved or other special-purpose address space"
      )
    )
  )
}

domain_causes <- function() {
  closed_domain(
    "causes",
    1L,
    data.frame(
      cause = c(
        "unresolvable",
        "pin-mismatch",
        "connect-failed",
        "tls-failed",
        "timeout",
        "response-too-large",
        "protocol-error"
      ),
      meaning = c(
        "resolution failed, or returned no address or an unparseable one",
        "the observed peer is not the pinned address, or evidence is absent",
        "no validated address accepted a connection",
        "certificate or hostname verification failed",
        "a connect or total deadline elapsed",
        "a size or count limit was reached",
        "a malformed, truncated or undecodable response"
      )
    )
  )
}

domain_condition_classes <- function() {
  kind <- c(
    "invalid_policy",
    "invalid_request",
    "invalid_from",
    "spent_binding",
    "budget_change",
    "invalid_argument"
  )
  closed_domain(
    "condition_classes",
    1L,
    data.frame(
      class = paste0("ssrfr_error_", kind),
      kind = kind,
      raised_when = c(
        "building a policy fails its construction checks",
        "a request plan breaks the header or body rules",
        "`from` is unspent, failed, or not a followed redirect",
        "ssrf_fetch() receives a binding whose fetchability is spent",
        "a redirect-hop policy changes max_redirects or total_timeout",
        "any other argument of the wrong type or shape"
      )
    )
  )
}

# Every closed domain, by name.
closed_domains <- function() {
  list(
    reason_codes = domain_reason_codes(),
    causes = domain_causes(),
    condition_classes = domain_condition_classes(),
    provider_endpoints = domain_provider_endpoints(),
    metadata_hostnames = domain_metadata_hostnames(),
    metadata_headers = domain_metadata_headers()
  )
}

# The keys of one closed domain.
domain_keys <- function(name) {
  closed_domains()[[name]][[1L]]
}

#' List a closed vocabulary
#'
#' Enumerates one of the closed vocabularies `ssrfr` publishes: the reason
#' codes a refusal carries, the causes an operational failure carries, the
#' classes of the misuse conditions it raises, and the three tables of policy
#' data it owns: the provider endpoints refused by address and the metadata
#' hostnames refused by name, each row citing the vendor documentation that
#' names it, and the metadata-service request headers a request plan may not
#' carry. Each vocabulary is API, carries a version stamp, and changes only
#' with a new version.
#'
#' @param domain The vocabulary to list: `"reason_codes"`, `"causes"`,
#'   `"condition_classes"`, `"provider_endpoints"`, `"metadata_hostnames"` or
#'   `"metadata_headers"`. `NULL`, the default, lists the vocabularies
#'   themselves.
#'
#' @return A data frame. For a named `domain`, one row per entry, keyed by the
#'   first column (`code`, `cause`, `class`, `address`, `hostname` or
#'   `header`), with the
#'   attributes `domain`, `version` (the vocabulary's version stamp) and
#'   `package_version`. For `NULL`, one row per vocabulary with its `domain`,
#'   `version` and `size`, and the `package_version` attribute.
#'
#' @examples
#' ssrf_vocabulary()
#' ssrf_vocabulary("reason_codes")$code
#' attr(ssrf_vocabulary("causes"), "version")
#' ssrf_vocabulary("metadata_hostnames")$hostname
#'
#' @export
ssrf_vocabulary <- function(domain = NULL) {
  domains <- closed_domains()
  if (is.null(domain)) {
    out <- data.frame(
      domain = names(domains),
      version = vapply(domains, attr, integer(1), which = "version"),
      size = vapply(domains, nrow, integer(1))
    )
    rownames(out) <- NULL
  } else {
    if (
      !is.character(domain) ||
        length(domain) != 1L ||
        is.na(domain) ||
        !domain %in% names(domains)
    ) {
      abort_ssrfr(
        "invalid_argument",
        paste0(
          "`domain` must be one of ",
          paste0("\"", names(domains), "\"", collapse = ", "),
          ", or NULL."
        ),
        fn = "ssrf_vocabulary"
      )
    }
    out <- domains[[domain]]
  }
  attr(out, "package_version") <- as.character(utils::packageVersion("ssrfr"))
  out
}
