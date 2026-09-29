# Inspection (ssrfr-v1.md §1, §1.1, §1.2): the facts a URL carries under a
# policy. Inspection reports; it is not a gate and not a defense, and only
# L2's guarded fetch is one (S2).
#
# L0, structural, does no I/O. It runs steps 1-6 of the request lifecycle
# (§12) and, for an address-literal host, gates 1-3 (§5), which need no
# resolution. L1, resolved, adds steps 7 and 8 for a name: resolve_hop()
# (R/resolve.R) resolves it once and classifies every answer.
#
# The internal steps are separate so later layers reuse them without parsing
# again: parse_hop() (R/parse.R) for steps 1-5, host_policy() for step 6,
# address_gates() (R/address.R) for gates 1-3 on one address, and
# resolve_hop() for steps 7 and 8.

inspection_layers <- c("L0", "L1")

# Steps 1-6, gates 1-3 for an address literal and, when `resolve` is TRUE,
# steps 7 and 8 for a name. Returns parse_hop()'s list with `finding` set by
# the first step that refuses or fails, `address_facts` for an address
# literal that reached the address gates, and `resolution`, resolve_hop()'s
# list, for a name that was resolved.
inspect_hop <- function(url, policy, base = NULL, resolve = FALSE) {
  hop <- parse_hop(url, policy, base)
  if (is.null(hop$finding)) {
    hop$finding <- host_policy(hop, policy)
  }
  if (is.null(hop$finding) && hop$host_kind %in% c("ipv4", "ipv6")) {
    gates <- address_gates(hop$address, policy)
    hop$finding <- gates$finding
    hop$address_facts <- gates$facts
    if (!is.null(hop$finding)) {
      hop$finding$host <- hop$host
    }
  }
  if (resolve && is.null(hop$finding) && identical(hop$host_kind, "name")) {
    hop$resolution <- resolve_hop(hop, policy)
    hop$finding <- hop$resolution$finding
  }
  hop
}

#' Inspect a URL without fetching it
#'
#' Reports what a URL is under a policy, without fetching it: whether it
#' parses without ambiguity, what scheme, host and port the transport would
#' act on, how an address host is classified and, at layer `"L1"`, every
#' address a name resolves to and how each is classified. Inspection is a
#' pre-filter and a way to lint a configuration, **not a defense**: what a
#' name resolves to can change the moment this returns, so a URL it finds
#' nothing wrong with may still be refused when fetched. Only the guarded
#' fetch protects a request.
#'
#' The URL is parsed as the guarded fetch parses it: `rurl` under the WHATWG
#' URL Standard, then libcurl's own parser on the string libcurl would be
#' handed. A URL the two parsers read differently is reported as `"parse"`.
#' Checks run in the order of a guarded hop, and the first one that applies
#' names the reason code: the length limit and the parse, the scheme, embedded
#' credentials, the port, an ambiguous numeric host spelling, the hostname
#' rules, and the address rules. A relative reference, such as a redirect's
#' `Location`, is resolved against `base` first.
#'
#' Layer `"L0"`, the default, is structural and does no network I/O: it
#' resolves no name, so for a name it reports no address. Layer `"L1"` also
#' asks the system resolver, once, for every address of a name that passed
#' the earlier checks, and classifies each one with its embedded addresses.
#' The name is looked up as absolute, with a trailing root dot, so no DNS
#' search domain is appended: `http://intranet/` is never looked up as
#' `intranet.corp.example`. One refused address refuses the whole set. A
#' resolver error, an empty answer or an answer that is not an address is
#' the operational cause `"unresolvable"`. An address host, or a URL an
#' earlier check refuses, is never resolved.
#'
#' @param url The URL, a single string.
#' @param policy The policy to inspect it under, from [ssrf_policy()].
#' @param base The URL of the previous hop, a single string, when `url` came
#'   from a redirect: `url` may then be a relative reference, and an `https`
#'   `base` makes an `http` `url` a `"downgrade"`. `NULL`, the default, for a
#'   first hop, which must be an absolute URL.
#' @param layer `"L0"` (the default) for structural inspection with no
#'   network I/O, or `"L1"` to also resolve a name and classify every
#'   address it resolves to.
#'
#' @return An object of class `ssrfr_inspection`, a list of facts:
#'   \describe{
#'     \item{`code`}{The reason code (see `ssrf_vocabulary("reason_codes")`)
#'       that the first applicable check reports, or `NA`. It is derived
#'       from the facts below, not a verdict: `NA` is not an approval. At
#'       L0 a name is still to be resolved; at L1 the addresses may differ
#'       by the time a fetch resolves the name again.}
#'     \item{`cause`}{The operational cause (see
#'       `ssrf_vocabulary("causes")`), `"unresolvable"`, when resolution
#'       failed at L1, or `NA`. A URL carries a `code` or a `cause`, never
#'       both.}
#'     \item{`step`}{The step of a guarded hop that reported `code` or
#'       `cause`, from 1 (parse) to 7 (resolution) and 8 (address
#'       classification), or `NA`.}
#'     \item{`detail`}{Operator detail for `code` or `cause`: the gate and
#'       precedence tier, the address category, embedding kind or
#'       provider-endpoint kind behind a code, or which resolution failure.}
#'     \item{`layer`}{`"L0"` or `"L1"`, the layer inspected.}
#'     \item{`url`}{The URL as given, for display, without userinfo.}
#'     \item{`scheme`, `host`, `port`}{The scheme, host and effective port
#'       libcurl reads, or `NA` when the URL did not parse that far.}
#'     \item{`userinfo`}{Whether the URL carries credentials.}
#'     \item{`host_kind`}{`"name"`, `"ipv4"` or `"ipv6"`, or `NA`.}
#'     \item{`address`}{For an address literal, `raddr`'s facts about it:
#'       its canonical text, reachability, category, embedded addresses and
#'       provider-endpoint row. `NULL` otherwise.}
#'     \item{`answers`}{At L1, for a name that was resolved, the addresses
#'       the resolver returned, in its order; `character(0)` for an empty
#'       answer. `NULL` when nothing was resolved or the resolver failed.}
#'     \item{`addresses`}{At L1, when every answer is an address, one entry
#'       per answer in the resolver's order: a list of `address` (the
#'       answer), `code` (the reason code gates report for it, or `NA`),
#'       `detail` and `facts` (`raddr`'s facts, as in `address`). `NULL`
#'       otherwise.}
#'   }
#'
#' @seealso [ssrf_policy()] for the rules; [ssrf_vocabulary()] for the reason
#'   codes, the causes, the provider endpoints and the metadata hostnames.
#'
#' @examples
#' ssrf_inspect_url("http://127.0.0.1/admin")$code
#' ssrf_inspect_url("http://0177.0.0.1/")$code
#' ssrf_inspect_url("http://[::ffff:169.254.169.254]/")$code
#'
#' # A name is not resolved at L0: nothing applies at this layer.
#' ssrf_inspect_url("https://example.com/")
#'
#' # Lint a policy: does it reopen what it should, and nothing more?
#' policy <- ssrf_policy(allow_ranges = "10.0.0.0/8", deny_hosts = ".corp")
#' ssrf_inspect_url("http://10.1.2.3/", policy)$code
#' ssrf_inspect_url("http://api.corp/", policy)$code
#'
#' # A redirect's Location, resolved against the previous hop.
#' ssrf_inspect_url("//169.254.169.254/", base = "http://example.com/a")$code
#'
#' # At L1 a URL refused before resolution is never looked up.
#' ssrf_inspect_url("ftp://files.example/", layer = "L1")$code
#' ssrf_inspect_url("http://example.com:6379/", layer = "L1")$code
#'
#' @export
ssrf_inspect_url <- function(
  url,
  policy = ssrf_policy(),
  base = NULL,
  layer = "L0"
) {
  bad <- function(message) {
    abort_ssrfr("invalid_argument", message, fn = "ssrf_inspect_url")
  }
  if (!is_string(url)) {
    bad("`url` must be a single string.")
  }
  if (!inherits(policy, "ssrfr_policy")) {
    bad("`policy` must be a policy built by ssrf_policy().")
  }
  if (!is.null(base) && !is_string(base)) {
    bad("`base` must be a single string, or NULL for a first hop.")
  }
  if (!is_string(layer) || !layer %in% inspection_layers) {
    bad("`layer` must be \"L0\" or \"L1\".")
  }
  hop <- inspect_hop(
    enc2utf8(url),
    policy,
    base = base,
    resolve = identical(layer, "L1")
  )
  finding <- hop$finding
  str_or_na <- function(x) if (is.null(x)) NA_character_ else x
  structure(
    list(
      code = str_or_na(finding$code),
      cause = str_or_na(finding$cause),
      step = if (is.null(finding)) NA_integer_ else finding$detail$step,
      detail = if (is.null(finding)) list() else finding$detail[-1L],
      layer = layer,
      url = redact_url(url),
      scheme = str_or_na(hop$scheme),
      host = str_or_na(hop$host),
      port = if (is.null(hop$port)) NA_integer_ else hop$port,
      userinfo = isTRUE(hop$userinfo),
      host_kind = if (is.null(hop$host_kind)) NA_character_ else hop$host_kind,
      address = hop$address_facts,
      answers = hop$resolution$answers,
      addresses = address_records(hop$resolution$addresses)
    ),
    class = "ssrfr_inspection"
  )
}

# The public form of resolve_hop()'s per-address records, or NULL.
address_records <- function(records) {
  if (is.null(records)) {
    return(NULL)
  }
  lapply(records, function(r) {
    list(
      address = r$address,
      code = if (is.null(r$finding)) NA_character_ else r$finding$code,
      detail = if (is.null(r$finding)) list() else r$finding$detail[-1L],
      facts = r$facts
    )
  })
}

#' @export
format.ssrfr_inspection <- function(x, ...) {
  line <- function(label, value) {
    if (length(value) != 1L || is.na(value)) {
      NULL
    } else {
      paste0("  ", label, ": ", value)
    }
  }
  detail <- NULL
  for (key in intersect(names(x$detail), display_detail_keys)) {
    detail <- c(
      detail,
      paste0(
        "    ",
        key,
        ": ",
        toString(format(x$detail[[key]], trim = TRUE, justify = "none"))
      )
    )
  }
  outcome <- if (is.na(x$cause)) {
    paste0("  code: ", if (is.na(x$code)) paste("none at", x$layer) else x$code)
  } else {
    paste0("  cause: ", x$cause)
  }
  answers <- if (!is.null(x$answers)) {
    shown <- if (length(x$answers)) toString(x$answers) else "none"
    paste0("  answers: ", shown)
  }
  addresses <- NULL
  for (r in x$addresses) {
    addresses <- c(
      addresses,
      paste0("    ", r$address, ": ", if (is.na(r$code)) "none" else r$code)
    )
  }
  c(
    paste0("<ssrfr_inspection> (", x$layer, ": facts, not a defense)"),
    outcome,
    line("step", x$step),
    if (length(detail)) c("  detail:", detail),
    line("url", x$url),
    line("scheme", x$scheme),
    line("host", x$host),
    line("host kind", x$host_kind),
    line("port", x$port),
    if (x$userinfo) "  userinfo: present (withheld)",
    answers,
    if (length(addresses)) c("  addresses:", addresses)
  )
}

#' @export
print.ssrfr_inspection <- function(x, ...) {
  cat(format(x, ...), sep = "\n")
  invisible(x)
}
