# The parse boundary: steps 1-5 of the request lifecycle (ssrfr-v1.md §12),
# with §3's input contract and §4.1-§4.2's parse gate.
#
# rurl parses the string the hop received, under WHATWG, with ssrfr's fixed
# bundle (R/dependencies.R). Its layered verdict is the gate: layer 1 `fail`
# refuses as `parse`, layer 2 other than `admitted` as `scheme` (§6.5); a rurl
# warning or parse_status never refuses (r-binding.md §2.2). rurl's
# serialization, with the fragment removed (§2.3), is the wire string libcurl
# is handed, and its host is the A-label (§4.1). That string, and the host
# curl_parse_url() returns from it, must be printable ASCII, or the hop refuses
# as `parse` (§4.1). curl_parse_url() of that exact string supplies the host
# the transport dials and the scheme, userinfo and port that steps 3-5 read
# (§12). The two parsers' hosts must be one value, addresses compared as raddr
# values and names as lowercase A-labels, or the hop refuses as `parse` (§4.1,
# INV-1, INV-2).

# rurl's numeric-literal shape diagnostics (r-binding.md §2.3): any of them on
# the host the hop received refuses as `numeric-literal` (§12 step 6).
numeric_literal_shapes <- c(
  "ipv4-octal",
  "ipv4-non-dotted",
  "ipv4-short-form",
  "ipv4-non-decimal",
  "ipv4-leading-zero",
  "ipv4-number-form"
)

default_ports <- c(http = 80L, https = 443L)

# Steps 1-5 for one hop. `url` is the string the hop received; `base`, the
# previous hop's URL, or NULL on the first hop; `base_scheme`, the scheme
# libcurl read from `base` when the caller already has it, as a redirect
# hop's `from` does, so `base` is not parsed again. Returns a list whose
# `finding` is NULL when steps 1-5 pass, with what the parse established:
#   received  the string the hop received, as given
#   url       the absolute URL parsed: `url`, or `url` resolved against `base`
#   wire      the string libcurl is handed: rurl's serialization of `url`,
#             without its fragment
#   scheme, host, port, userinfo
#             libcurl's parse of `wire`: the host as libcurl spells it, the
#             effective port as an integer, and whether userinfo is present
#   host_kind "name", "ipv4" or "ipv6"
#   name      for a name, its matching form (§5.0)
#   address   for an address literal, its text without brackets
# Fields the hop did not reach are NULL.
parse_hop <- function(url, policy, base = NULL, base_scheme = NULL) {
  hop <- list(received = url, finding = NULL)
  refuse <- function(code, step, ...) {
    hop$finding <- new_finding(code, step, ...)
    hop
  }

  # Step 1: the length limit, before either parser runs (§5.3), then
  # reference resolution against the previous hop (§3.2, §3.3).
  octets <- tryCatch(nchar(url, type = "bytes"), error = function(e) NA)
  if (is.na(octets) || octets > policy$max_url_length) {
    return(refuse("parse", 1L, check = "length", limit = "max_url_length"))
  }
  if (!is.null(base)) {
    if (is.null(base_scheme)) {
      prior <- parse_boundary(base)
      if (!is.null(prior$finding)) {
        return(refuse("parse", 1L, check = "base"))
      }
      base_scheme <- prior$scheme
    }
    url <- read_resolution(url, base)
    if (is.null(url)) {
      return(refuse("parse", 1L, check = "resolution"))
    }
  }
  hop$url <- url

  # Steps 1-2: both parsers, and their agreement.
  parsed <- parse_boundary(url)
  if (!is.null(parsed$finding)) {
    hop$finding <- parsed$finding
    return(hop)
  }
  hop <- c(hop, parsed[setdiff(names(parsed), "finding")])

  # Step 3: the scheme libcurl read, then no https-to-http redirect.
  if (!hop$scheme %in% policy$allow_schemes) {
    return(refuse("scheme", 3L, host = hop$host))
  }
  if (identical(base_scheme, "https") && identical(hop$scheme, "http")) {
    return(refuse("downgrade", 3L, host = hop$host))
  }

  # Step 4: userinfo, as libcurl read it.
  if (hop$userinfo && !policy$allow_userinfo) {
    return(refuse("userinfo", 4L, host = hop$host))
  }

  # Step 5: the effective port against the allowlist.
  if (!hop$port %in% policy$allow_ports) {
    return(refuse("port", 5L, host = hop$host))
  }
  hop
}

# Parses one absolute URL at the boundary (§4.1, §4.2), with no policy. Returns
# a list: `finding` (a `parse` or `scheme` finding, or NULL) and, when it is
# NULL, `wire`, `scheme`, `host`, `port`, `userinfo`, `host_kind`, `name` and
# `address` as parse_hop() describes them.
parse_boundary <- function(url) {
  refuse <- function(code, check) {
    list(
      finding = new_finding(
        code,
        if (code == "scheme") 3L else 2L,
        check = check
      )
    )
  }
  verdicts <- read_verdicts(url)
  if (is.null(verdicts) || verdicts$layer1 != "pass") {
    return(refuse("parse", "syntax"))
  }
  if (verdicts$layer2 != "admitted") {
    return(refuse("scheme", "scheme-verdict"))
  }
  ours <- read_rurl_parse(url)
  wire <- read_serialization(url)
  if (is.null(ours) || is.null(wire)) {
    return(refuse("parse", "syntax"))
  }
  # The target URI carries no fragment (§2.3). In a WHATWG serialization every
  # other `#` is percent-encoded; a host rurl left holding one (RURL-crsrkcoh)
  # is cut short here and then fails the agreement check below.
  wire <- sub("#.*$", "", wire, useBytes = TRUE)
  # §4.1: the string libcurl is handed must be printable ASCII, read before
  # curl_parse_url() sees it. A U-label reaching libcurl can defeat the
  # connect_to pin even when libcurl's parse returns the A-label (INV-6).
  if (!printable_ascii(wire)) {
    return(refuse("parse", "wire-ascii"))
  }
  theirs <- read_curl_parse(wire)
  if (is.null(theirs)) {
    return(refuse("parse", "transport-parse"))
  }
  host <- theirs$host
  agree <- hosts_agree(ours$host, host)
  if (is.na(agree)) {
    return(refuse("malformed-address", "agreement"))
  }
  if (!agree) {
    return(refuse("parse", "agreement"))
  }
  scheme <- ascii_lower(theirs$scheme)
  web <- scheme %in% names(default_ports)
  port <- if (is.null(theirs$port)) {
    if (web) default_ports[[scheme]] else NA_integer_
  } else {
    suppressWarnings(as.integer(theirs$port))
  }
  if (web && (is.null(host) || !nzchar(host) || is.na(port))) {
    return(refuse("parse", "transport-parse"))
  }
  kind <- if (is.null(host)) {
    NA_character_
  } else if (grepl("^\\[.*\\]$", host)) {
    "ipv6"
  } else if (ours$is_ip) {
    "ipv4"
  } else {
    "name"
  }
  list(
    finding = NULL,
    wire = wire,
    scheme = scheme,
    host = host,
    port = port,
    userinfo = nzchar(theirs$user %||% "") || nzchar(theirs$password %||% ""),
    host_kind = kind,
    name = if (identical(kind, "name")) normalize_host_name(host),
    address = if (!is.na(kind) && kind != "name") unbracket(host)
  )
}

# Whether `x` is printable ASCII, U+0021 to U+007E (§4.1). Read as bytes, so
# a string that is not valid UTF-8 gives FALSE rather than an error; any error
# still gives FALSE, a refusal (INV-11).
printable_ascii <- function(x) {
  is_string(x) &&
    isTRUE(tryCatch(
      !grepl("[^\\x21-\\x7e]", x, perl = TRUE, useBytes = TRUE),
      error = function(e) FALSE
    ))
}

unbracket <- function(host) {
  sub("^\\[(.*)\\]$", "\\1", host)
}

# Whether rurl's host and libcurl's host are one value (§4.1): both absent;
# both addresses equal as raddr values; or both the same name, compared as
# lowercase strings. rurl's host is the A-label, so a name that is not
# printable ASCII has no A-label and never agrees: the wire string must carry
# the A-label (§4.1, §5.0). The ASCII test on libcurl's host is the second
# half of §4.1's printable-ASCII rule, the first being parse_boundary()'s on
# the wire string: libcurl percent-decodes the host, so an ASCII string can
# still parse to a host that is not. NA when raddr parsed both and then failed
# to format one (§6.5: `malformed-address`).
hosts_agree <- function(ours, theirs) {
  absent <- function(h) is.null(h) || is.na(h) || !nzchar(h)
  if (absent(ours) || absent(theirs)) {
    return(absent(ours) && absent(theirs))
  }
  if (!printable_ascii(ours) || !printable_ascii(theirs)) {
    return(FALSE)
  }
  a <- canonical_address(unbracket(ours))
  b <- canonical_address(unbracket(theirs))
  if (!is.null(a) && !is.null(b)) {
    if (is.na(a) || is.na(b)) {
      return(NA)
    }
    return(identical(a, b))
  }
  is.null(a) && is.null(b) && identical(ascii_lower(ours), ascii_lower(theirs))
}

# Step 6 (§12): a non-canonical numeric spelling of the host the hop received
# refuses as `numeric-literal`; then the hostname dimension of §5.0 for a
# name. Returns a finding or NULL.
host_policy <- function(hop, policy) {
  diagnostics <- read_diagnostics(hop$received)
  if (is.null(diagnostics)) {
    return(new_finding("parse", 6L, host = hop$host, check = "diagnostics"))
  }
  if (any(diagnostics %in% numeric_literal_shapes)) {
    return(new_finding("numeric-literal", 6L, host = hop$host))
  }
  if (identical(hop$host_kind, "name")) {
    return(hostname_gates(hop$name, policy))
  }
  NULL
}
