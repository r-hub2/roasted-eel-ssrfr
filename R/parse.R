# The parse boundary: steps 1-5 of the request lifecycle (ssrfr-v1.md §12),
# with §3's input contract and §4.1-§4.2's parse gate.
#
# rurl parses the string the hop received, under WHATWG, with ssrfr's fixed
# bundle (R/dependencies.R). Its layered verdict is the gate: layer 1 `fail`
# refuses as `parse`, layer 2 other than `admitted` as `scheme` (§6.5); a rurl
# warning or parse_status never refuses (r-binding.md §2.2). Then rurl's
# diagnostics of the same string: a host carrying an `xn--` label that is not
# a genuine A-label, or an empty label, refuses as `parse` (§5.0), as does a
# failed reading. rurl's serialization, with the fragment removed (§2.3), is
# the wire string libcurl is handed, and its host is the A-label (§4.1). That
# string, and the host curl_parse_url() returns from it, must be printable
# ASCII, or the hop refuses as `parse` (§4.1). curl_parse_url() of that exact
# string supplies the host the transport dials and the scheme, userinfo and
# port that steps 3-5 read (§12). The two parsers' hosts must be one value,
# addresses compared as raddr values and names as lowercase A-labels, or the
# hop refuses as `parse` (§4.1, INV-1, INV-2).

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

# rurl's diagnostic for a label beginning `xn--`, in any ASCII case, that is
# not a genuine A-label: its Punycode decode fails, is empty or all ASCII, or
# fails the UTS #46 §4.1 Validity Criteria under WHATWG's non-strict flags,
# each label read alone. rurl documents it as complete for that predicate
# (rurl 3.1.0, ruling RUL-023), so its absence admits (§5.0).
ace_label_failure <- "domain-invalid-ace-label"

# rurl's diagnostic for a host with an empty label, such as `a..b`; one
# trailing root dot is not one. A URL host carrying it refuses as `parse`
# (§5.0), and so does a hostname rule (§5.3).
empty_label_diagnostic <- "domain-empty-label"

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

  # Step 1: the length limit and reference resolution.
  start <- parse_hop_start(url, policy, base, base_scheme)
  if (!is.null(start$finding)) {
    hop$finding <- start$finding
    return(hop)
  }
  hop$url <- start$url

  # Steps 1-2: both parsers, and their agreement.
  parsed <- parse_boundary(start$url)
  if (!is.null(parsed$finding)) {
    hop$finding <- parsed$finding
    return(hop)
  }
  hop <- c(hop, parsed[setdiff(names(parsed), "finding")])

  # Steps 3-5: the scheme, userinfo and port under the policy.
  finding <- parse_hop_policy(hop, policy, start$base_scheme)
  if (!is.null(finding)) {
    hop$finding <- finding
  }
  hop
}

# Step 1 for parse_hop(): the length limit, before either parser runs
# (§5.3), then reference resolution against the previous hop (§3.2, §3.3).
# Returns a list: `finding`, a step-1 `parse` finding or NULL, and when it is
# NULL, `url`, the absolute URL to parse, and `base_scheme`, the scheme
# libcurl read from `base` (NULL on a first hop).
parse_hop_start <- function(url, policy, base, base_scheme) {
  refuse <- function(...) {
    list(finding = new_finding("parse", 1L, ...))
  }
  octets <- tryCatch(nchar(url, type = "bytes"), error = function(e) NA)
  if (is.na(octets) || octets > policy$max_url_length) {
    return(refuse(check = "length", limit = "max_url_length"))
  }
  if (!is.null(base)) {
    if (is.null(base_scheme)) {
      prior <- parse_boundary(base)
      if (!is.null(prior$finding)) {
        return(refuse(check = "base"))
      }
      base_scheme <- prior$scheme
    }
    url <- read_resolution(url, base)
    if (is.null(url)) {
      return(refuse(check = "resolution"))
    }
  }
  list(finding = NULL, url = url, base_scheme = base_scheme)
}

# Steps 3-5 for parse_hop() on a hop that parsed: the first finding among the
# scheme, the https-to-http downgrade, userinfo and the port, or NULL.
parse_hop_policy <- function(hop, policy, base_scheme) {
  # Step 3: the scheme libcurl read, then no https-to-http redirect.
  if (!hop$scheme %in% policy$allow_schemes) {
    return(new_finding("scheme", 3L, host = hop$host))
  }
  if (identical(base_scheme, "https") && identical(hop$scheme, "http")) {
    return(new_finding("downgrade", 3L, host = hop$host))
  }

  # Step 4: userinfo, as libcurl read it.
  if (hop$userinfo && !policy$allow_userinfo) {
    return(new_finding("userinfo", 4L, host = hop$host))
  }

  # Step 5: the effective port against the allowlist.
  if (!hop$port %in% policy$allow_ports) {
    return(new_finding("port", 5L, host = hop$host))
  }
  NULL
}

# Parses one absolute URL at the boundary (§4.1, §4.2, §5.0), with no policy.
# Returns a list: `finding` (a `parse` or `scheme` finding, or NULL) and, when
# it is NULL, `wire`, `scheme`, `host`, `port`, `userinfo`, `host_kind`,
# `name` and `address` as parse_hop() describes them.
parse_boundary <- function(url) {
  refused <- parse_boundary_verdicts(url)
  if (!is.null(refused)) {
    return(refused)
  }
  ours <- read_rurl_parse(url)
  wire <- read_serialization(url)
  if (is.null(ours) || is.null(wire)) {
    return(parse_boundary_refuse("parse", "syntax"))
  }
  # The target URI carries no fragment (§2.3). In a WHATWG serialization every
  # other `#` is percent-encoded; a host rurl left holding one (RURL-crsrkcoh)
  # is cut short here and then fails the agreement check below.
  wire <- sub("#.*$", "", wire, useBytes = TRUE)
  refused <- parse_boundary_wire(wire)
  if (!is.null(refused)) {
    return(refused)
  }
  theirs <- read_curl_parse(wire)
  if (is.null(theirs)) {
    return(parse_boundary_refuse("parse", "transport-parse"))
  }
  refused <- parse_boundary_agreement(ours, theirs)
  if (!is.null(refused)) {
    return(refused)
  }
  parse_boundary_fields(wire, ours, theirs)
}

# The checks on the serialization `wire` before libcurl sees it (§5.0, §4.1):
# a parse_boundary() refusal when its diagnostics cannot be read, a label is
# empty or it is not printable ASCII; NULL when it may be handed to libcurl.
parse_boundary_wire <- function(wire) {
  # §5.0: UTS #46 mapping deletes ignored code points, so a label holding only
  # those is empty in the serialization alone (`evil.example.­.` becomes
  # `evil.example..`). The wire's diagnostics are read as well as the input's.
  wire_diagnostics <- read_diagnostics(wire)
  if (is.null(wire_diagnostics)) {
    return(parse_boundary_refuse("parse", "diagnostics"))
  }
  if (empty_label_diagnostic %in% wire_diagnostics) {
    return(parse_boundary_refuse("parse", "empty-label"))
  }
  # §4.1: the string libcurl is handed must be printable ASCII, read before
  # curl_parse_url() sees it. A U-label reaching libcurl can defeat the
  # connect_to pin even when libcurl's parse returns the A-label (INV-6).
  if (!printable_ascii(wire)) {
    return(parse_boundary_refuse("parse", "wire-ascii"))
  }
  NULL
}

# The two parsers' agreement on the host (§4.2): a parse_boundary() refusal
# when rurl's `ours` and libcurl's `theirs` disagree, or when agreement cannot
# be decided; NULL when they agree.
parse_boundary_agreement <- function(ours, theirs) {
  agree <- hosts_agree(ours$host, theirs$host)
  if (is.na(agree)) {
    return(parse_boundary_refuse("malformed-address", "agreement"))
  }
  if (!agree) {
    return(parse_boundary_refuse("parse", "agreement"))
  }
  NULL
}

# A parse_boundary() refusal: the finding alone, at step 3 for `scheme` and
# step 2 for every other code.
parse_boundary_refuse <- function(code, check) {
  list(
    finding = new_finding(
      code,
      if (code == "scheme") 3L else 2L,
      check = check
    )
  )
}

# rurl's verdicts and diagnostics of `url` (§4.2, §5.0): a parse_boundary()
# refusal when layer 1 fails, layer 2 does not admit, the diagnostics cannot
# be read, or a label is a false A-label or empty; NULL when the URL passes
# them.
parse_boundary_verdicts <- function(url) {
  verdicts <- read_verdicts(url)
  if (is.null(verdicts) || verdicts$layer1 != "pass") {
    return(parse_boundary_refuse("parse", "syntax"))
  }
  if (verdicts$layer2 != "admitted") {
    return(parse_boundary_refuse("scheme", "scheme-verdict"))
  }
  # §5.0: a host carrying an `xn--` label that is not a genuine A-label has no
  # A-label, and its input spelling must not stand in for one. rurl's
  # diagnostic is the signal; ssrfr decodes no label itself (§4).
  diagnostics <- read_diagnostics(url)
  if (is.null(diagnostics)) {
    return(parse_boundary_refuse("parse", "diagnostics"))
  }
  if (ace_label_failure %in% diagnostics) {
    return(parse_boundary_refuse("parse", "ace-label"))
  }
  # §5.0: an empty label would otherwise reach hostname matching unmatched,
  # since only one trailing root dot is removed (SSRF-qopriinc).
  if (empty_label_diagnostic %in% diagnostics) {
    return(parse_boundary_refuse("parse", "empty-label"))
  }
  NULL
}

# What parse_boundary() established once the two parsers agree: the fields
# parse_hop() describes, read from libcurl's parse `theirs` of `wire`, or a
# `transport-parse` refusal when an http(s) URL has no host or no valid port.
parse_boundary_fields <- function(wire, ours, theirs) {
  host <- theirs$host
  scheme <- ascii_lower(theirs$scheme)
  web <- scheme %in% names(default_ports)
  port <- parse_boundary_port(theirs$port, scheme)
  if (web && (is.null(host) || !nzchar(host) || is.na(port))) {
    return(parse_boundary_refuse("parse", "transport-parse"))
  }
  kind <- parse_boundary_host_kind(host, ours$is_ip)
  list(
    finding = NULL,
    wire = wire,
    scheme = scheme,
    host = host,
    port = port,
    userinfo = nzchar(default_if_null(theirs$user, "")) ||
      nzchar(default_if_null(theirs$password, "")),
    host_kind = kind,
    name = if (identical(kind, "name")) normalize_host_name(host),
    address = if (!is.na(kind) && kind != "name") unbracket(host)
  )
}

# The effective port: libcurl's port as an integer (NA when it is not one),
# or, when libcurl read none, the scheme's default, NA for a scheme without
# one.
parse_boundary_port <- function(port, scheme) {
  if (!is.null(port)) {
    return(suppressWarnings(as.integer(port)))
  }
  if (scheme %in% names(default_ports)) default_ports[[scheme]] else NA_integer_
}

# The host's kind: "ipv6" for a bracketed literal, "ipv4" for one rurl read
# as an address, "name" otherwise, NA when libcurl read no host.
parse_boundary_host_kind <- function(host, is_ip) {
  if (is.null(host)) {
    NA_character_
  } else if (grepl("^\\[.*\\]$", host)) {
    "ipv6"
  } else if (is_ip) {
    "ipv4"
  } else {
    "name"
  }
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
  if (hosts_agree_absent(ours) || hosts_agree_absent(theirs)) {
    return(hosts_agree_absent(ours) && hosts_agree_absent(theirs))
  }
  if (!printable_ascii(ours) || !printable_ascii(theirs)) {
    return(FALSE)
  }
  hosts_agree_values(ours, theirs)
}

# Whether a parser left the host absent: NULL, NA or empty.
hosts_agree_absent <- function(h) {
  is.null(h) || is.na(h) || !nzchar(h)
}

# hosts_agree() for two present, printable ASCII hosts: equal raddr values
# when both are addresses, NA when raddr failed to format one, equal
# lowercase strings when both are names, FALSE otherwise.
hosts_agree_values <- function(ours, theirs) {
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
