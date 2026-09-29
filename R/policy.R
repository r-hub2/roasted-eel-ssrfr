#' Build a guard policy
#'
#' Builds the policy a guarded hop is evaluated under. Every field has a
#' finite, conservative default, so `ssrf_policy()` alone is a complete
#' policy. The policy is validated when it is built: an entry that could
#' silently match nothing, or a limit that is not a usable number, is an error
#' of class `ssrfr_error_invalid_policy`, never a policy that quietly admits or
#' refuses more than it says.
#'
#' Allow fields are exceptions to the built-in refusals, not a destination
#' allowlist: `allow_ranges` reopens addresses the built-in rules refuse, and
#' `allow_hosts` reopens names the built-in metadata hostname list refuses. A
#' caller deny rule always wins over a caller allow rule.
#'
#' Hostname rules match the host's normalized form: IDNA A-label,
#' ASCII-lowercased, one trailing root dot removed. A rule matches that name
#' exactly, unless it begins with `.`, in which case it matches every proper
#' subdomain and not the bare name: `".corp"` matches `api.corp`, not `corp`.
#' No other wildcard exists. An address literal is not a hostname rule; write
#' it as a range. The policy stores the normalized rules.
#'
#' Ranges are CIDR blocks read by `raddr`, such as `"10.0.0.0/8"` or
#' `"2001:db8::/32"`. A single address is a `/32` or `/128`, and a block with
#' host bits set is an error.
#'
#' Every limit is finite and may be raised without a ceiling. `0` means zero,
#' never unlimited, and only `max_redirects` accepts it, meaning "refuse any
#' redirect".
#'
#' @param allow_schemes Schemes a URL may use, a subset of `"http"` and
#'   `"https"`.
#' @param allow_ports Ports a URL may use, whatever its scheme: an allowlist,
#'   never a denylist.
#' @param deny_hosts Hostname rules that refuse a host.
#' @param allow_hosts Hostname rules that override the built-in metadata
#'   hostname list for the matched name only.
#' @param deny_ranges Address ranges that refuse an address.
#' @param allow_ranges Address ranges that override the determinate built-in
#'   address refusals for the matched addresses only.
#' @param allow_userinfo Whether a URL may carry embedded credentials
#'   (`user:password@`). `TRUE` or `FALSE`.
#' @param max_redirects Redirects a chain may follow. `0` refuses any redirect.
#' @param connect_timeout Seconds allowed for each connection attempt.
#' @param total_timeout Seconds allowed for the whole redirect chain.
#' @param max_response_size Bytes of decoded response body allowed per hop.
#' @param max_header_bytes Bytes of response header allowed per hop.
#' @param max_header_fields Response header fields allowed per hop.
#' @param max_url_length Octets of URL string allowed per hop.
#' @param user_agent The `User-Agent` header value. The default names the
#'   package version and repository. It must be a valid HTTP field value;
#'   CR, LF and other control characters are refused, never stripped.
#'
#' @return An object of class `ssrfr_policy`: a list holding every field above,
#'   with hostname rules normalized and ports and limits as numbers.
#'
#' @examples
#' ssrf_policy()
#'
#' # Reach an internal service by name: authorize its address range.
#' ssrf_policy(allow_ranges = "10.0.0.0/8", deny_hosts = ".corp")
#'
#' # A malformed entry is an error, not a rule that matches nothing.
#' try(ssrf_policy(deny_hosts = "com, ru"))
#'
#' @export
ssrf_policy <- function(
  allow_schemes = c("http", "https"),
  allow_ports = c(80, 443),
  deny_hosts = character(),
  allow_hosts = character(),
  deny_ranges = character(),
  allow_ranges = character(),
  allow_userinfo = FALSE,
  max_redirects = 20,
  connect_timeout = 3,
  total_timeout = 30,
  max_response_size = 10 * 1024^2,
  max_header_bytes = 16 * 1024,
  max_header_fields = 128,
  max_url_length = 8000,
  user_agent = default_user_agent()
) {
  structure(
    list(
      allow_schemes = check_schemes(allow_schemes),
      allow_ports = check_ports(allow_ports),
      deny_hosts = check_host_rules(deny_hosts, "deny_hosts"),
      allow_hosts = check_host_rules(allow_hosts, "allow_hosts"),
      deny_ranges = check_ranges(deny_ranges, "deny_ranges"),
      allow_ranges = check_ranges(allow_ranges, "allow_ranges"),
      allow_userinfo = check_flag(allow_userinfo, "allow_userinfo"),
      max_redirects = check_limit(max_redirects, "max_redirects", zero = TRUE),
      connect_timeout = check_limit(connect_timeout, "connect_timeout"),
      total_timeout = check_limit(total_timeout, "total_timeout"),
      max_response_size = check_limit(max_response_size, "max_response_size"),
      max_header_bytes = check_limit(max_header_bytes, "max_header_bytes"),
      max_header_fields = check_limit(max_header_fields, "max_header_fields"),
      max_url_length = check_limit(max_url_length, "max_url_length"),
      user_agent = check_user_agent(user_agent)
    ),
    class = "ssrfr_policy"
  )
}

# "ssrfr/<version> (+<repository>)", assembled from DESCRIPTION at run time
# (§5.3). The repository is the URL entry that BugReports extends; failing
# that, the first URL entry.
default_user_agent <- function() {
  desc <- utils::packageDescription("ssrfr")
  urls <- strsplit(desc$URL %||% "", "[,[:space:]]+")[[1L]]
  urls <- urls[nzchar(urls)]
  bugs <- desc$BugReports %||% ""
  repo <- urls[startsWith(bugs, paste0(urls, "/"))]
  repo <- if (length(repo)) repo[[1L]] else urls[1L]
  paste0("ssrfr/", desc$Version, " (+", repo, ")")
}

`%||%` <- function(x, y) if (is.null(x)) y else x

policy_error <- function(message) {
  abort_ssrfr("invalid_policy", message, fn = "ssrf_policy")
}

# The label for entry `i` of `field` in a message: the position, never the
# value (R/conditions.R).
entry_label <- function(field, i) {
  paste0("`", field, "[", i, "]`")
}

# The entry checks every string list shares (§5.3): an entry that is missing
# or empty, carries leading or trailing whitespace, or joins several values in
# one string (`"com, ru"`). Returns the entries as UTF-8.
check_entries <- function(x, field) {
  if (is.null(x)) {
    x <- character()
  }
  if (!is.character(x)) {
    policy_error(paste0("`", field, "` must be a character vector."))
  }
  x <- enc2utf8(unname(x))
  for (i in seq_along(x)) {
    entry <- x[[i]]
    if (is.na(entry) || !nzchar(entry)) {
      policy_error(paste0(entry_label(field, i), " is missing or empty."))
    }
    if (grepl("^[\\h\\v]|[\\h\\v]$", entry, perl = TRUE)) {
      policy_error(paste0(
        entry_label(field, i),
        " has leading or trailing whitespace."
      ))
    }
    if (grepl("[,;\\h\\v]", entry, perl = TRUE)) {
      policy_error(paste0(
        entry_label(field, i),
        " joins several values in one string; give each its own entry."
      ))
    }
  }
  x
}

check_schemes <- function(x) {
  x <- check_entries(x, "allow_schemes")
  if (!length(x)) {
    policy_error("`allow_schemes` must name at least one scheme.")
  }
  bad <- which(!x %in% c("http", "https"))
  if (length(bad)) {
    policy_error(paste0(
      entry_label("allow_schemes", bad[[1L]]),
      " is not \"http\" or \"https\", the schemes the transport speaks."
    ))
  }
  x
}

check_ports <- function(x) {
  if (!is.numeric(x) || !length(x)) {
    policy_error("`allow_ports` must be a non-empty numeric vector.")
  }
  for (i in seq_along(x)) {
    port <- x[[i]]
    if (
      is.na(port) ||
        !is.finite(port) ||
        port != trunc(port) ||
        port < 1 ||
        port > 65535
    ) {
      policy_error(paste0(
        entry_label("allow_ports", i),
        " is not a port number from 1 to 65535."
      ))
    }
  }
  as.integer(unname(x))
}

check_flag <- function(x, field) {
  if (!is.logical(x) || length(x) != 1L || is.na(x)) {
    policy_error(paste0("`", field, "` must be TRUE or FALSE."))
  }
  x
}

# A limit that is missing, NA, negative, non-finite or not a whole number is a
# construction error, and so is 0 except for max_redirects (§5.3).
check_limit <- function(x, field, zero = FALSE) {
  if (!is.numeric(x) || length(x) != 1L) {
    policy_error(paste0("`", field, "` must be a single number."))
  }
  if (is.na(x) || !is.finite(x)) {
    policy_error(paste0("`", field, "` must be finite."))
  }
  if (x != trunc(x)) {
    policy_error(paste0("`", field, "` must be a whole number."))
  }
  if (x < 0 || (!zero && x == 0)) {
    policy_error(paste0(
      "`",
      field,
      "` must be ",
      if (zero) "zero or more." else "one or more; 0 never means unlimited."
    ))
  }
  as.numeric(x)
}

# A valid field value (RFC 9110 §5.5): visible ASCII, obs-text, and SP or
# HTAB between them, never at either end. CR, LF, NUL and every other control
# are refused, never stripped. An empty value is refused too: a User-Agent
# names at least one product (RFC 9110 §10.1.5).
check_user_agent <- function(x) {
  if (!is.character(x) || length(x) != 1L || is.na(x)) {
    policy_error("`user_agent` must be a single string.")
  }
  bytes <- as.integer(charToRaw(enc2utf8(x)))
  n <- length(bytes)
  if (!n) {
    policy_error("`user_agent` must not be empty.")
  }
  ok <- bytes == 0x09L | (bytes >= 0x20L & bytes != 0x7FL)
  edge <- bytes[c(1L, n)] %in% c(0x09L, 0x20L)
  if (!all(ok) || any(edge)) {
    policy_error(paste0(
      "`user_agent` is not a valid HTTP field value: it contains a control ",
      "character, or starts or ends with whitespace."
    ))
  }
  x
}

# Hostname rules (§5.0): a name, or `.` and a name for its proper subdomains.
# The name must be exactly one host that rurl's WHATWG parse admits as a
# domain, never an address literal, and it is stored normalized: IDNA A-label,
# ASCII-lowercased, one trailing root dot removed. rurl does the parsing and
# the IDNA mapping; ssrfr only reads the result.
check_host_rules <- function(x, field) {
  x <- check_entries(x, field)
  vapply(
    seq_along(x),
    function(i) normalize_host_rule(x[[i]], entry_label(field, i)),
    character(1)
  )
}

normalize_host_rule <- function(rule, label) {
  invalid <- function(why) {
    policy_error(paste0(label, " is not a valid hostname rule: ", why))
  }
  if (grepl("*", rule, fixed = TRUE)) {
    invalid("only a leading `.` may widen a rule; there are no wildcards.")
  }
  subdomains <- startsWith(rule, ".")
  name <- if (subdomains) substring(rule, 2L) else rule
  if (!nzchar(name)) {
    invalid("it names no host.")
  }
  host <- rule_host(name)
  if (is.null(host)) {
    invalid("it is not a single hostname.")
  }
  if (isTRUE(host$is_ip)) {
    invalid("it is an address literal; write it as a range instead.")
  }
  normalized <- sub("[.]$", "", ascii_lower(host$a_label))
  if (!nzchar(normalized) || grepl("[^\\x21-\\x7e]", normalized, perl = TRUE)) {
    invalid("it has no IDNA A-label form.")
  }
  if (subdomains) paste0(".", normalized) else normalized
}

# Parses `http://<name>:1/` with rurl under WHATWG and returns the host, or
# NULL unless the whole of `name` is the host: the probe port and the empty
# path must survive, and no userinfo, query or fragment may appear. Any rurl
# error is a NULL too.
rule_host <- function(name) {
  url <- paste0("http://", name, ":1/")
  tryCatch(
    {
      p <- rurl::safe_parse_urls(url, url_standard = "whatwg")
      verdict <- rurl::get_parse_verdicts(url, url_standard = "whatwg")
      whole <- identical(verdict$layer1_syntax_verdict[[1L]], "pass") &&
        !is.na(p$host[[1L]]) &&
        identical(as.character(p$port[[1L]]), "1") &&
        identical(p$path[[1L]], "/") &&
        is.na(p$user[[1L]]) &&
        is.na(p$password[[1L]]) &&
        is.na(p$query[[1L]]) &&
        is.na(p$fragment[[1L]])
      if (whole) {
        list(
          a_label = rurl::get_host(
            url,
            host_encoding = "idna",
            url_standard = "whatwg"
          )[[1L]],
          is_ip = p$is_ip_host[[1L]]
        )
      }
    },
    error = function(e) NULL
  )
}

# Locale-independent ASCII case folding (§5.0).
ascii_lower <- function(x) {
  chartr("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz", x)
}

# Ranges: the block must be one raddr can parse. raddr raises for a block it
# cannot read (a missing prefix length, host bits set, a non-RFC spelling), and
# ssrfr asks it rather than reading the block itself. raddr's message is not
# relayed, because it quotes the block.
check_ranges <- function(x, field) {
  x <- check_entries(x, field)
  probe <- raddr::addr_pton("0.0.0.0")
  for (i in seq_along(x)) {
    ok <- tryCatch(
      {
        raddr::addr_within_any(probe, x[[i]])
        TRUE
      },
      error = function(e) FALSE
    )
    if (!ok) {
      policy_error(paste0(
        entry_label(field, i),
        " is not a range raddr can parse: write an address and a prefix ",
        "length, such as 10.0.0.0/8 or 2001:db8::/32, with no host bits set."
      ))
    }
  }
  x
}

#' @export
format.ssrfr_policy <- function(x, ...) {
  show <- function(v) {
    if (!length(v)) {
      return("(none)")
    }
    v <- if (is.character(v)) {
      encodeString(v, quote = "\"")
    } else {
      vapply(v, format, character(1), scientific = FALSE)
    }
    toString(v)
  }
  fields <- names(x)
  c(
    "<ssrfr_policy>",
    paste0("  ", format(fields), "  ", vapply(x, show, character(1)))
  )
}

#' @export
print.ssrfr_policy <- function(x, ...) {
  cat(format(x, ...), sep = "\n")
  invisible(x)
}
