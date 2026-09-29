# The two negative outcome classes (ssrfr-v1.md §6.2). A refusal is a policy
# decision and carries a reason code (§6.5); an operational failure happened on
# the wire and carries a cause (§6.6). The two domains share no token, and a
# caller branches on the class, never on a string.
#
# Both carry the full factual record for the operator (§6.4): the hop index,
# the host and address involved, the URL in display form, and operator detail.
# The URL is redacted when the object is built, so no outcome ever holds
# userinfo (§2.3). format() and print() show operator detail only for the keys
# in `display_detail_keys`, facts ssrfr itself derives; every other detail value
# is withheld from the rendering, so a request-plan header value, a body or a
# proxy value placed there by mistake never reaches a log line. The detail
# itself stays on the object for the operator.

display_detail_keys <- c(
  "step",
  "check",
  "gate",
  "tier",
  "limit",
  "embedding_kind",
  "category",
  "provider_kind",
  "attempts",
  "callback"
)

# The single value ssrf_public_reason() returns (§6.4). It is not a reason code
# or a cause, and names no predicate, address, hop or outcome class.
public_reason_value <- "refused"

new_ssrf_refusal <- function(
  code,
  hop,
  host = NA_character_,
  address = NA_character_,
  url = NA_character_,
  detail = list()
) {
  check_token(code, domain_keys("reason_codes"), "code")
  new_outcome(
    list(code = code),
    hop,
    host,
    address,
    url,
    detail,
    "ssrfr_refusal"
  )
}

new_ssrf_failure <- function(
  cause,
  hop,
  host = NA_character_,
  address = NA_character_,
  url = NA_character_,
  detail = list()
) {
  check_token(cause, domain_keys("causes"), "cause")
  new_outcome(
    list(cause = cause),
    hop,
    host,
    address,
    url,
    detail,
    "ssrfr_failure"
  )
}

new_outcome <- function(token, hop, host, address, url, detail, class) {
  if (
    !is.numeric(hop) ||
      length(hop) != 1L ||
      is.na(hop) ||
      hop < 1 ||
      hop != trunc(hop)
  ) {
    internal_error("`hop` must be a whole number from 1, the first hop.")
  }
  for (field in list(host, address, url)) {
    if (!is.character(field) || length(field) != 1L) {
      internal_error("`host`, `address` and `url` must be single strings.")
    }
  }
  if (!is.list(detail) || (length(detail) && !is_named(detail))) {
    internal_error("`detail` must be a named list.")
  }
  structure(
    c(
      token,
      list(
        hop = as.integer(hop),
        host = host,
        address = address,
        url = redact_url(url),
        detail = detail
      )
    ),
    class = c(class, "ssrfr_outcome")
  )
}

is_named <- function(x) {
  nms <- names(x)
  !is.null(nms) && !anyNA(nms) && all(nzchar(nms))
}

check_token <- function(x, domain, field) {
  if (!is.character(x) || length(x) != 1L || !x %in% domain) {
    internal_error(paste0("`", field, "` is not in its closed domain."))
  }
}

# Outcomes are built inside ssrfr, never by the caller, so a bad field is a
# defect in ssrfr; it is still a classed condition with no value in it.
internal_error <- function(message) {
  abort_ssrfr("invalid_argument", paste("internal error:", message))
}

# The display form of a URL, without userinfo (§2.3), from rurl's
# format_url(). A URL that rurl cannot parse is withheld whole: its userinfo
# cannot be told apart from the rest.
redact_url <- function(url) {
  if (is.na(url)) {
    return(NA_character_)
  }
  shown <- tryCatch(rurl::format_url(url)[[1L]], error = function(e) NA)
  if (is.na(shown)) "<withheld: not a parseable URL>" else shown
}

#' @export
format.ssrfr_outcome <- function(x, ...) {
  refusal <- inherits(x, "ssrfr_refusal")
  line <- function(label, value) {
    if (is.na(value)) NULL else paste0("  ", label, ": ", value)
  }
  detail <- NULL
  for (key in names(x$detail)) {
    value <- x$detail[[key]]
    shown <- if (key %in% display_detail_keys && is.atomic(value)) {
      toString(format(value, trim = TRUE, justify = "none"))
    } else {
      "<withheld>"
    }
    detail <- c(detail, paste0("    ", key, ": ", shown))
  }
  c(
    if (refusal) "<ssrfr_refusal>" else "<ssrfr_failure>",
    if (refusal) line("code", x$code) else line("cause", x$cause),
    line("hop", as.character(x$hop)),
    line("host", x$host),
    line("address", x$address),
    line("url", x$url),
    if (length(detail)) c("  detail:", detail)
  )
}

#' @export
print.ssrfr_outcome <- function(x, ...) {
  cat(format(x, ...), sep = "\n")
  invisible(x)
}

#' Project a refusal or failure for an untrusted party
#'
#' Reduces a refusal or an operational failure to one fixed value that names
#' no predicate, cause, address, hop or outcome class. Every refusal and every
#' failure projects to the same value, so a party probing a service cannot
#' tell a refused private address from a closed port, a missing name or a
#' timeout.
#'
#' `ssrfr` cannot tell a trusted caller from an untrusted one, so it returns
#' the full record to its caller. Applying this projection where an untrusted
#' party receives the result is the application's job. Response timing still
#' differs between outcomes; this projection hides only their shape.
#'
#' A refusal (class `ssrfr_refusal`) carries `code`, a reason code from
#' `ssrf_vocabulary("reason_codes")`; an operational failure (class
#' `ssrfr_failure`) carries `cause`, from `ssrf_vocabulary("causes")`. Both
#' also carry `hop`, `host`, `address`, `url` (a display form with any userinfo
#' redacted) and `detail`. Their `print()` and `format()` methods show no
#' userinfo, request header value, body or proxy value.
#'
#' @param x A refusal or an operational failure.
#'
#' @return The single string `"refused"`, whatever `x` holds.
#'
#' @examples
#' refusal <- ssrfr:::new_ssrf_refusal("loopback", hop = 1, address = "::1")
#' refusal$code
#' ssrf_public_reason(refusal)
#'
#' failure <- ssrfr:::new_ssrf_failure("timeout", hop = 2)
#' ssrf_public_reason(failure)
#'
#' @export
ssrf_public_reason <- function(x) {
  if (!inherits(x, c("ssrfr_refusal", "ssrfr_failure"))) {
    abort_ssrfr(
      "invalid_argument",
      "`x` must be a refusal or an operational failure.",
      fn = "ssrf_public_reason"
    )
  }
  public_reason_value
}
