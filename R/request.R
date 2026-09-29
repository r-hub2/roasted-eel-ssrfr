# The request plan (ssrfr-v1.md §2.3): the method, header fields and body the
# caller asks for on the first hop. It enters at prepare, never at fetch, and
# the binding carries it sanitized: validated here, with nothing added or
# rewritten, so the plan the binding records is the plan the transport sends.
#
# A plan of the wrong type or shape is `ssrfr_error_invalid_argument`; one
# that breaks a header or body rule of §2.3 is `ssrfr_error_invalid_request`
# (§6.6). Neither message quotes a header name, value or body (§2.3): an entry
# is named by its position, in the plan the caller can read: `request` on a
# first hop, and on a redirect hop `from$request`, the plan inherited through
# `from` (plan_label()).

request_fields <- c("method", "headers", "body", "carry")

# RFC 9110 §5.6.2 token, one or more tchar: the syntax of a method, of a
# field name, and of a media type's type and subtype (R/transport.R).
http_tchars <- "[!#$%&'*+.^_`|~0-9A-Za-z-]+"
http_token <- paste0("^", http_tchars, "$")

# Field names a caller may not supply (§2.3), matched case-insensitively:
# transport-controlled routing and framing, plus any HTTP/2 or HTTP/3
# pseudo-header (a name beginning with `:`, which is not a token anyway).
# `user-agent` is transport-owned too: the policy's `user_agent` sets it
# (§5.3), and a caller field would silently replace it. So is `expect`:
# under 100-continue, libcurl answers a 417 by sending the request a second
# time within one fetch (§2.5), so the transport suppresses it on every body.
transport_owned_fields <- c(
  "host",
  "connection",
  "proxy-connection",
  "keep-alive",
  "transfer-encoding",
  "te",
  "trailer",
  "upgrade",
  "content-length",
  "accept-encoding",
  "user-agent",
  "expect"
)

# Fields that are never carryable across an origin, whatever the plan
# nominates (§2.3, INV-8).
never_carryable_fields <- c("authorization", "proxy-authorization", "cookie")

request_error <- function(message) {
  abort_ssrfr("invalid_request", message, fn = "ssrf_prepare_hop")
}

request_argument_error <- function(message) {
  abort_ssrfr("invalid_argument", message, fn = "ssrf_prepare_hop")
}

# How a message names the plan, a field of it or an entry of a field: as
# the R expression that reads it, rooted at `root`. `index` maps an entry's
# position in the plan checked to its position in the plan named.
plan_label <- function(root, index = function(field, i) i) {
  function(field = NULL, i = NULL) {
    if (!is.null(i)) {
      i <- index(field, i)
    }
    paste0(
      "`",
      root,
      if (!is.null(field)) paste0("$", field),
      if (!is.null(i)) paste0("[", i, "]"),
      "`"
    )
  }
}

# Validates a plan and returns it sanitized: `method` (a string), `headers`
# (a character vector named by field name, as given), `body` (a raw vector,
# or NULL) and `carry` (the nominated field names, lowercase). `label` names
# the plan in a message: the first hop's `request` by default.
check_request <- function(request, policy, label = plan_label("request")) {
  if (!is.list(request) || is.data.frame(request) || is.object(request)) {
    request_argument_error(paste0(
      label(),
      " must be a list of `method`, `headers`, `body` and `carry`."
    ))
  }
  given <- names(request)
  if (length(request) && (is.null(given) || !all(given %in% request_fields))) {
    request_argument_error(paste0(
      label(),
      " may hold only `method`, `headers`, `body` and `carry`, each named."
    ))
  }
  if (anyDuplicated(given)) {
    request_argument_error(paste0(label(), " names a field more than once."))
  }
  method <- check_method(request$method %||% "GET", label)
  headers <- check_headers(request$headers, policy, label)
  body <- check_body(request$body, method, label)
  carry <- check_carry(request$carry, headers, label)
  list(method = method, headers = headers, body = body, carry = carry)
}

check_method <- function(method, label) {
  if (!is_string(method)) {
    request_argument_error(paste0(label("method"), " must be a single string."))
  }
  if (!grepl(http_token, method)) {
    request_error(paste0(
      label("method"),
      " is not a valid HTTP method token."
    ))
  }
  method
}

# Header fields: a named character vector or a named list of single strings.
check_headers <- function(headers, policy, label) {
  if (is.null(headers) || !length(headers)) {
    return(stats::setNames(character(), character()))
  }
  if (is.list(headers)) {
    ok <- all(vapply(headers, is_string, logical(1L)))
    if (!ok) {
      request_argument_error(paste0(
        "Each entry of a list ",
        label("headers"),
        " must be a single string."
      ))
    }
    headers <- stats::setNames(
      unlist(headers, use.names = FALSE),
      names(headers)
    )
  }
  if (!is.character(headers) || anyNA(headers)) {
    request_argument_error(paste0(
      label("headers"),
      " must be a named character vector with no NA."
    ))
  }
  fields <- names(headers)
  if (is.null(fields) || anyNA(fields) || !all(nzchar(fields))) {
    request_argument_error(paste0(
      "Every entry of ",
      label("headers"),
      " must be named."
    ))
  }
  headers <- enc2utf8(headers)
  lower <- ascii_lower(fields)
  markers <- ascii_lower(domain_metadata_headers()$header)
  entry <- function(i) label("headers", i)
  for (i in seq_along(headers)) {
    if (!grepl(http_token, fields[[i]])) {
      request_error(paste0(
        entry(i),
        " has a field name that is not a valid token (RFC 9110 \u00a75.1)."
      ))
    }
    if (lower[[i]] %in% transport_owned_fields) {
      request_error(paste0(
        entry(i),
        " names a field the transport owns; it cannot be supplied."
      ))
    }
    if (grepl("[\r\n]", headers[[i]])) {
      request_error(paste0(
        entry(i),
        " has a value containing CR or LF; it is refused, never sanitized."
      ))
    }
    if (lower[[i]] %in% markers && !names_provider_endpoint(policy)) {
      request_error(paste0(
        entry(i),
        " is a metadata-service request marker; it is refused unless the ",
        "policy's `allow_ranges` names a provider endpoint exactly."
      ))
    }
  }
  headers
}

# A body: NULL, a raw vector, or a single string sent as its UTF-8 bytes.
check_body <- function(body, method, label) {
  if (is.null(body)) {
    return(NULL)
  }
  if (is_string(body)) {
    body <- charToRaw(enc2utf8(body))
  }
  if (!is.raw(body)) {
    request_argument_error(paste0(
      label("body"),
      " must be NULL, a raw vector or a single string."
    ))
  }
  if (identical(method, "HEAD")) {
    request_error(paste0(
      label("body"),
      " must be NULL for HEAD, which libcurl sends without one."
    ))
  }
  body
}

# Fields the plan nominates as safe to carry across an origin (§2.3): names of
# fields the plan holds, never a permanently non-carryable one.
check_carry <- function(carry, headers, label) {
  if (is.null(carry) || !length(carry)) {
    return(character())
  }
  if (!is.character(carry) || anyNA(carry)) {
    request_argument_error(paste0(
      label("carry"),
      " must be a character vector of field names."
    ))
  }
  carry <- ascii_lower(carry)
  for (i in seq_along(carry)) {
    if (carry[[i]] %in% never_carryable_fields) {
      request_error(paste0(
        label("carry", i),
        " nominates Authorization, Proxy-Authorization or Cookie, which never ",
        "cross an origin."
      ))
    }
    if (!carry[[i]] %in% ascii_lower(names(headers))) {
      request_error(paste0(
        label("carry", i),
        " nominates a field ",
        label("headers"),
        " does not hold."
      ))
    }
  }
  unique(carry)
}

# Whether an allow_ranges entry of the policy names a provider endpoint
# exactly: a /32 or /128 block equal to a row of gate 2's table (§2.3, §5.0).
# A raddr failure answers FALSE, so the marker stays refused (INV-11).
names_provider_endpoint <- function(policy) {
  if (!length(policy$allow_ranges)) {
    return(FALSE)
  }
  for (row in domain_provider_endpoints()$address) {
    addr <- read_address(row)
    family <- if (is.null(addr)) NULL else read_family(addr)
    exact <- if (is.null(family)) NULL else exact_allow(addr, family, policy)
    if (isTRUE(exact)) {
      return(TRUE)
    }
  }
  FALSE
}
