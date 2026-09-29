# Redirect hops (ssrfr-v1.md §2.3, §2.5, §2.6, §12 step 13, INV-7, INV-8).
# ssrf_prepare_hop(url, policy, from = previous) runs the whole lifecycle
# again for the new URL, resolved against the previous hop's (§3.2); this
# file holds what only a redirect hop needs: the checks on `from`, the chain
# budgets, origin equality, and the plan the new hop inherits.
#
# `from` supplies the base URL, the hop index, the previous origin, the
# sanitized plan and the transport-observed status (§2.6). The plan is never
# re-supplied, so credentials a hop stripped cannot come back (§2.3).

# The statuses ssrfr follows as a redirect: the Fetch Standard's (§2.3).
followed_statuses <- c(301L, 302L, 303L, 307L, 308L)

# Fields that describe a body, dropped whenever the body is (§2.3): RFC 9110
# §15.4's content-specific fields, a list it gives as "including (but not
# limited to)"; Content-Range, which places the body within a whole (RFC
# 9110 §14.4); Content-Disposition, which names the body as a file (RFC
# 6266); and Content-Digest and Repr-Digest, which RFC 9530 made of Digest.
# Content-Length is transport-owned and never in a plan.
body_content_fields <- c(
  "content-type",
  "content-encoding",
  "content-language",
  "content-location",
  "content-length",
  "content-range",
  "content-disposition",
  "digest",
  "content-digest",
  "repr-digest",
  "last-modified"
)

# Checks `from` for ssrf_prepare_hop() and returns nothing. It must be a
# binding (`invalid_argument`); spent, with a successful response that is a
# followed redirect (`invalid_from`, §2.3); and `policy` must state the chain
# budgets the first hop fixed (`budget_change`, §2.5). No message quotes a
# value of the binding or the response.
check_from <- function(from, policy) {
  if (!inherits(from, "ssrfr_binding") || !is.environment(from)) {
    abort_ssrfr(
      "invalid_argument",
      "`from` must be a binding returned by ssrf_prepare_hop().",
      fn = "ssrf_prepare_hop"
    )
  }
  invalid <- function(message) {
    abort_ssrfr("invalid_from", message, fn = "ssrf_prepare_hop")
  }
  state <- from$state
  if (!is.environment(state) || !identical(state$fetchable, FALSE)) {
    invalid(paste0(
      "`from` has not been fetched; fetch it with ssrf_fetch() before ",
      "following its redirect."
    ))
  }
  if (!isTRUE(state$fetched) || !identical(state$outcome, "response")) {
    invalid("`from` records no successful response to follow.")
  }
  followed <- is.integer(state$status) &&
    length(state$status) == 1L &&
    state$status %in% followed_statuses &&
    identical(state$location_count, 1L) &&
    is_string(state$location)
  if (!followed) {
    invalid(paste0(
      "`from` records a response that is not a followed redirect: a 301, ",
      "302, 303, 307 or 308 with exactly one Location field."
    ))
  }
  # A binding past its budget was refused as redirect-limit by ssrf_fetch()
  # and never records a response; this holds the line if one ever did.
  if (budget_spent(from)) {
    invalid("`from` spent the chain's redirect budget.")
  }
  budget <- from$budget
  if (
    !identical(policy$max_redirects, budget$max_redirects) ||
      !identical(policy$total_timeout, budget$total_timeout)
  ) {
    abort_ssrfr(
      "budget_change",
      paste0(
        "`policy` states a `max_redirects` or `total_timeout` other than the ",
        "one the chain's first hop fixed; the chain budgets cannot change ",
        "mid-chain."
      ),
      fn = "ssrf_prepare_hop"
    )
  }
  invisible()
}

# Whether a 3xx on `binding`'s hop is past the chain's redirect budget: the
# hops before it followed `hop - 1` redirects, and one more would exceed
# `max_redirects` (§2.3, §5.3; under max_redirects = 0, the first hop).
budget_spent <- function(binding) {
  binding$hop > binding$budget$max_redirects
}

# §12 step 13: once the budget is spent, every 3xx refuses as
# redirect-limit, with or without Location (§2.3, §8 item 33).
redirect_limit_refusal <- function(binding) {
  new_ssrf_refusal(
    "redirect-limit",
    binding$hop,
    host = binding$origin$host,
    address = binding$state$pin_used %||% NA_character_,
    url = binding$url,
    detail = list(step = 13L, check = "redirect", limit = "max_redirects")
  )
}

# The host of an origin as §2.3 compares it: an address literal as its
# canonical text (INV-3), a name in §5.0's matching form. NA when raddr
# cannot format an address it read, which then matches nothing.
origin_host_key <- function(host) {
  if (!is_string(host)) {
    return(NA_character_)
  }
  address <- canonical_address(unbracket(host))
  if (!is.null(address)) {
    return(address)
  }
  paste0("name:", normalize_host_name(host))
}

# Whether two origins are the same (§2.3): equal schemes, hosts equal after
# §5.0's normalization, and equal effective ports. Anything unreadable is a
# different origin, so a doubt strips rather than carries (INV-8).
same_origin <- function(a, b) {
  ka <- origin_host_key(a$host)
  kb <- origin_host_key(b$host)
  isTRUE(
    identical(a$scheme, b$scheme) &&
      !is.na(ka) &&
      identical(ka, kb) &&
      identical(as.integer(a$port), as.integer(b$port))
  )
}

# The plan a redirect hop inherits from `plan`, the previous hop's sanitized
# plan, for the previous response's `status` (§2.3). Returns `plan`, the
# new hop's plan; `kept`, the positions in the old plan's headers of the
# fields the new one keeps, in order; and `record`, what the transformation
# did, naming fields, never values:
#   301, 302  POST becomes GET without its body; other methods are kept
#   303       HEAD stays HEAD; every other method becomes GET; no body
#   307, 308  the method and the body are kept
# Across origins the body is dropped, and every field but the nominated
# ones; Authorization, Proxy-Authorization and Cookie never cross. Whenever
# the body is dropped, the fields describing it go too, nominated or not.
redirect_plan <- function(plan, status, cross_origin) {
  method <- plan$method
  to <- method
  if (status %in% c(301L, 302L) && identical(method, "POST")) {
    to <- "GET"
  } else if (status == 303L && !identical(method, "HEAD")) {
    to <- "GET"
  }
  # The hop sends no body: the content fields go whether or not the plan
  # had one, and the record says a body was dropped only when it had.
  no_body <- cross_origin ||
    status == 303L ||
    (status %in% c(301L, 302L) && identical(method, "POST"))
  headers <- plan$headers
  lower <- ascii_lower(names(headers))
  keep <- rep(TRUE, length(headers))
  if (cross_origin) {
    keep <- lower %in% plan$carry & !lower %in% never_carryable_fields
  }
  if (no_body) {
    keep <- keep & !lower %in% body_content_fields
  }
  kept <- headers[keep]
  carry <- intersect(plan$carry, ascii_lower(names(kept)))
  list(
    plan = list(
      method = to,
      headers = kept,
      body = if (no_body) NULL else plan$body,
      carry = carry
    ),
    record = list(
      status = status,
      cross_origin = cross_origin,
      method = c(from = method, to = to),
      body_dropped = no_body && !is.null(plan$body),
      dropped = unique(lower[!keep])
    ),
    kept = which(keep)
  )
}
