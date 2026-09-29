# The loop helper (ssrfr-v1.md §2.2, §8 item 25): ssrf_fetch_chain() follows
# a redirect chain for a caller without a loop of its own. It is built only
# on the public ssrf_prepare_hop() and ssrf_fetch(), calling them exactly as
# a caller's loop would, and adds no capability they lack (§1.3). Its body
# reads nothing but those two and base R, not even `followed_statuses`;
# test-chain.R walks it to hold that line.

#' Follow a redirect chain through the guard
#'
#' Fetches a URL through the guard and follows its redirects, hop by hop,
#' for a caller without a redirect loop of its own. It is the loop
#' documented under [ssrf_prepare_hop()], and nothing more: each hop is
#' prepared with [ssrf_prepare_hop()] and fetched with [ssrf_fetch()], so
#' every hop is checked from the start, resolved once and pinned, the
#' request plan is inherited and stripped across origins, and the chain's
#' budgets are its first hop's.
#'
#' Only a followed redirect is followed: a `301`, `302`, `303`, `307` or
#' `308` response with exactly one `Location` field. The next hop is
#' prepared with `from` set to the previous binding and `url` set to the
#' `Location` value that binding recorded, byte for byte. Any other response
#' ends the chain and is returned as it is, a `304` or a `302` without
#' `Location` included. Once the chain has followed the policy's
#' `max_redirects` redirects, [ssrf_fetch()] refuses the next `3xx` as
#' `"redirect-limit"`, which ends the chain too; the helper keeps no count
#' of its own.
#'
#' It returns only the last outcome. The bindings of the hops it followed
#' are not kept, so a caller that must log every hop, as OWASP's "log all
#' accepted and blocked network flows" asks, runs the per-hop loop shown in
#' the examples of [ssrf_prepare_hop()] and logs each binding and outcome
#' itself.
#'
#' @param url The URL of the chain's first hop, a single absolute URL
#'   string.
#' @param policy The policy to decide every hop under, from
#'   [ssrf_policy()]. Its `max_redirects` and `total_timeout` bound the
#'   whole chain.
#' @param request The request plan for the first hop, a list as described
#'   under [ssrf_prepare_hop()]; `list()` is a plain `GET`. It has no
#'   default, as a first hop's plan has none. Later hops inherit it,
#'   transformed for each redirect.
#'
#' @return What the chain's last call returned, told apart by class: the
#'   final response, class `ssrfr_response`, as [ssrf_fetch()] describes
#'   it; the refusal that ended the chain, class `ssrfr_refusal`, such as
#'   `"redirect-limit"`, `"downgrade"` or an address refusal on any hop; or
#'   the operational failure that ended it, class `ssrfr_failure`. A
#'   refusal and a failure name the hop, and the host and address where
#'   they are known, for the operator; project them with
#'   [ssrf_public_reason()] before an untrusted party sees them. A misuse,
#'   such as a request plan that breaks a header rule, is the error
#'   [ssrf_prepare_hop()] raises.
#'
#' @seealso [ssrf_prepare_hop()] and [ssrf_fetch()], the per-hop primitives
#'   it is built on, for a caller with its own loop or one that logs every
#'   hop.
#'
#' @examples
#' policy <- ssrf_policy()
#'
#' # Refused before any network I/O: the chain ends at its first hop.
#' refused <- ssrf_fetch_chain(
#'   "http://169.254.169.254/latest/",
#'   policy,
#'   request = list()
#' )
#' refused$code
#' ssrf_public_reason(refused)
#'
#' \dontrun{
#' result <- ssrf_fetch_chain(
#'   "https://example.com/start",
#'   ssrf_policy(max_redirects = 5),
#'   request = list(headers = c(Authorization = "Bearer secret"))
#' )
#' if (inherits(result, "ssrfr_response")) {
#'   result$status
#'   rawToChar(result$body)
#' } else {
#'   # A refusal's code or a failure's cause, for the operator only.
#'   if (inherits(result, "ssrfr_refusal")) result$code else result$cause
#' }
#' }
#'
#' @export
ssrf_fetch_chain <- function(url, policy, request) {
  result <- ssrf_prepare_hop(url, policy, request = request)
  while (inherits(result, "ssrfr_binding")) {
    binding <- result
    result <- ssrf_fetch(binding)
    # §2.3: a followed redirect is a 301, 302, 303, 307 or 308 response with
    # exactly one Location field; anything else ends the chain.
    followed <- inherits(result, "ssrfr_response") &&
      result$status %in% c(301L, 302L, 303L, 307L, 308L) &&
      identical(binding$state$location_count, 1L)
    if (!followed) {
      break
    }
    # §2.6: the Location as the binding recorded it, byte for byte.
    result <- ssrf_prepare_hop(binding$state$location, policy, from = binding)
  }
  result
}
