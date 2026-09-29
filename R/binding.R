# L2, the guarded hop (ssrfr-v1.md §1, §2): ssrf_prepare_hop() runs steps
# 1-8 of the request lifecycle (§12) and returns a refusal, an operational
# failure, or a binding; ssrf_fetch() (R/fetch.R) consumes the binding. Only
# this layer is a defense (S2).
#
# A binding (§2.3) holds the security identity (the origin without userinfo,
# the policy by value, the hop context, the validated address set and the
# selected pin, the TLS settings bound to the hostname) and the request data
# (the wire URL without fragment, the sanitized plan). It is an environment
# with locked bindings: opacity is ergonomic, not enforceable (§2.4). Its
# `state` records what fetching it did: fetchability, spent on entry to
# ssrf_fetch() (§2.5), and the transport-observed facts (status, Location,
# the pin used, each attempt). A redirect hop (R/redirect.R) is prepared
# from the previous, spent binding, which stays referenceable (§2.5, §2.6).

# Seconds elapsed since `start`, a value of proc.time()[["elapsed"]].
elapsed_since <- function(start) {
  proc.time()[["elapsed"]] - start
}

now <- function() {
  proc.time()[["elapsed"]]
}

#' Prepare one guarded hop
#'
#' Decides whether a URL may be fetched under a policy and, when it may,
#' returns the exact connection it may use. This is the first half of the
#' guarded fetch, the only part of `ssrfr` that is a defense against
#' server-side request forgery; [ssrf_fetch()] is the second.
#'
#' The URL is parsed as the transport will parse it, checked for its scheme,
#' embedded credentials, port, host spelling and hostname rules, then, for a
#' name, resolved exactly once, with a trailing root dot so no DNS search
#' domain applies. Every address it resolves to is classified with the
#' addresses embedded in it, and one refused address refuses the whole set.
#' A URL that passes becomes a binding pinned to those validated addresses:
#' [ssrf_fetch()] connects only to them, never resolving the name again, so a
#' name cannot be rebound between the check and the connection.
#'
#' The request plan is part of the decision. It is a list of up to four
#' fields, each optional:
#' \describe{
#'   \item{`method`}{The request method, `"GET"` by default. Any HTTP token is
#'     accepted; the application decides which methods an untrusted party
#'     may choose.}
#'   \item{`headers`}{Header fields to send, as a named character vector or a
#'     named list of strings. Names must be HTTP tokens and values carry no
#'     CR or LF. Fields the transport owns (`Host`, `Connection`,
#'     `Proxy-Connection`, `Keep-Alive`, `Transfer-Encoding`, `TE`,
#'     `Trailer`, `Upgrade`, `Content-Length`, `Accept-Encoding`, `Expect`
#'     and `User-Agent`, which the policy sets) are refused, and so are the
#'     metadata-service request markers of `ssrf_vocabulary("metadata_headers")`
#'     unless the policy's `allow_ranges` names a provider endpoint exactly.}
#'   \item{`body`}{The request body: a raw vector or a single string, sent as
#'     its UTF-8 bytes. `NULL` (the default) sends none.}
#'   \item{`carry`}{Names of fields in `headers` the application asserts
#'     carry no credential, so a redirect to another origin may keep them.
#'     Every other field and the body are treated as secret.
#'     `Authorization`, `Proxy-Authorization` and `Cookie` can never be
#'     nominated.}
#' }
#' `list()` is a plain `GET`. A plan that breaks one of these rules is an
#' error of class `ssrfr_error_invalid_request`, raised before anything is
#' parsed or resolved.
#'
#' A redirect is followed hop by hop: the caller fetches a binding, and when
#' its response is a followed redirect (a `301`, `302`, `303`, `307` or `308`
#' with exactly one `Location` field) prepares the next hop with
#' `from = binding` and the `Location` value as `url`. A relative `Location`
#' is resolved against the previous hop's URL, and the new URL is checked
#' from the start, as a first hop is. The request plan is inherited, never
#' restated, and changes with the redirect:
#' \itemize{
#'   \item a `301` or `302` turns `POST` into `GET` without its body, and
#'     keeps any other method;
#'   \item a `303` keeps `HEAD` and turns every other method into `GET`,
#'     without a body;
#'   \item a `307` or `308` keeps the method and the body.
#' }
#' A redirect to another origin (another scheme, host or port) drops the
#' body and every header field but those `carry` nominated; `Authorization`,
#' `Proxy-Authorization` and `Cookie` never cross. Whenever the body is
#' dropped, so are the fields that describe it, such as `Content-Type`, even
#' when nominated. The binding's `redirect` field records what was dropped.
#' The plan the redirect hop sends is checked under that hop's policy before
#' the new name is resolved, so a field it keeps and that policy refuses,
#' such as a metadata-service marker, is an error of class
#' `ssrfr_error_invalid_request`, whose message names the field by its
#' place in `from$request`; a field the redirect dropped is not.
#' An `https` hop that redirects to `http` is refused as `"downgrade"`.
#' [ssrf_fetch_chain()] runs this loop for a caller without one of its own,
#' and returns only the chain's last outcome; a caller that must log every
#' hop runs the loop in the examples below instead.
#'
#' The chain's budgets are its first hop's: `max_redirects` and
#' `total_timeout` travel through `from`, with the time the chain has used,
#' and a redirect hop's policy that states other values is an error of class
#' `ssrfr_error_budget_change`. Every other policy field applies to the hop
#' it is passed to. Once the chain has followed `max_redirects` redirects,
#' [ssrf_fetch()] refuses the next `3xx` response as `"redirect-limit"`,
#' whether or not it carries `Location`; under `max_redirects = 0` that is
#' the first. A `from` that is not yet fetched, whose fetch failed or whose
#' response is not a followed redirect is an error of class
#' `ssrfr_error_invalid_from`. A spent binding stays usable as `from`, so a
#' hop that failed can be prepared again from the same binding.
#'
#' The binding is single-use: [ssrf_fetch()] spends it on entry. It prints
#' without userinfo, header values or the body, and holds the policy by value,
#' so a later change to the policy object does not reach it.
#'
#' @param url The URL, a single string: an absolute URL on a first hop; on a
#'   redirect hop, the `Location` value `from` recorded,
#'   `from$state$location`, byte for byte, which may be a relative
#'   reference. Any other value on a redirect hop, even the same URL spelled
#'   another way, is an error of class `ssrfr_error_invalid_from`: a redirect
#'   goes where the server pointed, and a different URL starts a new chain.
#' @param policy The policy to decide under, from [ssrf_policy()].
#' @param request The request plan for a first hop, a list as described
#'   above; `list()` for a plain `GET`. Exactly one of `request` and `from`
#'   is required.
#' @param from The binding of the previous hop, for a redirect hop: fetched,
#'   and holding a followed redirect. Its plan, origin, status and chain
#'   budgets decide the new hop's plan.
#'
#' @return One of three values, told apart by class:
#'   \describe{
#'     \item{`ssrfr_binding`}{The hop may proceed: pass it to [ssrf_fetch()].
#'       Its fields can be read with `$`: `hop`, `url` (the URL the fetch
#'       requests, without fragment), `origin` (`scheme`, `host`, `port`),
#'       `validated` (the addresses a connection may use, in resolver
#'       order), `pin` (the first of them), `request` (the sanitized plan),
#'       `policy`, `budget` (the chain's `max_redirects` and
#'       `total_timeout`, and the seconds it had used), `redirect`, `tls`
#'       and `state`, the facts [ssrf_fetch()] records. On a redirect hop,
#'       `redirect` records the previous hop and status, whether the hop
#'       crossed an origin, the method before and after, whether the body
#'       was dropped and which fields were (by lowercase name); it is `NULL`
#'       on a first hop.}
#'     \item{`ssrfr_refusal`}{The policy refuses the hop; `code` is a reason
#'       code from `ssrf_vocabulary("reason_codes")`.}
#'     \item{`ssrfr_failure`}{The hop failed on the wire before a connection:
#'       `cause` is `"unresolvable"` when resolution failed, or `"timeout"`
#'       when resolution used up the policy's `total_timeout`.}
#'   }
#'   A refusal and a failure name the hop, and the host and address where
#'   they are known, for the operator; project them with
#'   [ssrf_public_reason()] before an untrusted party sees them.
#'
#' @seealso [ssrf_fetch()] to fetch through a binding; [ssrf_fetch_chain()]
#'   to follow a whole redirect chain; [ssrf_policy()] for the rules;
#'   [ssrf_inspect_url()] to lint a URL or policy without fetching.
#'
#' @examples
#' policy <- ssrf_policy()
#'
#' # Refused before any network I/O.
#' ssrf_prepare_hop("http://127.0.0.1/admin", policy, request = list())
#' ssrf_prepare_hop("http://0177.0.0.1/", policy, request = list())$code
#'
#' # An address host needs no resolution: this binding is pinned to it.
#' binding <- ssrf_prepare_hop(
#'   "https://93.184.216.34/data?page=2",
#'   policy,
#'   request = list(headers = c(Authorization = "Bearer secret"))
#' )
#' binding
#'
#' # A request plan that breaks a header rule is an error.
#' try(ssrf_prepare_hop(
#'   "https://example.com/",
#'   policy,
#'   request = list(headers = c(Host = "internal.example"))
#' ))
#'
#' \dontrun{
#' # Following a redirect chain: prepare each hop from the previous binding.
#' result <- ssrf_prepare_hop(
#'   "https://example.com/old",
#'   policy,
#'   request = list(headers = c(Authorization = "Bearer secret"))
#' )
#' while (inherits(result, "ssrfr_binding")) {
#'   binding <- result
#'   result <- ssrf_fetch(binding)
#'   followed <- inherits(result, "ssrfr_response") &&
#'     result$status %in% c(301, 302, 303, 307, 308) &&
#'     identical(binding$state$location_count, 1L)
#'   if (!followed) {
#'     break
#'   }
#'   # A relative Location is resolved against the previous hop's URL, and
#'   # Authorization is dropped if the redirect leaves the origin.
#'   result <- ssrf_prepare_hop(binding$state$location, policy, from = binding)
#' }
#' # `result` is the chain's final outcome. Log a code or cause for the
#' # operator; show an untrusted party only ssrf_public_reason(result).
#' outcome <- if (inherits(result, "ssrfr_response")) {
#'   result$body # the body's bytes, a raw vector, whatever they hold
#' } else if (inherits(result, "ssrfr_refusal")) {
#'   result$code # "redirect-limit" once max_redirects redirects are followed
#' } else {
#'   result$cause # an operational failure
#' }
#' }
#'
#' @export
ssrf_prepare_hop <- function(url, policy, request = NULL, from = NULL) {
  started <- now()
  bad <- function(message) {
    abort_ssrfr("invalid_argument", message, fn = "ssrf_prepare_hop")
  }
  if (!is_string(url)) {
    bad("`url` must be a single string.")
  }
  if (missing(policy) || !inherits(policy, "ssrfr_policy")) {
    bad("`policy` must be a policy built by ssrf_policy().")
  }
  if (!is.null(request) && !is.null(from)) {
    bad("Pass `request` on a first hop or `from` on a redirect hop, not both.")
  }
  if (is.null(request) && is.null(from)) {
    bad(paste0(
      "A first hop needs `request`, its request plan (`list()` is a plain ",
      "GET); a redirect hop needs `from`, the previous hop's binding."
    ))
  }
  if (is.null(from)) {
    plan <- check_request(request, policy)
    return(prepare_hop(enc2utf8(url), policy, plan, started))
  }
  check_from(from, policy)
  # §2.6: a redirect goes where the server pointed. `url` is the Location
  # `from` recorded, compared as bytes: identical() may call two strings in
  # different encodings equal.
  if (!identical(charToRaw(url), charToRaw(from$state$location))) {
    abort_ssrfr(
      "invalid_from",
      paste0(
        "`url` is not the `Location` value `from` recorded, byte for byte; a ",
        "redirect hop goes where the previous response pointed. Start a new ",
        "chain with `request` to fetch another URL."
      ),
      fn = "ssrf_prepare_hop"
    )
  }
  # The hop is prepared from the value `from` recorded, never from `url`:
  # the same bytes marked in another encoding would re-encode into another
  # URL. enc2utf8() leaves a recorded value as it is, UTF-8, ASCII or
  # "bytes", so an exact copy is prepared as it always was.
  location <- enc2utf8(from$state$location)
  # §2.3: the inherited plan is never re-supplied; prepare_hop() transforms
  # it for the redirect and checks what the new hop sends.
  prepare_hop(location, policy, from$request, started, from = from)
}

# Steps 1-8 for a hop: a first hop, whose request plan is valid, or, with
# `from`, a redirect hop, whose URL is resolved against the previous hop's
# (§3.2) and whose plan is `from`'s, transformed for the previous response
# (§2.3) once the new origin is known. Returns a refusal, a failure or a
# binding.
prepare_hop <- function(url, policy, plan, started, from = NULL) {
  hop_index <- if (is.null(from)) 1L else from$hop + 1L
  # §2.5: the time the chain consumed before this call counts against
  # total_timeout.
  before <- if (is.null(from)) 0 else from$state$elapsed
  hop <- parse_hop(
    url,
    policy,
    base = from$url,
    base_scheme = from$origin$scheme
  )
  # An outcome records the URL the hop resolved to (§3.2): on a redirect hop,
  # not a Location that may be relative, which would display as withheld.
  # Only a hop whose Location did not resolve records the Location.
  shown <- hop$url %||% url
  redirect <- NULL
  if (!is.null(from) && is.null(hop$finding)) {
    origin <- list(scheme = hop$scheme, host = hop$host, port = hop$port)
    inherited <- redirect_plan(
      plan,
      from$state$status,
      cross_origin = !same_origin(from$origin, origin)
    )
    # §2.3, §2.5: the plan this hop sends, once the redirect has dropped
    # what it drops, is checked under this hop's policy, which may not admit
    # a field the previous hop's did. A dropped field is not checked. The
    # caller passed `from`, not `request`, so a message names an entry by
    # its place in `from$request`, the plan inherited, not in the plan
    # derived from it.
    label <- plan_label("from$request", function(field, i) {
      switch(
        field,
        headers = inherited$kept[[i]],
        carry = match(inherited$plan$carry[[i]], from$request$carry),
        i
      )
    })
    plan <- check_request(inherited$plan, policy, label)
    redirect <- c(list(from_hop = from$hop), inherited$record)
  }
  if (is.null(hop$finding)) {
    hop$finding <- host_policy(hop, policy)
  }
  validated <- character()
  if (is.null(hop$finding) && hop$host_kind %in% c("ipv4", "ipv6")) {
    gates <- address_gates(hop$address, policy)
    hop$finding <- gates$finding
    if (is.null(hop$finding)) {
      # The pin target is the literal's canonical text (r-binding.md §2.6).
      canonical <- canonical_address(hop$address)
      if (!is_string(canonical)) {
        hop$finding <- new_finding(
          "malformed-address",
          8L,
          address = hop$address,
          gate = "1b",
          tier = 1L
        )
      }
      validated <- canonical
    }
    if (!is.null(hop$finding)) {
      hop$finding$host <- hop$host
    }
  } else if (is.null(hop$finding)) {
    resolution <- resolve_hop(hop, policy)
    hop$finding <- resolution$finding
    validated <- resolution$validated
  }
  if (!is.null(hop$finding)) {
    return(outcome_of(hop$finding, hop_index, shown))
  }
  # §5.3: elapsed time is re-checked after resolution.
  spent <- before + elapsed_since(started)
  if (spent >= policy$total_timeout) {
    return(new_ssrf_failure(
      "timeout",
      hop_index,
      host = hop$host,
      url = shown,
      detail = list(step = 7L, check = "total", limit = "total_timeout")
    ))
  }
  new_binding(hop, policy, plan, validated, hop_index, spent, redirect)
}

# A finding of steps 1-8 as the outcome ssrf_prepare_hop() returns: a refusal
# for a reason code, a failure for a cause.
outcome_of <- function(finding, hop_index, url) {
  host <- finding$host
  address <- finding$address
  host <- if (is_string(host)) host else NA_character_
  address <- if (is_string(address)) address else NA_character_
  if (!is.null(finding$cause)) {
    return(new_ssrf_failure(
      finding$cause,
      hop_index,
      host = host,
      address = address,
      url = url,
      detail = finding$detail
    ))
  }
  new_ssrf_refusal(
    finding$code,
    hop_index,
    host = host,
    address = address,
    url = url,
    detail = finding$detail
  )
}

new_binding <- function(
  hop,
  policy,
  plan,
  validated,
  hop_index,
  spent,
  redirect = NULL
) {
  b <- new.env(parent = emptyenv())
  b$hop <- hop_index
  b$redirect <- redirect
  b$url <- hop$wire
  b$origin <- list(scheme = hop$scheme, host = hop$host, port = hop$port)
  b$policy <- policy
  b$request <- plan
  b$validated <- validated
  b$pin <- validated[[1L]]
  b$tls <- list(verify_peer = TRUE, verify_host = TRUE, name = hop$host)
  b$budget <- list(
    max_redirects = policy$max_redirects,
    total_timeout = policy$total_timeout,
    elapsed = spent
  )
  # §2.4: the values live in a private store; `state` shows each field as a
  # read-only active binding and is locked once, never unlocked. The store
  # is `state`'s enclosure, where only set_state() looks for it.
  store <- list2env(
    list(
      fetchable = TRUE,
      fetched = FALSE,
      status = NULL,
      location = NULL,
      location_count = NULL,
      outcome = NULL,
      pin_used = NULL,
      attempts = character(),
      elapsed = spent
    ),
    parent = emptyenv()
  )
  state <- new.env(parent = store)
  for (field in names(store)) {
    makeActiveBinding(field, state_field(store, field), state)
  }
  lockEnvironment(state, bindings = TRUE)
  b$state <- state
  lockEnvironment(b, bindings = TRUE)
  class(b) <- "ssrfr_binding"
  b
}

# The active binding that shows `field` of a binding's store. It takes no
# value: new_binding() locks it, so R refuses a write before calling it. A
# read never errors, since the transport reads state inside libcurl
# callbacks (r-binding.md §7).
state_field <- function(store, field) {
  force(field)
  function() store[[field]]
}

# Writes the named fields of a binding's state into its store. Only ssrfr
# writes it, so a name that is not a state field is a defect in ssrfr. A
# valid write never errors: it may run inside a libcurl callback.
set_state <- function(binding, ...) {
  values <- list(...)
  store <- parent.env(binding$state)
  fields <- names(values) %||% rep("", length(values))
  if (!all(fields %in% names(store))) {
    internal_error("set_state() names a field a binding's state lacks.")
  }
  for (field in fields) {
    assign(field, values[[field]], envir = store)
  }
  invisible(binding)
}

#' @export
format.ssrfr_binding <- function(x, ...) {
  state <- x$state
  plan <- x$request
  fields <- names(plan$headers)
  headers <- if (length(fields)) {
    paste0(toString(fields), " (values withheld)")
  } else {
    "none"
  }
  body <- if (is.null(plan$body)) {
    "none"
  } else {
    paste0(length(plan$body), " bytes (withheld)")
  }
  status <- if (isTRUE(state$fetchable)) {
    "fetchable"
  } else if (isTRUE(state$fetched)) {
    "spent: fetched"
  } else {
    "spent"
  }
  origin <- x$origin
  redirect <- x$redirect
  if (!is.null(redirect)) {
    redirect <- paste0(
      "  redirect: ",
      redirect$status,
      " from hop ",
      redirect$from_hop,
      if (redirect$cross_origin) ", cross-origin" else ", same origin",
      if (length(redirect$dropped)) {
        paste0("; dropped ", toString(redirect$dropped))
      },
      if (redirect$body_dropped) "; body dropped"
    )
  }
  c(
    paste0("<ssrfr_binding> (hop ", x$hop, ", ", status, ")"),
    paste0(
      "  origin: ",
      origin$scheme,
      "://",
      origin$host,
      ":",
      origin$port
    ),
    paste0("  url: ", redact_url(x$url)),
    paste0("  validated: ", toString(x$validated)),
    paste0("  pin: ", state$pin_used %||% x$pin),
    paste0("  method: ", plan$method),
    paste0("  headers: ", headers),
    paste0("  body: ", body),
    if (length(plan$carry)) paste0("  carry: ", toString(plan$carry)),
    redirect,
    "  tls: certificate and hostname verified",
    if (!is.null(state$status)) paste0("  status: ", state$status),
    if (!is.null(state$outcome)) paste0("  outcome: ", state$outcome)
  )
}

#' @export
print.ssrfr_binding <- function(x, ...) {
  cat(format(x, ...), sep = "\n")
  invisible(x)
}
