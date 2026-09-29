# ssrf_fetch() (ssrfr-v1.md §2.2, §2.5, §12 steps 9-13, §14): consumes a
# binding, connects only to its validated addresses through a `connect_to`
# pin, checks the pin held, reads the whole response within the limits, and
# refuses a 3xx past the chain's redirect budget (step 13, R/redirect.R).
#
# Failover (§2.5): the validated addresses are tried in resolver order, and
# the next is tried only after an attempt that ended before a connection was
# established. `pin-mismatch` ends the fetch at once. When every address has
# been tried, the cause is `timeout` if every attempt's connect timed out and
# `connect-failed` otherwise (§6.6). There are no retries: the request is sent
# at most once.

# Causes of an attempt that established a connection, by curl error class.
# Every TLS failure is `tls-failed`; a class not listed is `protocol-error`.
# A size limit is never libcurl's: ssrfr's own callbacks count the header
# and the decoded body, and record the limit they reached.
curl_error_causes <- c(
  curl_error_operation_timedout = "timeout",
  curl_error_peer_failed_verification = "tls-failed",
  curl_error_use_ssl_failed = "tls-failed"
)

connected_cause <- function(error) {
  if (startsWith(error, "curl_error_ssl_")) {
    return("tls-failed")
  }
  cause <- curl_error_causes[error]
  if (is.na(cause)) "protocol-error" else unname(cause)
}

#' Fetch through a guarded binding
#'
#' Makes the request a binding from [ssrf_prepare_hop()] describes, connecting
#' only to an address that binding validated. The name is never resolved
#' again: the connection is pinned to the validated address while TLS, the
#' `Host` header and certificate verification stay bound to the hostname.
#' Certificate verification is never weakened, no proxy is used whatever the
#' environment says, redirects are not followed, and the request goes over
#' HTTP/1.1 on a new connection that is closed when the fetch returns.
#'
#' A binding is single-use. `ssrf_fetch()` spends it on entry, so a second
#' call with the same binding is an error of class
#' `ssrfr_error_spent_binding`, even when the first was interrupted. The
#' spent binding stays readable: its `state` records the response status,
#' the `Location` field, the address the connection was pinned to and each
#' address tried.
#'
#' When a name resolved to several addresses, they are tried in the order
#' the resolver returned them, moving on only when a connection could not be
#' established; a request is never sent twice. After connecting, `ssrfr`
#' confirms from libcurl's trace that the connection went to the pinned
#' address; if it cannot, the fetch fails as `"pin-mismatch"` without trying
#' another address.
#'
#' The whole response is read before `ssrf_fetch()` returns, within the
#' policy's limits: `max_response_size` counts the body's bytes after any
#' `gzip` or `deflate` decoding, as they arrive, so a compressed body cannot
#' exceed it; `max_header_bytes` and `max_header_fields` bound the header,
#' including any interim `1xx` responses and the trailer fields of a chunked
#' body, as it arrives;
#' `connect_timeout` bounds each connection attempt and `total_timeout` the
#' time spent in `ssrfr` for the chain, decoding included.
#'
#' A redirect is returned, not followed: its status and `Location` are in the
#' response, and the next hop is prepared with
#' `ssrf_prepare_hop(location, policy, from = binding)`. A caller that wants
#' the whole chain followed calls [ssrf_fetch_chain()] from the first hop,
#' in place of [ssrf_prepare_hop()] and `ssrf_fetch()`; it cannot take over
#' a redirect already in hand. Once the chain has followed the policy's
#' `max_redirects` redirects, a `3xx` response is refused as
#' `"redirect-limit"` instead, with or without `Location`; under
#' `max_redirects = 0` every `3xx` is. The refusal is decided at the status
#' line and the transfer stopped there, so nothing after it changes it: not
#' a second `Location`, nor a body over the limits or one that stalls.
#' `ssrfr` guards only requests made
#' through a binding. R's own
#' `download.file()`, `url()`, `readLines()` on a URL, direct `curl` calls,
#' and the packages that read URLs through them, such as
#' `jsonlite::fromJSON(url)`, `data.table::fread(url)` and
#' `xml2::read_xml(url)`, stay unguarded, as does the `curl` command-line
#' tool.
#'
#' @section Testing against a local server:
#' A loopback server is a refused destination, so a test that fetches one
#' through the guard reopens loopback in its own policy, with
#' `ssrf_policy(allow_ranges = "127.0.0.0/8", allow_ports = <port>)`. `ssrfr`
#' has no test mode and no switch that turns the guard off; keep such a
#' policy out of production code.
#'
#' @param binding A binding from [ssrf_prepare_hop()] that has not been
#'   fetched.
#'
#' @return A response, class `ssrfr_response`; an operational failure, class
#'   `ssrfr_failure`; or, for a `3xx` response past the chain's redirect
#'   budget, a refusal, class `ssrfr_refusal`, with code
#'   `"redirect-limit"`.
#'
#'   A response is a plain list that owns no handle, connection or file:
#'   `status` (the HTTP status code), `headers` (the final response's header
#'   fields, a character vector named by lowercase field name, without the
#'   trailer fields of a chunked body; a value that is not valid UTF-8 is
#'   kept byte for byte and marked `"bytes"`) and `body` (the decoded
#'   body, a raw vector; `rawToChar(response$body)` reads text). Its
#'   `print()` and `format()` show only the status, the media type and the
#'   body size, never the body or another header value.
#'
#'   A failure carries `cause`, from `ssrf_vocabulary("causes")`:
#'   `"connect-failed"`, `"timeout"`, `"tls-failed"`, `"pin-mismatch"`,
#'   `"response-too-large"` or `"protocol-error"`. Its `detail` lists each
#'   address tried and how the attempt ended, and names the limit that was
#'   reached.
#'
#' @seealso [ssrf_prepare_hop()], which makes the binding;
#'   [ssrf_public_reason()] before a failure reaches an untrusted party.
#'
#' @examples
#' binding <- ssrf_prepare_hop(
#'   "https://93.184.216.34/",
#'   ssrf_policy(),
#'   request = list()
#' )
#' \dontrun{
#' response <- ssrf_fetch(binding)
#' response
#' response$status
#' rawToChar(response$body)
#'
#' # A binding is spent on first use.
#' try(ssrf_fetch(binding))
#' binding$state$status
#' }
#'
#' # In a test, reach a local server by reopening loopback in the policy:
#' test_policy <- ssrf_policy(allow_ranges = "127.0.0.0/8", allow_ports = 8080)
#' ssrf_prepare_hop("http://127.0.0.1:8080/", test_policy, request = list())
#'
#' @export
ssrf_fetch <- function(binding) {
  if (!inherits(binding, "ssrfr_binding")) {
    abort_ssrfr(
      "invalid_argument",
      "`binding` must be a binding returned by ssrf_prepare_hop().",
      fn = "ssrf_fetch"
    )
  }
  if (!isTRUE(binding$state$fetchable)) {
    abort_ssrfr(
      "spent_binding",
      "This binding was already fetched; prepare the hop again.",
      fn = "ssrf_fetch"
    )
  }
  # §2.5: fetchability is spent on entry, before anything can fail.
  set_state(binding, fetchable = FALSE)
  started <- now()
  on.exit(
    set_state(
      binding,
      elapsed = binding$budget$elapsed + elapsed_since(started)
    ),
    add = TRUE
  )
  # A 3xx past the chain's redirect budget comes back as the redirect-limit
  # refusal (§12 step 13), decided in the attempt at its status line.
  result <- guarded_transfer(binding, started)
  set_state(
    binding,
    outcome = if (inherits(result, "ssrfr_response")) {
      "response"
    } else if (inherits(result, "ssrfr_refusal")) {
      result$code
    } else {
      result$cause
    }
  )
  result
}

# Steps 9-13 over the validated addresses, in resolver order.
guarded_transfer <- function(binding, started) {
  budget <- binding$budget$total_timeout - binding$budget$elapsed
  remaining <- function() budget - elapsed_since(started)
  capabilities <- session_curl_capabilities()
  endings <- character()
  # §6.6: no attempt is made once total_timeout is spent, the first
  # included; the check after a failed attempt below covers each later one.
  if (remaining() <= 0) {
    return(total_timeout_failure(binding, NA_character_, endings, step = 10L))
  }
  for (address in binding$validated) {
    attempt <- attempt_address(binding, address, remaining, capabilities)
    endings <- c(endings, paste(address, attempt$ending))
    set_state(binding, attempts = endings)
    if (attempt$ending == "pin-mismatch") {
      return(fetch_failure(
        binding,
        "pin-mismatch",
        address,
        endings,
        step = 11L,
        check = attempt$check,
        callback = attempt$callback
      ))
    }
    if (attempt$ending %in% c("connect-failed", "connect-timeout")) {
      if (remaining() <= 0) {
        return(total_timeout_failure(binding, address, endings, step = 10L))
      }
      next
    }
    set_state(binding, pin_used = address)
    # §12 step 13, decided at the status: the binding records the status it
    # observed, and no response, so it is never a `from`.
    if (!is.null(attempt$redirect_limit)) {
      set_state(binding, status = attempt$redirect_limit)
      return(redirect_limit_refusal(binding))
    }
    if (!is.null(attempt$cause)) {
      return(fetch_failure(
        binding,
        attempt$cause,
        address,
        endings,
        step = attempt$step,
        check = attempt$check,
        limit = attempt$limit,
        callback = attempt$callback
      ))
    }
    # §5.3: elapsed time is re-checked after decoding, which the transport's
    # own timer does not preempt.
    if (remaining() <= 0) {
      return(total_timeout_failure(binding, address, endings, step = 12L))
    }
    # The binding records a successful response only now (§2.3).
    set_state(binding, fetched = TRUE)
    return(attempt$response)
  }
  timed_out <- all(endsWith(endings, " connect-timeout"))
  fetch_failure(
    binding,
    if (timed_out) "timeout" else "connect-failed",
    NA_character_,
    endings,
    step = 10L,
    check = "failover-exhausted"
  )
}

# §6.6: total_timeout elapsing is `timeout` wherever it happens; `address`
# is the one last attempted.
total_timeout_failure <- function(binding, address, endings, step) {
  fetch_failure(
    binding,
    "timeout",
    address,
    endings,
    step = step,
    check = "total",
    limit = "total_timeout"
  )
}

fetch_failure <- function(binding, cause, address, endings, step, ...) {
  detail <- c(list(step = as.integer(step)), Filter(Negate(is.null), list(...)))
  if (length(endings)) {
    detail$attempts <- endings
  }
  new_ssrf_failure(
    cause,
    binding$hop,
    host = binding$origin$host,
    address = address,
    url = binding$url,
    detail = detail
  )
}

# One connection attempt at `address`. Returns a list: `ending`, how the
# attempt ended ("pin-mismatch", "connect-failed", "connect-timeout", or
# "connected"); for a connected attempt `cause` (with `step`, `check`,
# `limit` and `callback`), `redirect_limit` (the status of a 3xx past the
# redirect budget, §12 step 13) or `response`; for a pin mismatch, `check`
# and `callback`. `callback` is every callback that failed, in the order
# they first did, or NULL when none did.
attempt_address <- function(binding, address, remaining, capabilities) {
  policy <- binding$policy
  opts <- transport_options(binding, address, remaining(), capabilities)
  seen <- new.env(parent = emptyenv())
  seen$trace <- character()
  seen$header_bytes <- 0
  seen$header_fields <- 0L
  seen$body <- list()
  seen$bytes <- 0
  seen$body_started <- FALSE
  seen$body_since_progress <- FALSE
  seen$abort <- NULL
  # Records the limit reached and answers FALSE, which ends the transfer:
  # the transport wrapper cancels it within the round (R/dependencies.R).
  abort <- function(cause, check, limit) {
    seen$abort <- list(cause = cause, check = check, limit = limit)
    FALSE
  }
  # Measures the header buffer and answers FALSE, through the same record,
  # when what it holds ends the transfer: a header limit, or a 3xx past the
  # chain's redirect budget (header_stop()). Answers TRUE to go on. The
  # decision reads only what measure_header() records, so a buffer that has
  # not grown since the last one, which went on, is not decided again; every
  # buffer that has grown is.
  header_check <- function(buffer) {
    if (!measure_header(seen, buffer)) {
      return(TRUE)
    }
    stop <- header_stop(seen, policy, binding)
    if (is.null(stop)) {
      return(TRUE)
    }
    seen$abort <- stop
    FALSE
  }
  # Every text match here is byte by byte: a trace line may carry obs-text,
  # and a failed translation would warn with the line's bytes (INV-12).
  debug <- function(type, msg) {
    if (type == 0L) {
      text <- tryCatch(rawToChar(msg), error = function(e) "")
      lines <- strsplit(text, "\n", fixed = TRUE, useBytes = TRUE)[[1L]]
      lines <- gsub("^[ \t\r]+|[ \t\r]+$", "", lines, useBytes = TRUE)
      seen$trace <- c(
        seen$trace,
        grep("^(Trying|Connected to) ", lines, value = TRUE, useBytes = TRUE)
      )
    }
    NULL
  }
  # Answers TRUE to go on. The header is complete when the first body byte
  # arrives, so a header over its limits, or a 3xx past the redirect budget,
  # ends the transfer there, before any body byte is counted (§6.6, §12 step
  # 13). `received` is the transport wrapper's header buffer reader.
  on_body <- function(x, received) {
    if (!length(x)) {
      return(TRUE)
    }
    seen$body_since_progress <- TRUE
    if (!seen$body_started) {
      seen$body_started <- TRUE
      if (!header_check(received())) {
        return(FALSE)
      }
    }
    if (remaining() <= 0) {
      return(abort("timeout", "total", "total_timeout"))
    }
    # §5.3: decoded bytes, counted on each delivery; the delivery that passes
    # the limit is not kept.
    if (seen$bytes + length(x) > policy$max_response_size) {
      return(abort("response-too-large", "decoded-bytes", "max_response_size"))
    }
    seen$bytes <- seen$bytes + length(x)
    seen$body[[length(seen$body) + 1L]] <- x
    TRUE
  }
  # §14: the header limits hold while the header arrives, not only once a
  # body does. libcurl calls this after each read and whenever it waits, so
  # a header that never ends, a run of 1xx blocks, or an endless header on
  # a response with no body stops at its limit, not at total_timeout. A
  # chunked body's trailer lines count against the same limits as they
  # arrive. Both are measured from one source, libcurl's header buffer
  # (`received()`), never from the trace, which a build may not write for
  # every read. The buffer grows only while no body byte is delivered: before
  # the body, and after it as trailers. So it is read only on a call that no
  # delivery preceded, which keeps a body in flight from paying for it, and
  # scanned only when it has grown, so an idle wait pays for no scan and
  # each scan costs at most the header limit plus one read. The same check
  # stops a 3xx past the redirect budget once its status line is in the
  # buffer, so a body that stalls before its first byte does not run the
  # transfer to total_timeout (§12 step 13). Answers TRUE to go on.
  progress <- function(down, up, received) {
    if (!is.null(seen$abort)) {
      return(FALSE)
    }
    if (!seen$body_since_progress && !header_check(received())) {
      return(FALSE)
    }
    seen$body_since_progress <- FALSE
    TRUE
  }

  transfer <- read_transfer(opts, on_body, debug, progress)
  if (is.null(transfer)) {
    return(list(ending = "pin-mismatch", check = "no-transfer"))
  }
  # The callbacks that raised an error, which the wrapper caught (a defect,
  # never a limit), in the order they first failed.
  failed <- transfer$failed
  # INV-5: the detector runs on every attempt, whatever its outcome. Absent or
  # unreadable evidence is a mismatch (§6.6), and so is a trace whose
  # callback failed: evidence it may have missed cannot confirm the pin. The
  # mismatch names every callback that failed, in that order, whatever the
  # check: which one cut the trace short is not inferred, since whether
  # libcurl traces `Trying` before its first progress call is the build's.
  pin <- pin_check(seen$trace, address, binding$origin$port)
  traced <- !"debug" %in% failed
  if (pin == "match" && !traced) {
    pin <- "trace-error"
  }
  if (pin != "match") {
    return(list(ending = "pin-mismatch", check = pin, callback = failed))
  }
  connected <- transfer$connect > 0 ||
    any(startsWith(seen$trace, "Connected to "))
  # A transfer a callback stopped leaves a record, read below: the limit
  # reached (`seen$abort`) or the callback's failure (`failed`).
  stopped <- transfer$aborted
  if (!stopped && !is.null(transfer$error) && !connected) {
    timed_out <- transfer$error == "curl_error_operation_timedout"
    return(list(
      ending = if (timed_out) "connect-timeout" else "connect-failed"
    ))
  }
  ended <- function(cause, step, check, limit = NULL, callback = NULL) {
    list(
      ending = "connected",
      cause = cause,
      step = step,
      check = check,
      limit = limit,
      callback = callback
    )
  }
  # A limit record, left by header_stop() or a callback, as the attempt's
  # ending.
  ended_at_limit <- function(record) {
    ended(record$cause, 12L, record$check, record$limit)
  }
  # The record a callback left decides, unless it is a 3xx past the
  # redirect budget: one recorded in flight is decided once more below, with
  # a completed transfer's, now that libcurl's status is known (§2.3), so the
  # same bytes end the same way whenever the transfer stopped.
  record <- seen$abort
  if (is.null(record)) {
    # A callback that failed ends the transfer, and fails closed. No
    # cause names a defect of ssrfr's own (§6.6); the closest is
    # `protocol-error`, the check says what happened, and the callback names
    # every callback that failed, in that order. The condition itself is not
    # kept: its message may quote response bytes (INV-12).
    if (length(failed)) {
      return(ended("protocol-error", 12L, "callback-error", callback = failed))
    }
    # INV-11: a transfer the wrapper reports stopped, with neither record,
    # is never a response, however whole its header looks.
    if (stopped) {
      return(ended("protocol-error", 12L, "aborted"))
    }
  } else if (is.null(record$redirect_limit)) {
    # A limit a callback reached ends the transfer, which the wrapper
    # cancels, as that record says.
    return(ended_at_limit(record))
  }
  # The header is complete before libcurl ends a transfer on its own limits,
  # so a header limit it passed was the first limit reached (§6.6), and a
  # 3xx past the redirect budget was decided at its status line, before
  # anything libcurl did afterwards (§12 step 13), unless libcurl reports
  # another status (header_stop()). The buffer is measured once more here,
  # before any response is recorded, for header and trailer lines that
  # arrived after the last progress call.
  measure_header(seen, transfer$headers)
  stop <- header_stop(seen, policy, binding, transfer$status)
  if (!is.null(stop)) {
    # A 3xx past the redirect budget carries its status (§12 step 13).
    if (!is.null(stop$redirect_limit)) {
      return(list(ending = "connected", redirect_limit = stop$redirect_limit))
    }
    return(ended_at_limit(stop))
  }
  if (!is.null(transfer$error)) {
    cause <- connected_cause(transfer$error)
    limit <- if (cause == "timeout") "total_timeout"
    step <- if (cause == "tls-failed") 10L else 12L
    return(ended(cause, step, "transport", limit))
  }
  # INV-11: a transfer the wrapper reports stopped is never a response, and
  # `stopped` alone decides that, whatever the parse would read: a stopped
  # transfer is never parsed, and ends here before a status or a response
  # is recorded. Only one stopped at a 3xx past the redirect budget gets
  # here, and only when libcurl reports a status other than the status
  # line's, so step 13 decided nothing (§12): it ends as any transfer whose
  # two statuses disagree.
  if (stopped) {
    return(ended("protocol-error", 12L, "header"))
  }
  # The status libcurl reports and the header block ssrfr reads must be the
  # same response's: the status is transport-observed (§2.3), and a
  # disagreement records neither. The parse reads the segments the measure
  # above took of these same bytes, never segmenting them again.
  segments <- if (identical(seen$segmented, transfer$headers)) seen$segments
  parsed <- parse_response_headers(transfer$headers, segments)
  if (is.null(parsed) || parsed$status != transfer$status) {
    return(ended("protocol-error", 12L, "header"))
  }
  headers <- parsed$headers
  locations <- unname(headers[names(headers) == "location"])
  set_state(
    binding,
    status = as.integer(transfer$status),
    location_count = length(locations),
    location = if (length(locations) == 1L) locations else NULL
  )
  # §2.3, §6.6: more than one Location field line.
  if (length(locations) > 1L) {
    return(ended("protocol-error", 12L, "location"))
  }
  list(
    ending = "connected",
    response = new_ssrf_response(
      transfer$status,
      headers,
      if (length(seen$body)) do.call(c, seen$body) else raw()
    )
  )
}

# What the header buffer measure_header() last measured ends the transfer
# with, or NULL: a header limit (§5.3), as an abort record, or, once the
# final response's status line is a 3xx and the chain's redirect budget is
# spent, `redirect_limit`, that status (§2.3, §12 step 13, §8 item 33). The
# status line decides: a header limit that the bytes up to its end passed,
# in interim 1xx blocks or in the line itself, was reached first and wins
# (§6.6), and nothing after it (its fields, a second Location, the body,
# trailers, a stall or an error of libcurl's) changes the outcome, unless
# libcurl reports another status: then step 13 decides nothing, and a step
# 12 limit or a transport error that came first decides (`reported`,
# below; §12). A status line is final when it is not 1xx, whether or not
# its block has ended; libcurl writes whole lines to the buffer.
#
# `reported` is the status libcurl reports, NULL while it is not known (in
# flight), or 0 when libcurl reports none. The status step 13 records is
# transport-observed (§2.3): when libcurl reports one that is not the
# status line's, step 13 decides nothing, and the transfer ends as any
# other whose two statuses disagree: a header limit reached first, here,
# else the transport's error or `protocol-error` (attempt_address()).
header_stop <- function(seen, policy, binding, reported = NULL) {
  blocks <- seen$segments$blocks
  final <- which(blocks$status >= 200L)
  if (length(final) && budget_spent(binding)) {
    status <- blocks$status[[final]]
    if (status >= 300L && status <= 399L) {
      # The bytes and fields through the status line, which count before
      # the decision (§6.6: a limit the line itself passes was reached
      # first), by the rule the whole buffer is counted by.
      through <- header_size(seen$segments, blocks$start[[final]])
      over <- header_limit(through, policy)
      if (!is.null(over)) {
        return(header_limit_stop(over))
      }
      if (is.null(reported) || reported == 0 || reported == status) {
        return(list(redirect_limit = status))
      }
    }
  }
  over <- header_limit(seen, policy)
  if (!is.null(over)) header_limit_stop(over)
}

header_limit_stop <- function(limit) {
  list(cause = "response-too-large", check = "header", limit = limit)
}

# The header limit the response has passed (§5.3), or NULL. A chunked
# body's trailer fields count against the same limits as the header.
header_limit <- function(seen, policy) {
  if (seen$header_bytes > policy$max_header_bytes) {
    return("max_header_bytes")
  }
  if (seen$header_fields > policy$max_header_fields) {
    return("max_header_fields")
  }
  NULL
}

# Records the size of `buffer`, libcurl's header buffer so far, as
# header_size() counts it through its last line. The lines are read as
# header_segments() (R/transport.R) reads them for the parse, by the block
# before each: a block cut short is still a header block, and every line
# after a complete final block is a trailer line, so a count taken while the
# buffer arrives and one taken once it is whole agree. The buffer only
# grows, so a buffer of the length last measured is not scanned again, and
# one that extends the last is segmented on from where that reading
# stopped, which keeps the scans of every growth together linear in the
# buffer; any other buffer is segmented whole.
# Returns, invisibly, whether it measured.
measure_header <- function(seen, buffer) {
  # The bytes last measured, which seen$segments read.
  last <- seen$segmented
  if (!is.raw(buffer) || (is.raw(last) && length(buffer) == length(last))) {
    return(invisible(FALSE))
  }
  extends <- length(buffer) > length(last) &&
    identical(buffer[seq_along(last)], last)
  segments <- header_segments(buffer, if (extends) seen$segments)
  size <- header_size(segments, length(segments$lines))
  seen$header_bytes <- size$header_bytes
  seen$header_fields <- size$header_fields
  # Kept for the parse of a completed transfer, with the bytes they read.
  seen$segmented <- buffer
  seen$segments <- segments
  invisible(TRUE)
}

# The size of a segmented header buffer through its line `n`, the one
# counting rule the header limits read (§5.3): every byte through that
# line's end, and as fields every line but an empty one and the status line
# that opens a header block: every other header line, and every trailer
# line that is not empty.
header_size <- function(segments, n) {
  list(
    header_bytes = if (n > 0L) segments$ends[[n]] else 0L,
    header_fields = sum(nzchar(segments$lines[seq_len(n)])) -
      sum(segments$blocks$start <= n)
  )
}

new_ssrf_response <- function(status, headers, body) {
  structure(
    list(status = as.integer(status), headers = headers, body = body),
    class = "ssrfr_response"
  )
}

#' @export
format.ssrfr_response <- function(x, ...) {
  type <- display_media_type(unname(x$headers[
    names(x$headers) == "content-type"
  ]))
  c(
    "<ssrfr_response>",
    paste0("  status: ", x$status),
    paste0("  type: ", if (is.na(type)) "none" else type),
    paste0("  body: ", length(x$body), " bytes (read it with $body)")
  )
}

#' @export
print.ssrfr_response <- function(x, ...) {
  cat(format(x, ...), sep = "\n")
  invisible(x)
}
