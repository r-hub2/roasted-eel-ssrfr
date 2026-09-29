# ssrf_fetch() end to end (ssrfr-v1.md §2.2, §2.5, §5.3, §6.6, §12 steps
# 9-12, §14, INV-5, INV-6, INV-9, INV-10, INV-12), and the behaviour tests of
# r-binding.md §7 that need a server. Every server is on loopback, every
# host a `.invalid` name the resolver mock maps to it, so a fetch that
# arrives proves the pin was used.

# --- the pin -----------------------------------------------------------------

test_that("the pin is load-bearing and Host is kept", {
  skip_if_no_webfakes()
  web <- local_test_server()
  port <- web$get_port()
  seen <- mock_answers("127.0.0.1")
  r <- guarded_get(pinned_url(port), loopback_policy(port))
  expect_s3_class(r, "ssrfr_response")
  expect_identical(r$status, 200L)
  expect_identical(body_text(r), paste0("host=", pinned_host, ":", port))
  b <- attr(r, "binding")
  expect_identical(b$state$pin_used, "127.0.0.1")
  expect_identical(b$state$attempts, "127.0.0.1 connected")
  expect_identical(seen$queries, paste0(pinned_host, "."))
})

test_that("the pin holds on explicit, default and non-default ports", {
  mock_answers("127.0.0.1")
  cases <- list(
    list(url = paste0("http://", pinned_host, "/"), port = 80L),
    list(url = paste0("http://", pinned_host, ":80/"), port = 80L),
    list(url = paste0("https://", pinned_host, "/"), port = 443L),
    list(url = paste0("https://", pinned_host, ":443/"), port = 443L),
    list(url = paste0("http://", pinned_host, ":1/"), port = 1L)
  )
  for (case in cases) {
    local({
      trace <- local_trace_recorder()
      b <- ssrf_prepare_hop(case$url, loopback_policy(1), request = list())
      expect_identical(b$origin$port, case$port, label = case$url)
      ssrf_fetch(b)
      # Whatever answers there, the connection went to the pinned address on
      # the request's own port, and the pin check saw it.
      tries <- grep("^Trying ", trace$lines, value = TRUE)
      expect_identical(
        tries[[1L]],
        paste0("Trying 127.0.0.1:", case$port, "..."),
        label = case$url
      )
      expect_true(startsWith(b$state$attempts[[1L]], "127.0.0.1 "))
      expect_false(identical(b$state$outcome, "pin-mismatch"))
    })
  }
})

test_that("a changed second resolver answer is never used", {
  skip_if_no_webfakes()
  web <- local_test_server()
  port <- web$get_port()
  seen <- mock_answers(function(q) {
    if (length(seen$queries) == 1L) "127.0.0.1" else "10.0.0.5"
  })
  b <- ssrf_prepare_hop(
    pinned_url(port),
    loopback_policy(port),
    request = list()
  )
  r <- ssrf_fetch(b)
  expect_identical(r$status, 200L)
  expect_length(seen$queries, 1L)
  # The flipped answer exists, and a new hop would meet it.
  r2 <- ssrf_prepare_hop(
    pinned_url(port),
    loopback_policy(port),
    request = list()
  )
  expect_identical(r2$code, "private")
})

test_that("a missing trace or another peer is pin-mismatch", {
  skip_if_no_webfakes()
  web <- local_test_server()
  port <- web$get_port()
  mock_answers("127.0.0.1")
  transfer <- ssrfr:::dep_curl_transfer
  rewrite <- function(fn) {
    local_mocked_bindings(
      dep_curl_transfer = function(opts, on_body, debug, progress) {
        rewriting <- function(type, msg) {
          if (type == 0L) {
            msg <- charToRaw(fn(rawToChar(msg)))
          }
          debug(type, msg)
        }
        transfer(opts, on_body, rewriting, progress)
      },
      .env = parent.frame()
    )
  }
  cases <- list(
    absent = function(x) gsub("Trying ", "Dialing ", x, fixed = TRUE),
    `other-address` = function(x) {
      gsub("127.0.0.1", "10.0.0.7", x, fixed = TRUE)
    },
    garbled = function(x) sub("Trying [^ \n]*", "Trying ???", x)
  )
  for (check in names(cases)) {
    local({
      rewrite(cases[[check]])
      b <- ssrf_prepare_hop(
        pinned_url(port),
        loopback_policy(port),
        request = list()
      )
      r <- ssrf_fetch(b)
      expect_s3_class(r, "ssrfr_failure")
      expect_identical(r$cause, "pin-mismatch", label = check)
      expect_identical(r$detail$check, check)
      # The response the server did send is discarded, not returned.
      expect_null(b$state$status)
    })
  }
})

# §2.5: the transport speaks HTTP/1.1 only (r-binding.md §5). Over HTTP/2
# libcurl sends a request again after the server refuses its stream
# (RST_STREAM REFUSED_STREAM). webfakes has no HTTP/2, so what shows the
# pin on the wire is the TLS handshake: h2 is never offered in ALPN.
test_that("HTTP/2 is never offered, even over TLS", {
  skip_if_no_webfakes()
  skip_if_not(isTRUE(curl::curl_version()$http2), "libcurl has no HTTP/2")
  tls <- local_test_server(tls = TRUE)
  port <- tls$get_port()
  local_trust_test_ca()
  mock_answers("127.0.0.1")
  trace <- local_trace_recorder()
  r <- guarded_get(
    pinned_url(port, scheme = "https", host = "alpha.example.invalid"),
    loopback_policy(port)
  )
  expect_identical(r$status, 200L)
  offers <- grep("ALPN", trace$lines, value = TRUE, fixed = TRUE)
  expect_gt(length(offers), 0L)
  expect_false(any(grepl("h2", offers, fixed = TRUE)))
})

# --- the request plan (§2.3) --------------------------------------------------

# The request head a raw server received, split into lines.
request_head <- function(server) {
  bytes <- server$request()
  text <- rawToChar(bytes)
  head <- substr(text, 1L, regexpr("\r\n\r\n", text, fixed = TRUE) - 1L)
  strsplit(head, "\r\n", fixed = TRUE)[[1L]]
}

# §2.3: the plan the binding records is the plan the transport sends. libcurl
# adds Accept: */* to every request, a form Content-Type to every POST and
# Expect: 100-continue to a large body; none was in the plan, so none may
# reach the wire.
test_that("the transport sends no field the plan did not carry", {
  mock_answers("127.0.0.1")
  ok <- wire(
    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
  )
  fields <- function(head) {
    tolower(sub(":.*$", "", head[-1L]))
  }
  empty <- local_raw_server(ok)
  r <- guarded_get(
    pinned_url(empty$port, "/p"),
    loopback_policy(empty$port),
    request = list(method = "POST")
  )
  expect_identical(r$status, 200L)
  head <- request_head(empty)
  expect_identical(head[[1L]], "POST /p HTTP/1.1")
  expect_setequal(
    fields(head),
    c("host", "user-agent", "accept-encoding", "content-length")
  )
  expect_true("Content-Length: 0" %in% head)

  # 1.5 MiB: over libcurl's threshold for Expect: 100-continue.
  body <- as.raw(rep(0x61, 1.5 * 2^20))
  big <- local_raw_server(ok)
  r <- guarded_get(
    pinned_url(big$port, "/p"),
    loopback_policy(big$port),
    request = list(method = "POST", body = body)
  )
  expect_identical(r$status, 200L)
  head <- request_head(big)
  expect_setequal(
    fields(head),
    c("host", "user-agent", "accept-encoding", "content-length")
  )
  sent <- big$request()
  expect_identical(tail(sent, length(body)), body)

  # A Content-Type the plan carries is sent once, as given.
  typed <- local_raw_server(ok)
  guarded_get(
    pinned_url(typed$port, "/p"),
    loopback_policy(typed$port),
    request = list(
      method = "POST",
      headers = c(`Content-Type` = "text/plain"),
      body = "x"
    )
  )
  head <- request_head(typed)
  expect_identical(
    grep("^Content-Type", head, value = TRUE),
    "Content-Type: text/plain"
  )
  expect_false(any(grepl("^Expect", head)))

  # An Accept the plan carries is sent once, as given.
  accepts <- local_raw_server(ok)
  guarded_get(
    pinned_url(accepts$port, "/a"),
    loopback_policy(accepts$port),
    request = list(headers = c(Accept = "application/json"))
  )
  head <- request_head(accepts)
  expect_identical(
    grep("^Accept:", head, value = TRUE),
    "Accept: application/json"
  )
})

# --- the response ------------------------------------------------------------

# Records every warning raised inside the transport's callbacks. libcurl
# runs them as top-level calls, where no handler of the caller's sees a
# warning: R prints it later, header bytes and all.
local_callback_warnings <- function(env = parent.frame()) {
  transfer <- ssrfr:::dep_curl_transfer
  seen <- new.env(parent = emptyenv())
  seen$warnings <- character()
  record <- function(f) {
    function(...) {
      withCallingHandlers(f(...), warning = function(w) {
        seen$warnings <- c(seen$warnings, conditionMessage(w))
        invokeRestart("muffleWarning")
      })
    }
  }
  local_mocked_bindings(
    dep_curl_transfer = function(opts, on_body, debug, ...) {
      transfer(opts, record(on_body), record(debug), ...)
    },
    .package = "ssrfr",
    .env = env
  )
  seen
}

# RFC 9110 §5.5: obs-text in a field value, here a Latin-1 filename, is a
# valid response, and no warning quotes the header block, Set-Cookie
# included (INV-12, §2.3).
test_that("a Latin-1 byte in a header value is a response, with no warning", {
  e9 <- as.raw(0xe9)
  web <- local_raw_server(c(
    wire(
      "HTTP/1.1 200 OK\r\n",
      "Content-Type: text/plain\r\n",
      "Set-Cookie: session=secret-cookie\r\n",
      "Content-Disposition: attachment; filename=\"caf"
    ),
    e9,
    wire(".txt\"\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
  ))
  mock_answers("127.0.0.1")
  callbacks <- local_callback_warnings()
  r <- NULL
  expect_no_warning(
    r <- guarded_get(pinned_url(web$port), loopback_policy(web$port))
  )
  expect_s3_class(r, "ssrfr_response")
  expect_identical(r$status, 200L)
  expect_identical(body_text(r), "ok")
  expect_identical(
    charToRaw(unname(r$headers[["content-disposition"]])),
    c(wire("attachment; filename=\"caf"), e9, wire(".txt\""))
  )
  expect_identical(callbacks$warnings, character())
  expect_identical(format(r)[[3L]], "  type: text/plain")
})

# R's curl keeps a chunked body's trailer fields in the header bytes it
# returns. A trailer is not the header: its Location is neither a header
# field nor the redirect target the binding records (§2.3).
test_that("a trailer field never joins the header", {
  web <- local_raw_server(wire(
    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: Location\r\n",
    "Connection: close\r\n\r\n",
    "5\r\nhello\r\n0\r\nLocation: /trailer\r\nX-Trailer: t\r\n\r\n"
  ))
  mock_answers("127.0.0.1")
  r <- guarded_get(pinned_url(web$port), loopback_policy(web$port))
  expect_s3_class(r, "ssrfr_response")
  expect_identical(body_text(r), "hello")
  expect_named(r$headers, c("transfer-encoding", "trailer", "connection"))
  b <- attr(r, "binding")
  expect_identical(b$state$location_count, 0L)
  expect_null(b$state$location)
})

# The status libcurl reports and the status line of the header block ssrfr
# reads must be one response's; when they differ, neither is recorded
# (§2.3: the status is transport-observed).
test_that("a status that disagrees with the header block is a protocol error", {
  mock_answers("127.0.0.1")
  # The second buffer holds two final blocks: the first is the one read,
  # and the second, trailer lines (R/transport.R, header_segments()).
  buffers <- list(
    one = wire("HTTP/1.1 302 Found\r\nLocation: /x\r\n\r\n"),
    two = wire(
      "HTTP/1.1 302 Found\r\nLocation: /x\r\n\r\n",
      "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    )
  )
  for (name in names(buffers)) {
    local({
      buffer <- buffers[[name]]
      local_mocked_bindings(
        dep_curl_transfer = function(opts, on_body, debug, progress) {
          debug(0L, charToRaw("Trying 127.0.0.1:80...\n"))
          list(
            aborted = FALSE,
            error = NULL,
            status = 200L,
            headers = buffer,
            connect = 0.01
          )
        }
      )
      b <- ssrf_prepare_hop(
        paste0("http://", pinned_host, "/"),
        loopback_policy(),
        request = list()
      )
      r <- ssrf_fetch(b)
      expect_s3_class(r, "ssrfr_failure")
      expect_identical(r$cause, "protocol-error", label = name)
      expect_identical(r$detail$check, "header", label = name)
      expect_null(b$state$status)
      expect_null(b$state$location)
    })
  }
})

# The measure and the parse of a completed transfer read one segmentation
# of the header buffer: the bytes are segmented once, not once for each.
test_that("a completed transfer's header is segmented once", {
  mock_answers("127.0.0.1")
  segmenter <- ssrfr:::header_segments
  calls <- new.env(parent = emptyenv())
  calls$n <- 0L
  local_mocked_bindings(
    header_segments = function(buffer, from = NULL) {
      calls$n <- calls$n + 1L
      segmenter(buffer, from)
    },
    dep_curl_transfer = function(opts, on_body, debug, progress) {
      debug(0L, charToRaw("Trying 127.0.0.1:80...\n"))
      list(
        aborted = FALSE,
        error = NULL,
        status = 200L,
        headers = wire("HTTP/1.1 200 OK\r\nX-One: 1\r\n\r\n"),
        connect = 0.01
      )
    }
  )
  b <- ssrf_prepare_hop(
    paste0("http://", pinned_host, "/"),
    loopback_policy(),
    request = list()
  )
  r <- ssrf_fetch(b)
  expect_s3_class(r, "ssrfr_response")
  expect_identical(r$headers, c(`x-one` = "1"))
  expect_identical(calls$n, 1L)
})

# RFC 9112 §4: a status line is HTTP-version SP status-code SP
# [reason-phrase]. A tab after the code is not SP, so the block does not read
# as a status line and the response is a protocol error, although libcurl
# reports 200. Deliberate: it fails closed.
test_that("a status line with a tab for its space is a protocol error", {
  mock_answers("127.0.0.1")
  web <- local_raw_server(wire(
    "HTTP/1.1 200\tOK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
  ))
  r <- guarded_get(pinned_url(web$port), loopback_policy(web$port))
  expect_s3_class(r, "ssrfr_failure")
  expect_identical(r$cause, "protocol-error")
  expect_identical(r$detail$check, "header")
  expect_null(attr(r, "binding")$state$status)
})

# --- failover (§2.5, §6.6) ---------------------------------------------------

# Replaces the transport with a script: `outcomes` maps each address to how
# its attempt ends. Records the addresses in the order they were tried.
scripted_transfer <- function(outcomes, env = parent.frame()) {
  tried <- new.env(parent = emptyenv())
  tried$addresses <- character()
  local_mocked_bindings(
    dep_curl_transfer = function(opts, on_body, debug, progress) {
      key <- "multi.invalid::"
      target <- sub(":$", "", substring(opts$connect_to, nchar(key) + 1L))
      address <- gsub("[][]", "", target)
      tried$addresses <- c(tried$addresses, address)
      outcome <- outcomes[[address]]
      dialed <- if (outcome == "mismatch") "[fd00::66]" else target
      debug(0L, charToRaw(paste0("Trying ", dialed, ":80...\n")))
      base <- list(
        aborted = FALSE,
        error = NULL,
        status = 0L,
        headers = raw(),
        connect = 0
      )
      switch(
        outcome,
        refused = replace(base, "error", "curl_error_couldnt_connect"),
        timeout = replace(base, "error", "curl_error_operation_timedout"),
        mismatch = replace(base, "error", "curl_error_couldnt_connect"),
        tls = modifyList(
          base,
          list(error = "curl_error_peer_failed_verification", connect = 0.01)
        ),
        ok = {
          headers <- charToRaw(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"
          )
          on_body(charToRaw("hello"), function() headers)
          modifyList(
            base,
            list(status = 200L, connect = 0.01, headers = headers)
          )
        }
      )
    },
    .package = "ssrfr",
    .env = env
  )
  tried
}

failover_fetch <- function(outcomes) {
  addresses <- names(outcomes)
  local_mocked_bindings(dep_nslookup = function(query) addresses)
  policy <- ssrf_policy(allow_ranges = c("192.0.2.0/24", "2001:db8::/32"))
  b <- ssrf_prepare_hop("http://multi.invalid/", policy, request = list())
  list(result = ssrf_fetch(b), binding = b)
}

test_that("failover follows resolver order and stops at the first connection", {
  tried <- scripted_transfer(list(
    "192.0.2.3" = "refused",
    "2001:db8::1" = "timeout",
    "192.0.2.1" = "ok",
    "192.0.2.2" = "ok"
  ))
  out <- failover_fetch(list(
    "192.0.2.3" = 1,
    "2001:db8::1" = 1,
    "192.0.2.1" = 1,
    "192.0.2.2" = 1
  ))
  expect_identical(tried$addresses, c("192.0.2.3", "2001:db8::1", "192.0.2.1"))
  expect_s3_class(out$result, "ssrfr_response")
  expect_identical(body_text(out$result), "hello")
  expect_identical(out$binding$state$pin_used, "192.0.2.1")
  expect_identical(
    out$binding$state$attempts,
    c(
      "192.0.2.3 connect-failed",
      "2001:db8::1 connect-timeout",
      "192.0.2.1 connected"
    )
  )
})

test_that("exhausted failover is timeout only when every connect timed out", {
  run <- function(script) {
    local({
      tried <- scripted_transfer(script)
      out <- failover_fetch(lapply(script, function(x) 1))
      list(cause = out$result$cause, tried = tried$addresses, out = out$result)
    })
  }
  all_timeout <- run(list("192.0.2.1" = "timeout", "192.0.2.2" = "timeout"))
  expect_identical(all_timeout$cause, "timeout")
  expect_identical(all_timeout$tried, c("192.0.2.1", "192.0.2.2"))
  expect_identical(
    all_timeout$out$detail$attempts,
    c("192.0.2.1 connect-timeout", "192.0.2.2 connect-timeout")
  )
  mixed <- run(list("192.0.2.1" = "timeout", "192.0.2.2" = "refused"))
  expect_identical(mixed$cause, "connect-failed")
  mixed2 <- run(list("192.0.2.1" = "refused", "192.0.2.2" = "timeout"))
  expect_identical(mixed2$cause, "connect-failed")
  refused <- run(list("192.0.2.1" = "refused"))
  expect_identical(refused$cause, "connect-failed")
})

# §6.6: total_timeout elapsing during failover is `timeout`, naming the
# address last attempted; no further address is tried.
test_that("total_timeout ends failover as timeout", {
  tried <- new.env(parent = emptyenv())
  tried$addresses <- character()
  local_mocked_bindings(
    dep_curl_transfer = function(opts, on_body, debug, progress) {
      target <- sub("^multi[.]invalid::(.*):$", "\\1", opts$connect_to)
      tried$addresses <- c(tried$addresses, target)
      debug(0L, charToRaw(paste0("Trying ", target, ":80...\n")))
      Sys.sleep(0.6)
      list(
        aborted = FALSE,
        error = "curl_error_couldnt_connect",
        status = 0L,
        headers = raw(),
        connect = 0
      )
    }
  )
  addresses <- c("192.0.2.1", "192.0.2.2", "192.0.2.3")
  local_mocked_bindings(dep_nslookup = function(query) addresses)
  policy <- ssrf_policy(allow_ranges = "192.0.2.0/24", total_timeout = 1)
  b <- ssrf_prepare_hop("http://multi.invalid/", policy, request = list())
  r <- ssrf_fetch(b)
  expect_identical(r$cause, "timeout")
  expect_identical(r$detail$step, 10L)
  expect_identical(r$detail$limit, "total_timeout")
  expect_identical(r$address, "192.0.2.2")
  expect_identical(tried$addresses, c("192.0.2.1", "192.0.2.2"))
  expect_identical(
    r$detail$attempts,
    c("192.0.2.1 connect-failed", "192.0.2.2 connect-failed")
  )
})

test_that("pin-mismatch or an opened connection ends failover", {
  run <- function(script) {
    local({
      tried <- scripted_transfer(script)
      out <- failover_fetch(lapply(script, function(x) 1))
      list(cause = out$result$cause, tried = tried$addresses)
    })
  }
  first <- run(list("192.0.2.1" = "mismatch", "192.0.2.2" = "ok"))
  expect_identical(first$cause, "pin-mismatch")
  expect_identical(first$tried, "192.0.2.1")
  second <- run(list(
    "192.0.2.1" = "refused",
    "192.0.2.2" = "mismatch",
    "192.0.2.3" = "ok"
  ))
  expect_identical(second$cause, "pin-mismatch")
  expect_identical(second$tried, c("192.0.2.1", "192.0.2.2"))
  tls <- run(list("192.0.2.1" = "tls", "192.0.2.2" = "ok"))
  expect_identical(tls$cause, "tls-failed")
  expect_identical(tls$tried, "192.0.2.1")
})

test_that("failover reaches the listener after a dead address", {
  skip_if_no_webfakes()
  skip_if_not(isTRUE(curl::curl_version()$ipv6), "libcurl has no IPv6")
  web <- local_test_server()
  port <- web$get_port()
  mock_answers(c("::1", "127.0.0.1"))
  trace <- local_trace_recorder()
  r <- guarded_get(pinned_url(port), loopback_policy(port))
  expect_identical(r$status, 200L)
  b <- attr(r, "binding")
  expect_match(b$state$attempts[[1L]], "^::1 connect-(failed|timeout)$")
  expect_identical(b$state$attempts[[2L]], "127.0.0.1 connected")
  tries <- grep("^Trying ", trace$lines, value = TRUE)
  expect_length(tries, 2L)
  expect_match(tries[[1L]], paste0("^Trying \\[?::1\\]?:", port))
  expect_identical(tries[[2L]], paste0("Trying 127.0.0.1:", port, "..."))
})

# §2.5, §6.6: a fetch whose total_timeout is already spent makes no
# attempt at all, rather than dialing with the shortest timeout libcurl
# takes.
test_that("a spent total_timeout makes no attempt", {
  mock_answers("127.0.0.1")
  listener <- local_listener()
  b <- ssrf_prepare_hop(
    pinned_url(listener$port),
    loopback_policy(listener$port),
    request = list()
  )
  local_mocked_bindings(elapsed_since = function(start) 1e6)
  r <- ssrf_fetch(b)
  expect_s3_class(r, "ssrfr_failure")
  expect_identical(r$cause, "timeout")
  expect_identical(r$detail$check, "total")
  expect_identical(r$detail$limit, "total_timeout")
  expect_identical(r$detail$step, 10L)
  expect_null(r$detail$attempts)
  expect_identical(b$state$attempts, character())
  expect_false(connection_arrives(listener$socket, 1))
})

# --- callback failures -------------------------------------------------------

# A defect in ssrfr's own write or progress callback is not a limit: the
# transfer still ends, with no R error raised inside the callback, and the
# failure says a callback failed rather than passing for a limit stop.
test_that("an error in ssrfr's own callback fails closed and says so", {
  skip_if_not_installed("withr")
  mock_answers("127.0.0.1")
  hook <- new.env(parent = emptyenv())
  hook$runs <- 0L
  withr::local_options(error = function() hook$runs <- hook$runs + 1L)
  transfer <- ssrfr:::dep_curl_transfer
  broken <- list(
    data = function(on_body, progress) {
      list(on_body = function(x, ...) stop("a defect"), progress = progress)
    },
    progress = function(on_body, progress) {
      failing <- function(down, up, received) {
        if (length(received())) {
          stop("a defect")
        }
        progress(down, up, received)
      }
      list(on_body = on_body, progress = failing)
    }
  )
  for (name in names(broken)) {
    local({
      local_mocked_bindings(
        dep_curl_transfer = function(opts, on_body, debug, progress) {
          cb <- broken[[name]](on_body, progress)
          transfer(opts, cb$on_body, debug, cb$progress)
        }
      )
      server <- local_raw_server(wire(
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n",
        "hello"
      ))
      r <- NULL
      expect_no_error(
        r <- guarded_get(pinned_url(server$port), loopback_policy(server$port))
      )
      expect_s3_class(r, "ssrfr_failure")
      expect_identical(r$cause, "protocol-error", label = name)
      expect_identical(r$detail$check, "callback-error", label = name)
      expect_identical(r$detail$callback, name, label = name)
      expect_null(attr(r, "binding")$state$status)
      expect_identical(hook$runs, 0L, label = name)
    })
  }
})

# R's curl discards an error from the trace callback and goes on. The trace
# is the pin's only evidence, so a trace callback that fails leaves the pin
# unconfirmed: the fetch ends as pin-mismatch, whatever arrived.
test_that("an error in the trace callback fails closed as pin-mismatch", {
  skip_if_not_installed("withr")
  mock_answers("127.0.0.1")
  hook <- new.env(parent = emptyenv())
  hook$runs <- 0L
  withr::local_options(error = function() hook$runs <- hook$runs + 1L)
  transfer <- ssrfr:::dep_curl_transfer
  delivered <- new.env(parent = emptyenv())
  delivered$bytes <- 0L
  local_mocked_bindings(
    dep_curl_transfer = function(opts, on_body, debug, progress) {
      counting <- function(x, received) {
        delivered$bytes <- delivered$bytes + length(x)
        on_body(x, received)
      }
      traced <- new.env(parent = emptyenv())
      traced$trying <- FALSE
      failing <- function(type, msg) {
        if (traced$trying) {
          stop("a defect")
        }
        out <- debug(type, msg)
        traced$trying <- type == 0L &&
          grepl("Trying ", rawToChar(msg), fixed = TRUE)
        out
      }
      transfer(opts, counting, failing, progress)
    }
  )
  server <- local_raw_server(wire(
    "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"
  ))
  r <- NULL
  expect_no_error(
    r <- guarded_get(pinned_url(server$port), loopback_policy(server$port))
  )
  expect_s3_class(r, "ssrfr_failure")
  expect_identical(r$cause, "pin-mismatch")
  expect_identical(r$detail$check, "trace-error")
  expect_identical(r$detail$callback, "debug")
  expect_null(attr(r, "binding")$state$status)
  # The transfer ends at the failed trace: no body byte is read after it.
  expect_identical(delivered$bytes, 0L)
  expect_identical(hook$runs, 0L)
})

# Whether libcurl traces `Trying` before the libcurl round of its first
# progress call ends is the build's (design/evidence/
# 2026-09-28-progress-trace-order.txt). A progress callback that fails on its
# first call stops the transfer after that round, so the check the attempt
# reports records the order: `absent` (pin-mismatch) when no `Trying` line
# reached the trace, `callback-error` when one did and the pin matched.
# Either way the failure names progress.
test_that("a progress callback that fails on its first call is named", {
  skip_if_not_installed("withr")
  mock_answers("127.0.0.1")
  hook <- new.env(parent = emptyenv())
  hook$runs <- 0L
  withr::local_options(error = function() hook$runs <- hook$runs + 1L)
  listener <- local_listener()
  transfer <- ssrfr:::dep_curl_transfer
  seen <- new.env(parent = emptyenv())
  seen$calls <- 0L
  seen$trying <- FALSE
  local_mocked_bindings(
    dep_curl_transfer = function(opts, on_body, debug, progress) {
      recording <- function(type, msg) {
        # A `Trying` line as attempt_address() collects it for pin_check().
        if (type == 0L) {
          lines <- trimws(strsplit(rawToChar(msg), "\n", fixed = TRUE)[[1L]])
          if (any(startsWith(lines, "Trying "))) {
            seen$trying <- TRUE
          }
        }
        debug(type, msg)
      }
      failing <- function(down, up, received) {
        seen$calls <- seen$calls + 1L
        stop("a defect")
      }
      transfer(opts, on_body, recording, failing)
    }
  )
  r <- NULL
  expect_no_error(
    r <- guarded_get(pinned_url(listener$port), loopback_policy(listener$port))
  )
  expect_s3_class(r, "ssrfr_failure")
  # The wrapper calls a failed progress callback no more.
  expect_identical(seen$calls, 1L)
  order <- if (seen$trying) "traced first" else "progress first"
  want <- if (seen$trying) {
    list(cause = "protocol-error", check = "callback-error")
  } else {
    list(cause = "pin-mismatch", check = "absent")
  }
  expect_identical(r$cause, want$cause, label = order)
  expect_identical(r$detail$check, want$check, label = order)
  expect_identical(r$detail$callback, "progress", label = order)
  expect_null(attr(r, "binding")$state$status)
  expect_identical(hook$runs, 0L)
})

# §6.6: a pin-mismatch names every callback that failed, in the order they
# first failed, and none when none did; the check is the trace's own, or
# `trace-error` when the trace matches but the trace callback failed. Which
# callback cut the trace short is never inferred from the check.
test_that("a pin-mismatch names every failed callback, in order", {
  mock_answers("127.0.0.1")
  cases <- list(
    `other-address, none` = list(
      trace = "Trying 10.0.0.7:80...\n",
      failed = NULL,
      check = "other-address",
      callback = NULL
    ),
    `garbled, none` = list(
      trace = "Trying ???\n",
      failed = NULL,
      check = "garbled",
      callback = NULL
    ),
    # What the wrapper reports when progress fails on its first call before
    # libcurl traces anything or connects.
    `absent, nothing traced` = list(
      trace = "",
      failed = "progress",
      check = "absent",
      callback = "progress",
      connect = 0
    ),
    `other-address` = list(
      trace = "Trying 10.0.0.7:80...\n",
      failed = "data",
      check = "other-address",
      callback = "data"
    ),
    `other-address, debug` = list(
      trace = "Trying 10.0.0.7:80...\n",
      failed = "debug",
      check = "other-address",
      callback = "debug"
    ),
    absent = list(
      trace = "Dialing\n",
      failed = "progress",
      check = "absent",
      callback = "progress"
    ),
    `absent after data` = list(
      trace = "Dialing\n",
      failed = "data",
      check = "absent",
      callback = "data"
    ),
    # The wrapper records this: it stops calling progress once progress
    # fails, but still calls the trace callback until the round ends, and
    # libcurl can call progress in the round it then traces `Trying` in
    # (design/evidence/2026-09-28-progress-trace-order.txt). A trace
    # callback that fails on that line leaves no `Trying` traced.
    `absent, progress then debug` = list(
      trace = "Dialing\n",
      failed = c("progress", "debug"),
      check = "absent",
      callback = c("progress", "debug")
    ),
    garbled = list(
      trace = "Trying ???\n",
      failed = "data",
      check = "garbled",
      callback = "data"
    ),
    debug = list(
      trace = "Dialing\n",
      failed = "debug",
      check = "absent",
      callback = "debug"
    ),
    `trace-error` = list(
      trace = "Trying 127.0.0.1:80...\n",
      failed = "debug",
      check = "trace-error",
      callback = "debug"
    ),
    `trace-error after data` = list(
      trace = "Trying 127.0.0.1:80...\n",
      failed = c("data", "debug"),
      check = "trace-error",
      callback = c("data", "debug")
    )
  )
  for (name in names(cases)) {
    case <- cases[[name]]
    local({
      local_mocked_bindings(
        dep_curl_transfer = function(opts, on_body, debug, progress) {
          debug(0L, charToRaw(case$trace))
          list(
            aborted = TRUE,
            failed = case$failed,
            error = NULL,
            status = 0L,
            headers = raw(),
            connect = if (is.null(case$connect)) 0.01 else case$connect
          )
        }
      )
      b <- ssrf_prepare_hop(
        paste0("http://", pinned_host, "/"),
        loopback_policy(),
        request = list()
      )
      r <- ssrf_fetch(b)
      expect_identical(r$cause, "pin-mismatch", label = name)
      expect_identical(r$detail$check, case$check, label = name)
      expect_identical(r$detail$callback, case$callback, label = name)
      expect_null(b$state$status, label = name)
    })
  }
})

# A callback-error names every callback that failed, in order, not the first.
test_that("a callback-error names every failed callback, in order", {
  mock_answers("127.0.0.1")
  local_mocked_bindings(
    dep_curl_transfer = function(opts, on_body, debug, progress) {
      debug(0L, charToRaw("Trying 127.0.0.1:80...\n"))
      list(
        aborted = TRUE,
        failed = c("data", "progress"),
        error = NULL,
        status = 0L,
        headers = raw(),
        connect = 0.01
      )
    }
  )
  b <- ssrf_prepare_hop(
    paste0("http://", pinned_host, "/"),
    loopback_policy(),
    request = list()
  )
  r <- ssrf_fetch(b)
  expect_identical(r$cause, "protocol-error")
  expect_identical(r$detail$check, "callback-error")
  expect_identical(r$detail$callback, c("data", "progress"))
})

# INV-11: a transfer the wrapper reports as stopped by a callback, with
# neither a limit record nor a callback failure to say why, fails closed. Its
# header block is complete and its status agrees, yet it is never a response.
test_that("a stopped transfer with no record fails closed", {
  mock_answers("127.0.0.1")
  local_mocked_bindings(
    dep_curl_transfer = function(opts, on_body, debug, progress) {
      debug(0L, charToRaw("Trying 127.0.0.1:80...\n"))
      list(
        aborted = TRUE,
        failed = NULL,
        error = NULL,
        status = 200L,
        headers = wire("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
        connect = 0.01
      )
    }
  )
  b <- ssrf_prepare_hop(
    paste0("http://", pinned_host, "/"),
    loopback_policy(),
    request = list()
  )
  r <- ssrf_fetch(b)
  expect_s3_class(r, "ssrfr_failure")
  expect_identical(r$cause, "protocol-error")
  expect_identical(r$detail$check, "aborted")
  expect_null(r$detail$callback)
  expect_null(b$state$status)
  expect_false(b$state$fetched)
})

# --- single use (§2.5) -------------------------------------------------------

test_that("a binding is spent on entry, even when the fetch fails", {
  mock_answers("127.0.0.1")
  b <- ssrf_prepare_hop(
    "http://spent.invalid:1/",
    loopback_policy(1),
    request = list()
  )
  expect_true(b$state$fetchable)
  r <- ssrf_fetch(b)
  expect_identical(r$cause, "connect-failed")
  expect_false(b$state$fetchable)
  err <- expect_error(ssrf_fetch(b), class = "ssrfr_error_spent_binding")
  expect_s3_class(err, "ssrfr_error")
  # A copy is the same binding: spending one spends both.
  b2 <- ssrf_prepare_hop(
    "http://spent.invalid:1/",
    loopback_policy(1),
    request = list()
  )
  alias <- b2
  ssrf_fetch(alias)
  expect_error(ssrf_fetch(b2), class = "ssrfr_error_spent_binding")
  # A transport that errors still leaves the binding spent.
  local({
    local_mocked_bindings(dep_curl_transfer = function(...) stop("boom"))
    b3 <- ssrf_prepare_hop(
      "http://spent.invalid:1/",
      loopback_policy(1),
      request = list()
    )
    r <- NULL
    expect_no_error(r <- ssrf_fetch(b3))
    expect_identical(r$cause, "pin-mismatch")
    expect_error(ssrf_fetch(b3), class = "ssrfr_error_spent_binding")
  })
  expect_error(ssrf_fetch(r), class = "ssrfr_error_invalid_argument")
  expect_error(ssrf_fetch("http://x/"), class = "ssrfr_error_invalid_argument")
})

# §2.5: no retries. libcurl's default auth, CURLAUTH_ANY, answers a 401
# challenge by sending the request again with the URL's credentials; the
# server here offers Digest and Basic and counts the requests it receives.
test_that("an auth challenge never makes the request a second time", {
  skip_if_no_webfakes()
  web <- local_test_server()
  port <- web$get_port()
  mock_answers("127.0.0.1")
  r <- guarded_get(
    paste0("http://user:pass@", pinned_host, ":", port, "/auth"),
    loopback_policy(port, allow_userinfo = TRUE)
  )
  expect_s3_class(r, "ssrfr_response")
  expect_identical(r$status, 401L)
  # One request, and it carried the credentials the URL named.
  # "dXNlcjpwYXNz" is base64 of "user:pass".
  expect_identical(body_text(r), "hits=1 auth=Basic dXNlcjpwYXNz")
})

# §2.5: no retries. Each response here is one libcurl could answer by
# sending the request again within one fetch: a 417 to a body sent with
# 100-continue, a redirect it follows, or interim responses. The server
# answers every request on every connection it accepts and keeps them open,
# so a request sent again, on either, is counted. (A 401 challenge is the
# test above.)
test_that("a request reaches the server once, whatever the response", {
  mock_answers("127.0.0.1")
  body <- as.raw(rep(0x61, 1.5 * 2^20))
  cases <- list(
    expectation = list(
      response = wire(
        "HTTP/1.1 417 Expectation Failed\r\nContent-Length: 0\r\n\r\n"
      ),
      request = list(method = "POST", body = body),
      status = 417L
    ),
    redirect = list(
      response = wire(
        "HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\n\r\n"
      ),
      request = list(),
      status = 302L
    ),
    interim = list(
      response = wire(
        "HTTP/1.1 100 Continue\r\n\r\n",
        "HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
      ),
      request = list(),
      status = 200L
    )
  )
  for (name in names(cases)) {
    case <- cases[[name]]
    local({
      server <- local_counting_server(case$response)
      r <- guarded_get(
        pinned_url(server$port, "/once"),
        loopback_policy(server$port, total_timeout = 10),
        request = case$request
      )
      expect_s3_class(r, "ssrfr_response")
      expect_identical(r$status, case$status, label = name)
      seen <- server$stop()
      expect_identical(nrow(seen), 1L, label = name)
      expect_match(seen$line, " /once HTTP/1[.]1$", label = name)
    })
  }
})

test_that("a failing transport wrapper fails closed, never an R error", {
  modes <- list(
    stop = function(...) stop("dependency failed"),
    null = function(...) NULL,
    wrong_shape = function(...) list(unexpected = 42)
  )
  mock_answers("127.0.0.1")
  for (mode in names(modes)) {
    local({
      local_mocked_bindings(dep_curl_transfer = modes[[mode]])
      b <- ssrf_prepare_hop(
        "http://wrapper.invalid:1/",
        loopback_policy(1),
        request = list()
      )
      r <- NULL
      expect_no_error(r <- ssrf_fetch(b))
      expect_s3_class(r, "ssrfr_failure")
      expect_identical(r$cause, "pin-mismatch", label = mode)
    })
  }
})

# r-binding.md §7: an interrupt mid-transfer leaves the binding spent and no
# handle open. A raw server sends a header and one chunk, then waits; once
# the chunk is out, a second process interrupts this one. The server then
# reports whether the client closed the connection.
test_that("an interrupt leaves the binding spent and no handle open", {
  skip_if_not_installed("callr")
  skip_on_os("windows")
  port <- free_port()
  flag <- tempfile("chunk-sent-")
  ready <- tempfile("listening-")
  closed <- tempfile("closed-")
  server <- callr::r_bg(
    function(port, flag, ready, closed) {
      s <- serverSocket(port)
      on.exit(close(s))
      file.create(ready)
      con <- socketAccept(s, blocking = TRUE, open = "r+b", timeout = 30)
      on.exit(close(con), add = TRUE)
      repeat {
        l <- readLines(con, n = 1L, warn = FALSE)
        if (!length(l) || !nzchar(l)) break
      }
      writeBin(
        charToRaw(paste0(
          "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
          "5\r\nfirst\r\n"
        )),
        con
      )
      flush(con)
      file.create(flag)
      t0 <- Sys.time()
      repeat {
        x <- tryCatch(readBin(con, raw(), 1L), error = function(e) NULL)
        if (!length(x)) {
          file.create(closed)
          return("closed")
        }
        if (difftime(Sys.time(), t0, units = "secs") > 20) {
          return("still open")
        }
      }
    },
    args = list(port = port, flag = flag, ready = ready, closed = closed)
  )
  withr::defer(server$kill())
  interrupter <- callr::r_bg(
    function(pid, flag) {
      t0 <- Sys.time()
      while (!file.exists(flag)) {
        if (difftime(Sys.time(), t0, units = "secs") > 30) {
          return("no chunk")
        }
        Sys.sleep(0.05)
      }
      Sys.sleep(0.3)
      tools::pskill(pid, tools::SIGINT)
      "sent"
    },
    args = list(pid = Sys.getpid(), flag = flag)
  )
  withr::defer(interrupter$kill())
  # Wait for the server to listen before preparing the hop.
  t0 <- Sys.time()
  while (!file.exists(ready) && difftime(Sys.time(), t0, units = "secs") < 20) {
    Sys.sleep(0.05)
  }
  expect_true(file.exists(ready))
  mock_answers("127.0.0.1")
  b <- ssrf_prepare_hop(
    pinned_url(port),
    loopback_policy(port, total_timeout = 60),
    request = list()
  )
  got <- tryCatch(ssrf_fetch(b), interrupt = function(c) "interrupted")
  # The connection is closed at once, not whenever the garbage collector
  # finalizes an abandoned handle: poll before anything else allocates.
  t0 <- Sys.time()
  while (!file.exists(closed) && difftime(Sys.time(), t0, units = "secs") < 3) {
    Sys.sleep(0.05)
  }
  closed_at_once <- file.exists(closed)
  expect_identical(got, "interrupted")
  expect_true(closed_at_once)
  expect_false(b$state$fetchable)
  expect_error(ssrf_fetch(b), class = "ssrfr_error_spent_binding")
  server$wait(25000)
  expect_identical(server$get_result(), "closed")
})

# §2.5: every interrupt is the user's and propagates, even one already
# pending at the moment ssrfr stops a transfer at a limit. The SIGINT is
# sent from inside the progress call that reaches max_header_bytes, with
# R's interrupts suspended, so it waits exactly as one delivered while
# libcurl runs in C does: R acts on it only at curl's next interrupt check,
# after ssrfr has decided to stop.
test_that("a user interrupt pending when ssrfr stops at a limit propagates", {
  skip_on_os("windows")
  mock_answers("127.0.0.1")
  server <- local_raw_server(stream_forever(
    wire("HTTP/1.1 200 OK\r\n"),
    wire("X-Field: ", strrep("v", 50), "\r\n")
  ))
  transfer <- ssrfr:::dep_curl_transfer
  sent <- new.env(parent = emptyenv())
  sent$signal <- FALSE
  local_mocked_bindings(
    dep_curl_transfer = function(opts, on_body, debug, progress) {
      pending <- function(down, up, ...) {
        go <- progress(down, up, ...)
        if (!isTRUE(go) && !sent$signal) {
          sent$signal <- TRUE
          suspendInterrupts(tools::pskill(Sys.getpid(), tools::SIGINT))
        }
        go
      }
      transfer(opts, on_body, debug, pending)
    }
  )
  b <- ssrf_prepare_hop(
    pinned_url(server$port),
    loopback_policy(server$port, max_header_bytes = 1000, total_timeout = 20),
    request = list()
  )
  got <- tryCatch(ssrf_fetch(b), interrupt = function(c) "interrupted")
  expect_true(sent$signal)
  expect_identical(got, "interrupted")
  expect_false(b$state$fetchable)
  expect_null(b$state$status)
  expect_error(ssrf_fetch(b), class = "ssrfr_error_spent_binding")
})

# §2.5, §6.6: ssrfr never makes an interrupt of its own, so a limit stop is
# always a failure object, never an R interrupt, however often it happens.
test_that("a limit stop never surfaces as an interrupt", {
  mock_answers("127.0.0.1")
  # A header that never ends: 100 fields and no empty line.
  server <- local_counting_server(wire(
    "HTTP/1.1 200 OK\r\n",
    strrep("X-Field: 1\r\n", 100)
  ))
  policy <- loopback_policy(
    server$port,
    max_header_fields = 20,
    total_timeout = 10
  )
  ends <- character()
  for (i in seq_len(20L)) {
    r <- tryCatch(
      guarded_get(pinned_url(server$port), policy),
      interrupt = function(c) "interrupt"
    )
    ends <- c(
      ends,
      if (inherits(r, "ssrfr_failure")) {
        paste(r$cause, r$detail$check, r$detail$limit)
      } else {
        paste(class(r), collapse = "/")
      }
    )
  }
  expect_identical(
    ends,
    rep("response-too-large header max_header_fields", 20L)
  )
  expect_identical(nrow(server$stop()), 20L)
})
