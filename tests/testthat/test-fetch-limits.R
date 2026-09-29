# ssrf_fetch()'s limits and its isolation from ambient configuration
# (ssrfr-v1.md §2.3, §5.3, §6.6, §14, INV-10; r-binding.md §5, §7). Servers
# are loopback webfakes apps reached through a pin, as in test-fetch.R.

test_that("total_timeout ends a slow response as timeout", {
  skip_if_no_webfakes()
  web <- local_test_server()
  port <- web$get_port()
  mock_answers("127.0.0.1")
  t0 <- Sys.time()
  r <- guarded_get(
    pinned_url(port, "/slow"),
    loopback_policy(port, total_timeout = 1)
  )
  elapsed <- as.numeric(difftime(Sys.time(), t0, units = "secs"))
  expect_s3_class(r, "ssrfr_failure")
  expect_identical(r$cause, "timeout")
  expect_identical(r$detail$limit, "total_timeout")
  expect_lt(elapsed, 4.5)
})

test_that("total_timeout is re-checked after decoding", {
  skip_if_no_webfakes()
  web <- local_test_server()
  port <- web$get_port()
  mock_answers("127.0.0.1")
  transfer <- ssrfr:::dep_curl_transfer
  # A transfer that returns in time, followed by decoding that does not.
  local_mocked_bindings(
    dep_curl_transfer = function(opts, on_body, debug, progress) {
      out <- transfer(opts, on_body, debug, progress)
      Sys.sleep(1.3)
      out
    }
  )
  r <- guarded_get(pinned_url(port), loopback_policy(port, total_timeout = 1))
  expect_s3_class(r, "ssrfr_failure")
  expect_identical(r$cause, "timeout")
  expect_identical(r$detail$step, 12L)
  expect_false(attr(r, "binding")$state$fetched)
})

test_that("the byte cap ends a chunked body as response-too-large", {
  skip_if_no_webfakes()
  web <- local_test_server()
  port <- web$get_port()
  mock_answers("127.0.0.1")
  r <- guarded_get(
    pinned_url(port, "/chunked"),
    loopback_policy(port, max_response_size = 20000)
  )
  expect_s3_class(r, "ssrfr_failure")
  expect_identical(r$cause, "response-too-large")
  expect_identical(r$detail$limit, "max_response_size")
  # Under the cap, the same body arrives whole.
  r <- guarded_get(
    pinned_url(port, "/chunked"),
    loopback_policy(port, max_response_size = 250000)
  )
  expect_length(r$body, 250000L)
})

test_that("a compression bomb is response-too-large from ssrfr's own counter", {
  skip_if_no_webfakes()
  web <- local_test_server()
  port <- web$get_port()
  mock_answers("127.0.0.1")
  # 2,000,000 zero bytes, about 2 KB on the wire: under the cap as sent, over
  # it decoded. libcurl's maxfilesize counts the wire and lets it pass.
  r <- guarded_get(
    pinned_url(port, "/bomb"),
    loopback_policy(port, max_response_size = 100000)
  )
  expect_s3_class(r, "ssrfr_failure")
  expect_identical(r$cause, "response-too-large")
  expect_identical(r$detail$check, "decoded-bytes")
  expect_identical(r$detail$limit, "max_response_size")
  r <- guarded_get(
    pinned_url(port, "/bomb"),
    loopback_policy(port, max_response_size = 3e6)
  )
  expect_identical(r$status, 200L)
  expect_identical(r$body, raw(2e6))
  r <- guarded_get(pinned_url(port, "/deflate"), loopback_policy(port))
  expect_identical(body_text(r), strrep("deflated ", 1000))
})

# §5.3 counts decoded bytes. A declared Content-Length, or wire bytes that
# exceed the decoded body, never refuse a response whose decoded body is
# within the cap: libcurl's maxfilesize would refuse both.
test_that("only decoded bytes count against max_response_size", {
  mock_answers("127.0.0.1")
  policy <- function(port) loopback_policy(port, max_response_size = 1000)
  # A HEAD response declares the size of a body it does not carry.
  head <- local_raw_server(wire(
    "HTTP/1.1 200 OK\r\nContent-Length: 50000000\r\n",
    "Connection: close\r\n\r\n"
  ))
  r <- guarded_get(
    pinned_url(head$port),
    policy(head$port),
    request = list(method = "HEAD")
  )
  expect_s3_class(r, "ssrfr_response")
  expect_identical(r$status, 200L)
  expect_identical(r$body, raw())
  # 990 random bytes, deflated: over the cap on the wire, under it decoded.
  plain <- withr::with_seed(1L, as.raw(sample(0:255, 990L, replace = TRUE)))
  deflated <- memCompress(plain, "gzip")
  expect_gt(length(deflated), 1000L)
  packed <- local_raw_server(c(
    wire(
      "HTTP/1.1 200 OK\r\nContent-Encoding: deflate\r\n",
      "Content-Length: ",
      length(deflated),
      "\r\nConnection: close\r\n\r\n"
    ),
    deflated
  ))
  r <- guarded_get(pinned_url(packed$port), policy(packed$port))
  expect_s3_class(r, "ssrfr_response")
  expect_identical(r$body, plain)
})

test_that("header bytes and header fields have limits of their own", {
  skip_if_no_webfakes()
  web <- local_test_server()
  port <- web$get_port()
  mock_answers("127.0.0.1")
  fields <- guarded_get(
    pinned_url(port, "/many-headers"),
    loopback_policy(port, max_header_fields = 20)
  )
  expect_identical(fields$cause, "response-too-large")
  expect_identical(fields$detail$limit, "max_header_fields")
  bytes <- guarded_get(
    pinned_url(port, "/many-headers"),
    loopback_policy(port, max_header_bytes = 500)
  )
  expect_identical(bytes$cause, "response-too-large")
  expect_identical(bytes$detail$limit, "max_header_bytes")
  # The header arrives first, so its limit is the one that names the cause
  # even when the body would pass its own (§6.6).
  both <- guarded_get(
    pinned_url(port, "/many-headers?big=1"),
    loopback_policy(port, max_header_fields = 20, max_response_size = 1000)
  )
  expect_identical(both$cause, "response-too-large")
  expect_identical(both$detail$limit, "max_header_fields")
  ok <- guarded_get(pinned_url(port, "/many-headers"), loopback_policy(port))
  expect_identical(ok$status, 200L)
  expect_identical(unname(ok$headers[["x-field-50"]]), strrep("v", 40))
})

# §14: header bytes and field counts have limits of their own, which hold
# while the header arrives. A header that never ends, a run of 1xx blocks,
# or an endless header on a response to HEAD ends at its limit, well before
# total_timeout.
test_that("a header that never ends stops at its limit, not at the deadline", {
  mock_answers("127.0.0.1")
  field <- wire("X-Field: ", strrep("v", 50), "\r\n")
  cases <- list(
    bytes = list(
      prefix = wire("HTTP/1.1 200 OK\r\n"),
      chunk = field,
      limits = list(max_header_bytes = 1000),
      limit = "max_header_bytes"
    ),
    fields = list(
      prefix = wire("HTTP/1.1 200 OK\r\n"),
      chunk = wire("X: 1\r\n"),
      limits = list(max_header_fields = 20),
      limit = "max_header_fields"
    ),
    interim = list(
      prefix = raw(),
      chunk = wire("HTTP/1.1 102 Processing\r\n\r\n"),
      limits = list(max_header_bytes = 500),
      limit = "max_header_bytes"
    ),
    head = list(
      prefix = wire("HTTP/1.1 200 OK\r\n"),
      chunk = field,
      limits = list(max_header_bytes = 1000),
      limit = "max_header_bytes",
      request = list(method = "HEAD")
    )
  )
  for (name in names(cases)) {
    case <- cases[[name]]
    local({
      server <- local_raw_server(stream_forever(case$prefix, case$chunk))
      policy <- do.call(
        loopback_policy,
        c(list(server$port, total_timeout = 10), case$limits)
      )
      t0 <- Sys.time()
      r <- guarded_get(
        pinned_url(server$port),
        policy,
        request = if (is.null(case$request)) list() else case$request
      )
      elapsed <- as.numeric(difftime(Sys.time(), t0, units = "secs"))
      expect_identical(r$cause, "response-too-large", label = name)
      expect_identical(r$detail$check, "header", label = name)
      expect_identical(r$detail$limit, case$limit, label = name)
      expect_lt(elapsed, 4, label = name)
    })
  }
})

# §6.6: a header cut short before its empty line, with exactly
# max_header_fields fields, is within the limits. Its status line opens its
# block, so it is no field, and the transfer ends with the cause of how it
# ended: `timeout` when the server stalls, and when it closes,
# `protocol-error`, whether libcurl reports the close (check `transport`)
# or ssrfr finds the header never ended (check `header`).
test_that("a truncated header at the field limit ends as the transfer did", {
  mock_answers("127.0.0.1")
  head <- wire("HTTP/1.1 200 OK\r\n", strrep("X-F: 1\r\n", 20))
  stall <- function(con) {
    writeBin(HEAD, con)
    flush(con)
    Sys.sleep(10)
  }
  body(stall) <- do.call(substitute, list(body(stall), list(HEAD = head)))
  cases <- list(
    stall = list(bytes = stall, want = "timeout transport total_timeout"),
    close = list(bytes = head, want = "protocol-error (header|transport) none")
  )
  for (name in names(cases)) {
    case <- cases[[name]]
    local({
      server <- local_raw_server(case$bytes)
      policy <- loopback_policy(
        server$port,
        max_header_fields = 20,
        total_timeout = 2
      )
      r <- guarded_get(pinned_url(server$port), policy)
      expect_s3_class(r, "ssrfr_failure")
      expect_match(
        paste(
          r$cause,
          r$detail$check,
          if (is.null(r$detail$limit)) "none" else r$detail$limit
        ),
        paste0("^", case$want, "$"),
        label = name
      )
    })
  }
})

# §5.3, §14: trailer lines count as they arrive even when no body byte has
# been delivered: a chunked body that is empty, or a gzip body not yet
# decoded. A status-shaped first trailer line follows a complete final
# block, so it is a trailer field, and the progress call that sees it over
# the limit stops the transfer. libcurl 8.5 and later refuse such a line,
# so the transfer is scripted: one progress call over the header buffer.
test_that("a status-shaped first trailer counts before any body byte", {
  mock_answers("127.0.0.1")
  buffers <- list(
    empty = wire(
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX: 1\r\n\r\n",
      "HTTP/1.1 200 OK\r\n"
    ),
    gzip = wire(
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n",
      "Content-Encoding: gzip\r\n\r\n",
      "HTTP/1.1 302 Found\r\n"
    )
  )
  for (name in names(buffers)) {
    local({
      buffer <- buffers[[name]]
      seen <- new.env(parent = emptyenv())
      local_mocked_bindings(
        dep_curl_transfer = function(opts, on_body, debug, progress) {
          debug(0L, charToRaw("Trying 127.0.0.1:80...\n"))
          seen$go <- progress(0, 0, function() buffer)
          list(
            aborted = !isTRUE(seen$go),
            failed = NULL,
            error = NULL,
            status = 200L,
            headers = buffer,
            connect = 0.01
          )
        }
      )
      b <- ssrf_prepare_hop(
        paste0("http://", pinned_host, "/"),
        loopback_policy(max_header_fields = 2),
        request = list()
      )
      r <- ssrf_fetch(b)
      expect_false(seen$go, label = name)
      expect_identical(
        paste(r$cause, r$detail$check, r$detail$limit),
        "response-too-large header max_header_fields",
        label = name
      )
    })
  }
})

# A progress call over a header buffer that has not grown since the last
# one decides nothing again: the decision reads only what the measure
# records. Every buffer that grew is decided, on the call that sees it, and
# the completed transfer once more.
test_that("a header buffer is decided once per growth", {
  mock_answers("127.0.0.1")
  first <- wire("HTTP/1.1 200 OK\r\nX-One: 1\r\n")
  whole <- c(first, wire("X-Two: 2\r\n\r\n"))
  run <- function(max_fields) {
    calls <- new.env(parent = emptyenv())
    calls$n <- 0L
    stop_at <- ssrfr:::header_stop
    local_mocked_bindings(
      header_stop = function(seen, policy, binding, reported = NULL) {
        calls$n <- calls$n + 1L
        stop_at(seen, policy, binding, reported)
      },
      dep_curl_transfer = function(opts, on_body, debug, progress) {
        debug(0L, charToRaw("Trying 127.0.0.1:80...\n"))
        calls$go <- logical()
        for (buffer in list(first, first, first, whole, whole)) {
          calls$go <- c(calls$go, progress(0, 0, function() buffer))
        }
        calls$in_flight <- calls$n
        list(
          aborted = !all(calls$go),
          failed = NULL,
          error = NULL,
          status = 200L,
          headers = whole,
          connect = 0.01
        )
      }
    )
    r <- guarded_get(
      paste0("http://", pinned_host, "/"),
      loopback_policy(max_header_fields = max_fields)
    )
    list(result = r, calls = calls)
  }
  within <- run(2)
  expect_s3_class(within$result, "ssrfr_response")
  expect_identical(within$calls$go, rep(TRUE, 5L))
  # Two growths decided in flight, and the completed transfer once.
  expect_identical(within$calls$in_flight, 2L)
  expect_identical(within$calls$n, 3L)
  # The growth that passes a limit is decided on the call that sees it.
  over <- run(1)
  expect_identical(over$calls$go, c(TRUE, TRUE, TRUE, FALSE, FALSE))
  expect_identical(over$result$cause, "response-too-large")
  expect_identical(over$result$detail$limit, "max_header_fields")
})

# §5.3, §6.6: a chunked body's trailer fields count against the header
# limits, with the cause a header over them has. libcurl hands trailer lines
# to the header buffer but not to the trace's header lines, so they pass
# no header count unless ssrfr counts them itself. Trailers that never end
# stop at the limit, not at total_timeout.
test_that("trailer fields count against the header limits", {
  mock_answers("127.0.0.1")
  head <- wire(
    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n",
    "Connection: close\r\n\r\n",
    "5\r\nhello\r\n0\r\n"
  )
  many <- strrep("X-T: 1\r\n", 40)
  wide <- strrep(paste0("X-W: ", strrep("v", 95), "\r\n"), 20)
  cases <- list(
    fields = list(
      bytes = c(head, wire(many, "\r\n")),
      limits = list(max_header_fields = 20),
      limit = "max_header_fields"
    ),
    bytes = list(
      bytes = c(head, wire(wide, "\r\n")),
      limits = list(max_header_bytes = 1000),
      limit = "max_header_bytes"
    ),
    endless = list(
      bytes = stream_forever(head, wire("X-T: vvvv\r\n")),
      limits = list(max_header_fields = 20),
      limit = "max_header_fields"
    )
  )
  for (name in names(cases)) {
    case <- cases[[name]]
    local({
      server <- local_raw_server(case$bytes)
      policy <- do.call(
        loopback_policy,
        c(list(server$port, total_timeout = 10), case$limits)
      )
      t0 <- Sys.time()
      r <- guarded_get(pinned_url(server$port), policy)
      elapsed <- as.numeric(difftime(Sys.time(), t0, units = "secs"))
      expect_s3_class(r, "ssrfr_failure")
      expect_identical(r$cause, "response-too-large", label = name)
      expect_identical(r$detail$check, "header", label = name)
      expect_identical(r$detail$limit, case$limit, label = name)
      expect_lt(elapsed, 4, label = name)
      b <- attr(r, "binding")
      expect_null(b$state$status)
      expect_false(b$state$fetched)
    })
  }
  # Within the limits, the same trailers are a response, and none of them
  # is a header field.
  server <- local_raw_server(c(head, wire(many, "\r\n")))
  r <- guarded_get(pinned_url(server$port), loopback_policy(server$port))
  expect_s3_class(r, "ssrfr_response")
  expect_identical(body_text(r), "hello")
  expect_named(r$headers, c("transfer-encoding", "connection"))
})

# §5.3, §14: the header limits hold in flight whatever libcurl's trace
# says. A build may write no trace line for a read that carries only
# header or trailer bytes, so ssrfr measures both from the header buffer.
# Here every trace line but the text the pin check reads is withheld, and
# a header or a trailer section that never ends still stops at its limit.
test_that("the header limits hold without the trace's header or data lines", {
  mock_answers("127.0.0.1")
  transfer <- ssrfr:::dep_curl_transfer
  local_mocked_bindings(
    dep_curl_transfer = function(opts, on_body, debug, progress) {
      text_only <- function(type, msg) {
        if (type == 0L) debug(type, msg) else NULL
      }
      transfer(opts, on_body, text_only, progress)
    }
  )
  cases <- list(
    header = stream_forever(
      wire("HTTP/1.1 200 OK\r\n"),
      wire("X-T: vvvv\r\n")
    ),
    trailer = stream_forever(
      wire(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n",
        "Connection: close\r\n\r\n",
        "5\r\nhello\r\n0\r\n"
      ),
      wire("X-T: vvvv\r\n")
    )
  )
  for (name in names(cases)) {
    local({
      server <- local_raw_server(cases[[name]])
      policy <- loopback_policy(
        server$port,
        max_header_fields = 20,
        total_timeout = 10
      )
      t0 <- Sys.time()
      r <- guarded_get(pinned_url(server$port), policy)
      elapsed <- as.numeric(difftime(Sys.time(), t0, units = "secs"))
      expect_s3_class(r, "ssrfr_failure")
      expect_identical(r$cause, "response-too-large", label = name)
      expect_identical(r$detail$limit, "max_header_fields", label = name)
      expect_lt(elapsed, 4, label = name)
    })
  }
})

test_that("a redirect is returned with Location; two are a protocol error", {
  skip_if_no_webfakes()
  web <- local_test_server()
  port <- web$get_port()
  mock_answers("127.0.0.1")
  r <- guarded_get(pinned_url(port, "/redirect"), loopback_policy(port))
  expect_s3_class(r, "ssrfr_response")
  expect_identical(r$status, 302L)
  b <- attr(r, "binding")
  expect_identical(b$state$status, 302L)
  expect_identical(b$state$location, "/next?x=1")
  expect_identical(b$state$location_count, 1L)
  expect_true(b$state$fetched)

  r <- guarded_get(pinned_url(port, "/two-locations"), loopback_policy(port))
  expect_s3_class(r, "ssrfr_failure")
  expect_identical(r$cause, "protocol-error")
  expect_identical(r$detail$check, "location")
  b <- attr(r, "binding")
  expect_identical(b$state$location_count, 2L)
  expect_null(b$state$location)
  expect_false(b$state$fetched)
})

# r-binding.md §7, Rules: each proxy variable, with an http:// and a
# socks5h:// value, set to a dead loopback port, for a pinned http:// and a
# pinned https:// fetch. A variable libcurl honoured would send the fetch to
# the dead port.
test_that("proxy variables have no effect", {
  skip_if_no_webfakes()
  skip_if_not_installed("withr")
  web <- local_test_server()
  tls <- local_test_server(tls = TRUE)
  port <- web$get_port()
  tport <- tls$get_port()
  # The http rows run even where the fixture CA cannot be trusted.
  secure_too <- !test_ca_ignored()
  if (secure_too) {
    local_trust_test_ca()
  }
  mock_answers("127.0.0.1")
  dead <- free_port()
  policy <- loopback_policy(c(port, tport))
  secure_url <- pinned_url(
    tport,
    scheme = "https",
    host = "alpha.example.invalid"
  )
  vars <- c(
    "http_proxy",
    "HTTP_PROXY",
    "https_proxy",
    "HTTPS_PROXY",
    "all_proxy",
    "ALL_PROXY"
  )
  for (var in vars) {
    for (scheme in c("http", "socks5h")) {
      value <- paste0(scheme, "://127.0.0.1:", dead)
      local({
        withr::local_envvar(stats::setNames(value, var))
        plain <- guarded_get(pinned_url(port), policy)
        expect_identical(plain$status, 200L, label = paste(var, value, "http"))
        if (secure_too) {
          secure <- guarded_get(secure_url, policy)
          expect_identical(
            secure$status,
            200L,
            label = paste(var, value, "https")
          )
        }
      })
    }
  }
  skip_if_test_ca_ignored()
})

# Under a connect_to pin a leaked proxy is sent CONNECT to the pinned
# address, so the test asserts that nothing at all reaches a listener
# standing in for the proxy (r-binding.md §7, Rules).
test_that("nothing reaches a listener standing in for the proxy", {
  skip_if_no_webfakes()
  skip_if_not_installed("withr")
  web <- local_test_server()
  tls <- local_test_server(tls = TRUE)
  port <- web$get_port()
  tport <- tls$get_port()
  secure_too <- !test_ca_ignored()
  if (secure_too) {
    local_trust_test_ca()
  }
  mock_answers("127.0.0.1")
  proxy <- local_listener()
  value <- paste0("http://127.0.0.1:", proxy$port)
  withr::local_envvar(c(
    http_proxy = value,
    HTTPS_PROXY = value,
    https_proxy = value,
    ALL_PROXY = value
  ))
  policy <- loopback_policy(c(port, tport), total_timeout = 10)
  expect_identical(guarded_get(pinned_url(port), policy)$status, 200L)
  if (secure_too) {
    secure <- guarded_get(
      pinned_url(tport, scheme = "https", host = "alpha.example.invalid"),
      policy
    )
    expect_identical(secure$status, 200L)
  }
  expect_false(connection_arrives(proxy$socket, 1))
  skip_if_test_ca_ignored()
})

test_that("Alt-Svc has no effect on a later fetch", {
  skip_if_no_webfakes()
  web <- local_test_server()
  port <- web$get_port()
  mock_answers("127.0.0.1")
  dead <- free_port()
  trace <- local_trace_recorder()
  url <- pinned_url(port, paste0("/alt-svc?dead=", dead))
  first <- guarded_get(url, loopback_policy(c(port, dead)))
  second <- guarded_get(url, loopback_policy(c(port, dead)))
  expect_identical(body_text(first), "hit 1")
  expect_identical(body_text(second), "hit 2")
  expect_match(unname(first$headers[["alt-svc"]]), as.character(dead))
  tries <- grep("^Trying ", trace$lines, value = TRUE)
  expect_identical(tries, rep(paste0("Trying 127.0.0.1:", port, "..."), 2L))
})

test_that("a connection is never reused, within a pin or across pins", {
  skip_if_no_webfakes()
  web <- local_test_server(keep_alive = TRUE)
  port <- web$get_port()
  answers <- "127.0.0.1"
  mock_answers(function(q) answers)
  trace <- local_trace_recorder()
  policy <- ssrf_policy(
    allow_ranges = c("127.0.0.0/8", "192.0.2.0/24"),
    allow_ports = port,
    connect_timeout = 1
  )
  # Each fetch opens its own connection, which the pin check sees.
  for (i in 1:2) {
    r <- guarded_get(pinned_url(port), policy)
    expect_identical(r$status, 200L)
  }
  expect_length(grep("^Trying ", trace$lines), 2L)
  expect_length(grep("Re-?using", trace$lines), 0L)
  # The same URL pinned to another address never reaches the first server.
  answers <- "192.0.2.1"
  r <- guarded_get(pinned_url(port), policy)
  expect_s3_class(r, "ssrfr_failure")
  expect_true(r$cause %in% c("timeout", "connect-failed"))
  expect_identical(
    tail(grep("^Trying ", trace$lines, value = TRUE), 1L),
    paste0("Trying 192.0.2.1:", port, "...")
  )
})

# §14, r-binding.md §5: each transfer runs in a pool of its own, so no
# pooled connection can carry even its first request. The server keeps
# every connection open and answers each request on it, so two fetches
# that shared a connection would arrive on one.
test_that("every fetch opens a fresh connection", {
  mock_answers("127.0.0.1")
  server <- local_counting_server(
    wire("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
  )
  for (i in 1:2) {
    r <- guarded_get(pinned_url(server$port), loopback_policy(server$port))
    expect_identical(r$status, 200L)
  }
  seen <- server$stop()
  expect_identical(nrow(seen), 2L)
  expect_identical(seen$connection, c(1L, 2L))
})

# §14, r-binding.md §7, Rules: the scheme allowlist is enforced at the
# transport too, for every scheme this libcurl was built with, and the guard
# refuses each of them first.
test_that("the transport refuses every scheme but http and https", {
  mock_answers("127.0.0.1")
  b <- ssrf_prepare_hop(
    "http://proto.invalid:1/",
    loopback_policy(1),
    request = list()
  )
  opts <- ssrfr:::transport_options(
    b,
    "127.0.0.1",
    5,
    ssrfr:::read_curl_capabilities()
  )
  file <- tempfile(fileext = ".txt")
  writeLines("secret", file)
  target <- function(scheme) {
    switch(
      scheme,
      file = paste0("file://", normalizePath(file, winslash = "/")),
      smb = ,
      smbs = paste0(scheme, "://127.0.0.1:1/share/x"),
      paste0(scheme, "://127.0.0.1:1/x")
    )
  }
  schemes <- setdiff(curl::curl_version()$protocols, c("http", "https"))
  expect_gt(length(schemes), 0L)
  for (scheme in schemes) {
    got <- ssrfr:::dep_curl_transfer(
      replace(opts, "url", target(scheme)),
      function(x, received) TRUE,
      function(type, msg) NULL,
      function(down, up, received) TRUE
    )
    expect_identical(
      got$error,
      "curl_error_unsupported_protocol",
      label = scheme
    )
    guard <- ssrf_prepare_hop(target(scheme), ssrf_policy(), request = list())
    expect_true(guard$code %in% c("scheme", "parse"), label = scheme)
  }
})

# curl evaluates each callback as a top-level call, so an R error raised in
# one runs the user's options(error = ) hook, which may quit the process.
# ssrfr raises none: a limit reached in the write callback, at the first
# delivery or mid-body, or in the progress callback, is recorded and the
# transfer cancelled, and the fetch returns a failure.
test_that("a stop at a limit never runs the error hook", {
  skip_if_not_installed("withr")
  mock_answers("127.0.0.1")
  hook <- new.env(parent = emptyenv())
  hook$runs <- 0L
  withr::local_options(error = function() hook$runs <- hook$runs + 1L)
  # ssrfr's own total_timeout check runs on each delivery; libcurl's timer
  # is lifted so that check is the one that ends the transfer.
  builder <- ssrfr:::transport_options
  local_mocked_bindings(
    transport_options = function(...) {
      replace(builder(...), "timeout_ms", 60000L)
    }
  )
  fields <- strrep(paste0("X-Field: ", strrep("v", 50), "\r\n"), 30)
  cases <- list(
    size = list(
      bytes = c(
        wire("HTTP/1.1 200 OK\r\nContent-Length: 50000\r\n\r\n"),
        as.raw(rep(0x62, 50000))
      ),
      limits = list(max_response_size = 20000),
      want = "response-too-large decoded-bytes max_response_size"
    ),
    total = list(
      bytes = stream_forever(
        wire("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"),
        wire("1\r\nx\r\n")
      ),
      limits = list(total_timeout = 1),
      want = "timeout total total_timeout"
    ),
    delivery = list(
      bytes = wire(
        "HTTP/1.1 200 OK\r\n",
        fields,
        "Content-Length: 5\r\n\r\nhello"
      ),
      limits = list(max_header_bytes = 1000),
      want = "response-too-large header max_header_bytes"
    ),
    progress = list(
      bytes = stream_forever(
        wire("HTTP/1.1 200 OK\r\n"),
        wire("X-Field: ", strrep("v", 50), "\r\n")
      ),
      limits = list(max_header_bytes = 1000),
      want = "response-too-large header max_header_bytes"
    )
  )
  for (name in names(cases)) {
    case <- cases[[name]]
    local({
      server <- local_raw_server(case$bytes)
      policy <- do.call(loopback_policy, c(list(server$port), case$limits))
      r <- guarded_get(pinned_url(server$port), policy)
      expect_s3_class(r, "ssrfr_failure")
      expect_identical(
        paste(r$cause, r$detail$check, r$detail$limit),
        case$want,
        label = name
      )
      expect_identical(hook$runs, 0L, label = name)
    })
  }
})

# r-binding.md §7: a stop in the write callback ends the transfer there,
# through R's `abort` restart, which curl's R_tryEval() evaluation stops at:
# a short write, never an R condition. curl does not document that
# evaluation, so this runs the fetch in a subprocess whose options(error = )
# hook quits it: a restart that escaped, or a condition raised, would end the
# process before the marker. Against a gzip bomb stopped at max_response_size,
# the refusal is today's, libcurl reports its write error, and it reads no
# more than one buffer after the stop, where recording the stop alone let it
# read ten (design/evidence/2026-09-29-abort-post-stop-reads.txt).
test_that("a stop in the write callback aborts, without the error hook", {
  skip_if_not_installed("callr")
  bomb <- memCompress(raw(5e7), "gzip")
  server <- local_raw_server(c(
    wire(
      "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: ",
      length(bomb),
      "\r\nConnection: close\r\n\r\n"
    ),
    bomb
  ))
  # The package under test: installed under R CMD check, a source tree under
  # test_local().
  path <- getNamespaceInfo("ssrfr", "path")
  hooked <- tempfile("hook-ran-")
  out <- callr::r(
    function(path, port, hooked) {
      options(error = function() {
        file.create(hooked)
        quit("no", status = 3L)
      })
      if (dir.exists(file.path(path, "Meta"))) {
        loadNamespace("ssrfr", lib.loc = dirname(path))
      } else {
        pkgload::load_all(path, quiet = TRUE)
      }
      seen <- new.env()
      seen$stopped <- FALSE
      seen$after <- 0
      seen$cleanup <- FALSE
      transfer <- ssrfr:::dep_curl_transfer
      policy <- ssrfr::ssrf_policy(
        allow_ranges = "127.0.0.0/8",
        allow_ports = port,
        max_response_size = 1e5
      )
      r <- testthat::with_mocked_bindings(
        tryCatch(
          ssrfr::ssrf_fetch(ssrfr::ssrf_prepare_hop(
            paste0("http://127.0.0.1:", port, "/"),
            policy,
            request = list()
          )),
          finally = seen$cleanup <- TRUE
        ),
        dep_curl_transfer = function(opts, on_body, debug, progress) {
          counted <- function(x, received) {
            go <- on_body(x, received)
            seen$stopped <- !isTRUE(go)
            go
          }
          # Type 3 is the wire bytes libcurl reads (CURLINFO_DATA_IN).
          traced <- function(type, msg) {
            if (type == 3L && seen$stopped) {
              seen$after <- seen$after + length(msg)
            }
            debug(type, msg)
          }
          t <- transfer(opts, counted, traced, progress)
          seen$error <- t$error
          t
        },
        .package = "ssrfr"
      )
      list(
        ending = paste(r$cause, r$detail$check, r$detail$limit),
        error = seen$error,
        after = seen$after,
        cleanup = seen$cleanup,
        marker = "after the transfer"
      )
    },
    args = list(path = path, port = server$port, hooked = hooked)
  )
  expect_false(file.exists(hooked))
  expect_identical(out$marker, "after the transfer")
  expect_true(out$cleanup)
  expect_identical(
    out$ending,
    "response-too-large decoded-bytes max_response_size"
  )
  expect_identical(out$error, "curl_error_write_error")
  # libcurl's default buffer, 16 KiB, is the most one read can take.
  expect_lte(out$after, 16384)
})

# The header buffer holds every header block, each ended by an empty line,
# then a chunked body's trailer lines, which no empty line ends. A trailer
# line shaped like a status line opens no block: it is a field, on a
# libcurl that accepts one into the buffer.
test_that("a trailer line shaped like a status line is a field", {
  seen <- new.env(parent = emptyenv())
  buffer <- wire(
    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX: 1\r\n\r\n",
    "HTTP/1.1 200 x\r\nA: b\r\n"
  )
  ssrfr:::measure_header(seen, buffer)
  expect_identical(seen$header_bytes, length(buffer))
  expect_identical(seen$header_fields, 2L + 2L)
})

# §5.3: a block the buffer holds before any complete final block is a
# header block, ended or not, so its status line is no field; everything
# after a complete final block is a trailer line, and a field.
test_that("the header measure classifies a line by the block before it", {
  cases <- list(
    truncated = list(
      buffer = wire("HTTP/1.1 200 OK\r\nX: 1\r\nY: 2\r\n"),
      fields = 2L
    ),
    truncated_after_interim = list(
      buffer = wire("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nX: 1\r\n"),
      fields = 1L
    ),
    trailer_status_first = list(
      buffer = wire(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
        "HTTP/1.1 302 Found\r\nLocation: /t\r\n"
      ),
      fields = 3L
    )
  )
  for (name in names(cases)) {
    seen <- new.env(parent = emptyenv())
    ssrfr:::measure_header(seen, cases[[name]]$buffer)
    expect_identical(seen$header_fields, cases[[name]]$fields, label = name)
    expect_identical(
      seen$header_bytes,
      length(cases[[name]]$buffer),
      label = name
    )
  }
})

# §5.3: an empty line is never a field, after the final block included. A
# trailer section's closing empty line does not count against
# `max_header_fields`; only the trailer lines that carry a field do.
test_that("an empty line after the final block is no field", {
  seen <- new.env(parent = emptyenv())
  buffer <- wire(
    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX: 1\r\n\r\n",
    "X-T: 1\r\n\r\n"
  )
  ssrfr:::measure_header(seen, buffer)
  expect_identical(seen$header_bytes, length(buffer))
  expect_identical(seen$header_fields, 2L + 1L)
})

# §14: the header measure reads libcurl's header buffer each time it grows.
# However the bytes arrive, a line or a byte at a time, cut mid-line or
# mid-block, each growth measures, segments and parses as one reading of the
# same bytes; and so does a buffer that does not extend the one before.
test_that("a header measured as it grows reads as the whole measured once", {
  once <- function(buffer) {
    seen <- new.env(parent = emptyenv())
    ssrfr:::measure_header(seen, buffer)
    seen
  }
  reading <- function(seen, buffer) {
    list(
      bytes = seen$header_bytes,
      fields = seen$header_fields,
      segments = seen$segments[c("lines", "ends", "blocks", "trailers")],
      parsed = ssrfr:::parse_response_headers(buffer, seen$segments)
    )
  }
  buffers <- list(
    interim = wire(
      strrep("HTTP/1.1 100 X\r\n\r\n", 3),
      "HTTP/1.1 200 OK\r\nA: 1\r\n\r\n"
    ),
    trailers = wire(
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
      "HTTP/1.1 302 Found\r\nLocation: /t\r\n\r\n",
      "X: 1\r\n"
    ),
    strays = wire(
      "X: 1\r\nY: 2\r\n\r\n\r\n\r\nHTTP/1.1 101 S\r\n\r\n",
      "Z\r\n\r\nHTTP/1.1 200\tOK\r\n\r\nHTTP/1.1 200 OK\r\n\r\n"
    ),
    cut = wire(
      "HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n",
      "HTTP/1.1 200 OK\r\nX: 1\r"
    ),
    bare = wire("HTTP/1.1 100 X\n\nHTTP/1.1 204 N\n\n\r\nT: 1\n"),
    bytes = c(
      wire("HTTP/1.1 100 X\r\n\rY: 1\r\n\r\nHTTP/1.1 200 OK\r\nX: a"),
      as.raw(c(0L, 0xffL)),
      wire("b\r\n\r\n\r")
    )
  )
  for (name in names(buffers)) {
    buffer <- buffers[[name]]
    for (step in c(1L, 2L, 3L, 7L, 19L)) {
      seen <- new.env(parent = emptyenv())
      got <- list()
      want <- list()
      for (n in unique(c(seq(0L, length(buffer), by = step), length(buffer)))) {
        prefix <- buffer[seq_len(n)]
        ssrfr:::measure_header(seen, prefix)
        got[[length(got) + 1L]] <- reading(seen, prefix)
        want[[length(want) + 1L]] <- reading(once(prefix), prefix)
      }
      expect_identical(got, want, label = paste(name, step))
    }
  }
  # A buffer that does not extend the one measured before it, longer or
  # shorter, is measured as a whole.
  seen <- new.env(parent = emptyenv())
  for (buffer in list(
    buffers$interim[1:40],
    buffers$trailers,
    buffers$trailers[1:30],
    buffers$strays
  )) {
    ssrfr:::measure_header(seen, buffer)
    expect_identical(reading(seen, buffer), reading(once(buffer), buffer))
  }
})
