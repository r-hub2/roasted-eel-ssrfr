# The pure parts of the transport (ssrfr-v1.md §14, INV-5, INV-6, INV-9,
# INV-10; r-binding.md §5-§7): the option-list builder every attempt's
# options come from, the one-place-dials tripwire, the trace matcher, and the
# reading of response headers. No test here opens a connection.

caps_modern <- list(
  version = numeric_version("8.14.1"),
  protocols_str = TRUE,
  zlib = TRUE
)
caps_old <- list(
  version = numeric_version("7.81.0"),
  protocols_str = FALSE,
  zlib = TRUE
)

# A binding for `url`, with the resolver answering `answers`.
binding_for <- function(url, answers = "93.184.216.34", policy = NULL) {
  local_mocked_bindings(dep_nslookup = function(query) answers)
  policy <- policy %||% ssrf_policy(allow_ports = c(80, 443, 8080))
  ssrf_prepare_hop(url, policy, request = list())
}

`%||%` <- function(x, y) if (is.null(x)) y else x

# r-binding.md §7, Rules: every handle carries the pin; TLS is never
# weakened; the "never set" options are absent. Each scheme, with explicit,
# default and non-default ports, a name and both address families, and both
# forms of the protocol restriction.
test_that("every handle carries the pin; TLS is never weakened", {
  cases <- list(
    list(url = "http://pin.example/", answers = "93.184.216.34"),
    list(url = "http://pin.example:80/", answers = "93.184.216.34"),
    list(url = "http://pin.example:8080/", answers = "93.184.216.34"),
    list(url = "https://pin.example/", answers = "93.184.216.34"),
    list(url = "https://pin.example:443/", answers = "93.184.216.34"),
    list(url = "https://pin.example:8080/", answers = "93.184.216.34"),
    list(url = "https://PIN.Example./x", answers = "2606:4700:4700::1111"),
    list(url = "http://93.184.216.34:8080/", answers = NULL),
    list(url = "https://[2606:4700:4700::1111]/", answers = NULL)
  )
  for (case in cases) {
    b <- binding_for(case$url, case$answers)
    expect_s3_class(b, "ssrfr_binding")
    for (caps in list(caps_modern, caps_old, NULL)) {
      for (address in b$validated) {
        opts <- ssrfr:::transport_options(b, address, 10, caps)
        expect_identical(
          option_problems(opts, b$origin$host, address),
          character(),
          label = paste(case$url, address)
        )
        # The key is libcurl's own host, with no port field to mismatch.
        expect_true(startsWith(opts$connect_to, paste0(b$origin$host, "::")))
        expect_identical(opts$url, b$url)
      }
    }
  }
  # The restriction takes the string form from libcurl 7.85, else the bitmask.
  b <- binding_for("http://pin.example/")
  modern <- ssrfr:::transport_options(b, "93.184.216.34", 10, caps_modern)
  old <- ssrfr:::transport_options(b, "93.184.216.34", 10, caps_old)
  unknown <- ssrfr:::transport_options(b, "93.184.216.34", 10, NULL)
  expect_identical(modern$protocols_str, "http,https")
  expect_null(modern[["protocols"]])
  expect_identical(old[["protocols"]], 3L)
  expect_null(old$protocols_str)
  expect_identical(unknown[["protocols"]], 3L)
  # Accept-Encoding is always set, never NULL.
  expect_identical(modern$accept_encoding, "gzip, deflate")
  expect_identical(unknown$accept_encoding, "identity")
})

test_that("the option checker fires on a planted violation", {
  b <- binding_for("http://pin.example/")
  good <- ssrfr:::transport_options(b, "93.184.216.34", 10, caps_modern)
  expect_identical(
    option_problems(good, "pin.example", "93.184.216.34"),
    character()
  )
  planted <- list(
    missing_pin = within(good, rm(connect_to)),
    port_keyed = replace(good, "connect_to", "pin.example:80:93.184.216.34:80"),
    empty_host = replace(good, "connect_to", "::93.184.216.34:"),
    no_trailing_colon = replace(
      good,
      "connect_to",
      "pin.example::93.184.216.34"
    ),
    resolve = c(good, list(resolve = "pin.example:80:93.184.216.34")),
    verify_off = replace(good, "ssl_verifypeer", list(0L)),
    host_off = replace(good, "ssl_verifyhost", list(0L)),
    proxy = replace(good, "proxy", "http://proxy.example:3128"),
    noproxy_empty = replace(good, "noproxy", ""),
    reuse = replace(good, "forbid_reuse", list(0L)),
    follow = replace(good, "followlocation", list(1L)),
    netrc = replace(good, "netrc", list(1L)),
    auth_any = replace(good, "httpauth", list(-17L)),
    h2 = replace(good, "http_version", list(3L)),
    version_default = good[names(good) != "http_version"],
    cookie_engine = replace(good, "cookiefile", ""),
    protocols = within(good, rm(protocols_str, redir_protocols_str)),
    unix = c(good, list(unix_socket_path = "/var/run/docker.sock")),
    altsvc = c(good, list(altsvc = "altsvc.txt"))
  )
  for (name in names(planted)) {
    expect_gt(
      length(option_problems(planted[[name]], "pin.example", "93.184.216.34")),
      0L,
      label = name
    )
  }
})

test_that("limits and the request plan reach the options", {
  local_mocked_bindings(dep_nslookup = function(query) "93.184.216.34")
  policy <- ssrf_policy(
    connect_timeout = 2,
    total_timeout = 7,
    max_response_size = 12345,
    user_agent = "tester/1"
  )
  b <- ssrf_prepare_hop(
    "https://pin.example/",
    policy,
    request = list(
      method = "PATCH",
      headers = c(`X-A` = "1", `X-Empty` = ""),
      body = "payload"
    )
  )
  opts <- ssrfr:::transport_options(b, "93.184.216.34", 5, caps_modern)
  expect_identical(opts$connecttimeout_ms, 2000L)
  expect_identical(opts$timeout_ms, 5000L)
  # libcurl's declared-size cap is never set (§5.3): the limit is the
  # decoded-byte counter.
  expect_null(opts$maxfilesize_large)
  expect_null(opts$maxfilesize)
  expect_identical(opts$useragent, "tester/1")
  expect_identical(opts$customrequest, "PATCH")
  expect_identical(opts$postfields, charToRaw("payload"))
  # Fields libcurl would add on its own are suppressed (§2.3).
  expect_identical(
    opts$httpheader,
    c("X-A: 1", "X-Empty;", "Accept:", "Content-Type:", "Expect:")
  )
  # The connect timeout never exceeds what is left of the total.
  opts <- ssrfr:::transport_options(b, "93.184.216.34", 0.5, caps_modern)
  expect_identical(opts$connecttimeout_ms, 500L)

  methods <- list(
    GET = list(httpget = 1L, httpheader = "Accept:"),
    HEAD = list(nobody = 1L, httpheader = "Accept:"),
    POST = list(
      postfields = raw(),
      postfieldsize_large = 0,
      httpheader = c("Accept:", "Content-Type:")
    ),
    DELETE = list(customrequest = "DELETE", httpheader = "Accept:")
  )
  for (m in names(methods)) {
    b <- ssrf_prepare_hop(
      "https://pin.example/",
      policy,
      request = list(method = m)
    )
    opts <- ssrfr:::transport_options(b, "93.184.216.34", 5, caps_modern)
    for (field in names(methods[[m]])) {
      expect_identical(opts[[field]], methods[[m]][[field]], label = m)
    }
  }
  # A field the plan carries is sent as the plan says, never suppressed.
  b <- ssrf_prepare_hop(
    "https://pin.example/",
    policy,
    request = list(
      method = "POST",
      headers = c(`content-type` = "text/plain", ACCEPT = "text/html"),
      body = "x"
    )
  )
  opts <- ssrfr:::transport_options(b, "93.184.216.34", 5, caps_modern)
  expect_identical(
    opts$httpheader,
    c("content-type: text/plain", "ACCEPT: text/html", "Expect:")
  )
  # Expect is the transport's (§2.5): 100-continue lets libcurl send the
  # request again after a 417. prepare refuses it in a plan, and the
  # builder suppresses it on every body, whatever a plan says.
  planted <- list(
    method = "POST",
    headers = c(Expect = "100-continue"),
    body = charToRaw("x")
  )
  lines <- ssrfr:::request_options(planted, policy)$httpheader
  expect_identical(lines[[length(lines)]], "Expect:")
})

# r-binding.md §7, Rules: one place dials. Walk every closure in the
# installed namespace, nested closures included, for calls to a network entry
# point; only the resolver wrapper and the transport wrapper may make one.
test_that("one place dials", {
  ns <- asNamespace("ssrfr")
  callers <- network_callers(ns)
  expect_setequal(names(callers), c("dep_nslookup", "dep_curl_transfer"))
  expect_identical(callers[["dep_nslookup"]], "nslookup")
  expect_setequal(
    strsplit(callers[["dep_curl_transfer"]], ",", fixed = TRUE)[[1L]],
    c("new_handle", "handle_setopt", "multi_add", "multi_run")
  )

  # Positive control: a planted closure, nested one level down, is found.
  planted <- new.env()
  planted$sneaky <- function(u) {
    inner <- function() curl::curl_fetch_memory(u)
    inner
  }
  planted$quiet <- function(u) paste0(u, "/")
  expect_named(network_callers(planted), "sneaky")
})

# r-binding.md §6-§7: the trace matcher fails safe. Synthetic traces: none,
# garbled, another address or port are mismatches; the pinned address is a
# match, an IPv6 address compared as a raddr value (INV-3).
test_that("the trace matcher fails safe", {
  check <- ssrfr:::pin_check
  expect_identical(check(character(), "127.0.0.1", 80L), "absent")
  expect_identical(
    check(
      c("Connecting to hostname: 127.0.0.1", "Connected to x"),
      "127.0.0.1",
      80L
    ),
    "absent"
  )
  expect_identical(
    check("Trying pinned.invalid:80...", "127.0.0.1", 80L),
    "garbled"
  )
  expect_identical(check("Trying 127.0.0.1...", "127.0.0.1", 80L), "garbled")
  expect_identical(
    check("Trying 127.0.0.1:80:81...", "127.0.0.1", 80L),
    "garbled"
  )
  expect_identical(check("Trying 999.0.0.1:80...", "127.0.0.1", 80L), "garbled")
  expect_identical(
    check("Trying 10.0.0.1:80...", "127.0.0.1", 80L),
    "other-address"
  )
  expect_identical(
    check("Trying 127.0.0.1:8080...", "127.0.0.1", 80L),
    "other-address"
  )
  expect_identical(
    check(
      c("Trying 127.0.0.1:80...", "Trying 10.0.0.1:80..."),
      "127.0.0.1",
      80L
    ),
    "other-address"
  )
  expect_identical(check("Trying 127.0.0.1:80...", "127.0.0.1", 80L), "match")
  # libcurl 8.x brackets an IPv6 address, 7.x does not; both are one value.
  for (line in c(
    "Trying [::1]:8080...",
    "Trying ::1:8080...",
    "Trying [0:0:0:0:0:0:0:1]:8080..."
  )) {
    expect_identical(check(line, "::1", 8080L), "match", label = line)
  }
  expect_identical(check("Trying [::2]:8080...", "::1", 8080L), "other-address")
  # A raddr failure is never a match (INV-11).
  local_mocked_bindings(dep_raddr_pton = function(...) stop("raddr"))
  expect_identical(check("Trying 127.0.0.1:80...", "127.0.0.1", 80L), "garbled")
})

# The one segmenter of libcurl's header buffer, which the header measure
# and the header parse share. A status line at the start or after an empty
# line opens a block unless a complete final block precedes it; after a
# complete final block, every line is a trailer line.
test_that("the header buffer is segmented by the block before each line", {
  segments <- function(...) ssrfr:::header_segments(wire(...))
  blocks <- function(start, end, status, complete) {
    list(
      start = as.integer(start),
      end = as.integer(end),
      status = as.integer(status),
      complete = complete
    )
  }
  # An interim block, then the final one.
  s <- segments(
    "HTTP/1.1 100 Continue\r\n\r\n",
    "HTTP/1.1 200 OK\r\nA: 1\r\n\r\n"
  )
  expect_identical(
    s$blocks,
    blocks(c(1, 3), c(2, 5), c(100, 200), c(TRUE, TRUE))
  )
  expect_identical(s$trailers, integer())
  # Each line ends at its LF; a last line with none ends with the buffer.
  expect_identical(s$ends, c(23L, 25L, 42L, 48L, 50L))
  expect_identical(segments("HTTP/1.1 200 OK\r\nX: 1")$ends, c(17L, 21L))
  # A final block, then trailer lines, the first one status-shaped.
  s <- segments(
    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
    "HTTP/1.1 302 Found\r\nLocation: /t\r\n"
  )
  expect_identical(s$blocks, blocks(1, 3, 200, TRUE))
  expect_identical(s$trailers, 4:5)
  # After a complete final block, even an ended status-shaped block is
  # trailer lines.
  s <- segments(
    "HTTP/1.1 401 Unauthorized\r\n\r\n",
    "HTTP/1.1 200 OK\r\nX: 1\r\n\r\n"
  )
  expect_identical(s$blocks, blocks(1, 2, 401, TRUE))
  expect_identical(s$trailers, 3:5)
  # A block cut short before its empty line, after an interim block.
  s <- segments(
    "HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n",
    "HTTP/1.1 200 OK\r\nX: 1\r\n"
  )
  expect_identical(
    s$blocks,
    blocks(c(1, 4), c(3, 5), c(103, 200), c(TRUE, FALSE))
  )
  expect_identical(s$trailers, integer())
  # An empty buffer has no block and no trailer.
  s <- ssrfr:::header_segments(raw())
  expect_identical(s$blocks, blocks(integer(), integer(), integer(), logical()))
  expect_identical(s$trailers, integer())
  expect_identical(s$ends, integer())
  # One status-line test, RFC 9112 §4: a tab for the space is no status
  # line, and a NUL byte never breaks the reading.
  s <- segments("HTTP/1.1 200\tOK\r\nX: 1\r\n\r\n")
  expect_length(s$blocks$start, 0L)
  s <- ssrfr:::header_segments(c(
    wire("HTTP/1.1 200 OK\r\nX: a"),
    as.raw(0L),
    wire("b\r\n\r\n")
  ))
  expect_identical(s$blocks, blocks(1, 3, 200, TRUE))
})

# A last line with no LF is read as the buffer holds it, by the block before
# it: a status line opens a block, a lone CR is an empty line that ends one,
# and after a complete final block it is a trailer line.
test_that("a last line with no LF is segmented as the buffer holds it", {
  segments <- function(...) ssrfr:::header_segments(wire(...))
  blocks <- function(start, end, status, complete) {
    list(
      start = as.integer(start),
      end = as.integer(end),
      status = as.integer(status),
      complete = complete
    )
  }
  s <- segments("HTTP/1.1 100 X\r\n\r\nHTTP/1.1 200 OK")
  expect_identical(
    s$blocks,
    blocks(c(1, 3), c(2, 3), c(100, 200), c(TRUE, FALSE))
  )
  expect_identical(s$ends, c(16L, 18L, 33L))
  s <- segments("HTTP/1.1 100 X\r\n\r")
  expect_identical(s$blocks, blocks(1, 2, 100, TRUE))
  expect_identical(s$lines, c("HTTP/1.1 100 X", ""))
  s <- segments("HTTP/1.1 200 OK\r\nX: 1")
  expect_identical(s$blocks, blocks(1, 2, 200, FALSE))
  s <- segments("HTTP/1.1 200 OK\r\n\r\nX: 1")
  expect_identical(s$trailers, 3L)
  s <- segments("HTTP/1.1 101 S\r\n\r\nZ")
  expect_identical(s$blocks, blocks(1, 2, 101, TRUE))
  expect_identical(s$trailers, integer())
})

# The header measure runs the segmenter on every growth of the header
# buffer, inside callbacks that run with interrupts suspended, so one pass
# costs time linear in the buffer. Eight times the interim blocks, a run of
# 1xx responses, take about eight times as long, where a quadratic pass
# takes sixty-four; the ratio, unlike a wall-clock bound, holds under
# coverage instrumentation and on a slow runner.
test_that("the header buffer is segmented in linear time", {
  skip_on_cran()
  block <- "HTTP/1.1 100 X\r\n\r\n"
  # Seconds a call, from calls repeated until a batch takes 0.25 s: Windows
  # times in steps of 10 ms, where one 64 KiB call takes about that long
  # (r-binding.md §7, Harness notes).
  timed <- function(kib) {
    count <- (kib * 1024) %/% nchar(block)
    buffer <- wire(strrep(block, count))
    expect_length(ssrfr:::header_segments(buffer)$blocks$start, count)
    reps <- 1L
    repeat {
      t <- system.time(
        for (i in seq_len(reps)) {
          ssrfr:::header_segments(buffer)
        }
      )[["elapsed"]]
      if (t >= 0.25 || reps >= 256L) {
        return(max(t, 0.001) / reps)
      }
      reps <- reps * 2L
    }
  }
  small <- timed(64)
  large <- timed(512)
  expect_lt(large / small, 24)
})

# A server can trickle interim 1xx blocks, which carry no field, so only
# max_header_bytes bounds the buffer, and the header measure segments it on
# every growth. Each growth reads only the bytes after the last line the
# reading before it ended, and classifies only the lines they hold: eight
# times the blocks, a line at a time, cost eight times the bytes read and
# the lines classified, where segmenting each growth whole costs sixty-four.
# The work is counted, not timed, so the ratio holds on any runner.
test_that("a header trickled a line at a time is segmented in linear work", {
  work <- new.env(parent = emptyenv())
  read_lines <- ssrfr:::header_lines
  classify <- ssrfr:::classify_lines
  local_mocked_bindings(
    header_lines = function(bytes) {
      work$bytes <- work$bytes + length(bytes)
      read_lines(bytes)
    },
    classify_lines = function(state, lines, from, to) {
      work$lines <- work$lines + max(to - from + 1L, 0L)
      classify(state, lines, from, to)
    }
  )
  block <- "HTTP/1.1 100 X\r\n\r\n"
  trickled <- function(kib) {
    work$bytes <- 0
    work$lines <- 0
    count <- (kib * 1024) %/% nchar(block)
    buffer <- wire(strrep(block, count))
    seen <- new.env(parent = emptyenv())
    for (n in which(buffer == as.raw(10L))) {
      ssrfr:::measure_header(seen, buffer[seq_len(n)])
    }
    expect_length(seen$segments$blocks$start, count)
    c(bytes = work$bytes, lines = work$lines)
  }
  small <- trickled(2)
  large <- trickled(16)
  expect_lt(large[["bytes"]] / small[["bytes"]], 12)
  expect_lt(large[["lines"]] / small[["lines"]], 12)
})

test_that("response headers are read from the final block only", {
  raw <- charToRaw(paste0(
    "HTTP/1.1 100 Continue\r\n\r\n",
    "HTTP/1.1 302 Found\r\n",
    "Location: /a\r\n",
    "Content-Type: text/html; charset=utf-8\r\n",
    "X-Folded: one\r\n two\r\n",
    "Set-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n"
  ))
  parsed <- ssrfr:::parse_response_headers(raw)
  expect_identical(parsed$status, 302L)
  h <- parsed$headers
  expect_named(
    h,
    c("location", "content-type", "x-folded", "set-cookie", "set-cookie")
  )
  expect_identical(unname(h[["x-folded"]]), "one two")
  # libcurl appends a chunked body's trailer section after the header's
  # empty line; its fields are not header fields.
  trailed <- ssrfr:::parse_response_headers(charToRaw(paste0(
    "HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n",
    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
    "Location: /trailer\r\nHTTP/1.1 302 Found\r\n\r\n"
  )))
  expect_identical(trailed$headers, c(`transfer-encoding` = "chunked"))
  expect_null(ssrfr:::parse_response_headers(charToRaw("garbage\r\n")))
  expect_null(
    ssrfr:::parse_response_headers(charToRaw("HTTP/1.1 200 OK\r\nno colon\r\n"))
  )
  expect_null(ssrfr:::parse_response_headers(as.raw(c(0x48, 0x00, 0x49))))
})

# libcurl reads no header after a complete final block, so the status and
# the fields come from the one complete final block, and every line after
# it is a trailer line. A buffer with a second final block reads as the
# first one and trailers; libcurl reports the last status, which then
# disagrees, and the fetch fails before the first one's Location reaches the
# binding (test-fetch.R, "a status that disagrees with the header block").
test_that("status and fields come from the complete final block", {
  parsed <- ssrfr:::parse_response_headers(wire(
    "HTTP/1.1 100 Continue\r\n\r\n",
    "HTTP/1.1 401 Unauthorized\r\n",
    "Location: /a\r\nWWW-Authenticate: Basic realm=\"x\"\r\n\r\n",
    "HTTP/1.1 100 Continue\r\n\r\n",
    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"
  ))
  expect_identical(parsed$status, 401L)
  expect_named(parsed$headers, c("location", "www-authenticate"))
  expect_false("content-type" %in% names(parsed$headers))
  # A trailer section follows the final block with no empty line of its
  # own, so a trailer line shaped like a status line never starts a block.
  forged <- ssrfr:::parse_response_headers(wire(
    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
    "HTTP/1.1 302 Found\r\nLocation: /trailer\r\n"
  ))
  expect_identical(forged$status, 200L)
  expect_identical(forged$headers, c(`transfer-encoding` = "chunked"))
  # A buffer whose only final block never ends is not a response.
  expect_null(ssrfr:::parse_response_headers(wire(
    "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nX: 1\r\n"
  )))
})

# RFC 9110 §5.5: a field value may carry obs-text. The block is read as
# bytes, so a Latin-1 byte neither fails the parse nor raises a warning that
# would quote the header block (INV-12).
test_that("a header value with obs-text is kept byte for byte", {
  e9 <- as.raw(0xe9)
  raw <- c(
    wire("HTTP/1.1 200 OK\r\n", "Content-Disposition: attachment; name=caf"),
    e9,
    wire("\r\nX-Utf8: caf\u00e9\r\n", "Content-Type: text/"),
    e9,
    wire("\r\nSet-Cookie: secret=1\r\n\r\n")
  )
  h <- NULL
  expect_no_warning(h <- ssrfr:::parse_response_headers(raw)$headers)
  expect_named(
    h,
    c("content-disposition", "x-utf8", "content-type", "set-cookie")
  )
  disposition <- unname(h[["content-disposition"]])
  expect_identical(
    charToRaw(disposition),
    c(wire("attachment; name=caf"), as.raw(0xe9))
  )
  expect_identical(Encoding(disposition), "bytes")
  expect_identical(unname(h[["x-utf8"]]), "caf\u00e9")
  expect_identical(Encoding(unname(h[["x-utf8"]])), "UTF-8")
  expect_identical(
    charToRaw(unname(h[["content-type"]])),
    c(wire("text/"), as.raw(0xe9))
  )
  # A media type that is not text is withheld, never an error.
  expect_identical(
    ssrfr:::display_media_type(unname(h[["content-type"]])),
    "<withheld>"
  )
})

test_that("the displayed media type drops parameters and withholds junk", {
  show <- ssrfr:::display_media_type
  expect_identical(show("Text/HTML; charset=utf-8"), "text/html")
  expect_identical(show(character()), NA_character_)
  expect_identical(show("\033[31mred\033[0m/x"), "<withheld>")
  expect_identical(show("not a type"), "<withheld>")
})

test_that("libcurl's capabilities are read once per session", {
  cache <- ssrfr:::curl_capabilities_cache
  saved <- cache$value
  withr::defer(assign("value", saved, envir = cache))
  version <- ssrfr:::dep_curl_version
  calls <- new.env(parent = emptyenv())
  calls$n <- 0L
  local_mocked_bindings(dep_curl_version = function() {
    calls$n <- calls$n + 1L
    version()
  })
  cache$value <- NULL
  first <- ssrfr:::session_curl_capabilities()
  second <- ssrfr:::session_curl_capabilities()
  expect_identical(first, ssrfr:::read_curl_capabilities())
  expect_identical(second, first)
  # The two session readings made one call; the direct reading another.
  expect_identical(calls$n, 2L)
  # A failed reading is not kept.
  cache$value <- NULL
  local_mocked_bindings(dep_curl_version = function() stop("x"))
  expect_null(ssrfr:::session_curl_capabilities())
  expect_null(cache$value)
})

test_that("libcurl's capabilities are read through guarded wrappers", {
  caps <- ssrfr:::read_curl_capabilities()
  expect_s3_class(caps$version, "numeric_version")
  expect_type(caps$protocols_str, "logical")
  for (wrapper in c("dep_curl_version", "dep_curl_options")) {
    for (failure in list(function() stop("x"), function() NULL, function() {
      42
    })) {
      local({
        do.call(local_mocked_bindings, stats::setNames(list(failure), wrapper))
        expect_null(ssrfr:::read_curl_capabilities(), label = wrapper)
      })
    }
  }
})
