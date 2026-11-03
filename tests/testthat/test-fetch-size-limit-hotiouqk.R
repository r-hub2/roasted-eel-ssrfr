# A size-limit failure carries what the transport observed before the limit
# ended it (ssrfr-v1.md §2.3, §6.6; SSRF-hotiouqk): at the decoded-body check,
# the final status line's status and the decoded bytes reached; at a header
# limit, no status. Neither makes the binding a `from`.

# A raw server's response: `head`, then `size` body bytes in 64 KiB writes,
# until they are sent or the client goes away.
large_body <- function(head, size) {
  respond <- function(con) {
    writeBin(HEAD, con)
    left <- SIZE
    while (left > 0) {
      n <- min(65536, left)
      sent <- tryCatch(
        {
          writeBin(as.raw(rep(0x61, n)), con)
          flush(con)
          TRUE
        },
        error = function(e) FALSE
      )
      if (!sent) {
        break
      }
      left <- left - n
    }
  }
  body(respond) <- do.call(
    substitute,
    list(body(respond), list(HEAD = head, SIZE = size))
  )
  respond
}

planted_value <- "planted-header-value-hotiouqk"

# A 404 with a 2 MiB body, fetched under a 512 KiB max_response_size.
fetch_large_404 <- function(env = parent.frame()) {
  size <- 2 * 1024^2
  server <- local_raw_server(
    large_body(
      wire(
        "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n",
        "X-Planted: ",
        planted_value,
        "\r\nContent-Length: ",
        format(size, scientific = FALSE),
        "\r\nConnection: close\r\n\r\n"
      ),
      size
    ),
    env = env
  )
  policy <- loopback_policy(server$port, max_response_size = 524288)
  r <- guarded_get(pinned_url(server$port), policy)
  list(result = r, binding = attr(r, "binding"), policy = policy, size = size)
}

test_that("a 404 whose body passes max_response_size records its status", {
  mock_answers("127.0.0.1")
  got <- fetch_large_404()
  r <- got$result
  expect_s3_class(r, "ssrfr_failure")
  expect_identical(r$cause, "response-too-large")
  expect_identical(r$detail$check, "decoded-bytes")
  expect_identical(r$detail$limit, "max_response_size")
  expect_identical(got$binding$state$status, 404L)
  expect_identical(r$detail$status, 404L)
  expect_type(r$detail$observed_bytes, "double")
  observed <- r$detail$observed_bytes
  expect_gt(observed, 524288)
  expect_lte(observed, got$size)
  # The rendering shows the status and the bytes reached, never a header
  # value.
  out <- capture.output(print(r))
  expect_true(any(grepl("^ +status: 404$", out)))
  expect_true(any(grepl(paste0("^ +observed_bytes: ", observed, "$"), out)))
  expect_false(any(grepl(planted_value, out, fixed = TRUE)))
  expect_false(any(grepl(planted_value, format(got$binding), fixed = TRUE)))
})

test_that("a size-limit failure's binding is still refused as from", {
  mock_answers("127.0.0.1")
  got <- fetch_large_404()
  expect_identical(got$result$cause, "response-too-large")
  expect_false(got$binding$state$fetched)
  # Location is not recorded at a size limit.
  expect_null(got$binding$state$location_count)
  expect_null(got$binding$state$location)
  expect_error(
    ssrf_prepare_hop(pinned_url(1L), got$policy, from = got$binding),
    regexp = "no successful response",
    class = "ssrfr_error_invalid_from"
  )
})

test_that("a header-limit failure records no status", {
  mock_answers("127.0.0.1")
  fields <- paste0("X-Field-", 1:30, ": v\r\n", collapse = "")
  server <- local_raw_server(large_body(
    wire(
      "HTTP/1.1 404 Not Found\r\n",
      fields,
      "Content-Length: 4096\r\nConnection: close\r\n\r\n"
    ),
    4096
  ))
  policy <- loopback_policy(server$port, max_header_fields = 20)
  r <- guarded_get(pinned_url(server$port), policy)
  binding <- attr(r, "binding")
  expect_s3_class(r, "ssrfr_failure")
  expect_identical(r$cause, "response-too-large")
  expect_identical(r$detail$check, "header")
  expect_identical(r$detail$limit, "max_header_fields")
  expect_null(binding$state$status)
  expect_null(r$detail$status)
  expect_null(r$detail$observed_bytes)
  expect_false(binding$state$fetched)
})

# §2.3: the status is transport-observed. At the decoded-body check it is
# recorded only when libcurl reports the final status line's status; a
# status libcurl does not report, or one that disagrees, records none.
test_that("a decoded-bytes failure records no status libcurl disagrees with", {
  stub_transfer <- function(reported) {
    function(opts, on_body, debug, progress) {
      debug(0L, charToRaw("Trying 192.0.2.1:80...\n"))
      headers <- wire(
        "HTTP/1.1 404 Not Found\r\n",
        "Content-Type: text/plain\r\n\r\n"
      )
      go <- on_body(as.raw(rep(0x61, 2000)), function() headers)
      list(
        aborted = !go,
        error = NULL,
        status = reported,
        headers = headers,
        connect = 0.01
      )
    }
  }
  local_mocked_bindings(dep_nslookup = function(query) "192.0.2.1")
  policy <- ssrf_policy(allow_ranges = "192.0.2.0/24", max_response_size = 1000)
  for (reported in c(404L, 0L, 500L)) {
    local({
      local_mocked_bindings(dep_curl_transfer = stub_transfer(reported))
      b <- ssrf_prepare_hop("http://big.invalid/", policy, request = list())
      r <- ssrf_fetch(b)
      label <- paste("libcurl reports", reported)
      expect_s3_class(r, "ssrfr_failure")
      expect_identical(r$cause, "response-too-large", label = label)
      expect_identical(r$detail$check, "decoded-bytes", label = label)
      expect_identical(r$detail$observed_bytes, 2000, label = label)
      want <- if (reported == 404L) 404L
      expect_identical(r$detail$status, want, label = label)
      expect_identical(b$state$status, want, label = label)
    })
  }
})
