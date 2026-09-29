# The request plan enters at prepare (ssrfr-v1.md §2.3): its header and body
# rules raise ssrfr_error_invalid_request, a plan of the wrong shape
# ssrfr_error_invalid_argument (§6.6), and both before any parse or
# resolution. Every URL here is an address literal or is refused before
# resolution, and the resolver is a tripwire, so no test makes a DNS query.

prepare <- function(
  request,
  policy = ssrf_policy(),
  url = "http://93.184.216.34/"
) {
  local_mocked_bindings(
    dep_nslookup = function(query) stop("resolver called")
  )
  ssrf_prepare_hop(url, policy, request = request)
}

test_that("a valid plan is carried sanitized, unchanged", {
  b <- prepare(list(
    method = "PUT",
    headers = c(`X-Api-Key` = "k", Accept = "application/json", `X-Empty` = ""),
    body = "{\"a\":1}",
    carry = c("ACCEPT", "accept")
  ))
  expect_s3_class(b, "ssrfr_binding")
  expect_identical(b$request$method, "PUT")
  expect_identical(
    b$request$headers,
    c(`X-Api-Key` = "k", Accept = "application/json", `X-Empty` = "")
  )
  expect_identical(b$request$body, charToRaw("{\"a\":1}"))
  expect_identical(b$request$carry, "accept")

  # A list of strings is accepted as headers; list() is a plain GET.
  b <- prepare(list(headers = list(`X-A` = "1")))
  expect_identical(b$request$headers, c(`X-A` = "1"))
  b <- prepare(list())
  expect_identical(b$request$method, "GET")
  expect_length(b$request$headers, 0L)
  expect_null(b$request$body)
  expect_identical(b$request$carry, character())
})

test_that("transport-owned and pseudo-header fields are refused", {
  owned <- c(
    "Host",
    "connection",
    "Proxy-Connection",
    "KEEP-ALIVE",
    "Transfer-Encoding",
    "TE",
    "Trailer",
    "Upgrade",
    "Content-Length",
    "Accept-Encoding",
    "User-Agent",
    "Expect",
    "EXPECT",
    ":authority",
    ":path"
  )
  for (name in owned) {
    expect_error(
      prepare(list(headers = stats::setNames("x", name))),
      class = "ssrfr_error_invalid_request",
      label = name
    )
  }
})

test_that("a field name that is not a token, or CR or LF, is refused", {
  bad <- list(
    stats::setNames("x", "Bad Name"),
    stats::setNames("x", "X(y)"),
    stats::setNames("x", "Xé"),
    c(`X-A` = "a\r\nInjected: 1"),
    c(`X-A` = "a\nb"),
    c(`X-A` = "a\rb")
  )
  for (h in bad) {
    expect_error(
      prepare(list(headers = h)),
      class = "ssrfr_error_invalid_request"
    )
  }
  expect_error(
    prepare(list(method = "GE T")),
    class = "ssrfr_error_invalid_request"
  )
  expect_error(
    prepare(list(method = "HEAD", body = "x")),
    class = "ssrfr_error_invalid_request"
  )
})

test_that("Authorization, Proxy-Authorization and Cookie cannot be nominated", {
  headers <- c(
    Authorization = "Bearer t",
    `Proxy-Authorization` = "Basic x",
    Cookie = "a=b",
    `X-Safe` = "1"
  )
  # Supplying them is allowed; they are simply never carryable.
  expect_s3_class(prepare(list(headers = headers)), "ssrfr_binding")
  for (name in c("authorization", "Proxy-Authorization", "COOKIE")) {
    expect_error(
      prepare(list(headers = headers, carry = name)),
      class = "ssrfr_error_invalid_request",
      label = name
    )
  }
  # A nomination must name a field the plan holds.
  expect_error(
    prepare(list(headers = headers, carry = "X-Other")),
    class = "ssrfr_error_invalid_request"
  )
  expect_identical(
    prepare(list(headers = headers, carry = "x-safe"))$request$carry,
    "x-safe"
  )
})

test_that("metadata markers are refused unless an endpoint is allowed", {
  markers <- ssrf_vocabulary("metadata_headers")$header
  expect_length(markers, 10L)
  expect_identical(anyDuplicated(tolower(markers)), 0L)
  exact <- ssrf_policy(allow_ranges = "169.254.169.254/32")
  broad <- ssrf_policy(allow_ranges = "169.254.0.0/16")
  v6 <- ssrf_policy(allow_ranges = "fd00:ec2::254/128")
  for (name in c(markers, toupper(markers), tolower(markers))) {
    h <- stats::setNames("true", name)
    expect_error(
      prepare(list(headers = h)),
      class = "ssrfr_error_invalid_request",
      label = name
    )
    expect_error(
      prepare(list(headers = h), broad),
      class = "ssrfr_error_invalid_request",
      label = paste(name, "under a broad range")
    )
    expect_s3_class(prepare(list(headers = h), exact), "ssrfr_binding")
    expect_s3_class(prepare(list(headers = h), v6), "ssrfr_binding")
  }
  # A name only near a marker is an ordinary field.
  near <- c(
    `X-Metadata` = "1",
    `Metadata-Flavour` = "1",
    `X-Security-Token` = "t"
  )
  expect_s3_class(prepare(list(headers = near)), "ssrfr_binding")
  # A failing raddr wrapper leaves the marker refused (INV-11).
  local_mocked_bindings(dep_raddr_within_any = function(...) stop("raddr"))
  expect_error(
    prepare(list(headers = c(Metadata = "true")), exact),
    class = "ssrfr_error_invalid_request"
  )
})

test_that("a plan of the wrong shape is an invalid argument", {
  bad <- list(
    "GET",
    data.frame(method = "GET"),
    list(method = "GET", verb = "GET"),
    list("GET"),
    list(method = c("GET", "POST")),
    list(method = NA_character_),
    list(headers = c("x", "y")),
    list(headers = c(`X-A` = NA)),
    list(headers = list(`X-A` = 1)),
    list(headers = 1:2),
    list(body = 1:3),
    list(body = c("a", "b")),
    list(carry = 1)
  )
  for (request in bad) {
    expect_error(
      prepare(request),
      class = "ssrfr_error_invalid_argument"
    )
  }
})

test_that("a plan is checked before the URL is parsed or resolved", {
  local_mocked_bindings(
    dep_rurl_verdicts = function(...) stop("parsed"),
    dep_nslookup = function(...) stop("resolved")
  )
  expect_error(
    ssrf_prepare_hop(
      "http://example.com/",
      ssrf_policy(),
      request = list(headers = c(Host = "x"))
    ),
    class = "ssrfr_error_invalid_request"
  )
})
