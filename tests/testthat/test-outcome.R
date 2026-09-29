# Refusals and operational failures (ssrfr-v1.md §6.2), the minimized
# projection (§6.4) and redaction (§2.3); r-binding.md §7, "Minimized
# projection and redaction". Printed output is asserted with explicit
# expectations: tests/testthat/_snaps/ is git-ignored, so snapshots would never
# reach CI.

# Values planted where a careless record could pick them up. None may appear
# in any rendering or condition message.
planted <- c(
  userinfo = "s3cretPW",
  header = "Bearer TOKEN-4f9a",
  body = "BODY-7c21",
  proxy = "PROXYPW-19e3"
)

planted_refusal <- function(code = "loopback") {
  new_ssrf_refusal(
    code,
    hop = 3,
    host = "internal.example",
    address = "127.0.0.1",
    url = "https://alice:s3cretPW@internal.example/path?q=1",
    detail = list(
      gate = "1a",
      category = "loopback",
      authorization = "Bearer TOKEN-4f9a",
      request = list(headers = c(Authorization = "Bearer TOKEN-4f9a")),
      body = "BODY-7c21",
      proxy = "http://proxyuser:PROXYPW-19e3@proxy.example:3128"
    )
  )
}

planted_failure <- function(cause = "connect-failed") {
  new_ssrf_failure(
    cause,
    hop = 2,
    host = "internal.example",
    address = "10.0.0.5",
    url = "http://alice:s3cretPW@internal.example:8080/",
    detail = list(
      limit = "max_header_bytes",
      header_value = "Bearer TOKEN-4f9a",
      body = "BODY-7c21",
      https_proxy = "socks5h://u:PROXYPW-19e3@127.0.0.1:1"
    )
  )
}

expect_no_planted <- function(text, label) {
  for (secret in planted) {
    expect_no_match(
      paste(text, collapse = "\n"),
      secret,
      fixed = TRUE,
      label = paste(label, "shows", names(planted)[planted == secret])
    )
  }
}

test_that("a refusal carries its reason code, host or address, and hop", {
  r <- planted_refusal("cloud-metadata")
  expect_s3_class(r, "ssrfr_refusal")
  expect_s3_class(r, "ssrfr_outcome")
  expect_false(inherits(r, "ssrfr_failure"))
  expect_identical(r$code, "cloud-metadata")
  expect_identical(r$hop, 3L)
  expect_identical(r$host, "internal.example")
  expect_identical(r$address, "127.0.0.1")
  expect_null(r$cause)
})

test_that("an operational failure carries its cause, not a reason code", {
  f <- planted_failure("timeout")
  expect_s3_class(f, "ssrfr_failure")
  expect_false(inherits(f, "ssrfr_refusal"))
  expect_identical(f$cause, "timeout")
  expect_identical(f$hop, 2L)
  expect_null(f$code)
})

test_that("an outcome takes only tokens from its own closed domain", {
  expect_error(
    new_ssrf_refusal("timeout", hop = 1),
    class = "ssrfr_error_invalid_argument"
  )
  expect_error(
    new_ssrf_failure("loopback", hop = 1),
    class = "ssrfr_error_invalid_argument"
  )
  expect_error(
    new_ssrf_refusal("Loopback", hop = 1),
    class = "ssrfr_error_invalid_argument"
  )
  expect_error(
    new_ssrf_refusal("loopback", hop = 0),
    class = "ssrfr_error_invalid_argument"
  )
  expect_error(
    new_ssrf_refusal("loopback", hop = 1, detail = list("unnamed")),
    class = "ssrfr_error_invalid_argument"
  )
  expect_error(
    new_ssrf_refusal("loopback", hop = 1, host = 1),
    class = "ssrfr_error_invalid_argument"
  )
})

test_that("ssrf_public_reason() returns one value for every code and cause", {
  codes <- ssrf_vocabulary("reason_codes")$code
  causes <- ssrf_vocabulary("causes")$cause
  projected <- c(
    vapply(
      codes,
      function(code) ssrf_public_reason(planted_refusal(code)),
      character(1)
    ),
    vapply(
      causes,
      function(cause) ssrf_public_reason(planted_failure(cause)),
      character(1)
    )
  )
  expect_length(projected, length(codes) + length(causes))
  expect_identical(unique(unname(projected)), "refused")
  expect_false("refused" %in% c(codes, causes))
})

test_that("ssrf_public_reason() refuses anything but a refusal or failure", {
  expect_error(
    ssrf_public_reason("loopback"),
    class = "ssrfr_error_invalid_argument"
  )
  expect_error(
    ssrf_public_reason(unclass(planted_refusal())),
    class = "ssrfr_error_invalid_argument"
  )
  expect_error(ssrf_public_reason(NULL), class = "ssrfr_error_invalid_argument")
})

test_that("print, format and conditions omit planted secrets", {
  r <- planted_refusal()
  f <- planted_failure()
  expect_no_planted(format(r), "format(refusal)")
  expect_no_planted(capture.output(print(r)), "print(refusal)")
  expect_no_planted(format(f), "format(failure)")
  expect_no_planted(capture.output(print(f)), "print(failure)")
  # Userinfo is gone from the object itself, not only from its rendering.
  expect_no_match(r$url, "s3cretPW", fixed = TRUE)
  expect_no_match(f$url, "s3cretPW", fixed = TRUE)

  conditions <- list(
    tryCatch(
      ssrf_policy(deny_hosts = "https://alice:s3cretPW@evil.example/"),
      error = identity
    ),
    tryCatch(
      ssrf_policy(allow_ranges = "http://u:PROXYPW-19e3@10.0.0.0/8"),
      error = identity
    ),
    tryCatch(
      ssrf_policy(user_agent = "x\r\nAuthorization: Bearer TOKEN-4f9a"),
      error = identity
    ),
    tryCatch(
      ssrf_policy(allow_schemes = "BODY-7c21"),
      error = identity
    ),
    tryCatch(
      ssrf_public_reason(unclass(r)),
      error = identity
    ),
    tryCatch(
      ssrf_vocabulary("Bearer TOKEN-4f9a"),
      error = identity
    ),
    tryCatch(
      new_ssrf_refusal("BODY-7c21", hop = 1),
      error = identity
    )
  )
  for (cond in conditions) {
    expect_s3_class(cond, "ssrfr_error")
    expect_no_planted(conditionMessage(cond), "a condition message")
    expect_no_planted(capture.output(print(cond)), "a printed condition")
    expect_no_planted(deparse(conditionCall(cond)), "a condition call")
  }
})

test_that("a URL rurl cannot parse is withheld whole", {
  f <- new_ssrf_failure(
    "protocol-error",
    hop = 1,
    url = "http://alice:s3cretPW@exa mple/"
  )
  expect_identical(f$url, "<withheld: not a parseable URL>")
  expect_no_planted(format(f), "format(failure)")
})

test_that("the rendering still names the predicate, address and hop", {
  out <- format(planted_refusal("loopback"))
  expect_identical(out[[1L]], "<ssrfr_refusal>")
  expect_match(out, "^  code: loopback$", all = FALSE)
  expect_match(out, "^  hop: 3$", all = FALSE)
  expect_match(out, "^  host: internal\\.example$", all = FALSE)
  expect_match(out, "^  address: 127\\.0\\.0\\.1$", all = FALSE)
  expect_match(
    out,
    "^  url: https://<redacted>@internal\\.example/path\\?q=1$",
    all = FALSE
  )
  expect_match(out, "^    gate: 1a$", all = FALSE)
  expect_match(out, "^    authorization: <withheld>$", all = FALSE)
  expect_match(out, "^    request: <withheld>$", all = FALSE)

  failure <- format(planted_failure("timeout"))
  expect_identical(failure[[1L]], "<ssrfr_failure>")
  expect_match(failure, "^  cause: timeout$", all = FALSE)
  expect_match(failure, "^    limit: max_header_bytes$", all = FALSE)

  # The callbacks that failed are ssrfr's own labels, shown in order.
  failed <- format(new_ssrf_failure(
    "protocol-error",
    hop = 1,
    detail = list(check = "callback-error", callback = c("data", "progress"))
  ))
  expect_match(failed, "^    callback: data, progress$", all = FALSE)
})

test_that("absent fields are left out of the rendering", {
  out <- format(new_ssrf_failure("timeout", hop = 1))
  expect_identical(out, c("<ssrfr_failure>", "  cause: timeout", "  hop: 1"))
  expect_identical(
    capture.output(print(new_ssrf_refusal("port", hop = 2))),
    c(
      "<ssrfr_refusal>",
      "  code: port",
      "  hop: 2"
    )
  )
})
