# Policy fields and construction validation (ssrfr-v1.md §5.3), with hostname
# rules normalized as §5.0 says.

expect_invalid_policy <- function(...) {
  expect_error(ssrf_policy(...), class = "ssrfr_error_invalid_policy")
}

test_that("the default policy builds with every §5.3 default", {
  p <- ssrf_policy()
  expect_s3_class(p, "ssrfr_policy")
  expect_named(
    p,
    c(
      "allow_schemes",
      "allow_ports",
      "deny_hosts",
      "allow_hosts",
      "deny_ranges",
      "allow_ranges",
      "allow_userinfo",
      "max_redirects",
      "connect_timeout",
      "total_timeout",
      "max_response_size",
      "max_header_bytes",
      "max_header_fields",
      "max_url_length",
      "user_agent"
    )
  )
  expect_identical(p$allow_schemes, c("http", "https"))
  expect_identical(p$allow_ports, c(80L, 443L))
  expect_identical(p$deny_hosts, character())
  expect_identical(p$allow_hosts, character())
  expect_identical(p$deny_ranges, character())
  expect_identical(p$allow_ranges, character())
  expect_false(p$allow_userinfo)
  expect_identical(p$max_redirects, 20)
  expect_identical(p$connect_timeout, 3)
  expect_identical(p$total_timeout, 30)
  expect_identical(p$max_response_size, 10 * 1024^2)
  expect_identical(p$max_header_bytes, 16 * 1024)
  expect_identical(p$max_header_fields, 128)
  expect_identical(p$max_url_length, 8000)
})

test_that("the default user agent is assembled from DESCRIPTION", {
  version <- as.character(utils::packageVersion("ssrfr"))
  expect_identical(
    ssrf_policy()$user_agent,
    paste0("ssrfr/", version, " (+https://gitlab.com/bart-turczynski/ssrfr)")
  )
})

test_that("an empty or missing entry is a construction error", {
  expect_invalid_policy(deny_hosts = "")
  expect_invalid_policy(allow_hosts = c("example.com", NA))
  expect_invalid_policy(deny_ranges = "")
  expect_invalid_policy(allow_ranges = NA_character_)
  expect_invalid_policy(allow_schemes = "")
})

test_that("an entry padded with whitespace is a construction error", {
  expect_invalid_policy(deny_hosts = " example.com")
  expect_invalid_policy(allow_hosts = "example.com\t")
  expect_invalid_policy(deny_hosts = "example.com\u00a0")
  expect_invalid_policy(deny_ranges = " 10.0.0.0/8")
  expect_invalid_policy(allow_ranges = "10.0.0.0/8\n")
  expect_invalid_policy(allow_schemes = "https ")
})

test_that("an entry joining several values is a construction error", {
  expect_invalid_policy(deny_hosts = "com, ru")
  expect_invalid_policy(deny_hosts = "com,ru")
  expect_invalid_policy(allow_hosts = "a.example b.example")
  expect_invalid_policy(deny_ranges = "10.0.0.0/8;192.168.0.0/16")
  expect_invalid_policy(allow_ranges = "10.0.0.0/8,::1/128")
  expect_invalid_policy(allow_schemes = "http,https")
})

test_that("an invalid hostname rule is a construction error", {
  expect_invalid_policy(deny_hosts = "*.corp")
  expect_invalid_policy(deny_hosts = "api.*.corp")
  expect_invalid_policy(deny_hosts = ".")
  expect_invalid_policy(deny_hosts = "example.com:80")
  expect_invalid_policy(deny_hosts = "example.com/path")
  expect_invalid_policy(deny_hosts = "user@example.com")
  expect_invalid_policy(deny_hosts = "https://example.com/")
  expect_invalid_policy(deny_hosts = "a.b?c")
  expect_invalid_policy(deny_hosts = "a#b")
  expect_invalid_policy(deny_hosts = "a|b")
  expect_invalid_policy(deny_hosts = "1.2.3.08")
  expect_invalid_policy(allow_hosts = "10.0.0.1")
  expect_invalid_policy(allow_hosts = "[::1]")
  expect_invalid_policy(allow_hosts = "0x7f.1")
  expect_invalid_policy(deny_hosts = 1)
})

test_that("a range raddr cannot parse is a construction error", {
  expect_invalid_policy(deny_ranges = "10.0.0.1")
  expect_invalid_policy(deny_ranges = "192.168.1.1/24")
  expect_invalid_policy(deny_ranges = "10.0.0.0/33")
  expect_invalid_policy(allow_ranges = "010.0.0.0/8")
  expect_invalid_policy(allow_ranges = "fe80::%eth0/64")
  expect_invalid_policy(allow_ranges = "example.com/8")
  expect_invalid_policy(allow_ranges = 10)
})

test_that("a missing, NA, negative, infinite or fractional limit is an error", {
  limits <- c(
    "max_redirects",
    "connect_timeout",
    "total_timeout",
    "max_response_size",
    "max_header_bytes",
    "max_header_fields",
    "max_url_length"
  )
  bad <- list(NULL, numeric(), NA_real_, NA, -1, Inf, NaN, 1.5, "10", c(1, 2))
  for (limit in limits) {
    for (value in bad) {
      args <- stats::setNames(list(value), limit)
      expect_error(
        do.call(ssrf_policy, args),
        class = "ssrfr_error_invalid_policy",
        label = paste(limit, "=", deparse(value))
      )
    }
  }
})

test_that("0 is accepted by max_redirects only, and never means unlimited", {
  expect_identical(ssrf_policy(max_redirects = 0)$max_redirects, 0)
  expect_invalid_policy(connect_timeout = 0)
  expect_invalid_policy(total_timeout = 0)
  expect_invalid_policy(max_response_size = 0)
  expect_invalid_policy(max_header_bytes = 0)
  expect_invalid_policy(max_header_fields = 0)
  expect_invalid_policy(max_url_length = 0)
})

test_that("every limit can be raised without a ceiling", {
  p <- ssrf_policy(
    max_redirects = 1e6,
    connect_timeout = 86400,
    total_timeout = 1e7,
    max_response_size = 2^40,
    max_header_bytes = 2^31,
    max_header_fields = 1e6,
    max_url_length = 8e6
  )
  expect_identical(p$max_response_size, 2^40)
  expect_identical(p$max_header_bytes, 2^31)
})

test_that("a user agent that is not a valid field value is an error", {
  expect_invalid_policy(user_agent = "agent\r\nX-Injected: 1")
  expect_invalid_policy(user_agent = "agent\nX-Injected: 1")
  expect_invalid_policy(user_agent = "agent\r")
  expect_invalid_policy(user_agent = "agent\001")
  expect_invalid_policy(user_agent = "agent\177")
  expect_invalid_policy(user_agent = " agent")
  expect_invalid_policy(user_agent = "agent\t")
  expect_invalid_policy(user_agent = "")
  expect_invalid_policy(user_agent = NA_character_)
  expect_invalid_policy(user_agent = c("a", "b"))
  expect_identical(
    ssrf_policy(user_agent = "my-app/1.0 (+https://example.com)\tx")$user_agent,
    "my-app/1.0 (+https://example.com)\tx"
  )
})

test_that("schemes, ports and the userinfo flag are validated", {
  expect_invalid_policy(allow_schemes = "ftp")
  expect_invalid_policy(allow_schemes = "HTTP")
  expect_invalid_policy(allow_schemes = character())
  expect_invalid_policy(allow_ports = 0)
  expect_invalid_policy(allow_ports = 65536)
  expect_invalid_policy(allow_ports = 80.5)
  expect_invalid_policy(allow_ports = NA_real_)
  expect_invalid_policy(allow_ports = "80")
  expect_invalid_policy(allow_ports = numeric())
  expect_invalid_policy(allow_userinfo = NA)
  expect_invalid_policy(allow_userinfo = "yes")
  expect_identical(ssrf_policy(allow_schemes = "https")$allow_schemes, "https")
  expect_identical(ssrf_policy(allow_ports = 8443)$allow_ports, 8443L)
  expect_true(ssrf_policy(allow_userinfo = TRUE)$allow_userinfo)
})

test_that("hostname rules are stored normalized", {
  p <- ssrf_policy(
    deny_hosts = c("EXAMPLE.com.", ".Corp", "bücher.example", "BÜCHER.example"),
    allow_hosts = "metadata.google.internal."
  )
  expect_identical(
    p$deny_hosts,
    c(
      "example.com",
      ".corp",
      "xn--bcher-kva.example",
      "xn--bcher-kva.example"
    )
  )
  expect_identical(p$allow_hosts, "metadata.google.internal")
  expect_identical(ssrf_policy(deny_hosts = NULL)$deny_hosts, character())
})

test_that("hostname rules fold case the same way in any locale", {
  old <- Sys.getlocale("LC_CTYPE")
  on.exit(Sys.setlocale("LC_CTYPE", old), add = TRUE)
  # Unavailable locales leave LC_CTYPE unchanged, which still tests the rule.
  for (locale in c("tr_TR.UTF-8", "C")) {
    suppressWarnings(Sys.setlocale("LC_CTYPE", locale))
    expect_identical(
      ssrf_policy(deny_hosts = "INTERNAL.example")$deny_hosts,
      "internal.example"
    )
  }
})

test_that("valid ranges are kept as written", {
  p <- ssrf_policy(
    deny_ranges = c("203.0.113.7/32", "2001:db8::/32"),
    allow_ranges = c("10.0.0.0/8", "::1/128")
  )
  expect_identical(p$deny_ranges, c("203.0.113.7/32", "2001:db8::/32"))
  expect_identical(p$allow_ranges, c("10.0.0.0/8", "::1/128"))
})

test_that("a policy prints every field", {
  out <- capture.output(print(ssrf_policy(deny_hosts = ".corp")))
  expect_identical(out[[1L]], "<ssrfr_policy>")
  expect_match(out, "deny_hosts +\"\\.corp\"", all = FALSE)
  expect_match(out, "max_response_size +10485760", all = FALSE)
  expect_match(out, "allow_ports +80, 443", all = FALSE)
  expect_length(out, 16L)
})
