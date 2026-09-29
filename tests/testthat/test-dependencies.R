# r-binding.md §7: a failing dependency refuses. Each internal wrapper of
# R/dependencies.R is made to stop(), return NULL, or return a value of the
# wrong shape. A parser wrapper then refuses as `parse` (§5.3), a raddr
# wrapper as `malformed-address` (§6.5, §8 item 32), and neither raises an
# error to the caller (INV-11).

failure_modes <- list(
  stop = function(...) stop("dependency failed"),
  null = function(...) NULL,
  wrong_shape = function(...) list(unexpected = 42)
)

inspect_with <- function(wrapper, failure, url, base = NULL) {
  do.call(
    local_mocked_bindings,
    stats::setNames(list(failure), wrapper)
  )
  ssrf_inspect_url(url, base = base)
}

test_that("a failing parser wrapper refuses as parse, never an error", {
  wrappers <- c(
    "dep_rurl_verdicts",
    "dep_rurl_parse",
    "dep_rurl_serialize",
    "dep_rurl_resolve",
    "dep_rurl_diagnostics",
    "dep_curl_parse"
  )
  for (wrapper in wrappers) {
    for (mode in names(failure_modes)) {
      label <- paste(wrapper, mode)
      res <- NULL
      expect_no_error(
        res <- inspect_with(
          wrapper,
          failure_modes[[mode]],
          "/next",
          base = "https://example.com/a"
        )
      )
      expect_identical(res$code, "parse", label = label)
    }
  }
})

test_that("a failing raddr wrapper refuses as malformed-address", {
  wrappers <- c(
    "dep_raddr_pton",
    "dep_raddr_reachability",
    "dep_raddr_category",
    "dep_raddr_family",
    "dep_raddr_embeddings",
    "dep_raddr_within_any",
    "dep_raddr_format"
  )
  # Each of these admits when raddr answers.
  urls <- c(
    "http://93.184.216.34/",
    "http://[2606:4700:4700::1111]/",
    "http://[64:ff9b::5db8:d822]/"
  )
  for (url in urls) {
    expect_identical(ssrf_inspect_url(url)$code, NA_character_, label = url)
  }
  for (wrapper in wrappers) {
    for (mode in names(failure_modes)) {
      for (url in urls) {
        label <- paste(wrapper, mode, url)
        res <- NULL
        expect_no_error(
          res <- inspect_with(wrapper, failure_modes[[mode]], url)
        )
        expect_identical(res$code, "malformed-address", label = label)
      }
    }
  }
})

test_that("canonical_address() tells a name from a raddr failure", {
  canonical <- ssrfr:::canonical_address
  expect_identical(canonical("0:0:0:0:0:0:0:1"), "::1")
  expect_identical(canonical("127.0.0.1"), "127.0.0.1")
  expect_null(canonical("pinned.example.invalid"))
  local_mocked_bindings(dep_raddr_format = function(x) stop("raddr"))
  expect_identical(canonical("::1"), NA_character_)
  local_mocked_bindings(dep_raddr_pton = function(x) stop("raddr"))
  expect_null(canonical("::1"))
})

test_that("a dependency's warning is muffled and never refuses", {
  local_mocked_bindings(
    dep_rurl_verdicts = function(url) {
      warning("a rurl warning quoting http://user:secret@example.com/")
      data.frame(
        layer1_syntax_verdict = "pass",
        layer2_policy_verdict = "admitted",
        layer3_annotation_state = "warning-no-tld"
      )
    }
  )
  res <- NULL
  expect_no_warning(res <- ssrf_inspect_url("http://localhost/"))
  expect_identical(res$code, NA_character_)
})

# §4.2, r-binding.md §2.2: a PSL annotation is not ambiguity.
test_that("parse_status annotations do not refuse", {
  for (url in c("http://localhost/", "http://internal-api.corp/")) {
    expect_identical(ssrf_inspect_url(url)$code, NA_character_, label = url)
  }
})
