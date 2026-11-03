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
  canonical <- canonical_address
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

# A raddr call that fails on one reading only, after the others answered,
# refuses as `malformed-address` at gate 1b too (§6.5, §8 item 32, INV-11):
# the embedded address of a mapped or translated literal, the embedding
# rows' reachability, and a caller range.
expect_malformed_at_1b <- function(res, label) {
  expect_identical(res$code, "malformed-address", label = label)
  expect_identical(res$step, 8L, label = label)
  expect_identical(res$detail$gate, "1b", label = label)
  expect_identical(res$detail$tier, 1L, label = label)
}

test_that("raddr failing on an embedded address refuses as malformed-address", {
  urls <- c("http://[::ffff:169.254.169.254]/", "http://[64:ff9b::a9fe:a9fe]/")
  # Read whole, the embedded address is the metadata endpoint.
  for (url in urls) {
    expect_identical(ssrf_inspect_url(url)$code, "cloud-metadata", label = url)
  }
  pton <- dep_raddr_pton
  local_mocked_bindings(
    dep_raddr_pton = function(text) {
      if (identical(text, "169.254.169.254")) stop("raddr") else pton(text)
    }
  )
  for (url in urls) {
    expect_malformed_at_1b(ssrf_inspect_url(url), url)
  }
})

test_that("raddr failing on embedding reachability refuses as malformed", {
  reachability <- dep_raddr_reachability
  local_mocked_bindings(
    dep_raddr_reachability = function(x) {
      if (inherits(x, "raddr_embedding")) stop("raddr") else reachability(x)
    }
  )
  # The address's own reachability is read; its NAT64 embedding's is not.
  expect_malformed_at_1b(
    ssrf_inspect_url("http://[64:ff9b::5db8:d822]/"),
    "nat64"
  )
  # An address with no embedding never asks for an embedding's.
  expect_identical(
    ssrf_inspect_url("http://93.184.216.34/")$code,
    NA_character_
  )
})

test_that("an embedding record of the wrong shape refuses as malformed", {
  embeddings <- dep_raddr_embeddings
  rows <- unclass(embeddings(raddr::addr_pton("64:ff9b::5db8:d822"))[[1L]])
  record <- function(fields) {
    function(x) list(structure(fields, class = "raddr_embedding"))
  }
  shapes <- list(
    "no address" = rows[c("kind", "role")],
    "an NA kind" = modifyList(rows, list(kind = NA_character_)),
    "a short role" = modifyList(rows, list(role = character()))
  )
  for (shape in names(shapes)) {
    local({
      local_mocked_bindings(dep_raddr_embeddings = record(shapes[[shape]]))
      expect_malformed_at_1b(
        ssrf_inspect_url("http://[64:ff9b::5db8:d822]/"),
        shape
      )
    })
  }
})

test_that("raddr failing on a caller range refuses with the facts it read", {
  within <- dep_raddr_within_any
  local_mocked_bindings(
    dep_raddr_within_any = function(x, blocks) {
      if ("10.0.0.0/8" %in% blocks) stop("raddr") else within(x, blocks)
    }
  )
  policies <- list(
    deny = ssrf_policy(deny_ranges = "10.0.0.0/8"),
    allow = ssrf_policy(allow_ranges = "10.0.0.0/8")
  )
  for (name in names(policies)) {
    res <- ssrf_inspect_url("http://93.184.216.34/", policies[[name]])
    expect_malformed_at_1b(res, name)
    # The reading failed at tier 2 or 3, after raddr reported the facts.
    expect_identical(res$address$address, "93.184.216.34", label = name)
    expect_true(res$address$reachability, label = name)
    expect_identical(res$address$category, "global", label = name)
  }
})

# §6.5: a provider endpoint is the most specific fact, so it names the
# refusal even where an unknown reachability refuses first (gate 1b).
test_that("a provider endpoint outranks unknown reachability at gate 1b", {
  local_mocked_bindings(dep_raddr_reachability = function(x) {
    rep(NA, length(x))
  })
  cases <- list(
    "http://169.254.169.254/" = NULL,
    "http://[::ffff:169.254.169.254]/" = "ipv4_mapped"
  )
  for (url in names(cases)) {
    res <- ssrf_inspect_url(url)
    expect_identical(res$code, "cloud-metadata", label = url)
    expect_identical(res$detail$gate, "1b", label = url)
    expect_identical(res$detail$provider_kind, "instance-metadata", label = url)
    expect_identical(res$detail$embedding_kind, cases[[url]], label = url)
  }
})
