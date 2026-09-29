# The closed domains of ssrfr-v1.md §6.1, pinned in both directions: a key
# added or removed without a version bump fails, and a bump that leaves the
# pinned key set stale fails.
#
# `vocabulary_pins` is each domain's history: every version ever released,
# with its full key set. To change a domain's keys, bump its version in
# R/vocabulary.R and append the new version here with the new key set; never
# edit an earlier version. A new domain adds a builder to closed_domains() and
# a history here.

vocabulary_pins <- list(
  reason_codes = list(
    "1" = c(
      "loopback",
      "private",
      "link-local",
      "cloud-metadata",
      "shared",
      "unspecified",
      "this-network",
      "ipv4-mapped",
      "ipv4-translated",
      "ipv4-compatible",
      "nat64",
      "6to4",
      "teredo",
      "isatap",
      "malformed-address",
      "numeric-literal",
      "scheme",
      "downgrade",
      "userinfo",
      "port",
      "host-denied",
      "range-denied",
      "parse",
      "multicast",
      "redirect-limit",
      "reserved"
    )
  ),
  causes = list(
    "1" = c(
      "unresolvable",
      "pin-mismatch",
      "connect-failed",
      "tls-failed",
      "timeout",
      "response-too-large",
      "protocol-error"
    )
  ),
  condition_classes = list(
    "1" = c(
      "ssrfr_error_invalid_policy",
      "ssrfr_error_invalid_request",
      "ssrfr_error_invalid_from",
      "ssrfr_error_spent_binding",
      "ssrfr_error_budget_change",
      "ssrfr_error_invalid_argument"
    )
  ),
  provider_endpoints = list(
    "1" = c(
      "169.254.169.254",
      "fd00:ec2::254",
      "192.0.0.192",
      "100.100.100.200",
      "168.63.129.16",
      "169.254.170.2",
      "169.254.170.23",
      "fd00:ec2::23",
      "169.254.0.23",
      "fd20:ce::254",
      "169.254.42.42",
      "fd00:42::42",
      "fd00:a9fe:a9fe::1",
      "fe80::a9fe:a9fe"
    )
  ),
  metadata_hostnames = list(
    "1" = c(
      "metadata.google.internal",
      "metadata.goog",
      "metadata.tencentyun.com",
      "api.metadata.cloud.ibm.com",
      "metadata.exoscale.com"
    )
  ),
  metadata_headers = list(
    "1" = c(
      "Metadata",
      "Metadata-Flavor",
      "X-Google-Metadata-Request",
      "X-aws-ec2-metadata-token",
      "X-aws-ec2-metadata-token-ttl-seconds",
      "X-aliyun-ecs-metadata-token",
      "X-aliyun-ecs-metadata-token-ttl-seconds",
      "Metadata-Token",
      "Metadata-Token-Expiry-Seconds",
      "X-Metadata-Token-Ttl-Seconds"
    )
  )
)

# What is wrong with a domain against its pin history; character(0) when
# nothing is.
pin_problems <- function(domain, history) {
  version <- attr(domain, "version")
  keys <- domain[[1L]]
  pinned <- as.integer(names(history))
  problems <- character()
  if (!identical(pinned, seq_along(history))) {
    problems <- c(problems, "pinned versions are not 1, 2, 3, ...")
  }
  for (i in seq_along(history)[-1L]) {
    if (setequal(history[[i]], history[[i - 1L]])) {
      problems <- c(
        problems,
        paste("version", i, "repeats the key set of version", i - 1L)
      )
    }
  }
  if (!as.character(version) %in% names(history)) {
    return(c(problems, paste("version", version, "has no pinned key set")))
  }
  if (version != max(pinned)) {
    problems <- c(problems, paste("version", version, "is not the latest pin"))
  }
  if (!setequal(keys, history[[as.character(version)]])) {
    problems <- c(
      problems,
      paste("keys differ from the set pinned for version", version)
    )
  }
  problems
}

test_that("every closed domain matches its pinned version and key set", {
  domains <- closed_domains()
  expect_setequal(names(domains), names(vocabulary_pins))
  for (name in names(domains)) {
    expect_identical(
      pin_problems(domains[[name]], vocabulary_pins[[name]]),
      character(),
      label = paste("pin problems of", name)
    )
  }
})

# Positive control: the pin check must fire on each planted violation, or a
# check that silently matches nothing would still pass the test above.
test_that("the pin check catches an unbumped key change and a stale bump", {
  history <- list("1" = c("a", "b"))
  dom <- function(version, keys) {
    closed_domain("toy", version, data.frame(key = keys))
  }

  expect_identical(pin_problems(dom(1, c("a", "b")), history), character())
  expect_match(
    pin_problems(dom(1, c("a", "b", "c")), history),
    "keys differ from the set pinned for version 1"
  )
  expect_match(
    pin_problems(dom(1, "a"), history),
    "keys differ from the set pinned for version 1"
  )
  expect_match(
    pin_problems(dom(2, c("a", "b")), history),
    "version 2 has no pinned key set"
  )
  expect_match(
    pin_problems(dom(2, c("a", "b")), c(history, list("2" = c("a", "b")))),
    "version 2 repeats the key set of version 1",
    all = FALSE
  )
  expect_identical(
    pin_problems(
      dom(2, c("a", "b", "c")),
      c(history, list("2" = c("a", "b", "c")))
    ),
    character()
  )
  expect_match(
    pin_problems(dom(1, c("a", "b")), c(history, list("2" = c("a", "c")))),
    "version 1 is not the latest pin"
  )
})

test_that("each closed domain is enumerable at runtime with its version", {
  index <- ssrf_vocabulary()
  expect_named(index, c("domain", "version", "size"))
  expect_setequal(index$domain, names(vocabulary_pins))
  expect_identical(
    attr(index, "package_version"),
    as.character(utils::packageVersion("ssrfr"))
  )
  for (name in names(vocabulary_pins)) {
    v <- ssrf_vocabulary(name)
    expect_identical(attr(v, "domain"), name)
    expect_identical(attr(v, "version"), index$version[index$domain == name])
    expect_identical(nrow(v), index$size[index$domain == name])
    expect_identical(
      attr(v, "package_version"),
      as.character(utils::packageVersion("ssrfr"))
    )
    expect_false(anyNA(v[[1L]]))
  }
  expect_named(ssrf_vocabulary("reason_codes"), c("code", "meaning"))
  expect_named(ssrf_vocabulary("causes"), c("cause", "meaning"))
  expect_named(
    ssrf_vocabulary("condition_classes"),
    c("class", "kind", "raised_when")
  )
  expect_named(
    ssrf_vocabulary("provider_endpoints"),
    c("address", "provider", "kind", "source", "quote", "retrieved")
  )
  expect_named(
    ssrf_vocabulary("metadata_hostnames"),
    c("hostname", "address", "provider", "source", "quote", "retrieved")
  )
  expect_named(
    ssrf_vocabulary("metadata_headers"),
    c("header", "provider", "source")
  )
})

test_that("reason codes and causes are kebab-case and share no token", {
  codes <- ssrf_vocabulary("reason_codes")$code
  causes <- ssrf_vocabulary("causes")$cause
  expect_match(c(codes, causes), "^[a-z0-9]+(-[a-z0-9]+)*$")
  expect_length(intersect(codes, causes), 0L)
})

test_that("an unknown vocabulary is an invalid argument", {
  expect_error(
    ssrf_vocabulary("reasons"),
    class = "ssrfr_error_invalid_argument"
  )
  expect_error(
    ssrf_vocabulary(c("causes", "reason_codes")),
    class = "ssrfr_error_invalid_argument"
  )
  expect_error(ssrf_vocabulary(NA), class = "ssrfr_error_invalid_argument")
})

test_that("a closed domain refuses a missing or repeated key", {
  expect_error(closed_domain("toy", 1, data.frame(key = c("a", "a"))))
  expect_error(closed_domain("toy", 1, data.frame(key = c("a", NA))))
  expect_error(closed_domain("toy", 0, data.frame(key = "a")))
  expect_error(closed_domain("toy", 1.5, data.frame(key = "a")))
})
