# L1 resolved inspection (ssrfr-v1.md §1, §1.2, §5.0 "Names resolve as
# absolute", §12 steps 7-8, INV-4, INV-5, INV-11) and the named L1 tests of
# r-binding.md §7. The resolver is always the mocked internal wrapper, so no
# test here makes a real DNS query; the corpus rows run in test-corpus.R.

# Replaces the resolver wrapper for the calling test with `answers`, a
# function of the query or an `answers` column value (helper-corpus.R), and
# returns the environment recording every query.
mock_resolver <- function(answers, env = parent.frame()) {
  seen <- new.env(parent = emptyenv())
  seen$queries <- character()
  fn <- if (is.function(answers)) answers else answers_resolver(answers)$fn
  local_mocked_bindings(
    dep_nslookup = function(query) {
      seen$queries <- c(seen$queries, query)
      fn(query)
    },
    .env = env
  )
  seen
}

inspect_l1 <- function(url, policy = ssrf_policy(), base = NULL) {
  ssrf_inspect_url(url, policy, base = base, layer = "L1")
}

# Evaluates `code` with `fn` bound as dep_nslookup in the global environment.
with_global_shadow <- function(fn, code) {
  assign("dep_nslookup", fn, envir = globalenv())
  on.exit(rm("dep_nslookup", envir = globalenv()))
  force(code)
}

# L1 inspection of `url` with the resolver answering `answers` and the raddr
# wrapper named `wrapper` replaced with `failure`.
inspect_l1_failing <- function(wrapper, failure, answers, url) {
  mock_resolver(answers)
  do.call(local_mocked_bindings, stats::setNames(list(failure), wrapper))
  inspect_l1(url)
}

# r-binding.md §7, Rules: no public resolver argument, and a test that the
# seam cannot be overridden from outside the namespace (INV-5).
test_that("the resolver seam cannot be overridden from outside ssrfr", {
  ns <- asNamespace("ssrfr")
  expect_false("dep_nslookup" %in% getNamespaceExports("ssrfr"))
  # No exported function takes a resolver, and a policy cannot carry one.
  for (fn in getNamespaceExports("ssrfr")) {
    value <- get(fn, envir = ns)
    if (is.function(value)) {
      expect_false(
        any(grepl("resolv|dns|lookup", names(formals(value)))),
        label = fn
      )
    }
  }
  expect_error(ssrf_policy(resolver = function(q) "127.0.0.1"))
  # The namespace binding is locked against assignment from outside.
  expect_true(bindingIsLocked("dep_nslookup", ns))
  expect_error(assign("dep_nslookup", function(q) "127.0.0.1", envir = ns))

  # A same-named function in the caller's or the global environment is never
  # consulted: the wrapper is looked up in the namespace. The mock stands in
  # for the real resolver and answers with a public address.
  seen <- mock_resolver("93.184.216.34")
  dep_nslookup <- function(query) "127.0.0.1"
  res <- with_global_shadow(dep_nslookup, inspect_l1("http://example.com/"))
  expect_identical(res$code, NA_character_)
  expect_identical(res$answers, "93.184.216.34")
  # The internal seam stays mockable: the mock, not the caller's function,
  # answered.
  expect_identical(seen$queries, "example.com.")
})

# r-binding.md §7: one resolution per hop (INV-5, INV-7), by counting mock.
test_that("a name is resolved exactly once per hop", {
  seen <- mock_resolver("93.184.216.34,2606:2800:220:1:248:1893:25c8:1946")
  inspect_l1("https://example.com/a")
  expect_length(seen$queries, 1L)

  # A redirect hop resolves its own host once, never the previous hop's.
  seen <- mock_resolver("93.184.216.34")
  inspect_l1("https://next.example/b", base = "https://example.com/a")
  expect_identical(seen$queries, "next.example.")
  seen <- mock_resolver("93.184.216.34")
  inspect_l1("/relative", base = "https://example.com/a")
  expect_identical(seen$queries, "example.com.")

  # A refused set and a failed resolution are not retried.
  seen <- mock_resolver("93.184.216.34,127.0.0.1")
  expect_identical(inspect_l1("http://mixed.example/")$code, "loopback")
  expect_length(seen$queries, 1L)
  seen <- mock_resolver("error")
  expect_identical(inspect_l1("http://error.example/")$cause, "unresolvable")
  expect_length(seen$queries, 1L)
})

# r-binding.md §7: scheme and port refused before resolution (§12), and every
# other refusal before step 7 as well: zero calls on the counting mock.
test_that("a URL refused before step 7 is never resolved", {
  refused <- list(
    "ftp://files.example/" = "scheme",
    "gopher://files.example/" = "scheme",
    "http://files.example:6379/" = "port",
    "https://files.example:22/" = "port",
    "http://user:pw@files.example/" = "userinfo",
    "http://metadata.google.internal/" = "cloud-metadata",
    "http://0x7f.1/" = "numeric-literal",
    "http://a b.example/" = "parse"
  )
  for (url in names(refused)) {
    seen <- mock_resolver("93.184.216.34")
    expect_identical(inspect_l1(url)$code, refused[[url]], label = url)
    expect_identical(seen$queries, character(), label = url)
  }
  # A downgrade on a redirect hop, and a caller deny_hosts rule.
  seen <- mock_resolver("93.184.216.34")
  expect_identical(
    inspect_l1("http://next.example/", base = "https://example.com/")$code,
    "downgrade"
  )
  expect_identical(
    inspect_l1("http://api.corp/", ssrf_policy(deny_hosts = ".corp"))$code,
    "host-denied"
  )
  expect_identical(seen$queries, character())

  # An address literal is classified, not resolved; L0 never resolves.
  seen <- mock_resolver("93.184.216.34")
  expect_identical(inspect_l1("http://127.0.0.1/")$code, "loopback")
  expect_identical(inspect_l1("http://[2606:4700::1111]/")$code, NA_character_)
  res <- ssrf_inspect_url("http://example.com/")
  expect_identical(res$code, NA_character_)
  expect_null(res$answers)
  expect_identical(seen$queries, character())
})

# §5.0, "Names resolve as absolute": the query carries a single trailing root
# dot, so no search domain applies; the host itself keeps libcurl's spelling,
# which the Host header, SNI and the pin key use.
test_that("a name is resolved as absolute, with one trailing root dot", {
  cases <- list(
    "http://intranet/" = c(query = "intranet.", host = "intranet"),
    "http://Example.COM/" = c(query = "example.com.", host = "example.com"),
    "http://LoCalHost./" = c(query = "localhost.", host = "localhost."),
    "http://bücher.example/" = c(
      query = "xn--bcher-kva.example.",
      host = "xn--bcher-kva.example"
    )
  )
  for (url in names(cases)) {
    seen <- mock_resolver("93.184.216.34")
    res <- inspect_l1(url)
    expect_identical(seen$queries, cases[[url]][["query"]], label = url)
    expect_identical(res$host, cases[[url]][["host"]], label = url)
  }
  hop <- ssrfr:::parse_hop("http://intranet/", ssrf_policy())
  expect_identical(
    ssrfr:::resolve_hop(hop, ssrf_policy())$query,
    "intranet."
  )
  expect_identical(hop$wire, "http://intranet/")
})

# r-binding.md §7: one bad address refuses the set (INV-4), with INV-4's own
# cases: public+private, A public + AAAA ::1, all-private, all-public. The
# order of the answers does not matter, and the set is never filtered down.
test_that("one bad address refuses the whole answer set", {
  cases <- list(
    "93.184.216.34,10.0.0.1" = "private",
    "10.0.0.1,93.184.216.34" = "private",
    "93.184.216.34,::1" = "loopback",
    "::1,93.184.216.34" = "loopback",
    "10.0.0.1,10.0.0.2" = "private",
    "93.184.216.34,8.8.8.8,169.254.169.254" = "cloud-metadata",
    "93.184.216.34,64:ff9b::a9fe:a9fe" = "cloud-metadata",
    "93.184.216.34,2606:2800:220:1:248:1893:25c8:1946" = NA_character_
  )
  for (answers in names(cases)) {
    mock_resolver(answers)
    res <- inspect_l1("http://mixed.example/")
    expect_identical(res$code, cases[[answers]], label = answers)
    expect_identical(res$step, if (is.na(res$code)) NA_integer_ else 8L)
    # Every address is kept and classified, in the resolver's order.
    listed <- strsplit(answers, ",", fixed = TRUE)[[1L]]
    expect_identical(res$answers, listed, label = answers)
    expect_identical(
      vapply(res$addresses, function(a) a$address, ""),
      listed,
      label = answers
    )
    for (a in res$addresses) {
      expect_identical(a$facts$address, a$address, label = answers)
    }
  }

  # The refused address is named, and the permitted one keeps its facts.
  mock_resolver("93.184.216.34,::1")
  res <- inspect_l1("http://dual.example/")
  expect_identical(res$host, "dual.example")
  codes <- vapply(res$addresses, function(a) a$code, "")
  expect_identical(codes, c(NA_character_, "loopback"))
  expect_true(res$addresses[[1L]]$facts$reachability)
  expect_false(res$addresses[[2L]]$facts$reachability)
  expect_identical(res$addresses[[2L]]$detail$gate, "1a")

  # The internal step L2 reuses: nothing validated from a refused set.
  hop <- ssrfr:::parse_hop("http://dual.example/", ssrf_policy())
  resolved <- ssrfr:::resolve_hop(hop, ssrf_policy())
  expect_identical(resolved$finding$code, "loopback")
  expect_identical(resolved$finding$address, "::1")
  expect_identical(resolved$validated, character())
})

# §1.2: L1 returns evidence, the address set and each address's facts, not a
# summary "all permitted" boolean.
test_that("L1 returns per-address evidence and no roll-up boolean", {
  mock_resolver("93.184.216.34,2606:2800:220:1:248:1893:25c8:1946")
  res <- inspect_l1("https://example.com/")
  expect_identical(res$layer, "L1")
  expect_identical(res$code, NA_character_)
  expect_identical(res$cause, NA_character_)
  flags <- vapply(res, function(x) is.logical(x) && length(x) == 1L, TRUE)
  expect_identical(names(res)[flags], "userinfo")
  expect_length(res$addresses, 2L)
  for (a in res$addresses) {
    expect_named(a, c("address", "code", "detail", "facts"))
    expect_true(a$facts$reachability)
    expect_identical(nrow(a$facts$embeddings), 0L)
  }
  out <- paste(format(res), collapse = "\n")
  expect_match(out, "L1: facts, not a defense", fixed = TRUE)
  expect_match(out, "none at L1", fixed = TRUE)
  expect_match(out, "93.184.216.34: none", fixed = TRUE)

  # The internal step L2 reuses returns the validated set with its facts.
  hop <- ssrfr:::parse_hop("https://example.com/", ssrf_policy())
  resolved <- ssrfr:::resolve_hop(hop, ssrf_policy())
  expect_null(resolved$finding)
  expect_identical(
    resolved$validated,
    c("93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946")
  )
  expect_identical(resolved$addresses[[2L]]$facts$family, "v6")
})

# r-binding.md §7: an empty answer or a resolver error is `unresolvable`
# (§6.6, INV-11), and so is an answer raddr cannot read as an address. It is
# an operational cause, not a reason code (§6.2).
test_that("an empty answer or a resolver error is unresolvable", {
  cases <- list(
    empty = list(fn = function(q) character(), check = "empty"),
    error = list(
      fn = function(q) stop("Failed to resolve hostname"),
      check = "resolver-error"
    ),
    null = list(fn = function(q) NULL, check = "resolver-error"),
    na = list(fn = function(q) NA_character_, check = "resolver-error"),
    numeric = list(fn = function(q) 2130706433, check = "resolver-error"),
    list = list(
      fn = function(q) list("93.184.216.34"),
      check = "resolver-error"
    ),
    garbage = list(fn = function(q) "not-an-address", check = "unparseable"),
    partly = list(
      fn = function(q) c("93.184.216.34", "999.1.1.1"),
      check = "unparseable"
    )
  )
  for (name in names(cases)) {
    mock_resolver(cases[[name]]$fn)
    res <- NULL
    expect_no_error(res <- inspect_l1("http://nx.example/"))
    expect_identical(res$cause, "unresolvable", label = name)
    expect_identical(res$code, NA_character_, label = name)
    expect_identical(res$step, 7L, label = name)
    expect_identical(res$detail$check, cases[[name]]$check, label = name)
    expect_null(res$addresses)
  }
  mock_resolver("empty")
  expect_identical(inspect_l1("http://nx.example/")$answers, character())
  out <- paste(format(inspect_l1("http://nx.example/")), collapse = "\n")
  expect_match(out, "cause: unresolvable", fixed = TRUE)

  # The cause is one of the closed operational causes.
  expect_true("unresolvable" %in% ssrf_vocabulary("causes")$cause)
})

# r-binding.md §7, INV-11, §6.5, §8 item 32: a raddr call that fails on a
# resolved answer refuses the set as `malformed-address`, never an R error.
# dep_raddr_format is not on this path: it serves the parse agreement check,
# covered in test-dependencies.R.
test_that("a failing raddr wrapper refuses an answer as malformed-address", {
  wrappers <- c(
    "dep_raddr_pton",
    "dep_raddr_reachability",
    "dep_raddr_category",
    "dep_raddr_family",
    "dep_raddr_embeddings",
    "dep_raddr_within_any"
  )
  failures <- list(
    stop = function(...) stop("dependency failed"),
    null = function(...) NULL,
    wrong_shape = function(...) list(unexpected = 42)
  )
  # Each answer admits when raddr answers.
  answers <- c(
    "93.184.216.34",
    "2606:4700:4700::1111",
    "64:ff9b::5db8:d822"
  )
  for (answer in answers) {
    mock_resolver(answer)
    expect_identical(inspect_l1("http://a.example/")$code, NA_character_)
  }
  for (wrapper in wrappers) {
    for (mode in names(failures)) {
      for (answer in answers) {
        label <- paste(wrapper, mode, answer)
        res <- NULL
        expect_no_error(
          res <- inspect_l1_failing(
            wrapper,
            failures[[mode]],
            paste0("93.184.216.34,", answer),
            "http://a.example/"
          )
        )
        expect_identical(res$code, "malformed-address", label = label)
        expect_identical(res$cause, NA_character_, label = label)
      }
    }
  }
})
