# Redirect hops (ssrfr-v1.md §2.3, §2.5, §2.6, §3.2, §6.5, §6.6, §8 item 33,
# §12 steps 3 and 13, INV-7, INV-8, INV-12): ssrf_prepare_hop(from =), the
# method and body transformation, cross-origin stripping, the chain budgets,
# `redirect-limit` and `downgrade`, and the r-binding.md §7 tests that need a
# redirect chain. Every server is on loopback and every host a name the
# resolver mock maps to it; the harness is helper-redirect.R.

# --- the redirect hop ---------------------------------------------------------

test_that("a redirect hop resolves Location against the previous hop", {
  skip_if_no_webfakes()
  web <- local_redirect_server()
  port <- web$get_port()
  seen <- mock_answers("127.0.0.1")
  policy <- loopback_policy(port)
  plan <- c(`X-Corpus-Location` = "../echo?q=1#frag", `X-Plan` = "kept")
  b1 <- ssrf_prepare_hop(
    pinned_url(port, "/a/b/c"),
    policy,
    request = list(headers = plan)
  )
  r1 <- ssrf_fetch(b1)
  expect_identical(r1$status, 302L)
  expect_identical(b1$state$location, "../echo?q=1#frag")
  b2 <- ssrf_prepare_hop(b1$state$location, policy, from = b1)
  expect_s3_class(b2, "ssrfr_binding")
  expect_identical(b2$hop, 2L)
  # RFC 3986 §5.2 against the previous hop's URL, without the fragment.
  expect_identical(b2$url, pinned_url(port, "/a/echo?q=1"))
  expect_identical(b2$origin, b1$origin)
  # The plan is inherited, not re-supplied (§2.3).
  expect_identical(b2$request$headers, plan)
  expect_true(b2$state$fetchable)
  # INV-5, INV-7: the new hop resolved its own name, once.
  expect_identical(seen$queries, rep(paste0(pinned_host, "."), 2L))
  expect_identical(ssrf_fetch(b2)$status, 302L)
  # A redirect hop is itself a valid `from`.
  b1 <- ssrf_prepare_hop(
    pinned_url(port, "/r/301?to=/r/308%3Fto%3D/echo"),
    policy,
    request = list()
  )
  ssrf_fetch(b1)
  b2 <- ssrf_prepare_hop(b1$state$location, policy, from = b1)
  expect_identical(ssrf_fetch(b2)$status, 308L)
  b3 <- ssrf_prepare_hop(b2$state$location, policy, from = b2)
  expect_identical(b3$hop, 3L)
  expect_identical(echo_of(ssrf_fetch(b3))$method, "GET")
  shown <- paste(format(b3), collapse = "\n")
  expect_match(shown, "(hop 3, spent: fetched)", fixed = TRUE)
  expect_match(shown, "redirect: 308 from hop 2, same origin", fixed = TRUE)
})

# The previous hop's URL is its binding's wire URL, parsed when that binding
# was prepared: a redirect hop reads the scheme from `from` and parses only
# its own URL, and the downgrade rule still sees https (test below).
test_that("a redirect hop parses its own URL, not the previous one again", {
  skip_if_no_webfakes()
  web <- local_redirect_server()
  port <- web$get_port()
  mock_answers("127.0.0.1")
  policy <- loopback_policy(port)
  b1 <- ssrf_prepare_hop(
    pinned_url(port, "/r/302?to=/echo"),
    policy,
    request = list()
  )
  expect_identical(ssrf_fetch(b1)$status, 302L)
  parsed <- new.env(parent = emptyenv())
  parsed$urls <- character()
  boundary <- ssrfr:::parse_boundary
  local_mocked_bindings(parse_boundary = function(url) {
    parsed$urls <- c(parsed$urls, url)
    boundary(url)
  })
  b2 <- ssrf_prepare_hop(b1$state$location, policy, from = b1)
  expect_s3_class(b2, "ssrfr_binding")
  expect_identical(parsed$urls, pinned_url(port, "/echo"))
})

# §3.2, §6.4: an outcome on a redirect hop records the URL the hop resolved
# to, never a relative Location, which could only display as withheld.
test_that("outcomes on a redirect hop record the resolved URL", {
  skip_if_no_webfakes()
  web <- local_redirect_server()
  port <- web$get_port()
  mock_answers(function(q) {
    if (identical(q, "gone.example.invalid.")) character() else "127.0.0.1"
  })
  policy <- loopback_policy(
    c(port, 1),
    deny_hosts = "denied.example.invalid",
    max_redirects = 1
  )
  from_location <- function(location) {
    b <- ssrf_prepare_hop(
      pinned_url(port, "/start"),
      policy,
      request = list(headers = c(`X-Corpus-Location` = location))
    )
    expect_identical(ssrf_fetch(b)$status, 302L)
    expect_identical(b$state$location, location)
    b
  }
  withheld <- ssrfr:::redact_url("//denied.example.invalid/x")
  expect_match(withheld, "withheld", fixed = TRUE)
  check_url <- function(out, want, label) {
    expect_identical(out$url, ssrfr:::redact_url(want), label = label)
    expect_false(grepl("withheld", out$url, fixed = TRUE), label = label)
    shown <- paste(format(out), collapse = "\n")
    expect_match(shown, paste0("url: ", out$url), fixed = TRUE, label = label)
  }
  # A refusal ssrf_prepare_hop() returns.
  b <- from_location("//denied.example.invalid/x")
  r <- ssrf_prepare_hop(b$state$location, policy, from = b)
  expect_identical(r$code, "host-denied")
  check_url(r, "http://denied.example.invalid/x", "refusal")
  # A failure it returns: resolution.
  b <- from_location("//gone.example.invalid/y")
  f <- ssrf_prepare_hop(b$state$location, policy, from = b)
  expect_identical(f$cause, "unresolvable")
  check_url(f, "http://gone.example.invalid/y", "unresolvable")
  # And the time budget, spent after resolution.
  b <- from_location("../echo")
  local({
    local_mocked_bindings(elapsed_since = function(start) 60)
    f <- ssrf_prepare_hop(b$state$location, policy, from = b)
    expect_identical(f$cause, "timeout")
    check_url(f, pinned_url(port, "/echo"), "timeout")
  })
  # A failure ssrf_fetch() returns on a redirect hop.
  b <- from_location("//other.example.invalid:1/z")
  b2 <- ssrf_prepare_hop(b$state$location, policy, from = b)
  f <- ssrf_fetch(b2)
  expect_identical(f$cause, "connect-failed")
  expect_identical(f$hop, 2L)
  check_url(f, "http://other.example.invalid:1/z", "fetch failure")
  # The redirect-limit refusal, past the budget on the second hop.
  b <- from_location("/r/302?to=/echo")
  b2 <- ssrf_prepare_hop(b$state$location, policy, from = b)
  r <- ssrf_fetch(b2)
  expect_identical(r$code, "redirect-limit")
  check_url(r, pinned_url(port, "/r/302?to=/echo"), "redirect-limit")
  # The binding holds the resolved URL, which the next hop resolves against.
  expect_identical(b2$url, pinned_url(port, "/r/302?to=/echo"))
})

# --- misuse (§2.3, §6.6) ------------------------------------------------------

test_that("a from that is not a spent, followed redirect is invalid_from", {
  skip_if_no_webfakes()
  web <- local_redirect_server()
  port <- web$get_port()
  mock_answers("127.0.0.1")
  policy <- loopback_policy(c(port, 1), max_redirects = 5)
  hop <- function(path, p = policy) {
    b <- ssrf_prepare_hop(pinned_url(port, path), p, request = list())
    ssrf_fetch(b)
    b
  }
  invalid_from <- function(from, label) {
    err <- expect_error(
      ssrf_prepare_hop("/echo", policy, from = from),
      class = "ssrfr_error_invalid_from",
      label = label
    )
    expect_s3_class(err, "ssrfr_error")
    expect_identical(err$kind, "invalid_from")
    # §2.3: the message quotes no value the caller or the server supplied.
    expect_false(grepl("echo", conditionMessage(err), fixed = TRUE))
  }
  # Unspent.
  unspent <- ssrf_prepare_hop(
    pinned_url(port, "/r/302?to=/echo"),
    policy,
    request = list()
  )
  invalid_from(unspent, "unspent")
  # A fetch that failed on the wire.
  failed <- ssrf_prepare_hop(
    pinned_url(1, "/"),
    policy,
    request = list()
  )
  expect_identical(ssrf_fetch(failed)$cause, "connect-failed")
  invalid_from(failed, "failed")
  # Responses that are not a followed redirect: a final status, a 3xx that
  # ssrfr does not follow, and a redirect status without Location.
  invalid_from(hop("/echo"), "200")
  invalid_from(hop("/r/304"), "304")
  invalid_from(hop("/r/300?to=/echo"), "300 with Location")
  invalid_from(hop("/r/305?to=/echo"), "305 with Location")
  invalid_from(hop("/r/302"), "302 without Location")
  # A 3xx refused as redirect-limit (max_redirects = 0) is no redirect.
  limited <- hop(
    "/r/302?to=/echo",
    loopback_policy(c(port, 1), max_redirects = 0)
  )
  expect_identical(limited$state$status, 302L)
  expect_error(
    ssrf_prepare_hop(
      "/echo",
      loopback_policy(c(port, 1), max_redirects = 0),
      from = limited
    ),
    class = "ssrfr_error_invalid_from"
  )
  # More than one Location is protocol-error (§6.6), so never a `from`.
  two <- local_raw_server(wire(
    "HTTP/1.1 302 Found\r\nLocation: /a\r\nLocation: /b\r\n",
    "Content-Length: 0\r\nConnection: close\r\n\r\n"
  ))
  b <- ssrf_prepare_hop(
    pinned_url(two$port),
    loopback_policy(two$port, max_redirects = 5),
    request = list()
  )
  expect_identical(ssrf_fetch(b)$cause, "protocol-error")
  expect_error(
    ssrf_prepare_hop(
      "/a",
      loopback_policy(two$port, max_redirects = 5),
      from = b
    ),
    class = "ssrfr_error_invalid_from"
  )
})

test_that("request with from, or a from that is no binding, is misuse", {
  skip_if_no_webfakes()
  web <- local_redirect_server()
  port <- web$get_port()
  mock_answers("127.0.0.1")
  policy <- loopback_policy(port)
  b <- ssrf_prepare_hop(
    pinned_url(port, "/r/302?to=/echo"),
    policy,
    request = list(headers = c(Authorization = "Bearer t"))
  )
  r <- ssrf_fetch(b)
  expect_identical(r$status, 302L)
  # §2.3: restating the plan on a redirect hop could re-add what the
  # previous hop stripped, so `request` with `from` is refused.
  expect_error(
    ssrf_prepare_hop("/echo", policy, request = list(), from = b),
    class = "ssrfr_error_invalid_argument"
  )
  for (from in list(r, list(), "b", structure(list(), class = class(b)))) {
    expect_error(
      ssrf_prepare_hop("/echo", policy, from = from),
      class = "ssrfr_error_invalid_argument"
    )
  }
})

# §2.6, amended 2026-09-27: a redirect hop's url is the Location `from`
# recorded, byte for byte; the caller cannot re-aim the redirect.
test_that("a redirect hop's url must be the recorded Location, byte for byte", {
  skip_if_no_webfakes()
  web <- local_redirect_server()
  port <- web$get_port()
  seen <- mock_answers("127.0.0.1")
  policy <- loopback_policy(port)
  b <- ssrf_prepare_hop(
    pinned_url(port, "/r/302?to=/Echo"),
    policy,
    request = list()
  )
  expect_identical(ssrf_fetch(b)$status, 302L)
  expect_identical(b$state$location, "/Echo")
  others <- list(
    "a case change" = "/echo",
    "the absolute form" = pinned_url(port, "/Echo"),
    "a trailing space" = "/Echo ",
    "a leading space" = " /Echo"
  )
  for (label in names(others)) {
    seen$queries <- character()
    err <- expect_error(
      ssrf_prepare_hop(others[[label]], policy, from = b),
      class = "ssrfr_error_invalid_from",
      label = label
    )
    expect_identical(err$kind, "invalid_from")
    # The message quotes neither value.
    expect_false(grepl("echo", conditionMessage(err), ignore.case = TRUE))
    # Raised before anything is resolved.
    expect_length(seen$queries, 0L)
  }
  # The exact value proceeds. The same bytes in another declared encoding
  # are the tests below: marking ASCII is a no-op, so it tests nothing here.
  b2 <- ssrf_prepare_hop(b$state$location, policy, from = b)
  expect_s3_class(b2, "ssrfr_binding")
  expect_identical(b2$url, pinned_url(port, "/Echo"))
  expect_s3_class(ssrf_prepare_hop("/Echo", policy, from = b), "ssrfr_binding")
})

# identical() calls a string equal to its re-encoding; the bytes differ, and
# so does the URL a redirect hop is prepared for.
test_that("the Location is compared as bytes, not as strings", {
  web <- local_raw_server(c(
    wire("HTTP/1.1 302 Found\r\nLocation: /caf"),
    as.raw(c(0xc3, 0xa9)),
    wire("\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
  ))
  mock_answers("127.0.0.1")
  policy <- loopback_policy(web$port)
  b <- ssrf_prepare_hop(pinned_url(web$port), policy, request = list())
  expect_identical(ssrf_fetch(b)$status, 302L)
  location <- b$state$location
  expect_identical(Encoding(location), "UTF-8")
  latin <- iconv(location, "UTF-8", "latin1")
  expect_true(identical(latin, location))
  expect_error(
    ssrf_prepare_hop(latin, policy, from = b),
    class = "ssrfr_error_invalid_from"
  )
  expect_s3_class(
    ssrf_prepare_hop(location, policy, from = b),
    "ssrfr_binding"
  )
})

# The same bytes marked in another encoding pass the byte comparison, so the
# hop must be prepared from the recorded value: `url` re-encoded to UTF-8
# would be another URL. A copy marked latin1 has the recorded bytes, so it
# proceeds, to exactly the recorded target.
test_that("a Location marked in another encoding keeps the recorded target", {
  mock_answers("127.0.0.1")
  # What an outcome points at: a binding's URL, or a refusal's code and URL.
  target <- function(out) {
    if (inherits(out, "ssrfr_binding")) {
      list("binding", out$url)
    } else {
      list(class(out)[[1L]], out$code, out$url)
    }
  }
  location_bytes <- list(
    "valid UTF-8" = as.raw(c(0xc3, 0xa9)),
    "not valid UTF-8" = as.raw(0xe9)
  )
  kinds <- c("valid UTF-8" = "binding", "not valid UTF-8" = "ssrfr_refusal")
  for (label in names(location_bytes)) {
    local({
      web <- local_raw_server(c(
        wire("HTTP/1.1 302 Found\r\nLocation: /caf"),
        location_bytes[[label]],
        wire("\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
      ))
      policy <- loopback_policy(web$port)
      b <- ssrf_prepare_hop(pinned_url(web$port), policy, request = list())
      expect_identical(ssrf_fetch(b)$status, 302L, label = label)
      location <- b$state$location
      marked <- location
      Encoding(marked) <- "latin1"
      # The mark really differs, and the bytes do not.
      expect_false(
        identical(Encoding(marked), Encoding(location)),
        label = label
      )
      expect_identical(charToRaw(marked), charToRaw(location), label = label)
      want <- target(ssrf_prepare_hop(location, policy, from = b))
      # The recorded target: the URL for valid UTF-8, a parse refusal for
      # bytes that are not (test below).
      expect_identical(want[[1L]], kinds[[label]], label = label)
      got <- target(ssrf_prepare_hop(marked, policy, from = b))
      expect_identical(got, want, label = label)
    })
  }
})

test_that("a changed chain budget raises budget_change", {
  skip_if_no_webfakes()
  web <- local_redirect_server()
  port <- web$get_port()
  mock_answers("127.0.0.1")
  policy <- loopback_policy(port, max_redirects = 5, total_timeout = 20)
  first <- function() {
    b <- ssrf_prepare_hop(
      pinned_url(port, "/r/302?to=/echo"),
      policy,
      request = list()
    )
    ssrf_fetch(b)
    b
  }
  b <- first()
  changed <- list(
    loopback_policy(port, max_redirects = 6, total_timeout = 20),
    loopback_policy(port, max_redirects = 5, total_timeout = 21),
    loopback_policy(port, total_timeout = 20),
    loopback_policy(port)
  )
  for (p in changed) {
    err <- expect_error(
      ssrf_prepare_hop("/echo", p, from = b),
      class = "ssrfr_error_budget_change"
    )
    expect_s3_class(
      err,
      c("ssrfr_error_budget_change", "ssrfr_error", "error", "condition"),
      exact = TRUE
    )
    expect_identical(err$kind, "budget_change")
  }
  # The from stays referenceable: the same from, with the budgets restated
  # unchanged, still prepares the hop (§2.5), and a per-hop field may change.
  same <- loopback_policy(
    port,
    max_redirects = 5,
    total_timeout = 20,
    deny_hosts = "elsewhere.invalid",
    user_agent = "ssrfr-test/2"
  )
  b2 <- ssrf_prepare_hop("/echo", same, from = b)
  expect_s3_class(b2, "ssrfr_binding")
  expect_identical(b2$policy$user_agent, "ssrfr-test/2")
  expect_s3_class(ssrf_prepare_hop("/echo", same, from = b), "ssrfr_binding")
})

# §2.3, §2.5: the inherited plan is checked again under the redirect hop's
# own policy. A metadata-service marker admitted where the policy named a
# provider endpoint exactly is refused where the policy does not.
test_that("the inherited plan is checked under the redirect hop's policy", {
  skip_if_no_webfakes()
  web <- local_redirect_server()
  port <- web$get_port()
  mock_answers("127.0.0.1")
  named <- ssrf_policy(
    allow_ranges = c("127.0.0.0/8", "169.254.169.254/32"),
    allow_ports = c(80, 443, port)
  )
  b <- ssrf_prepare_hop(
    pinned_url(port, "/r/302?to=/echo"),
    named,
    request = list(headers = c(`Metadata-Flavor` = "Google"))
  )
  expect_identical(ssrf_fetch(b)$status, 302L)
  expect_s3_class(ssrf_prepare_hop("/echo", named, from = b), "ssrfr_binding")
  err <- expect_error(
    ssrf_prepare_hop("/echo", loopback_policy(port), from = b),
    class = "ssrfr_error_invalid_request"
  )
  expect_false(grepl("Google", conditionMessage(err), fixed = TRUE))

  # What is checked is the plan the new hop sends: a marker the redirect
  # drops across origins no longer raises, while a nominated one it keeps
  # still does.
  cross <- function(carry) {
    to <- pinned_url(port, "/echo", host = other_host)
    b <- ssrf_prepare_hop(
      pinned_url(port, paste0("/r/302?to=", URLencode(to, TRUE))),
      named,
      request = list(
        headers = c(`Metadata-Flavor` = "Google", `X-Trace` = "t1"),
        carry = carry
      )
    )
    expect_identical(ssrf_fetch(b)$status, 302L)
    b
  }
  b <- cross("X-Trace")
  b2 <- ssrf_prepare_hop(b$state$location, loopback_policy(port), from = b)
  expect_s3_class(b2, "ssrfr_binding")
  expect_identical(b2$redirect$dropped, "metadata-flavor")
  expect_named(b2$request$headers, "X-Trace")
  expect_identical(b2$request$carry, "x-trace")
  b <- cross(c("X-Trace", "Metadata-Flavor"))
  err <- expect_error(
    ssrf_prepare_hop(b$state$location, loopback_policy(port), from = b),
    class = "ssrfr_error_invalid_request"
  )
  expect_false(grepl("Google", conditionMessage(err), fixed = TRUE))

  # The caller passed `from`, not `request`: the message names the field by
  # its place in `from$request`, the plan inherited, which is not its place
  # in the plan the redirect derived from it once a field before it dropped.
  to <- pinned_url(port, "/echo", host = other_host)
  b <- ssrf_prepare_hop(
    pinned_url(port, paste0("/r/302?to=", URLencode(to, TRUE))),
    named,
    request = list(
      headers = c(
        `X-Dropped` = "d1",
        `Metadata-Flavor` = "Google",
        `X-Trace` = "t1"
      ),
      carry = c("X-Trace", "Metadata-Flavor")
    )
  )
  expect_identical(ssrf_fetch(b)$status, 302L)
  expect_identical(names(b$request$headers)[[2L]], "Metadata-Flavor")
  err <- expect_error(
    ssrf_prepare_hop(b$state$location, loopback_policy(port), from = b),
    class = "ssrfr_error_invalid_request"
  )
  message <- conditionMessage(err)
  expect_match(message, "`from$request$headers[2]`", fixed = TRUE)
  expect_false(grepl("`request$", message, fixed = TRUE))
  expect_false(grepl("Google", message, fixed = TRUE))
  expect_false(grepl("Metadata-Flavor", message, fixed = TRUE))
})

# --- chain budgets (§2.5, §5.3, §6.5, §8 item 33) ----------------------------

test_that("the chain budgets are inherited through from", {
  skip_if_no_webfakes()
  web <- local_redirect_server()
  port <- web$get_port()
  mock_answers("127.0.0.1")
  policy <- loopback_policy(port, max_redirects = 4, total_timeout = 30)
  b1 <- ssrf_prepare_hop(
    pinned_url(port, "/r/302?to=/echo"),
    policy,
    request = list()
  )
  # Twenty seconds pass inside the first fetch.
  local({
    local_mocked_bindings(elapsed_since = function(start) 20)
    expect_identical(ssrf_fetch(b1)$status, 302L)
  })
  expect_gte(b1$state$elapsed, 20)
  b2 <- ssrf_prepare_hop("/echo", policy, from = b1)
  expect_identical(b2$hop, 2L)
  expect_identical(b2$budget$max_redirects, 4)
  expect_identical(b2$budget$total_timeout, 30)
  # The time the chain consumed carries into the new hop.
  expect_gte(b2$budget$elapsed, b1$state$elapsed)
  expect_lt(b2$budget$elapsed, 30)
  # Ten more seconds inside the redirect hop's prepare spend the chain's
  # total_timeout: the hop fails as timeout after resolution (§5.3).
  local({
    local_mocked_bindings(elapsed_since = function(start) 10)
    f <- ssrf_prepare_hop("/echo", policy, from = b1)
    expect_s3_class(f, "ssrfr_failure")
    expect_identical(f$cause, "timeout")
    expect_identical(f$hop, 2L)
    expect_identical(f$detail$limit, "total_timeout")
  })
})

test_that("the redirect budget refuses as redirect-limit on a self-redirect", {
  skip_if_no_webfakes()
  mock_answers("127.0.0.1")
  for (budget in c(0, 3, 20)) {
    local({
      web <- local_redirect_server()
      port <- web$get_port()
      chain <- follow_chain(
        pinned_url(port, "/loop"),
        loopback_policy(port, max_redirects = budget)
      )
      r <- chain$result
      label <- paste("max_redirects =", budget)
      expect_s3_class(r, "ssrfr_refusal")
      expect_identical(r$code, "redirect-limit", label = label)
      # `budget` redirects followed, and the next 3xx refused.
      expect_identical(r$hop, as.integer(budget + 1), label = label)
      expect_length(chain$bindings, budget + 1)
      expect_identical(r$detail$step, 13L)
      expect_identical(r$detail$limit, "max_redirects")
      last <- chain$bindings[[budget + 1]]
      expect_identical(last$state$status, 302L)
      expect_identical(last$state$outcome, "redirect-limit")
      # Each hop's request reached the server once.
      expect_identical(
        loop_hits(port),
        as.character(budget + 1),
        label = label
      )
      expect_identical(ssrf_public_reason(r), "refused")
    })
  }
})

# §2.3, §8 item 33: once the budget is spent, including under
# max_redirects = 0, every 3xx refuses, with or without Location, followed
# status or not. While budget remains, a 3xx that is not a followed redirect
# is a final response.
test_that("a spent budget refuses every 3xx, with or without Location", {
  skip_if_no_webfakes()
  web <- local_redirect_server()
  port <- web$get_port()
  mock_answers("127.0.0.1")
  finals <- c("/r/304", "/r/302", "/r/300?to=/echo", "/r/399")
  for (path in c(finals, "/r/302?to=/echo", "/r/308?to=/echo")) {
    r <- guarded_get(
      pinned_url(port, path),
      loopback_policy(port, max_redirects = 0)
    )
    expect_s3_class(r, "ssrfr_refusal")
    expect_identical(r$code, "redirect-limit", label = path)
    expect_identical(r$hop, 1L)
  }
  # Not a 3xx: the budget does not apply.
  expect_identical(
    guarded_get(
      pinned_url(port, "/echo"),
      loopback_policy(port, max_redirects = 0)
    )$status,
    200L
  )
  # With budget left, the same responses are final.
  for (path in finals) {
    r <- guarded_get(
      pinned_url(port, path),
      loopback_policy(port, max_redirects = 1)
    )
    expect_s3_class(r, "ssrfr_response")
    expect_identical(r$status, as.integer(substr(path, 4L, 6L)), label = path)
  }
  # After one followed redirect under max_redirects = 1, the budget is spent.
  for (path in finals) {
    policy <- loopback_policy(port, max_redirects = 1)
    to <- utils::URLencode(path, reserved = TRUE)
    b <- ssrf_prepare_hop(
      pinned_url(port, paste0("/r/302?to=", to)),
      policy,
      request = list()
    )
    expect_identical(ssrf_fetch(b)$status, 302L)
    b2 <- ssrf_prepare_hop(b$state$location, policy, from = b)
    r <- ssrf_fetch(b2)
    expect_s3_class(r, "ssrfr_refusal")
    expect_identical(r$code, "redirect-limit", label = path)
    expect_identical(r$hop, 2L)
  }
})

# §2.3, §12 step 13: past the budget, a 3xx is decided at its status line.
# Whatever follows it, a second Location, a body over max_response_size, or
# a body that stalls past total_timeout, the outcome is redirect-limit, and
# the transfer is stopped through the callbacks' record, not left to run.
test_that("past the budget, a 3xx refuses whatever follows its status", {
  mock_answers("127.0.0.1")
  transfer <- ssrfr:::dep_curl_transfer
  last <- new.env(parent = emptyenv())
  local_mocked_bindings(
    dep_curl_transfer = function(opts, on_body, debug, progress) {
      out <- transfer(opts, on_body, debug, progress)
      last$aborted <- out$aborted
      last$error <- out$error
      out
    }
  )
  # A server that sends `bytes` and then stalls.
  stall_after <- function(bytes) {
    respond <- function(con) {
      writeBin(BYTES, con)
      flush(con)
      Sys.sleep(10)
    }
    body(respond) <- do.call(
      substitute,
      list(body(respond), list(BYTES = bytes))
    )
    respond
  }
  head <- wire(
    "HTTP/1.1 302 Found\r\nLocation: /next\r\n",
    "Content-Length: 100\r\nConnection: close\r\n\r\n"
  )
  cases <- list(
    "two Location fields" = list(
      bytes = wire(
        "HTTP/1.1 302 Found\r\nLocation: /a\r\nLocation: /b\r\n",
        "Content-Length: 0\r\nConnection: close\r\n\r\n"
      ),
      budget_left = "protocol-error"
    ),
    "a body over max_response_size" = list(
      bytes = c(
        wire(
          "HTTP/1.1 307 Temporary Redirect\r\nLocation: /next\r\n",
          "Content-Length: 5000\r\nConnection: close\r\n\r\n"
        ),
        as.raw(rep(0x61, 5000L))
      ),
      budget_left = "response-too-large",
      stopped = "write"
    ),
    "a body that stalls" = list(
      bytes = stall_after(c(head, wire("ab"))),
      budget_left = "timeout",
      stopped = "write"
    ),
    # No body byte arrives: the progress callback decides.
    "a body that never starts" = list(
      bytes = stall_after(head),
      budget_left = "timeout",
      stopped = "progress"
    )
  )
  for (label in names(cases)) {
    case <- cases[[label]]
    local({
      server <- local_raw_server(case$bytes)
      policy <- loopback_policy(
        server$port,
        max_redirects = 0,
        max_response_size = 100,
        total_timeout = 2
      )
      r <- guarded_get(pinned_url(server$port), policy)
      expect_s3_class(r, "ssrfr_refusal")
      expect_identical(r$code, "redirect-limit", label = label)
      expect_identical(r$detail$step, 13L, label = label)
      # The address the connection was pinned to, recorded before the stop.
      expect_identical(r$address, "127.0.0.1", label = label)
      b <- attr(r, "binding")
      expect_identical(b$state$outcome, "redirect-limit", label = label)
      expect_identical(b$state$pin_used, "127.0.0.1", label = label)
      expect_true(b$state$status %in% c(302L, 307L), label = label)
      expect_false(b$state$fetched, label = label)
      if (!is.null(case$stopped)) {
        # Stopped by ssrfr's record, not ended by libcurl's timer: a stop at
        # a delivery ends in the write callback, as a write error; one in
        # the progress callback, with no delivery after it, at the loop.
        expect_true(last$aborted, label = label)
        if (case$stopped == "write") {
          expect_identical(last$error, "curl_error_write_error", label = label)
        } else {
          expect_null(last$error, label = label)
        }
      }
    })
  }
  # With budget left, the same responses end as they always did.
  for (label in names(cases)) {
    case <- cases[[label]]
    local({
      server <- local_raw_server(case$bytes)
      policy <- loopback_policy(
        server$port,
        max_redirects = 5,
        max_response_size = 100,
        total_timeout = 2
      )
      r <- guarded_get(pinned_url(server$port), policy)
      expect_s3_class(r, "ssrfr_failure")
      expect_identical(r$cause, case$budget_left, label = label)
    })
  }
})

# §12: the pin check (step 11) runs before step 13; a 3xx past the budget
# whose pin cannot be confirmed is pin-mismatch.
test_that("a pin failure wins over redirect-limit", {
  mock_answers("127.0.0.1")
  local_mocked_bindings(pin_check = function(lines, address, port) {
    "other-address"
  })
  server <- local_raw_server(wire(
    "HTTP/1.1 302 Found\r\nLocation: /next\r\n",
    "Content-Length: 0\r\nConnection: close\r\n\r\n"
  ))
  r <- guarded_get(
    pinned_url(server$port),
    loopback_policy(server$port, max_redirects = 0)
  )
  expect_s3_class(r, "ssrfr_failure")
  expect_identical(r$cause, "pin-mismatch")
})

# §2.3: the status step 13 records is transport-observed. On a completed
# transfer whose libcurl status is not the status line's, protocol-error
# wins over redirect-limit and no status is recorded; a status libcurl does
# not report (0) leaves the status line to decide.
test_that("a completed transfer's statuses must agree before redirect-limit", {
  mock_answers("127.0.0.1")
  reported <- new.env(parent = emptyenv())
  local_mocked_bindings(
    dep_curl_transfer = function(opts, on_body, debug, progress) {
      debug(0L, charToRaw("Trying 127.0.0.1:80...\n"))
      list(
        aborted = FALSE,
        error = NULL,
        status = reported$status,
        headers = wire(
          "HTTP/1.1 302 Found\r\nLocation: /a\r\nContent-Length: 0\r\n\r\n"
        ),
        connect = 0.01
      )
    }
  )
  fetch <- function(status) {
    reported$status <- status
    guarded_get(
      paste0("http://", pinned_host, "/"),
      loopback_policy(max_redirects = 0)
    )
  }
  for (status in c(200L, 307L)) {
    r <- fetch(status)
    expect_s3_class(r, "ssrfr_failure")
    expect_identical(r$cause, "protocol-error", label = status)
    expect_identical(r$detail$check, "header", label = status)
    expect_null(attr(r, "binding")$state$status, label = status)
  }
  for (status in c(302L, 0L)) {
    r <- fetch(status)
    expect_s3_class(r, "ssrfr_refusal")
    expect_identical(r$code, "redirect-limit", label = status)
    expect_identical(attr(r, "binding")$state$status, 302L, label = status)
  }
})

# §2.3, §12 as amended 2026-09-27: a transfer stopped in flight at a 3xx past
# the budget ends as the completed one with the same bytes does. Once the
# stop is made libcurl's status is known, and when it is not the status
# line's, step 13 decided nothing: a header limit passed after the status
# line, then a transport error, then `protocol-error`, as for any transfer
# whose statuses disagree. INV-11: a stopped transfer is never a response,
# even one whose parse would read libcurl's status.
test_that("a transfer stopped at a 3xx needs its statuses to agree too", {
  mock_answers("127.0.0.1")
  line <- wire("HTTP/1.1 302 Found\r\n")
  short <- c(line, wire("Location: /a\r\nContent-Length: 0\r\n\r\n"))
  long <- c(line, wire(strrep("X-F: 1\r\n", 6), "Location: /a\r\n\r\n"))
  scripted <- new.env(parent = emptyenv())
  parse <- ssrfr:::parse_response_headers
  local_mocked_bindings(
    # A parse that reads `scripted$parsed` as the status, when it is set,
    # and counts its calls.
    parse_response_headers = function(raw, segments = NULL) {
      scripted$parses <- scripted$parses + 1L
      parsed <- parse(raw, segments)
      if (!is.null(scripted$parsed)) {
        parsed$status <- scripted$parsed
      }
      parsed
    },
    dep_curl_transfer = function(opts, on_body, debug, progress) {
      debug(0L, charToRaw("Trying 127.0.0.1:80...\n"))
      # In flight, the status line alone decides and stops the transfer.
      scripted$go <- if (scripted$in_flight) {
        progress(0, 0, function() line)
      }
      list(
        aborted = scripted$in_flight,
        failed = NULL,
        error = scripted$error,
        status = scripted$status,
        headers = scripted$headers,
        connect = 0.01
      )
    }
  )
  # The outcome's class, code or cause, check, limit, and the binding's
  # recorded status, location, whether it was fetched, and its outcome.
  outcome <- function(
    status,
    headers = short,
    error = NULL,
    parsed = NULL,
    in_flight
  ) {
    scripted$status <- status
    scripted$headers <- headers
    scripted$error <- error
    scripted$parsed <- parsed
    scripted$in_flight <- in_flight
    scripted$parses <- 0L
    r <- guarded_get(
      paste0("http://", pinned_host, "/"),
      loopback_policy(max_redirects = 0, max_header_fields = 4)
    )
    # INV-11: a stopped transfer is never parsed.
    if (in_flight) {
      expect_false(scripted$go)
      expect_identical(scripted$parses, 0L)
    }
    state <- attr(r, "binding")$state
    list(
      class(r)[[1L]],
      if (inherits(r, "ssrfr_refusal")) r$code else r$cause,
      r$detail$check,
      r$detail$limit,
      state$status,
      state$location,
      state$fetched,
      state$outcome
    )
  }
  # A failure that records no status and fetches nothing.
  failure <- function(cause, check, limit = NULL) {
    list("ssrfr_failure", cause, check, limit, NULL, NULL, FALSE, cause)
  }
  refusal <- list(
    "ssrfr_refusal",
    "redirect-limit",
    "redirect",
    "max_redirects",
    302L,
    NULL,
    FALSE,
    "redirect-limit"
  )
  # Each case ends as `want`, stopped in flight or completed, unless it
  # names what the completed transfer ends as.
  cases <- list(
    "disagreeing" = list(
      args = list(status = 307L),
      want = failure("protocol-error", "header")
    ),
    "disagreeing, with a transport error" = list(
      args = list(status = 307L, error = "curl_error_operation_timedout"),
      want = failure("timeout", "transport", "total_timeout")
    ),
    "disagreeing, with a header limit passed after the line" = list(
      args = list(
        status = 307L,
        headers = long,
        error = "curl_error_operation_timedout"
      ),
      want = failure("response-too-large", "header", "max_header_fields")
    ),
    # INV-11: a parse that reads libcurl's status leaves only `stopped` in
    # the way. The completed transfer with the same parse is a response,
    # which shows the parse cannot be what stops the stopped one.
    "disagreeing, with a parse that agrees with libcurl" = list(
      args = list(status = 307L, parsed = 307L),
      want = failure("protocol-error", "header"),
      completed = list(
        "ssrfr_response",
        NULL,
        NULL,
        NULL,
        307L,
        "/a",
        TRUE,
        "response"
      )
    ),
    "agreeing" = list(
      args = list(status = 302L, headers = long),
      want = refusal
    ),
    "not reported" = list(
      args = list(status = 0L, error = "curl_error_operation_timedout"),
      want = refusal
    )
  )
  for (label in names(cases)) {
    case <- cases[[label]]
    stopped <- do.call(outcome, c(case$args, in_flight = TRUE))
    completed <- do.call(outcome, c(case$args, in_flight = FALSE))
    expect_identical(stopped, case$want, label = label)
    expect_identical(completed, case$completed %||% case$want, label = label)
  }
})

# The decision at the status line, on scripted header buffers: a header
# limit the interim 1xx blocks passed was reached first; nothing after the
# final status line counts against it.
test_that("header_stop decides at the final status line", {
  spent <- list(hop = 1L, budget = list(max_redirects = 0))
  left <- list(hop = 1L, budget = list(max_redirects = 1))
  policy <- ssrf_policy(max_header_fields = 4, max_header_bytes = 200)
  stop_for <- function(text, binding = spent, reported = NULL) {
    seen <- new.env(parent = emptyenv())
    ssrfr:::measure_header(seen, charToRaw(text))
    ssrfr:::header_stop(seen, policy, binding, reported)
  }
  many <- strrep("X-F: 1\r\n", 6)
  final <- "HTTP/1.1 302 Found\r\n"
  # Fields past the limit after the final status line: redirect-limit.
  expect_identical(
    stop_for(paste0(final, many, "\r\n")),
    list(redirect_limit = 302L)
  )
  # §2.3: a status libcurl reports decides with the line when it agrees, or
  # is 0 (none); one that disagrees leaves step 13 deciding nothing, and the
  # header limits the whole buffer passed decide as for any response.
  for (reported in list(302L, 0L)) {
    expect_identical(
      stop_for(paste0(final, many, "\r\n"), reported = reported),
      list(redirect_limit = 302L)
    )
  }
  expect_identical(
    stop_for(paste0(final, many, "\r\n"), reported = 307L)$limit,
    "max_header_fields"
  )
  expect_null(stop_for(paste0(final, "Location: /a\r\n\r\n"), reported = 200L))
  # Only the status line so far, the block not ended.
  expect_identical(stop_for(final), list(redirect_limit = 302L))
  # A 1xx block past the field limit before it: the header limit.
  expect_identical(
    stop_for(paste0("HTTP/1.1 103 Early Hints\r\n", many, "\r\n", final)),
    list(
      cause = "response-too-large",
      check = "header",
      limit = "max_header_fields"
    )
  )
  # A 1xx block within the limits: the status line decides.
  early <- "HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n"
  expect_identical(
    stop_for(paste0(early, final, many)),
    list(redirect_limit = 302L)
  )
  # 1xx bytes past max_header_bytes before the status line.
  wide <- paste0("HTTP/1.1 103 Early Hints\r\nX-W: ", strrep("w", 200), "\r\n")
  expect_identical(
    stop_for(paste0(wide, "\r\n", final))$limit,
    "max_header_bytes"
  )
  # A 1xx block alone decides nothing yet.
  expect_null(stop_for(early))
  # Budget left, or no 3xx: the header limits as before.
  expect_identical(
    stop_for(paste0(final, many, "\r\n"), left)$limit,
    "max_header_fields"
  )
  expect_null(stop_for(paste0(final, "Location: /a\r\n\r\n"), left))
  expect_identical(
    stop_for(paste0("HTTP/1.1 200 OK\r\n", many, "\r\n"))$limit,
    "max_header_fields"
  )
  expect_null(stop_for(paste0("HTTP/1.1 399 X\r\n"), left))
  expect_identical(
    stop_for("HTTP/1.1 399 X\r\n"),
    list(redirect_limit = 399L)
  )
})

# §6.6, §12 as amended 2026-09-27: the status line itself counts before the
# decision, so a status line that alone passes max_header_bytes is the
# header limit, reached first; one exactly at the limit is redirect-limit.
# The status line is not a field.
test_that("the status line counts against the header limits it decides", {
  spent <- list(hop = 1L, budget = list(max_redirects = 0))
  final <- "HTTP/1.1 302 Found\r\n"
  expect_identical(nchar(final, type = "bytes"), 20L)
  stop_for <- function(text, max_bytes, max_fields = 128) {
    seen <- new.env(parent = emptyenv())
    ssrfr:::measure_header(seen, charToRaw(text))
    policy <- ssrf_policy(
      max_header_bytes = max_bytes,
      max_header_fields = max_fields
    )
    ssrfr:::header_stop(seen, policy, spent)
  }
  too_large <- list(
    cause = "response-too-large",
    check = "header",
    limit = "max_header_bytes"
  )
  rest <- "Location: /a\r\nX-F: 1\r\n\r\n"
  expect_identical(stop_for(paste0(final, rest), 19), too_large)
  expect_identical(stop_for(final, 19), too_large)
  expect_identical(
    stop_for(paste0(final, rest), 20),
    list(redirect_limit = 302L)
  )
  # After interim 1xx blocks, the status line's own bytes count too.
  early <- "HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n"
  upto <- nchar(early, type = "bytes") + 20L
  expect_identical(stop_for(paste0(early, final, rest), upto - 1L), too_large)
  expect_identical(
    stop_for(paste0(early, final, rest), upto),
    list(redirect_limit = 302L)
  )
  # Neither status line is a field: one 1xx field fits a limit of one.
  expect_identical(
    stop_for(paste0(early, final, rest), 16 * 1024, max_fields = 1),
    list(redirect_limit = 302L)
  )

  # On the wire, under max_redirects = 0.
  mock_answers("127.0.0.1")
  over <- function(max_bytes) {
    server <- local_raw_server(wire(
      final,
      "Location: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    ))
    guarded_get(
      pinned_url(server$port),
      loopback_policy(
        server$port,
        max_redirects = 0,
        max_header_bytes = max_bytes
      )
    )
  }
  r <- over(19)
  expect_s3_class(r, "ssrfr_failure")
  expect_identical(r$cause, "response-too-large")
  expect_identical(r$detail$limit, "max_header_bytes")
  # The binding records no status, which was never decided.
  expect_null(attr(r, "binding")$state$status)
  r <- over(20)
  expect_s3_class(r, "ssrfr_refusal")
  expect_identical(r$code, "redirect-limit")
})

# --- INV-7 --------------------------------------------------------------------

# r-binding.md §7: a webfakes redirect chain whose second redirect points at
# a target refused on one dimension: the address (a literal, and a name that
# resolves to a provider endpoint), the scheme, the port, a caller host rule,
# credentials, a numeric spelling and a downgrade.
test_that("every dimension is revalidated on every hop", {
  skip_if_no_webfakes()
  web <- local_redirect_server()
  port <- web$get_port()
  seen <- mock_answers(function(q) {
    if (identical(q, "imds.example.invalid.")) {
      "169.254.169.254"
    } else {
      "127.0.0.1"
    }
  })
  policy <- loopback_policy(
    port,
    deny_hosts = "denied.example.invalid",
    total_timeout = 60
  )
  other <- function(path) pinned_url(port, path, host = other_host)
  targets <- list(
    "http://10.0.0.5/" = "private",
    "http://imds.example.invalid/latest/meta-data/" = "cloud-metadata",
    "http://169.254.169.254/latest/meta-data/" = "cloud-metadata",
    "ftp://files.example.invalid/" = "scheme",
    "gopher://files.example.invalid:70/_x" = "scheme",
    "http://other.example.invalid:6379/" = "port",
    "http://denied.example.invalid/" = "host-denied",
    "http://user:pw@other.example.invalid/" = "userinfo",
    "http://0177.0.0.1/" = "numeric-literal",
    "http://metadata.google.internal/" = "cloud-metadata"
  )
  for (target in names(targets)) {
    seen$queries <- character()
    to <- utils::URLencode(target, reserved = TRUE)
    second <- utils::URLencode(
      other(paste0("/r/307?to=", to)),
      reserved = TRUE,
      repeated = TRUE
    )
    chain <- follow_chain(
      pinned_url(port, paste0("/r/302?to=", second)),
      policy
    )
    r <- chain$result
    expect_s3_class(r, "ssrfr_refusal")
    expect_identical(r$code, targets[[target]], label = target)
    # The third hop was refused: two hops were fetched before it.
    expect_identical(r$hop, 3L, label = target)
    expect_length(chain$bindings, 2L)
    expect_identical(chain$bindings[[2L]]$origin$host, other_host)
    # One resolution per hop that reached step 7 (INV-5).
    resolved <- c(paste0(pinned_host, "."), paste0(other_host, "."))
    if (identical(target, "http://imds.example.invalid/latest/meta-data/")) {
      resolved <- c(resolved, "imds.example.invalid.")
    }
    expect_identical(seen$queries, resolved, label = target)
  }

  # The scheme dimension's redirect rule: https to http refuses as
  # downgrade (§12 step 3), even to the same host.
  tls <- local_redirect_server(tls = TRUE)
  tport <- tls$get_port()
  local_trust_test_ca()
  tpolicy <- loopback_policy(tport)
  b <- ssrf_prepare_hop(
    paste0("https://legit.example:", tport, "/"),
    tpolicy,
    request = list(
      headers = c(`X-Corpus-Location` = paste0("http://legit.example:", tport))
    )
  )
  expect_identical(ssrf_fetch(b)$status, 302L)
  r <- ssrf_prepare_hop(b$state$location, tpolicy, from = b)
  expect_s3_class(r, "ssrfr_refusal")
  expect_identical(r$code, "downgrade")
  expect_identical(r$hop, 2L)
  expect_identical(r$detail$step, 3L)
  # https to https is no downgrade.
  b <- ssrf_prepare_hop(
    paste0("https://legit.example:", tport, "/"),
    tpolicy,
    request = list(
      headers = c(
        `X-Corpus-Location` = paste0("https://legit.example:", tport, "/next")
      )
    )
  )
  expect_identical(ssrf_fetch(b)$status, 302L)
  up <- ssrf_prepare_hop(b$state$location, tpolicy, from = b)
  expect_s3_class(up, "ssrfr_binding")
})

# --- INV-8 --------------------------------------------------------------------

# r-binding.md §7, L3: after a cross-origin 307, the raw request bytes carry
# no Authorization, Cookie, Proxy-Authorization, unnominated field or body,
# and no nominated Content-Type without the body it described (§2.3).
test_that("credentials are absent after a cross-origin hop in the raw bytes", {
  skip_if_no_webfakes()
  web <- local_redirect_server()
  port <- web$get_port()
  landing <- local_raw_server(wire(
    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
  ))
  mock_answers("127.0.0.1")
  policy <- loopback_policy(c(port, landing$port))
  secrets <- c(
    "s3cret-token",
    "s3cret-cookie",
    "s3cret-proxy",
    "s3cret-key",
    "s3cret-body"
  )
  request <- list(
    method = "POST",
    headers = c(
      Authorization = "Bearer s3cret-token",
      Cookie = "session=s3cret-cookie",
      `Proxy-Authorization` = "Basic s3cret-proxy",
      `X-Api-Key` = "s3cret-key",
      `X-Trace` = "trace-1",
      `Content-Type` = "text/plain"
    ),
    body = "s3cret-body",
    carry = c("X-Trace", "Content-Type")
  )
  to <- pinned_url(landing$port, "/landing", host = other_host)
  b1 <- ssrf_prepare_hop(
    pinned_url(port, paste0("/r/307?to=", utils::URLencode(to, TRUE))),
    policy,
    request = request
  )
  expect_identical(ssrf_fetch(b1)$status, 307L)
  b2 <- ssrf_prepare_hop(b1$state$location, policy, from = b1)
  expect_s3_class(b2, "ssrfr_binding")
  r <- ssrf_fetch(b2)
  expect_identical(r$status, 200L)
  sent <- landing$request()
  text <- rawToChar(sent)
  for (s in secrets) {
    expect_false(grepl(s, text, fixed = TRUE), label = s)
  }
  head <- recorded_head(landing)
  # 307 keeps the method, and the body goes with the origin.
  expect_identical(head[[1L]], "POST /landing HTTP/1.1")
  expect_setequal(
    tolower(sub(":.*$", "", head[-1L])),
    c("host", "user-agent", "accept-encoding", "content-length", "x-trace")
  )
  expect_true("Content-Length: 0" %in% head)
  expect_true("X-Trace: trace-1" %in% head)
  expect_identical(
    head[startsWith(head, "Host:")],
    paste0("Host: ", other_host, ":", landing$port)
  )
  # The binding records the drop as a fact (§2.3), naming fields, never
  # values, and prints none of the secrets (INV-12).
  expect_true(b2$redirect$cross_origin)
  expect_true(b2$redirect$body_dropped)
  expect_setequal(
    b2$redirect$dropped,
    c(
      "authorization",
      "cookie",
      "proxy-authorization",
      "x-api-key",
      "content-type"
    )
  )
  expect_null(b2$request$body)
  expect_identical(b2$request$carry, "x-trace")
  shown <- paste(c(format(b1), format(b2)), collapse = "\n")
  for (s in secrets) {
    expect_false(grepl(s, shown, fixed = TRUE), label = s)
  }
})

# §2.3's table, on the wire: each followed status, to the same origin and to
# another, for GET, HEAD and POST. Every plan carries credentials, an
# unnominated secret, a nominated field and nominated content fields; POST
# also carries a body.
test_that("the method and body transformation follows the status table", {
  skip_if_no_webfakes()
  web <- local_redirect_server()
  port <- web$get_port()
  mock_answers("127.0.0.1")
  policy <- loopback_policy(port, total_timeout = 120)
  secret <- c("authorization", "cookie", "x-api-key")
  content <- c("content-language", "content-type")
  for (status in c(301L, 302L, 303L, 307L, 308L)) {
    for (cross in c(FALSE, TRUE)) {
      for (method in c("GET", "HEAD", "POST")) {
        label <- paste(status, if (cross) "cross-origin" else "same", method)
        request <- list(
          method = method,
          headers = c(
            Authorization = "Bearer t",
            Cookie = "c=1",
            `X-Api-Key` = "k",
            `X-Trace` = "t1",
            `Content-Type` = "text/plain",
            `Content-Language` = "en"
          ),
          body = if (method == "POST") "payload",
          carry = c("X-Trace", "Content-Type", "Content-Language")
        )
        to <- if (cross) {
          pinned_url(port, "/echo", host = other_host)
        } else {
          "/echo"
        }
        b1 <- ssrf_prepare_hop(
          pinned_url(port, paste0("/r/", status, "?to=", URLencode(to, TRUE))),
          policy,
          request = request
        )
        expect_identical(ssrf_fetch(b1)$status, status, label = label)
        b2 <- ssrf_prepare_hop(b1$state$location, policy, from = b1)
        echo <- echo_of(ssrf_fetch(b2))
        # §2.3: 301 and 302 turn POST into GET; 303 turns all but HEAD into
        # GET; 307 and 308 keep the method.
        want_method <- if (status %in% c(307L, 308L)) {
          method
        } else if (status == 303L) {
          if (method == "HEAD") "HEAD" else "GET"
        } else if (method == "POST") {
          "GET"
        } else {
          method
        }
        body_dropped <- cross ||
          status == 303L ||
          (status %in% c(301L, 302L) && method == "POST")
        expect_identical(echo$method, want_method, label = label)
        expect_identical(b2$request$method, want_method, label = label)
        want_body <- if (method == "POST" && !body_dropped) "payload" else ""
        expect_identical(echo$body, want_body, label = label)
        fields <- setdiff(
          echo$fields,
          c("host", "user-agent", "accept-encoding", "content-length")
        )
        want_fields <- c(
          if (!cross) secret,
          "x-trace",
          if (!body_dropped) content
        )
        expect_setequal(fields, want_fields)
        expect_identical(b2$redirect$status, status, label = label)
        expect_identical(b2$redirect$cross_origin, cross, label = label)
        # A body was dropped only when the plan had one.
        expect_identical(
          b2$redirect$body_dropped,
          body_dropped && method == "POST",
          label = label
        )
      }
    }
  }
})

# §2.3: two origins are the same when scheme, host (A-label, lowercase, no
# trailing root dot) and effective port are equal.
test_that("origin equality is scheme, normalized host and effective port", {
  same <- function(a, b) {
    ssrfr:::same_origin(
      list(scheme = a[[1]], host = a[[2]], port = a[[3]]),
      list(scheme = b[[1]], host = b[[2]], port = b[[3]])
    )
  }
  expect_true(same(
    list("https", "EXAMPLE.com", 443L),
    list("https", "example.com.", 443L)
  ))
  expect_true(same(list("http", "[::1]", 80L), list("http", "[0:0::1]", 80L)))
  expect_true(same(
    list("http", "10.0.0.1", 80L),
    list("http", "10.0.0.1", 80L)
  ))
  expect_false(same(
    list("http", "example.com", 80L),
    list("https", "example.com", 443L)
  ))
  expect_false(same(
    list("http", "example.com", 80L),
    list("http", "example.com", 8080L)
  ))
  expect_false(same(
    list("http", "example.com", 80L),
    list("http", "www.example.com", 80L)
  ))
  expect_false(same(
    list("http", "10.0.0.1", 80L),
    list("http", "10.0.0.2", 80L)
  ))

  # On the wire: a Location differing only in the host's case stays
  # same-origin, so the plan carries.
  skip_if_no_webfakes()
  web <- local_redirect_server()
  port <- web$get_port()
  mock_answers("127.0.0.1")
  policy <- loopback_policy(port)
  to <- paste0("http://PINNED.Example.INVALID:", port, "/echo")
  b1 <- ssrf_prepare_hop(
    pinned_url(port, paste0("/r/307?to=", URLencode(to, TRUE))),
    policy,
    request = list(headers = c(Authorization = "Bearer t"))
  )
  ssrf_fetch(b1)
  b2 <- ssrf_prepare_hop(b1$state$location, policy, from = b1)
  expect_false(b2$redirect$cross_origin)
  expect_true("authorization" %in% echo_of(ssrf_fetch(b2))$fields)
})

# §2.3: whenever the body is dropped, every field describing it goes too,
# nominated or not: RFC 9110 §15.4's content fields, Content-Range (RFC 9110
# §14.4), Content-Disposition (RFC 6266), and Content-Digest and Repr-Digest
# (RFC 9530).
test_that("a dropped body takes every field that describes it", {
  content <- c(
    `Content-Type` = "text/plain",
    `Content-Encoding` = "gzip",
    `Content-Language` = "en",
    `Content-Location` = "/doc",
    `Content-Range` = "bytes 0-6/7",
    `Content-Disposition` = "attachment; filename=a.txt",
    Digest = "sha-256=x",
    `Content-Digest` = "sha-256=:x:",
    `Repr-Digest` = "sha-256=:x:",
    `Last-Modified` = "Mon, 01 Jan 2026 00:00:00 GMT"
  )
  plan <- list(
    method = "POST",
    headers = c(content, `X-Trace` = "t1"),
    body = charToRaw("payload"),
    carry = tolower(c(names(content), "X-Trace"))
  )
  for (status in c(301L, 303L)) {
    out <- ssrfr:::redirect_plan(plan, status, cross_origin = FALSE)
    expect_named(out$plan$headers, "X-Trace", label = status)
    expect_setequal(out$record$dropped, tolower(names(content)))
  }
  # Across origins, nomination does not keep them either.
  plan$method <- "PUT"
  out <- ssrfr:::redirect_plan(plan, 307L, cross_origin = TRUE)
  expect_named(out$plan$headers, "X-Trace")
  # A kept body keeps them.
  out <- ssrfr:::redirect_plan(plan, 307L, cross_origin = FALSE)
  expect_identical(out$plan$headers, plan$headers)
})

# The record says a body was dropped only when the plan had one; the
# content fields go whenever the hop sends no body (§2.3).
test_that("the record names a dropped body only when there was one", {
  plan <- list(
    method = "GET",
    headers = c(`Content-Type` = "text/plain", `X-Trace` = "t1"),
    body = NULL,
    carry = c("content-type", "x-trace")
  )
  cases <- list(
    list(status = 302L, cross = TRUE, method = "GET"),
    list(status = 303L, cross = FALSE, method = "GET"),
    list(status = 303L, cross = FALSE, method = "DELETE"),
    list(status = 302L, cross = FALSE, method = "POST")
  )
  for (case in cases) {
    label <- paste(case$status, case$method, case$cross)
    plan$method <- case$method
    out <- ssrfr:::redirect_plan(plan, case$status, case$cross)
    expect_false(out$record$body_dropped, label = label)
    expect_identical(out$record$dropped, "content-type", label = label)
    plan$body <- charToRaw("payload")
    out <- ssrfr:::redirect_plan(plan, case$status, case$cross)
    expect_true(out$record$body_dropped, label = label)
    expect_null(out$plan$body, label = label)
    plan$body <- NULL
  }

  # On a binding: a cross-origin GET drops no body, and says none.
  skip_if_no_webfakes()
  web <- local_redirect_server()
  port <- web$get_port()
  mock_answers("127.0.0.1")
  policy <- loopback_policy(port)
  to <- pinned_url(port, "/echo", host = other_host)
  b1 <- ssrf_prepare_hop(
    pinned_url(port, paste0("/r/302?to=", URLencode(to, TRUE))),
    policy,
    request = list(headers = plan$headers, carry = plan$carry)
  )
  expect_identical(ssrf_fetch(b1)$status, 302L)
  b2 <- ssrf_prepare_hop(b1$state$location, policy, from = b1)
  expect_false(b2$redirect$body_dropped)
  shown <- paste(format(b2), collapse = "\n")
  expect_match(shown, "cross-origin; dropped content-type", fixed = TRUE)
  expect_false(grepl("body dropped", shown, fixed = TRUE))
})

# --- the Location value -------------------------------------------------------

# A Location that is not valid UTF-8 is kept byte for byte, marked "bytes";
# resolving it neither translates it nor warns, and it refuses as `parse`
# (§3.2, INV-2, INV-12).
test_that("a Location that is not valid UTF-8 refuses as parse, silently", {
  web <- local_raw_server(c(
    wire("HTTP/1.1 302 Found\r\nLocation: /caf"),
    as.raw(0xe9),
    wire("\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
  ))
  seen <- mock_answers("127.0.0.1")
  policy <- loopback_policy(web$port)
  b <- ssrf_prepare_hop(pinned_url(web$port), policy, request = list())
  expect_identical(ssrf_fetch(b)$status, 302L)
  location <- b$state$location
  expect_identical(Encoding(location), "bytes")
  r <- NULL
  expect_no_warning(r <- ssrf_prepare_hop(location, policy, from = b))
  expect_s3_class(r, "ssrfr_refusal")
  expect_identical(r$code, "parse")
  expect_identical(r$hop, 2L)
  expect_false(grepl("caf", paste(format(r), collapse = "\n"), fixed = TRUE))
  # Only the first hop was resolved.
  expect_identical(seen$queries, paste0(pinned_host, "."))
})

# --- the documented loop ------------------------------------------------------

# The loop ssrf_prepare_hop()'s example and the vignette show ends with
# `result` holding the chain's final outcome, whichever call returned it,
# and handles a response, whatever its body holds, a refusal and a failure.
# Each is run against scripted stand-ins for the two primitives.
test_that("the documented redirect loops end on the chain's final outcome", {
  rd_file <- system.file("man", "ssrf_prepare_hop.Rd", package = "ssrfr")
  rd <- if (nzchar(rd_file)) {
    tools::parse_Rd(rd_file)
  } else {
    tools::Rd_db("ssrfr")[["ssrf_prepare_hop.Rd"]]
  }
  tagged <- function(x, tag) {
    Filter(function(node) identical(attr(node, "Rd_tag"), tag), x)[[1L]]
  }
  example <- paste(
    unlist(tagged(tagged(rd, "\\examples"), "\\dontrun")),
    collapse = ""
  )
  source_rmd <- test_path("..", "..", "vignettes", "introduction.Rmd")
  rmd_file <- if (file.exists(source_rmd)) {
    source_rmd
  } else {
    system.file("doc", "introduction.Rmd", package = "ssrfr")
  }
  # covr installs the package without its vignettes: the Rd half still runs.
  codes <- list(example = example)
  if (file.exists(rmd_file)) {
    rmd <- readLines(rmd_file, encoding = "UTF-8")
    section <- rmd[seq(which(rmd == "## Following redirects"), length(rmd))]
    # The section's first chunk calls ssrf_fetch_chain(); the per-hop loop is
    # the first chunk that runs a `while` loop.
    ends <- which(section == "```")
    chunks <- lapply(which(startsWith(section, "```{r")), function(opens) {
      closes <- ends[ends > opens][[1L]]
      paste(section[seq(opens + 1L, closes - 1L)], collapse = "\n")
    })
    loops <- Filter(function(code) grepl("while (", code, fixed = TRUE), chunks)
    if (length(loops) == 0L) {
      stop("the vignette's Following redirects section has no `while` loop")
    }
    codes$vignette <- loops[[1L]]
  }

  hop <- function(count = 1L) {
    structure(
      list(state = list(location = "/next", location_count = count)),
      class = "ssrfr_binding"
    )
  }
  # A body with an embedded NUL, which no string can hold: the loops keep
  # any body.
  done <- as.raw(c(0x64, 0x00, 0x6e))
  response <- function(status) {
    structure(
      list(status = status, headers = character(), body = done),
      class = "ssrfr_response"
    )
  }
  refusal <- function(code) ssrfr:::new_ssrf_refusal(code, 1L)
  failure <- function(cause) ssrfr:::new_ssrf_failure(cause, 1L)
  scripts <- list(
    "a followed redirect, then 200" = list(
      calls = list(hop(), response(302L), hop(), response(200L)),
      outcome = done
    ),
    "a refused redirect hop" = list(
      calls = list(hop(), response(302L), refusal("downgrade")),
      outcome = "downgrade"
    ),
    "a fetch that fails" = list(
      calls = list(hop(), failure("connect-failed")),
      outcome = "connect-failed"
    ),
    "a refused first hop" = list(
      calls = list(refusal("private")),
      outcome = "private"
    ),
    "the budget spent" = list(
      calls = list(hop(), response(302L), hop(), refusal("redirect-limit")),
      outcome = "redirect-limit"
    ),
    "a 302 without Location" = list(
      calls = list(hop(count = 0L), response(302L)),
      outcome = done
    )
  )
  for (code in codes) {
    for (label in names(scripts)) {
      script <- scripts[[label]]
      queue <- new.env(parent = emptyenv())
      queue$left <- script$calls
      answer <- function(...) {
        out <- queue$left[[1L]]
        queue$left <- queue$left[-1L]
        out
      }
      env <- new.env()
      env$policy <- ssrf_policy()
      env$ssrf_prepare_hop <- answer
      env$ssrf_fetch <- answer
      eval(parse(text = code, keep.source = FALSE), env)
      expect_length(queue$left, 0L)
      final <- script$calls[[length(script$calls)]]
      expect_identical(env$result, final, label = label)
      expect_identical(env$outcome, script$outcome, label = label)
    }
  }
  skip_if_not("vignette" %in% names(codes), "the vignette is not installed")
})

# --- a real app ---------------------------------------------------------------

# r-binding.md §7: ordinary HTTP still works through the guard, a redirect
# chain included, relative and absolute, followed hop by hop through the
# public primitives.
test_that("a redirect chain works through webfakes::httpbin_app()", {
  skip_if_no_webfakes()
  web <- webfakes::local_app_process(
    webfakes::httpbin_app(),
    opts = webfakes::server_opts(num_threads = 2)
  )
  port <- web$get_port()
  mock_answers("127.0.0.1")
  policy <- loopback_policy(port)
  host <- "httpbin.invalid"
  url <- function(path) pinned_url(port, path, host = host)

  chain <- follow_chain(url("/redirect/3"), policy)
  expect_s3_class(chain$result, "ssrfr_response")
  expect_identical(chain$result$status, 200L)
  expect_length(chain$bindings, 4L)
  expect_identical(chain$bindings[[4L]]$url, url("/get"))
  expect_match(body_text(chain$result), paste0("\"Host\": *\"", host))

  chain <- follow_chain(url("/relative-redirect/2"), policy)
  expect_identical(chain$result$status, 200L)
  expect_length(chain$bindings, 3L)

  # httpbin's absolute redirects name 127.0.0.1: another origin, which the
  # nominated field survives and the credential does not.
  chain <- follow_chain(
    url("/absolute-redirect/1"),
    policy,
    request = list(
      headers = c(Authorization = "Bearer t", `X-Keep` = "yes"),
      carry = "X-Keep"
    )
  )
  expect_identical(chain$result$status, 200L)
  expect_identical(chain$bindings[[2L]]$origin$host, "127.0.0.1")
  got <- body_text(chain$result)
  expect_match(got, "\"X-Keep\": *\"yes\"")
  expect_false(grepl("Authorization", got, fixed = TRUE))

  # 303 turns POST into GET; 307 keeps POST and its body, same origin.
  chain <- follow_chain(
    url("/redirect-to?url=%2Fget&status_code=303"),
    policy,
    request = list(method = "POST", body = "a=1")
  )
  expect_identical(chain$result$status, 200L)
  expect_identical(chain$bindings[[2L]]$request$method, "GET")
  chain <- follow_chain(
    url("/redirect-to?url=%2Fpost&status_code=307"),
    policy,
    request = list(
      method = "POST",
      headers = c(`Content-Type` = "application/json"),
      body = "{\"n\":42}"
    )
  )
  expect_identical(chain$result$status, 200L)
  expect_match(body_text(chain$result), "\"n\": *42")
})
