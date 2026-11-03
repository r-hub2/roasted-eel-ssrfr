# ssrf_prepare_hop() (ssrfr-v1.md §2.1-§2.5, §6.2, §6.6, §12 steps 1-8): the
# arguments, the three outcome classes, what a binding carries, resolve
# once, and the refusal that opens no connection (INV-11, r-binding.md §7).
# The resolver is always the mocked internal wrapper.

test_that("prepare takes exactly one of request and from", {
  p <- ssrf_policy()
  url <- "http://93.184.216.34/"
  expect_error(ssrf_prepare_hop(url, p), class = "ssrfr_error_invalid_argument")
  expect_error(
    ssrf_prepare_hop(url, p, request = NULL, from = NULL),
    class = "ssrfr_error_invalid_argument"
  )
  b <- ssrf_prepare_hop(url, p, request = list())
  expect_error(
    ssrf_prepare_hop(url, p, request = list(), from = b),
    class = "ssrfr_error_invalid_argument"
  )
  # `from` alone is a redirect hop; an unspent binding is not a valid one
  # (test-redirect.R has the rest).
  expect_error(
    ssrf_prepare_hop("/next", p, from = b),
    class = "ssrfr_error_invalid_from"
  )
  expect_error(
    ssrf_prepare_hop(c(url, url), p, request = list()),
    class = "ssrfr_error_invalid_argument"
  )
  expect_error(
    ssrf_prepare_hop(url, list(), request = list()),
    class = "ssrfr_error_invalid_argument"
  )
  expect_error(
    ssrf_prepare_hop(url, request = list()),
    class = "ssrfr_error_invalid_argument"
  )
})

test_that("a refused hop returns a refusal with its reason code and hop", {
  seen <- mock_answers("93.184.216.34")
  cases <- list(
    "http://127.0.0.1/" = "loopback",
    "http://0177.0.0.1/" = "numeric-literal",
    "ftp://files.example/" = "scheme",
    "http://files.example:6379/" = "port",
    "http://user:pw@files.example/" = "userinfo",
    "http://metadata.google.internal/" = "cloud-metadata",
    "http://[64:ff9b::a9fe:a9fe]/" = "cloud-metadata"
  )
  for (url in names(cases)) {
    r <- ssrf_prepare_hop(url, ssrf_policy(), request = list())
    expect_s3_class(r, "ssrfr_refusal")
    expect_identical(r$code, cases[[url]], label = url)
    expect_identical(r$hop, 1L)
  }
  # None of them was resolved.
  expect_identical(seen$queries, character())

  # One refused answer refuses the whole set (INV-4).
  mock_answers(c("93.184.216.34", "10.0.0.5"))
  r <- ssrf_prepare_hop(
    "http://mixed.example/",
    ssrf_policy(),
    request = list()
  )
  expect_s3_class(r, "ssrfr_refusal")
  expect_identical(r$code, "private")
  expect_identical(r$address, "10.0.0.5")
})

# r-binding.md §2.6, §6.5: a literal's pin target is its canonical text. When
# raddr classified the address and then fails to format it, the hop refuses
# as `malformed-address` at gate 1b, naming the host, and binds nothing.
test_that("a literal raddr cannot format once classified refuses", {
  classified <- new.env(parent = emptyenv())
  classified$yes <- FALSE
  reachability <- dep_raddr_reachability
  format_address <- dep_raddr_format
  local_mocked_bindings(
    dep_raddr_reachability = function(x) {
      classified$yes <- TRUE
      reachability(x)
    },
    dep_raddr_format = function(x) {
      if (classified$yes) stop("raddr") else format_address(x)
    }
  )
  hosts <- c(
    "http://93.184.216.34/" = "93.184.216.34",
    "http://[2606:4700:4700::1111]/" = "[2606:4700:4700::1111]"
  )
  for (url in names(hosts)) {
    classified$yes <- FALSE
    r <- ssrf_prepare_hop(url, ssrf_policy(), request = list())
    expect_s3_class(r, "ssrfr_refusal")
    expect_identical(r$code, "malformed-address", label = url)
    expect_identical(r$detail$step, 8L, label = url)
    expect_identical(r$detail$gate, "1b", label = url)
    expect_identical(r$detail$tier, 1L, label = url)
    expect_identical(r$host, hosts[[url]], label = url)
  }
})

# §4.2, INV-11: a zone-ID literal, and a host WHATWG cannot read, refuse at
# prepare as `parse`, before any resolution, whatever address or name the
# rest of the host spells. The percent-encoded trailing stops are V0541,
# V0542, V0551 and V0552, pending on rurl: whichever code they reach, they
# refuse.
test_that("a zone ID or an unreadable host refuses at prepare, unresolved", {
  seen <- mock_answers("93.184.216.34")
  urls <- c(
    "http://[::1%25lo0]/",
    "http://[fd00:ec2::254%25lo0]/",
    "http://[::ffff:127.0.0.1%25lo0]/",
    "http://[fe80::1%25eth0]/",
    "http://[fe80::1%eth0]/",
    "http://metadata﹒google﹒internal/",
    "http://metadata.google.internal﹒/",
    "http://metadata.google.internal‍/",
    "http://meta‍data.google.internal/"
  )
  for (url in urls) {
    r <- ssrf_prepare_hop(url, ssrf_policy(), request = list())
    expect_s3_class(r, "ssrfr_refusal")
    expect_identical(r$code, "parse", label = url)
  }
  for (url in c(
    "http://metadata.google.internal%E3%80%82/",
    "http://metadata.google.internal%EF%BC%8E/",
    "http://metadata%E3%80%82/",
    "http://metadata%EF%BC%8E/"
  )) {
    r <- ssrf_prepare_hop(url, ssrf_policy(), request = list())
    expect_s3_class(r, "ssrfr_refusal")
    expect_true(r$code %in% c("parse", "cloud-metadata"), label = url)
  }
  expect_identical(seen$queries, character())

  # A metadata name off the built-in list refuses on its answer (§5).
  mock_answers("169.254.169.254")
  r <- ssrf_prepare_hop(
    "http://instance-data.ec2.internal/",
    ssrf_policy(),
    request = list()
  )
  expect_s3_class(r, "ssrfr_refusal")
  expect_identical(r$code, "cloud-metadata")
})

test_that("a failed resolution is an operational failure, not a refusal", {
  for (answers in list(function(q) stop("no"), character(), "not-an-address")) {
    mock_answers(answers)
    r <- ssrf_prepare_hop(
      "http://gone.example/",
      ssrf_policy(),
      request = list()
    )
    expect_s3_class(r, "ssrfr_failure")
    expect_identical(r$cause, "unresolvable")
  }
})

test_that("resolution that uses up total_timeout is a timeout", {
  mock_answers(function(q) {
    Sys.sleep(1.2)
    "93.184.216.34"
  })
  r <- ssrf_prepare_hop(
    "http://slow-dns.example/",
    ssrf_policy(total_timeout = 1),
    request = list()
  )
  expect_s3_class(r, "ssrfr_failure")
  expect_identical(r$cause, "timeout")
  expect_identical(r$detail$limit, "total_timeout")
})

test_that("a binding carries the identity, the plan and the validated set", {
  seen <- mock_answers(c("93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"))
  policy <- ssrf_policy(connect_timeout = 5)
  b <- ssrf_prepare_hop(
    "HTTPS://Example.COM./a/b?q=1#frag",
    policy,
    request = list(method = "POST", body = "x")
  )
  expect_s3_class(b, "ssrfr_binding")
  expect_identical(seen$queries, "example.com.")
  expect_identical(b$hop, 1L)
  # The fragment is never part of the target (§2.3).
  expect_identical(b$url, "https://example.com./a/b?q=1")
  expect_identical(
    b$origin,
    list(scheme = "https", host = "example.com.", port = 443L)
  )
  expect_identical(
    b$validated,
    c("93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946")
  )
  expect_identical(b$pin, "93.184.216.34")
  expect_true(b$tls$verify_peer)
  expect_true(b$tls$verify_host)
  expect_true(b$state$fetchable)

  # The policy is held by value (§2.5), and the binding resists casual edits.
  policy$connect_timeout <- 99
  expect_identical(b$policy$connect_timeout, 5)
  expect_error(b$url <- "http://127.0.0.1/")
  expect_error(assign("fetchable", TRUE, envir = b$state))

  # An address literal is its own validated set, in canonical form.
  b <- ssrf_prepare_hop(
    "http://[2606:2800:0220:0001:0248:1893:25c8:1946]:443/",
    ssrf_policy(),
    request = list()
  )
  expect_identical(b$validated, "2606:2800:220:1:248:1893:25c8:1946")
  expect_identical(b$origin$port, 443L)
})

# REQ-057 (§0 S4, §2.3, §6.2): a refusal and a binding for a U-label URL carry
# the A-label host the decision used. The input is built with intToUtf8(): a
# "\u" escape parsed in a C-locale session is unmarked and refuses as `parse`.
test_that("a U-label URL's refusal and binding carry the A-label host", {
  u_label <- paste0("b", intToUtf8(0xFC), "cher.example")
  a_label <- "xn--bcher-kva.example"
  url <- paste0("https://", u_label, "/")

  # Refused by a rule written as the A-label (step 6), before any query, and
  # by the address the A-label resolved to (step 8).
  seen <- mock_answers("10.0.0.5")
  r <- ssrf_prepare_hop(
    url,
    ssrf_policy(deny_hosts = a_label),
    request = list()
  )
  expect_s3_class(r, "ssrfr_refusal")
  expect_identical(r$code, "host-denied")
  expect_identical(r$host, a_label)
  expect_identical(seen$queries, character())
  r <- ssrf_prepare_hop(url, ssrf_policy(), request = list())
  expect_s3_class(r, "ssrfr_refusal")
  expect_identical(r$code, "private")
  expect_identical(r$host, a_label)
  expect_identical(seen$queries, paste0(a_label, "."))

  seen <- mock_answers("93.184.216.34")
  b <- ssrf_prepare_hop(url, ssrf_policy(), request = list())
  expect_s3_class(b, "ssrfr_binding")
  expect_identical(seen$queries, paste0(a_label, "."))
  expect_identical(b$url, paste0("https://", a_label, "/"))
  expect_identical(b$origin$host, a_label)
  expect_identical(b$tls$name, a_label)
})

# §2.5: a binding captures its policy by value, and a policy is a value: a
# list of atomic fields, no environment or other reference among them. So no
# edit to the caller's policy, or to any copy of it, reaches the binding's or
# changes a decision already made, and the binding refuses edits to its own.
test_that("a policy edited after prepare changes nothing already decided", {
  skip_if_no_webfakes()
  web <- local_test_server()
  port <- web$get_port()
  mock_answers("127.0.0.1")
  policy <- loopback_policy(
    port,
    deny_hosts = "denied.example.invalid",
    user_agent = "ua-at-prepare"
  )
  expect_type(policy, "list")
  expect_true(all(vapply(policy, is.atomic, logical(1))))
  b <- ssrf_prepare_hop(
    pinned_url(port, "/echo-headers"),
    policy,
    request = list()
  )
  expect_s3_class(b, "ssrfr_binding")

  # Every way R edits a value, on the caller's policy and on a copy of it.
  edit <- function(p) {
    p$user_agent <- "ua-edited"
    p[["max_response_size"]] <- 1
    p$deny_hosts <- character()
    p$allow_ports <- 80L
    attr(p, "class") <- NULL
    p
  }
  copy <- policy
  copy <- edit(copy)
  policy$user_agent <- "ua-edited"
  policy[["max_response_size"]] <- 1
  attr(policy, "extra") <- TRUE

  # Nor can the binding's own policy or budget be written.
  expect_error(b$policy <- copy)
  expect_error(b[["policy"]] <- copy)
  expect_error(assign("policy", copy, envir = b))
  expect_error(b$policy$user_agent <- "ua-edited")
  expect_error(b[["policy"]][["max_response_size"]] <- 1)
  expect_error(attr(b$policy, "class") <- NULL)
  expect_error(b$budget$max_redirects <- 99)

  expect_s3_class(b$policy, "ssrfr_policy")
  expect_identical(b$policy$user_agent, "ua-at-prepare")
  expect_identical(b$policy$max_response_size, 10 * 1024^2)
  expect_identical(b$policy$deny_hosts, "denied.example.invalid")
  expect_identical(b$policy$allow_ports, c(80L, 443L, as.integer(port)))
  expect_identical(b$budget$max_redirects, 20)

  # The fetch decides under the policy the binding captured: its user agent,
  # and a body larger than the edited 1-byte limit.
  r <- ssrf_fetch(b)
  expect_s3_class(r, "ssrfr_response")
  expect_identical(r$status, 200L)
  expect_match(body_text(r), "User-Agent=ua-at-prepare", fixed = TRUE)

  # A policy decides later as it did when built, whatever became of a copy.
  built <- ssrf_policy(deny_hosts = "denied.example.invalid")
  copy <- edit(built)
  expect_identical(
    ssrf_inspect_url("http://denied.example.invalid/", built)$code,
    "host-denied"
  )
})

test_that("a name is resolved once per hop, and never again by the fetch", {
  seen <- mock_answers(function(q) {
    if (length(seen$queries) == 1L) "127.0.0.1" else "10.9.9.9"
  })
  b <- ssrf_prepare_hop(
    "http://once.invalid:1/",
    loopback_policy(1),
    request = list()
  )
  expect_identical(b$validated, "127.0.0.1")
  r <- ssrf_fetch(b)
  # Port 1 answers nothing; what matters is who was asked, and what was dialed.
  expect_s3_class(r, "ssrfr_failure")
  expect_length(seen$queries, 1L)
  expect_identical(b$state$attempts, "127.0.0.1 connect-failed")
})

# The fields of a binding's state (§2.3).
state_fields <- c(
  "fetchable",
  "fetched",
  "status",
  "location",
  "location_count",
  "outcome",
  "pin_used",
  "attempts",
  "elapsed"
)

# §2.4: a caller cannot write a binding's state, fetchable or spent, while
# ssrf_fetch() records what it observed there.
test_that("a caller cannot write the binding's state, but a fetch does", {
  skip_if_no_webfakes()
  web <- local_test_server()
  port <- web$get_port()
  mock_answers("127.0.0.1")
  b <- ssrf_prepare_hop(
    pinned_url(port),
    loopback_policy(port),
    request = list()
  )
  expect_error(b$state$fetchable <- FALSE)
  expect_error(assign("fetchable", FALSE, envir = b$state))
  expect_error(b$state$status <- 204L)
  expect_error(assign("status", 204L, envir = b$state))
  expect_error(b$state$extra <- 1L)
  expect_error(assign("extra", 1L, envir = b$state))
  expect_error(b$state <- new.env())
  expect_true(b$state$fetchable)
  expect_null(b$state$status)
  expect_setequal(ls(b$state, all.names = TRUE), state_fields)

  r <- ssrf_fetch(b)
  expect_s3_class(r, "ssrfr_response")
  expect_false(b$state$fetchable)
  expect_true(b$state$fetched)
  expect_identical(b$state$status, 200L)
  expect_identical(b$state$outcome, "response")
  expect_identical(b$state$pin_used, "127.0.0.1")
  expect_identical(b$state$attempts, "127.0.0.1 connected")
  expect_identical(b$state$location_count, 0L)
  expect_null(b$state$location)

  # A spent binding resists the same writes.
  expect_error(b$state$fetchable <- TRUE)
  expect_error(assign("fetchable", TRUE, envir = b$state))
  expect_error(b$state$status <- 204L)
  expect_error(assign("extra", 1L, envir = b$state))
  expect_false(b$state$fetchable)
  expect_identical(b$state$status, 200L)
  expect_setequal(ls(b$state, all.names = TRUE), state_fields)
})

# §2.4: state is locked once and never unlocked. Each field is a read-only
# active binding over a private store, which only set_state() writes.
test_that("binding state is read-only fields over a store set_state() writes", {
  mock_answers("127.0.0.1")
  b <- ssrf_prepare_hop(
    "http://state.invalid:1/",
    loopback_policy(1),
    request = list()
  )
  expect_setequal(ls(b$state, all.names = TRUE), state_fields)
  expect_true(environmentIsLocked(b$state))
  every <- stats::setNames(rep(TRUE, length(state_fields)), state_fields)
  expect_identical(
    vapply(state_fields, bindingIsActive, logical(1), env = b$state),
    every
  )
  expect_identical(
    vapply(state_fields, bindingIsLocked, logical(1), env = b$state),
    every
  )

  set <- set_state
  set(b, status = 302L, location = "/next", location_count = 1L)
  expect_identical(b$state$status, 302L)
  expect_identical(b$state$location, "/next")
  expect_identical(b$state$location_count, 1L)
  set(b, location = NULL)
  expect_null(b$state$location)
  expect_true(environmentIsLocked(b$state))
  expect_error(b$state$status <- 200L)
  expect_identical(b$state$status, 302L)

  # Only ssrfr calls set_state(): an unknown field is an internal error, and
  # nothing is written.
  expect_error(
    set(b, status = 200L, extra = 1L),
    "internal error",
    class = "ssrfr_error_invalid_argument"
  )
  expect_identical(b$state$status, 302L)
  expect_setequal(ls(b$state, all.names = TRUE), state_fields)
  expect_setequal(ls(parent.env(b$state), all.names = TRUE), state_fields)
})

# r-binding.md §7: a refusal makes no connection (INV-11). The resolver maps
# honeypot.invalid to a loopback listener, which the default policy refuses;
# the listener must see nothing across the whole window. A failing parser,
# resolver or raddr wrapper refuses the same way, and opens nothing.
test_that("a refusal opens no connection, whatever refused it", {
  listener <- local_listener()
  url <- pinned_url(listener$port, host = "honeypot.invalid")
  policy <- ssrf_policy(allow_ports = c(80, 443, listener$port))

  # Positive control: the listener does see a bare TCP connect.
  control <- local_listener()
  h <- curl::new_handle(connect_only = TRUE, timeout = 3)
  curl::curl_fetch_memory(
    paste0("http://127.0.0.1:", control$port, "/"),
    handle = h
  )
  expect_true(connection_arrives(control$socket, 3))

  attempt <- function() {
    r <- ssrf_prepare_hop(url, policy, request = list())
    if (inherits(r, "ssrfr_binding")) ssrf_fetch(r) else r
  }
  mock_answers("127.0.0.1")
  r <- attempt()
  expect_s3_class(r, "ssrfr_refusal")
  expect_identical(r$code, "loopback")

  failure_modes <- list(
    stop = function(...) stop("dependency failed"),
    null = function(...) NULL,
    wrong_shape = function(...) list(unexpected = 42)
  )
  wrappers <- c(
    "dep_rurl_verdicts",
    "dep_rurl_parse",
    "dep_rurl_serialize",
    "dep_rurl_diagnostics",
    "dep_curl_parse",
    "dep_nslookup",
    "dep_raddr_pton",
    "dep_raddr_reachability",
    "dep_raddr_category",
    "dep_raddr_family",
    "dep_raddr_embeddings",
    "dep_raddr_within_any",
    "dep_raddr_format"
  )
  for (wrapper in wrappers) {
    for (mode in names(failure_modes)) {
      label <- paste(wrapper, mode)
      local({
        mock_answers("127.0.0.1")
        do.call(
          local_mocked_bindings,
          stats::setNames(list(failure_modes[[mode]]), wrapper)
        )
        r <- NULL
        expect_no_error(r <- attempt())
        expect_true(
          inherits(r, c("ssrfr_refusal", "ssrfr_failure")),
          label = label
        )
      })
    }
  }
  expect_false(connection_arrives(listener$socket, 2))
})
