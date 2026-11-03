# L4, the real-network test layer (r-binding.md §7): real DNS, real
# certificate chains, IPv6 pinning and live rebinding against public hosts
# (INV-4, INV-5, INV-9). Every test here runs only when the environment
# variable SSRFR_INTEGRATION_TESTS is set, and never on CRAN or offline.
#
# This file is in .fleet-ci.yml's exclude_tests, so the gate, which fails on
# any skip, never runs it: CI never makes these requests. Run it locally with
#   SSRFR_INTEGRATION_TESTS=true \
#     Rscript -e "testthat::test_local(filter = 'integration')"
#
# Each test makes a few requests with generous timeouts. The hosts are public
# test infrastructure needing no credentials: example.com, badssl.com,
# ipv6.google.com, the 1u.ms rebinding service, and the DNS-over-HTTPS
# endpoints of 1.1.1.1 and 8.8.8.8.

# Skips unless SSRFR_INTEGRATION_TESTS is `true` (as.logical() reads it), on
# CRAN, and offline.
skip_unless_integration <- function() {
  skip_if(
    !isTRUE(as.logical(Sys.getenv("SSRFR_INTEGRATION_TESTS"))),
    "SSRFR_INTEGRATION_TESTS not set to true"
  )
  skip_on_cran()
  skip_if_offline()
}

# A policy for the public internet: the defaults, with room for a slow link.
integration_policy <- function(connect_timeout = 10, ...) {
  ssrf_policy(connect_timeout = connect_timeout, total_timeout = 30, ...)
}

# The real resolver behind the internal seam, counting its calls: the guard
# still resolves through the system resolver, and the test sees each query.
local_counting_resolver <- function(env = parent.frame()) {
  real <- dep_nslookup
  seen <- new.env(parent = emptyenv())
  seen$queries <- character()
  local_mocked_bindings(
    dep_nslookup = function(query) {
      seen$queries <- c(seen$queries, query)
      real(query)
    },
    .package = "ssrfr",
    .env = env
  )
  seen
}

# The address and port of every `Trying` line libcurl traced, brackets
# removed: what the transport dialed, read independently of ssrfr's own
# pin check.
dialed <- function(lines) {
  trying <- grep("^Trying ", lines, value = TRUE)
  target <- sub("^Trying (.*)[.]{3}$", "\\1", trying)
  data.frame(
    address = gsub("^\\[|\\]$", "", sub(":[0-9]+$", "", target)),
    port = as.integer(sub("^.*:", "", target))
  )
}

global <- function(addresses) {
  raddr::addr_global_reachability(raddr::addr_pton(addresses))
}

# Whether this machine can open a TCP connection over IPv6 to a public
# anycast resolver, by address, so no DNS is involved.
ipv6_route <- function() {
  for (host in c("[2606:4700:4700::1111]", "[2001:4860:4860::8888]")) {
    handle <- curl::new_handle(
      connect_only = 1L,
      connecttimeout = 5L,
      noproxy = "*"
    )
    connected <- tryCatch(
      {
        curl::curl_fetch_memory(paste0("http://", host, "/"), handle = handle)
        TRUE
      },
      error = function(e) FALSE
    )
    if (connected) {
      return(TRUE)
    }
  }
  FALSE
}

# The A records a public resolver returns for `name`, asked over
# DNS-over-HTTPS (the JSON form) at an address, so the system resolver plays
# no part. An HTTP or transport failure is an error, never an empty answer.
doh_answers <- function(name, endpoint) {
  handle <- curl::new_handle(timeout = 15L, noproxy = "*")
  curl::handle_setheaders(handle, Accept = "application/dns-json")
  r <- curl::curl_fetch_memory(
    paste0(endpoint, "?type=A&name=", name),
    handle = handle
  )
  if (r$status_code != 200L) {
    stop("DNS-over-HTTPS at ", endpoint, " answered ", r$status_code)
  }
  text <- rawToChar(r$content)
  data <- "\"data\": *\"([0-9]{1,3}([.][0-9]{1,3}){3})\""
  found <- regmatches(text, gregexpr(data, text))[[1L]]
  sub(paste0("^", data, "$"), "\\1", found)
}

doh_endpoints <- c("https://1.1.1.1/dns-query", "https://8.8.8.8/resolve")

test_that("real DNS: one resolution, global addresses, the fetch on the pin", {
  skip_unless_integration()
  resolver <- local_counting_resolver()
  trace <- local_trace_recorder()
  b <- ssrf_prepare_hop(
    "https://example.com/",
    integration_policy(),
    request = list()
  )
  expect_s3_class(b, "ssrfr_binding")
  # INV-5: one resolution, absolute, so no search domain applies.
  expect_identical(resolver$queries, "example.com.")
  expect_gt(length(b$validated), 0L)
  expect_true(all(global(b$validated)))
  expect_identical(b$pin, b$validated[[1L]])

  r <- ssrf_fetch(b)
  expect_s3_class(r, "ssrfr_response")
  expect_identical(r$status, 200L)
  # The fetch resolves nothing more. It may fail over in resolver order
  # (§2.5), say past an AAAA with no route, but every address libcurl dialed
  # is a validated one, and the last attempt connected.
  expect_identical(resolver$queries, "example.com.")
  expect_true(b$state$pin_used %in% b$validated)
  attempts <- b$state$attempts
  expect_identical(
    attempts[[length(attempts)]],
    paste(b$state$pin_used, "connected")
  )
  tried <- dialed(trace$lines)
  expect_gt(nrow(tried), 0L)
  expect_true(all(tried$address %in% b$validated))
  expect_identical(unique(tried$port), 443L)
})

# INV-4 through the system resolver: `localhost` answers ::1 and 127.0.0.1
# from the hosts file on macOS and most Linux systems; where the platform does
# not answer the absolute `localhost.` (some nss_files builds, Windows), the
# test skips rather than testing the resolver. Public wildcard names that answer
# 127.0.0.1 (nip.io, localtest.me) are not used: rebinding-protected
# resolvers (NextDNS, dnsmasq's stop-dns-rebind, Pi-hole) answer them with
# nothing, which would test the resolver, not the guard.
test_that("real DNS: a name with a loopback address refuses, never connects", {
  skip_unless_integration()
  skip_if_not_installed("withr")
  local_answers <- tryCatch(
    dep_nslookup("localhost."),
    error = function(e) character()
  )
  skip_if(
    length(local_answers) == 0L,
    "this platform's resolver does not answer localhost."
  )
  resolver <- local_counting_resolver()
  honeypot <- local_listener()
  policy <- integration_policy(allow_ports = c(80, 443, honeypot$port))
  r <- ssrf_prepare_hop(
    paste0("http://localhost:", honeypot$port, "/"),
    policy,
    request = list()
  )
  expect_s3_class(r, "ssrfr_refusal")
  expect_identical(r$code, "loopback")
  expect_identical(r$detail$step, 8L)
  expect_identical(r$host, "localhost")
  expect_false(global(r$address))
  expect_identical(resolver$queries, "localhost.")
  # A guard that admitted the set would be fetched, as an application does.
  if (inherits(r, "ssrfr_binding")) {
    ssrf_fetch(r)
  }
  expect_false(connection_arrives(honeypot$socket, 2))
})

# INV-9 against real chains. ssrfr sets no CA bundle, so the platform's trust
# store decides; verification is bound to the URL's hostname through the pin.
test_that("TLS: a real valid chain verifies; verification is not weakened", {
  skip_unless_integration()
  builder <- transport_options
  seen <- new.env(parent = emptyenv())
  seen$opts <- list()
  local_mocked_bindings(
    transport_options = function(...) {
      opts <- builder(...)
      seen$opts <- c(seen$opts, list(opts))
      opts
    },
    .package = "ssrfr"
  )
  trace <- local_trace_recorder()
  r <- guarded_get("https://badssl.com/", integration_policy())
  expect_s3_class(r, "ssrfr_response")
  expect_identical(r$status, 200L)
  b <- attr(r, "binding")
  expect_identical(
    b$tls,
    list(verify_peer = TRUE, verify_host = TRUE, name = "badssl.com")
  )
  expect_length(seen$opts, 1L)
  opts <- seen$opts[[1L]]
  # Every row of r-binding.md §5 on the attempt that went to the network:
  # ssl_verifypeer 1, ssl_verifyhost 2, the pin, and nothing that weakens or
  # replaces the trust store.
  expect_identical(option_problems(opts, "badssl.com", b$pin), character())
  expect_identical(
    intersect(names(opts), c("cainfo", "capath", "ssl_options")),
    character()
  )
  expect_identical(unique(dialed(trace$lines)$address), b$pin)
})

# The badssl.com hosts all live at one address and pick a certificate by SNI.
# Their names are answered with badssl.com's own address, resolved for real
# first, so a resolver that refuses to resolve them (NextDNS's
# untrusted-certs category blocks self-signed and untrusted-root) cannot turn
# the test into one of DNS. The control, badssl.com at the same pin, shows
# each failure is the chain's.
test_that("TLS: real bad chains refuse as tls-failed at the pinned address", {
  skip_unless_integration()
  good <- ssrf_prepare_hop(
    "https://badssl.com/",
    integration_policy(),
    request = list()
  )
  expect_s3_class(good, "ssrfr_binding")
  address <- good$validated
  expect_true(all(global(address)))
  resolver <- mock_answers(address)
  control <- guarded_get("https://badssl.com/", integration_policy())
  expect_identical(control$status, 200L)
  bad <- c(
    "expired.badssl.com",
    "wrong.host.badssl.com",
    "self-signed.badssl.com",
    "untrusted-root.badssl.com"
  )
  for (host in bad) {
    r <- guarded_get(paste0("https://", host, "/"), integration_policy())
    expect_s3_class(r, "ssrfr_failure")
    expect_identical(r$cause, "tls-failed", label = host)
    expect_identical(r$detail$step, 10L, label = host)
    expect_identical(r$detail$check, "transport", label = host)
    b <- attr(r, "binding")
    expect_identical(b$tls$name, host)
    expect_identical(b$state$pin_used, address[[1L]], label = host)
    expect_null(b$state$status)
  }
  expect_identical(resolver$queries, paste0(c("badssl.com", bad), "."))
})

# IPv6 pinning against a real host: ipv6.google.com publishes AAAA records
# only, so every validated address, and the pin, is IPv6.
test_that("IPv6: a real AAAA-only name is pinned and dialed over IPv6", {
  skip_unless_integration()
  skip_if_not(isTRUE(curl::curl_version()$ipv6), "libcurl has no IPv6")
  skip_if_not(ipv6_route(), "no IPv6 route from this machine")
  resolver <- local_counting_resolver()
  trace <- local_trace_recorder()
  r <- guarded_get("https://ipv6.google.com/", integration_policy())
  expect_s3_class(r, "ssrfr_response")
  expect_gte(r$status, 200L)
  expect_lt(r$status, 400L)
  b <- attr(r, "binding")
  expect_identical(resolver$queries, "ipv6.google.com.")
  expect_true(all(grepl(":", b$validated, fixed = TRUE)))
  expect_true(all(global(b$validated)))
  expect_identical(b$state$pin_used, b$pin)
  tried <- dialed(trace$lines)
  expect_identical(unique(tried$address), b$pin)
  expect_identical(unique(tried$port), 443L)
})

# INV-5 against a live rebinding service. 1u.ms answers
# make-<A>-rebind-127.0.0.1-rr.1u.ms with A or 127.0.0.1 in turn, as each
# query reaches it, with TTL 0. The answers reach the guard through its
# internal resolver seam, asked of 1.1.1.1 and 8.8.8.8 in turn over
# DNS-over-HTTPS: a rebinding-protected system resolver answers the name with
# nothing (NextDNS blocks 1u.ms). Over these two the answers have alternated
# in practice, but resolver caches and retries move the service's counter, so
# the test hops until it has seen both outcomes, up to ten hops.
# A is example.com's real address; the URL's port is a loopback honeypot's,
# where nothing on the public side listens. Each hop resolves once: a
# loopback answer refuses, a public one is pinned, and the fetch dials only
# the pin even after the name has rebound to 127.0.0.1. The honeypot must see
# no connection.
test_that("live rebinding: one resolution per hop, never a loopback dial", {
  skip_unless_integration()
  skip_if_not_installed("withr")
  public <- ssrf_prepare_hop(
    "https://example.com/",
    integration_policy(),
    request = list()
  )
  expect_s3_class(public, "ssrfr_binding")
  v4 <- grep(":", public$validated, fixed = TRUE, value = TRUE, invert = TRUE)
  expect_gt(length(v4), 0L)
  target <- v4[[1L]]
  name <- paste0("make-", target, "-rebind-127.0.0.1-rr.1u.ms")

  seen <- new.env(parent = emptyenv())
  seen$queries <- character()
  seen$answers <- list()
  seen$endpoints <- character()
  seen$errors <- character()
  local_mocked_bindings(
    dep_nslookup = function(query) {
      endpoint <- doh_endpoints[[length(seen$queries) %% 2L + 1L]]
      # Recorded before the query, so a DNS-over-HTTPS failure is reported
      # as one, not as a guard refusal.
      seen$queries <- c(seen$queries, query)
      seen$endpoints <- c(seen$endpoints, endpoint)
      result <- tryCatch(
        list(answers = doh_answers(query, endpoint), error = ""),
        error = function(e) {
          list(answers = character(), error = conditionMessage(e))
        }
      )
      seen$errors <- c(seen$errors, result$error)
      seen$answers <- c(seen$answers, list(result$answers))
      result$answers
    },
    .package = "ssrfr"
  )
  trace <- local_trace_recorder()
  honeypot <- local_listener()
  policy <- integration_policy(
    connect_timeout = 3,
    allow_ports = c(80, 443, honeypot$port)
  )
  url <- paste0("http://", name, ":", honeypot$port, "/")
  outcomes <- character()
  for (i in 1:10) {
    if (all(c("refused", "pinned") %in% outcomes)) {
      break
    }
    asked <- length(seen$queries)
    b <- ssrf_prepare_hop(url, policy, request = list())
    expect_length(seen$queries, asked + 1L)
    answer <- seen$answers[[asked + 1L]]
    if (length(answer) == 0L) {
      fail(paste0(
        "no DNS-over-HTTPS answer from ",
        seen$endpoints[[asked + 1L]],
        if (nzchar(seen$errors[[asked + 1L]])) ": ",
        seen$errors[[asked + 1L]]
      ))
      break
    }
    if (identical(answer, "127.0.0.1")) {
      # A guard that admitted the answer would be fetched, as an
      # application does.
      if (inherits(b, "ssrfr_binding")) {
        ssrf_fetch(b)
      }
      expect_s3_class(b, "ssrfr_refusal")
      expect_identical(b$code, "loopback")
      expect_identical(b$detail$step, 8L)
      outcomes <- c(outcomes, "refused")
      next
    }
    expect_identical(answer, target)
    expect_s3_class(b, "ssrfr_binding")
    expect_identical(b$validated, target)
    # The name has rebound before the fetch: the service now answers
    # 127.0.0.1 to the next resolver that asks.
    rebound <- character()
    for (endpoint in rep(rev(doh_endpoints), 2L)) {
      rebound <- tryCatch(
        doh_answers(paste0(name, "."), endpoint),
        error = function(e) character()
      )
      if (identical(rebound, "127.0.0.1")) {
        break
      }
    }
    expect_identical(rebound, "127.0.0.1")
    trace$lines <- character()
    ssrf_fetch(b)
    expect_length(seen$queries, asked + 1L)
    tried <- dialed(trace$lines)
    expect_gt(nrow(tried), 0L)
    expect_identical(unique(tried$address), target)
    expect_identical(sub(" .*$", "", b$state$attempts), target)
    outcomes <- c(outcomes, "pinned")
  }
  # The service rebound across hops, so both branches ran.
  expect_setequal(unique(outcomes), c("refused", "pinned"))
  expect_false(connection_arrives(honeypot$socket, 2))
})
