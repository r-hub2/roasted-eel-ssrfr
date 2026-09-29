# The loop helper (ssrfr-v1.md §2.2 "The loop helper", §2.3, §2.6, §8 item
# 25): ssrf_fetch_chain() follows a redirect chain through the public
# primitives, as a caller's loop would, and returns what the chain's last
# call returned. The servers, the resolver mock and the test policy are
# helper-redirect.R's and helper-transport.R's; the chain tests below are
# test-redirect.R's, run through the helper instead of a hand loop.

# --- built on the primitives only ---------------------------------------------

# §2.2: the helper is built only on ssrf_prepare_hop() and ssrf_fetch() and
# takes no argument they do not. Every symbol its body reads, bar its own
# arguments and locals and the field names after `$`, is one of the two
# primitives or base R, and none is an ssrfr internal (a copy of
# `followed_statuses`, say, or a base name ssrfr masks).
test_that("ssrf_fetch_chain() reads nothing but the primitives and base R", {
  # covr instruments a body with calls to its own counter, covr:::count(),
  # built here so the test names no package it does not suggest.
  counter <- call(":::", as.name("covr"), as.name("count"))
  read_symbols <- function(expr) {
    if (is.name(expr)) {
      return(as.character(expr))
    }
    if (!is.call(expr) || identical(expr[[1L]], counter)) {
      return(character())
    }
    parts <- as.list(expr)
    if (identical(parts[[1L]], as.name("$"))) {
      parts <- parts[1:2]
    }
    unique(unlist(lapply(parts, read_symbols)))
  }
  assigned <- function(expr) {
    if (!is.call(expr)) {
      return(character())
    }
    parts <- as.list(expr)
    own <- if (identical(parts[[1L]], as.name("<-")) && is.name(parts[[2L]])) {
      as.character(parts[[2L]])
    }
    unique(c(own, unlist(lapply(parts[-1L], assigned))))
  }
  # The walk sees a symbol wherever it is read, in call position or not.
  expect_contains(
    read_symbols(quote(x$status %in% followed_statuses)),
    "followed_statuses"
  )
  expect_identical(read_symbols(quote(x$status)), c("$", "x"))
  expect_identical(read_symbols(as.call(list(counter, "k"))), character())

  fn <- ssrf_fetch_chain
  expect_named(formals(fn), c("url", "policy", "request"))
  # §2.2: `request` has no default, as a first hop's plan has none.
  expect_identical(formals(fn)$request, quote(expr = ))
  expect_identical(environment(fn), asNamespace("ssrfr"))

  reads <- read_symbols(body(fn))
  free <- setdiff(
    reads[nzchar(reads)],
    c(names(formals(fn)), assigned(body(fn)))
  )
  exports <- getNamespaceExports("ssrfr")
  expect_setequal(intersect(free, exports), c("ssrf_prepare_hop", "ssrf_fetch"))
  rest <- setdiff(free, exports)
  internals <- setdiff(ls(asNamespace("ssrfr"), all.names = TRUE), exports)
  expect_identical(intersect(rest, internals), character())
  on_base <- vapply(
    rest,
    exists,
    logical(1),
    envir = baseenv(),
    inherits = FALSE
  )
  expect_identical(rest[!on_base], character())
})

# The calls the helper makes, recorded through mocked primitives: the first
# hop gets `request`, every later hop `from` and the Location that binding
# recorded, as the same bytes, and every hop the same policy.
test_that("each hop is prepared from the recorded Location, as a loop would", {
  hop <- function(location = NULL, count = 1L) {
    structure(
      list(state = list(location = location, location_count = count)),
      class = "ssrfr_binding"
    )
  }
  response <- function(status) {
    structure(
      list(status = status, headers = character(), body = raw()),
      class = "ssrfr_response"
    )
  }
  # A Location that is not UTF-8: the helper must not re-encode it.
  odd <- "/caf\xe9?q=%zz#f"
  Encoding(odd) <- "latin1"
  b1 <- hop(odd)
  b2 <- hop("https://other.example/final")
  b3 <- hop(count = 0L)
  final <- response(302L)
  log <- new.env(parent = emptyenv())
  log$prepare <- list()
  log$fetch <- list()
  outcomes <- list(
    prepare = list(b1, b2, b3),
    fetch = list(
      response(307L),
      response(301L),
      final
    )
  )
  local_mocked_bindings(
    ssrf_prepare_hop = function(url, policy, request = NULL, from = NULL) {
      n <- length(log$prepare) + 1L
      log$prepare[[n]] <- list(
        url = url,
        policy = policy,
        request = request,
        from = from
      )
      outcomes$prepare[[n]]
    },
    ssrf_fetch = function(binding) {
      n <- length(log$fetch) + 1L
      log$fetch[[n]] <- binding
      outcomes$fetch[[n]]
    }
  )
  policy <- ssrf_policy(max_redirects = 7)
  plan <- list(method = "POST", body = "x")
  out <- ssrf_fetch_chain("https://example.com/start", policy, plan)
  # A 302 without Location is a final response (§2.3), returned as is.
  expect_identical(out, final)
  expect_length(log$prepare, 3L)
  expect_identical(log$fetch, list(b1, b2, b3))
  first <- log$prepare[[1L]]
  expect_identical(first$url, "https://example.com/start")
  expect_identical(first$request, plan)
  expect_null(first$from)
  for (i in 2:3) {
    call <- log$prepare[[i]]
    from <- list(b1, b2)[[i - 1L]]
    expect_identical(call$from, from)
    expect_null(call$request)
    # §2.6: the Location as `from` recorded it, byte for byte.
    expect_identical(charToRaw(call$url), charToRaw(from$state$location))
    expect_identical(Encoding(call$url), Encoding(from$state$location))
  }
  for (call in log$prepare) {
    expect_identical(call$policy, policy)
  }

  # `request` has no default, as a first hop's plan has none (§2.2): a call
  # without it prepares nothing. A refused first hop is returned without a
  # fetch.
  log$prepare <- list()
  log$fetch <- list()
  expect_error(ssrf_fetch_chain("http://10.0.0.1/", policy), "request")
  expect_length(log$prepare, 0L)
  refused <- ssrfr:::new_ssrf_refusal("private", 1L)
  outcomes$prepare <- list(refused)
  expect_identical(
    ssrf_fetch_chain("http://10.0.0.1/", policy, request = list()),
    refused
  )
  expect_identical(log$prepare[[1L]]$request, list())
  expect_length(log$fetch, 0L)

  # A fetch that ends in a failure after its binding recorded a followed
  # redirect's status and Location, as when total_timeout runs out after
  # the body is decoded (§5.3), ends the chain: only a response is followed.
  log$prepare <- list()
  log$fetch <- list()
  late <- ssrfr:::new_ssrf_failure("timeout", 1L)
  outcomes$prepare <- list(hop("/next"))
  outcomes$fetch <- list(late)
  expect_identical(
    ssrf_fetch_chain("https://example.com/", policy, request = list()),
    late
  )
  expect_length(log$prepare, 1L)
  expect_length(log$fetch, 1L)
})

# The helper adds no misuse of its own and hides none: ssrf_prepare_hop()'s
# errors reach the caller unchanged.
test_that("misuse errors propagate from ssrf_prepare_hop() unchanged", {
  policy <- ssrf_policy()
  same_error <- function(chain, hop) {
    a <- tryCatch(chain, error = identity)
    b <- tryCatch(hop, error = identity)
    expect_s3_class(a, class(b), exact = TRUE)
    expect_identical(conditionMessage(a), conditionMessage(b))
  }
  same_error(
    ssrf_fetch_chain(1, policy),
    ssrf_prepare_hop(1, policy, request = list())
  )
  same_error(
    ssrf_fetch_chain("http://example.com/", "policy"),
    ssrf_prepare_hop("http://example.com/", "policy", request = list())
  )
  same_error(
    ssrf_fetch_chain("http://example.com/"),
    ssrf_prepare_hop("http://example.com/", request = list())
  )
  same_error(
    ssrf_fetch_chain("http://example.com/", policy, request = NULL),
    ssrf_prepare_hop("http://example.com/", policy, request = NULL)
  )
  expect_error(
    ssrf_fetch_chain(
      "http://example.com/",
      policy,
      request = list(headers = c(Host = "internal.example"))
    ),
    class = "ssrfr_error_invalid_request"
  )
})

# The vignette's ssrf_fetch_chain() chunk is not evaluated (eval = FALSE):
# each call in it is matched against the helper's arguments, so a renamed or
# dropped argument cannot leave it stale.
test_that("the vignette's ssrf_fetch_chain() calls match the helper", {
  source_rmd <- test_path("..", "..", "vignettes", "introduction.Rmd")
  rmd_file <- if (file.exists(source_rmd)) {
    source_rmd
  } else {
    system.file("doc", "introduction.Rmd", package = "ssrfr")
  }
  skip_if_not(file.exists(rmd_file), "the vignette is not installed")
  rmd <- readLines(rmd_file, encoding = "UTF-8")
  ends <- which(rmd == "```")
  code <- unlist(lapply(which(startsWith(rmd, "```{r")), function(opens) {
    rmd[seq(opens + 1L, ends[ends > opens][[1L]] - 1L)]
  }))
  found <- new.env(parent = emptyenv())
  found$calls <- list()
  walk <- function(e) {
    if (is.call(e)) {
      if (identical(e[[1L]], as.name("ssrf_fetch_chain"))) {
        found$calls <- c(found$calls, list(e))
      }
      for (x in as.list(e)) {
        if (!missing(x)) walk(x)
      }
    }
  }
  for (e in parse(text = code, keep.source = FALSE)) {
    walk(e)
  }
  expect_gt(length(found$calls), 0L)
  for (call in found$calls) {
    matched <- match.call(ssrf_fetch_chain, call)
    expect_true(
      all(c("url", "policy", "request") %in% names(matched)),
      label = deparse1(call)
    )
  }
})

# --- chains through a real server ---------------------------------------------

test_that("a redirect chain returns the final response", {
  skip_if_no_webfakes()
  web <- local_redirect_server()
  port <- web$get_port()
  seen <- mock_answers("127.0.0.1")
  policy <- loopback_policy(port)
  r <- ssrf_fetch_chain(
    pinned_url(port, "/r/301?to=/r/308%3Fto%3D/echo"),
    policy,
    request = list()
  )
  expect_s3_class(r, "ssrfr_response")
  expect_identical(r$status, 200L)
  expect_identical(echo_of(r)$method, "GET")
  # INV-5, INV-7: one resolution per hop, three hops.
  expect_identical(seen$queries, rep(paste0(pinned_host, "."), 3L))
  # A relative Location resolved against the previous hop's URL (§3.2):
  # /a/b/c redirects to ../echo, that is /a/echo, which redirects to
  # ../echo again, that is /echo.
  seen$queries <- character()
  r <- ssrf_fetch_chain(
    pinned_url(port, "/a/b/c"),
    policy,
    request = list(headers = c(`X-Corpus-Location` = "../echo?q=1#frag"))
  )
  expect_identical(r$status, 200L)
  expect_identical(body_text(r), "echo")
  expect_length(seen$queries, 3L)
  # The first-hop plan travels the chain: a 307 keeps POST and its body.
  r <- ssrf_fetch_chain(
    pinned_url(port, "/r/307?to=/echo"),
    policy,
    request = list(method = "POST", body = "payload")
  )
  expect_identical(echo_of(r)$method, "POST")
  expect_identical(echo_of(r)$body, "payload")
})

test_that("the redirect budget ends a self-redirect as redirect-limit", {
  skip_if_no_webfakes()
  mock_answers("127.0.0.1")
  for (budget in c(0, 3, 20)) {
    local({
      web <- local_redirect_server()
      port <- web$get_port()
      r <- ssrf_fetch_chain(
        pinned_url(port, "/loop"),
        loopback_policy(port, max_redirects = budget),
        request = list()
      )
      label <- paste("max_redirects =", budget)
      expect_s3_class(r, "ssrfr_refusal")
      expect_identical(r$code, "redirect-limit", label = label)
      # `budget` redirects followed, and the next 3xx refused.
      expect_identical(r$hop, as.integer(budget + 1), label = label)
      expect_identical(r$detail$step, 13L)
      expect_identical(r$detail$limit, "max_redirects")
      # Each hop's request reached the server once.
      expect_identical(
        loop_hits(port),
        as.character(budget + 1),
        label = label
      )
    })
  }
})

test_that("every dimension is revalidated on every hop of the chain", {
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
  targets <- list(
    "http://10.0.0.5/" = "private",
    "http://imds.example.invalid/latest/meta-data/" = "cloud-metadata",
    "ftp://files.example.invalid/" = "scheme",
    "http://other.example.invalid:6379/" = "port",
    "http://denied.example.invalid/" = "host-denied",
    "http://user:pw@other.example.invalid/" = "userinfo",
    "http://0177.0.0.1/" = "numeric-literal"
  )
  for (target in names(targets)) {
    seen$queries <- character()
    to <- utils::URLencode(target, reserved = TRUE)
    second <- utils::URLencode(
      pinned_url(port, paste0("/r/307?to=", to), host = other_host),
      reserved = TRUE,
      repeated = TRUE
    )
    r <- ssrf_fetch_chain(
      pinned_url(port, paste0("/r/302?to=", second)),
      policy,
      request = list()
    )
    expect_s3_class(r, "ssrfr_refusal")
    expect_identical(r$code, targets[[target]], label = target)
    # The third hop was refused: two hops were fetched before it.
    expect_identical(r$hop, 3L, label = target)
    resolved <- c(paste0(pinned_host, "."), paste0(other_host, "."))
    if (identical(target, "http://imds.example.invalid/latest/meta-data/")) {
      resolved <- c(resolved, "imds.example.invalid.")
    }
    expect_identical(seen$queries, resolved, label = target)
  }
})

test_that("an https to http redirect ends the chain as downgrade", {
  skip_if_no_webfakes()
  mock_answers("127.0.0.1")
  tls <- local_redirect_server(tls = TRUE)
  tport <- tls$get_port()
  local_trust_test_ca()
  tpolicy <- loopback_policy(tport)
  r <- ssrf_fetch_chain(
    paste0("https://legit.example:", tport, "/"),
    tpolicy,
    request = list(
      headers = c(`X-Corpus-Location` = paste0("http://legit.example:", tport))
    )
  )
  expect_s3_class(r, "ssrfr_refusal")
  expect_identical(r$code, "downgrade")
  expect_identical(r$hop, 2L)
  expect_identical(r$detail$step, 3L)
})

test_that("a failure on a later hop ends the chain", {
  skip_if_no_webfakes()
  web <- local_redirect_server()
  port <- web$get_port()
  dead <- free_port()
  mock_answers("127.0.0.1")
  to <- utils::URLencode(pinned_url(dead, "/gone"), reserved = TRUE)
  r <- ssrf_fetch_chain(
    pinned_url(port, paste0("/r/302?to=", to)),
    loopback_policy(c(port, dead)),
    request = list()
  )
  expect_s3_class(r, "ssrfr_failure")
  expect_identical(r$cause, "connect-failed")
  expect_identical(r$hop, 2L)
})

# §2.3: while budget remains, a 3xx that is not a followed redirect is
# whatever ssrf_fetch() returned: a final response, or protocol-error for a
# second Location.
test_that("a 3xx that is not a followed redirect is returned as is", {
  skip_if_no_webfakes()
  web <- local_redirect_server()
  port <- web$get_port()
  mock_answers("127.0.0.1")
  policy <- loopback_policy(port, max_redirects = 5)
  finals <- c(
    "/r/304",
    "/r/304?to=/echo",
    "/r/302",
    "/r/300?to=/echo",
    "/r/399?to=/echo"
  )
  for (path in finals) {
    r <- ssrf_fetch_chain(pinned_url(port, path), policy, request = list())
    direct <- guarded_get(pinned_url(port, path), policy)
    expect_s3_class(r, "ssrfr_response")
    expect_identical(r$status, as.integer(substr(path, 4L, 6L)), label = path)
    expect_identical(r$status, direct$status, label = path)
    expect_identical(
      r$headers[names(r$headers) == "location"],
      direct$headers[names(direct$headers) == "location"],
      label = path
    )
  }
  two <- local_raw_server(wire(
    "HTTP/1.1 302 Found\r\nLocation: /a\r\nLocation: /b\r\n",
    "Content-Length: 0\r\nConnection: close\r\n\r\n"
  ))
  r <- ssrf_fetch_chain(
    pinned_url(two$port),
    loopback_policy(two$port, max_redirects = 5),
    request = list()
  )
  expect_s3_class(r, "ssrfr_failure")
  expect_identical(r$cause, "protocol-error")
  expect_identical(r$hop, 1L)
})

# --- INV-8 and the status table through the helper ----------------------------

test_that("credentials are absent after a cross-origin hop in the raw bytes", {
  skip_if_no_webfakes()
  web <- local_redirect_server()
  port <- web$get_port()
  landing <- local_raw_server(wire(
    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
  ))
  mock_answers("127.0.0.1")
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
  r <- ssrf_fetch_chain(
    pinned_url(port, paste0("/r/307?to=", utils::URLencode(to, TRUE))),
    loopback_policy(c(port, landing$port)),
    request
  )
  expect_identical(r$status, 200L)
  text <- rawToChar(landing$request())
  for (s in secrets) {
    expect_false(grepl(s, text, fixed = TRUE), label = s)
  }
  head <- recorded_head(landing)
  expect_identical(head[[1L]], "POST /landing HTTP/1.1")
  expect_setequal(
    tolower(sub(":.*$", "", head[-1L])),
    c("host", "user-agent", "accept-encoding", "content-length", "x-trace")
  )
  expect_true("Content-Length: 0" %in% head)
  expect_true("X-Trace: trace-1" %in% head)
})

test_that("the chain applies the status table on the wire", {
  skip_if_no_webfakes()
  web <- local_redirect_server()
  port <- web$get_port()
  mock_answers("127.0.0.1")
  policy <- loopback_policy(port)
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
        r <- ssrf_fetch_chain(
          pinned_url(port, paste0("/r/", status, "?to=", URLencode(to, TRUE))),
          policy,
          request
        )
        expect_identical(r$status, 200L, label = label)
        echo <- echo_of(r)
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
        want_body <- if (method == "POST" && !body_dropped) "payload" else ""
        expect_identical(echo$body, want_body, label = label)
        fields <- setdiff(
          echo$fields,
          c("host", "user-agent", "accept-encoding", "content-length")
        )
        expect_setequal(
          fields,
          c(if (!cross) secret, "x-trace", if (!body_dropped) content)
        )
      }
    }
  }
})
