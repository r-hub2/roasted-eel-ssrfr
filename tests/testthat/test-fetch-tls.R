# TLS through the pin, the IPv6 pin, ordinary HTTP, and what a result owns
# and shows (ssrfr-v1.md §2.2, §2.3, INV-6, INV-9, INV-12; r-binding.md
# §4.4, §7). The TLS fixtures in certs/ name `.invalid` hosts only and carry
# no IP SAN; make-certs.sh regenerates them.

test_that("certificate verification stays bound to the hostname over TLS", {
  skip_if_no_webfakes()
  tls <- local_test_server(tls = TRUE)
  tport <- tls$get_port()
  mock_answers("127.0.0.1")
  policy <- loopback_policy(tport)
  alpha <- pinned_url(tport, scheme = "https", host = "alpha.example.invalid")
  beta <- pinned_url(tport, scheme = "https", host = "beta.example.invalid")
  # Without the test CA the chain is untrusted: nothing weakened verification.
  r <- guarded_get(alpha, policy)
  expect_identical(r$cause, "tls-failed")
  expect_identical(r$detail$step, 10L)
  local_trust_test_ca()
  r <- guarded_get(alpha, policy)
  expect_identical(r$status, 200L)
  expect_identical(body_text(r), paste0("host=alpha.example.invalid:", tport))
  # The pin moves only the TCP peer: the same address under another name
  # fails verification, and so does the address itself as the URL host.
  expect_identical(guarded_get(beta, policy)$cause, "tls-failed")
  ip <- guarded_get(paste0("https://127.0.0.1:", tport, "/"), policy)
  expect_identical(ip$cause, "tls-failed")
})

# r-binding.md §7, "Proving SNI": two virtual hosts on one socket. Only SNI
# can select beta's certificate, so receiving it through a pin proves the
# hostname travelled in the handshake; the server holding alpha alone is the
# control.
test_that("SNI carries the hostname through the pin", {
  skip_on_cran()
  openssl <- Sys.which("openssl")
  skip_if(!nzchar(openssl), "the openssl command-line tool is not installed")
  skip_if_not_installed("processx")
  skip_if_not_installed("withr")
  cert <- function(x) test_path("certs", x)
  serve <- function(two) {
    port <- free_port()
    args <- c(
      "s_server",
      "-accept",
      port,
      "-quiet",
      "-www",
      "-cert",
      cert("alpha.crt"),
      "-key",
      cert("alpha.key")
    )
    if (two) {
      args <- c(
        args,
        "-servername",
        "beta.example.invalid",
        "-cert2",
        cert("beta.crt"),
        "-key2",
        cert("beta.key")
      )
    }
    p <- processx::process$new(openssl, args, stdout = "|", stderr = "|")
    t0 <- Sys.time()
    repeat {
      up <- tryCatch(
        {
          curl::curl_fetch_memory(
            paste0("http://127.0.0.1:", port, "/"),
            handle = curl::new_handle(connect_only = TRUE, timeout = 1)
          )
          TRUE
        },
        error = function(e) FALSE
      )
      waited <- difftime(Sys.time(), t0, units = "secs")
      if (up || !p$is_alive() || waited > 10) {
        break
      }
      Sys.sleep(0.1)
    }
    list(process = p, port = port)
  }
  subject_of <- function(host, port) {
    trace <- local_trace_recorder()
    r <- guarded_get(
      pinned_url(port, scheme = "https", host = host),
      loopback_policy(port)
    )
    subject <- grep("subject: ", trace$lines, value = TRUE, fixed = TRUE)
    list(result = r, subject = sub("^.*subject: *", "", subject))
  }
  local_trust_test_ca()
  mock_answers("127.0.0.1")

  both <- serve(TRUE)
  withr::defer(both$process$kill())
  expect_true(both$process$is_alive())
  a <- subject_of("alpha.example.invalid", both$port)
  expect_identical(a$result$status, 200L)
  expect_match(a$subject[[1L]], "CN *= *alpha.example.invalid")
  b <- subject_of("beta.example.invalid", both$port)
  expect_identical(b$result$status, 200L)
  expect_match(b$subject[[1L]], "CN *= *beta.example.invalid")
  both$process$kill()

  alpha_only <- serve(FALSE)
  withr::defer(alpha_only$process$kill())
  control <- subject_of("beta.example.invalid", alpha_only$port)
  expect_identical(control$result$cause, "tls-failed")
})

# r-binding.md §4.4, §7: the bracketed IPv6 pin, against httpuv on ::1
# (webfakes cannot bind ::1). The server runs in a subprocess so this one can
# fetch.
test_that("an IPv6 address is pinned, bracketed, with Host kept", {
  skip_if_not_installed("httpuv")
  skip_if_not_installed("callr")
  skip_if_not_installed("withr")
  skip_if_not(isTRUE(curl::curl_version()$ipv6), "libcurl has no IPv6")
  port <- free_port()
  server <- callr::r_bg(
    function(port) {
      httpuv::startServer(
        "::1",
        port,
        list(call = function(req) {
          list(
            status = 200L,
            headers = list("Content-Type" = "text/plain"),
            body = paste0("host=", req$HTTP_HOST)
          )
        })
      )
      repeat {
        httpuv::service(100)
      }
    },
    args = list(port = port)
  )
  withr::defer(server$kill())
  t0 <- Sys.time()
  repeat {
    up <- tryCatch(
      {
        curl::curl_fetch_memory(
          paste0("http://[::1]:", port, "/"),
          handle = curl::new_handle(timeout = 1)
        )
        TRUE
      },
      error = function(e) FALSE
    )
    waited <- difftime(Sys.time(), t0, units = "secs")
    if (up || !server$is_alive() || waited > 15) {
      break
    }
    Sys.sleep(0.1)
  }
  skip_if_not(up, "could not serve on ::1")
  mock_answers("::1")
  trace <- local_trace_recorder()
  r <- guarded_get(
    pinned_url(port, host = "v6pin.invalid"),
    loopback_policy(port)
  )
  expect_identical(r$status, 200L)
  expect_identical(body_text(r), paste0("host=v6pin.invalid:", port))
  b <- attr(r, "binding")
  expect_identical(b$state$attempts, "::1 connected")
  expect_match(grep("^Trying ", trace$lines, value = TRUE)[[1L]], "::1\\]?:")
})

test_that("ordinary HTTP still works through the guard", {
  skip_if_no_webfakes()
  web <- local_app_server(
    webfakes::httpbin_app(),
    opts = webfakes::server_opts(num_threads = 2)
  )
  port <- web$get_port()
  mock_answers("127.0.0.1")
  policy <- loopback_policy(port, user_agent = "ssrfr-test/1.0")
  host <- "httpbin.invalid"
  get <- function(path, request = list()) {
    guarded_get(pinned_url(port, path, host = host), policy, request)
  }

  r <- get("/get?a=1", list(headers = c(`X-Test` = "yes")))
  expect_identical(r$status, 200L)
  expect_match(body_text(r), "\"X-Test\": *\"yes\"")
  expect_match(body_text(r), paste0("\"Host\": *\"", host, ":", port, "\""))
  expect_match(body_text(r), "\"User-Agent\": *\"ssrfr-test/1.0\"")

  for (method in c("POST", "PUT", "PATCH", "DELETE")) {
    r <- get(
      paste0("/", ascii_lower(method)),
      list(
        method = method,
        headers = c(`Content-Type` = "application/json"),
        body = "{\"n\":42}"
      )
    )
    expect_identical(r$status, 200L, label = method)
    expect_match(body_text(r), "\"n\": *42", label = method)
  }
  r <- get("/get", list(method = "HEAD"))
  expect_identical(r$status, 200L)
  expect_length(r$body, 0L)

  # A gzip body comes from the package's own app: httpbin's is written
  # through gzcon(), whose output is broken on Windows under R-devel
  # (r-binding.md §7, Harness notes).
  gz <- local_test_server()
  gport <- gz$get_port()
  gzipped <- guarded_get(
    pinned_url(gport, "/gzip", host = host),
    loopback_policy(gport)
  )
  expect_identical(gzipped$status, 200L)
  expect_match(body_text(gzipped), "\"gzipped\": *true")
  expect_identical(get("/status/404")$status, 404L)
  expect_identical(get("/status/500")$status, 500L)
  r <- get("/redirect/2")
  expect_identical(r$status, 302L)
  expect_identical(attr(r, "binding")$state$location, "/redirect/1")
})

test_that("a response is a plain value that owns nothing and prints no body", {
  skip_if_no_webfakes()
  web <- local_test_server()
  port <- web$get_port()
  mock_answers("127.0.0.1")
  r <- guarded_get(pinned_url(port), loopback_policy(port))
  attr(r, "binding") <- NULL
  owns <- function(x) {
    if (is.environment(x) || typeof(x) %in% c("externalptr", "closure")) {
      return(TRUE)
    }
    if (inherits(x, "connection")) {
      return(TRUE)
    }
    is.list(x) && any(vapply(x, owns, logical(1L)))
  }
  expect_false(owns(r))
  expect_named(r, c("status", "headers", "body"))
  expect_type(r$body, "raw")
  shown <- paste(format(r), collapse = "\n")
  expect_match(shown, "status: 200")
  expect_match(shown, "type: text/plain")
  expect_match(shown, "body: [0-9]+ bytes")
  expect_false(grepl("host=", shown, fixed = TRUE))
  expect_identical(capture.output(print(r)), format(r))
})

# INV-12, §2.3: planted userinfo, header values, a body and a proxy value
# appear in no print, format or condition message, before or after a fetch,
# on a response or on a failure.
test_that("planted secrets appear in no binding, result or condition", {
  skip_if_no_webfakes()
  skip_if_not_installed("withr")
  web <- local_test_server()
  port <- web$get_port()
  mock_answers("127.0.0.1")
  policy <- loopback_policy(c(port, 1), allow_userinfo = TRUE)
  secrets <- c(
    "pl4nted-pass",
    "pl4nted-header",
    "pl4nted-token",
    "pl4nted-body",
    "pl4nted-proxy"
  )
  request <- list(
    method = "POST",
    headers = c(
      `X-Secret` = "pl4nted-header",
      Authorization = "Bearer pl4nted-token"
    ),
    body = "pl4nted-body"
  )
  proxy <- "http://pl4nted-proxy.invalid:1"
  withr::local_envvar(c(http_proxy = proxy, ALL_PROXY = proxy))
  leaks <- function(x) {
    text <- if (is.character(x)) x else c(format(x), capture.output(print(x)))
    text <- paste(text, collapse = "\n")
    secrets[vapply(secrets, grepl, logical(1L), x = text, fixed = TRUE)]
  }
  url <- paste0("http://user:pl4nted-pass@", pinned_host, ":", port, "/post")
  b <- ssrf_prepare_hop(url, policy, request = request)
  expect_s3_class(b, "ssrfr_binding")
  expect_identical(leaks(b), character())
  r <- ssrf_fetch(b)
  expect_identical(r$status, 200L)
  expect_identical(leaks(b), character())
  expect_identical(leaks(r), character())

  closed <- paste0("http://user:pl4nted-pass@", pinned_host, ":1/post")
  f <- guarded_get(closed, policy, request)
  expect_s3_class(f, "ssrfr_failure")
  expect_identical(leaks(f), character())
  expect_identical(leaks(attr(f, "binding")), character())

  # Conditions: a refused plan and a spent binding.
  bad <- list(headers = c(`X-A` = "pl4nted-header\r\nX-B: pl4nted-body"))
  err <- expect_error(
    ssrf_prepare_hop(url, policy, request = bad),
    class = "ssrfr_error_invalid_request"
  )
  expect_identical(leaks(conditionMessage(err)), character())
  expect_identical(leaks(capture.output(print(err))), character())
  err <- expect_error(ssrf_fetch(b), class = "ssrfr_error_spent_binding")
  expect_identical(leaks(conditionMessage(err)), character())
  # The full record is still there for the operator.
  expect_identical(b$request$headers[["X-Secret"]], "pl4nted-header")
})
