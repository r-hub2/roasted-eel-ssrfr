# Windows https diagnosis behind fp SSRF-nfizdzxt: why every https fetch of
# ssrfr's own test suite failed on Windows
# (2026-09-29-windows-testthat-output.txt), and whether the corpus files
# arrive with CR bytes. R-hub runs custom code only through R CMD check, so
# this file is placed, in a scratch copy of the package that is never
# committed, at tests/testthat/test-zz-windows-https-probe.R, where the
# suite's helpers are loaded. It is submitted with
#   rhub::rc_submit(path = <tarball>, platforms = "windows", confirmation = TRUE)
# and its output lands in testthat.Rout. Not for the package's own suite.
#
# Part 1 prints the corpus and certificate fixtures as the check sees them:
# size, MD5, and the count of CR bytes. Part 2 fetches the TLS test server
# through the guard with the test CA trusted, as test-fetch-tls.R does, and
# prints the outcome and libcurl's trace. Part 3 fetches the same server with
# a bare curl handle carrying the same pin and CA, under each ssl_options
# value, and prints curl's error message. Part 4 repeats part 3 in a
# subprocess with CURL_SSL_BACKEND=openssl set before curl loads.

cr_count <- function(path) {
  bytes <- readBin(path, "raw", file.size(path))
  sum(bytes == as.raw(13L))
}

bare_fetch <- function(url, host, port, ca, ssl_options) {
  trace <- character()
  opts <- list(
    connect_to = paste0(host, "::127.0.0.1:"),
    cainfo = ca,
    noproxy = "*",
    connecttimeout = 5L,
    timeout = 10L,
    verbose = TRUE,
    debugfunction = function(type, msg) {
      if (type == 0L) {
        trace <<- c(trace, trimws(rawToChar(msg)))
      }
      NULL
    }
  )
  if (!is.na(ssl_options)) {
    opts$ssl_options <- ssl_options
  }
  handle <- do.call(curl::new_handle, opts)
  out <- tryCatch(
    paste("status", curl::curl_fetch_memory(url, handle = handle)$status_code),
    error = function(e) {
      paste0("error [", class(e)[[1L]], "]: ", conditionMessage(e))
    }
  )
  list(out = out, trace = trace)
}

bare_rows <- function(url, host, port, ca) {
  for (so in c(NA, 0L, 2L, 8L)) {
    label <- if (is.na(so)) "default" else paste("ssl_options =", so)
    r <- bare_fetch(url, host, port, ca, so)
    cat(sprintf("%-18s %s\n", label, r$out))
    if (!startsWith(r$out, "status 200")) {
      cat(paste0("        | ", r$trace, collapse = "\n"), "\n")
    }
  }
}

test_that("windows https probe prints its output", {
  cat("\n\n######## BEGIN PROBE: windows https ########\n")
  cat("curl", as.character(utils::packageVersion("curl")), "| libcurl",
      curl::curl_version()$version, "| ssl:", curl::curl_version()$ssl_version,
      "| CURL_SSL_BACKEND:", shQuote(Sys.getenv("CURL_SSL_BACKEND")),
      "| CURL_CA_BUNDLE:", shQuote(Sys.getenv("CURL_CA_BUNDLE")), "\n")

  cat("\n## 1. fixtures as the check sees them\n")
  files <- c(
    file.path("fixtures", c("verdict-vectors.tsv", "parse-vectors.tsv",
                            "requirements.tsv", "corpus-manifest.tsv")),
    file.path("certs", c("ca.crt", "alpha.pem"))
  )
  for (f in files) {
    p <- test_path(f)
    cat(sprintf("%-32s %8d bytes  md5 %s  CR bytes %d\n", f, file.size(p),
                unname(tools::md5sum(p)), cr_count(p)))
  }

  cat("\n## 2. through the guard, test CA trusted (test-fetch-tls.R)\n")
  tls <- local_test_server(tls = TRUE)
  tport <- tls$get_port()
  mock_answers("127.0.0.1")
  policy <- loopback_policy(tport)
  host <- "alpha.example.invalid"
  url <- pinned_url(tport, scheme = "https", host = host)
  local({
    local_trust_test_ca()
    seen <- local_trace_recorder()
    r <- guarded_get(url, policy)
    cat("class:", class(r), "| status:", format(r$status), "| cause:",
        format(r$cause), "| code:", format(r$code), "\n")
    cat("detail:\n")
    utils::str(unclass(r$detail))
    cat(paste0("        | ", seen$lines, collapse = "\n"), "\n")
  })

  ca <- normalizePath(test_path("certs", "ca.crt"), winslash = "/")
  cat("\n## 3. bare curl handle, same pin and CA, default backend\n")
  bare_rows(url, host, tport, ca)

  cat("\n## 4. bare curl handle, CURL_SSL_BACKEND=openssl\n")
  # The helpers travel without their enclosing environment.
  fns <- lapply(list(bare_fetch = bare_fetch, bare_rows = bare_rows),
                `environment<-`, value = globalenv())
  callr::r(
    function(url, host, port, ca, fns) {
      list2env(fns, globalenv())
      cat("ssl:", curl::curl_version()$ssl_version, "\n")
      bare_rows(url, host, port, ca)
    },
    args = list(url, host, tport, ca, fns),
    env = c(callr::rcmd_safe_env(), CURL_SSL_BACKEND = "openssl"),
    show = TRUE
  )
  cat("\n######## END PROBE: windows https ########\n\n")
  expect_true(TRUE)
})
