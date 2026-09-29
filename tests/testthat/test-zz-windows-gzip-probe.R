# Windows plain-http failure behind fp SSRF-nfizdzxt: "ordinary HTTP still
# works through the guard" (test-fetch-tls.R) fails on Windows at
# `body_text(get("/gzip"))`, a plain-http fetch of webfakes' httpbin app, so
# the guard returned no response (2026-09-29-windows-testthat-output.txt and
# both later R-hub runs). This probe prints what the guard returned for
# /gzip, libcurl's trace, and the same URL fetched by a bare curl handle
# with and without decoding, so the raw bytes show what the server sent.
#
# Placed, in a scratch copy of the package that is never committed, at
# tests/testthat/test-zz-windows-gzip-probe.R, and submitted with
#   rhub::rc_submit(path = <tarball>, platforms = "windows", confirmation = TRUE)
# Not for the package's own suite.

test_that("windows gzip probe prints its output", {
  cat("\n\n######## BEGIN PROBE: windows gzip ########\n")
  cat("curl", as.character(utils::packageVersion("curl")), "| libcurl",
      curl::curl_version()$version, "| ssl:", curl::curl_version()$ssl_version,
      "| zlib:", curl::curl_version()$libz_version, "| webfakes",
      as.character(utils::packageVersion("webfakes")), "\n")
  web <- webfakes::local_app_process(
    webfakes::httpbin_app(),
    opts = webfakes::server_opts(num_threads = 2)
  )
  port <- web$get_port()
  mock_answers("127.0.0.1")
  policy <- loopback_policy(port)
  host <- "httpbin.invalid"

  cat("\n## 1. through the guard\n")
  for (path in c("/gzip", "/deflate", "/get")) {
    local({
      seen <- local_trace_recorder()
      r <- guarded_get(pinned_url(port, path, host = host), policy)
      cat(path, "| class:", class(r), "| status:", format(r$status),
          "| cause:", format(r$cause), "| code:", format(r$code),
          "| body bytes:", length(r$body), "\n")
      if (!inherits(r, "ssrfr_response")) {
        utils::str(unclass(r$detail))
        cat(paste0("        | ", seen$lines, collapse = "\n"), "\n")
      }
    })
  }

  url <- paste0("http://127.0.0.1:", port, "/gzip")
  cat("\n## 2. bare handle, decoding on\n")
  res <- tryCatch(
    curl::curl_fetch_memory(url, handle = curl::new_handle(
      accept_encoding = "gzip, deflate", noproxy = "*"
    )),
    error = function(e) paste0("error [", class(e)[[1L]], "]: ",
                               conditionMessage(e))
  )
  if (is.character(res)) cat(res, "\n") else
    cat("status", res$status_code, "| body bytes", length(res$content), "\n")

  cat("\n## 3. bare handle, decoding off, gzip asked for\n")
  res <- curl::curl_fetch_memory(url, handle = curl::new_handle(
    accept_encoding = NULL, httpheader = "Accept-Encoding: gzip",
    noproxy = "*"
  ))
  cat(gsub("\r", "\\\\r", rawToChar(res$headers)), "\n")
  cat("body bytes:", length(res$content), "| first 32:",
      paste(format(utils::head(res$content, 32L)), collapse = " "), "\n")
  cat("\n######## END PROBE: windows gzip ########\n\n")
  expect_true(TRUE)
})
