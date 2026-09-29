# Windows Schannel follow-up behind fp SSRF-nfizdzxt. The https probe
# (2026-09-29-windows-https-probe.R) found every https fetch of the test
# suite failing under Schannel with SEC_E_UNTRUSTED_ROOT from the handshake
# while `cainfo` named the test CA, and passing under CURL_SSL_BACKEND=openssl.
# libcurl 8.14.1 (lib/vtls/schannel.c) switches Schannel to manual validation
# against the CA file whenever one is set, and reports a manual failure with
# its own "CertGetCertificateChain trust error" text, so the handshake error
# says Schannel validated on its own. This probe varies one thing at a time
# to find what the CA file needs (R's curl 8.0.0 cannot set cainfo_blob),
# and fetches a public https site through the guard, the path a caller
# takes, which sets no CA file.
#
# Placed, in a scratch copy of the package that is never committed, at
# tests/testthat/test-zz-windows-schannel-ca-probe.R, and submitted with
#   rhub::rc_submit(path = <tarball>, platforms = "windows", confirmation = TRUE)
# The scratch copy also drops `^\.gitattributes$` from .Rbuildignore, so the
# R-hub checkout keeps the fixtures' LF endings. Not for the package's own
# suite.

schannel_fetch <- function(url, host, opts) {
  trace <- character()
  opts <- c(opts, list(
    connect_to = paste0(host, "::127.0.0.1:"),
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
  ))
  handle <- do.call(curl::new_handle, opts)
  out <- tryCatch(
    paste("status", curl::curl_fetch_memory(url, handle = handle)$status_code),
    error = function(e) {
      paste0("error [", class(e)[[1L]], "]: ",
             gsub("\n", " ", conditionMessage(e)))
    }
  )
  list(out = out, trace = trace)
}

test_that("windows schannel CA probe prints its output", {
  cat("\n\n######## BEGIN PROBE: windows schannel CA ########\n")
  cat("curl", as.character(utils::packageVersion("curl")), "| libcurl",
      curl::curl_version()$version, "| ssl:", curl::curl_version()$ssl_version,
      "| os:", utils::osVersion, "\n")

  ca <- normalizePath(test_path("certs", "ca.crt"), winslash = "/")
  cat("ca.crt CR bytes:", sum(readBin(ca, "raw", file.size(ca)) == as.raw(13L)),
      "\n")
  lf <- tempfile(fileext = ".crt")
  writeBin(
    charToRaw(gsub("\r", "", rawToChar(readBin(ca, "raw", file.size(ca))))),
    lf
  )
  lf <- normalizePath(lf, winslash = "/")
  backslash <- normalizePath(lf, winslash = "\\")

  tls <- local_test_server(tls = TRUE)
  tport <- tls$get_port()
  host <- "alpha.example.invalid"
  url <- paste0("https://", host, ":", tport, "/")

  # CURL_SSLVERSION_TLSv1_2 (6) with CURL_SSLVERSION_MAX_TLSv1_2 (6 << 16).
  tls12 <- 6L + 6L * 65536L
  rows <- list(
    "no CA file (control)" = list(),
    "cainfo, as shipped" = list(cainfo = ca),
    "cainfo, LF copy" = list(cainfo = lf),
    "cainfo, LF copy, backslashes" = list(cainfo = backslash),
    "cainfo, LF copy, TLS 1.2 only" = list(cainfo = lf, sslversion = tls12),
    "cainfo, LF copy, cipher list" = list(
      cainfo = lf,
      ssl_cipher_list = "CALG_AES_256:CALG_AES_128:CALG_SHA_256:CALG_ECDHE:CALG_RSA_KEYX"
    ),
    "cainfo, LF copy, capath too" = list(cainfo = lf, capath = dirname(lf))
  )
  for (label in names(rows)) {
    r <- tryCatch(
      schannel_fetch(url, host, rows[[label]]),
      error = function(e) list(out = paste("setup error:", conditionMessage(e)),
                               trace = character())
    )
    cat(sprintf("%-32s %s\n", label, r$out))
    keep <- grepl("schannel|TLS|SSL|CA|cert", r$trace, ignore.case = TRUE)
    if (any(keep)) {
      cat(paste0("        | ", r$trace[keep], collapse = "\n"), "\n")
    }
  }

  cat("\n## public https through the guard (no CA file set)\n")
  for (u in c("https://cloud.r-project.org/", "https://www.example.com/")) {
    r <- tryCatch(
      ssrfr::ssrf_fetch_chain(u, ssrfr::ssrf_policy(), request = list()),
      error = function(e) structure(list(msg = conditionMessage(e)),
                                    class = "probe_error")
    )
    cat(sprintf("%-32s class %s | status %s | cause %s | code %s%s\n", u,
                paste(class(r), collapse = "/"), format(r$status),
                format(r$cause), format(r$code),
                if (is.null(r$msg)) "" else paste(" |", r$msg)))
  }
  cat("\n######## END PROBE: windows schannel CA ########\n\n")
  expect_true(TRUE)
})
