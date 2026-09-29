# Scratch-only wrapper for the R-hub Windows run of fp SSRF-fjgfnaaq: runs the
# design/evidence transport probes (copied into probes/) in Rscript
# subprocesses and prints their full output into testthat.Rout. It never
# fails on a DIFFERS row: the output is the finding. Not for the real suite.

probe_env <- function(backend = NULL) {
  env <- callr::rcmd_safe_env()
  if (!is.null(backend)) env <- c(env, CURL_SSL_BACKEND = backend)
  env
}

run_probe <- function(label, probe, backend = NULL, timeout = 1500) {
  path <- normalizePath(test_path("probes", probe), winslash = "/")
  runner <- tempfile(fileext = ".R")
  writeLines(c(
    'cat("CURL_SSL_BACKEND =", shQuote(Sys.getenv("CURL_SSL_BACKEND")), "\\n")',
    'cat("R:", R.version.string, "|", R.version$platform, "|", utils::osVersion, "\\n")',
    'cat("LC_CTYPE:", Sys.getlocale("LC_CTYPE"), "\\n")',
    'cat("curl package:", as.character(utils::packageVersion("curl")), "\\n")',
    'cat("curl_version():\\n"); utils::str(curl::curl_version())',
    'cat("----\\n")',
    sprintf('source(%s, echo = FALSE, encoding = "UTF-8")', deparse(path))
  ), runner)
  t0 <- Sys.time()
  res <- tryCatch(
    callr::rscript(runner, env = probe_env(backend), show = FALSE,
                   fail_on_status = FALSE, timeout = timeout,
                   wd = dirname(path)),
    error = function(e) list(status = NA, stdout = "",
                             stderr = paste("callr error:", conditionMessage(e)))
  )
  cat("\n\n######## BEGIN PROBE:", label, "########\n")
  cat(res$stdout)
  cat("\n######## STDERR:", label, "########\n")
  cat(res$stderr)
  cat(sprintf("\n######## END PROBE: %s (exit status %s, %.0f s) ########\n\n",
              label, format(res$status),
              as.numeric(difftime(Sys.time(), t0, units = "secs"))))
}

test_that("windows transport probes print their output", {
  cat("\n\n######## RUNNER ########\n")
  cat("ImageOS:", Sys.getenv("ImageOS"), "| ImageVersion:",
      Sys.getenv("ImageVersion"), "| RUNNER_OS:", Sys.getenv("RUNNER_OS"),
      "| NOT_CRAN:", shQuote(Sys.getenv("NOT_CRAN")), "\n")
  cat("Sys.info():", paste(Sys.info()[c("sysname", "release", "version",
                                        "machine")], collapse = " | "), "\n")
  cat("######## END RUNNER ########\n")

  run_probe("platform-transport, default backend",
            "2026-09-25-platform-transport-probes.R")
  run_probe("platform-transport, CURL_SSL_BACKEND=openssl",
            "2026-09-25-platform-transport-probes.R", backend = "openssl")
  run_probe("progress-trace-order, default backend",
            "2026-09-28-progress-trace-order.R")
  run_probe("post-stop-reads, default backend",
            "2026-09-26-post-stop-reads.R")
  run_probe("revocation, default backend", "revocation-probe.R")
  run_probe("revocation, CURL_SSL_BACKEND=openssl", "revocation-probe.R",
            backend = "openssl")
  expect_true(TRUE)
})
