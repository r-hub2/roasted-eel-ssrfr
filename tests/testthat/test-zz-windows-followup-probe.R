# Two Windows failures left after the fixture-CA skip (fp SSRF-nfizdzxt),
# seen in R-hub builds close-pinkriverdolphin (Schannel) and
# superstitious-xraytetra (CURL_SSL_BACKEND=openssl), both with NOT_CRAN set:
#
# - "ordinary HTTP still works through the guard" fails at webfakes'
#   httpbin /gzip: a bare curl handle cannot decode it either
#   (2026-09-29-windows-gzip-probe.R). httpbin builds that body by writing
#   through gzcon(file(tmp, "wb")). Part 1 repeats that write and checks
#   the bytes: the gzip trailer's ISIZE against the input length, and what a
#   bounded gzcon() read gets back.
# - "the header buffer is segmented in linear time" (test-transport.R,
#   skip_on_cran, so it first ran here) measured a 512/64 KiB time ratio of
#   30 against a bound of 24 (8 is linear, 64 quadratic). Part 2 times
#   header_segments() over sizes, each call repeated until the batch takes
#   at least 0.25 s, so the timer's resolution does not decide the ratio.
#
# A first version of this probe, which decoded with memDecompress() in the
# check process, never finished on R-hub (builds clever-dingo and
# washable-arrowcrab). Each part now runs in a child R process under a time
# limit, so a hang is reported, not suffered.
#
# Placed, in a scratch copy of the package that is never committed, at
# tests/testthat/test-zz-windows-followup-probe.R, and submitted with
#   rhub::rc_submit(path = <tarball>, platforms = "windows", confirmation = TRUE)
# Not for the package's own suite.

part_gzip <- function(port) {
  gzip_report <- function(label, bytes, n_in) {
    size <- length(bytes)
    isize <- if (size >= 4L) {
      sum(as.integer(bytes[(size - 3L):size]) * 256^(0:3))
    } else {
      NA
    }
    back <- tryCatch(
      {
        con <- gzcon(rawConnection(bytes))
        on.exit(close(con))
        length(readBin(con, "raw", 1e6))
      },
      error = function(e) paste("error:", conditionMessage(e)),
      warning = function(w) paste("warning:", conditionMessage(w))
    )
    cat(sprintf(
      "%-20s %5d bytes | head %s | tail %s | ISIZE %s (input %s) | gzcon read: %s\n",
      label, size, paste(format(utils::head(bytes, 10L)), collapse = " "),
      paste(format(utils::tail(bytes, 8L)), collapse = " "),
      format(isize), format(n_in), format(back)
    ))
  }
  json <- charToRaw(paste(rep("{\"gzipped\": true}", 20L), collapse = "\n"))
  tmp <- tempfile()
  con <- file(tmp, open = "wb")
  con2 <- gzcon(con)
  writeBin(json, con2)
  flush(con2)
  close(con2)
  gzip_report("gzcon(file(wb))", readBin(tmp, "raw", file.info(tmp)$size),
              length(json))
  tmp2 <- tempfile()
  g <- gzfile(tmp2, open = "wb")
  writeBin(json, g)
  close(g)
  gzip_report("gzfile(wb)", readBin(tmp2, "raw", file.info(tmp2)$size),
              length(json))
  res <- curl::curl_fetch_memory(
    paste0("http://127.0.0.1:", port, "/gzip"),
    handle = curl::new_handle(
      accept_encoding = NULL, httpheader = "Accept-Encoding: gzip",
      noproxy = "*", timeout = 20L
    )
  )
  gzip_report("httpbin /gzip body", res$content, NA)
}

part_timing <- function() {
  block <- "HTTP/1.1 100 X\r\n\r\n"
  buffer_of <- function(kib) {
    charToRaw(strrep(block, (kib * 1024) %/% nchar(block)))
  }
  per_call <- function(kib) {
    buffer <- buffer_of(kib)
    reps <- 1L
    repeat {
      t <- system.time(
        for (i in seq_len(reps)) ssrfr:::header_segments(buffer)
      )[["elapsed"]]
      if (t >= 0.25 || reps >= 256L) break
      reps <- reps * 2L
    }
    cat(sprintf("%5d KiB: %4d calls in %.3f s, %.5f s a call\n",
                kib, reps, t, t / reps))
    t / reps
  }
  per <- vapply(c(64, 128, 256, 512), per_call, numeric(1L))
  cat("per-call ratio 512/64:", per[[4L]] / per[[1L]], "\n")
  single <- function(kib) {
    buffer <- buffer_of(kib)
    vapply(1:3, function(i) {
      system.time(ssrfr:::header_segments(buffer))[["elapsed"]]
    }, numeric(1L))
  }
  cat("single calls, as the test times them: 64 KiB", format(single(64)),
      "| 512 KiB", format(single(512)), "\n")
}

run_part <- function(label, fn, args = list(), timeout = 240) {
  cat("\n##", label, "\n")
  t0 <- Sys.time()
  out <- tryCatch(
    callr::r(fn, args = args, timeout = timeout, show = TRUE),
    error = function(e) cat("PART FAILED OR TIMED OUT:", conditionMessage(e), "\n")
  )
  cat(sprintf("(%.0f s)\n", as.numeric(difftime(Sys.time(), t0, units = "secs"))))
}

test_that("windows follow-up probe prints its output", {
  cat("\n\n######## BEGIN PROBE: windows follow-up ########\n")
  cat(R.version.string, "|", R.version$platform, "| curl",
      as.character(utils::packageVersion("curl")), "| libcurl",
      curl::curl_version()$version, "| zlib", curl::curl_version()$libz_version,
      "\n")
  web <- webfakes::local_app_process(
    webfakes::httpbin_app(),
    opts = webfakes::server_opts(num_threads = 2)
  )
  run_part("1. gzcon() writing to a file, as webfakes' /gzip does", part_gzip,
           list(port = web$get_port()))
  run_part("2. header_segments() per call, over sizes", part_timing)
  cat("\n######## END PROBE: windows follow-up ########\n\n")
  expect_true(TRUE)
})
