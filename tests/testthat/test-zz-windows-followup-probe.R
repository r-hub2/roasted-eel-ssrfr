# Two Windows failures left after the fixture-CA skip (fp SSRF-nfizdzxt),
# seen in R-hub builds close-pinkriverdolphin (Schannel) and
# superstitious-xraytetra (CURL_SSL_BACKEND=openssl), both with NOT_CRAN set:
#
# - "ordinary HTTP still works through the guard" fails at webfakes'
#   httpbin /gzip: a bare curl handle cannot decode it either
#   (2026-09-29-windows-gzip-probe.R). httpbin builds that body by writing
#   through gzcon(file(tmp, "wb")). Part 1 repeats that write in this
#   process and checks the bytes: the gzip trailer's ISIZE against the input
#   length, and whether R and libcurl can decode them.
# - "the header buffer is segmented in linear time" (test-transport.R,
#   skip_on_cran, so it first ran here) measured a 512/64 KiB time ratio of
#   30 against a bound of 24 (8 is linear, 64 quadratic). Part 2 times
#   header_segments() over sizes, each call repeated until the batch takes
#   at least 0.25 s, so the timer's resolution does not decide the ratio.
#
# Placed, in a scratch copy of the package that is never committed, at
# tests/testthat/test-zz-windows-followup-probe.R, and submitted with
#   rhub::rc_submit(path = <tarball>, platforms = "windows", confirmation = TRUE)
# Not for the package's own suite.

gzip_report <- function(label, bytes, n_in) {
  size <- length(bytes)
  isize <- if (size >= 4L) {
    sum(as.integer(bytes[(size - 3L):size]) * 256^(0:3))
  } else {
    NA
  }
  inflated <- tryCatch(
    length(memDecompress(bytes, type = "gzip")),
    error = function(e) paste("error:", conditionMessage(e))
  )
  cat(sprintf(
    "%-24s %5d bytes | header %s | ISIZE %s (input %s) | memDecompress: %s\n",
    label, size, paste(format(utils::head(bytes, 10L)), collapse = " "),
    format(isize), format(n_in), format(inflated)
  ))
}

test_that("windows follow-up probe prints its output", {
  cat("\n\n######## BEGIN PROBE: windows follow-up ########\n")
  cat(R.version.string, "|", R.version$platform, "| curl",
      as.character(utils::packageVersion("curl")), "| libcurl",
      curl::curl_version()$version, "| zlib", curl::curl_version()$libz_version,
      "\n")

  cat("\n## 1. gzcon() writing to a file, as webfakes' /gzip does\n")
  json <- charToRaw(paste(rep("{\"gzipped\": true}", 20L), collapse = "\n"))
  tmp <- tempfile()
  con <- file(tmp, open = "wb")
  con2 <- gzcon(con)
  writeBin(json, con2)
  flush(con2)
  close(con2)
  gzcon_bytes <- readBin(tmp, "raw", file.info(tmp)$size)
  gzip_report("gzcon(file(wb))", gzcon_bytes, length(json))
  tmp2 <- tempfile()
  g <- gzfile(tmp2, open = "wb")
  writeBin(json, g)
  close(g)
  gzip_report("gzfile(wb)", readBin(tmp2, "raw", file.info(tmp2)$size),
              length(json))

  web <- webfakes::local_app_process(
    webfakes::httpbin_app(),
    opts = webfakes::server_opts(num_threads = 2)
  )
  res <- curl::curl_fetch_memory(
    paste0("http://127.0.0.1:", web$get_port(), "/gzip"),
    handle = curl::new_handle(
      accept_encoding = NULL, httpheader = "Accept-Encoding: gzip",
      noproxy = "*"
    )
  )
  gzip_report("httpbin /gzip body", res$content, NA)

  cat("\n## 2. header_segments() per call, over sizes\n")
  block <- "HTTP/1.1 100 X\r\n\r\n"
  per_call <- function(kib) {
    count <- (kib * 1024) %/% nchar(block)
    buffer <- wire(strrep(block, count))
    reps <- 1L
    repeat {
      t <- system.time(
        for (i in seq_len(reps)) ssrfr:::header_segments(buffer)
      )[["elapsed"]]
      if (t >= 0.25 || reps >= 4096L) break
      reps <- reps * 2L
    }
    c(kib = kib, reps = reps, seconds = t / reps)
  }
  single <- function(kib) {
    count <- (kib * 1024) %/% nchar(block)
    buffer <- wire(strrep(block, count))
    vapply(1:3, function(i) {
      system.time(ssrfr:::header_segments(buffer))[["elapsed"]]
    }, numeric(1L))
  }
  rows <- t(vapply(c(64, 128, 256, 512, 1024), per_call, numeric(3L)))
  print(rows)
  cat("per-call ratio 512/64:", rows[4L, "seconds"] / rows[1L, "seconds"], "\n")
  cat("single calls, as the test times them: 64 KiB",
      format(single(64)), "| 512 KiB", format(single(512)), "\n")
  cat("\n######## END PROBE: windows follow-up ########\n\n")
  expect_true(TRUE)
})
