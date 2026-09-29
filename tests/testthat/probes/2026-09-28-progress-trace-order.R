# Progress/trace order probe behind r-binding.md §7's callback-failure row
# (fp SSRF-dmmcitul): whether libcurl calls the progress callback before it
# traces `Trying`, the line the pin check reads. When it does, a progress
# callback that fails on its first call stops the transfer with the trace
# empty, and the pin check reports `absent`; when it does not, the trace
# holds `Trying` first and the pin can match.
#
# This reproduces ssrfr's transport (R/dependencies.R, dep_curl_transfer())
# with curl alone (no ssrfr): one handle in a pool of one connection, the
# fixed options that bear on the dial (R/transport.R), the pin as a
# `connect_to` entry, a text trace and a progress callback, and one libcurl
# round per multi_run(timeout = 0). It records every progress call and every
# trace line, in order and by round, up to `Connected to`, against a loopback
# listener that never answers, for 127.0.0.1 and ::1. ssrfr's wrapper cancels
# a transfer after the round a callback failed in, and its trace callback
# still records within that round, so the finding is the round of the first
# progress call against the round of the first `Trying` line. Where the
# listener does not take IPv6, the ::1 dial is refused after `Trying`, which
# still shows the order.
#
#   Rscript --vanilla design/evidence/2026-09-28-progress-trace-order.R
#
# Needs a free loopback port (SSRFR_PROBE_PORT, default 18182). Captured
# output: 2026-09-28-progress-trace-order.txt.

suppressMessages(library(curl))

port <- as.integer(Sys.getenv("SSRFR_PROBE_PORT", "18182"))
host <- "pinned.example.invalid"
listener <- serverSocket(port)

probe <- function(address) {
  seen <- new.env()
  seen$events <- character()
  seen$connected <- FALSE
  pool <- new_pool(total_con = 1L, host_con = 1L, multiplex = FALSE)
  target <- if (grepl(":", address, fixed = TRUE)) {
    paste0("[", address, "]")
  } else {
    address
  }
  h <- new_handle(
    url = sprintf("http://%s:%d/", host, port),
    connect_to = paste0(host, "::", target, ":"),
    followlocation = 0L,
    forbid_reuse = 1L,
    dns_cache_timeout = 0L,
    proxy = "",
    noproxy = "*",
    http_version = 2L,
    connecttimeout_ms = 2000L,
    timeout_ms = 3000L,
    verbose = TRUE,
    debugfunction = function(type, msg) {
      if (type == 0L && !seen$connected) {
        lines <- trimws(strsplit(rawToChar(msg), "\n", fixed = TRUE)[[1L]])
        lines <- lines[nzchar(lines)]
        seen$events <- c(seen$events, paste("trace:", lines))
        seen$connected <- any(startsWith(lines, "Connected to "))
      }
      NULL
    },
    noprogress = 0L,
    xferinfofunction = function(down, up) {
      if (!seen$connected) {
        seen$events <- c(seen$events, "progress")
      }
      TRUE
    }
  )
  multi_add(h, fail = function(msg) NULL, pool = pool)
  t0 <- Sys.time()
  round <- 0L
  while (
    !seen$connected &&
      length(multi_list(pool)) &&
      difftime(Sys.time(), t0, units = "secs") < 3
  ) {
    round <- round + 1L
    seen$events <- c(seen$events, paste("-- round", round))
    multi_run(timeout = 0, pool = pool)
    Sys.sleep(0.001)
  }
  multi_cancel(h)
  # Consecutive progress calls collapse to one entry with a count.
  runs <- rle(seen$events)
  shown <- ifelse(
    runs$lengths > 1L,
    paste0(runs$values, " (x", runs$lengths, ")"),
    runs$values
  )
  # The round each event came in. ssrfr cancels a transfer after the round
  # a callback failed in, so what matters is whether the first progress call
  # comes in an earlier round than the first `Trying` line.
  rounds <- cumsum(startsWith(seen$events, "-- round "))
  trying <- rounds[startsWith(seen$events, "trace: Trying ")]
  progress <- rounds[seen$events == "progress"]
  verdict <- if (!length(trying) || !length(progress)) {
    "no `Trying` line or no progress call before `Connected to`"
  } else if (progress[[1L]] < trying[[1L]]) {
    sprintf(
      "first progress call in round %d, first `Trying` in round %d: a stop at the first progress call leaves no `Trying` traced",
      progress[[1L]],
      trying[[1L]]
    )
  } else {
    sprintf(
      "first progress call in round %d, first `Trying` in round %d: a stop at the first progress call leaves `Trying` traced",
      progress[[1L]],
      trying[[1L]]
    )
  }
  c(sprintf("== %s: %s", address, verdict), paste0("  ", shown))
}

v <- curl_version()
cat(
  "curl",
  as.character(packageVersion("curl")),
  "| libcurl",
  v$version,
  "|",
  R.version$platform,
  "\n"
)
for (address in c("127.0.0.1", "::1")) {
  out <- tryCatch(
    probe(address),
    error = function(e) sprintf("== %s: probe failed: %s", address, conditionMessage(e))
  )
  cat(out, sep = "\n")
}
close(listener)
