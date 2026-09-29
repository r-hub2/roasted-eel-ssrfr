# Post-stop reads probe behind r-binding.md §7's accepted residual row,
# decoding after a stop (fp SSRF-rgcijatt, SSRF-qqfvoxch): how much a
# transfer reads and decodes after a write callback records a limit stop
# without raising an R error. ssrfr sets no `buffersize`; the probe varies it
# to show that it scales the remainder on every build and bounds it on none.
#
# ssrfr's transport (R/dependencies.R, dep_curl_transfer()) raises no R error
# inside a curl callback, because curl evaluates each callback as a top-level
# call and an error there runs the user's options(error = ) hook. So a stop is
# recorded, later deliveries are dropped, and the loop cancels the transfer
# after the libcurl round the stop came in. This probe reproduces that
# mechanism with curl alone (no ssrfr): a local server sends a gzip body of
# zeros, 1000:1 or so; the write callback stops at 100,000 decoded bytes; the
# trace counts the wire bytes (CURLINFO_DATA_IN) and the callback the decoded
# bytes that arrive after the stop, for each `buffersize`.
#
#   Rscript --vanilla design/evidence/2026-09-26-post-stop-reads.R
#
# Needs a free loopback port (SSRFR_PROBE_PORT, default 18181) and about
# 400 MB of memory for the server to build its body once. Captured output:
# 2026-09-26-post-stop-reads.txt.

suppressMessages(library(curl))

port <- as.integer(Sys.getenv("SSRFR_PROBE_PORT", "18181"))
limit <- 1e5
sizes <- c(0L, 4096L, 1024L) # 0: libcurl's default buffer, 16 KiB

server <- sprintf(
  'body <- memCompress(raw(4e8), "gzip")
  head <- charToRaw(paste0("HTTP/1.1 200 OK\\r\\nContent-Encoding: gzip\\r\\n",
    "Content-Type: application/octet-stream\\r\\nContent-Length: ",
    length(body), "\\r\\nConnection: close\\r\\n\\r\\n"))
  s <- serverSocket(%dL)
  invisible(file.create(%s))
  for (i in seq_len(%dL)) {
    con <- socketAccept(s, open = "r+b", blocking = TRUE)
    readBin(con, "raw", 65536L)
    try(writeBin(c(head, body), con), silent = TRUE)
    try(close(con), silent = TRUE)
  }
  close(s)',
  port,
  deparse(ready <- tempfile("ready")),
  length(sizes)
)
script <- tempfile(fileext = ".R")
writeLines(server, script)
system2(file.path(R.home("bin"), "Rscript"), c("--vanilla", script), wait = FALSE)
for (i in seq_len(600)) {
  if (file.exists(ready)) break
  Sys.sleep(0.1)
}
stopifnot(file.exists(ready))

probe <- function(size) {
  seen <- new.env()
  seen$decoded <- 0
  seen$stopped <- FALSE
  seen$wire_after <- 0
  seen$decoded_after <- 0
  pool <- new_pool(total_con = 1L, host_con = 1L, multiplex = FALSE)
  h <- new_handle(
    url = sprintf("http://127.0.0.1:%d/", port),
    accept_encoding = "gzip, deflate",
    forbid_reuse = 1L,
    http_version = 2L,
    verbose = TRUE,
    debugfunction = function(type, msg) {
      if (type == 3L && seen$stopped) {
        seen$wire_after <- seen$wire_after + length(msg)
      }
    }
  )
  if (size > 0L) handle_setopt(h, buffersize = size)
  multi_add(
    h,
    data = function(x, final = FALSE) {
      if (seen$stopped) {
        seen$decoded_after <- seen$decoded_after + length(x)
        return(invisible())
      }
      seen$decoded <- seen$decoded + length(x)
      if (seen$decoded > limit) seen$stopped <- TRUE
      invisible()
    },
    fail = function(msg) NULL,
    pool = pool
  )
  repeat {
    multi_run(timeout = 0, pool = pool)
    if (seen$stopped) {
      multi_cancel(h)
      break
    }
    if (!length(multi_list(pool))) break
    Sys.sleep(0.001)
  }
  sprintf(
    "buffersize %-7s wire bytes after the stop %8.0f | decoded bytes after the stop %11.0f",
    if (size > 0L) size else "default",
    seen$wire_after,
    seen$decoded_after
  )
}

v <- curl_version()
cat("curl", as.character(packageVersion("curl")), "| libcurl", v$version,
    "|", R.version$platform, "\n")
for (size in sizes) cat(probe(size), "\n")
