# Platform transport probes behind r-binding.md §4-§6 and ssrfr-v1.md §8
# items 6 and 7 (fp SSRF-rcwugkqo): the debugfunction audit seam, the
# connect_to and resolve key forms and their fail-open, host-key mismatches
# (U-label/A-label, IPv6 and IPv4 spellings, case, trailing dot), the
# bracketed IPv6 pin, failover, protocol exposure and both restriction options
# (protocols_str and the pre-7.85 protocols bitmask), redirect-hop protocols,
# connection reuse and the shared DNS cache, and maxfilesize.
#
# Platform-neutral: plain Rscript with curl, webfakes and callr installed;
# httpuv is optional (block 4d). No network access is needed: every target is
# loopback, an RFC 2606 .invalid name, or 192.0.2.1 (TEST-NET-1, RFC 5737),
# which never answers.
#   Rscript --vanilla design/evidence/2026-09-25-platform-transport-probes.R
# 2026-09-25-linux-transport-matrix.sh runs it on the host and in Docker on
# Ubuntu 22.04, Ubuntu 24.04 and Rocky 9; the captured output of every run is
# 2026-09-25-linux-transport-results.txt.
#
# Each probe prints one row: "ok" when this build behaves as the reference
# (the 2026-09-24 macOS build, libcurl 8.14.1, as r-binding.md records it, or,
# for the probes new here, the macOS result of 2026-09-25), "DIFFERS" when it
# does not, then the label and the observed outcome, and the reference after a
# DIFFERS. A pin row says "honoured" when the first dial went to the pinned
# address, and "IGNORED" with what happened instead; every pin block runs a
# control that must read "honoured" beside the failure form, so a run shows it
# can tell the two apart. A DIFFERS row is a finding about that platform, not
# a failure of this script.
#
# Recorded environments: see the header of each section of the results file.

suppressMessages({
  library(curl)
  library(webfakes)
})

v <- curl_version()
os <- if (file.exists("/etc/os-release")) {
  x <- grep("^PRETTY_NAME=", readLines("/etc/os-release"), value = TRUE)
  gsub('^PRETTY_NAME=|"', "", x)
} else {
  paste(Sys.info()[c("sysname", "release", "machine")], collapse = " ")
}
cat("os:", os, "| R", as.character(getRversion()), "| LC_CTYPE",
    Sys.getlocale("LC_CTYPE"), "\n")
cat("curl", as.character(packageVersion("curl")), "| libcurl", v$version,
    "|", v$ssl_version, "| ipv6", v$ipv6, "| idn", v$idn, "| http2", v$http2,
    "| ares", !is.null(v$ares), "\n")
cat("webfakes", as.character(packageVersion("webfakes")), "| httpuv",
    if (requireNamespace("httpuv", quietly = TRUE))
      as.character(packageVersion("httpuv")) else "absent", "\n")

# ---- helpers ----------------------------------------------------------------

# Fetch `url` with a verbose handle; keep the libcurl text trace (debug type
# 0), split into lines, and the error message if any.
trace_fetch <- function(url, ..., handle = NULL, connecttimeout = 2) {
  log <- character()
  h <- if (is.null(handle)) {
    new_handle(connecttimeout = connecttimeout, timeout = 4)
  } else handle
  handle_setopt(h, ..., verbose = TRUE, debugfunction = function(type, msg) {
    if (type == 0L) log <<- c(log, trimws(strsplit(rawToChar(msg), "\n")[[1]]))
    NULL
  })
  res <- tryCatch(curl_fetch_memory(enc2utf8(url), handle = h),
                  error = function(e) gsub("\\s+", " ", conditionMessage(e)))
  list(log = log[nzchar(log)], result = res)
}
err_of <- function(t) if (is.character(t$result)) t$result else ""
# The addresses dialed, in order, from the "Trying" lines, brackets dropped:
# libcurl 8.x writes "Trying [::1]:1...", older ones may write "Trying ::1:1...".
dials <- function(t) {
  x <- grep("^Trying ", t$log, value = TRUE)
  gsub("[][]", "", sub("\\.\\.\\.$", "", sub("^Trying ", "", x)))
}
# honoured / IGNORED for a pin to `target` ("127.0.0.1:1", "::1:1").
pin_state <- function(t, target) {
  d <- dials(t)
  if (length(d) && d[1] == target) return("honoured")
  if (length(d)) return(paste0("IGNORED (dialed ", d[1], ")"))
  if (any(grepl("resolve", c(t$log, err_of(t)), ignore.case = TRUE))) {
    return("IGNORED (resolved the name: failed)")
  }
  paste("no dial:", substr(err_of(t), 1, 60))
}
row <- function(label, ref, obs) {
  same <- identical(ref, obs)
  cat(sprintf("%-7s %-58s %s%s\n", if (same) "ok" else "DIFFERS", label, obs,
              if (same) "" else paste0("   [ref: ", ref, "]")))
}
pin <- function(label, url, target, ref = "honoured", ...) {
  row(label, ref, pin_state(trace_fetch(url, ...), target))
}
show_log <- function(t, port = NULL) {
  x <- t$log
  if (!is.null(port)) x <- gsub(paste0("\\b", port, "\\b"), "<port>", x)
  x <- gsub("port [0-9]{4,5}\\b", "port <n>", x)
  x <- gsub("after [0-9]+ ms", "after <n> ms", x)
  cat(paste0("        | ", x), sep = "\n")
}
has_opt <- function(o) o %in% names(curl_options())
setopt_ok <- function(...) {
  tryCatch({ handle_setopt(new_handle(), ...); "settable" },
           error = function(e) paste("NOT settable:", conditionMessage(e)))
}

# A loopback app: echoes Host, redirects to ?u=, serves a sized and a chunked
# body. Keep-alive is on so that block 7 can observe connection reuse; the
# pooled connections each hold a server thread, hence 8 threads.
app <- new_app()
app$get("/", function(req, res) res$send(paste("host:", req$get_header("Host"))))
app$get("/to", function(req, res) res$redirect(req$query$u, 302L))
app$get("/big", function(req, res) res$send(strrep("x", 200000)))
app$get("/chunked", function(req, res) {
  for (i in 1:50) res$send_chunk(strrep("y", 5000))
})
srv <- new_app_process(app, opts = server_opts(enable_keep_alive = TRUE,
                                               num_threads = 8))
port <- srv$get_port()

# ---- 1. The debugfunction audit seam (r-binding.md §6) ------------------------
cat("\n## 1. debugfunction audit seam\n")
t <- trace_fetch("http://127.0.0.1:1/")
show_log(t)
row("1a debugfunction fires with an R closure", "TRUE", as.character(length(t$log) > 0))
row("1b trace names the dialed address 127.0.0.1:1", "honoured",
    pin_state(t, "127.0.0.1:1"))
row("1c handle_data() has a peer-IP field", "FALSE",
    as.character(any(grepl("ip", names(handle_data(new_handle())), ignore.case = TRUE))))

# ---- 2. Key forms and the port-key fail-open (r-binding.md §4.2, INV-6) ------
cat("\n## 2. pin key forms; a port-key mismatch fails open\n")
# Every probe uses its own name: a resolve entry stays in the shared DNS cache
# (block 7g) and would answer a later probe of the same name and port.
pin("2a resolve  key :1   request :1 (control)", "http://rs1.invalid:1/",
    "127.0.0.1:1", resolve = "rs1.invalid:1:127.0.0.1")
pin("2b resolve  key :443 request :1", "http://rs2.invalid:1/", "127.0.0.1:1",
    ref = "IGNORED (resolved the name: failed)", resolve = "rs2.invalid:443:127.0.0.1")
pin("2c connect_to key :1   request :1 (control)", "http://ct1.invalid:1/",
    "127.0.0.1:1", connect_to = "ct1.invalid:1:127.0.0.1:1")
pin("2d connect_to key :443 request :1", "http://ct2.invalid:1/", "127.0.0.1:1",
    ref = "IGNORED (resolved the name: failed)",
    connect_to = "ct2.invalid:443:127.0.0.1:443")
pin("2e connect_to HOST::IP: request :1", "http://ct3.invalid:1/", "127.0.0.1:1",
    connect_to = "ct3.invalid::127.0.0.1:")
pin("2f connect_to HOST::IP:1 request :8080 (port rewritten)",
    "http://ct4.invalid:8080/", "127.0.0.1:1", connect_to = "ct4.invalid::127.0.0.1:1")
pin("2g connect_to ::IP: (empty HOST) matches any host", "http://any.invalid:1/",
    "127.0.0.1:1", connect_to = "::127.0.0.1:")
pin("2h HOST::IP: http default port", "http://dp1.invalid/", "127.0.0.1:80",
    connect_to = "dp1.invalid::127.0.0.1:")
pin("2i HOST::IP: https default port", "https://dp2.invalid/", "127.0.0.1:443",
    connect_to = "dp2.invalid::127.0.0.1:")
pin("2j key :80 on an http URL with no port", "http://dp3.invalid/", "127.0.0.1:80",
    connect_to = "dp3.invalid:80:127.0.0.1:")
pin("2k key :443 on an http URL with no port", "http://dp4.invalid/", "127.0.0.1:80",
    ref = "IGNORED (resolved the name: failed)",
    connect_to = "dp4.invalid:443:127.0.0.1:")
r <- tryCatch(rawToChar(curl_fetch_memory(
  sprintf("http://pinned.example.invalid:%d/", port),
  handle = new_handle(connect_to = "pinned.example.invalid::127.0.0.1:"))$content),
  error = function(e) conditionMessage(e))
row("2l HOST::IP: reaches the app, Host kept", "host: pinned.example.invalid:<port>",
    sub(port, "<port>", r))

# ---- 3. Host-key mismatch (r-binding.md §4.2) ----------------------------------
# The HOST field is compared with libcurl's own host for the request. Each
# group runs a control, the mismatching spellings, and the key the spec takes
# from curl_parse_url() (ssrfr-v1.md §4.2), which must read "honoured".
cat("\n## 3. host-key mismatch\n")
ck <- function(url) {
  h <- tryCatch(curl_parse_url(enc2utf8(url))$host, error = function(e) "<error>")
  if (grepl(":", h, fixed = TRUE) && !startsWith(h, "[")) paste0("[", h, "]") else h
}
A <- "xn--bcher-kva.invalid"
U <- "b\u00fccher.invalid"
uA <- sprintf("http://%s:1/", A)
uU <- sprintf("http://%s:1/", U)
cat("        curl_parse_url host of the U-label URL:", ck(uU), "\n")
pin("3a request A-label, key A-label (control)", uA, "127.0.0.1:1",
    connect_to = paste0(A, "::127.0.0.1:"))
pin("3b request A-label, key U-label", uA, "127.0.0.1:1",
    ref = "IGNORED (resolved the name: failed)", connect_to = paste0(U, "::127.0.0.1:"))
pin("3c request U-label, key U-label", uU, "127.0.0.1:1",
    connect_to = paste0(U, "::127.0.0.1:"))
pin("3d request U-label, key A-label", uU, "127.0.0.1:1",
    ref = "IGNORED (resolved the name: failed)", connect_to = paste0(A, "::127.0.0.1:"))
pin("3e request U-label, key = curl_parse_url() host", uU, "127.0.0.1:1",
    connect_to = paste0(ck(uU), "::127.0.0.1:"))
pin("3e2 request A-label, key = curl_parse_url() host", uA, "127.0.0.1:1",
    connect_to = paste0(ck(uA), "::127.0.0.1:"))
pin("3f request lower case, key upper case", "http://case.invalid:1/",
    "127.0.0.1:1", connect_to = "CASE.INVALID::127.0.0.1:")
cat("        curl_parse_url host of http://dot.invalid.:1/:", ck("http://dot.invalid.:1/"), "\n")
pin("3g request dot1.invalid., key dot1.invalid.", "http://dot1.invalid.:1/",
    "127.0.0.1:1", connect_to = "dot1.invalid.::127.0.0.1:")
pin("3h request dot2.invalid., key dot2.invalid", "http://dot2.invalid.:1/",
    "127.0.0.1:1", ref = "IGNORED (resolved the name: failed)",
    connect_to = "dot2.invalid::127.0.0.1:")
pin("3i request dot3.invalid, key dot3.invalid.", "http://dot3.invalid:1/",
    "127.0.0.1:1", ref = "IGNORED (resolved the name: failed)",
    connect_to = "dot3.invalid.::127.0.0.1:")
# IPv6 literal hosts. The pin goes to 127.0.0.1, so an ignored pin shows up as
# a dial to the literal itself.
L <- "http://[0:0:0:0:0:0:0:1]:1/"
cat("        curl_parse_url host of", L, ":", ck(L), "\n")
pin("3j request [::1], key [::1] (control)", "http://[::1]:1/", "127.0.0.1:1",
    connect_to = "[::1]::127.0.0.1:")
pin("3k request [::1], key [0:0:0:0:0:0:0:1]", "http://[::1]:1/", "127.0.0.1:1",
    ref = "IGNORED (dialed ::1:1)", connect_to = "[0:0:0:0:0:0:0:1]::127.0.0.1:")
pin("3l request [0:..:1], key [::1]", L, "127.0.0.1:1",
    connect_to = "[::1]::127.0.0.1:")
pin("3m request [0:..:1], key [0:0:0:0:0:0:0:1]", L, "127.0.0.1:1",
    ref = "IGNORED (dialed ::1:1)", connect_to = "[0:0:0:0:0:0:0:1]::127.0.0.1:")
pin("3n request [0:..:1], key = curl_parse_url() host", L, "127.0.0.1:1",
    connect_to = paste0(ck(L), "::127.0.0.1:"))
M <- "http://[::ffff:127.0.0.1]:1/"
cat("        curl_parse_url host of", M, ":", ck(M), "\n")
pin("3o request [::ffff:127.0.0.1], key [::ffff:7f00:1] (rurl)", M, "::1:1",
    ref = "IGNORED (dialed ::ffff:127.0.0.1:1)", connect_to = "[::ffff:7f00:1]::[::1]:")
pin("3p request [::ffff:127.0.0.1], key = curl_parse_url() host", M, "::1:1",
    connect_to = paste0(ck(M), "::[::1]:"))
# Numeric IPv4 forms. The pin goes to 192.0.2.1, so an ignored pin shows up
# as a dial to 127.0.0.1, where getaddrinfo() or libcurl puts the literal.
for (lit in c("0177.0.0.1", "2130706433")) {
  u <- sprintf("http://%s:1/", lit)
  cat("        curl_parse_url host of", u, ":", ck(u), "\n")
  pin(sprintf("3q request %s, key 127.0.0.1", lit), u, "192.0.2.1:1",
      connect_to = "127.0.0.1::192.0.2.1:", connecttimeout = 1)
  pin(sprintf("3r request %s, key %s", lit, lit), u, "192.0.2.1:1",
      ref = "IGNORED (dialed 127.0.0.1:1)",
      connect_to = paste0(lit, "::192.0.2.1:"), connecttimeout = 1)
  pin(sprintf("3s request %s, key = curl_parse_url() host", lit), u, "192.0.2.1:1",
      connect_to = paste0(ck(u), "::192.0.2.1:"), connecttimeout = 1)
}

# ---- 4. The bracketed IPv6 pin (r-binding.md §4.4) ------------------------------
# Refused-port trick: nothing listens on port 1, so "Trying [::1]:1" followed
# by "Connection refused" shows the SYN went to ::1 and the kernel answered.
cat("\n## 4. IPv6 bracketed-literal pin\n")
t <- trace_fetch("http://[::1]:1/")
show_log(t)
row("4a direct http://[::1]:1/ dials ::1", "honoured", pin_state(t, "::1:1"))
t <- trace_fetch("http://v6.invalid:1/", connect_to = "v6.invalid::[::1]:")
show_log(t)
row("4b connect_to v6.invalid::[::1]: (control)", "honoured", pin_state(t, "::1:1"))
row("4c ... refused by ::1, not unreachable", "TRUE",
    as.character(grepl("refused|Couldn't connect|Could not connect|Failed to connect",
                       paste(c(t$log, err_of(t)), collapse = " "), ignore.case = TRUE) &&
                   !grepl("unreachable|Cannot assign|not available",
                          paste(c(t$log, err_of(t)), collapse = " "), ignore.case = TRUE)))
pin("4d connect_to v6b.invalid:443:[::1]: request :1", "http://v6b.invalid:1/", "::1:1",
    ref = "IGNORED (resolved the name: failed)", connect_to = "v6b.invalid:443:[::1]:")
# End to end with httpuv on ::1 (webfakes cannot bind ::1), fetched from a
# callr child so this process can serve.
v6 <- NULL
if (requireNamespace("httpuv", quietly = TRUE) && requireNamespace("callr", quietly = TRUE)) {
  v6port <- httpuv::randomPort()
  v6 <- tryCatch(httpuv::startServer("::1", v6port, list(call = function(req) {
    list(status = 200L, headers = list("Content-Type" = "text/plain"),
         body = paste0("host=", req$HTTP_HOST))
  })), error = function(e) NULL)
}
if (is.null(v6)) {
  cat("        4e skipped: httpuv or callr missing, or ::1 cannot be bound\n")
} else {
  px <- callr::r_bg(function(port) {
    h <- curl::new_handle(connect_to = "v6pin.invalid::[::1]:", timeout = 5)
    tryCatch(rawToChar(curl::curl_fetch_memory(
      sprintf("http://v6pin.invalid:%d/", port), handle = h)$content),
      error = function(e) conditionMessage(e))
  }, args = list(port = v6port))
  t0 <- Sys.time()
  while (px$is_alive() && difftime(Sys.time(), t0, units = "secs") < 20) httpuv::service(100)
  row("4e httpuv on ::1, pinned fetch, Host kept", "host=v6pin.invalid:<port>",
      sub(v6port, "<port>", px$get_result()))
  httpuv::stopServer(v6)
}

# ---- 5. Failover (r-binding.md §4.1, §4.3) ------------------------------------
cat("\n## 5. failover\n")
t <- trace_fetch("http://fo.invalid:1/", resolve = "fo.invalid:1:127.0.0.1,127.0.0.2")
row("5a resolve with two addresses tries both, in order",
    "127.0.0.1:1 -> 127.0.0.2:1", paste(dials(t), collapse = " -> "))
t <- trace_fetch("http://fo2.invalid:1/",
                 connect_to = c("fo2.invalid::127.0.0.1:", "fo2.invalid::127.0.0.2:"))
row("5b connect_to with two entries: first match only", "127.0.0.1:1",
    paste(dials(t), collapse = " -> "))

# ---- 6. Protocol exposure (r-binding.md §5, "Minimum libcurl") ---------------
cat("\n## 6. protocol exposure\n")
p <- v$protocols
cat("        compiled in (", length(p), "):", paste(p, collapse = " "), "\n")
for (o in c("protocols_str", "redir_protocols_str", "protocols", "redir_protocols")) {
  val <- if (grepl("_str$", o)) "http,https" else 3L   # CURLPROTO_HTTP | _HTTPS
  cat(sprintf("        %-20s listed %-5s %s\n", o, has_opt(o),
              do.call(setopt_ok, setNames(list(val), o))))
}
tf <- tempfile(fileext = ".txt")
writeLines("probe file", tf)
file_url <- paste0("file://", if (startsWith(tf, "/")) "" else "/", gsub("\\\\", "/", tf))
scheme_url <- function(s) switch(s,
  file = file_url,
  smb = , smbs = sprintf("%s://127.0.0.1:1/share/x", s),
  sprintf("%s://127.0.0.1:1/x", s))
# attempted: libcurl dialed or read; refused: stopped before any I/O.
classify <- function(t) {
  if (!is.character(t$result)) return("ATTEMPTED (fetched)")
  if (length(dials(t))) return("ATTEMPTED (dialed)")
  if (grepl("Unsupported protocol|disabled", t$result)) return("refused")
  paste("other:", substr(t$result, 1, 50))
}
probe_schemes <- function(...) {
  vapply(setNames(p, p), function(s) classify(trace_fetch(scheme_url(s), ...)), "")
}
summ <- function(x) {
  paste(vapply(split(names(x), x), function(n) paste(n, collapse = " "), ""),
        paste0("[", names(split(names(x), x)), "]"), sep = " ", collapse = "; ")
}
unr <- probe_schemes()
cat("        6a unrestricted first hop:", summ(unr), "\n")
row("6a unrestricted: file:// is read", "ATTEMPTED (fetched)", unname(unr["file"]))
for (o in c("protocols_str", "protocols")) {
  val <- if (o == "protocols_str") "http,https" else 3L
  if (!startsWith(do.call(setopt_ok, setNames(list(val), o)), "settable")) {
    cat(sprintf("        6b %s: not settable on this build, skipped\n", o))
    next
  }
  res <- do.call(probe_schemes, setNames(list(val), o))
  others <- setdiff(names(res), c("http", "https"))
  cat(sprintf("        6b %s: %s\n", o, summ(res)))
  row(sprintf("6b %s: every other scheme refused", o), "TRUE",
      as.character(all(res[others] == "refused")))
  row(sprintf("6b %s: http and https attempted", o), "TRUE",
      as.character(all(startsWith(res[c("http", "https")], "ATTEMPTED"))))
}
# Redirect hops, with libcurl following: its default list, then the
# restriction options. The first hop is the loopback app.
# The first hop always dials the app, so only the redirect target counts.
redir <- function(target, ...) {
  t <- trace_fetch(srv$url("/to", query = list(u = target)), followlocation = 1L, ...)
  if (is.character(t$result) && grepl("Unsupported protocol|disabled", t$result)) {
    return("refused")
  }
  if ("127.0.0.1:1" %in% dials(t)) return("ATTEMPTED (dialed)")
  if (!is.character(t$result) && t$result$status_code < 300) return("ATTEMPTED (fetched)")
  paste("other:", substr(err_of(t), 1, 50))
}
rt <- c(file = file_url, gopher = "gopher://127.0.0.1:1/x",
        dict = "dict://127.0.0.1:1/x", ftp = "ftp://127.0.0.1:1/x",
        http = "http://127.0.0.1:1/x")
rt <- rt[names(rt) %in% p]
ref_default <- c(file = "refused", gopher = "refused", dict = "refused",
                 ftp = "ATTEMPTED (dialed)", http = "ATTEMPTED (dialed)")
for (s in names(rt)) row(paste("6c redirect to", s, "- libcurl default"),
                         ref_default[[s]], redir(rt[[s]]))
for (o in c("redir_protocols_str", "redir_protocols")) {
  val <- if (o == "redir_protocols_str") "http,https" else 3L
  if (!startsWith(do.call(setopt_ok, setNames(list(val), o)), "settable")) {
    cat(sprintf("        6d %s: not settable on this build, skipped\n", o))
    next
  }
  for (s in names(rt)) {
    row(sprintf("6d redirect to %s - %s", s, o),
        if (s == "http") "ATTEMPTED (dialed)" else "refused",
        do.call(redir, c(list(rt[[s]]), setNames(list(val), o))))
  }
}

# ---- 7. Connection reuse and the shared DNS cache (r-binding.md §4.1) ---------
# Two requests to the same name and port; the second carries a pin to
# 192.0.2.1, on the same handle or a fresh one. "REUSED" means a pooled
# connection answered and the second pin was never consulted.
cat("\n## 7. connection reuse and the DNS cache\n")
reuse <- function(opt, forbid = 0L, fresh_handle = FALSE) {
  host <- sprintf("reuse-%s-%d-%d.invalid", sub("_", "", opt), forbid, fresh_handle)
  u <- sprintf("http://%s:%d/", host, port)
  key <- function(ip) {
    if (opt == "resolve") sprintf("%s:%d:%s", host, port, ip) else sprintf("%s::%s:", host, ip)
  }
  mk <- function(ip) {
    h <- new_handle(connecttimeout = 1, timeout = 3, forbid_reuse = forbid)
    handle_setopt(h, .list = setNames(list(key(ip)), opt))
  }
  h <- mk("127.0.0.1")
  a <- trace_fetch(u, handle = h)
  if (fresh_handle) h <- mk("192.0.2.1") else {
    handle_setopt(h, .list = setNames(list(key("192.0.2.1")), opt))
  }
  b <- trace_fetch(u, handle = h)
  first <- if (is.character(a$result)) "first FAILED" else paste("first", a$result$status_code)
  re <- grep("^Re-?using", b$log, value = TRUE)
  if (length(re)) cat(paste0("        | ", sub(host, "<host>", re[1], fixed = TRUE)), "\n")
  second <- if (length(re)) {
    paste("REUSED ->", if (is.character(b$result)) "error" else b$result$status_code)
  } else if (length(dials(b))) {
    paste("new connection to", sub(":[0-9]+$", "", dials(b)[1]))
  } else paste("?", substr(err_of(b), 1, 40))
  paste(first, "|", second)
}
row("7a resolve,    same handle", "first 200 | REUSED -> 200", reuse("resolve"))
row("7b resolve,    fresh handle", "first 200 | REUSED -> 200",
    reuse("resolve", fresh_handle = TRUE))
row("7c resolve,    same handle, forbid_reuse", "first 200 | new connection to 192.0.2.1",
    reuse("resolve", forbid = 1L))
row("7d connect_to, same handle", "first 200 | new connection to 192.0.2.1",
    reuse("connect_to"))
row("7e connect_to, fresh handle", "first 200 | new connection to 192.0.2.1",
    reuse("connect_to", fresh_handle = TRUE))
row("7f connect_to, same handle, forbid_reuse", "first 200 | new connection to 192.0.2.1",
    reuse("connect_to", forbid = 1L))
# A pin on handle A; handle B is fresh, unpinned, dns_cache_timeout = 0.
leak <- function(pin, host) {
  a <- new_handle(connecttimeout = 2, timeout = 3)
  handle_setopt(a, .list = pin)
  b <- new_handle(connecttimeout = 2, timeout = 3, dns_cache_timeout = 0L)
  u <- sprintf("http://%s:%d/", host, port)
  f <- function(h) tryCatch(as.character(curl_fetch_memory(u, handle = h)$status_code),
                            error = function(e) "error")
  paste0("A ", f(a), ", B ", f(b))
}
row("7g resolve on A answers B's lookup", "A 200, B 200",
    leak(list(resolve = sprintf("leak-r.invalid:%d:127.0.0.1", port)), "leak-r.invalid"))
row("7h connect_to on A does not", "A 200, B error",
    leak(list(connect_to = "leak-c.invalid::127.0.0.1:"), "leak-c.invalid"))

# ---- 8. maxfilesize (r-binding.md §5, traps) ----------------------------------
cat("\n## 8. maxfilesize\n")
mfs <- function(path) {
  t <- trace_fetch(srv$url(path), maxfilesize = 1000)
  if (is.character(t$result)) {
    if (grepl("file size|filesize", t$result, ignore.case = TRUE)) "aborted" else
      paste("error:", substr(t$result, 1, 50))
  } else paste("delivered", length(t$result$content), "bytes")
}
row("8a Content-Length 200000, maxfilesize 1000", "aborted", mfs("/big"))
row("8b chunked 250000, maxfilesize 1000", "aborted", mfs("/chunked"))

# ---- 9. Trace text of a pinned fetch (r-binding.md §6 stability) --------------
cat("\n## 9. trace of a successful pinned fetch\n")
t <- trace_fetch(sprintf("http://trace.invalid:%d/", port),
                 connect_to = "trace.invalid::127.0.0.1:", forbid_reuse = 1L)
show_log(t, port)
row("9a first Trying line names the pin", "honoured",
    pin_state(t, paste0("127.0.0.1:", port)))
invisible(srv$stop())
cat("\ndone\n")
