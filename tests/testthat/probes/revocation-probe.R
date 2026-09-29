# Informational probe for r-binding.md §5's Windows row: which ssl_options
# bits curl's new_handle() sets on Windows. R's curl cannot read an option
# back, so this infers the default from behaviour: the same two Let's Encrypt
# test hosts (one valid, one revoked) are fetched with the package default
# and with explicit ssl_options values, and the default is read off as the
# explicit value it behaves like. Needs outbound HTTPS.
#   CURLSSLOPT_NO_REVOKE = 2, CURLSSLOPT_NATIVE_CA = 16.
# Expected from curl's src/handle.c: Schannel default = 2 (revoked host
# accepted), OpenSSL default = 18 when CURL_CA_BUNDLE is unset (native CA
# store used, no revocation check).

suppressMessages(library(curl))
v <- curl_version()
cat("CURL_SSL_BACKEND:", shQuote(Sys.getenv("CURL_SSL_BACKEND")),
    "| CURL_CA_BUNDLE:", shQuote(Sys.getenv("CURL_CA_BUNDLE")),
    "| ssl_version:", v$ssl_version, "\n")
fetch <- function(url, ...) {
  h <- new_handle(connecttimeout = 15, timeout = 30, nobody = TRUE)
  if (length(list(...))) handle_setopt(h, ...)
  tryCatch(paste("status", curl_fetch_memory(url, handle = h)$status_code),
           error = function(e) paste("error:", gsub("\\s+", " ", conditionMessage(e))))
}
hosts <- c(valid = "https://valid-isrgrootx1.letsencrypt.org/",
           revoked = "https://revoked-isrgrootx1.letsencrypt.org/")
for (n in names(hosts)) {
  cat(sprintf("%-8s default (new_handle)             %s\n", n, fetch(hosts[[n]])))
  for (o in c(0L, 2L, 16L, 18L)) {
    cat(sprintf("%-8s ssl_options = %-2d                  %s\n", n, o,
                fetch(hosts[[n]], ssl_options = o)))
  }
}
cat("done\n")
