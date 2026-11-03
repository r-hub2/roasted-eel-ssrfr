## ----include = FALSE----------------------------------------------------------
knitr::opts_chunk$set(
  collapse = TRUE,
  comment = "#>"
)

## ----setup--------------------------------------------------------------------
library(ssrfr)

## -----------------------------------------------------------------------------
policy <- ssrf_policy(allow_ranges = "10.0.0.0/8", deny_hosts = ".corp")
policy

try(ssrf_policy(deny_hosts = "com, ru"))

## -----------------------------------------------------------------------------
ssrf_vocabulary("reason_codes")$code

## -----------------------------------------------------------------------------
ssrf_inspect_url("http://0177.0.0.1/")$code
ssrf_inspect_url("http://[64:ff9b::a9fe:a9fe]/latest/meta-data/")

## -----------------------------------------------------------------------------
ssrf_inspect_url("https://example.com/")$code

policy <- ssrf_policy(allow_ranges = "10.0.0.0/8")
ssrf_inspect_url("http://10.1.2.3/", policy)$code

## -----------------------------------------------------------------------------
ssrf_vocabulary("metadata_hostnames")$hostname

## ----eval = FALSE-------------------------------------------------------------
# res <- ssrf_inspect_url("http://dual.example/", layer = "L1")
# res$code
# #> [1] "loopback"
# vapply(res$addresses, function(a) a$code, "")
# #> [1] NA         "loopback"

## -----------------------------------------------------------------------------
ssrf_inspect_url("http://files.example:6379/", layer = "L1")$code

## -----------------------------------------------------------------------------
policy <- ssrf_policy()

refusal <- ssrf_prepare_hop("http://169.254.169.254/latest/", policy,
                            request = list())
refusal$code
ssrf_public_reason(refusal)

binding <- ssrf_prepare_hop(
  "https://93.184.216.34/data?page=2#top",
  policy,
  request = list(headers = c(Authorization = "Bearer not-shown"))
)
binding

## -----------------------------------------------------------------------------
try(ssrf_prepare_hop("https://example.com/", policy,
                     request = list(headers = c(`Metadata-Flavor` = "Google"))))

## ----eval = FALSE-------------------------------------------------------------
# response <- ssrf_fetch(binding)
# response
# #> <ssrfr_response>
# #>   status: 200
# #>   type: text/html
# #>   body: 1256 bytes (read it with $body)
# rawToChar(response$body)
# binding$state$status
# #> [1] 200
# try(ssrf_fetch(binding))
# #> Error : This binding was already fetched; prepare the hop again.

## ----eval = FALSE-------------------------------------------------------------
# policy <- ssrf_policy(max_redirects = 5)
# result <- ssrf_fetch_chain(
#   "https://example.com/start",
#   policy,
#   request = list(headers = c(Authorization = "Bearer not-shown"))
# )

## ----eval = FALSE-------------------------------------------------------------
# policy <- ssrf_policy(max_redirects = 5)
# result <- ssrf_prepare_hop(
#   "https://example.com/start",
#   policy,
#   request = list(headers = c(Authorization = "Bearer not-shown"))
# )
# while (inherits(result, "ssrfr_binding")) {
#   hop <- result
#   result <- ssrf_fetch(hop)
#   # Log this hop here: `hop` is its spent binding, `result` its outcome.
#   followed <- inherits(result, "ssrfr_response") &&
#     result$status %in% c(301, 302, 303, 307, 308) &&
#     identical(hop$state$location_count, 1L)
#   if (!followed) {
#     break
#   }
#   result <- ssrf_prepare_hop(hop$state$location, policy, from = hop)
# }
# outcome <- if (inherits(result, "ssrfr_response")) {
#   result$body # the body's bytes, a raw vector, whatever they hold
# } else if (inherits(result, "ssrfr_refusal")) {
#   result$code
# } else {
#   result$cause
# }

## ----eval = FALSE-------------------------------------------------------------
# test_policy <- ssrf_policy(allow_ranges = "127.0.0.0/8", allow_ports = 8080)
# binding <- ssrf_prepare_hop("http://127.0.0.1:8080/health", test_policy,
#                             request = list())
# ssrf_fetch(binding)$status

