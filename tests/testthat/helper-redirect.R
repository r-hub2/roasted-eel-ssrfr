# Harness for redirect hops (ssrfr-v1.md §2.3, §2.5, §2.6, INV-7, INV-8;
# r-binding.md §7): a webfakes app that redirects and echoes, a TLS server
# for the corpus's https hosts, and a test-side loop over the public
# primitives. The loop helper of §2.2 is ssrf_fetch_chain() (R/chain.R);
# test-chain.R runs these fixtures through it.

# The second pinned test host: another origin on the same loopback server.
other_host <- "other.example.invalid"

# The redirect app.
#   /r/:status?to=URL  answers `status`, with `Location: URL` when `to` is
#                      given and no Location when it is not
#   /echo              answers 200 and reports the request it received in
#                      its header fields, so a HEAD request is reported too:
#                      X-Echo-Method, X-Echo-Fields (the lowercase field
#                      names, sorted, comma-separated) and X-Echo-Body (the
#                      body as text)
#   /loop              redirects to itself, counting the requests it gets
#   /hits              the count /loop has seen
#   /corpus            answers 302 with the Location the request's
#                      X-Corpus-Location field names (the corpus harness)
redirect_app <- function() {
  app <- webfakes::new_app()
  app$locals$loops <- 0L
  app$all("/r/:status", function(req, res) {
    res$set_status(as.integer(req$params$status))
    if (!is.null(req$query$to)) {
      res$set_header("Location", req$query$to)
    }
    res$send("")
  })
  app$all("/echo", function(req, res) {
    fields <- sort(tolower(names(req$headers)))
    body <- req$.body
    res$set_header("X-Echo-Method", toupper(req$method))
    res$set_header("X-Echo-Fields", paste(fields, collapse = ","))
    res$set_header(
      "X-Echo-Body",
      if (length(body)) rawToChar(body) else ""
    )
    res$send("echo")
  })
  app$all("/loop", function(req, res) {
    req$app$locals$loops <- req$app$locals$loops + 1L
    res$redirect("/loop", 302L)
  })
  app$get("/hits", function(req, res) {
    res$send(as.character(req$app$locals$loops))
  })
  app$all(webfakes::new_regexp("^/"), function(req, res) {
    to <- req$get_header("X-Corpus-Location")
    if (is.null(to)) {
      res$send_status(404L)
    } else {
      res$set_status(302L)
      res$set_header("Location", to)
      res$send("")
    }
  })
  app
}

# A webfakes server for `app`, over TLS with the corpus certificate when
# `tls` is TRUE (certs/make-certs.sh: legit.example and secure.example).
local_redirect_server <- function(
  app = redirect_app(),
  tls = FALSE,
  env = parent.frame()
) {
  opts <- webfakes::server_opts(
    num_threads = 2,
    enable_keep_alive = FALSE,
    error_log_file = FALSE,
    ssl_certificate = if (tls) test_path("certs", "corpus.pem")
  )
  webfakes::local_app_process(
    app,
    port = if (tls) "0s" else NULL,
    opts = opts,
    .local_envir = env
  )
}

# The echo a /echo response reports.
echo_of <- function(response) {
  h <- response$headers
  fields <- unname(h[["x-echo-fields"]])
  list(
    method = unname(h[["x-echo-method"]]),
    fields = if (nzchar(fields)) strsplit(fields, ",", fixed = TRUE)[[1L]],
    body = unname(h[["x-echo-body"]])
  )
}

# Follows a chain through the public primitives as a caller's loop would:
# prepare, fetch, and prepare the next hop from the binding while its
# response is a followed redirect (§2.3). Returns the last value and every
# binding, in hop order.
follow_chain <- function(url, policy, request = list(), max_hops = 50L) {
  bindings <- list()
  out <- ssrf_prepare_hop(url, policy, request = request)
  repeat {
    if (!inherits(out, "ssrfr_binding")) {
      break
    }
    binding <- out
    bindings[[length(bindings) + 1L]] <- binding
    out <- ssrf_fetch(binding)
    followed <- inherits(out, "ssrfr_response") &&
      out$status %in% c(301L, 302L, 303L, 307L, 308L) &&
      identical(binding$state$location_count, 1L)
    if (!followed || length(bindings) >= max_hops) {
      break
    }
    out <- ssrf_prepare_hop(binding$state$location, policy, from = binding)
  }
  list(result = out, bindings = bindings)
}

# The number of requests the redirect app's /loop has seen, read around the
# guard.
loop_hits <- function(port) {
  h <- curl::new_handle()
  rawToChar(
    curl::curl_fetch_memory(
      paste0("http://127.0.0.1:", port, "/hits"),
      handle = h
    )$content
  )
}

# The request head a raw server recorded, as lines.
recorded_head <- function(server) {
  text <- rawToChar(server$request())
  head <- substr(text, 1L, regexpr("\r\n\r\n", text, fixed = TRUE) - 1L)
  strsplit(head, "\r\n", fixed = TRUE)[[1L]]
}
