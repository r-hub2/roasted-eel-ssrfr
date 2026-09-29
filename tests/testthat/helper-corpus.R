# Readers for the conformance corpus (ssrfr-v1.md §7; fixtures/README.md).

read_corpus <- function(file) {
  utils::read.delim(
    test_path("fixtures", file),
    quote = "",
    comment.char = "",
    na.strings = character(),
    colClasses = "character",
    encoding = "UTF-8",
    check.names = FALSE
  )
}

# The escapes of fixtures/README.md: \\ \t \n \r \0 and \u{XXXX}. An R string
# cannot hold NUL, so a field using \0 is an error here, not a silent skip.
unescape_field <- function(s) {
  out <- character()
  ch <- strsplit(s, "", fixed = TRUE)[[1L]]
  i <- 1L
  while (i <= length(ch)) {
    if (ch[[i]] == "\\" && i < length(ch)) {
      nx <- ch[[i + 1L]]
      simple <- c("\\" = "\\", t = "\t", n = "\n", r = "\r")
      if (nx %in% names(simple)) {
        out <- c(out, simple[[nx]])
        i <- i + 2L
        next
      }
      if (nx == "0") {
        stop("an R string cannot hold NUL: ", s)
      }
      if (nx == "u") {
        close <- match("}", ch[(i + 3L):length(ch)]) + i + 2L
        hex <- paste(ch[(i + 3L):(close - 1L)], collapse = "")
        out <- c(out, intToUtf8(strtoi(hex, 16L)))
        i <- close + 1L
        next
      }
    }
    out <- c(out, ch[[i]])
    i <- i + 1L
  }
  enc2utf8(paste(out, collapse = ""))
}

# The `policy` column: `default`, or `;`-separated field overrides with `|`
# between the values of one field. `allow_ports` adds ports to the ones the
# column allows (the L2 harness's server port).
corpus_policy <- function(spec, allow_ports = NULL) {
  if (identical(spec, "default")) {
    return(ssrf_policy(allow_ports = c(80, 443, allow_ports)))
  }
  numeric <- c(
    "allow_ports",
    "max_redirects",
    "connect_timeout",
    "total_timeout",
    "max_response_size",
    "max_header_bytes",
    "max_header_fields",
    "max_url_length"
  )
  args <- list()
  for (pair in strsplit(spec, ";", fixed = TRUE)[[1L]]) {
    field <- sub("=.*$", "", pair)
    values <- strsplit(sub("^[^=]*=", "", pair), "|", fixed = TRUE)[[1L]]
    args[[field]] <- if (field %in% numeric) {
      as.numeric(values)
    } else if (field == "allow_userinfo") {
      as.logical(values)
    } else {
      values
    }
  }
  if (length(allow_ports)) {
    given <- if (is.null(args$allow_ports)) c(80, 443) else args$allow_ports
    args$allow_ports <- unique(c(given, allow_ports))
  }
  do.call(ssrf_policy, args)
}

# The previous hop's URL from the `hop` column, or NULL for a first hop.
corpus_base <- function(hop) {
  if (startsWith(hop, "redirect:")) sub("^redirect:", "", hop) else NULL
}

# A verdict-vector row inspected at L0: the reason code, or "-" when nothing
# at L0 applies.
inspect_row <- function(row) {
  res <- ssrf_inspect_url(
    unescape_field(row$input),
    corpus_policy(row$policy),
    base = corpus_base(row$hop)
  )
  if (is.na(res$code)) "-" else res$code
}

# Steps 1-3 of a parse-vector row under the default policy (§7 component 2):
# "parse", "scheme" or "agree", and the host the guard acts on.
parse_row <- function(input) {
  hop <- ssrfr:::parse_hop(unescape_field(input), ssrf_policy())
  code <- hop$finding$code
  step <- hop$finding$detail$step
  outcome <- if (
    !is.null(code) && step <= 3L && code %in% c("parse", "scheme")
  ) {
    code
  } else {
    "agree"
  }
  list(outcome = outcome, host = hop$host)
}

# Two hosts are one value when raddr reads both as the same address, or when
# neither is an address and they are the same lowercase name (§4.1).
same_host_value <- function(a, b) {
  strip <- function(h) sub("^\\[(.*)\\]$", "\\1", h)
  pa <- raddr::addr_pton(strip(a))
  pb <- raddr::addr_pton(strip(b))
  if (!is.na(pa) && !is.na(pb)) {
    return(identical(raddr::addr_format(pa), raddr::addr_format(pb)))
  }
  is.na(pa) && is.na(pb) && identical(tolower(a), tolower(b))
}

# Runs `code` with every network entry point of curl and raddr made to fail,
# so any network call L0 made would raise an error (r-binding.md §7).
network_entry_points <- list(
  curl = c(
    "nslookup",
    "curl_fetch_memory",
    "curl_fetch_disk",
    "curl_fetch_stream",
    "curl_fetch_multi",
    "curl_fetch_echo",
    "curl_download",
    "curl_upload",
    "curl_echo",
    "multi_download",
    "curl",
    "multi_add",
    "multi_run",
    "new_handle",
    "handle_setopt",
    "ie_get_proxy_for_url"
  ),
  raddr = "addr_getaddrinfo"
)

local_no_network <- function(env = parent.frame()) {
  for (pkg in names(network_entry_points)) {
    fns <- network_entry_points[[pkg]]
    tripwires <- lapply(fns, function(fn) {
      force(fn)
      function(...) stop("network entry point called: ", pkg, "::", fn)
    })
    names(tripwires) <- fns
    do.call(
      testthat::local_mocked_bindings,
      c(tripwires, list(.package = pkg, .env = env))
    )
  }
}

# The `answers` column (fixtures/README.md) as a replacement for the internal
# resolver wrapper, which records each query it is asked: a comma-separated
# answer set, `empty`, `error`, or `unparseable:<text>`. A row with `-`
# expects no resolution, so a call is an error (r-binding.md §7).
answers_resolver <- function(answers) {
  seen <- new.env(parent = emptyenv())
  seen$queries <- character()
  fn <- function(query) {
    seen$queries <- c(seen$queries, query)
    if (identical(answers, "-")) {
      stop("resolver called for a row that expects no resolution")
    }
    if (identical(answers, "empty")) {
      return(character())
    }
    if (identical(answers, "error")) {
      stop("Failed to resolve hostname")
    }
    if (startsWith(answers, "unparseable:")) {
      return(sub("^unparseable:", "", answers))
    }
    strsplit(answers, ",", fixed = TRUE)[[1L]]
  }
  list(fn = fn, seen = seen)
}

# A verdict-vector row inspected at L1, with its `answers` fed through the
# mocked resolver wrapper: the outcome (the reason code, the cause, or "-"
# when nothing refuses or fails), its verdict class, and the resolver queries
# made.
inspect_row_l1 <- function(row) {
  resolver <- answers_resolver(row$answers)
  local_mocked_bindings(dep_nslookup = resolver$fn, .package = "ssrfr")
  res <- ssrf_inspect_url(
    unescape_field(row$input),
    corpus_policy(row$policy),
    base = corpus_base(row$hop),
    layer = "L1"
  )
  verdict <- if (!is.na(res$cause)) {
    "fail"
  } else if (is.na(res$code)) {
    "admit"
  } else {
    "refuse"
  }
  list(
    outcome = switch(verdict, fail = res$cause, admit = "-", res$code),
    verdict = verdict,
    queries = resolver$seen$queries
  )
}

# --- L2 -----------------------------------------------------------------------

# The servers the L2 harness serves a redirect row's previous hop from: the
# redirect app (helper-redirect.R) over http, and over TLS with the corpus
# certificate. Returns their ports by scheme.
local_corpus_servers <- function(env = parent.frame()) {
  http <- local_redirect_server(env = env)
  https <- local_redirect_server(tls = TRUE, env = env)
  list(http = http$get_port(), https = https$get_port())
}

# A verdict-vector row decided by the guarded hop (§7, L2). A first-hop row
# is prepared with an empty plan. A redirect row's previous hop, its `hop`
# column's URL with the server's port added, is prepared under a policy that
# reopens loopback with the row's chain budgets, and fetched for real: the
# app answers 302 with the row's input as Location (the X-Corpus-Location
# field of the plan). The row is then decided by
# ssrf_prepare_hop(input, policy, from = that binding), under the row's
# policy with the server's port allowed, so a relative Location that keeps
# the port is judged on everything else. When the fetch does not return a
# response, as under max_redirects = 0 where no followed `from` can exist,
# the row is decided by what it returned. The previous hop's name resolves
# to loopback; every later query gets the row's `answers`.
#
# Returns the outcome, its verdict class, the hop that decided it, `via`
# ("first", "fetch" or "from") and the resolver queries after the first hop;
# NULL for a row served over TLS where the fixture CA cannot be trusted
# (helper-transport.R), which the caller skips once every other row ran.
decide_row_l2 <- function(row, ports) {
  input <- unescape_field(row$input)
  base <- corpus_base(row$hop)
  resolver <- answers_resolver(row$answers)
  if (is.null(base)) {
    local_mocked_bindings(dep_nslookup = resolver$fn, .package = "ssrfr")
    out <- ssrf_prepare_hop(input, corpus_policy(row$policy), request = list())
    return(l2_outcome(out, "first", resolver$seen$queries))
  }
  scheme <- sub(":.*$", "", base)
  if (scheme == "https" && test_ca_ignored()) {
    return(NULL)
  }
  port <- ports[[scheme]]
  previous <- sub("^(https?://[^/?#]+)", paste0("\\1:", port), base)
  policy <- corpus_policy(row$policy, allow_ports = port)
  first <- new.env(parent = emptyenv())
  first$answered <- FALSE
  local_mocked_bindings(
    dep_nslookup = function(query) {
      if (!first$answered) {
        first$answered <- TRUE
        return("127.0.0.1")
      }
      resolver$fn(query)
    },
    .package = "ssrfr"
  )
  if (scheme == "https") {
    local_trust_test_ca()
  }
  binding <- ssrf_prepare_hop(
    previous,
    loopback_policy(
      port,
      max_redirects = policy$max_redirects,
      total_timeout = policy$total_timeout
    ),
    request = list(headers = c(`X-Corpus-Location` = input))
  )
  if (!inherits(binding, "ssrfr_binding")) {
    stop("the corpus harness could not prepare the previous hop: ", previous)
  }
  out <- ssrf_fetch(binding)
  if (!inherits(out, "ssrfr_response")) {
    return(l2_outcome(out, "fetch", resolver$seen$queries))
  }
  out <- ssrf_prepare_hop(input, policy, from = binding)
  l2_outcome(out, "from", resolver$seen$queries)
}

l2_outcome <- function(out, via, queries) {
  verdict <- if (inherits(out, "ssrfr_refusal")) {
    "refuse"
  } else if (inherits(out, "ssrfr_failure")) {
    "fail"
  } else if (inherits(out, "ssrfr_binding")) {
    "admit"
  } else {
    class(out)[[1L]]
  }
  list(
    outcome = switch(
      verdict,
      refuse = out$code,
      fail = out$cause,
      admit = "-",
      verdict
    ),
    verdict = verdict,
    hop = out$hop,
    via = via,
    queries = queries
  )
}
