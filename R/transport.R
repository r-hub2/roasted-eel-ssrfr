# The transport of the guarded fetch (ssrfr-v1.md §12 steps 9-12, §14,
# INV-5, INV-6, INV-9, INV-10; r-binding.md §4-§6). Everything here is pure:
# the option list a connection attempt is made with, the reading of libcurl's
# trace that checks the pin held, and the reading of the response header
# bytes. The attempt itself is dep_curl_transfer() (R/dependencies.R), and the
# lifecycle around it is ssrf_fetch() (R/fetch.R).

# The options every attempt carries, whatever the hop (r-binding.md §5).
# ssrfr never relies on a default of curl's new_handle(): each row that the
# package sets is overridden here.
fixed_transport_options <- list(
  followlocation = 0L,
  forbid_reuse = 1L,
  dns_cache_timeout = 0L,
  dns_shuffle_addresses = 0L,
  proxy = "",
  noproxy = "*",
  unrestricted_auth = 0L,
  # CURLAUTH_BASIC: URL credentials (allow_userinfo) go out with the one
  # request. The package default, CURLAUTH_ANY, first sends the request
  # without them and answers a 401 challenge by sending it again, a second
  # request within one fetch (§2.5).
  httpauth = 1L,
  # CURL_HTTP_VERSION_1_1: over HTTP/2 libcurl sends the request again when
  # the server refuses its stream (RST_STREAM REFUSED_STREAM), a second
  # request within one fetch (§2.5); one request gains nothing from HTTP/2.
  http_version = 2L,
  netrc = 0L,
  cookiefile = NULL,
  path_as_is = 1L,
  ssl_verifypeer = 1L,
  ssl_verifyhost = 2L
)

# Options that no attempt may carry, and that nothing in ssrfr sets
# (r-binding.md §5, "never set"): each would move the connection off the pin,
# widen what is reachable, or read ambient state.
never_set_options <- c(
  "resolve",
  "cookiejar",
  "altsvc",
  "altsvc_ctrl",
  "hsts",
  "hsts_ctrl",
  "unix_socket_path",
  "abstract_unix_socket",
  "doh_url",
  "interface",
  "localport",
  "localportrange",
  "share",
  "proxyport",
  "proxytype",
  "preproxy",
  "netrc_file",
  "default_protocol",
  "ssl_options"
)

# libcurl 7.85 added the string forms of the protocol restriction. Below it,
# or where R's curl does not list them, the bitmasks restrict to the same two
# schemes: CURLPROTO_HTTP (1) and CURLPROTO_HTTPS (2) (r-binding.md §5,
# "Minimum libcurl").
protocols_str_since <- numeric_version("7.85.0")
curlproto_http_https <- 3L

protocol_options <- function(capabilities) {
  modern <- !is.null(capabilities) &&
    isTRUE(capabilities$protocols_str) &&
    capabilities$version >= protocols_str_since
  if (modern) {
    list(protocols_str = "http,https", redir_protocols_str = "http,https")
  } else {
    list(
      protocols = curlproto_http_https,
      redir_protocols = curlproto_http_https
    )
  }
}

# The Accept-Encoding the transport sends, which is also what it decodes
# (§5.3; r-binding.md §5, "accept_encoding"). Never NULL, which would deliver
# compressed bytes past the decoded-byte counter.
accept_encoding_value <- function(capabilities) {
  if (isTRUE(capabilities$zlib)) "gzip, deflate" else "identity"
}

# An address as the target of a connect_to entry: an IPv6 address bracketed.
pin_target <- function(address) {
  if (grepl(":", address, fixed = TRUE)) paste0("[", address, "]") else address
}

# The connect_to entry (r-binding.md §4.2): "HOST::IP:". HOST is libcurl's own
# parse of the wire string, verbatim, so the key names the host libcurl
# requests (INV-6, §4.2); the port fields are empty, so no port key can
# mismatch and the request's own port is kept; the trailing colon keeps the
# port from being rewritten.
pin_entry <- function(host, address) {
  key <- if (grepl(":", host, fixed = TRUE) && !startsWith(host, "[")) {
    paste0("[", host, "]")
  } else {
    host
  }
  paste0(key, "::", pin_target(address), ":")
}

# Milliseconds for a libcurl timeout option: at least 1, at most what an R
# integer holds.
as_timeout_ms <- function(seconds) {
  ms <- ceiling(seconds * 1000)
  as.integer(max(1, min(ms, .Machine$integer.max)))
}

# The request plan as libcurl options (§2.3): the method, the body and the
# caller's header fields. The User-Agent is the policy's (§5.3).
request_options <- function(request, policy) {
  headers <- request$headers
  lines <- if (length(headers)) {
    ifelse(
      nzchar(headers),
      paste0(names(headers), ": ", headers),
      paste0(names(headers), ";")
    )
  } else {
    character()
  }
  body <- request$body
  method <- request$method
  # A field libcurl adds on its own is suppressed, an empty "Name:" line,
  # unless the plan carries it (§2.3): Accept (*/*) on every request, and
  # Content-Type (application/x-www-form-urlencoded) on every POST and on
  # every request with a body.
  carried <- ascii_lower(names(headers))
  if (!"accept" %in% carried) {
    lines <- c(lines, "Accept:")
  }
  if ((!is.null(body) || method == "POST") && !"content-type" %in% carried) {
    lines <- c(lines, "Content-Type:")
  }
  # Expect is suppressed on every body, whatever a plan says, and prepare
  # refuses it in a plan (R/request.R). libcurl adds 100-continue to a large
  # body, and answers a 417 to it by sending the request again within one
  # fetch; the request is sent at most once (§2.5).
  if (!is.null(body)) {
    lines <- c(lines, "Expect:")
  }
  opts <- list(useragent = policy$user_agent)
  if (length(lines)) {
    opts$httpheader <- lines
  }
  if (!is.null(body)) {
    opts$postfields <- body
    opts$postfieldsize_large <- length(body)
    if (method != "POST") {
      opts$customrequest <- method
    }
  } else if (method == "GET") {
    opts$httpget <- 1L
  } else if (method == "HEAD") {
    opts$nobody <- 1L
  } else if (method == "POST") {
    opts$postfields <- raw()
    opts$postfieldsize_large <- 0
  } else {
    opts$customrequest <- method
  }
  opts
}

# The option list for one attempt at `address` (r-binding.md §5): the pin,
# the protocol restriction, the fixed hardening, the limits and the request.
# `remaining` is the chain's time budget left, in seconds. Pure: every
# attempt's options come from here, so one test checks them all.
#
# `maxfilesize` is never set. libcurl compares it with the declared
# Content-Length and the wire bytes, so it refuses responses whose decoded
# body is within `max_response_size`: a HEAD, which has no body, and a
# compressed body larger on the wire than decoded. The limit is the decoded
# byte count the write callback keeps (§5.3; R/fetch.R).
transport_options <- function(binding, address, remaining, capabilities) {
  policy <- binding$policy
  c(
    list(
      url = binding$url,
      connect_to = pin_entry(binding$origin$host, address)
    ),
    protocol_options(capabilities),
    fixed_transport_options,
    list(
      accept_encoding = accept_encoding_value(capabilities),
      connecttimeout_ms = as_timeout_ms(min(policy$connect_timeout, remaining)),
      timeout_ms = as_timeout_ms(remaining)
    ),
    request_options(binding$request, policy)
  )
}

# --- the audit seam: libcurl's trace (INV-5; r-binding.md §6) -----------------
# The trace is observational and cannot veto: by the time libcurl writes
# `Trying`, connect() has been issued. It is a detector; the pin is the
# control. Matching fails safe: no `Trying` line, a line that cannot be read,
# or one naming another address or port is `pin-mismatch` (§6.6).

# Whether every `Trying` line in `lines` names `address` (canonical text) and
# `port`, compared as raddr values (INV-3). Returns "match", or the reason it
# is not: "absent", "garbled" or "other-address".
pin_check <- function(lines, address, port) {
  trying <- grep("^Trying ", lines, value = TRUE, useBytes = TRUE)
  if (!length(trying)) {
    return("absent")
  }
  want <- canonical_address(address)
  if (!is_string(want)) {
    return("garbled")
  }
  for (line in trying) {
    dialed <- sub("^Trying ", "", sub("[.]{3}$", "", line))
    shape <- "^(\\[[0-9A-Fa-f:.]+\\]|[0-9A-Fa-f:.]+):([0-9]{1,5})$"
    if (!grepl(shape, dialed)) {
      return("garbled")
    }
    host <- unbracket(sub(shape, "\\1", dialed))
    got <- canonical_address(host)
    if (!is_string(got)) {
      return("garbled")
    }
    if (
      !identical(got, want) || as.integer(sub(shape, "\\2", dialed)) != port
    ) {
      return("other-address")
    }
  }
  "match"
}

# --- response headers --------------------------------------------------------

# A status line (RFC 9112 §4): HTTP-version SP status-code SP [reason].
status_line <- "^HTTP/[^ ]* +([0-9]{3})( |$)"

# The segments of `buffer`, libcurl's header buffer: every header block,
# interim 1xx responses included, each ended by an empty line, then a
# chunked body's trailer lines, which no empty line ends. The one reading of
# the buffer that the header measure (R/fetch.R) and the header parse share.
#
# A line is classified by the block before it, never by a line after it, so
# it reads the same while the buffer arrives as once it is whole. A status
# line at the start or after an empty line opens a header block, ended or
# not, unless a complete final (non-1xx) block precedes it: libcurl reads no
# header after that, so every line that follows is a trailer line, one shaped
# like a status line included.
#
# Returns a list: `lines` (the buffer's lines, without their line endings,
# a NUL byte read as 0x7f), `ends` (the byte at which each line ends, its
# line ending included: the buffer's length for a last line with no LF),
# `blocks` (a list of four equal-length vectors, one element per header
# block: its `start` and `end` line, its `status`, and `complete`, whether
# an empty line ended it) and `trailers` (the
# numbers of the lines after the complete final block). A line in neither is
# a stray, which libcurl does not write. Read as bytes: a line may carry
# obs-text. The list also carries `resume`, where the next reading goes on.
#
# The header measure (R/fetch.R) runs this on every growth of the buffer,
# inside callbacks with interrupts suspended. `from` is this function's
# reading of an earlier buffer that `buffer` extends, or NULL: the lines
# that reading ended with an LF are kept, with the classification it left
# after them, and only the bytes after them are read and classified. So the
# readings of every growth together cost time linear in the last buffer,
# however it arrives. A last line with no LF is read again with the next
# growth: its bytes, and whether it is empty or a status line, may change.
header_segments <- function(buffer, from = NULL) {
  kept <- if (is.null(from)) {
    list(bytes = 0L, count = 0L, state = unclassified)
  } else {
    from$resume
  }
  fresh <- seq_len(length(buffer) - kept$bytes) + kept$bytes
  read <- header_lines(buffer[fresh])
  prior <- seq_len(kept$count)
  lines <- c(from$lines[prior], read$lines)
  ends <- c(from$ends[prior], read$ends + kept$bytes)
  n <- length(lines)
  whole <- if (read$open) n - 1L else n
  state <- classify_lines(kept$state, lines, kept$count + 1L, whole)
  resume <- list(
    bytes = if (whole > 0L) ends[[whole]] else 0L,
    count = whole,
    state = state
  )
  state <- classify_lines(state, lines, whole + 1L, n)
  list(
    lines = lines,
    ends = ends,
    blocks = state$blocks,
    trailers = state$trailers,
    resume = resume
  )
}

# The lines of `bytes`, which start at the start of a line, for
# header_segments(): `lines` without their line endings, a NUL byte read as
# 0x7f, `ends` (the byte of `bytes` at which each ends, its LF included: the
# last byte for a last line with no LF) and `open`, whether the last line
# has no LF.
header_lines <- function(bytes) {
  bytes[bytes == as.raw(0L)] <- as.raw(0x7fL)
  lines <- strsplit(rawToChar(bytes), "\n", fixed = TRUE, useBytes = TRUE)
  lines <- lines[[1L]]
  size <- length(bytes)
  list(
    lines = sub("\r$", "", lines, useBytes = TRUE),
    ends = pmin(cumsum(nchar(lines, type = "bytes") + 1L), size),
    open = size > 0L && bytes[[size]] != as.raw(10L)
  )
}

# The classification of no line: header_segments()'s starting state.
unclassified <- list(
  mode = "start",
  blocks = list(
    start = integer(),
    end = integer(),
    status = integer(),
    complete = logical()
  ),
  trailers = integer()
)

# `state`, the classification of `lines` before line `from`, carried on
# through line `to`. It holds header_segments()'s `blocks` and `trailers`,
# and the `mode` the next line is read in: "start" (the start of the buffer
# or the line after an empty one), "block" (the last block, not yet ended by
# an empty line), "stray" (a stray line, and any up to the next empty line)
# or "trailer" (after the complete final block). Each block's end is looked
# up, never searched for, and each vector grows once a call.
classify_lines <- function(state, lines, from, to) {
  if (from > to) {
    return(state)
  }
  if (state$mode == "trailer") {
    state$trailers <- c(state$trailers, from:to)
    return(state)
  }
  span <- lines[from:to]
  n <- length(span)
  skip <- from - 1L
  empties <- which(!nzchar(span))
  # The first empty line at or after line i, for i in 1..n+1, or NA.
  next_empty <- empties[findInterval(seq_len(n + 1L) - 1L, empties) + 1L]
  opens <- grepl(status_line, span, useBytes = TRUE)
  codes <- rep(NA_integer_, n)
  codes[opens] <- as.integer(sub(
    paste0(status_line, ".*$"),
    "\\1",
    span[opens],
    useBytes = TRUE
  ))
  blocks <- state$blocks
  more <- sum(opens)
  start <- c(blocks$start, integer(more))
  end <- c(blocks$end, integer(more))
  status <- c(blocks$status, integer(more))
  complete <- c(blocks$complete, logical(more))
  count <- length(blocks$start)
  trailers <- state$trailers
  mode <- state$mode
  at <- 1L
  while (at <= n) {
    if (mode == "start" && opens[[at]]) {
      mode <- "block"
      count <- count + 1L
      start[[count]] <- at + skip
      status[[count]] <- codes[[at]]
      # The block's end is looked up from the line after its status line.
      at <- at + 1L
    } else if (mode == "start") {
      mode <- "stray"
    }
    ended <- next_empty[[at]]
    if (is.na(ended)) {
      if (mode == "block") {
        end[[count]] <- to
      }
      break
    }
    if (mode == "block") {
      end[[count]] <- ended + skip
      complete[[count]] <- TRUE
      if (status[[count]] >= 200L) {
        trailers <- c(trailers, seq_len(n - ended) + ended + skip)
        mode <- "trailer"
        break
      }
    }
    mode <- "start"
    at <- ended + 1L
  }
  kept <- seq_len(count)
  list(
    mode = mode,
    blocks = list(
      start = start[kept],
      end = end[kept],
      status = status[kept],
      complete = complete[kept]
    ),
    trailers = trailers
  )
}

# The final response in `raw`, libcurl's header buffer: a list of `status`
# (an integer) and `headers` (a character vector of values named by the
# lowercase field name, in order). The block read is header_segments()'s
# complete final block, the last block libcurl received: trailer fields are
# not header fields (RFC 9110 §6.5), so neither a trailer `Location` nor a
# trailer line shaped like a status line reaches the binding. NULL when
# there is no complete final block, or its bytes do not read as HTTP header
# lines, which is a `protocol-error` (§6.6).
#
# The block is read as bytes, never translated: a field value may carry
# obs-text (RFC 9110 §5.5), and a translation would fail, with a warning
# quoting every header, Set-Cookie included (INV-12, §2.3). A value is kept
# byte for byte, marked UTF-8 when it is valid UTF-8 and "bytes" when it is
# not, so R never re-encodes it. A NUL byte reads as no header.
#
# `segments` is header_segments(raw) when the caller already has it, so a
# completed transfer's buffer is segmented once for the measure and the
# parse (R/fetch.R); NULL segments `raw` here.
parse_response_headers <- function(raw, segments = NULL) {
  if (!is.raw(raw) || any(raw == as.raw(0L))) {
    return(NULL)
  }
  if (is.null(segments)) {
    segments <- header_segments(raw)
  }
  blocks <- segments$blocks
  final <- which(blocks$complete & blocks$status >= 200L)
  if (!length(final)) {
    return(NULL)
  }
  first <- blocks$start[[final]] + 1L
  lines <- segments$lines[seq_len(blocks$end[[final]] - first) + first - 1L]
  field_line <- paste0("^", http_tchars, ":")
  fields <- character()
  values <- character()
  for (line in lines) {
    if (grepl("^[ \t]", line, useBytes = TRUE) && length(values)) {
      # An obsolete line folding continues the previous field (RFC 9112 §5.2).
      values[length(values)] <- paste(values[length(values)], trim_ows(line))
      next
    }
    if (!grepl(field_line, line, useBytes = TRUE)) {
      return(NULL)
    }
    fields <- c(fields, ascii_lower(sub(":.*$", "", line, useBytes = TRUE)))
    values <- c(values, trim_ows(sub("^[^:]*:", "", line, useBytes = TRUE)))
  }
  valid <- validUTF8(values)
  Encoding(values[valid]) <- "UTF-8"
  Encoding(values[!valid]) <- "bytes"
  list(
    status = blocks$status[[final]],
    headers = stats::setNames(values, fields)
  )
}

# A field value without its leading and trailing whitespace (RFC 9110 §5.5,
# OWS), matched byte by byte.
trim_ows <- function(x) {
  gsub("^[ \t]+|[ \t]+$", "", x, useBytes = TRUE)
}

# The media type of a Content-Type value for display, without parameters, or
# NA when there is none. A value that is not `type/subtype` in token
# characters is withheld: the header is attacker-chosen and could carry
# terminal control sequences (§2.2).
display_media_type <- function(value) {
  if (!length(value) || is.na(value[[1L]])) {
    return(NA_character_)
  }
  # Byte by byte: the value may not be text (parse_response_headers()).
  type <- trim_ows(sub(";.*$", "", value[[1L]], useBytes = TRUE))
  media_type <- paste0("^", http_tchars, "/", http_tchars, "$")
  if (grepl(media_type, type, useBytes = TRUE)) {
    ascii_lower(type)
  } else {
    "<withheld>"
  }
}
