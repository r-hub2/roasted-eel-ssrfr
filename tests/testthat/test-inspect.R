# L0 structural inspection (ssrfr-v1.md §1, §1.1, §12 steps 1-6, §5 gates
# 1-3 on address literals), and the named tests of r-binding.md §7 that L0
# carries. The corpus rows themselves run in test-corpus.R.

test_that("L0 returns facts under a name that claims no verdict", {
  res <- ssrf_inspect_url("http://127.0.0.1:80/admin")
  expect_s3_class(res, "ssrfr_inspection")
  expect_named(
    res,
    c(
      "code",
      "cause",
      "step",
      "detail",
      "layer",
      "url",
      "scheme",
      "host",
      "port",
      "userinfo",
      "host_kind",
      "address",
      "answers",
      "addresses"
    )
  )
  expect_identical(res$code, "loopback")
  expect_identical(res$cause, NA_character_)
  expect_identical(res$layer, "L0")
  expect_null(res$answers)
  expect_null(res$addresses)
  expect_identical(res$step, 8L)
  expect_identical(res$scheme, "http")
  expect_identical(res$host, "127.0.0.1")
  expect_identical(res$port, 80L)
  expect_identical(res$host_kind, "ipv4")
  expect_identical(res$address$category, "loopback")
  expect_false(res$address$reachability)
  expect_identical(res$detail$gate, "1a")
  expect_identical(res$detail$tier, 4L)

  # A name is not resolved at L0: nothing applies, and that is not approval.
  name <- ssrf_inspect_url("https://example.com/")
  expect_identical(name$code, NA_character_)
  expect_identical(name$host_kind, "name")
  expect_identical(name$port, 443L)
  expect_null(name$address)

  # §1.1: no exported name implies a security decision.
  exports <- getNamespaceExports("ssrfr")
  expect_false(any(grepl("safe|check|valid", exports)))
})

test_that("the refusal-carrying facts name gate, tier and embedding", {
  res <- ssrf_inspect_url("http://[64:ff9b::a9fe:a9fe]/")
  expect_identical(res$code, "cloud-metadata")
  expect_identical(res$detail$tier, 1L)
  expect_identical(res$detail$embedding_kind, "nat64_wk")
  expect_identical(res$detail$provider_kind, "instance-metadata")
  expect_true(res$address$reachability)
  expect_identical(res$address$embeddings$address, "169.254.169.254")

  wire <- ssrf_inspect_url("http://168.63.129.16/")
  expect_identical(wire$detail$provider_kind, "provider-internal")
  expect_identical(wire$detail$gate, "2")
})

# r-binding.md §7: parser disagreement refuses as `parse` (a MUST-test), with
# the refusal asserted whatever rurl's verdict (§4.1; design/evidence/
# 2026-09-25-fullwidth-separators.R).
test_that("fullwidth separators in a host refuse as parse whatever rurl says", {
  separators <- c("＃", "／", "？", "：")
  urls <- paste0("http://127.0.0.1", separators, ".evil.example/")
  for (url in urls) {
    expect_identical(ssrf_inspect_url(url)$code, "parse", label = url)
  }
  # rurl's layer-1 verdict made to pass: the refusal still comes from the
  # parse boundary, the two parsers' disagreement or libcurl's own failure.
  local_mocked_bindings(
    dep_rurl_verdicts = function(url) {
      data.frame(
        layer1_syntax_verdict = "pass",
        layer2_policy_verdict = "admitted",
        layer3_annotation_state = "not-applicable"
      )
    }
  )
  for (url in urls) {
    res <- ssrf_inspect_url(url)
    expect_identical(res$code, "parse", label = url)
    expect_true(
      res$detail$check %in% c("agreement", "transport-parse"),
      label = url
    )
  }
})

# INV-3: every spelling of an address is one value and one verdict. The
# corpus's ipv6-spelling rows are the inherited tables; these add each
# address's spellings side by side.
test_that("every spelling of an address gives one verdict", {
  spellings <- list(
    loopback = c(
      "::1",
      "0::1",
      "::0:1",
      "0:0:0:0:0:0:0:1",
      "0000:0000:0000:0000:0000:0000:0000:0001",
      "::0.0.0.1"
    ),
    "cloud-metadata" = c(
      "fd00:ec2::254",
      "FD00:EC2::254",
      "fd00:0ec2::254",
      "fd00:ec2:0:0:0:0:0:254",
      "fd00:0ec2:0000:0000:0000:0000:0000:0254"
    ),
    "link-local" = c(
      "fe80::1",
      "FE80::1",
      "fe80:0:0:0:0:0:0:1",
      "fe80:0000::0001"
    ),
    "ipv4-mapped" = c(
      "::ffff:127.0.0.1",
      "::FFFF:7F00:1",
      "0:0:0:0:0:ffff:7f00:1",
      "::ffff:7f00:0001",
      "0:0:0:0:0:FFFF:127.0.0.1"
    ),
    nat64 = c(
      "64:ff9b::10.0.0.1",
      "64:ff9b::a00:1",
      "0064:ff9b:0000:0000:0000:0000:0a00:0001",
      "64:FF9B::A00:1"
    )
  )
  for (code in names(spellings)) {
    for (s in spellings[[code]]) {
      expect_identical(
        ssrf_inspect_url(paste0("http://[", s, "]/"))$code,
        code,
        label = s
      )
    }
  }
  # The second production bug: `fe8::` is 0fe8::, nowhere near fe80::/10.
  expect_identical(ssrf_inspect_url("http://[fe8::]/")$code, "reserved")

  # Across the corpus: rows naming one address value agree on the code.
  v <- read_corpus("verdict-vectors.tsv")
  rows <- v[
    v$layer == "L0" &
      v$status == "active" &
      v$policy == "default" &
      v$group %in% c("ipv6-spelling", "ipv6-literal", "embedding") &
      v$code != "parse",
  ]
  literal <- sub("^http://\\[([^]]*)\\].*$", "\\1", rows$input)
  value <- raddr::addr_format(raddr::addr_pton(literal))
  for (key in unique(value[duplicated(value)])) {
    same <- which(value == key)
    codes <- vapply(same, function(i) inspect_row(rows[i, ]), character(1))
    expect_length(unique(codes), 1L)
  }
})

# §3.4: classifying the raw host reinstates the verified `0177.0.0.1` bypass
# (ipaddress and raddr read it as 177.0.0.1; libcurl dials 127.0.0.1). The
# address layer is fed libcurl's parse of the wire string, never raw input.
test_that("the address layer reads libcurl's host, never the raw input", {
  hop <- ssrfr:::parse_hop("http://0177.0.0.1/", ssrf_policy())
  expect_null(hop$finding)
  expect_identical(hop$address, "127.0.0.1")
  expect_identical(hop$wire, "http://127.0.0.1/")
  expect_identical(
    ssrfr:::address_gates(hop$address, ssrf_policy())$finding$code,
    "loopback"
  )
  # The raw spelling itself refuses first, whatever it decodes to.
  expect_identical(
    ssrf_inspect_url("http://0177.0.0.1/")$code,
    "numeric-literal"
  )
  expect_identical(
    ssrf_inspect_url("http://010.0.0.1/")$code,
    "numeric-literal"
  )
})

# §4.1, clarified 2026-09-24: libcurl is handed the A-label host. With IDN
# support built in, libcurl dials the A-label of a U-label host while
# curl_parse_url() reports the U-label, so a pin keyed on it would not engage.
test_that("the wire string carries an ASCII A-label host", {
  for (url in c(
    "http://bücher.example/",
    "http://BÜCHER.EXAMPLE/x",
    "http://ß.example/"
  )) {
    hop <- ssrfr:::parse_hop(url, ssrf_policy())
    expect_null(hop$finding)
    host <- curl::curl_parse_url(hop$wire)$host
    expect_false(grepl("[^\\x21-\\x7e]", host, perl = TRUE), label = url)
    expect_match(host, "^xn--", label = url)
    expect_identical(host, hop$host)
  }
  # The record reports the A-label the decision used (S4).
  expect_identical(
    ssrf_inspect_url("http://bücher.example/")$host,
    "xn--bcher-kva.example"
  )
  # A host rurl leaves without an A-label never reaches the wire.
  expect_false(ssrfr:::hosts_agree("bücher.example", "bücher.example"))
})

# §12: steps 3-5 read the scheme, userinfo and effective port from libcurl's
# parse of the wire string, the values libcurl acts on, never from rurl's.
test_that("scheme, userinfo and port come from libcurl's parse", {
  curl_reads <- function(...) {
    function(url) {
      c(list(url = url, host = "example.com", path = "/"), list(...))
    }
  }
  local_mocked_bindings(
    dep_curl_parse = curl_reads(scheme = "http", port = "6379")
  )
  expect_identical(ssrf_inspect_url("http://example.com/")$code, "port")

  local_mocked_bindings(
    dep_curl_parse = curl_reads(scheme = "http", user = "u")
  )
  expect_identical(ssrf_inspect_url("http://example.com/")$code, "userinfo")

  local_mocked_bindings(dep_curl_parse = curl_reads(scheme = "https"))
  res <- ssrf_inspect_url(
    "http://example.com/",
    ssrf_policy(allow_schemes = "http")
  )
  expect_identical(res$code, "scheme")

  local_mocked_bindings(dep_curl_parse = curl_reads(scheme = "http"))
  res <- ssrf_inspect_url("http://example.com:8080/")
  expect_identical(res$code, NA_character_)
  expect_identical(res$port, 80L)
})

test_that("the wire string drops the fragment and keeps port and query", {
  hop <- ssrfr:::parse_hop(
    "http://Example.COM:8080/a/../b?q=1#frag",
    ssrf_policy(allow_ports = 8080)
  )
  expect_null(hop$finding)
  expect_identical(hop$wire, "http://example.com:8080/b?q=1")
  expect_identical(hop$port, 8080L)
})

test_that("a redirect reference resolves against the previous hop", {
  base <- "http://example.com/a/b"
  expect_identical(
    ssrf_inspect_url("//127.0.0.1/", base = base)$code,
    "loopback"
  )
  rel <- ssrf_inspect_url("../c?x=1", base = base)
  expect_identical(rel$code, NA_character_)
  expect_identical(rel$host, "example.com")
  # Without a base, a relative reference is a parse refusal (§3.2).
  expect_identical(ssrf_inspect_url("../c")$code, "parse")
  # An https hop redirecting to http is a downgrade (§12 step 3).
  expect_identical(
    ssrf_inspect_url("http://example.com/", base = "https://example.com/")$code,
    "downgrade"
  )
  expect_identical(
    ssrf_inspect_url("/next", base = "https://example.com/")$code,
    NA_character_
  )
  # A base that does not parse leaves nothing to resolve against.
  expect_identical(ssrf_inspect_url("/x", base = "not a url")$code, "parse")
  # A numeric spelling in the reference itself still refuses.
  expect_identical(
    ssrf_inspect_url("//0x7f.1/", base = base)$code,
    "numeric-literal"
  )
})

test_that("the URL length limit counts octets before any parse", {
  policy <- ssrf_policy(max_url_length = 20)
  expect_identical(
    ssrf_inspect_url("http://example.com/", policy)$code,
    NA_character_
  )
  long <- ssrf_inspect_url("http://example.com/xy", policy)
  expect_identical(long$code, "parse")
  expect_identical(long$detail$limit, "max_url_length")
  expect_identical(long$step, 1L)
})

test_that("address_gates() classifies one resolved address for L1", {
  policy <- ssrf_policy(allow_ranges = "10.0.0.0/8")
  expect_null(ssrfr:::address_gates("10.1.2.3", policy)$finding)
  expect_identical(
    ssrfr:::address_gates("10.1.2.3", ssrf_policy())$finding$code,
    "private"
  )
  expect_identical(
    ssrfr:::address_gates("::ffff:169.254.169.254", policy)$finding$code,
    "cloud-metadata"
  )
  expect_identical(
    ssrfr:::address_gates("not an address", policy)$finding$code,
    "malformed-address"
  )
  expect_null(ssrfr:::address_gates("93.184.216.34", policy)$finding)
})

test_that("an inspection prints its facts without userinfo", {
  res <- ssrf_inspect_url("http://alice:s3cret@10.0.0.1/p")
  expect_identical(res$code, "userinfo")
  expect_true(res$userinfo)
  out <- paste(capture.output(print(res)), collapse = "\n")
  expect_match(out, "userinfo", fixed = TRUE)
  expect_match(out, "not a defense", fixed = TRUE)
  expect_no_match(out, "alice", fixed = TRUE)
  expect_no_match(out, "s3cret", fixed = TRUE)
  expect_false(any(grepl("s3cret", unlist(res), fixed = TRUE)))

  clean <- paste(
    format(ssrf_inspect_url("https://example.com/")),
    collapse = "\n"
  )
  expect_match(clean, "none at L0", fixed = TRUE)
})

test_that("a malformed argument is an invalid-argument error", {
  cls <- "ssrfr_error_invalid_argument"
  expect_error(ssrf_inspect_url(NA_character_), class = cls)
  expect_error(ssrf_inspect_url(c("http://a/", "http://b/")), class = cls)
  expect_error(ssrf_inspect_url(1), class = cls)
  expect_error(ssrf_inspect_url("http://a/", policy = list()), class = cls)
  expect_error(ssrf_inspect_url("http://a/", base = 1), class = cls)
  expect_error(ssrf_inspect_url("http://a/", base = NA_character_), class = cls)
  for (layer in list("L2", "l1", c("L0", "L1"), NA_character_, 1, TRUE)) {
    expect_error(ssrf_inspect_url("http://a/", layer = layer), class = cls)
  }
})

# r-binding.md §7: L0 makes no network call. Every network entry point of
# curl and raddr is made to fail, then the whole L0 golden table runs.
test_that("L0 makes no network call", {
  local_no_network()
  # Positive control: the tripwires are live.
  expect_error(curl::nslookup("example.com"), "network entry point")
  expect_error(
    curl::curl_fetch_memory("http://example.com/"),
    "network entry point"
  )
  expect_error(curl::new_handle(), "network entry point")
  expect_error(raddr::addr_getaddrinfo("example.com"), "network entry point")

  v <- read_corpus("verdict-vectors.tsv")
  rows <- v[v$status == "active", ]
  got <- vapply(seq_len(nrow(rows)), function(i) inspect_row(rows[i, ]), "")
  l0 <- rows$layer == "L0"
  expect_identical(got[l0], rows$code[l0])
  expect_true(all(got[!l0] %in% c("-", rows$code[!l0])))

  p <- read_corpus("parse-vectors.tsv")
  p <- p[p$status == "active", ]
  outcomes <- vapply(
    p$input,
    function(x) parse_row(x)$outcome,
    "",
    USE.NAMES = FALSE
  )
  expect_identical(outcomes, p$expect)
})
