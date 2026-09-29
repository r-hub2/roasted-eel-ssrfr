# The two policy-data tables of R/policy-data.R (ssrfr-v1.md §5 gates 2 and
# 5). Their key sets are pinned to their versions in test-vocabulary.R; these
# tests hold the rows to §5's sourcing rule and to the form matching needs.

test_that("every provider endpoint is a canonical address with a sourced row", {
  table <- ssrf_vocabulary("provider_endpoints")
  a <- raddr::addr_pton(table$address)
  expect_false(anyNA(a))
  # Canonical text, so the key names one value (INV-3).
  expect_identical(raddr::addr_format(a), table$address)
  expect_true(all(table$kind %in% c("instance-metadata", "provider-internal")))
  expect_match(table$source, "^https?://")
  expect_match(table$retrieved, "^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
  expect_true(all(nzchar(table$provider)))
  # The vendor text quoted names the address itself.
  for (i in seq_len(nrow(table))) {
    expect_true(
      grepl(table$address[i], table$quote[i], fixed = TRUE),
      label = paste("quote of", table$address[i])
    )
  }
})

test_that("every metadata hostname is normalized and names a table endpoint", {
  names <- ssrf_vocabulary("metadata_hostnames")
  endpoints <- ssrf_vocabulary("provider_endpoints")$address
  # Stored in matching form: ASCII-lowercase, no trailing root dot (§5.0).
  expect_identical(names$hostname, ssrfr:::normalize_host_name(names$hostname))
  for (name in names$hostname) {
    expect_identical(ssrfr:::normalize_host_rule(name, name), name)
  }
  # §5 gate 5: a name is admitted only as the name of a gate 2 endpoint.
  expect_true(all(names$address %in% endpoints))
  expect_match(names$source, "^https?://")
  expect_match(names$retrieved, "^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
  for (i in seq_len(nrow(names))) {
    expect_true(
      grepl(names$hostname[i], names$quote[i], fixed = TRUE),
      label = paste("quote of", names$hostname[i])
    )
  }
})

test_that("each provider endpoint refuses by value as cloud-metadata", {
  for (address in ssrf_vocabulary("provider_endpoints")$address) {
    host <- if (grepl(":", address, fixed = TRUE)) {
      paste0("[", address, "]")
    } else {
      address
    }
    expect_identical(
      ssrf_inspect_url(paste0("http://", host, "/"))$code,
      "cloud-metadata",
      label = address
    )
  }
})

test_that("each metadata hostname refuses exactly, as cloud-metadata", {
  for (name in ssrf_vocabulary("metadata_hostnames")$hostname) {
    expect_identical(
      ssrf_inspect_url(paste0("http://", name, "/"))$code,
      "cloud-metadata",
      label = name
    )
    # Exact whole-host matching: no subdomain, no suffix.
    expect_true(
      is.na(ssrf_inspect_url(paste0("http://x.", name, "/"))$code),
      label = paste("subdomain of", name)
    )
    expect_true(
      is.na(ssrf_inspect_url(paste0("http://x", name, "/"))$code),
      label = paste("suffix of", name)
    )
  }
})
