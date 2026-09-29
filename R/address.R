# Gates 1-3 of ssrfr-v1.md §5 on one address, with the address dimension of
# §5.0's precedence and §6.5's mapping from raddr facts to a reason code.
#
# address_gates() takes one address as canonical text: a literal host from
# libcurl's parse with its brackets removed (L0), or one answer of the
# resolver (L1). raddr parses it (r-binding.md §2.6) and classifies it;
# ssrfr only reads the facts and applies policy. Every raddr call goes through
# a guarded reading (R/dependencies.R); one that fails refuses the address as
# `malformed-address` (§5.1, §6.5, INV-11), never as an R error.

# The embedding kinds whose extracted address is the destination, which gate 2
# reads (§5). 6to4, Teredo and ISATAP carry tunnel underlay instead.
destination_embedding_kinds <- c(
  "ipv4_mapped",
  "ipv4_translated",
  "ipv4_compatible",
  "nat64_wk",
  "nat64_local",
  "nat64_nsp"
)

# raddr embedding kinds and their codes (§6.5).
embedding_kind_codes <- c(
  ipv4_mapped = "ipv4-mapped",
  ipv4_translated = "ipv4-translated",
  ipv4_compatible = "ipv4-compatible",
  nat64_wk = "nat64",
  nat64_local = "nat64",
  nat64_nsp = "nat64",
  "6to4" = "6to4",
  teredo = "teredo",
  isatap = "isatap"
)

# raddr categories with a code of their own (§6.5); every other category that
# refuses maps to `reserved`.
named_category_codes <- c(
  loopback = "loopback",
  private = "private",
  link_local = "link-local",
  unspecified = "unspecified",
  this_network = "this-network",
  shared = "shared",
  multicast = "multicast"
)

# A finding: the reason code the facts carry under the policy, and operator
# detail naming the lifecycle step (§12), the gate and tier (§5, §5.0), and
# the facts behind the code (§6.4). Only values ssrfr derives go into
# `detail`, never a value the caller supplied.
new_finding <- function(
  code,
  step,
  host = NA_character_,
  address = NA_character_,
  ...
) {
  list(
    code = code,
    host = host,
    address = address,
    detail = c(list(step = as.integer(step)), list(...))
  )
}

# Classifies one address (canonical text) and applies gates 1-3. Returns a
# list: `finding`, NULL when no gate refuses, and `facts`, what raddr
# reported (NULL when raddr failed).
address_gates <- function(text, policy) {
  malformed <- function(facts = NULL) {
    list(
      finding = new_finding(
        "malformed-address",
        8L,
        address = text,
        gate = "1b",
        tier = 1L
      ),
      facts = facts
    )
  }
  addr <- read_address(text)
  if (is.null(addr)) {
    return(malformed())
  }
  reach <- read_reachability(addr)
  category <- read_category(addr)
  family <- read_family(addr)
  embeddings <- read_embeddings(addr)
  endpoint <- if (is.null(family)) NULL else provider_endpoint_of(addr, family)
  if (
    is.null(reach) ||
      is.null(category) ||
      is.null(embeddings) ||
      is.null(endpoint)
  ) {
    return(malformed())
  }
  embedded <- embedded_endpoints(embeddings)
  if (is.null(embedded)) {
    return(malformed())
  }
  endpoints <- c(endpoint[!is.na(endpoint)], embedded)
  facts <- list(
    address = text,
    family = family,
    reachability = reach,
    category = category,
    embeddings = embeddings,
    provider_endpoint = endpoint
  )
  refuse <- function(code, gate, tier) {
    detail <- list(gate = gate, tier = tier, category = category)
    if (nrow(embeddings)) {
      detail$embedding_kind <- embeddings$kind[[1L]]
    }
    if (identical(code, "cloud-metadata") && length(endpoints)) {
      detail$provider_kind <- provider_kind(endpoints[[1L]])
    }
    finding <- do.call(new_finding, c(list(code, 8L, address = text), detail))
    list(finding = finding, facts = facts)
  }
  admit <- list(finding = NULL, facts = facts)

  # Tier 1 (§5.0): reachability NA, or FALSE or a provider endpoint derived
  # from an embedded address. No rule of the policy reaches it.
  if (is.na(reach) || anyNA(embeddings$reachability)) {
    return(refuse(fact_code(embeddings, category, endpoints), "1b", 1L))
  }
  if (length(embedded)) {
    return(refuse("cloud-metadata", "2", 1L))
  }
  if (!all(embeddings$reachability)) {
    return(refuse(fact_code(embeddings, category, endpoints), "1c", 1L))
  }

  # Tier 2: a caller deny range.
  denied <- read_within_any(addr, policy$deny_ranges)
  if (is.null(denied)) {
    return(malformed(facts))
  }
  if (denied) {
    return(refuse("range-denied", "3", 2L))
  }

  # Tier 3: a caller allow range overrides tier 4 for this address, except
  # that only an exact entry reopens a provider endpoint.
  allowed <- read_within_any(addr, policy$allow_ranges)
  exact <- if (is.na(endpoint)) FALSE else exact_allow(addr, family, policy)
  if (is.null(allowed) || is.null(exact)) {
    return(malformed(facts))
  }

  # Tier 4: the built-ins, gate 2's table and gate 1a.
  if (!is.na(endpoint) && !exact) {
    return(refuse("cloud-metadata", "2", 4L))
  }
  if (allowed || reach) {
    return(admit)
  }
  refuse(fact_code(embeddings, category, endpoints), "1a", 4L)
}

# §6.5's mapping for a refusal that the reachability facts carry. The most
# specific fact wins: a provider endpoint (gate 2), then the embedding kind,
# then the category; a category without a code of its own is `reserved`.
fact_code <- function(embeddings, category, endpoints) {
  if (length(endpoints)) {
    return("cloud-metadata")
  }
  if (nrow(embeddings)) {
    code <- embedding_kind_codes[embeddings$kind[[1L]]]
    if (!is.na(code)) {
      return(unname(code))
    }
  }
  code <- named_category_codes[category]
  if (is.na(code)) "reserved" else unname(code)
}

# The provider-endpoint rows among the destination embeddings (§5, gate 2):
# a character vector, or NULL when raddr fails on one.
embedded_endpoints <- function(embeddings) {
  out <- character()
  for (i in which(embeddings$kind %in% destination_embedding_kinds)) {
    e <- read_address(embeddings$address[[i]])
    family <- if (is.null(e)) NULL else read_family(e)
    hit <- if (is.null(family)) NULL else provider_endpoint_of(e, family)
    if (is.null(hit)) {
      return(NULL)
    }
    out <- c(out, hit[!is.na(hit)])
  }
  out
}

# The provider-endpoint row that `addr` is, by value: its key, NA_character_
# when it is none, or NULL when raddr fails. A row is written as canonical
# text, so the block for it is the row with a /32 or /128 prefix.
provider_endpoint_of <- function(addr, family) {
  for (row in domain_provider_endpoints()$address) {
    v4 <- !grepl(":", row, fixed = TRUE)
    if (v4 != identical(family, "v4")) {
      next
    }
    hit <- read_within_any(addr, paste0(row, if (v4) "/32" else "/128"))
    if (is.null(hit)) {
      return(NULL)
    }
    if (hit) {
      return(row)
    }
  }
  NA_character_
}

provider_kind <- function(row) {
  table <- domain_provider_endpoints()
  table$kind[match(row, table$address)]
}

# Whether an allow_ranges entry names this provider endpoint exactly: a /32
# or /128 block that contains it (§5.0). NULL when raddr fails.
exact_allow <- function(addr, family, policy) {
  width <- if (identical(family, "v4")) "32" else "128"
  ranges <- policy$allow_ranges
  read_within_any(addr, ranges[sub("^.*/", "", ranges) == width])
}
