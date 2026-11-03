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
  read <- address_gates_read(text)
  if (is.null(read)) {
    return(address_gates_malformed(text))
  }
  refused <- address_gates_tier1(read)
  if (!is.null(refused)) {
    return(refused)
  }
  address_gates_policy(read, policy)
}

# address_gates()'s `malformed-address` result: gate 1b, tier 1, with the
# facts raddr reported, or NULL when it failed before reporting them.
address_gates_malformed <- function(text, facts = NULL) {
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

# What raddr reports about `text`: its parsed value `addr`, `family`,
# `reach`, `category`, `embeddings`, its own provider `endpoint` (NA when
# none), the `embedded` provider endpoints, all `endpoints` together, and
# the `facts` address_gates() returns. NULL when any raddr reading fails.
address_gates_read <- function(text) {
  addr <- read_address(text)
  if (is.null(addr)) {
    return(NULL)
  }
  own <- address_gates_classify(addr)
  if (is.null(own)) {
    return(NULL)
  }
  embedded <- embedded_endpoints(own$embeddings)
  if (is.null(embedded)) {
    return(NULL)
  }
  endpoint <- own$endpoint
  c(
    list(text = text, addr = addr),
    own,
    list(
      embedded = embedded,
      endpoints = c(endpoint[!is.na(endpoint)], embedded),
      facts = list(
        address = text,
        family = own$family,
        reachability = own$reach,
        category = own$category,
        embeddings = own$embeddings,
        provider_endpoint = endpoint
      )
    )
  )
}

# raddr's facts about the parsed address `addr` itself: `reach`,
# `category`, `family`, `embeddings` and its provider `endpoint` (NA when
# none). NULL when any reading fails.
address_gates_classify <- function(addr) {
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
    return(NULL)
  }
  list(
    reach = reach,
    category = category,
    family = family,
    embeddings = embeddings,
    endpoint = endpoint
  )
}

# address_gates()'s refusal as `code` at `gate` and `tier`, with the detail
# the facts in `read` carry: the category, the first embedding's kind, and
# for `cloud-metadata` the provider kind of the first endpoint.
address_gates_refuse <- function(read, code, gate, tier) {
  detail <- list(gate = gate, tier = tier, category = read$category)
  if (nrow(read$embeddings)) {
    detail$embedding_kind <- read$embeddings$kind[[1L]]
  }
  if (identical(code, "cloud-metadata") && length(read$endpoints)) {
    detail$provider_kind <- provider_kind(read$endpoints[[1L]])
  }
  finding <- do.call(
    new_finding,
    c(list(code, 8L, address = read$text), detail)
  )
  list(finding = finding, facts = read$facts)
}

# Tier 1 (§5.0): reachability NA, or FALSE or a provider endpoint derived
# from an embedded address. No rule of the policy reaches it. A refusal, or
# NULL when tier 1 does not refuse.
address_gates_tier1 <- function(read) {
  embeddings <- read$embeddings
  if (is.na(read$reach) || anyNA(embeddings$reachability)) {
    code <- fact_code(embeddings, read$category, read$endpoints)
    return(address_gates_refuse(read, code, "1b", 1L))
  }
  if (length(read$embedded)) {
    return(address_gates_refuse(read, "cloud-metadata", "2", 1L))
  }
  if (!all(embeddings$reachability)) {
    code <- fact_code(embeddings, read$category, read$endpoints)
    return(address_gates_refuse(read, code, "1c", 1L))
  }
  NULL
}

# Tiers 2-4 (§5.0) on an address tier 1 passed: the caller's deny ranges,
# then its allow ranges against the built-ins. A refusal, or the admission.
address_gates_policy <- function(read, policy) {
  refused <- address_gates_tier2(read, policy)
  if (!is.null(refused)) {
    return(refused)
  }
  address_gates_tiers34(read, policy)
}

# Tier 2: a caller deny range. A refusal, or NULL when no deny range holds
# the address.
address_gates_tier2 <- function(read, policy) {
  denied <- read_within_any(read$addr, policy$deny_ranges)
  if (is.null(denied)) {
    return(address_gates_malformed(read$text, read$facts))
  }
  if (denied) {
    return(address_gates_refuse(read, "range-denied", "3", 2L))
  }
  NULL
}

# Tiers 3 and 4 on an address no deny range holds: a refusal, or the
# admission.
address_gates_tiers34 <- function(read, policy) {
  addr <- read$addr
  endpoint <- read$endpoint

  # Tier 3: a caller allow range overrides tier 4 for this address, except
  # that only an exact entry reopens a provider endpoint.
  allowed <- read_within_any(addr, policy$allow_ranges)
  family <- read$family
  exact <- if (is.na(endpoint)) FALSE else exact_allow(addr, family, policy)
  if (is.null(allowed) || is.null(exact)) {
    return(address_gates_malformed(read$text, read$facts))
  }

  # Tier 4: the built-ins, gate 2's table and gate 1a.
  if (!is.na(endpoint) && !exact) {
    return(address_gates_refuse(read, "cloud-metadata", "2", 4L))
  }
  if (allowed || read$reach) {
    return(list(finding = NULL, facts = read$facts))
  }
  code <- fact_code(read$embeddings, read$category, read$endpoints)
  address_gates_refuse(read, code, "1a", 4L)
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
