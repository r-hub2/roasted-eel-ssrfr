# L1, resolved inspection (ssrfr-v1.md §1, §1.2): steps 7 and 8 of the
# request lifecycle (§12) for a hop whose host is a name. The name is
# resolved exactly once (INV-5), every address the one resolver call returns
# is kept (INV-4) and classified by address_gates() with each of its
# embeddings (§5, §5.2), and one refused address refuses the whole set. L1
# returns evidence, the answer set and each address's facts, not a roll-up
# (§1.2); it is not a defense.
#
# resolve_hop() is the internal step the guarded fetch (L2) reuses: it takes
# a hop parse_hop() and host_policy() passed and returns the validated
# addresses, the only ones a connection may use (INV-5), with per-address
# facts. The resolver is reached only through dep_nslookup()
# (R/dependencies.R), looked up by name at call time, so there is no public
# resolver argument and tests mock the seam (r-binding.md §3, §7).

# The resolver query for a host name (§5.0, "Names resolve as absolute"):
# libcurl's host with a single trailing root dot, so no DNS search suffix
# applies. The dot is on the query only; the host itself, and with it the
# Host header, SNI and the pin key, keeps libcurl's spelling.
absolute_query <- function(host) {
  paste0(sub("[.]$", "", host), ".")
}

# An operational failure found while inspecting a hop (§6.2, §6.6): a cause,
# never a reason code, with operator detail as new_finding() carries it.
new_cause_finding <- function(cause, step, host = NA_character_, ...) {
  list(
    cause = cause,
    host = host,
    address = NA_character_,
    detail = c(list(step = as.integer(step)), list(...))
  )
}

# Steps 7 and 8 for a hop whose host is a name and which steps 1-6 passed.
# Returns a list:
#   query      the resolver query: the host, made absolute
#   answers    the resolver's answers as it returned them, in its order, or
#              NULL when the call failed
#   addresses  one record per answer, in the resolver's order, when every
#              answer is an address: `address` (the answer), `finding` (the
#              refusal gates 1-3 report for it, or NULL) and `facts` (raddr's
#              facts, NULL when raddr failed); NULL otherwise
#   finding    NULL, or the hop's outcome: the failure `unresolvable` when the
#              resolver errs, answers nothing, or answers something raddr
#              cannot read as an address (§6.6, INV-11); else the first
#              refusal in resolver order, which refuses the whole set (INV-4)
#   validated  the answers every gate passed, which alone a connection may
#              use: every answer when `finding` is NULL, character() otherwise
resolve_hop <- function(hop, policy) {
  out <- list(
    query = absolute_query(hop$host),
    answers = NULL,
    addresses = NULL,
    finding = NULL,
    validated = character()
  )
  fail <- function(check) {
    out$finding <- new_cause_finding(
      "unresolvable",
      7L,
      host = hop$host,
      check = check
    )
    out
  }

  # Step 7: one resolver call, every answer kept.
  answers <- read_answers(out$query)
  if (is.null(answers)) {
    return(fail("resolver-error"))
  }
  out$answers <- answers
  if (!length(answers)) {
    return(fail("empty"))
  }
  readable <- lapply(answers, read_is_address)
  if (any(vapply(readable, isFALSE, logical(1L)))) {
    return(fail("unparseable"))
  }

  # Step 8: gates 1-3 on every answer, each with its embeddings. An answer
  # raddr fails on refuses as `malformed-address` inside address_gates().
  out$addresses <- lapply(answers, function(text) {
    gates <- address_gates(text, policy)
    list(address = text, finding = gates$finding, facts = gates$facts)
  })
  for (record in out$addresses) {
    if (!is.null(record$finding)) {
      out$finding <- record$finding
      out$finding$host <- hop$host
      return(out)
    }
  }
  out$validated <- answers
  out
}
