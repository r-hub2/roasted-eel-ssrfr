# The hostname dimension of ssrfr-v1.md §5.0: gate 4 (the caller's
# deny_hosts) and gate 5 (the built-in metadata hostname list), with
# allow_hosts overriding gate 5 only.
#
# Rules and host are normalized the same way (§5.0, "Hostname matching"):
# IDNA A-label, ASCII-lowercased, one trailing root dot removed. The policy
# stores its rules normalized (R/policy.R), and the metadata hostname list is
# written normalized (R/policy-data.R). The host is libcurl's parse of the
# wire string, which carries rurl's A-label host (§4.1), so normalizing it is
# case folding and one dot.

# The matching form of a host name: ASCII-lowercased, one trailing root dot
# removed. Case folding is ASCII-only and ignores the locale (§5.0).
normalize_host_name <- function(host) {
  sub("[.]$", "", ascii_lower(host))
}

# Whether normalized `host` matches any normalized rule: exactly, or as a
# proper subdomain of a rule that begins with `.` (§5.0).
host_rule_match <- function(host, rules) {
  subdomain <- startsWith(rules, ".")
  any(rules[!subdomain] == host) ||
    any(
      endsWith(host, rules[subdomain]) & nchar(host) > nchar(rules[subdomain])
    )
}

# Gates 4 and 5 on a normalized host name. Returns a finding, or NULL when
# the hostname dimension permits the name.
hostname_gates <- function(name, policy) {
  refuse <- function(code, gate, tier) {
    new_finding(code, 6L, host = name, gate = gate, tier = tier)
  }
  # Tier 2: a caller deny rule.
  if (host_rule_match(name, policy$deny_hosts)) {
    return(refuse("host-denied", "4", 2L))
  }
  # Tier 3: a caller allow rule overrides the built-in list for this name.
  if (host_rule_match(name, policy$allow_hosts)) {
    return(NULL)
  }
  # Tier 4: the built-in metadata hostname list, exact names only.
  names <- domain_metadata_hostnames()
  row <- match(name, names$hostname)
  if (!is.na(row)) {
    finding <- refuse("cloud-metadata", "5", 4L)
    finding$detail$provider_kind <- provider_kind(names$address[[row]])
    return(finding)
  }
  NULL
}
