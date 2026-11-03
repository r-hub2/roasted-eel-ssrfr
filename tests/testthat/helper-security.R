# Disposition machinery for the OSS Index dependency audit in
# test-security.R. The allow-list lives here rather than in the test file
# because more than one test block reads it -- the offline well-formedness
# check and the network audit itself.
#
# WHY THESE ROWS. The contract this file implements is "every reported
# advisory has a current, explicit disposition", replacing "the scan reports
# nothing" (SEOR-fkvlzltx). ssrfr imports `curl` directly, and measured
# 2026-10-18 with live OSS Index credentials the hard dependency closure
# reports exactly four advisories, all against curl 8.1.0, CRAN's current
# release, so no available version clears any of them. OSS Index matches the
# R package's version number against libcurl's affected ranges. Each row
# below says why the advisory does not reach a fetch made through ssrfr. Rows
# are added only for advisories the audit reports today: rule B fails a row
# that is not currently reported, so an anticipatory row is stale on arrival.
#
# Three rules keep the list honest. test-security.R enforces them:
#
#   A  UNEXPECTED  an advisory reported and not allow-listed FAILS. This is
#                  the gate still doing its job.
#   B  STALE       an allow-listed advisory NO LONGER reported FAILS. An
#                  allow-list may not over-permit; a row that has outlived its
#                  justification is deleted, not left to widen the exemption
#                  silently.
#   C  DRIFT       past its review date, or audited at a package version later
#                  than `version_seen`, a row WARNS. Deliberately not a
#                  failure: a calendar date that turns every push red is how a
#                  gate teaches people to reach for --no-verify.
#
# Adding a row is a decision, not a formality. Rule B is what keeps it one.
#
# The reference implementation is seor's.

oss_index_allowlist <- list(
  list(
    id = "CVE-2026-18924",
    package = "curl",
    version_seen = "8.1.0",
    review = as.Date("2026-12-01"),
    reason = paste(
      "CWE-416 use-after-free on HTTP/2 server push over a shared",
      "connection handle (CVSS 9.1). Names a libcurl range covering CRAN's",
      "current curl 8.1.0, so no available version clears it. Unreachable",
      "through ssrfr: the transport pins http_version to HTTP/1.1 and sets",
      "forbid_reuse (R/transport.R), so there is no HTTP/2 connection to",
      "push on, and R's curl cannot set CURLMOPT_PUSHFUNCTION. Re-check",
      "R/transport.R before renewing this row."
    )
  ),
  list(
    id = "CVE-2026-3783",
    package = "curl",
    version_seen = "8.1.0",
    review = as.Date("2026-12-01"),
    reason = paste(
      "CWE-522: an OAuth2 bearer token leaks to a redirect target when",
      ".netrc carries a machine/default entry (CVSS 6.9). Names a libcurl",
      "range covering CRAN's current curl 8.1.0, so no available version",
      "clears it. Unreachable through ssrfr: the transport sets netrc = 0",
      "and followlocation = 0 (R/transport.R), so libcurl neither reads",
      ".netrc nor follows a redirect, and ssrfr's own redirect hop drops",
      "Authorization on any cross-origin hop. Re-check before renewing."
    )
  ),
  list(
    id = "CVE-2026-86410",
    package = "curl",
    version_seen = "8.1.0",
    review = as.Date("2026-12-01"),
    reason = paste(
      "CWE-297: the curl command-line tool installs its SSH host",
      "verification options only for a direct SFTP or SCP transfer, not for",
      "one reached by a redirect (CVSS 5.1). curl.se states libcurl is not",
      "affected; the tool's range covers CRAN's current curl 8.1.0, so no",
      "available version clears it. Unreachable through ssrfr: it drives",
      "libcurl, never the tool, and the transport restricts protocols and",
      "redir_protocols to http,https and sets followlocation = 0",
      "(R/transport.R), so no transfer is SFTP or SCP. Re-check",
      "R/transport.R before renewing this row."
    )
  ),
  list(
    id = "CVE-2026-87865",
    package = "curl",
    version_seen = "8.1.0",
    review = as.Date("2026-12-01"),
    reason = paste(
      "CWE-295: libcurl built on libssh2, with a hashed known_hosts file,",
      "can report a host-key mismatch as a missing key to a",
      "CURLOPT_SSH_KEYFUNCTION callback (CVSS 6.9). Names a libcurl range",
      "covering CRAN's current curl 8.1.0, so no available version clears",
      "it. Unreachable through ssrfr: the transport restricts protocols and",
      "redir_protocols to http,https (R/transport.R), so libcurl never opens",
      "an SFTP or SCP transfer, and ssrfr sets no SSH key callback. Re-check",
      "R/transport.R before renewing this row."
    )
  ),
  list(
    id = "CVE-2026-86414",
    package = "curl",
    version_seen = "8.1.0",
    review = as.Date("2026-12-01"),
    reason = paste(
      "CWE-201: an HTTP proxy answering a CONNECT with 401 instead of 407",
      "makes libcurl send the origin's credentials to the proxy (CVSS 6.5).",
      "Names a libcurl range covering CRAN's current curl 8.1.0, so no",
      "available version clears it. Unreachable through ssrfr: the",
      "transport sets proxy = \"\" and noproxy = \"*\" (R/transport.R), so no",
      "attempt goes through a proxy whatever the environment says.",
      "Re-check R/transport.R before renewing this row."
    )
  ),
  list(
    id = "CVE-2026-87864",
    package = "curl",
    version_seen = "8.1.0",
    review = as.Date("2026-12-01"),
    reason = paste(
      "CWE-130: with CURLOPT_CRLF set, curl advertises the raw byte count",
      "in an IMAP APPEND literal but sends the expanded data, so the",
      "overflow runs as pipelined IMAP commands (CVSS 3.7). Names a libcurl",
      "range covering CRAN's current curl 8.1.0, so no available version",
      "clears it. Unreachable through ssrfr: the transport restricts",
      "protocols and redir_protocols to http,https (R/transport.R), so",
      "libcurl never opens the IMAP transfer an APPEND needs, and nothing",
      "sets crlf. Re-check R/transport.R before renewing this row."
    )
  )
)

# The fields every allow-list row carries, in the order they are documented.
oss_index_allowlist_fields <- c(
  "id",
  "package",
  "version_seen",
  "review",
  "reason"
)

# Problems with a set of allow-list rows, as a character vector; empty when the
# set is well formed. Written as a function returning findings rather than as a
# block of expectations so that it can be exercised against fixtures -- with no
# live rows, a loop of expectations over `oss_index_allowlist` would assert
# nothing at all and still report as a passing test.
oss_index_allowlist_violations <- function(rows) {
  out <- character()

  parses_as_version <- function(x) {
    tryCatch(
      {
        package_version(x)
        TRUE
      },
      error = function(e) FALSE,
      warning = function(w) FALSE
    )
  }

  for (i in seq_along(rows)) {
    row <- rows[[i]]
    label <- sprintf("row %d", i)

    absent <- setdiff(oss_index_allowlist_fields, names(row))
    unknown <- setdiff(names(row), oss_index_allowlist_fields)
    if (length(absent) > 0) {
      out <- c(
        out,
        sprintf("%s: missing field(s): %s", label, toString(absent))
      )
    }
    if (length(unknown) > 0) {
      out <- c(
        out,
        sprintf("%s: unknown field(s): %s", label, toString(unknown))
      )
    }
    if (length(absent) > 0) {
      next
    }

    label <- sprintf("row %d (%s)", i, paste(row$id, collapse = " "))
    if (
      !is.character(row$id) ||
        length(row$id) != 1L ||
        !grepl("^CVE-[0-9]{4}-[0-9]+$", row$id)
    ) {
      out <- c(out, sprintf("%s: `id` is not a single CVE identifier", label))
    }
    if (
      !is.character(row$package) ||
        length(row$package) != 1L ||
        !nzchar(row$package)
    ) {
      out <- c(
        out,
        sprintf("%s: `package` is not a single package name", label)
      )
    }
    if (
      !is.character(row$version_seen) ||
        length(row$version_seen) != 1L ||
        !parses_as_version(row$version_seen)
    ) {
      out <- c(
        out,
        sprintf("%s: `version_seen` is not a parseable version", label)
      )
    }
    if (!inherits(row$review, "Date") || length(row$review) != 1L) {
      out <- c(out, sprintf("%s: `review` is not a single Date", label))
    }
    # A reason long enough to be an argument rather than a placeholder.
    if (
      !is.character(row$reason) ||
        length(row$reason) != 1L ||
        nchar(row$reason) <= 80
    ) {
      out <- c(
        out,
        sprintf("%s: `reason` is missing or too short to be an argument", label)
      )
    }
  }

  ids <- vapply(
    rows,
    function(row) {
      if (is.character(row$id) && length(row$id) == 1L) {
        row$id
      } else {
        NA_character_
      }
    },
    character(1)
  )
  duplicates <- unique(ids[duplicated(ids) & !is.na(ids)])
  if (length(duplicates) > 0) {
    out <- c(
      out,
      sprintf("duplicate allow-list id(s): %s", toString(duplicates))
    )
  }

  out
}

# Flatten an oysteR::audit_description() result to one row per reported
# advisory. The `vulnerabilities` column is a list of per-package lists, empty
# for a clean package, so the zero-advisory case has to survive unlist().
oss_index_reported <- function(audit) {
  ids <- lapply(audit$vulnerabilities, function(v) {
    if (length(v) == 0) {
      return(character())
    }
    vapply(v, function(x) as.character(x$id), character(1))
  })
  data.frame(
    package = rep(as.character(audit$package), lengths(ids)),
    version = rep(as.character(audit$version), lengths(ids)),
    id = as.character(unlist(ids, use.names = FALSE))
  )
}
