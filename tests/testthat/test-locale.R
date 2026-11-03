# Same input, same decision, whatever the locale (ssrfr-v1.md §5.0, §5.3):
# case folding is ASCII-only, so a locale whose case mapping is not ASCII's,
# Turkish above all (dotless ı, dotted İ), changes no decision.
#
# The decisions run under C in this process, which every machine has, and
# again in a fresh R process for each locale in `hostile` this machine has. A
# fresh process, because stringi, which rurl uses, takes ICU's default locale
# from the environment when it loads: Sys.setlocale() afterwards changes
# LC_CTYPE and LC_COLLATE, which base R's tolower() and regex read, but not
# ICU's. Non-ASCII text is built with intToUtf8(), so it is marked UTF-8
# whatever the locale of the process that runs it.

# Locales whose case mapping of I and i is not ASCII's (Turkish, Azeri), or
# that map an accented I specially (Lithuanian), under their usual names.
hostile_locales <- c(
  "tr_TR.UTF-8",
  "tr_TR.ISO8859-9",
  "tr_TR.iso88599",
  "az_AZ.UTF-8",
  "lt_LT.UTF-8"
)

test_that("decisions do not depend on the locale's case mapping", {
  # Every decision below, as one string each, from one self-contained
  # function: it runs here and, shipped as it is, in another process.
  decide <- function() {
    dotless <- intToUtf8(0x131L)
    dotted <- intToUtf8(0x130L)
    outcome <- function(code) {
      tryCatch(
        {
          x <- testthat::with_mocked_bindings(
            code,
            dep_nslookup = function(query) "93.184.216.34",
            .package = "ssrfr"
          )
          if (inherits(x, "ssrfr_inspection")) {
            paste("code", x$code)
          } else if (inherits(x, "ssrfr_refusal")) {
            paste("refuse", x$code)
          } else if (inherits(x, "ssrfr_binding")) {
            paste("binding", x$origin$host, toString(x$request$carry))
          } else if (is.character(x)) {
            paste("value", toString(x))
          } else {
            paste("other", class(x)[[1L]])
          }
        },
        error = function(e) paste("error", class(e)[[1L]])
      )
    }
    deny <- function() {
      ssrfr::ssrf_policy(deny_hosts = c("WIKI.example", ".INTERNAL.example"))
    }
    deny_dotted <- function() {
      ssrfr::ssrf_policy(deny_hosts = paste0("W", dotted, "KI.example"))
    }
    inspect <- function(url, policy = ssrfr::ssrf_policy()) {
      ssrfr::ssrf_inspect_url(url, policy)
    }
    prepare <- function(request, url = "http://93.184.216.34/", policy = NULL) {
      policy <- if (is.null(policy)) ssrfr::ssrf_policy() else policy
      ssrfr::ssrf_prepare_hop(url, policy, request = request)
    }
    c(
      rules = outcome(deny()$deny_hosts),
      rule_dotted = outcome(deny_dotted()$deny_hosts),
      host = outcome(inspect("http://wiki.example/", deny())),
      host_upper = outcome(inspect("http://WIKI.EXAMPLE/", deny())),
      host_mixed = outcome(inspect("http://Wiki.Example./", deny())),
      host_dotless = outcome(
        inspect(paste0("http://w", dotless, "ki.example/"), deny())
      ),
      host_dotted = outcome(
        inspect(paste0("http://W", dotted, "KI.example/"), deny())
      ),
      host_dotted_rule = outcome(
        inspect(paste0("http://w", dotted, "ki.example/"), deny_dotted())
      ),
      subdomain_upper = outcome(
        inspect("http://API.INTERNAL.EXAMPLE/", deny())
      ),
      subdomain_bare = outcome(inspect("http://INTERNAL.example/", deny())),
      metadata = outcome(inspect("http://METADATA.GOOGLE.INTERNAL/")),
      metadata_allowed = outcome(
        inspect(
          "http://METADATA.GOOGLE.INTERNAL/",
          ssrfr::ssrf_policy(allow_hosts = "METADATA.GOOGLE.INTERNAL")
        )
      ),
      prepare_denied = outcome(prepare(list(), "http://WIKI.EXAMPLE/", deny())),
      prepare_admitted = outcome(prepare(list(), "http://OK.EXAMPLE/", deny())),
      marker = outcome(
        prepare(list(headers = c(`X-ALIYUN-ECS-METADATA-TOKEN` = "t")))
      ),
      marker_expiry = outcome(
        prepare(list(headers = c(`METADATA-TOKEN-EXPIRY-SECONDS` = "60")))
      ),
      transport_owned = outcome(
        prepare(list(headers = c(`TRANSFER-ENCODING` = "chunked")))
      ),
      carry_authorization = outcome(
        prepare(list(
          headers = c(AUTHORIZATION = "Basic eDp5"),
          carry = "AUTHORIZATION"
        ))
      ),
      carry = outcome(
        prepare(list(headers = c(`X-TRACE-ID` = "1"), carry = "X-Trace-Id"))
      )
    )
  }
  environment(decide) <- globalenv()
  expected <- c(
    rules = "value wiki.example, .internal.example",
    rule_dotted = "value xn--wiki-rwc.example",
    host = "code host-denied",
    host_upper = "code host-denied",
    host_mixed = "code host-denied",
    host_dotless = "code NA",
    host_dotted = "code NA",
    host_dotted_rule = "code host-denied",
    subdomain_upper = "code host-denied",
    subdomain_bare = "code NA",
    metadata = "code cloud-metadata",
    metadata_allowed = "code NA",
    prepare_denied = "refuse host-denied",
    prepare_admitted = "binding ok.example ",
    marker = "error ssrfr_error_invalid_request",
    marker_expiry = "error ssrfr_error_invalid_request",
    transport_owned = "error ssrfr_error_invalid_request",
    carry_authorization = "error ssrfr_error_invalid_request",
    carry = "binding 93.184.216.34 x-trace-id"
  )

  local({
    withr::local_locale(c(LC_CTYPE = "C", LC_COLLATE = "C"))
    expect_identical(decide(), expected, label = "decisions under C")
  })

  # The package under test: installed under R CMD check, a source tree under
  # test_local().
  path <- getNamespaceInfo("ssrfr", "path")
  in_locale <- function(path, locale, decide) {
    Sys.setlocale("LC_ALL", locale)
    if (dir.exists(file.path(path, "Meta"))) {
      loadNamespace("ssrfr", lib.loc = dirname(path))
    } else {
      pkgload::load_all(path, quiet = TRUE)
    }
    list(ctype = Sys.getlocale("LC_CTYPE"), decisions = decide())
  }
  environment(in_locale) <- globalenv()
  accepts <- function(locale) {
    old <- Sys.getlocale("LC_CTYPE")
    on.exit(Sys.setlocale("LC_CTYPE", old), add = TRUE)
    nzchar(suppressWarnings(Sys.setlocale("LC_CTYPE", locale)))
  }
  hostile <- if (requireNamespace("callr", quietly = TRUE)) {
    Filter(accepts, hostile_locales)
  }
  for (locale in hostile) {
    child <- callr::r(
      in_locale,
      args = list(path = path, locale = locale, decide = decide),
      env = c(callr::rcmd_safe_env(), LANG = locale, LC_ALL = locale)
    )
    # The child really ran under `locale`, so a Turkish locale this machine
    # has is one the decisions met.
    expect_identical(child$ctype, locale)
    expect_identical(
      child$decisions,
      expected,
      label = paste("decisions under", locale)
    )
  }
})
