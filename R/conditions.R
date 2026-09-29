# Misuse conditions (ssrfr-v1.md §6.6). Every one is built with base R's
# errorCondition(), with the class vector
# c("ssrfr_error_<kind>", "ssrfr_error", "error", "condition") and the kind as a
# data field. The kinds are the closed domain `condition_classes`
# (R/vocabulary.R), so a new kind is a version bump there, not an edit here.
#
# Redaction (§2.3): a message never quotes a value the caller passed, only the
# argument's name and the position of the offending entry, so no message can
# carry userinfo, a header value, a body or a proxy value. The call recorded on
# the condition is the bare function name, `ssrf_policy()`, never the deparsed
# call, which would print every argument value next to the message.

# The kinds of misuse condition, read from the closed domain.
condition_kinds <- function() {
  domain_condition_classes()$kind
}

# Builds a misuse condition. `fn` names the exported function the caller
# called; `...` adds data fields (never a caller-supplied value).
new_ssrfr_error <- function(kind, message, fn = NULL, ...) {
  if (
    !is.character(kind) || length(kind) != 1L || !kind %in% condition_kinds()
  ) {
    stop("internal error: unknown ssrfr error kind", call. = FALSE)
  }
  errorCondition(
    message,
    ...,
    kind = kind,
    class = c(paste0("ssrfr_error_", kind), "ssrfr_error"),
    call = if (is.null(fn)) NULL else call(fn)
  )
}

# Signals a misuse condition.
abort_ssrfr <- function(kind, message, fn = NULL, ...) {
  stop(new_ssrfr_error(kind, message, fn = fn, ...))
}
