# General helpers with no home in one guard layer.

# `x`, or `default` when `x` is NULL. Base R has no such operator below 4.4.0.
default_if_null <- function(x, default) if (is.null(x)) default else x

# Every ssrfr class prints its format() method, one element per line. The
# methods share this one function rather than five copies of its body.
print_formatted <- function(x, ...) {
  cat(format(x, ...), sep = "\n")
  invisible(x)
}

#' @export
print.ssrfr_binding <- print_formatted

#' @export
print.ssrfr_inspection <- print_formatted

#' @export
print.ssrfr_outcome <- print_formatted

#' @export
print.ssrfr_policy <- print_formatted

#' @export
print.ssrfr_response <- print_formatted
