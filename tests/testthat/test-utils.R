# General helpers (R/utils.R).

test_that("default_if_null() falls back only on NULL", {
  expect_identical(default_if_null(NULL, "fallback"), "fallback")
  expect_identical(default_if_null("given", "fallback"), "given")
  # Values that are empty or missing but not NULL pass through.
  expect_identical(default_if_null(NA_character_, "fallback"), NA_character_)
  expect_identical(default_if_null(character(), "fallback"), character())
  expect_identical(default_if_null(list(), "fallback"), list())
})

test_that("default_if_null() evaluates `default` only when `x` is NULL", {
  expect_identical(
    default_if_null("given", stop("`default` was evaluated")),
    "given"
  )
  expect_error(
    default_if_null(NULL, stop("`default` was evaluated")),
    "`default` was evaluated",
    fixed = TRUE
  )
})
