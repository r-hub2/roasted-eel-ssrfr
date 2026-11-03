# Misuse conditions (ssrfr-v1.md §6.6).

test_that("every misuse kind has the class vector §6.6 names", {
  classes <- ssrf_vocabulary("condition_classes")
  for (i in seq_len(nrow(classes))) {
    cond <- new_ssrfr_error(classes$kind[i], "message", fn = "ssrf_policy")
    expect_s3_class(
      cond,
      c(classes$class[i], "ssrfr_error", "error", "condition"),
      exact = TRUE
    )
    expect_identical(cond$kind, classes$kind[i])
    expect_identical(conditionMessage(cond), "message")
  }
  expect_identical(
    classes$class,
    paste0("ssrfr_error_", classes$kind)
  )
})

test_that("a condition records the bare function name, not the call", {
  cond <- new_ssrfr_error("invalid_policy", "message", fn = "ssrf_policy")
  expect_identical(conditionCall(cond), quote(ssrf_policy()))
  expect_null(conditionCall(new_ssrfr_error("invalid_argument", "message")))
})

test_that("a signaled condition is caught by its kind and by its parent", {
  expect_error(
    abort_ssrfr("spent_binding", "spent", fn = "ssrf_fetch"),
    class = "ssrfr_error_spent_binding"
  )
  expect_error(
    abort_ssrfr("budget_change", "budget", fn = "ssrf_prepare_hop"),
    class = "ssrfr_error"
  )
})

test_that("an unknown kind is refused", {
  expect_error(new_ssrfr_error("invalid_url", "message"), "unknown")
  expect_error(new_ssrfr_error(c("invalid_policy", "invalid_from"), "m"))
})
