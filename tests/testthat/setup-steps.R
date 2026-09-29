# Cucumber step definitions. testthat sources `setup-*.R` before the test files,
# which registers these steps before `cucumber::run()` executes the features.
#
# Guarded on `cucumber` being installed so the suggests-only R CMD check
# (`_R_CHECK_DEPENDS_ONLY_=true`, which CRAN runs) degrades gracefully: with the
# package absent the steps simply are not registered and test-cucumber.R skips.
if (requireNamespace("cucumber", quietly = TRUE)) {
  library(cucumber)

  # policy.feature

  when("I build a policy with no arguments", function(context) {
    context$result <- tryCatch(ssrf_policy(), error = identity)
  })

  when(
    "I build a policy with {string} set to {string}",
    function(
      field,
      entry,
      context
    ) {
      args <- stats::setNames(list(entry), field)
      context$result <- tryCatch(do.call(ssrf_policy, args), error = identity)
    }
  )

  then("the policy is built", function(context) {
    expect_s3_class(context$result, "ssrfr_policy")
  })

  then("its {string} is {int}", function(field, value, context) {
    expect_equal(context$result[[field]], value)
  })

  then("its {string} is {string}", function(field, value, context) {
    expect_identical(context$result[[field]], value)
  })

  then("policy construction fails as {string}", function(class, context) {
    expect_s3_class(context$result, class)
  })

  given(
    "a {string} refusal for the URL {string}",
    function(code, url, context) {
      context$refusal <- new_ssrf_refusal(code, hop = 1, url = url)
    }
  )

  when("I print it", function(context) {
    context$output <- paste(
      capture.output(print(context$refusal)),
      collapse = "\n"
    )
  })

  then("the output contains {string}", function(text, context) {
    expect_match(context$output, text, fixed = TRUE)
  })

  then("the output does not contain {string}", function(text, context) {
    expect_no_match(context$output, text, fixed = TRUE)
  })

  then("its public reason is {string}", function(value, context) {
    expect_identical(ssrf_public_reason(context$refusal), value)
  })
}
