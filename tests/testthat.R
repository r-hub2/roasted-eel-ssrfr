Sys.setenv(CURL_SSL_BACKEND = "openssl", NOT_CRAN = "true")
library(testthat)
library(ssrfr)

test_check("ssrfr")
