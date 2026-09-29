# The test harness's own helpers (helper-transport.R).

# Holds `host`:`port` with an httpuv server in a background process, killed
# when the calling test ends. Returns whether the server answered within 15 s.
local_held_port <- function(host, port, env = parent.frame()) {
  skip_if_not_installed("httpuv")
  skip_if_not_installed("callr")
  server <- callr::r_bg(
    function(host, port) {
      httpuv::startServer(
        host,
        port,
        list(call = function(req) {
          list(status = 501L, headers = list(), body = "stranger")
        })
      )
      repeat {
        httpuv::service(100)
      }
    },
    args = list(host = host, port = port)
  )
  withr::defer(server$kill(), envir = env)
  target <- if (grepl(":", host, fixed = TRUE)) paste0("[", host, "]") else host
  t0 <- Sys.time()
  repeat {
    up <- tryCatch(
      {
        curl::curl_fetch_memory(
          paste0("http://", target, ":", port, "/"),
          handle = curl::new_handle(timeout = 1, noproxy = "*")
        )
        TRUE
      },
      error = function(e) FALSE
    )
    waited <- difftime(Sys.time(), t0, units = "secs")
    if (up || !server$is_alive() || waited > 15) {
      return(up)
    }
    Sys.sleep(0.1)
  }
}

# SSRF-diqojrtv: serverSocket() binds every address, and on macOS that bind
# succeeds while another process listens on 127.0.0.1 alone. A test that then
# connects to 127.0.0.1 reaches the stranger.
test_that("free_port() skips a port another process holds on 127.0.0.1", {
  held <- free_port()
  expect_true(local_held_port("127.0.0.1", held))
  spare <- free_port(setdiff(sample(30000:60000, 50), held))
  expect_identical(free_port(c(held, spare)), spare)
})

test_that("free_port() skips a port another process holds on ::1", {
  skip_if_not(isTRUE(curl::curl_version()$ipv6), "libcurl has no IPv6")
  held <- free_port()
  skip_if_not(local_held_port("::1", held), "could not serve on ::1")
  spare <- free_port(setdiff(sample(30000:60000, 50), held))
  expect_identical(free_port(c(held, spare)), spare)
})
