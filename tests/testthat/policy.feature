Feature: Policy construction and refusal redaction
  A policy is validated when it is built, so a malformed rule is an error
  rather than a rule that silently matches nothing (ssrfr-v1.md §5.3). A
  refusal names its reason for the operator, never a credential, and projects
  to one value for an untrusted party (§2.3, §6.4).

  Scenario: The default policy builds
    When I build a policy with no arguments
    Then the policy is built
    And its "max_redirects" is 20
    And its "max_url_length" is 8000

  Scenario Outline: A malformed entry is refused at construction
    When I build a policy with "<field>" set to "<entry>"
    Then policy construction fails as "ssrfr_error_invalid_policy"

    Examples:
      | field        | entry          |
      | deny_hosts   | com, ru        |
      | deny_hosts   | *.corp         |
      | allow_hosts  | 10.0.0.1       |
      | deny_ranges  | 192.168.1.1/24 |
      | allow_ranges | 10.0.0.1       |

  Scenario: A subdomain rule is stored normalized
    When I build a policy with "deny_hosts" set to ".Corp."
    Then the policy is built
    And its "deny_hosts" is ".corp"

  Scenario: A printed refusal carries no credentials
    Given a "loopback" refusal for the URL "https://alice:s3cretPW@internal.example/path"
    When I print it
    Then the output contains "code: loopback"
    And the output contains "internal.example/path"
    And the output does not contain "s3cretPW"
    And its public reason is "refused"
