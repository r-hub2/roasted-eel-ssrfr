# The two tables ssrfr owns as policy data (ssrfr-v1.md §4, §5, ADR 0004):
# gate 2's provider-endpoint table and gate 5's metadata hostname list. Neither
# is IANA registry data, and raddr assigns both to ssrfr. Each is a closed
# domain (R/vocabulary.R) with its own version stamp, separate from raddr's
# registry snapshot, and tests/testthat/test-vocabulary.R pins each version to
# its key set in both directions.
#
# Every row cites current vendor documentation, the date it was retrieved, and
# the vendor's own text naming the address or name, verbatim (§5). `linklint`'s
# table (packages/core/src/data/cloud-metadata.ts at 8830901) is the starting
# point; the Scaleway and Linode rows are the four §5 adds. Where the page
# linklint cites does not name the address, the row cites the page that does.
#
# Keys are canonical: an address in raddr's canonical text form, a hostname
# ASCII-lowercase with no trailing root dot. Matching is by value, through
# raddr, never by string (INV-3); tests/testthat/test-policy-data.R checks the
# spelling, the family and the hostname-to-endpoint tie.

domain_provider_endpoints <- function() {
  rows <- list(
    c(
      "169.254.169.254",
      "AWS / Azure / GCP / DigitalOcean / OpenStack",
      "instance-metadata",
      paste0(
        "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/",
        "instancedata-data-retrieval.html"
      ),
      paste(
        "To retrieve instance metadata using an IPv6 address, ensure that you",
        "enable and use the IPv6 address of the IMDS [fd00:ec2::254] instead",
        "of the IPv4 address 169.254.169.254."
      )
    ),
    c(
      "fd00:ec2::254",
      "AWS (IPv6 IMDS)",
      "instance-metadata",
      paste0(
        "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/",
        "configuring-instance-metadata-service.html"
      ),
      paste(
        "If you are retrieving instance metadata for EC2 instances over the",
        "IPv6 address, ensure that you enable and use the IPv6 address",
        "instead: [fd00:ec2::254]."
      )
    ),
    c(
      "192.0.0.192",
      "Oracle Cloud",
      "instance-metadata",
      paste0(
        "https://docs.oracle.com/en/cloud/iaas-classic/compute-iaas-cloud/",
        "stcsg/retrieving-instance-metadata.html"
      ),
      paste(
        "The predefined instance metadata fields are stored at",
        "http://192.0.0.192/{version}/metadata."
      )
    ),
    c(
      "100.100.100.200",
      "Alibaba Cloud",
      "instance-metadata",
      paste0(
        "https://www.alibabacloud.com/help/en/ecs/user-guide/",
        "view-instance-metadata/"
      ),
      paste(
        "100.100.100.200 is a link-local address reachable only from within an",
        "ECS instance over its virtual network interface."
      )
    ),
    c(
      "168.63.129.16",
      "Azure (WireServer host channel)",
      "provider-internal",
      paste0(
        "https://learn.microsoft.com/en-us/azure/virtual-network/",
        "what-is-ip-address-168-63-129-16"
      ),
      paste(
        "The virtual machine Agent requires outbound communication over ports",
        "80/tcp and 32526/tcp with WireServer (168.63.129.16)."
      )
    ),
    c(
      "169.254.170.2",
      "AWS (ECS task credentials)",
      "instance-metadata",
      paste0(
        "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/",
        "task-iam-roles.html"
      ),
      paste(
        "New-NetRoute -DestinationPrefix 169.254.170.2/32 -InterfaceIndex",
        "$ifIndex -NextHop $gateway -PolicyStore ActiveStore # credentials API"
      )
    ),
    c(
      "169.254.170.23",
      "AWS (EKS Pod Identity)",
      "instance-metadata",
      paste0(
        "https://docs.aws.amazon.com/eks/latest/userguide/",
        "pod-id-agent-setup.html"
      ),
      paste(
        "The agent uses the loopback (localhost) IP address 169.254.170.23 for",
        "IPv4 and the localhost IP address [fd00:ec2::23] for IPv6."
      )
    ),
    c(
      "fd00:ec2::23",
      "AWS (EKS Pod Identity, IPv6)",
      "instance-metadata",
      paste0(
        "https://docs.aws.amazon.com/eks/latest/userguide/",
        "pod-id-agent-setup.html"
      ),
      paste(
        "The agent uses the loopback (localhost) IP address 169.254.170.23 for",
        "IPv4 and the localhost IP address [fd00:ec2::23] for IPv6."
      )
    ),
    c(
      "169.254.0.23",
      "Tencent Cloud",
      "instance-metadata",
      paste0(
        "http://web.archive.org/web/20260210034812/",
        "https://www.tencentcloud.com/document/product/213/32364"
      ),
      "metadata_base_url = http://169.254.0.23/"
    ),
    c(
      "fd20:ce::254",
      "GCP (IPv6-only instances)",
      "instance-metadata",
      "https://docs.cloud.google.com/compute/docs/metadata/querying-metadata",
      paste(
        "The IPv6 address (only for IPv6-only instances):",
        "http://fd20:ce::254/computeMetadata/v1"
      )
    ),
    c(
      "169.254.42.42",
      "Scaleway",
      "instance-metadata",
      paste0(
        "https://www.scaleway.com/en/docs/instances/reference-content/",
        "manual-configuration-private-ips/"
      ),
      paste(
        "The endpoint for the Scaleway Metadata API is 169.254.42.42/32, and",
        "the gateway depends on your Instance."
      )
    ),
    c(
      "fd00:42::42",
      "Scaleway (IPv6)",
      "instance-metadata",
      paste0(
        "https://github.com/scaleway/scaleway-sdk-go/blob/",
        "25895fc5ce562db9b94242f507ffbb553347a73f/api/instance/v1/",
        "instance_metadata_sdk.go#L22"
      ),
      "metadataAPIv6 = \"http://[fd00:42::42]\""
    ),
    c(
      "fd00:a9fe:a9fe::1",
      "Linode (Akamai)",
      "instance-metadata",
      "https://techdocs.akamai.com/cloud-computing/docs/metadata-service-api",
      paste(
        "the Metadata API is accessible via link-local addresses,",
        "specifically: IPv4: 169.254.169.254 IPv6: fd00:a9fe:a9fe::1,",
        "fe80::a9fe:a9fe"
      )
    ),
    c(
      "fe80::a9fe:a9fe",
      "Linode (Akamai)",
      "instance-metadata",
      "https://techdocs.akamai.com/cloud-computing/docs/metadata-service-api",
      paste(
        "the Metadata API is accessible via link-local addresses,",
        "specifically: IPv4: 169.254.169.254 IPv6: fd00:a9fe:a9fe::1,",
        "fe80::a9fe:a9fe"
      )
    )
  )
  closed_domain(
    "provider_endpoints",
    1L,
    policy_table(
      rows,
      c("address", "provider", "kind", "source", "quote"),
      retrieved = "2026-09-25"
    )
  )
}

domain_metadata_hostnames <- function() {
  google <- paste0(
    "https://docs.cloud.google.com/compute/docs/metadata/",
    "querying-metadata"
  )
  rows <- list(
    c(
      "metadata.google.internal",
      "169.254.169.254",
      "GCP",
      google,
      paste(
        "The DNS name: http://metadata.google.internal/computeMetadata/v1",
        "(Recommended)"
      )
    ),
    c(
      "metadata.goog",
      "169.254.169.254",
      "GCP",
      google,
      "http://metadata.goog/computeMetadata/v1"
    ),
    c(
      "metadata.tencentyun.com",
      "169.254.0.23",
      "Tencent Cloud",
      paste0(
        "http://web.archive.org/web/20260121135137/",
        "https://www.tencentcloud.com/document/product/213/4934"
      ),
      paste(
        "To view all the instance metadata within a running instance, use the",
        "following URI: http://metadata.tencentyun.com/latest/meta-data/"
      )
    ),
    c(
      "api.metadata.cloud.ibm.com",
      "169.254.169.254",
      "IBM Cloud VPC",
      paste0(
        "http://web.archive.org/web/20251206195733/",
        "https://cloud.ibm.com/apidocs/vpc-metadata"
      ),
      paste(
        "When the metadata_service.protocol property is http, the endpoint URL",
        "may contain either the service's IP address http://169.254.169.254 or",
        "the service's hostname http://api.metadata.cloud.ibm.com."
      )
    ),
    c(
      "metadata.exoscale.com",
      "169.254.169.254",
      "Exoscale",
      paste0(
        "https://community.exoscale.com/product/compute/instances/how-to/",
        "cloud-init-user-data/"
      ),
      "curl http://metadata.exoscale.com/latest/meta-data"
    )
  )
  closed_domain(
    "metadata_hostnames",
    1L,
    policy_table(
      rows,
      c("hostname", "address", "provider", "source", "quote"),
      retrieved = "2026-09-25"
    )
  )
}

# Metadata-service request markers (ssrfr-v1.md §2.3): header fields that
# exist only to show a metadata service that a request was meant for it. A
# request plan carrying one is refused at prepare, matched exactly and
# case-insensitively, unless the policy's allow_ranges names a provider
# endpoint exactly (§5.0). The names and their providers are the ratified list
# of §2.3, which admits a name only when vendor documentation shows it sent to
# an endpoint of gate 2's table; the rows cite that section. The list cannot
# be complete: Oracle's marker is `Authorization: Bearer Oracle`.
domain_metadata_headers <- function() {
  spec <- "ssrfr-v1.md \u00a72.3"
  rows <- list(
    c("Metadata", "Azure", spec),
    c("Metadata-Flavor", "GCP", spec),
    c("X-Google-Metadata-Request", "GCP", spec),
    c("X-aws-ec2-metadata-token", "AWS", spec),
    c("X-aws-ec2-metadata-token-ttl-seconds", "AWS", spec),
    c("X-aliyun-ecs-metadata-token", "Alibaba Cloud", spec),
    c("X-aliyun-ecs-metadata-token-ttl-seconds", "Alibaba Cloud", spec),
    c("Metadata-Token", "Linode (Akamai) / Vultr", spec),
    c("Metadata-Token-Expiry-Seconds", "Linode (Akamai)", spec),
    c("X-Metadata-Token-Ttl-Seconds", "Huawei Cloud", spec)
  )
  m <- do.call(rbind, rows)
  colnames(m) <- c("header", "provider", "source")
  closed_domain("metadata_headers", 1L, as.data.frame(m))
}

# Binds rows of equal length into a data frame with the given columns, and
# stamps the retrieval date on each.
policy_table <- function(rows, columns, retrieved) {
  m <- do.call(rbind, rows)
  colnames(m) <- columns
  out <- as.data.frame(m)
  out$retrieved <- retrieved
  out
}
