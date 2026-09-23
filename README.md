# pq-cloud-scan

Find out whether cloud provider endpoints offer post-quantum (PQ) cryptography alongside classical cryptography, or classical only. It checks TLS, SSH, QUIC, STARTTLS mail and database ports, DTLS, IPsec, DNSSEC, DNSCurve and DNSCrypt on AWS, Azure, GCP, IBM Cloud (formerly Bluemix), Oracle Cloud, Cloudflare, Fastly and Akamai (including Akamai Cloud, formerly Linode), plus Google Public DNS, the TLD zones, and the DNS resolver companies (AdGuard, OpenDNS/Cisco Umbrella, Quad9, NextDNS, CleanBrowsing, Control D, Mullvad), plus any endpoint you name.

It needs no credentials. Every verdict comes from real handshakes, not vendor documentation.

## Quick start

```bash
./pq-cloud-scan.sh                 # every built-in provider (about 230 endpoints, four to five minutes)
./pq-cloud-scan.sh --setup         # install any optional tools this machine lacks
./pq-cloud-scan.sh https://example.com   # just your own URL
./pq-cloud-scan.sh aws gcp         # only these providers
./pq-cloud-scan.sh bluemix         # bluemix, ibmcloud and ibm all mean IBM Cloud
```

Results print to the terminal and are saved in `./pq-scan-YYYYmmdd-HHMMSS/`.

## Requirements

| Tool | Needed? | Why |
|------|---------|-----|
| `bash` 4.4+, `openssl`, `ssh`, `timeout`, `awk`, `sort`, `paste` | required | the probes themselves |
| OpenSSL **3.5 or newer** | required for TLS PQ verdicts | older versions cannot offer ML-KEM groups; verdicts become `UNKNOWN-CLIENT-NO-PQ` instead of a false "classical only" |
| `curl` | optional | second opinion before any `CLASSICAL-ONLY` verdict |
| `jq` | optional | `results.json` and `--creds` parsing |
| `column` | optional | aligned tables |
| `dig` | optional | `dnssec`, `dnscurve`, `dnscrypt` probes |
| `ike-scan` | optional | `ike` probe |
| `nc` (netcat) | optional | plain-NTP part of the `ntp` probe |
| NetworkManager (`nmcli`) | optional | `--local` Wi-Fi and VPN listing; used through the host when run inside a toolbox |
| `nmap`, `sslyze`, `ssh-audit`, `testssl.sh` | optional | `--deep` |
| `aws`, `az`, `gcloud`, `ibmcloud` | optional | `--creds` |

Any OpenSSH version works for SSH verdicts. Servers announce their full algorithm list in cleartext before negotiating, so the client does not need PQ support to read it.

### Installing the tools: `--setup`

```bash
./pq-cloud-scan.sh --setup          # shows what is missing and how it would be installed, then asks
./pq-cloud-scan.sh --setup --yes    # no prompt (needed in scripts and containers)
```

`--setup` finds the package manager by itself and installs only what is missing. It never scans.

| Package manager | Distros |
|-----------------|---------|
| `apt-get` | Debian, Ubuntu, Mint, Kali |
| `dnf`, `yum` | Fedora, RHEL, CentOS, Rocky, Alma, Amazon Linux |
| `zypper` | openSUSE, SLES |
| `pacman` | Arch, Manjaro, EndeavourOS |
| `apk` | Alpine (install `bash` first: `apk add bash`) |
| Homebrew, `rpm-ostree` | image-based Fedora such as Silverblue and Bazzite; Homebrew is preferred, `rpm-ostree` needs a reboot |

- `sslyze` is not packaged by most distros, so it goes through `pipx`, or `pip --user` if pipx is unavailable. `ssh-audit` does the same where there is no package.
- `testssl.sh` comes from the distro where packaged (often as `testssl`; both names are recognised). Otherwise it is cloned from its GitHub release branch into `~/.local/share` and linked in `~/.local/bin`.
- `ike-scan` is packaged only by Debian-family distros and Homebrew. Everywhere else `--setup` builds it from the upstream source into `~/.local` (installing gcc, make, autoconf and automake first if needed). Tested on a clean Fedora.
- The script adds `~/.local/bin` to its own `PATH`, so tools installed there are found without any shell changes.
- **sudo:** system packages need administrator rights. When you are not root, `--setup` prints the exact `sudo` command before it runs it, and sudo may ask for your password. If sudo is not installed it prints the command for you to run as root instead. Homebrew, pipx, pip and the git fallback install for your user only and never use sudo.
- **Safe to re-run:** tools already present show a green check and `..installed`, and are left alone. When nothing is missing it makes no changes at all. Set `NO_COLOR=1` for plain output.
- On Arch it does not refresh the package database, because that would be a partial upgrade. If pacman fails, run `pacman -Syu` and try again.
- Cloud CLIs for `--creds` are not installed; use each vendor's installer.
- It ends by telling you whether your OpenSSL can offer post-quantum groups.

Tested in clean containers of Debian 13, Alpine 3.24, Fedora 44, Arch and openSUSE Tumbleweed.

Check your client:

```bash
openssl list -tls-groups | tr ':' '\n' | grep -i mlkem    # should list X25519MLKEM768 etc.
```

## Usage examples

### Pick providers

```bash
./pq-cloud-scan.sh                     # default: every provider in targets.tsv
./pq-cloud-scan.sh adguard opendns quad9   # resolver companies work as words too
./pq-cloud-scan.sh azure               # one provider
./pq-cloud-scan.sh aws azure gcp       # several
./pq-cloud-scan.sh -p aws,ibm          # same thing as a comma list
```

Accepted names: `aws` (`amazon`), `azure` (`microsoft`), `gcp` (`google`), `ibm` (`bluemix`, `ibmcloud`), `oracle` (`oci`), `cloudflare` (`cf`), `fastly`, `akamai` (`linode`), `dns-zones` (`zones`: DNSSEC on com, org, gov, ietf.org and the DNSCurve reference zone), `adguard`, `opendns`, `quad9`, `nextdns`, `cleanbrowsing`, `controld`, `mullvad`. Any provider name you add to `targets.tsv` works as a word as well. Case does not matter.

### Scan your own endpoints

Endpoint arguments are probed by exactly the same code as the built-in targets. Give endpoints alone and only those are scanned. Add provider words, or `--with-targets`, to scan the built-in list as well.

```bash
# format: [label=][proto://]host[:port]
./pq-cloud-scan.sh https://vault.example.com/any/path       # full URLs work; the path is ignored
./pq-cloud-scan.sh vault.example.com                        # bare host, TLS on 443
./pq-cloud-scan.sh api.example.com:8443                     # TLS on another port
./pq-cloud-scan.sh ssh://sftp.example.com:2222              # SSH
./pq-cloud-scan.sh prod=tls://my-alb.example.com            # "prod" becomes the group label in totals

# a provider plus your own hosts
./pq-cloud-scan.sh aws my-alb.example.com ssh://bastion.example.com

# everything built in, plus your own host
./pq-cloud-scan.sh --with-targets my-alb.example.com
```

Without `proto://`, ports 22, 2022 and 2222 mean SSH and everything else means TLS. `http://` is rejected, because plain HTTP has no TLS to inspect.

Public endpoints that need no login work well as a sanity check:

```bash
./pq-cloud-scan.sh \
  aws=ip-ranges.amazonaws.com aws=public.ecr.aws \
  azure=prices.azure.com azure=mcr.microsoft.com \
  gcp=www.googleapis.com gcp=storage.googleapis.com
```

### Other protocols

The scheme in an endpoint picks the probe. Default ports follow the scheme.

| Scheme | What is tested | Can it be post-quantum today? |
|---|---|---|
| `https`, `tls` | TLS 1.3 groups, TLS 1.2, suites, certificate, ML-DSA signing | yes, hybrid ML-KEM |
| `ssh`, `sftp` | server-announced kex, host keys, ciphers, MACs, login methods | yes, `mlkem768x25519`, `sntrup761x25519` |
| `quic`, `h3` | the same TLS probe over HTTP/3 on UDP; one group per handshake because OpenSSL does not print the group under QUIC | yes |
| `doq` | DNS over QUIC (ALPN `doq`, UDP 853), same probe | yes |
| `smtp` `imap` `pop3` `ldap` `ftp` `xmpp` `postgres` `mysql` | STARTTLS upgrade, then the full TLS probe | yes |
| `smtps` `imaps` `pop3s` `ldaps` `ftps` `dot` `mqtts` `amqps` `rdp` | TLS from the first byte on the right default port | yes |
| `dtls` | DTLS 1.2 and 1.0, the data channel of SSL VPNs (AnyConnect, ocserv, Fortinet) | no: DTLS 1.2 has no PQ groups and OpenSSL has no DTLS 1.3 |
| `ike`, `ipsec` | IKEv2 and IKEv1 transforms a gateway accepts, via `ike-scan` | not testable: ike-scan cannot offer RFC 9370 additional key exchanges |
| `dnssec` | signing algorithms from DNSKEY and the DS at the parent; host is a zone name | no standard PQ algorithm yet |
| `dnscurve` | `uz5…` Curve25519 keys in the NS names; host is a zone name | no |
| `dnscrypt` | the resolver certificate's cipher versions; `dnscrypt://IP:PORT/PROVIDER-NAME` | no |
| `ntp`, `nts` | plain NTP on UDP 123, then NTS-KE (TLS 1.3, ALPN `ntske/1`) on TCP 4460; the verdict follows NTS | yes in principle; Cloudflare, Netnod and PTB refuse PQ groups today |
| `ech` | the HTTPS DNS record: ALPNs and the Encrypted Client Hello config, with its HPKE KEM | no: HPKE uses X25519 |
| `mail` | `mail://DOMAIN[/SELECTOR]`: DKIM signing keys (WEAK for RSA-1024), DANE TLSA on the MX hosts, MTA-STS mode | no |

```bash
./pq-cloud-scan.sh smtp://smtp.gmail.com imaps://imap.gmail.com        # mail
./pq-cloud-scan.sh postgres://db.example.com:5432                       # database STARTTLS
./pq-cloud-scan.sh quic://cloudflare.com dot://dns.google               # HTTP/3, DNS over TLS
./pq-cloud-scan.sh dnssec://example.com dnscurve://example.com           # zones
./pq-cloud-scan.sh dnscrypt://9.9.9.9:8443/2.dnscrypt-cert.quad9.net
./pq-cloud-scan.sh dtls://vpn.example.com ike://vpn.example.com          # your own VPN gateway
./pq-cloud-scan.sh --proto dnssec                                        # one protocol across the built-in list
```

VPNs you cannot scan: **WireGuard** never answers without a valid key, and its crypto is fixed (Curve25519, so classical, with an optional pre-shared key as the only PQ hedge). **OpenVPN** needs a real OpenVPN client, and servers with `tls-crypt` stay silent to strangers. **SSL VPN** portals are plain TLS on 443, so the default probe already covers them.

With AWS credentials, Site-to-Site VPN tunnels are read from the API and reported as `vpn-config` rows under `aws-account` with their DH groups, ciphers and IKE versions. No packets are sent for those.

Verdicts `NOT-OFFERED` (an unsigned zone, no DNSCurve servers) and `SKIPPED-NO-TOOL` (`dig` or `ike-scan` missing; run `--setup`) join the list above. `NOT-OFFERED` has its own column in the grand total and does not count against `pq%`.

Only point the `ike` and `dtls` probes at gateways you own or are cleared to test; they show up as connection attempts in the gateway's logs.

### Local Wi-Fi and VPN, IPv6, and everything at a glance

```bash
./pq-cloud-scan.sh --protocols            # table of every protocol the script can check
./pq-cloud-scan.sh --local aws            # add the Wi-Fi networks in range and active VPN links
./pq-cloud-scan.sh -6 cloudflare          # also probe over IPv6 where a host has an AAAA record
```

`--local` reads NetworkManager (through the host when run inside a toolbox) and sends nothing. Wi-Fi rows show the security type (WEP, WPA, WPA2, WPA3, open), how the session key is agreed (WPA3 SAE is elliptic-curve, WPA2-Personal is a symmetric PSK handshake), the cipher (CCMP, GCMP, TKIP), and WEAK for WEP or TKIP. No Wi-Fi standard is post-quantum yet, so every encrypted network is CLASSICAL-ONLY and an open network is NOT-OFFERED. Active WireGuard links are listed as classical (Curve25519), with the optional pre-shared key noted as the only PQ hedge.

Every TLS row now carries a `chain=` summary in the note: key type and signature at each certificate level, with WEAK for RSA under 2048 bits or SHA-1.

With AWS credentials the account scan also lists KMS keys by key spec (ML-DSA and ML-KEM keys show as PQ-ONLY, AES/HMAC keys as SYMMETRIC, RSA/ECC as CLASSICAL-ONLY) and ACM certificates by key algorithm. SYMMETRIC rows count as answered but sit outside `pq%`, which is PQ-capable over PQ-capable plus classical-only.

### Regions and protocols

```bash
./pq-cloud-scan.sh aws -r eu-west-1     # replaces {region} in target hostnames
./pq-cloud-scan.sh --proto ssh          # SSH endpoints only
./pq-cloud-scan.sh --proto tls gcp      # TLS only, one provider
```

Default regions: aws `us-east-1`, azure `eastus`, gcp `us-central1`, ibm `us-south`, oracle `us-ashburn-1`.

### Speed and depth

```bash
./pq-cloud-scan.sh --quick              # 4 TLS handshakes per host instead of about 20
./pq-cloud-scan.sh --deep azure         # adds nmap, sslyze, ssh-audit output under raw/
./pq-cloud-scan.sh -j 16 --timeout 5    # more parallelism, shorter timeout
```

- Default mode offers every PQ group, every classical group and every TLS 1.3 suite on its own, so you see everything the server accepts, not just its first choice.
- `--quick` makes one combined PQ offer and one combined classical offer. The verdict is the same; the algorithm lists are shorter.
- `--deep` is slow (about 30 seconds per host) and makes hundreds of connections per host. Note that nmap cannot see ML-KEM groups, so use it for the full TLS 1.2 cipher list, not for the PQ verdict.

### Use your AWS credentials to scan far more

Nothing to switch on. If the AWS CLI has working credentials, a run that includes `aws` adds, with read-only calls:

1. **Every AWS service endpoint in the region**, about 360 per region, read from the public SSM parameters AWS maintains (`/aws/service/global-infrastructure`). Without credentials you get the 28 curated ones.
2. **Your own account's internet-facing endpoints**: load balancers (HTTPS and TLS listeners), CloudFront distributions and their alternate names, API Gateway APIs and custom domains, Transfer Family SFTP servers, public OpenSearch domains, public EKS control planes, and SSH on running EC2 instances with a public DNS name. No login is attempted anywhere.

AWS's endpoints are reported as `aws`. Yours are reported as `aws-account`, with a grand-total row to themselves, because an ALB's TLS policy is your choice and not AWS's.

```bash
./pq-cloud-scan.sh aws                                  # credentials found by themselves
./pq-cloud-scan.sh aws --profile 123456789012_AdministratorAccess
AWS_PROFILE=audit ./pq-cloud-scan.sh aws -r eu-west-1
./pq-cloud-scan.sh aws -r us-east-1,eu-west-1           # --region takes a comma list, for any provider
./pq-cloud-scan.sh aws --all-regions --quick -j 32      # every enabled region: about 6,000 endpoints
./pq-cloud-scan.sh aws --no-discover                    # ignore credentials, public list only
```

Which credentials are used:

- `--profile NAME`, `AWS_PROFILE`, environment keys or the `default` profile, whichever the AWS CLI would use.
- If none of those work, each named profile in `~/.aws` is tried. If exactly one authenticates, it is used and named in the log. If several do, nothing is guessed and you are asked for `--profile`.
- An expired SSO session shows up as "did not authenticate"; run `aws sso login --profile NAME`.

Good to know:

- One region in default mode is about 350 endpoints and a few minutes; `--quick -j 24` does it in under a minute. `--all-regions` is thousands of endpoints, so use `--quick` and raise `-j`.
- `--discover-max N` caps resources taken per type and region (default 25).
- Only `list`, `describe` and `get` calls are made. The account id appears in the log as its last four digits, but `results.tsv` will contain your resource hostnames, so treat the output folder as private.
- Expect your EC2 SSH rows to be `UNREACHABLE` unless the security group allows your IP on port 22.

### Provider policy catalogs (needs credentials)

```bash
./pq-cloud-scan.sh aws --creds          # uses your current AWS profile
AWS_PROFILE=audit ./pq-cloud-scan.sh aws --creds -r us-west-2
```

`--creds` makes read-only calls and flags policies that contain PQ algorithms:

| Provider | Calls |
|----------|-------|
| AWS | `elbv2 describe-ssl-policies`, `transfer list-security-policies`, `transfer describe-security-policy` |
| Azure | `network application-gateway ssl-policy list-options`, `... predefined list` |
| GCP | `compute ssl-policies list-available-features` |
| IBM | none available; IBM verdicts rest on the handshakes |

Only the CLIs for the providers you selected are called. A missing or logged-out CLI is logged and skipped.

### Choose where output goes

```bash
./pq-cloud-scan.sh -o ~/scans/2026-09 aws
```

## All options

| Option | Meaning |
|---|---|
| `PROVIDER ...` | bare provider words: `aws azure gcp ibm oracle cloudflare fastly akamai dns-zones adguard opendns quad9 nextdns cleanbrowsing controld mullvad`, aliases `amazon microsoft google bluemix ibmcloud oci cf linode zones`, plus any provider name in `targets.tsv` |
| `ENDPOINT ...` | `[label=][scheme://]host[:port]`; endpoints alone scan only those endpoints |
| `-t, --targets FILE` | use another targets file |
| `--no-targets` / `--with-targets` | skip the built-in list / scan it alongside your endpoints |
| `-p, --provider LIST` | comma list, same as provider words |
| `--proto NAME` | one protocol only: `tls ssh quic doq dtls ike ntp ech mail dnssec dnscurve dnscrypt starttls-smtp ...` |
| `-r, --region R[,R...]` | replace `{region}`; comma list allowed |
| `-o, --out DIR` | output directory (default `./pq-scan-<timestamp>`) |
| `-j, --jobs N` | parallel probes (default 8) |
| `--timeout SEC` | per-handshake timeout (default 8) |
| `--quick` | 4 TLS handshakes per host instead of about 20 |
| `--deep` | nmap, sslyze, ssh-audit, testssl.sh output under `raw/` |
| `--creds` | provider policy catalogs via aws/az/gcloud/ibmcloud (read-only) |
| `--profile NAME` | AWS profile (same as `AWS_PROFILE`) |
| `--no-discover` | ignore AWS credentials: no per-region service list, no account endpoints |
| `--all-regions` | every AWS region enabled in the account (needs credentials) |
| `--discover-max N` | cap per resource type and region (default 25) |
| `--local`, `--wifi` | list Wi-Fi networks in range and active VPN links (NetworkManager) |
| `-6, --ipv6` | also probe over IPv6 where a host has an AAAA record |
| `--setup` [`-y`] | install missing optional tools through the system package manager |
| `--protocols` | table of every protocol the script can check |
| `-h`, `--version` | help, version |

## Reading the results

### Verdicts

| Verdict | Meaning |
|---------|---------|
| `PQ-HYBRID+CLASSICAL` | accepts a hybrid PQ key exchange (for example `X25519MLKEM768`) and also classical |
| `PQ-PURE+CLASSICAL` | accepts only pure ML-KEM groups on the PQ side, and also classical |
| `PQ-ONLY` | accepts PQ, refuses a classical-only offer |
| `CLASSICAL-ONLY` | refuses a PQ-only offer, accepts classical |
| `UNKNOWN-CLIENT-NO-PQ` | your OpenSSL cannot offer PQ groups, so nothing can be concluded |
| `HANDSHAKE-FAILED` | the port is open but no probe completed (wrong protocol, needs a real SNI, etc.) |
| `UNREACHABLE` | DNS failure, connection refused, or timeout |

The `pq_auth` column is separate from the verdict. It is `yes` only if the server presents a PQ certificate key or signs the handshake with ML-DSA, or an SSH server offers a PQ host key. Key exchange and authentication are scored apart on purpose: a provider can have shipped one and not the other.

### Output files

| File | Contents |
|------|----------|
| `results.tsv` | one row per endpoint, 19 columns (below) |
| `algorithms.tsv` | tallies: provider, proto, category, algorithm, endpoints using it, denominator |
| `summary.txt` | a legend explaining every probe type that ran, verdict totals per provider and protocol, every algorithm and cipher with counts, and a grand total per provider |
| `results.json` | the same data as JSON (needs `jq`) |
| `scan.log` | progress and skipped or rejected targets |
| `raw/` | `--deep` tool output and `--creds` JSON |

`results.tsv` columns:

| Column | TLS | SSH |
|--------|-----|-----|
| `provider`, `service`, `proto`, `host`, `port` | target identity | same |
| `verdict` | see above | see above |
| `pq_kex` | PQ groups the server accepted | PQ kex names the server offers |
| `classical_kex` | classical groups actually negotiated | classical kex names the server offers |
| `versions` | TLS versions accepted | `SSH-2.0` |
| `ciphers` | suites accepted (all TLS 1.3 suites tested; TLS 1.2 shows preferred ones, `--deep` lists all) | `-` |
| `auth_key` | certificate key type and size | negotiated host key |
| `auth_sig` | certificate and handshake signature algorithms | `-` |
| `pq_auth` | `yes` / `no` / `unknown` | `yes` / `no` |
| `srv_kex`, `srv_hostkeys`, `srv_ciphers`, `srv_macs`, `user_auth` | `-` | lists the server announced, and its login methods |
| `note` | probe notes | negotiated kex and server banner |

In `algorithms.tsv`, verdict rows are counted against all endpoints; algorithm rows are counted against reachable endpoints.

Handy one-liners:

```bash
# every endpoint that is still classical only
awk -F'\t' '$6 == "CLASSICAL-ONLY" { print $1, $3, $4 }' pq-scan-*/results.tsv

# which PQ groups each provider accepts, and on how many endpoints
awk -F'\t' '$3 == "pq_key_exchange"' pq-scan-*/algorithms.tsv | column -t

# endpoints that still allow key exchange without forward secrecy
grep 'static-RSA' pq-scan-*/results.tsv | cut -f1,4

jq '.results[] | select(.verdict == "PQ-ONLY") | .host' pq-scan-*/results.json
```

## Editing the target list

`targets.tsv` sits beside the script. It is tab separated, five columns, `#` for comments:

```
provider<TAB>service<TAB>proto<TAB>host<TAB>port
aws	kms	tls	kms.{region}.amazonaws.com	443
azure	devops-ssh	ssh	ssh.dev.azure.com	22
```

- `{region}` is replaced by `--region` or the provider default.
- Rows with a new provider name have no default region; give `--region` or write the full hostname.
- The provider name `ALL` is reserved for totals.
- Use another file with `-t my-targets.tsv`.

## How it decides

**TLS.** A classical-only offer establishes reachability, the certificate and the preferred group. Then each PQ group is offered alone on TLS 1.3, and counts only if the server negotiates that exact group. Each classical group is offered alone too, and the script records what was *negotiated*, not what was offered: some servers quietly fall back to TLS 1.2 with finite-field DH or static RSA when they lack the offered group. A TLS 1.2 probe, one probe per TLS 1.3 suite, and an ML-DSA-only signature probe follow. A handshake counts only if `openssl s_client` exits 0 and a real cipher was agreed. Before any `CLASSICAL-ONLY` verdict, `curl` retries the PQ offer as a second opinion.

**SSH.** One unauthenticated connection with `ssh -vv`. The script reads the server's own algorithm announcement (never the client's), and asks for login methods with a "none" auth request. It never sends a password or key. The probe username defaults to `git`; change it with `SSH_PROBE_USER=name`.

## Limits

- **One vantage, one moment.** Providers serve different front ends per region and point of presence. Re-run from other networks and with other `--region` values before generalising.
- **The target list is curated, not exhaustive.** Providers terminate TLS on a small number of shared fleets, so a few dozen endpoints per provider are representative. Add rows or endpoint arguments for anything you depend on.
- **What you measure may be a CDN.** Some provider hostnames are fronted by a third-party edge, so the PQ support you see can belong to that edge rather than the provider's own stack.
- **TLS 1.2 cipher lists are partial** without `--deep`.
- **Input is validated.** Hostnames that start with `-`, contain shell characters or `..` are rejected, and server-supplied SSH text is stripped of tabs and control bytes before it is written out.
- **Be polite.** The default mode makes about 20 short connections per host. Use `--quick` for large private lists, and only scan endpoints you are allowed to test.

## License

MIT. See `LICENSE`.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | scan finished (individual endpoints may still be unreachable) |
| 2 | bad arguments, missing required tool, unreadable targets file, or no targets selected |
