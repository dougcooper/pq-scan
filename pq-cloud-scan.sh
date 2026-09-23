#!/usr/bin/env bash
# pq-cloud-scan.sh — inventory TLS and SSH cryptography on cloud provider endpoints
# and decide, per endpoint, whether post-quantum (PQ) key exchange / authentication
# is offered in addition to classical cryptography, or classical only.
#
# Method (no credentials needed):
#   TLS  the verdict comes from handshakes that offer ONLY PQ groups versus ONLY classical
#        groups. Each PQ group, classical group and TLS 1.3 suite is also offered alone
#        (--quick skips that), plus a TLS 1.2 probe and an ML-DSA-only signature probe.
#   SSH  the server announces its full algorithm lists in cleartext (KEXINIT), so one
#        unauthenticated connection yields kex / host key / cipher / MAC lists and,
#        via a "none" auth request, the user authentication methods.
# Optional: --deep (nmap, sslyze, ssh-audit), --creds (read-only cloud CLI catalogs).

set -uo pipefail
# Probe output is bytes, not text: openssl and ssh traces can carry non-UTF-8 sequences that make gawk
# warn "Invalid multibyte data". A byte locale keeps every awk/grep/sort here quiet and deterministic.
export LC_ALL=C

readonly VERSION="1.0.0"
readonly PQ_NAME_RE='mlkem|ml-kem|kyber|sntrup|ntru|frodo|bike|hqc|mceliece'
readonly PQ_SIG_RE='mldsa|ml-dsa|slhdsa|slh-dsa|dilithium|falcon|fndsa|sphincs|mayo'
readonly CLASSICAL_GROUPS='X25519:P-256:P-384:P-521:X448:ffdhe2048:ffdhe3072'
readonly TLS13_SUITES="TLS_AES_128_GCM_SHA256 TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256 TLS_AES_128_CCM_SHA256"
readonly PROTO_RE='^(tls|ssh|quic|doq|dtls|ike|ntp|ech|mail|dnssec|dnscurve|dnscrypt|starttls-(smtp|imap|pop3|ldap|ftp|xmpp|postgres|mysql))$'
readonly HOST_RE='^[A-Za-z0-9][A-Za-z0-9._-]*$'
# results.tsv columns: six identity columns, then the fields a probe may fill (see emit_row)
readonly ROW_FIELDS="pq_kex classical_kex versions ciphers auth_key auth_sig pq_auth srv_kex srv_hostkeys srv_ciphers srv_macs user_auth note"
readonly HEADER=$'provider\tservice\tproto\thost\tport\tverdict\t'"${ROW_FIELDS// /$'\t'}"

# pipx, pip --user and the --setup git fallback all install here
[[ -d $HOME/.local/bin && ":$PATH:" != *":$HOME/.local/bin:"* ]] && PATH="$PATH:$HOME/.local/bin"

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
TARGETS="$SCRIPT_DIR/targets.tsv"
OUT=""
REGION=""
PROVIDERS=""
readonly DEFAULT_PROVIDERS="aws,azure,gcp,ibm,oracle,cloudflare,fastly,akamai,dns-zones,adguard,opendns,quad9,nextdns,cleanbrowsing,controld,mullvad"
EXPLICIT_PROVIDERS=0
FORCE_TARGETS=0
PROTO_FILTER=""
TIMEOUT=8
JOBS=8
DEEP=0
QUICK=0
CREDS=0
SETUP=0
ASSUME_YES=0
DISCOVER=1
DISCOVER_MAX=25
LOCAL=0
IPV6=0
ALL_REGIONS=0
AWS_OK=0
AWS_REGIONS=""
AWS_IDENTITY=""
USE_TARGETS=1
SSH_PROBE_USER="${SSH_PROBE_USER:-git}"
ENDPOINTS=()

usage() {
  cat <<EOF
pq-cloud-scan $VERSION — TLS/SSH post-quantum readiness inventory for cloud endpoints

Usage: $(basename "$0") [options] [PROVIDER ...] [ENDPOINT ...]

PROVIDER   any of: aws azure gcp ibm oracle cloudflare fastly akamai dns-zones (bluemix and
           ibmcloud mean ibm, oci means oracle, cf means cloudflare, linode means akamai; dns-zones
           is the DNSSEC state of com, org, gov, ietf.org and the DNSCurve reference zone), or any
           provider name in the targets file. Give no providers and no endpoints and the default
           list is scanned (see --provider).  e.g.  $(basename "$0") aws gcp

ENDPOINT   your own host or URL, probed exactly like the built-in targets. Endpoints alone scan
           only those endpoints; add provider words or --with-targets to scan the built-ins too.
             [provider=][scheme://]host[:port]
           Without a scheme, ports 22/2022/2222 mean ssh and anything else tls. provider defaults
           to "custom". Schemes:
             https tls ssh sftp                      TLS and SSH
             quic (h3)                               HTTP/3 over QUIC, UDP
             doq                                     DNS over QUIC (ALPN doq), UDP 853
             smtp imap pop3 ldap ftp xmpp postgres mysql   STARTTLS upgrade, then the TLS probe
             smtps imaps pop3s ldaps ftps dot mqtts amqps rdp   TLS from the first byte, right default port
             dtls                                    DTLS, the data channel of SSL VPNs (UDP)
             ike                                     IPsec VPN gateway, needs ike-scan (UDP 500)
             dnssec dnscurve                         host is a zone name, e.g. dnssec://example.com
             dnscrypt                                dnscrypt://RESOLVER-IP:PORT/PROVIDER-NAME
             ntp                                     plain NTP on UDP 123 plus NTS-KE on TCP 4460
             ech                                     HTTPS DNS record: ALPNs and Encrypted Client Hello config
             mail                                    mail://DOMAIN[/DKIM-SELECTOR]: DKIM keys, DANE, MTA-STS
           e.g.  vault.example.com   ssh://sftp.example.com:2222   aws=tls://my-alb.example.com

Options:
  -t, --targets FILE     targets file (default: targets.tsv beside this script)
      --no-targets       scan only the ENDPOINT arguments (automatic when no provider is named)
      --with-targets     scan the built-in targets as well as the ENDPOINT arguments
  -p, --provider LIST    same as PROVIDER words, as a comma list (default: $DEFAULT_PROVIDERS).
                         ENDPOINT arguments are always scanned, whatever providers are chosen.
      --proto NAME       limit to one protocol: tls ssh quic dtls ike dnssec dnscurve dnscrypt starttls-smtp ...

  -r, --region REGION    replace {region} in hosts (default per provider:
                         aws=us-east-1 azure=eastus gcp=us-central1 ibm=us-south
                         oracle=us-ashburn-1)
  -o, --out DIR          output directory (default: ./pq-scan-YYYYmmdd-HHMMSS)
  -j, --jobs N           parallel probes (default: $JOBS)
      --timeout SEC      per-handshake timeout (default: $TIMEOUT)
      --quick            4 TLS handshakes per host (one combined PQ offer, one combined classical
                         offer) instead of testing every group and TLS 1.3 suite on its own (~20)
      --deep             also run nmap ssl-enum-ciphers / ssh2-enum-algos / ssh-auth-methods,
                         plus sslyze and ssh-audit when installed (many handshakes per host)
      --creds            also query provider policy catalogs with aws / az / gcloud / ibmcloud
                         (read-only list/describe calls; skipped when a CLI is absent)
      --profile NAME     AWS profile to use (same as AWS_PROFILE). Without it the default credentials are
                         tried, then named profiles: if exactly one works it is used, otherwise you are
                         asked to choose.
      --no-discover      AWS credentials are used automatically when present, with read-only calls, to add:
                         (1) every AWS service endpoint in the region (about 360, from AWS's public SSM
                         parameters), and (2) the account's own internet-facing endpoints (load balancers,
                         CloudFront, API Gateway, Transfer, OpenSearch, EKS, EC2 SSH) as "aws-account".
                         This flag turns both off.
      --all-regions      do that for every region enabled in the account (about 6,000 endpoints for 17
                         regions; pair it with --quick and a higher -j)
      --discover-max N   most resources taken per type and region (default: 25)
      --local, --wifi    also list the Wi-Fi networks in range and active VPN links on this machine
                         (NetworkManager, read-only) as provider "local"
  -6, --ipv6             also probe TLS/QUIC/SSH/DTLS targets over IPv6 when the host has an AAAA record
      --setup            install the tools this script can use and this machine lacks (curl, jq, nmap,
                         ssh-audit, testssl.sh, sslyze, ...). Detects apt, dnf, yum, zypper, pacman,
                         apk, Homebrew or rpm-ostree; Python tools go through pipx or pip. Shows the
                         plan and asks first, then exits without scanning.
  -y, --yes              with --setup: install without asking (needed when not on a terminal)
  -h, --help             this text
      --version          print version

Verdicts:
  PQ-HYBRID+CLASSICAL  hybrid PQ key exchange offered, classical also accepted
  PQ-PURE+CLASSICAL    pure ML-KEM group offered, classical also accepted
  PQ-ONLY              PQ accepted, classical-only offer refused
  CLASSICAL-ONLY       PQ-only offer refused, classical accepted
  UNKNOWN-CLIENT-NO-PQ local openssl cannot offer PQ groups; nothing can be concluded
  HANDSHAKE-FAILED     reachable, but no probe completed
  UNREACHABLE          DNS/connect failure or timeout

Outputs in DIR: results.tsv, algorithms.tsv, summary.txt, results.json (needs jq), scan.log, raw/
EOF
}

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*" | tee -a "${LOGFILE:-/dev/null}" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 2; }
have() { command -v "$1" >/dev/null 2>&1; }
# distro packages ship testssl.sh as "testssl"; upstream calls it "testssl.sh"
testssl_bin() { command -v testssl.sh 2>/dev/null || command -v testssl 2>/dev/null; }
tool_present() { if [[ $1 == testssl.sh ]]; then testssl_bin >/dev/null; else have "$1"; fi; }
# join stdin lines with commas, dropping blanks and duplicates (order preserved)
csv() { awk 'NF && !seen[$0]++' | paste -sd, -; }
# csv_merge LIST...: one comma list from several comma lists or line lists, in the order given
csv_merge() { printf '%s\n' "$@" | tr ',' '\n' | csv; }
# append_csv VAR ITEM...: add items to the comma list held in the variable named VAR
append_csv() {
  local -n _list=$1
  shift
  _list=$(csv_merge "$_list" "$@")
}
pretty() { if have column; then column -t -s $'\t'; else cat; fi; }

default_region() {
  case "$1" in
    aws) echo us-east-1 ;;
    azure) echo eastus ;;
    gcp) echo us-central1 ;;
    ibm) echo us-south ;;
    oracle) echo us-ashburn-1 ;;
    *) echo "" ;;
  esac
}

# Canonical name for a built-in provider word or one of its aliases (bluemix is the old name for
# IBM Cloud). Fails for any other word, so callers can fall back to the targets file.
provider_alias() {
  case "${1,,}" in
    aws|amazon) echo aws ;;
    azure|microsoft) echo azure ;;
    gcp|google) echo gcp ;;
    ibm|bluemix|ibmcloud) echo ibm ;;
    oracle|oci) echo oracle ;;
    cloudflare|cf) echo cloudflare ;;
    fastly) echo fastly ;;
    akamai|linode) echo akamai ;;
    dns-zones|zones) echo dns-zones ;;
    *) return 1 ;;
  esac
}

# ------------------------------------------------------------------ setup (--setup)
# Installs whatever this script can use and the machine lacks, through the system's own
# package manager. Python-only tools (sslyze) go through pipx or pip.
readonly SETUP_TOOLS="openssl ssh timeout awk curl jq column dig nmap ike-scan ssh-audit testssl.sh sslyze"

# read with bash only: a minimal image may not have awk yet, and sourcing os-release would clash with our readonly VERSION
distro_name() {
  local k v
  while IFS== read -r k v; do
    if [[ $k == PRETTY_NAME ]]; then v=${v#\"}; echo "${v%\"}"; return; fi
  done </etc/os-release 2>/dev/null
  echo unknown
}

detect_pkg_manager() {
  local m
  # image-based Fedora (Silverblue, Kinoite, Bazzite): /usr is read-only, so prefer Homebrew
  if [[ -e /run/ostree-booted ]]; then
    if have brew; then echo brew; elif have rpm-ostree; then echo rpm-ostree; fi
    return
  fi
  for m in apt-get dnf yum zypper pacman apk brew; do
    if have "$m"; then echo "$m"; return; fi
  done
}

# Package that provides a tool under a given manager. Empty output means "not packaged here".
pkg_for() {
  local tool=$1 mgr=$2
  case "$tool:$mgr" in
    ssh:apt-get|ssh:apk) echo openssh-client ;;
    ssh:dnf|ssh:yum|ssh:rpm-ostree) echo openssh-clients ;;
    ssh:*) echo openssh ;;
    timeout:*) echo coreutils ;;
    awk:*) echo gawk ;;
    dig:apt-get) echo dnsutils ;;
    dig:apk) echo bind-tools ;;
    dig:pacman|dig:brew) echo bind ;;
    dig:*) echo bind-utils ;;
    ike-scan:apt-get|ike-scan:brew) echo ike-scan ;;
    ike-scan:*) ;;
    column:apt-get) echo bsdextrautils ;;
    column:apk) echo util-linux-misc ;;
    column:*) echo util-linux ;;
    nmap:apk) echo "nmap nmap-scripts" ;;
    testssl.sh:dnf|testssl.sh:yum|testssl.sh:rpm-ostree|testssl.sh:brew) echo testssl ;;
    testssl.sh:zypper|testssl.sh:apk) ;;
    ssh-audit:zypper|ssh-audit:yum) ;;
    sslyze:*) ;;
    *) echo "$tool" ;;
  esac
}

pkg_install() { # manager package...
  local mgr=$1
  shift
  case "$mgr" in
    apt-get) "${SUDO[@]}" apt-get update -qq && "${SUDO[@]}" env DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" ;;
    dnf|yum) "${SUDO[@]}" "$mgr" install -y "$@" ;;
    zypper) "${SUDO[@]}" zypper --non-interactive install "$@" ;;
    # no -y: refreshing the database without a full upgrade is a partial upgrade, which Arch does not support
    pacman) "${SUDO[@]}" pacman -S --noconfirm --needed "$@" || { echo "pacman failed: run 'pacman -Syu' first, then re-run --setup" >&2; return 1; } ;;
    apk) "${SUDO[@]}" apk add --no-cache "$@" ;;
    brew) brew install "$@" ;;
    rpm-ostree) "${SUDO[@]}" rpm-ostree install --idempotent --allow-inactive "$@" ;;
    *) return 1 ;;
  esac
}

# ike-scan is packaged only by Debian-family distros and Homebrew. Elsewhere: build the upstream source
# into ~/.local (no sudo), installing the compiler toolchain through the package manager if it is missing.
ike_scan_from_source() {
  local src="$HOME/.local/src/ike-scan" deps=""
  case "$MGR" in
    dnf|yum|rpm-ostree) deps="gcc make autoconf automake openssl-devel git" ;;
    zypper) deps="gcc make autoconf automake libopenssl-devel git" ;;
    pacman) deps="base-devel openssl git" ;;
    apk) deps="build-base autoconf automake openssl-dev git" ;;
    apt-get) deps="build-essential autoconf automake libssl-dev git" ;;
  esac
  if ! { have gcc && have make && have autoreconf && have git; }; then
    [[ -n $deps && -n $MGR ]] && pkg_install "$MGR" $deps >/dev/null 2>&1
    { have gcc && have make && have autoreconf && have git; } || { echo "ike-scan: cannot build, missing gcc/make/autoconf/git" >&2; return 1; }
  fi
  mkdir -p "$HOME/.local/src" "$HOME/.local/bin" || return 1
  [[ -d $src ]] || git clone --quiet --depth 1 https://github.com/royhills/ike-scan.git "$src" || return 1
  ( cd "$src" && autoreconf -fi && ./configure --quiet --prefix="$HOME/.local" --with-openssl && make -s && make -s install ) >"$HOME/.local/src/ike-scan-build.log" 2>&1 ||
    { echo "ike-scan: build failed, see ~/.local/src/ike-scan-build.log" >&2; return 1; }
}

# No package on this distro: fetch the upstream release branch and link it into ~/.local/bin.
testssl_from_git() {
  if ! have git && [[ -n $MGR ]]; then pkg_install "$MGR" git >/dev/null 2>&1; fi
  have git || { echo "testssl.sh: no package here and git could not be installed" >&2; return 1; }
  local dest="$HOME/.local/share/testssl.sh"
  mkdir -p "$HOME/.local/share" "$HOME/.local/bin" || return 1
  [[ -d $dest ]] || git clone --quiet --depth 1 https://github.com/testssl/testssl.sh.git "$dest" || return 1
  ln -sf "$dest/testssl.sh" "$HOME/.local/bin/testssl.sh"
}

python_tool_install() { # pip package name
  local pkg=$1 pipx_pkg
  if ! have pipx && [[ -n $MGR ]]; then
    case "$MGR" in pacman) pipx_pkg=python-pipx ;; zypper) pipx_pkg=python3-pipx ;; *) pipx_pkg=pipx ;; esac
    pkg_install "$MGR" "$pipx_pkg" >/dev/null 2>&1
  fi
  if have pipx; then
    pipx install "$pkg" && return 0
  fi
  if have python3 && python3 -m pip --version >/dev/null 2>&1; then
    python3 -m pip install --user "$pkg" && return 0
  fi
  return 1
}

setup_footer() {
  if have openssl; then
    if openssl list -tls-groups 2>/dev/null | grep -qiE "$PQ_NAME_RE"; then
      echo "  openssl can offer post-quantum TLS groups: yes ($(openssl version | cut -d' ' -f1-2))"
    else
      echo "  openssl can offer post-quantum TLS groups: NO ($(openssl version | cut -d' ' -f1-2)). TLS verdicts need"
      echo "  OpenSSL 3.5 or newer; this distro's package is older. SSH verdicts are unaffected."
    fi
  fi
  echo "  cloud CLIs for --creds (aws, az, gcloud, ibmcloud) are not installed by --setup; use each vendor's installer."
}

run_setup() {
  local tool pkg how missing=() pkgs=() python_tools=() failed=() answer
  # colour only on a terminal, and never when NO_COLOR is set
  local ok="✓" no="✗" green="" red="" yellow="" reset=""
  if [[ -t 1 && -z ${NO_COLOR:-} ]]; then green=$'\e[32m' red=$'\e[31m' yellow=$'\e[33m' reset=$'\e[0m'; fi
  MGR=$(detect_pkg_manager)
  SUDO=()
  local need_root=0 can_root=1
  if [[ $MGR != brew && $(id -u) -ne 0 ]]; then
    need_root=1
    if have sudo; then SUDO=(sudo); else can_root=0; fi
  fi

  echo "pq-cloud-scan setup"
  echo "  distro          : $(distro_name)"
  echo "  package manager : ${MGR:-none found}"
  for tool in $SETUP_TOOLS; do
    if tool_present "$tool"; then printf '  %s%s%s %-12s ..installed\n' "$green" "$ok" "$reset" "$tool"; continue; fi
    missing+=("$tool")
    pkg=$(pkg_for "$tool" "${MGR:-none}")
    if [[ -n $pkg && -n $MGR ]]; then
      printf '  %s%s%s %-12s ..missing, will run: %s install %s\n' "$yellow" "$no" "$reset" "$tool" "$MGR" "$pkg"
      # shellcheck disable=SC2206
      pkgs+=($pkg)
    else
      case "$tool" in
        ike-scan) how="not packaged here: will build from source into ~/.local (needs gcc, make, autoconf, automake)" ;;
        testssl.sh) how="will: git clone into ~/.local/share, link in ~/.local/bin" ;;
        *) how="will run: pipx/pip install $tool" ;;
      esac
      printf '  %s%s%s %-12s ..missing, %s\n' "$yellow" "$no" "$reset" "$tool" "$how"
      python_tools+=("$tool")
    fi
  done

  if ((${#missing[@]} == 0)); then
    echo "  everything is already installed; nothing to do."
    setup_footer
    return 0
  else
    # say up front what needs administrator rights and what does not
    echo
    if ((${#pkgs[@]})); then
      if ((need_root && can_root)); then
        echo "  note: system packages need administrator rights. This will run with sudo, which may ask for your password:"
        echo "          sudo $MGR install ${pkgs[*]}"
      elif ((need_root)); then
        echo "  note: system packages need administrator rights, and you are not root and sudo is not installed."
        echo "        Run this as root yourself, then re-run --setup:   $MGR install ${pkgs[*]}"
      elif [[ $MGR == brew ]]; then
        echo "  note: Homebrew installs into its own prefix; no sudo is used."
      else
        echo "  note: running as root; no sudo needed."
      fi
    fi
    if ((${#python_tools[@]})); then
      echo "  note: installed into ~/.local for your user only, no sudo: ${python_tools[*]}"
      [[ " ${python_tools[*]} " == *" ike-scan "* ]] && echo "        (ike-scan builds from source; if gcc/make/autoconf are missing they are installed with the package manager first)"
    fi
    if ((!ASSUME_YES)); then
      if [[ -t 0 ]]; then
        read -r -p "install the missing tools now? [y/N] " answer
        [[ ${answer,,} == y || ${answer,,} == yes ]] || { echo "nothing installed."; return 0; }
      else
        echo "not a terminal: re-run with --setup --yes to install. nothing installed."
        return 0
      fi
    fi
    if ((${#pkgs[@]})); then
      # one transaction first; if any name is wrong for this distro, fall back to one at a time
      if ! pkg_install "$MGR" "${pkgs[@]}"; then
        for pkg in "${pkgs[@]}"; do pkg_install "$MGR" "$pkg" || failed+=("$pkg"); done
      fi
    fi
    for tool in "${python_tools[@]}"; do
      if [[ $tool == testssl.sh ]]; then testssl_from_git || failed+=("$tool"); continue; fi
      if [[ $tool == ike-scan ]]; then ike_scan_from_source || failed+=("$tool"); continue; fi
      python_tool_install "$tool" || failed+=("$tool")
    done
    [[ $MGR == rpm-ostree ]] && echo "note: rpm-ostree layers packages into the next deployment; reboot to use them."
  fi

  echo
  # tools built or pipx-installed during this run land in ~/.local/bin, which may not have existed at start
  [[ -d $HOME/.local/bin && ":$PATH:" != *":$HOME/.local/bin:"* ]] && PATH="$PATH:$HOME/.local/bin"
  echo "after setup:"
  for tool in $SETUP_TOOLS; do
    if tool_present "$tool"; then printf '  %s%s%s %-12s ..installed\n' "$green" "$ok" "$reset" "$tool"
    else printf '  %s%s%s %-12s ..still missing\n' "$red" "$no" "$reset" "$tool"; fi
  done
  setup_footer
  ((${#failed[@]} == 0)) || { echo "could not install: ${failed[*]}"; return 1; }
}

# --protocols: everything this script can check, one line each
print_protocols() {
  cat <<'P'
Protocols pq-cloud-scan can check. Use the scheme on the command line (scheme://host[:port]) or in the
proto column of targets.tsv. "PQ possible" says whether the protocol has any post-quantum option today.

  scheme(s)                   proto in results   default port  PQ possible  what is tested                               needs
  https tls smtps imaps       tls                443 465 993   yes          TLS groups, versions, suites, cert, ML-DSA   openssl 3.5+
    pop3s ldaps ftps dot                         995 636 990
    mqtts amqps rdp                              853 8883 5671 3389
  smtp imap pop3 ldap ftp     tls (starttls-*)   587 143 110   yes          STARTTLS upgrade, then the TLS probe        openssl 3.5+
    xmpp postgres mysql                          389 21 5222 5432 3306
  ssh sftp                    ssh                22            yes          server kex/hostkey/cipher/MAC lists, auth   ssh
  quic h3 http3               quic               443           yes          HTTP/3 over QUIC (UDP), alt-svc check        openssl 3.5+, curl
  doq                         quic (doq)         853           yes          DNS over QUIC                                openssl 3.5+
  ntp nts                     ntp                123 (+4460)   yes (NTS)    plain NTP answer, then NTS-KE TLS on 4460    nc, openssl
  dtls                        dtls               443           no           DTLS 1.2/1.0 (SSL VPN data channel)          openssl
  ike ikev2 ipsec             ike                500           not testable IKEv2/IKEv1 transforms of a VPN gateway      ike-scan
  ech httpsrr                 ech                443           no           HTTPS DNS record: ALPNs, ECH config KEM      dig
  dnssec                      dnssec             53            no           zone signing algorithms (DNSKEY, DS)         dig
  dnscurve                    dnscurve           53            no           uz5 Curve25519 keys in NS names              dig
  dnscrypt                    dnscrypt           443           no           resolver certificate cipher versions         dig
  mail                        mail               25            no           DKIM keys, DANE TLSA, MTA-STS for a domain   dig, curl

Result-only rows (no scheme; produced by flags or credentials):
  wifi, vpn-local             --local            Wi-Fi networks in range, active VPN links (NetworkManager)
  vpn-config                  AWS credentials    Site-to-Site VPN tunnel DH groups, ciphers, IKE versions
  kms-key, acm-cert           AWS credentials    KMS key specs (ML-DSA/ML-KEM in use?), ACM certificate key algorithms

Not scannable from outside: WireGuard (silent without a valid key), OpenVPN with tls-crypt.
P
}

# ------------------------------------------------------------------ arguments
add_provider() { PROVIDERS+="${PROVIDERS:+,}$1"; EXPLICIT_PROVIDERS=1; }

# Is this word a provider name in the targets file? (e.g. adguard, quad9, or one the user added)
provider_in_targets() {
  [[ $1 =~ ^[A-Za-z0-9_-]+$ && -r $TARGETS ]] &&
    awk -F'\t' -v p="${1,,}" '!/^#/ && tolower($1) == p { f = 1; exit } END { exit !f }' "$TARGETS"
}

parse_args() {
  while (($#)); do
    case "$1" in
      -t|--targets) TARGETS=${2:?}; shift 2 ;;
      --no-targets) USE_TARGETS=0; shift ;;
      -p|--provider) add_provider "${2:?}"; shift 2 ;;
      --with-targets) FORCE_TARGETS=1; shift ;;
      --proto) PROTO_FILTER=${2:?}; shift 2 ;;
      -r|--region) REGION=${2:?}; shift 2 ;;
      -o|--out) OUT=${2:?}; shift 2 ;;
      -j|--jobs) JOBS=${2:?}; shift 2 ;;
      --timeout) TIMEOUT=${2:?}; shift 2 ;;
      --deep) DEEP=1; shift ;;
      --quick) QUICK=1; shift ;;
      --creds) CREDS=1; shift ;;
      --setup) SETUP=1; shift ;;
      --profile) export AWS_PROFILE=${2:?}; shift 2 ;;
      --no-discover) DISCOVER=0; shift ;;
      --local|--wifi) LOCAL=1; shift ;;
      -6|--ipv6) IPV6=1; shift ;;
      --all-regions) ALL_REGIONS=1; shift ;;
      --discover-max) DISCOVER_MAX=${2:?}; shift 2 ;;
      -y|--yes) ASSUME_YES=1; shift ;;
      -h|--help) usage; exit 0 ;;
      --version) echo "$VERSION"; exit 0 ;;
      --protocols) print_protocols; exit 0 ;;
      --) shift; ENDPOINTS+=("$@"); break ;;
      -*) die "unknown option: $1 (see --help)" ;;
      *)
        # a bare provider name (built in, or from the targets file) selects that provider;
        # anything else is an endpoint
        if provider_alias "$1" >/dev/null || provider_in_targets "$1"; then add_provider "$1"; else ENDPOINTS+=("$1"); fi
        shift ;;
    esac
  done
}

# Comma list of provider words -> canonical names, lower case, duplicates dropped
normalise_providers() {
  local p canon out=""
  for p in ${1//,/ }; do
    canon=$(provider_alias "$p") || canon=${p,,}
    [[ ",$out," == *",$canon,"* ]] || out+="${out:+,}$canon"
  done
  printf "%s" "$out"
}

validate_args() {
  [[ $TIMEOUT =~ ^[0-9]+$ && $JOBS =~ ^[1-9][0-9]*$ ]] || die "--timeout and --jobs must be positive integers"
  [[ -z $PROTO_FILTER || $PROTO_FILTER =~ $PROTO_RE ]] ||
    die "--proto must be one of: tls ssh quic dtls ike dnssec dnscurve dnscrypt starttls-smtp (imap, pop3, ldap, ftp, xmpp, postgres, mysql)"
  [[ -z $REGION || $REGION =~ ^[a-z0-9-]+(,[a-z0-9-]+)*$ ]] || die "invalid --region: $REGION (one region, or a comma list)"
  [[ -z ${AWS_PROFILE:-} || $AWS_PROFILE =~ ^[A-Za-z0-9._@+=,-]+$ ]] || die "invalid --profile name: $AWS_PROFILE"
  [[ $DISCOVER_MAX =~ ^[1-9][0-9]*$ ]] || die "--discover-max must be a positive integer"
}

# ------------------------------------------------------------------ target list
# Emits validated rows: provider<TAB>service<TAB>proto<TAB>host<TAB>port
valid_row() {
  local provider=$1 service=$2 proto=$3 host=$4 port=$5
  [[ $host =~ $HOST_RE && $host != *..* ]] || { log "rejected target (bad host, or {region} with no region set): $host"; return 1; }
  [[ ${provider^^} != ALL ]] || { log "rejected target (provider name ALL is reserved for totals): $host"; return 1; }
  [[ $port =~ ^[0-9]{1,5}$ ]] && ((port >= 1 && port <= 65535)) || { log "rejected target (bad port): $host:$port"; return 1; }
  [[ $proto =~ $PROTO_RE ]] || { log "rejected target (bad proto): $proto $host"; return 1; }
  [[ $provider =~ ^[A-Za-z0-9_-]+$ && $service =~ ^[A-Za-z0-9._-]+$ ]] || { log "rejected target (bad label): $provider/$service"; return 1; }
  printf '%s\t%s\t%s\t%s\t%s\n' "$provider" "$service" "$proto" "$host" "$port"
}

file_targets() {
  local provider service proto host port region regions
  while IFS=$'\t' read -r provider service proto host port _; do
    [[ -z $provider || $provider == \#* ]] && continue
    if [[ $host != *"{region}"* ]]; then valid_row "$provider" "$service" "$proto" "$host" "$port"; continue; fi
    # one row per region: --region may be a comma list, and --all-regions fills the AWS list from the account
    regions=${REGION:-$(default_region "$provider")}
    [[ $provider == aws && -n $AWS_REGIONS ]] && regions=$AWS_REGIONS
    for region in ${regions//,/ }; do
      valid_row "$provider" "$service" "$proto" "${host//\{region\}/$region}" "$port"
    done
  done <"$TARGETS"
}

endpoint_targets() {
  local spec provider proto host port path service defport
  for spec in "${ENDPOINTS[@]}"; do
    provider=custom proto="" port=""
    if [[ $spec == *=* ]]; then provider=${spec%%=*}; spec=${spec#*=}; fi
    if [[ $spec == *://* ]]; then proto=${spec%%://*}; spec=${spec#*://}; fi
    path="" service=cli-arg defport=443
    if [[ $spec == */* ]]; then path=${spec#*/}; path=${path%%/*}; fi
    spec=${spec%%/*}
    host=$spec
    if [[ $spec == *:* ]]; then host=${spec%:*}; port=${spec##*:}; fi
    # URL scheme -> probe type and default port
    case "${proto,,}" in
      https|tls) proto=tls ;;
      ssh|sftp) proto=ssh defport=22 ;;
      quic|h3|http3) proto=quic ;;
      doq) proto=doq defport=853 ;;
      ntp|nts) proto=ntp defport=123 ;;
      ech|httpsrr) proto=ech ;;
      # mail://DOMAIN[/DKIM-SELECTOR]
      mail) proto=mail defport=25; [[ -n $path ]] && service=cli-arg.$path ;;
      dtls) proto=dtls ;;
      ike|ikev2|ipsec) proto=ike defport=500 ;;
      dnssec) proto=dnssec defport=53 ;;
      dnscurve) proto=dnscurve defport=53 ;;
      # dnscrypt://RESOLVER-IP:PORT/PROVIDER-NAME  e.g. dnscrypt://9.9.9.9:8443/2.dnscrypt-cert.quad9.net
      dnscrypt) proto=dnscrypt; [[ -n $path ]] && service=cli-arg.$path ;;
      smtp|submission) proto=starttls-smtp defport=587 ;;
      imap) proto=starttls-imap defport=143 ;;
      pop3) proto=starttls-pop3 defport=110 ;;
      ldap) proto=starttls-ldap defport=389 ;;
      ftp) proto=starttls-ftp defport=21 ;;
      xmpp) proto=starttls-xmpp defport=5222 ;;
      postgres|postgresql) proto=starttls-postgres defport=5432 ;;
      mysql) proto=starttls-mysql defport=3306 ;;
      # TLS from the first byte: only the default port differs
      smtps) proto=tls defport=465 ;; imaps) proto=tls defport=993 ;; pop3s) proto=tls defport=995 ;;
      ldaps) proto=tls defport=636 ;; dot) proto=tls defport=853 ;; mqtts) proto=tls defport=8883 ;;
      amqps) proto=tls defport=5671 ;; rdp) proto=tls defport=3389 ;; ftps) proto=tls defport=990 ;;
      "") case "$port" in 22|2022|2222) proto=ssh defport=22 ;; *) proto=tls ;; esac ;;
      *) log "rejected endpoint (unknown scheme $proto): $spec"; continue ;;
    esac
    [[ -n $port ]] || port=$defport
    valid_row "$provider" "$service" "$proto" "$host" "$port"
  done
}

# ------------------------------------------------------------------ AWS account discovery
# When working AWS credentials are present, list the account's own internet-facing endpoints with
# read-only list/describe/get calls and scan them too. They are reported under the provider label
# "aws-account", kept apart from "aws": an ALB's TLS policy is the account owner's choice, not AWS's.
awsq() { AWS_PAGER="" timeout 120 aws "$@" --output json 2>>"$LOGFILE"; }

aws_credentials_ok() {
  local p err working=()
  have aws && have jq || return 1
  # 1. whatever the AWS CLI would use by itself: --profile, AWS_PROFILE, env keys, or the default profile
  if AWS_IDENTITY=$(awsq sts get-caller-identity) && [[ -n $AWS_IDENTITY ]]; then return 0; fi
  [[ -z ${AWS_PROFILE:-} ]] || { log "aws profile $AWS_PROFILE did not authenticate (SSO session expired? try: aws sso login --profile $AWS_PROFILE)"; return 1; }
  # 2. no usable default: try the named profiles. Exactly one working profile is used; several are never guessed between.
  while read -r p; do
    [[ $p =~ ^[A-Za-z0-9._@+=,-]+$ && $p != default ]] || continue
    if AWS_PROFILE=$p awsq sts get-caller-identity >/dev/null; then working+=("$p")
    else
      err=$(AWS_PROFILE=$p AWS_PAGER="" timeout 30 aws sts get-caller-identity 2>&1 >/dev/null | tr -d '\n' | cut -c1-90)
      case "$err" in
        *[Ee]xpired*|*sso*|*SSO*) log "aws profile $p: session expired (run: aws sso login --profile $p)" ;;
        *) log "aws profile $p: not usable (${err:-no details})" ;;
      esac
    fi
  done < <(AWS_PAGER="" aws configure list-profiles 2>/dev/null)
  if ((${#working[@]} == 1)); then
    export AWS_PROFILE=${working[0]}
    AWS_IDENTITY=$(awsq sts get-caller-identity)
    log "aws: no default credentials, using the only working profile: $AWS_PROFILE"
    return 0
  elif ((${#working[@]} > 1)); then
    log "aws: several profiles work (${working[*]}); pick one with --profile NAME. Not guessing."
  fi
  return 1
}

discover_aws_region() {
  local region=$1 arn name host port id n dh enc integ ike spec usage state manager domain alg status pqk pqa verdict note
  # Every AWS service endpoint in this region, from the public SSM parameters AWS maintains
  # (/aws/service/global-infrastructure). These are AWS-owned hosts, so they count under "aws".
  awsq ssm get-parameters-by-path --region "$region" --recursive \
    --path "/aws/service/global-infrastructure/regions/$region/services" |
    jq -r '.Parameters[]? | select(.Name | endswith("/endpoint")) | [(.Name | split("/")[-2]), (.Value | sub("^[a-z]+://"; "") | sub("/.*$"; ""))] | @tsv' |
    while IFS=$'\t' read -r name host; do
      [[ -n $host && $name =~ ^[A-Za-z0-9._-]+$ ]] && valid_row aws "$name" tls "$host" 443
    done

  # Application / Network Load Balancers: internet-facing, HTTPS or TLS listeners only
  while IFS=$'\t' read -r arn host; do
    [[ -n $arn ]] || continue
    while read -r port; do
      [[ -n $port ]] && valid_row aws-account "alb-nlb" tls "$host" "$port"
    done < <(awsq elbv2 describe-listeners --region "$region" --load-balancer-arn "$arn" |
      jq -r '.Listeners[]? | select(.Protocol == "HTTPS" or .Protocol == "TLS") | .Port')
  done < <(awsq elbv2 describe-load-balancers --region "$region" |
    jq -r --argjson max "$DISCOVER_MAX" '[.LoadBalancers[]? | select(.Scheme == "internet-facing")][:$max][] | [.LoadBalancerArn, .DNSName] | @tsv')

  # Classic Load Balancers
  awsq elb describe-load-balancers --region "$region" |
    jq -r --argjson max "$DISCOVER_MAX" '[.LoadBalancerDescriptions[]? | select(.Scheme == "internet-facing")][:$max][]
      | .DNSName as $h | .ListenerDescriptions[].Listener | select(.Protocol == "HTTPS" or .Protocol == "SSL") | [$h, .LoadBalancerPort] | @tsv' |
    while IFS=$'\t' read -r host port; do valid_row aws-account "classic-elb" tls "$host" "$port"; done

  # API Gateway: REST APIs, HTTP/WebSocket APIs, custom domain names
  awsq apigateway get-rest-apis --region "$region" | jq -r --argjson max "$DISCOVER_MAX" '[.items[]?.id][:$max][]' |
    while read -r id; do valid_row aws-account "apigw-rest" tls "$id.execute-api.$region.amazonaws.com" 443; done
  awsq apigatewayv2 get-apis --region "$region" |
    jq -r --argjson max "$DISCOVER_MAX" '[.Items[]?.ApiEndpoint // empty][:$max][] | sub("^[a-z]+://"; "")' |
    while read -r host; do valid_row aws-account "apigw-http" tls "$host" 443; done
  awsq apigateway get-domain-names --region "$region" | jq -r --argjson max "$DISCOVER_MAX" '[.items[]?.domainName][:$max][]' |
    while read -r host; do valid_row aws-account "apigw-domain" tls "$host" 443; done

  # Transfer Family (SFTP) servers with a public endpoint
  awsq transfer list-servers --region "$region" |
    jq -r --argjson max "$DISCOVER_MAX" '[.Servers[]? | select(.EndpointType == "PUBLIC") | .ServerId][:$max][]' |
    while read -r id; do valid_row aws-account "transfer-sftp" ssh "$id.server.transfer.$region.amazonaws.com" 22; done

  # OpenSearch domains with a public endpoint
  n=$(awsq opensearch list-domain-names --region "$region" | jq -r --argjson max "$DISCOVER_MAX" '[.DomainNames[]?.DomainName][:$max] | join(" ")')
  if [[ -n $n ]]; then
    # shellcheck disable=SC2086
    awsq opensearch describe-domains --region "$region" --domain-names $n | jq -r '.DomainStatusList[]? | .Endpoint // empty' |
      while read -r host; do valid_row aws-account "opensearch" tls "$host" 443; done
  fi

  # EKS control planes with public access
  awsq eks list-clusters --region "$region" | jq -r --argjson max "$DISCOVER_MAX" '[.clusters[]?][:$max][]' |
    while read -r name; do
      [[ $name =~ ^[A-Za-z0-9_-]+$ ]] || continue
      awsq eks describe-cluster --region "$region" --name "$name" |
        jq -r '.cluster | select(.resourcesVpcConfig.endpointPublicAccess == true) | .endpoint | sub("^[a-z]+://"; "")' |
        while read -r host; do valid_row aws-account "eks-api" tls "$host" 443; done
    done

  # Site-to-Site VPN tunnels: the IPsec settings come straight from the API, so no packets are sent.
  # These become finished result rows (proto vpn-config) rather than targets to probe.
  n=0
  while IFS='|' read -r id host dh enc integ ike; do
    [[ $id =~ ^vpn-[0-9a-f]+$ && $host =~ ^[0-9a-fA-F.:]+$ ]] || continue
    n=$((n + 1))
    emit_row aws-account "s2s-vpn.$id" vpn-config "$host" 500 CLASSICAL-ONLY \
      classical_kex="${dh:-aws-default-groups}" versions="${ike:-ikev1,ikev2}" \
      ciphers="${enc:-aws-default-ciphers}" auth_sig="${integ:-aws-default-integrity}" \
      note="read from the AWS API in $region, no packets sent; these IPsec options have no post-quantum key exchange" \
      >"$OUT/rows/zz-vpn-$region-$id-$n.tsv"
  done < <(awsq ec2 describe-vpn-connections --region "$region" |
    jq -r '.VpnConnections[]? | select(.State != "deleted") | .VpnConnectionId as $id | .Options.TunnelOptions[]?
      | [$id, (.OutsideIpAddress // ""),
         ([.Phase1DHGroupNumbers[]?.Value, .Phase2DHGroupNumbers[]?.Value] | unique | map("DH-group-\(.)") | join(",")),
         ([.Phase1EncryptionAlgorithms[]?.Value, .Phase2EncryptionAlgorithms[]?.Value] | unique | join(",")),
         ([.Phase1IntegrityAlgorithms[]?.Value, .Phase2IntegrityAlgorithms[]?.Value] | unique | join(",")),
         ([.IkeVersions[]?.Value] | unique | join(","))] | join("|")')

  # KMS keys: which key specs the account actually uses. AWS offers ML-DSA and ML-KEM specs; are they in use?
  n=0
  while IFS='|' read -r id spec usage state manager; do
    [[ $id =~ ^[0-9a-f-]+$ && $state == Enabled ]] || continue
    n=$((n + 1))
    pqk=""; pqa=no
    case "$spec" in
      ML_KEM*) pqk=$spec; verdict=PQ-ONLY; note="KMS key spec $spec" ;;
      ML_DSA*|SLH_DSA*) pqa=yes; verdict=PQ-ONLY; note="KMS key spec $spec" ;;
      SYMMETRIC_DEFAULT|HMAC_*) verdict=SYMMETRIC; note="symmetric KMS key: no public-key exposure, AES-256/HMAC are considered quantum-resistant" ;;
      *) verdict=CLASSICAL-ONLY; note="KMS key spec $spec; AWS also offers ML_DSA_44/65/87 key specs" ;;
    esac
    emit_row aws-account "kms.$manager" kms-key "$id" 0 "$verdict" \
      pq_kex="$pqk" versions="$usage" auth_key="$spec" pq_auth="$pqa" \
      note="$note (in $region, from the API, no packets sent)" \
      >"$OUT/rows/zz-kms-$region-$n.tsv"
  done < <(awsq kms list-keys --region "$region" | jq -r --argjson max "$DISCOVER_MAX" '[.Keys[]?.KeyId][:$max][]' |
    while read -r id; do
      awsq kms describe-key --region "$region" --key-id "$id" |
        jq -r '.KeyMetadata | [.KeyId, (.KeySpec // .CustomerMasterKeySpec // "unknown"), (.KeyUsage // ""), (.KeyState // ""), (.KeyManager // "")] | join("|")'
    done)

  # ACM certificates: key algorithms in use (ACM has no post-quantum key type yet)
  n=0
  while IFS='|' read -r domain alg status; do
    domain=${domain#\*.}
    [[ $domain =~ $HOST_RE && $status == ISSUED ]] || continue
    n=$((n + 1))
    emit_row aws-account "acm-cert" acm-cert "$domain" 0 CLASSICAL-ONLY auth_key="$alg" \
      note="ACM certificate key $alg (in $region, from the API, no packets sent); ACM offers no post-quantum key type yet" \
      >"$OUT/rows/zz-acm-$region-$n.tsv"
  done < <(awsq acm list-certificates --region "$region" --includes keyTypes=RSA_1024,RSA_2048,RSA_3072,RSA_4096,EC_prime256v1,EC_secp384r1,EC_secp521r1 |
    jq -r --argjson max "$DISCOVER_MAX" '[.CertificateSummaryList[]?][:$max][] | [.DomainName, (.KeyAlgorithm // ""), (.Status // "")] | join("|")')

  # Running EC2 instances with a public DNS name: SSH handshake on port 22 (no login is attempted)
  awsq ec2 describe-instances --region "$region" --filters Name=instance-state-name,Values=running |
    jq -r --argjson max "$DISCOVER_MAX" '[.Reservations[]?.Instances[]? | .PublicDnsName | select(. != null and length > 0)][:$max][]' |
    while read -r host; do valid_row aws-account "ec2-ssh" ssh "$host" 22; done
}

discover_aws() {
  local region
  # CloudFront is global: distribution domains and their alternate names (wildcards cannot be probed)
  awsq cloudfront list-distributions |
    jq -r --argjson max "$DISCOVER_MAX" '[.DistributionList.Items[]? | .DomainName, (.Aliases.Items[]?)][:$max][] | select(startswith("*") | not)' |
    while read -r host; do valid_row aws-account "cloudfront" tls "$host" 443; done
  for region in ${AWS_REGIONS//,/ }; do discover_aws_region "$region"; done
}

# --ipv6: every TLS/QUIC/SSH/DTLS row whose host has an AAAA record gets a second row probed over IPv6
add_ipv6_rows() {
  local provider service proto host port
  while IFS=$'\t' read -r provider service proto host port; do
    printf '%s\t%s\t%s\t%s\t%s\n' "$provider" "$service" "$proto" "$host" "$port"
    case "$proto" in tls|quic|doq|ssh|dtls|starttls-*) ;; *) continue ;; esac
    [[ $host =~ ^[0-9.]+$ ]] && continue
    if digq AAAA "$host" | grep -qE '^[0-9a-f:]+$'; then
      printf '%s\t%s.ipv6\t%s\t%s\t%s\n' "$provider" "$service" "$proto" "$host" "$port"
    fi
  done
}

build_targets() {
  {
    if ((USE_TARGETS)); then file_targets; fi
    if ((AWS_OK && DISCOVER)); then discover_aws; fi
    if [[ ${#ENDPOINTS[@]} -gt 0 ]]; then endpoint_targets; fi
  } | if ((IPV6)); then add_ipv6_rows; else cat; fi | awk -F'\t' -v provs="$PROVIDERS" -v proto="$PROTO_FILTER" '
      BEGIN { n = split(provs, a, ","); for (i = 1; i <= n; i++) want[a[i]] = 1 }
      ($2 ~ /^cli-arg/ || $1 == "aws-account" || n == 0 || ($1 in want)) && (proto == "" || $3 == proto) && !seen[$3 FS $4 FS $5 FS ($2 ~ /\.ipv6$/)]++'
}

# ------------------------------------------------------------------ result rows
# emit_row provider service proto host port verdict [field=value ...]
# One results.tsv row. Fields are named after the columns in ROW_FIELDS; any field left out or
# empty prints as "-", and pq_auth defaults to "no".
emit_row() {
  local -A field=([pq_auth]=no)
  local row kv name
  printf -v row '%s\t%s\t%s\t%s\t%s\t%s' "${@:1:6}"
  shift 6
  for kv in "$@"; do field[${kv%%=*}]=${kv#*=}; done
  for name in $ROW_FIELDS; do row+=$'\t'${field[$name]:--}; done
  printf '%s\n' "$row"
}

# need_tool TOOL provider service proto host port: true when TOOL is installed; otherwise writes
# the SKIPPED-NO-TOOL row for that target and fails, so a probe can say: need_tool dig ... || return 0
need_tool() {
  have "$1" && return 0
  emit_row "${@:2:5}" SKIPPED-NO-TOOL note="$1 not installed (run --setup)"
  return 1
}

# ------------------------------------------------------------------ TLS probe
# Extra s_client arguments for the probe in progress: QUIC (-quic -alpn h3), STARTTLS
# (-starttls smtp ...), IPv6 (-6). Probes shadow it with a local of the same name.
TLS_EXTRA=()

s_client() { # host port [openssl s_client args...]
  local host=$1 port=$2
  shift 2
  # QUIC output can contain NUL bytes, which bash would warn about
  timeout "$TIMEOUT" openssl s_client -connect "$host:$port" -servername "$host" "${TLS_EXTRA[@]}" "$@" </dev/null 2>&1 | tr -d '\000'
  return "${PIPESTATUS[0]}"
}

# --- parsers for an s_client transcript ($1) ---
tls_field() { awk -v key="$2" 'index($0, key) { sub(/^.*: */, ""); sub(/,.*$/, ""); gsub(/[ \r]+$/, ""); print; exit }' <<<"$1"; }
tls_cipher() { awk '/Cipher is/ { print $NF; exit }' <<<"$1"; }
tls_proto() { awk '/^ *Protocol *:/ { print $NF; exit } /^New, / { sub(/,$/, "", $2); p=$2 } END { if (p) print p }' <<<"$1" | head -n1; }
# "Peer Temp Key: ECDH, prime256v1, 256 bits" -> P-256 ; "X25519, 253 bits" -> X25519 ; "DH, 2048 bits" -> DH-2048
tls_temp_key() {
  awk -F': ' '
    /Temp Key/ {
      n = split($2, a, ", ")
      if (a[1] == "ECDH" && n > 2) {
        g = a[2]
        if (g == "prime256v1") g = "P-256"
        if (g == "secp384r1") g = "P-384"
        if (g == "secp521r1") g = "P-521"
        print g
      } else if (a[1] == "DH") {
        sub(/ bits.*/, "", a[2])
        print "DH-" a[2]
      } else print a[1]
      exit
    }' <<<"$1"
}
# A handshake counts only when s_client exits 0 AND a real cipher was negotiated.
hs_ok() { local c; c=$(tls_cipher "$2"); [[ $1 -eq 0 && -n $c && $c != "(NONE)" && $c != 0000 ]]; }

# --- parsers for "openssl x509 -text" on stdin ---
# Key algorithm and size, e.g. rsaEncryption-2048; the bare algorithm when no size is printed
cert_key_type() {
  awk '/Public Key Algorithm:/ { a = $NF } /Public-Key:/ { gsub(/[()]/, ""); print a "-" $2; f = 1; exit } END { if (!f && a) print a }'
}
cert_sig_alg() { awk '/Signature Algorithm:/ { print $NF; exit }'; }

# Certificate chain summary from an s_client -showcerts transcript:
#   chain=RSA-2048/sha256WithRSAEncryption > RSA-4096/...
# with a WEAK marker for RSA under 2048, SHA-1 or MD5 signatures, or DSA anywhere in the chain.
chain_summary() {
  local dir f text key sig out="" weak=""
  dir=$(mktemp -d) || return 0
  awk -v d="$dir" '/-----BEGIN CERTIFICATE-----/ { n++; f = d "/c" n ".pem" } f { print > f } /-----END CERTIFICATE-----/ { f = "" }' <<<"$1"
  for f in "$dir"/c*.pem; do
    [[ -e $f ]] || break
    text=$(openssl x509 -in "$f" -noout -text 2>/dev/null)
    key=$(cert_key_type <<<"$text")
    sig=$(cert_sig_alg <<<"$text")
    key=${key/rsaEncryption/RSA}; key=${key/id-ecPublicKey/EC}
    out+="${out:+ > }${key}/${sig}"
    [[ $key =~ ^RSA-(512|768|1024)$ || $sig =~ [Ss][Hh][Aa]1|md5|dsa ]] && weak="WEAK:${key}/${sig}"
  done
  rm -rf "$dir"
  [[ -n $out ]] && printf 'chain=%s%s' "$out" "${weak:+ $weak}"
}

# --- second opinions from curl: some front ends treat s_client and curl differently ---
# Prints the negotiated group when curl completes a PQ-only TLS 1.3 handshake.
curl_pq_group() { # host port
  have curl || return 1
  # -q and --noproxy: ignore ~/.curlrc and proxy env so curl talks to the same endpoint s_client did
  curl -q --noproxy '*' -sv -o /dev/null --max-time "$TIMEOUT" --tlsv1.3 --curves "$CLIENT_PQ_GROUPS" "https://$1:$2/" 2>&1 |
    awk -F' / ' '/SSL connection using/ { print $3; exit }' | grep -iE "$PQ_NAME_RE"
}
# The same over HTTP/3: prints the group when curl completes a QUIC handshake
# (curl needs an HTTP/3 build; the version line lists "HTTP3" when it has one)
curl_h3_group() { # host port groups
  have curl && curl --version | grep -q HTTP3 || return 1
  curl -q --noproxy '*' -sv -o /dev/null --max-time "$TIMEOUT" --http3-only --curves "$3" "https://$1:$2/" 2>&1 |
    awk -F' / ' '/SSL connection using/ { print $3; exit }' | grep -E '.'
}

# --- probe_tls and its phases ---
# The tls_* phase functions are called only from probe_tls and share its locals (bash dynamic
# scoping): the target (host port mode label pin13 TLS_EXTRA), the findings (pq_groups cl_groups
# versions ciphers auth_key auth_sig pq_auth chain note verdict) and the flags (pq_ok cl_ok has13
# grp_args). HS_OUT and HS_RC hold the transcript and exit code of the last handshake.

# handshake ARGS...: one s_client run against the target; true only for a completed handshake
handshake() {
  HS_OUT=$(s_client "$host" "$port" "$@"); HS_RC=$?
  hs_ok "$HS_RC" "$HS_OUT"
}

# 1. classical-only offer, version unpinned: reachability, preferred group, certificate
tls_classical_offer() {
  local cert
  if handshake -showcerts -groups "$CLASSICAL_OFFER"; then
    cl_ok=1
    chain=$(chain_summary "$HS_OUT")
    cl_groups=$(tls_field "$HS_OUT" "Negotiated TLS1.3 group")
    [[ -z $cl_groups || $cl_groups == "<NULL>" ]] && cl_groups=$(tls_temp_key "$HS_OUT")
    [[ -z $cl_groups ]] && cl_groups="no-ephemeral-key(static-RSA)"
    versions=$(tls_proto "$HS_OUT")
    ciphers=$(tls_cipher "$HS_OUT")
    auth_sig=$(tls_field "$HS_OUT" "Peer signature type")
    cert=$(openssl x509 -noout -text <<<"$HS_OUT" 2>/dev/null)
    if [[ -n $cert ]]; then
      auth_key=$(cert_key_type <<<"$cert")
      auth_sig=$(csv_merge "cert:$(cert_sig_alg <<<"$cert")" "${auth_sig:+handshake:$auth_sig}")
      grep -qiE "$PQ_SIG_RE" <<<"$auth_key" && pq_auth=yes
    fi
  elif grep -qiE 'connect:errno|BIO_lookup|Name or service|No route|refused|getaddrinfo' <<<"$HS_OUT"; then
    note="connect-failed"
  elif ((HS_RC == 124)); then
    # A timeout is not proof of a dead host: a PQ-only front end may black-hole classical hellos.
    # One combined PQ offer decides whether the full PQ enumeration is worth running.
    note="classical-probe-timeout"
    if [[ -z $CLIENT_PQ_GROUPS ]] || ! handshake "${pin13[@]}" -groups "$CLIENT_PQ_GROUPS"; then note="connect-failed"; fi
  fi
}

# 2. PQ-only offers (PQ groups exist only in TLS 1.3). Full mode tests each group alone,
#    because one combined offer only reveals the server's first pick.
tls_pq_offers() {
  local g
  [[ -n $CLIENT_PQ_GROUPS ]] || return 0
  # under QUIC s_client does not print the group name, so only single-group offers can name it
  if ((QUICK)) && [[ $label != quic ]]; then
    if handshake "${pin13[@]}" -groups "$CLIENT_PQ_GROUPS"; then
      g=$(tls_field "$HS_OUT" "Negotiated TLS1.3 group")
      if grep -qiE "$PQ_NAME_RE" <<<"$g"; then pq_groups=$g; fi
    fi
  else
    for g in ${CLIENT_PQ_GROUPS//:/ }; do
      if handshake "${pin13[@]}" -groups "$g" &&
        { [[ $label == quic ]] || [[ $(tls_field "$HS_OUT" "Negotiated TLS1.3 group") == "$g" ]]; }; then
        append_csv pq_groups "$g"
      fi
    done
  fi
  if [[ -z $pq_groups && $mode == tls ]] && pq_groups=$(curl_pq_group "$host" "$port"); then
    note="pq-confirmed-by-curl-only"
  fi
  if [[ -n $pq_groups ]]; then pq_ok=1; versions=$(csv_merge TLSv1.3 "$versions"); fi
}

# 3. each classical group alone. Record what was NEGOTIATED, not what was offered: a server
#    that lacks the offered group may fall back to TLS 1.2 DHE/RSA and still complete.
tls_classical_offers() {
  local g negotiated
  for g in ${CLASSICAL_GROUPS//:/ }; do
    handshake -groups "$g" || continue
    negotiated=$(tls_temp_key "$HS_OUT")
    append_csv cl_groups "${negotiated:-no-ephemeral-key(static-RSA)}"
    append_csv ciphers "$(tls_cipher "$HS_OUT")"
  done
}

# 4 and 5. which TLS versions are accepted, and which TLS 1.3 suites
tls_versions_and_suites() {
  local cs
  # a PQ-only server needs a PQ group in the remaining probes
  if ((!cl_ok)); then grp_args=(-groups "${pq_groups//,/:}"); fi
  [[ $versions == *TLSv1.3* ]] && has13=1
  # the classical offer may have landed on TLS 1.2 even though the server speaks 1.3
  if ((!has13)) && handshake "${pin13[@]}"; then has13=1; versions=$(csv_merge TLSv1.3 "$versions"); fi

  # TLS 1.2 still accepted? (records the server-preferred 1.2 suite; --deep lists them all)
  if [[ $label != quic ]] && handshake -tls1_2; then
    append_csv versions TLSv1.2
    append_csv ciphers "$(tls_cipher "$HS_OUT")"
  fi

  # each TLS 1.3 cipher suite alone (--quick: only the server's preferred one)
  ((has13)) || return 0
  if ((QUICK)); then
    if handshake "${pin13[@]}" "${grp_args[@]}"; then append_csv ciphers "$(tls_cipher "$HS_OUT")"; fi
    return 0
  fi
  for cs in $TLS13_SUITES; do
    if handshake "${pin13[@]}" -ciphersuites "$cs" "${grp_args[@]}"; then append_csv ciphers "$cs"; fi
  done
}

# 6. PQ-signature-only offer. "Cipher is" still prints on a sigalg failure, so
#    success is the exit code plus a PQ "Peer signature type".
tls_pq_signature() {
  local sig
  if [[ -z $CLIENT_PQ_SIGALGS ]]; then pq_auth=unknown; return 0; fi
  ((has13)) || return 0
  handshake "${pin13[@]}" -sigalgs "$CLIENT_PQ_SIGALGS" "${grp_args[@]}" || return 0
  sig=$(tls_field "$HS_OUT" "Peer signature type")
  if grep -qiE "$PQ_SIG_RE" <<<"$sig"; then pq_auth=yes; append_csv auth_sig "handshake:$sig"; fi
}

tls_verdict() {
  if ((pq_ok && cl_ok)); then
    # hybrid names carry a classical curve prefix (X25519…, SecP256r1…); pure ones start with MLKEM
    if tr ',' '\n' <<<"$pq_groups" | grep -qivE '^mlkem'; then verdict=PQ-HYBRID+CLASSICAL; else verdict=PQ-PURE+CLASSICAL; fi
  elif ((pq_ok)); then verdict=PQ-ONLY
  elif ((cl_ok)) && [[ -z $CLIENT_PQ_GROUPS ]]; then verdict=UNKNOWN-CLIENT-NO-PQ
  elif ((cl_ok)); then verdict=CLASSICAL-ONLY
  elif [[ $note == connect-failed ]]; then verdict=UNREACHABLE
  else verdict=HANDSHAKE-FAILED
  fi
}

# OpenSSL's QUIC client is minimal: before a failed QUIC probe is called "not offered", let curl try
# HTTP/3 too, then check whether the server advertises HTTP/3 at all (alt-svc on the HTTPS response).
tls_quic_second_opinion() {
  local g
  if g=$(curl_h3_group "$host" "$port" "${CLIENT_PQ_GROUPS:-X25519}"); then
    cl_groups=$g; verdict=CLASSICAL-ONLY; note="quic-confirmed-by-curl-only"
    if grep -qiE "$PQ_NAME_RE" <<<"$g"; then pq_groups=$g cl_groups=""; verdict=PQ-HYBRID+CLASSICAL; fi
  elif have curl && curl -q --noproxy '*' -sI --max-time "$TIMEOUT" "https://$host:$port/" 2>/dev/null | grep -qi '^alt-svc:.*h3'; then
    verdict=HANDSHAKE-FAILED
    note="server advertises HTTP/3 (alt-svc h3) but neither openssl nor curl could complete a QUIC handshake"
  else
    verdict=NOT-OFFERED
    note="server does not advertise HTTP/3 (no alt-svc h3 header); nothing to test over QUIC"
  fi
}

probe_tls() {
  local provider=$1 service=$2 host=$3 port=$4 mode=${5:-tls}
  # QUIC is TLS 1.3 only and s_client rejects -tls1_3 with -quic; STARTTLS upgrades a plaintext session first
  local label=tls pin13=(-tls1_3) TLS_EXTRA=()
  [[ $service == *.ipv6 ]] && TLS_EXTRA=(-6)
  case "$mode" in
    quic) label=quic pin13=() TLS_EXTRA+=(-quic -alpn h3) ;;
    doq) label=quic pin13=() TLS_EXTRA+=(-quic -alpn doq) ;;
    starttls-*) TLS_EXTRA+=(-starttls "${mode#starttls-}") ;;
  esac
  local HS_OUT="" HS_RC=0 pq_ok=0 cl_ok=0 has13=0 grp_args=()
  local pq_groups="" cl_groups="" versions="" ciphers="" auth_key="" auth_sig="" pq_auth=no chain="" note="" verdict

  tls_classical_offer
  if [[ $note != connect-failed ]]; then
    tls_pq_offers
    if ((cl_ok && !QUICK)); then tls_classical_offers; fi
  fi
  if ((pq_ok || cl_ok)); then
    tls_versions_and_suites
    tls_pq_signature
  fi
  tls_verdict

  [[ $mode == starttls-* || $mode == doq ]] && note="${note:+$note }${mode}"
  [[ $service == *.ipv6 ]] && note="${note:+$note }over-IPv6"
  [[ -n $chain ]] && note="${note:+$note; }$chain"
  if [[ $label == quic && $verdict == @(UNREACHABLE|HANDSHAKE-FAILED) ]]; then tls_quic_second_opinion; fi

  emit_row "$provider" "$service" "$label" "$host" "$port" "$verdict" \
    pq_kex="$pq_groups" classical_kex="$cl_groups" versions="$versions" ciphers="$ciphers" \
    auth_key="$auth_key" auth_sig="$auth_sig" pq_auth="$pq_auth" note="$note"
}

# ------------------------------------------------------------------ SSH probe
# Value of one list from the SERVER's KEXINIT block only (the client block precedes it).
ssh_srv_list() {
  awk -v key="debug2: $2: " '
    /peer server KEXINIT proposal/ { f=1; next }
    f && index($0, key) == 1 { v=substr($0, length(key) + 1); gsub(/\r/, "", v); print v; exit }' <<<"$1" |
    tr ',' '\n' | grep -vE '^(kex-strict-|ext-info-)' | csv
}

probe_ssh() {
  local provider=$1 service=$2 host=$3 port=$4
  local out kex hostkeys ciphers macs auth banner neg_kex neg_hostkey pq classical verdict pq_auth=no note="" ip6=()
  [[ $service == *.ipv6 ]] && ip6=(-6)

  # Everything parsed below is server-controlled text: tabs and control bytes are stripped so a
  # hostile server cannot shift TSV columns or inject terminal escapes.
  out=$(timeout "$((TIMEOUT + 6))" ssh -vv -F /dev/null \
    -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o GlobalKnownHostsFile=/dev/null -o PreferredAuthentications=none \
    -o ConnectTimeout="$TIMEOUT" -p "$port" "${ip6[@]}" -- "$SSH_PROBE_USER@$host" true 2>&1 |
    tr -d '\t\r' | tr -cd '[:print:]\n')

  kex=$(ssh_srv_list "$out" "KEX algorithms")
  hostkeys=$(ssh_srv_list "$out" "host key algorithms")
  ciphers=$(ssh_srv_list "$out" "ciphers stoc")
  macs=$(ssh_srv_list "$out" "MACs stoc")
  auth=$(awk -F': ' '/Authentications that can continue/ { gsub(/\r/, "", $NF); print $NF; exit }' <<<"$out")
  banner=$(awk -F'remote software version ' '/remote software version/ { gsub(/[\r\t]/, "", $2); print $2; exit }' <<<"$out")
  neg_kex=$(awk -F': ' '/debug1: kex: algorithm:/ { print $NF; exit }' <<<"$out")
  neg_hostkey=$(awk -F': ' '/debug1: kex: host key algorithm:/ { print $NF; exit }' <<<"$out")

  pq=$(tr ',' '\n' <<<"$kex" | grep -iE "$PQ_NAME_RE" | csv)
  classical=$(tr ',' '\n' <<<"$kex" | grep -ivE "$PQ_NAME_RE" | csv)
  grep -qiE "$PQ_SIG_RE" <<<"$hostkeys" && pq_auth=yes

  if [[ -z $kex ]]; then
    # TCP connected but no SSH KEXINIT came back: the port is open, it just is not (usable) SSH
    if grep -q 'Connection established' <<<"$out"; then verdict=HANDSHAKE-FAILED; else verdict=UNREACHABLE; fi
    note=$(grep -m1 -E '^ssh: |Could not resolve|Connection (refused|timed out|reset|closed)|No route to host' <<<"$out" | cut -c1-80)
  elif [[ -n $pq && -n $classical ]]; then verdict=PQ-HYBRID+CLASSICAL
  elif [[ -n $pq ]]; then verdict=PQ-ONLY
  else verdict=CLASSICAL-ONLY
  fi
  [[ -n $neg_kex ]] && note="negotiated:$neg_kex${note:+ $note}"
  [[ -n $banner ]] && note="${note:+$note }banner:$banner"

  emit_row "$provider" "$service" ssh "$host" "$port" "$verdict" \
    pq_kex="$pq" classical_kex="$classical" versions=SSH-2.0 auth_key="$neg_hostkey" pq_auth="$pq_auth" \
    srv_kex="$kex" srv_hostkeys="$hostkeys" srv_ciphers="$ciphers" srv_macs="$macs" user_auth="$auth" note="$note"
}

# ------------------------------------------------------------------ DNS probes
# dig with a fallback chain: the system resolver first, then public ones. Large answers (DNSKEY)
# are asked over TCP, because fragmented UDP replies are dropped on many networks.
digq() { # type name [extra dig args...]
  local type=$1 name=$2 r out
  shift 2
  for r in "" 8.8.8.8 9.9.9.9 1.1.1.1; do
    out=$(dig +short +timeout=3 +tries=2 "$@" ${r:+@"$r"} "$type" "$name" 2>/dev/null | grep -v '^;')
    if [[ -n $out ]]; then printf '%s\n' "$out"; return 0; fi
  done
  return 1
}

dnssec_alg_name() {
  case "$1" in
    1) echo RSAMD5 ;; 3) echo DSA ;; 5) echo RSASHA1 ;; 6) echo DSA-NSEC3-SHA1 ;; 7) echo RSASHA1-NSEC3-SHA1 ;;
    8) echo RSASHA256 ;; 10) echo RSASHA512 ;; 12) echo ECC-GOST ;; 13) echo ECDSAP256SHA256 ;;
    14) echo ECDSAP384SHA384 ;; 15) echo ED25519 ;; 16) echo ED448 ;; *) echo "alg-$1" ;;
  esac
}

# DNSSEC is a signature scheme: the question is which algorithm signs the zone.
probe_dnssec() {
  local provider=$1 service=$2 zone=$3 port=$4 keys ds algs="" dsinfo="" a note="" verdict pq_auth=no
  local target=("$provider" "$service" dnssec "$zone" "$port")
  need_tool dig "${target[@]}" || return 0
  keys=$(digq DNSKEY "$zone" +tcp)
  ds=$(digq DS "$zone")
  for a in $(awk '{ print $3 }' <<<"$keys" | sort -un); do append_csv algs "$(dnssec_alg_name "$a")"; done
  for a in $(awk '{ print $2 }' <<<"$ds" | sort -un); do append_csv dsinfo "DS:$(dnssec_alg_name "$a")"; done
  if [[ -z $algs && -z $dsinfo ]]; then
    if digq NS "$zone" >/dev/null; then verdict=NOT-OFFERED note="zone is not signed"; else verdict=UNREACHABLE note="no DNS answer for zone"; fi
  else
    verdict=CLASSICAL-ONLY
    [[ -n $algs && -z $dsinfo ]] && note="signed, but no DS at the parent (not chained to the root)"
    if grep -qiE "$PQ_SIG_RE" <<<"$algs"; then pq_auth=yes verdict=PQ-SIGNED; fi
  fi
  emit_row "${target[@]}" "$verdict" versions=DNSSEC auth_key="$algs" auth_sig="$dsinfo" pq_auth="$pq_auth" note="$note"
}

# DNSCurve announces itself in the NS names: a label starting uz5 is the server's Curve25519 public key.
probe_dnscurve() {
  local provider=$1 service=$2 zone=$3 port=$4 ns n
  local target=("$provider" "$service" dnscurve "$zone" "$port")
  need_tool dig "${target[@]}" || return 0
  ns=$(digq NS "$zone") || { emit_row "${target[@]}" UNREACHABLE note="no NS answer"; return; }
  n=$(grep -ciE '^uz5[0-9a-z]{51}\.' <<<"$ns")
  if ((n > 0)); then
    emit_row "${target[@]}" CLASSICAL-ONLY classical_kex=X25519 versions=DNSCurve ciphers=XSalsa20-Poly1305 \
      auth_key=Curve25519-key-in-NS-name note="$n of $(wc -l <<<"$ns") name servers speak DNSCurve"
  else
    emit_row "${target[@]}" NOT-OFFERED note="no uz5 name servers"
  fi
}

# DNSCrypt resolvers publish a certificate as a TXT record; bytes 5-6 are the cipher-suite version.
# The "service" field carries the provider name, e.g. 2.dnscrypt-cert.quad9.net.
probe_dnscrypt() {
  local provider=$1 name=$2 host=$3 port=$4 txt es="" v
  local target=("$provider" "$name" dnscrypt "$host" "$port")
  need_tool dig "${target[@]}" || return 0
  txt=$(dig +short +timeout=5 +tries=2 @"$host" -p "$port" TXT "$name" 2>/dev/null | grep -a 'DNSC')
  if [[ -z $txt ]]; then
    emit_row "${target[@]}" UNREACHABLE note="no DNSCrypt certificate for that provider name"
    return
  fi
  for v in $(grep -aoE 'DNSC\\000\\00[0-9]' <<<"$txt" | grep -oE '[0-9]$' | sort -u); do
    case "$v" in
      1) append_csv es XSalsa20-Poly1305 ;;
      2) append_csv es XChaCha20-Poly1305 ;;
      *) append_csv es "es-version-$v" ;;
    esac
  done
  emit_row "${target[@]}" CLASSICAL-ONLY classical_kex=X25519 versions=DNSCrypt-v2 ciphers="$es" \
    auth_key=Ed25519-signed-cert note="DNSCrypt defines no post-quantum suite"
}

# HTTPS DNS record (type 65): advertised ALPNs, IPv6 hints, and an Encrypted Client Hello config whose
# KEM is the only key-exchange choice in ECH. The record is signed by DNSSEC where the zone is signed.
probe_ech() {
  local provider=$1 service=$2 name=$3 port=$4 rr alpn="" ech="" kem="" kemid verdict
  local target=("$provider" "$service" ech "$name" "$port")
  need_tool dig "${target[@]}" || return 0
  rr=$(digq HTTPS "$name" | head -n1)
  if [[ -z $rr ]]; then emit_row "${target[@]}" NOT-OFFERED note="no HTTPS DNS record"; return; fi
  alpn=$(grep -oE 'alpn="[^"]+"' <<<"$rr" | cut -d'"' -f2)
  ech=$(grep -oE 'ech=[A-Za-z0-9+/=]+' <<<"$rr" | cut -d= -f2-)
  if [[ -z $ech ]]; then
    emit_row "${target[@]}" NOT-OFFERED note="HTTPS record present${alpn:+ (alpn=$alpn)} but no ECH config"
    return
  fi
  # ECHConfigList: 2-byte list length, then ECHConfig: version(2) length(2) config_id(1) kem_id(2)
  kemid=$(printf '%s' "$ech" | base64 -d 2>/dev/null | od -An -tx1 -j7 -N2 | tr -d ' \n')
  case "$kemid" in
    0020) kem=DHKEM-X25519 ;;
    0010) kem=DHKEM-P256 ;;
    0011) kem=DHKEM-P384 ;;
    0012) kem=DHKEM-P521 ;;
    0021) kem=DHKEM-X448 ;;
    "") kem=unparsed ;;
    *) kem="kem-0x$kemid" ;;
  esac
  if grep -qiE "$PQ_NAME_RE" <<<"$kem"; then verdict=PQ-HYBRID+CLASSICAL; else verdict=CLASSICAL-ONLY; fi
  emit_row "${target[@]}" "$verdict" classical_kex="$kem" versions=ECH/HPKE \
    note="ECH config present; HPKE KEM $kem${alpn:+; alpn=$alpn}"
}

# Mail DNS for a domain: DKIM signing keys (common selectors, or mail://domain/SELECTOR), DANE TLSA
# records on the MX hosts, and the MTA-STS policy. All of it is signature or pinning; none is PQ today.
readonly DKIM_SELECTORS="google selector1 selector2 default k1 k2 s1 s2 dkim mail smtp 20230601 20221208 20210112 protonmail pm mandrill amazonses everlytickey1 fm1 fm2 mx zendesk1 sig1 mimecast20190328 cm k3"
probe_mail() {
  local provider=$1 service=$2 domain=$3 port=$4 sel rec p key keys="" mxs mx tlsa="" sts="" mode="" weak="" note="" n=0
  local target=("$provider" "$service" mail "$domain" "$port")
  need_tool dig "${target[@]}" || return 0
  local selectors=$DKIM_SELECTORS
  [[ $service == cli-arg.* ]] && selectors=${service#cli-arg.}

  # DKIM: at most four keys
  for sel in $selectors; do
    rec=$(digq TXT "$sel._domainkey.$domain" | grep -v '\.$' | tr -d '"' | tr -d ' ') || continue
    [[ $rec == *DKIM1* || $rec == *p=* ]] || continue
    p=$(grep -oE 'p=[A-Za-z0-9+/=]+' <<<"$rec" | head -n1 | cut -c3-)
    [[ -n $p ]] || { append_csv keys "$sel:revoked"; continue; }
    key=$(printf '%s' "$p" | base64 -d 2>/dev/null | openssl pkey -pubin -inform DER -noout -text 2>/dev/null |
      awk '/ED25519/ { print "ed25519"; exit } /Public-Key:/ { gsub(/[()]/, ""); print "rsa-" $2; exit }')
    [[ -n $key ]] || key=$(grep -oE 'k=[a-z0-9]+' <<<"$rec" | head -n1 | cut -c3-)
    append_csv keys "$sel:${key:-unknown}"
    [[ $key =~ ^rsa-(512|768|1024)$ ]] && weak="${weak:+$weak,}$sel:$key"
    n=$((n + 1)); ((n >= 4)) && break
  done

  # DANE TLSA on the first three MX hosts
  mxs=$(digq MX "$domain" | sort -n | awk '{ print $2 }' | sed 's/\.$//' | head -n3)
  for mx in $mxs; do
    rec=$(digq TLSA "_25._tcp.$mx") || continue
    append_csv tlsa "$mx:$(awk '{ print "usage" $1 "/sel" $2 "/match" $3 }' <<<"$rec" | head -n1)"
  done

  # MTA-STS policy mode
  sts=$(digq TXT "_mta-sts.$domain" | tr -d '"' | grep -o 'v=STSv1' | head -n1)
  if [[ -n $sts ]] && have curl; then
    mode=$(curl -q --noproxy '*' -s --max-time "$TIMEOUT" "https://mta-sts.$domain/.well-known/mta-sts.txt" 2>/dev/null |
      tr -d '\r' | awk -F': *' '/^mode:/ { print $2; exit }')
    mode="MTA-STS:${mode:-published}"
  fi

  if [[ -z $keys && -z $tlsa && -z $mode ]]; then
    if [[ -n $mxs ]]; then
      note="MX found (${mxs//$'\n'/,}) but no DKIM key under common selectors, no DANE, no MTA-STS; try mail://$domain/SELECTOR"
    else
      note="no MX record: domain does not receive mail"
    fi
    emit_row "${target[@]}" NOT-OFFERED note="$note"
    return
  fi
  note="DKIM/DANE/MTA-STS are all classical today${weak:+; WEAK DKIM keys: $weak}"
  [[ -z $keys ]] && note="no DKIM key found under common selectors; $note"
  emit_row "${target[@]}" CLASSICAL-ONLY versions="${mode:-no-MTA-STS}" auth_key="$keys" auth_sig="${tlsa:-no-DANE}" note="$note"
}

# ------------------------------------------------------------------ VPN and time probes
# DTLS carries SSL-VPN data channels (AnyConnect, ocserv, Fortinet). DTLS 1.2 has no PQ groups and
# OpenSSL has no DTLS 1.3 yet, so a completed handshake means classical.
probe_dtls() {
  local provider=$1 service=$2 host=$3 port=$4 out rc versions="" ciphers="" group="" auth_key="" v
  local target=("$provider" "$service" dtls "$host" "$port")
  for v in dtls1_2 dtls1; do
    out=$(timeout "$TIMEOUT" openssl s_client "-$v" -connect "$host:$port" </dev/null 2>&1); rc=$?
    hs_ok "$rc" "$out" || continue
    append_csv versions "$(tls_proto "$out")"
    append_csv ciphers "$(tls_cipher "$out")"
    [[ -n $group ]] || group=$(tls_temp_key "$out")
    [[ -n $auth_key ]] || auth_key=$(openssl x509 -noout -text <<<"$out" 2>/dev/null | cert_key_type)
  done
  if [[ -n $versions ]]; then
    emit_row "${target[@]}" CLASSICAL-ONLY classical_kex="$group" versions="$versions" ciphers="$ciphers" \
      auth_key="$auth_key" note="DTLS 1.2 defines no post-quantum groups"
  else
    emit_row "${target[@]}" UNREACHABLE note="no DTLS answer (UDP)"
  fi
}

# IKE (IPsec VPN gateways). ike-scan shows the transforms a gateway accepts without authenticating.
# It cannot offer the RFC 9370 additional key exchanges, so ML-KEM support is not testable here.
probe_ike() {
  local provider=$1 service=$2 host=$3 port=$4 out sa enc="" dh="" integ="" versions="" f
  local target=("$provider" "$service" ike "$host" "$port")
  need_tool ike-scan "${target[@]}" || return 0
  for f in --ikev2 ""; do
    # shellcheck disable=SC2086
    out=$(timeout "$((TIMEOUT + 6))" ike-scan $f --sport=0 --dport="$port" --retry=2 -M "$host" 2>&1)
    sa=$(grep -E 'SA=\(|Enc=|Encr=' <<<"$out" | tr -d '\t' | tr '\n' ' ')
    [[ -n $sa ]] || continue
    if [[ -n $f ]]; then append_csv versions IKEv2; else append_csv versions IKEv1; fi
    append_csv enc "$(grep -oE 'Encr?=[A-Za-z0-9_-]+(,KeyLength=[0-9]+)?' <<<"$sa" | sed -E 's/Encr?=//; s/,KeyLength=/-/')"
    append_csv integ "$(grep -oE '(Integ|Hash)=[A-Za-z0-9_-]+' <<<"$sa" | sed -E 's/^[A-Za-z]+=//')"
    append_csv dh "$(grep -oE '(DH_Group|Group)=[0-9]+:[A-Za-z0-9_-]+' <<<"$sa" | sed -E 's/^[A-Za-z_]+=[0-9]+://')"
  done
  if [[ -n $versions ]]; then
    emit_row "${target[@]}" CLASSICAL-ONLY classical_kex="$dh" versions="$versions" ciphers="$enc" auth_sig="$integ" \
      note="ike-scan cannot offer ML-KEM (RFC 9370); only the classical transforms are visible"
  else
    emit_row "${target[@]}" UNREACHABLE note="no IKE answer (UDP); gateways often ignore unknown peers"
  fi
}

# NTP: an unauthenticated NTP query on UDP 123 shows the server answers at all; NTS-KE on TCP 4460
# (TLS 1.3 with ALPN ntske/1) is the only cryptographic protection NTP has. The verdict follows NTS.
probe_ntp() {
  local provider=$1 service=$2 host=$3 port=$4 out rc g raw="" nts=0 pq="" cl="" ciphers="" auth_key="" note=""
  local target=("$provider" "$service" ntp "$host" "$port")
  if have nc; then
    raw=$({ printf '\x23'; head -c 47 /dev/zero; } | timeout 6 nc -u -w 3 "$host" "$port" 2>/dev/null | od -An -tx1 | tr -d ' \n')
    if [[ -n $raw ]]; then note="NTP on UDP $port answers (stratum $((16#${raw:2:2}))), unauthenticated"; else note="no NTP answer on UDP $port"; fi
  else
    note="nc not installed, plain NTP not probed"
  fi

  local TLS_EXTRA=(-alpn ntske/1)
  out=$(s_client "$host" 4460 -groups "$CLASSICAL_OFFER"); rc=$?
  if hs_ok "$rc" "$out" && grep -q 'ALPN protocol: ntske/1' <<<"$out"; then
    nts=1
    cl=$(tls_temp_key "$out")
    ciphers=$(tls_cipher "$out")
    auth_key=$(openssl x509 -noout -text <<<"$out" 2>/dev/null | cert_key_type)
    for g in ${CLIENT_PQ_GROUPS//:/ }; do
      out=$(s_client "$host" 4460 -tls1_3 -groups "$g"); rc=$?
      if hs_ok "$rc" "$out" && [[ $(tls_field "$out" "Negotiated TLS1.3 group") == "$g" ]]; then append_csv pq "$g"; fi
    done
  fi

  if ((nts)) && [[ -n $pq ]]; then
    emit_row "${target[@]}" PQ-HYBRID+CLASSICAL pq_kex="$pq" classical_kex="$cl" versions=NTS-KE/TLSv1.3 \
      ciphers="$ciphers" auth_key="$auth_key" note="NTS on 4460; $note"
  elif ((nts)); then
    emit_row "${target[@]}" CLASSICAL-ONLY classical_kex="$cl" versions=NTS-KE/TLSv1.3 \
      ciphers="$ciphers" auth_key="$auth_key" note="NTS on 4460 refused every PQ group; $note"
  elif [[ -n $raw ]]; then
    emit_row "${target[@]}" NOT-OFFERED versions=NTPv4 note="no NTS (TCP 4460); $note; time is unauthenticated"
  else
    emit_row "${target[@]}" UNREACHABLE note="no NTS on 4460 and $note"
  fi
}

# ------------------------------------------------------------------ local Wi-Fi and VPN (--local)
# Read from NetworkManager (through the host when inside a toolbox). Nothing is sent.
nm() {
  if have nmcli; then nmcli "$@"
  elif [[ -e /run/.toolboxenv ]] && have flatpak-spawn; then flatpak-spawn --host nmcli "$@"
  else return 127; fi
}

safe_label() { printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '_'; }

scan_local() { # writes finished rows for the Wi-Fi networks in range and the active VPN links
  local ssid sec wpa rsn sig freq chan verdict kex="" cipher="" note="" hostname n=0 name type dev
  nm --version >/dev/null 2>&1 || { log "local: nmcli not available (NetworkManager), Wi-Fi and VPN links not listed"; return; }
  while IFS=: read -r ssid sec wpa rsn sig freq chan; do
    [[ -n $ssid ]] || continue
    n=$((n + 1))
    hostname=$(safe_label "$ssid" | cut -c1-60); hostname=${hostname:-hidden}
    kex="" cipher="" note="SSID \"$ssid\", ${freq}, channel ${chan}, signal ${sig}%"
    case "$sec" in
      *WPA3*)
        verdict=CLASSICAL-ONLY; kex="SAE-Dragonfly(ECC-P256)"
        cipher=$(grep -oE 'pair_(ccmp|gcmp[^ ]*)' <<<"$rsn" | head -n1 | cut -d_ -f2 | tr a-z A-Z)
        [[ $sec == *WPA2* ]] && note="$note; WPA2/WPA3 transition mode (downgrade to WPA2-PSK possible)"
        note="$note; WPA3 SAE uses elliptic-curve Diffie-Hellman: classical, no PQ Wi-Fi standard exists yet" ;;
      *WPA2*)
        verdict=CLASSICAL-ONLY
        cipher=$(grep -oE 'pair_(ccmp|tkip|gcmp[^ ]*)' <<<"$rsn" | head -n1 | cut -d_ -f2 | tr a-z A-Z)
        if [[ $rsn == *802.1X* ]]; then
          kex="802.1X/EAP(TLS)"; note="$note; WPA2-Enterprise: EAP over TLS, classical certificates"
        else
          kex="PSK-4way-handshake(symmetric)"
          note="$note; WPA2-Personal has no public-key exchange (PBKDF2+HMAC): Shor does not apply, offline password guessing does"
        fi
        [[ $rsn == *tkip* ]] && note="$note; WEAK: TKIP allowed" ;;
      *WPA1*|*WPA\ *|WPA)
        verdict=CLASSICAL-ONLY; kex="PSK(TKIP)"; cipher="TKIP"; note="$note; WEAK: WPA1/TKIP is deprecated" ;;
      *WEP*)
        verdict=CLASSICAL-ONLY; kex="WEP-shared-key"; cipher="RC4"; note="$note; WEAK: WEP is broken, treat as open" ;;
      ""|--)
        verdict=NOT-OFFERED; note="$note; open network, no encryption" ;;
      *)
        verdict=CLASSICAL-ONLY; note="$note; security: $sec" ;;
    esac
    emit_row local "wifi-$n" wifi "$hostname" 0 "$verdict" classical_kex="$kex" versions="${sec:-open}" ciphers="$cipher" note="$note" \
      >"$OUT/rows/zz-local-wifi-$(printf '%03d' "$n").tsv"
  done < <(nm -t -f SSID,SECURITY,WPA-FLAGS,RSN-FLAGS,SIGNAL,FREQ,CHAN dev wifi list 2>/dev/null | sort -t: -k5,5nr | awk -F: '!seen[$1]++')

  n=0
  while IFS=: read -r name type dev; do
    case "$type" in
      wireguard)
        n=$((n + 1))
        emit_row local "vpn-$n" vpn-local "$(safe_label "$name")" 0 CLASSICAL-ONLY \
          classical_kex="Curve25519(Noise-IK)" versions=WireGuard ciphers=ChaCha20-Poly1305 \
          note="active WireGuard link \"$name\" on $dev; classical key exchange, optional pre-shared key is the only PQ hedge" \
          >"$OUT/rows/zz-local-vpn-$n.tsv" ;;
      vpn|tun)
        n=$((n + 1))
        emit_row local "vpn-$n" vpn-local "$(safe_label "$name")" 0 CLASSICAL-ONLY \
          classical_kex="TLS/IKE(see plugin)" versions="$type" \
          note="active VPN link \"$name\" on $dev (NetworkManager plugin); classical" \
          >"$OUT/rows/zz-local-vpn-$n.tsv" ;;
    esac
  done < <(nm -t -f NAME,TYPE,DEVICE con show --active 2>/dev/null)
  log "local: listed Wi-Fi networks in range and active VPN links as provider \"local\""
}

# ------------------------------------------------------------------ deep mode
deep_scan() {
  local proto=$1 host=$2 port=$3 base="$OUT/raw/${2}_${3}"
  [[ $proto == tls || $proto == ssh ]] || return 0
  if [[ $proto == tls ]]; then
    have nmap && nmap -Pn -p "$port" --script ssl-enum-ciphers "$host" -oN "$base.nmap.txt" >/dev/null 2>&1
    have sslyze && sslyze "$host:$port" --json_out "$base.sslyze.json" >/dev/null 2>&1
    if testssl_bin >/dev/null; then "$(testssl_bin)" --quiet --color 0 -P -f "$host:$port" >"$base.testssl.txt" 2>&1; fi
  else
    have nmap && nmap -Pn -p "$port" --script ssh2-enum-algos,ssh-auth-methods,ssh-hostkey "$host" -oN "$base.nmap.txt" >/dev/null 2>&1
    have ssh-audit && ssh-audit -n -p "$port" "$host" >"$base.ssh-audit.txt" 2>&1
  fi
  return 0
}

probe_one() { # index provider service proto host port
  local idx=$1 provider=$2 service=$3 proto=$4 host=$5 port=$6 row
  case "$proto" in
    tls|quic|doq|starttls-*) row=$(probe_tls "$provider" "$service" "$host" "$port" "$proto") ;;
    ssh) row=$(probe_ssh "$provider" "$service" "$host" "$port") ;;
    dtls) row=$(probe_dtls "$provider" "$service" "$host" "$port") ;;
    ike) row=$(probe_ike "$provider" "$service" "$host" "$port") ;;
    dnssec) row=$(probe_dnssec "$provider" "$service" "$host" "$port") ;;
    dnscurve) row=$(probe_dnscurve "$provider" "$service" "$host" "$port") ;;
    dnscrypt) row=$(probe_dnscrypt "$provider" "${service#cli-arg.}" "$host" "$port") ;;
    ntp) row=$(probe_ntp "$provider" "$service" "$host" "$port") ;;
    ech) row=$(probe_ech "$provider" "$service" "$host" "$port") ;;
    mail) row=$(probe_mail "$provider" "$service" "$host" "$port") ;;
  esac
  printf '%s\n' "$row" >"$OUT/rows/$idx.tsv"
  log "$(awk -F'\t' '{ printf "%-6s %-4s %-52s %s", $1, $3, $4 ":" $5, $6 }' <<<"$row")"
  ((DEEP)) && deep_scan "$proto" "$host" "$port"
  return 0
}

# ------------------------------------------------------------------ credentialed catalogs (read-only)
creds_aws() {
  local region=${AWS_REGIONS%%,*} dir="$OUT/raw/creds" name
  have aws || { log "creds: aws CLI not installed — skipped"; return; }
  aws sts get-caller-identity --output json >"$dir/aws-identity.json" 2>>"$LOGFILE" ||
    { log "creds: aws CLI present but not authenticated — skipped"; return; }
  if aws elbv2 describe-ssl-policies --region "$region" --output json >"$dir/aws-elbv2-ssl-policies.json" 2>>"$LOGFILE" && have jq; then
    jq -r --arg re "$PQ_NAME_RE|PQ" '.SslPolicies[] | select((.Name | test($re; "i")) or ([.Ciphers[].Name] | join(",") | test($re; "i")))
      | "aws\telbv2-ssl-policy\t\(.Name)\tprotocols=\(.SslProtocols | join(","))"' "$dir/aws-elbv2-ssl-policies.json" >>"$OUT/creds-findings.tsv"
    log "creds: aws elbv2 policies: $(jq '.SslPolicies | length' "$dir/aws-elbv2-ssl-policies.json") total"
  fi
  if aws transfer list-security-policies --region "$region" --output json >"$dir/aws-transfer-policies.json" 2>>"$LOGFILE" && have jq; then
    while read -r name; do
      [[ $name =~ ^[A-Za-z0-9._-]+$ ]] || continue
      aws transfer describe-security-policy --region "$region" --security-policy-name "$name" --output json \
        >"$dir/aws-transfer-$name.json" 2>>"$LOGFILE" || continue
      jq -r --arg re "$PQ_NAME_RE" '.SecurityPolicy | select((.SshKexs // []) | join(",") | test($re; "i"))
        | "aws\ttransfer-security-policy\t\(.SecurityPolicyName)\tpq_kex=\([.SshKexs[] | select(test($re; "i"))] | join(","))"' \
        "$dir/aws-transfer-$name.json" >>"$OUT/creds-findings.tsv"
    done < <(jq -r '.SecurityPolicyNames[]' "$dir/aws-transfer-policies.json")
    log "creds: aws transfer policies: $(jq '.SecurityPolicyNames | length' "$dir/aws-transfer-policies.json") total"
  fi
}

creds_azure() {
  local dir="$OUT/raw/creds"
  have az || { log "creds: az CLI not installed — skipped"; return; }
  az account show --output json >"$dir/azure-account.json" 2>>"$LOGFILE" ||
    { log "creds: az CLI present but not logged in — skipped"; return; }
  az network application-gateway ssl-policy list-options --output json >"$dir/azure-appgw-ssl-options.json" 2>>"$LOGFILE"
  az network application-gateway ssl-policy predefined list --output json >"$dir/azure-appgw-ssl-predefined.json" 2>>"$LOGFILE"
  grep -liE "$PQ_NAME_RE" "$dir"/azure-appgw-*.json 2>/dev/null |
    while read -r f; do printf 'azure\tappgw-ssl-policy\t%s\tcontains PQ algorithm names\n' "$(basename "$f")"; done >>"$OUT/creds-findings.tsv"
  log "creds: azure application-gateway TLS policy catalog saved"
}

creds_gcp() {
  local dir="$OUT/raw/creds"
  have gcloud || { log "creds: gcloud CLI not installed — skipped"; return; }
  gcloud compute ssl-policies list-available-features --format=json >"$dir/gcp-ssl-features.json" 2>>"$LOGFILE" ||
    { log "creds: gcloud present but not authenticated / no project — skipped"; return; }
  grep -qiE "$PQ_NAME_RE" "$dir/gcp-ssl-features.json" &&
    printf 'gcp\tcompute-ssl-policy-features\tgcp-ssl-features.json\tcontains PQ algorithm names\n' >>"$OUT/creds-findings.tsv"
  log "creds: gcp ssl-policy feature catalog saved"
}

creds_ibm() {
  local dir="$OUT/raw/creds"
  have ibmcloud || { log "creds: ibmcloud CLI not installed — skipped"; return; }
  ibmcloud target --output json >"$dir/ibm-target.json" 2>>"$LOGFILE" ||
    { log "creds: ibmcloud present but not logged in — skipped"; return; }
  log "creds: ibmcloud has no provider-wide TLS policy catalog; IBM verdicts rest on the handshakes"
}

# What each probe did and how to read its row. Only the protocols present in this run are described.
print_legend() {
  local results=$1 protos p
  protos=$(cut -f3 "$results" | tail -n +2 | sort -u | paste -sd' ' -)
  echo "== WHAT WAS TESTED (one entry per protocol in this run) =="
  for p in $protos; do
    case "$p" in
      tls) cat <<'T'
  tls        TLS on the given port (HTTPS, mail/LDAP/database ports, DNS-over-TLS, or STARTTLS upgrade
             when the note says starttls-*). Probes: one classical-only offer (reachability, certificate,
             preferred group); each PQ group offered alone on TLS 1.3; each classical group alone; a
             TLS 1.2 probe; each TLS 1.3 cipher suite alone; an ML-DSA-only signature offer.
             pq_kex = PQ groups the server accepted, classical_kex = groups actually negotiated,
             ciphers = suites accepted, auth_key/auth_sig = certificate key and signatures,
             pq_auth = did it authenticate with a post-quantum signature.
T
      ;;
      quic) cat <<'T'
  quic       The same TLS probe over QUIC on UDP (HTTP/3 with ALPN h3, or DNS-over-QUIC when the note
             says doq). One PQ group per handshake, because OpenSSL does not print the group under QUIC.
             NOT-OFFERED means the server sends no alt-svc h3 header, so it does not run HTTP/3.
T
      ;;
      ssh) cat <<'T'
  ssh        One unauthenticated SSH connection. The server announces every algorithm it supports before
             anything is negotiated, so srv_kex/srv_hostkeys/srv_ciphers/srv_macs are the server's own
             lists, user_auth is the login methods it offers, and the note carries the negotiated kex and
             banner. No password or key is ever sent. pq_kex = PQ kex names in the server's list.
T
      ;;
      dtls) cat <<'T'
  dtls       DTLS 1.2 and 1.0 handshakes on UDP, the data channel of SSL VPNs (AnyConnect, ocserv,
             Fortinet). Records version, group, cipher and certificate key. DTLS 1.2 defines no PQ
             groups and OpenSSL has no DTLS 1.3, so a working DTLS endpoint is CLASSICAL-ONLY.
T
      ;;
      ike) cat <<'T'
  ike        IKEv2 then IKEv1 proposals sent with ike-scan to an IPsec VPN gateway. classical_kex = DH
             groups, ciphers = encryption transforms, auth_sig = integrity/PRF. ike-scan cannot offer the
             RFC 9370 additional key exchanges, so ML-KEM support is not testable here.
T
      ;;
      ntp) cat <<'T'
  ntp        An unauthenticated NTP query on UDP 123 (does the server answer), then NTS-KE on TCP 4460:
             TLS 1.3 with ALPN ntske/1, the only cryptographic protection NTP has. The verdict follows
             NTS: PQ if a PQ group is accepted there, CLASSICAL-ONLY if not, NOT-OFFERED if the server
             only speaks plain NTP (time is then unauthenticated).
T
      ;;
      ech) cat <<'T'
  ech        The domain's HTTPS DNS record: advertised ALPNs (h3 = HTTP/3), and whether an Encrypted
             Client Hello config is published. classical_kex = the HPKE KEM in that config (X25519
             today). NOT-OFFERED = no record or no ECH config.
T
      ;;
      mail) cat <<'T'
  mail       Mail DNS for a domain: DKIM signing keys under common selectors (auth_key, e.g.
             google:rsa-2048; WEAK flags RSA-1024), DANE TLSA records on the MX hosts (auth_sig), and
             the MTA-STS policy mode (versions). All three are classical mechanisms today.
T
      ;;
      wifi) cat <<'T'
  wifi       Wi-Fi networks in range, read from NetworkManager (--local), no packets sent. versions =
             security type (WEP/WPA/WPA2/WPA3), classical_kex = how the session key is agreed,
             ciphers = CCMP/GCMP/TKIP. No Wi-Fi standard is post-quantum yet; WEAK marks WEP and TKIP.
T
      ;;
      vpn-local) cat <<'T'
  vpn-local  VPN links active on this machine (--local): WireGuard (Curve25519, classical, optional
             pre-shared key as the only PQ hedge) and NetworkManager VPN plugins.
T
      ;;
      kms-key) cat <<'T'
  kms-key    AWS KMS keys in the account (from the API): auth_key = key spec. PQ-ONLY for ML-DSA/ML-KEM
             specs, SYMMETRIC for AES/HMAC keys (no public-key exposure), CLASSICAL-ONLY for RSA/ECC.
T
      ;;
      acm-cert) cat <<'T'
  acm-cert   AWS ACM certificates in the account (from the API): auth_key = key algorithm. ACM issues
             no post-quantum keys yet, so these are CLASSICAL-ONLY.
T
      ;;
      vpn-config) cat <<'T'
  vpn-config AWS Site-to-Site VPN tunnel settings read from the AWS API (no packets sent): DH groups,
             ciphers, integrity and IKE versions per tunnel. "aws-default-*" means the tunnel uses AWS's
             default option set rather than an explicit list.
T
      ;;
      dnssec) cat <<'T'
  dnssec     host is a zone name. Reads the zone's DNSKEY records (over TCP) and the DS record at the
             parent. auth_key = signing algorithms, auth_sig = DS algorithm. CLASSICAL-ONLY = signed with
             RSA or ECDSA/EdDSA; NOT-OFFERED = the zone is not signed. No PQ DNSSEC algorithm exists yet.
T
      ;;
      dnscurve) cat <<'T'
  dnscurve   host is a zone name. DNSCurve servers embed a Curve25519 public key in their NS names
             (labels starting uz5...). Found = CLASSICAL-ONLY (X25519, XSalsa20-Poly1305); none = NOT-OFFERED.
T
      ;;
      dnscrypt) cat <<'T'
  dnscrypt   host is a resolver IP, service is the provider name. Asks the resolver for its DNSCrypt
             certificate (a TXT record) and reads the cipher versions it signs: XSalsa20 or XChaCha20
             with X25519. DNSCrypt defines no PQ suite, so a working resolver is CLASSICAL-ONLY.
T
      ;;
    esac
  done
  cat <<'T'

  Verdicts: PQ-HYBRID+CLASSICAL / PQ-PURE+CLASSICAL = PQ key exchange offered and classical still accepted;
  PQ-ONLY = classical refused; CLASSICAL-ONLY = PQ refused; NOT-OFFERED = the feature is absent (unsigned
  zone, no HTTP/3, no DNSCurve); HANDSHAKE-FAILED = answered but no probe completed; UNREACHABLE = no
  answer at all; SKIPPED-NO-TOOL = install the tool with --setup; UNKNOWN-CLIENT-NO-PQ = this openssl
  cannot offer PQ; SYMMETRIC = a symmetric key with no public-key exposure. pq_auth is always separate:
  it is "yes" only for a post-quantum certificate, host key or signing key. TLS rows carry a chain=
  summary in the note (key/signature per certificate level, WEAK for RSA<2048 or SHA-1).
T
}

# ------------------------------------------------------------------ aggregation
# algorithms.tsv: provider proto category algorithm endpoints_using denominator
write_algorithms_tsv() {
  local results=$1
  awk -F'\t' '
    BEGIN {
      OFS = "\t"
      t[6]="verdict"; t[7]="pq_key_exchange"; t[8]="classical_key_exchange"; t[9]="tls_version"
      t[10]="cipher_suite_accepted"; t[11]="cert_public_key"; t[12]="signature_algorithm"; t[13]="pq_authentication"
      s[6]="verdict"; s[11]="hostkey_negotiated"; s[13]="pq_authentication"; s[14]="kex_offered"
      s[15]="hostkey_offered"; s[16]="cipher_offered"; s[17]="mac_offered"; s[18]="user_auth_method"
    }
    NR == 1 { next }
    {
      reach = ($6 != "UNREACHABLE")
      split("ALL," $1, provs, ",")
      for (p in provs) {
        pk = provs[p] OFS $3
        all[pk]++
        if (reach) total[pk]++
        for (c = 6; c <= 18; c++) {
          cat = ($3 == "ssh") ? s[c] : t[c]
          if (cat == "" || $c == "-" || $c == "") continue
          if (!reach && c != 6) continue
          n = split($c, vals, ",")
          for (i = 1; i <= n; i++) count[pk OFS cat OFS vals[i]]++
        }
      }
    }
    END {
      # verdict rows are counted against ALL endpoints; algorithm rows against reachable ones
      for (k in count) { split(k, parts, OFS); pk = parts[1] OFS parts[2]; print k, count[k], (parts[3] == "verdict" ? all[pk] : total[pk]) + 0 }
    }
  ' "$results" | sort -t$'\t' -k1,1 -k2,2 -k3,3 -k5,5nr -k4,4 |
    { printf 'provider\tproto\tcategory\talgorithm\tendpoints_using\tdenominator\n'; cat; } >"$OUT/algorithms.tsv"
}

write_summary() {
  local results=$1
  {
    echo "pq-cloud-scan $VERSION — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "client: $(openssl version | cut -d' ' -f1-2), $(ssh -V 2>&1 | cut -d, -f1)"
    echo "client PQ TLS groups: ${CLIENT_PQ_GROUPS:-NONE}   PQ sigalgs: ${CLIENT_PQ_SIGALGS:-NONE}"
    echo "scope: each verdict is a snapshot of one endpoint, from this network vantage, at this time; providers"
    echo "       serve different front ends per region and POP, so re-run with --region or extra ENDPOINT args to widen it."
    echo
    print_legend "$results"
    echo
    echo "== VERDICT TOTALS (endpoints per provider / protocol) =="
    # POSIX awk only (no asorti): the verdict columns come from sort -u, row order from sort,
    # with a leading 0/1 key so the ALL rows land last.
    {
      printf 'provider\tproto\t%s\ttotal\n' "$(cut -f6 "$results" | tail -n +2 | sort -u | paste -sd$'\t' -)"
      awk -F'\t' -v verdicts="$(cut -f6 "$results" | tail -n +2 | sort -u | paste -sd, -)" '
        NR == 1 { next }
        { k = "0\t" $1 "\t" $3; a = "1\tALL\t" $3; keys[k]; keys[a]; v[k, $6]++; v[a, $6]++ }
        END {
          n = split(verdicts, vs, ",")
          for (k in keys) {
            printf "%s", k
            sum = 0
            for (i = 1; i <= n; i++) { printf "\t%d", v[k, vs[i]]; sum += v[k, vs[i]] }
            printf "\t%d\n", sum
          }
        }
      ' "$results" | sort -t$'\t' -k1,1n -k2,2 -k3,3 | cut -f2-
    } | pretty
    echo
    echo "== ALGORITHMS AND CIPHERS IN USE (count = endpoints using it / reachable endpoints) =="
    awk -F'\t' '
      NR == 1 || $3 == "verdict" { next }
      { h = $1 " / " $2 " / " $3; if (h != last) { if (last) print ""; printf "%s:\n", h; last = h } printf "    %-52s %d/%d\n", $4, $5, $6 }
    ' "$OUT/algorithms.tsv"
    if [[ -s $OUT/creds-findings.tsv ]]; then
      echo
      echo "== PQ-BEARING POLICIES FOUND VIA CLOUD CLIs (--creds) =="
      pretty <"$OUT/creds-findings.tsv"
    fi
    echo
    echo "== GRAND TOTAL PER PROVIDER (all protocols combined) =="
    # pq% is PQ-capable over PQ-capable + classical-only. not_offered (unsigned zone, no DNSCurve),
    # SYMMETRIC (AES/HMAC keys, no public-key exposure) and no_answer are left out of it.
    {
      printf 'provider\tendpoints\tanswered\tpq_capable\tclassical_only\tnot_offered\tno_answer\tpq%%\tpq_auth\n'
      awk -F'\t' '
        NR == 1 { next }
        function add(k) {
          seen[k]; n[k]++
          if ($6 ~ /^PQ-/) { pq[k]++; ans[k]++ }
          else if ($6 == "CLASSICAL-ONLY" || $6 == "UNKNOWN-CLIENT-NO-PQ") { cl[k] += ($6 == "CLASSICAL-ONLY"); ans[k]++ }
          else if ($6 == "NOT-OFFERED") off[k]++
          else if ($6 == "SYMMETRIC") { sym[k]++; ans[k]++ }
          else bad[k]++
          if ($13 == "yes") auth[k]++
        }
        { add("0\t" $1); add("1\tALL") }
        END {
          for (k in seen) printf "%s\t%d\t%d\t%d\t%d\t%d\t%d\t%s\t%d\n", k, n[k], ans[k], pq[k], cl[k], off[k], bad[k],
            ((pq[k] + cl[k]) ? sprintf("%d%%", 100 * pq[k] / (pq[k] + cl[k]) + 0.5) : "n/a"), auth[k]
        }
      ' "$results" | sort -t$'\t' -k1,1n -k2,2 | cut -f2-
    } | pretty
  } >"$OUT/summary.txt"
}

write_json() {
  local results=$1
  if have jq; then
    jq -Rn --arg version "$VERSION" --arg groups "$CLIENT_PQ_GROUPS" --arg sigalgs "$CLIENT_PQ_SIGALGS" \
      --rawfile algos "$OUT/algorithms.tsv" '
      def table: split("\n") | map(select(length > 0) | split("\t")) | .[0] as $h
        | .[1:] | map(. as $r | reduce range(0; $h | length) as $i ({}; .[$h[$i]] = ($r[$i] // "-")));
      def listify: if . == "-" then [] else split(",") end;
      { tool: "pq-cloud-scan", version: $version, generated: (now | todate),
        client: { pq_tls_groups: ($groups | split(":")), pq_sigalgs: ($sigalgs | split(":")) },
        results: ([inputs] | join("\n") | table | map(
          .pq_kex |= listify | .classical_kex |= listify | .versions |= listify | .ciphers |= listify
          | .auth_sig |= listify | .srv_kex |= listify | .srv_hostkeys |= listify | .srv_ciphers |= listify
          | .srv_macs |= listify | .user_auth |= listify | .port |= (tonumber? // 0))),
        algorithms: ($algos | table | map(.endpoints_using |= (tonumber? // 0) | .denominator |= (tonumber? // 0))) }
    ' "$results" >"$OUT/results.json" || log "json export failed"
  else
    log "jq not installed — results.json skipped"
  fi
}

aggregate() {
  local results="$OUT/results.tsv"
  write_algorithms_tsv "$results"
  write_summary "$results"
  write_json "$results"
}

# ------------------------------------------------------------------ main
# What this machine's openssl and ssh can offer. Without PQ groups here TLS verdicts are UNKNOWN-CLIENT-NO-PQ.
detect_client() {
  CLIENT_PQ_GROUPS=$(openssl list -tls-groups 2>/dev/null | tr ':' '\n' | grep -iE "$PQ_NAME_RE" |
    awk '{ print ($0 ~ /^[Mm][Ll]/ ? 1 : 0) "\t" $0 }' | sort -s -k1,1n | cut -f2 | paste -sd: -)
  CLIENT_PQ_SIGALGS=$(openssl list -signature-algorithms 2>/dev/null | grep -oiE 'mldsa[0-9]+' | tr 'A-Z' 'a-z' | sort -u | paste -sd: -)
  # The combined classical offer adds the rarer groups this openssl knows (large ffdhe, brainpool), so a
  # server that only speaks those is not misread as HANDSHAKE-FAILED or PQ-ONLY. Common groups stay first.
  CLASSICAL_OFFER=$(
    { tr ':' '\n' <<<"$CLASSICAL_GROUPS"
      openssl list -tls-groups 2>/dev/null | tr ':' '\n' | grep -E '^(ffdhe(4096|6144|8192)|brainpool.*)$'
    } | paste -sd: -
  )
  CLIENT_SSH_PQ=$(ssh -Q kex 2>/dev/null | grep -iE "$PQ_NAME_RE" | paste -sd, -)

  if [[ -n $CLIENT_PQ_GROUPS ]]; then log "client PQ TLS groups : $CLIENT_PQ_GROUPS"
  else log "client PQ TLS groups : NONE, so TLS verdicts will be UNKNOWN-CLIENT-NO-PQ (OpenSSL 3.5 or newer is needed)"; fi
  if [[ -n $CLIENT_PQ_SIGALGS ]]; then log "client PQ TLS sigalgs: $CLIENT_PQ_SIGALGS"
  else log "client PQ TLS sigalgs: NONE, so PQ authentication will be reported as unknown"; fi
  log "client PQ SSH kex    : ${CLIENT_SSH_PQ:-none} (SSH verdicts read the list the server announces, so this is informational)"
}

# AWS credentials unlock two things: the account's own endpoints, and (with --all-regions) every enabled region.
setup_aws() {
  AWS_REGIONS=${REGION:-us-east-1}
  if ((USE_TARGETS)) && [[ ",$PROVIDERS," == *,aws,* ]] && { ((DISCOVER)) || ((ALL_REGIONS)); }; then
    if aws_credentials_ok; then
      AWS_OK=1
      log "aws credentials found (account ...$(jq -r '.Account[-4:]' <<<"$AWS_IDENTITY")): adding every AWS service endpoint per region, plus this account's own endpoints as aws-account (--no-discover to skip)"
      if ((ALL_REGIONS)); then
        AWS_REGIONS=$(awsq ec2 describe-regions | jq -r '[.Regions[].RegionName] | sort | join(",")')
        [[ -n $AWS_REGIONS ]] || AWS_REGIONS=${REGION:-us-east-1}
        log "aws regions enabled for this account: $AWS_REGIONS"
      fi
    else
      log "aws credentials not found or not valid: scanning the public AWS endpoints only"
      ((ALL_REGIONS)) && log "--all-regions needs AWS credentials to list regions; using $AWS_REGIONS"
    fi
  fi
}

# One background probe per target row, at most $JOBS at a time
run_probes() {
  local idx=0 provider service proto host port
  while IFS=$'\t' read -r provider service proto host port; do
    idx=$((idx + 1))
    while (($(jobs -rp | wc -l) >= JOBS)); do wait -n; done
    probe_one "$(printf '%05d' "$idx")" "$provider" "$service" "$proto" "$host" "$port" &
  done <<<"$TARGET_ROWS"
  wait
}

run_creds() {
  : >"$OUT/creds-findings.tsv"
  [[ ",$PROVIDERS," == *,aws,* ]] && creds_aws
  [[ ",$PROVIDERS," == *,azure,* ]] && creds_azure
  [[ ",$PROVIDERS," == *,gcp,* ]] && creds_gcp
  [[ ",$PROVIDERS," == *,ibm,* ]] && creds_ibm
}

print_report() {
  echo
  echo "== PER-ENDPOINT RESULTS =="
  cut -f1,2,3,4,5,6,7,8,9,13,19 "$OUT/results.tsv" | pretty
  echo
  cat "$OUT/summary.txt"
  echo
  echo "files in $OUT: results.tsv algorithms.tsv summary.txt results.json scan.log raw/"
}

main() {
  local tool deep_note=""
  parse_args "$@"
  PROVIDERS=$(normalise_providers "${PROVIDERS:-$DEFAULT_PROVIDERS}")
  # Endpoint arguments with no provider named mean "scan just these": burying one URL under the
  # whole built-in list reads as the argument being ignored. Name providers (or --with-targets) to get both.
  if ((${#ENDPOINTS[@]} > 0 && !EXPLICIT_PROVIDERS && !FORCE_TARGETS)); then USE_TARGETS=0; fi
  validate_args

  if ((SETUP)); then run_setup; exit $?; fi

  for tool in openssl ssh timeout awk paste sort; do
    have "$tool" || die "required tool not found: $tool"
  done

  OUT=${OUT:-./pq-scan-$(date +%Y%m%d-%H%M%S)}
  mkdir -p "$OUT/rows" "$OUT/raw/creds" || die "cannot create output dir: $OUT"
  LOGFILE="$OUT/scan.log"
  : >"$LOGFILE"

  detect_client
  if ((USE_TARGETS)) && [[ ! -r $TARGETS ]]; then die "targets file not readable: $TARGETS"; fi
  setup_aws

  TARGET_ROWS=$(build_targets)
  [[ -n $TARGET_ROWS ]] || die "no targets to scan: check --provider, --proto, --targets, or pass ENDPOINT args"
  if ((DEEP)); then deep_note=", deep mode"; fi
  log "scanning $(wc -l <<<"$TARGET_ROWS") endpoints, $JOBS at a time, timeout ${TIMEOUT}s$deep_note"

  run_probes
  if ((LOCAL)); then scan_local; fi
  { printf '%s\n' "$HEADER"; cat "$OUT"/rows/*.tsv; } >"$OUT/results.tsv"
  rm -rf "$OUT/rows"

  if ((CREDS)); then run_creds; fi
  aggregate
  print_report
}

main "$@"
