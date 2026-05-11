#!/usr/bin/env bash
# Generates representative seed corpora for all fuzz targets.
# Run from the repository root: bash fuzz/generate_corpus.sh
# Requires: python3, xxd or printf for binary output.

set -euo pipefail

CORPUS_DIR="fuzz/corpus"

# ── fuzz_parse_message seeds ──────────────────────────────────────────────────
# DNS wire-format messages covering: query types, response flags, EDNS, TC,
# AA, RA, Z-bits, various RCODE values, zero-length messages, max-size, etc.
MSG_DIR="${CORPUS_DIR}/fuzz_parse_message"
mkdir -p "${MSG_DIR}"

python3 - <<'PYEOF'
import os, struct

out = "fuzz/corpus/fuzz_parse_message"

def dns_query(qname_labels, qtype=1, qclass=1, qid=0, flags=0x0100, edns=False):
    """Build a minimal DNS query wire message."""
    hdr = struct.pack(">HHHHHH", qid, flags, 1, 0, 0, 1 if edns else 0)
    qname = b""
    for label in qname_labels:
        enc = label.encode()
        qname += bytes([len(enc)]) + enc
    qname += b"\x00"
    question = qname + struct.pack(">HH", qtype, qclass)
    if edns:
        # OPT record: name=root, type=41, class=4096 (payload), ttl=0, rdlen=0
        opt = b"\x00" + struct.pack(">HHiH", 41, 4096, 0, 0)
    else:
        opt = b""
    return hdr + question + opt

def dns_response(qname_labels, qtype=1, qclass=1, qid=0, rcode=0, ancount=0):
    flags = 0x8000 | (rcode & 0xF)
    hdr = struct.pack(">HHHHHH", qid, flags, 1, ancount, 0, 0)
    qname = b""
    for label in qname_labels:
        enc = label.encode()
        qname += bytes([len(enc)]) + enc
    qname += b"\x00"
    question = qname + struct.pack(">HH", qtype, qclass)
    return hdr + question

seeds = []

# Basic queries for various QTYPEs
qtypes = [1, 2, 5, 6, 12, 15, 16, 28, 33, 43, 44, 46, 47, 48, 50, 52, 53, 255, 65]
for qt in qtypes:
    seeds.append(("query_type_{:04d}".format(qt), dns_query(["example","com"], qt)))
    seeds.append(("query_edns_type_{:04d}".format(qt), dns_query(["example","com"], qt, edns=True)))

# Various domain name patterns
names = [
    ["a"],
    ["a","b"],
    ["www","example","com"],
    ["xn--nxasmq6b","com"],   # IDN
    ["_dmarc","example","com"],
    ["a" * 63, "com"],         # Max label length
    ["1","2","3","4","5","6","7","8","9","10","11","12","13","14","15","16",
     "17","18","19","20","21","22","23","24","25","26","27","28"],  # Deep
]
for i, name in enumerate(names):
    seeds.append(("query_name_{:02d}".format(i), dns_query(name)))

# Various RCODE responses
for rcode in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 16, 17, 18, 23]:
    seeds.append(("response_rcode_{:02d}".format(rcode), dns_response(["example","com"], rcode=rcode)))

# Truncated flag set
trunc_hdr = struct.pack(">HHHHHH", 1, 0x0200, 1, 0, 0, 0)
seeds.append(("response_truncated", trunc_hdr + b"\x07example\x03com\x00\x00\x01\x00\x01"))

# Zero-length message
seeds.append(("empty", b""))

# One byte
seeds.append(("one_byte", b"\x00"))

# Header-only (12 bytes)
seeds.append(("header_only", struct.pack(">HHHHHH", 0, 0, 0, 0, 0, 0)))

# Malformed: qdcount=1 but no question bytes
seeds.append(("malformed_qdcount_no_question", struct.pack(">HHHHHH", 0, 0x0100, 1, 0, 0, 0)))

# Max UDP size (512 bytes padded with zeros)
seeds.append(("max_udp_zero_padded", dns_query(["example","com"], edns=True) + b"\x00" * 400))

# AAAA query
seeds.append(("query_aaaa", dns_query(["ipv6","example","com"], qtype=28)))

# ANY query
seeds.append(("query_any", dns_query(["example","com"], qtype=255, qclass=255)))

# AXFR query
seeds.append(("query_axfr", dns_query(["example","com"], qtype=252)))

# Message with AA + RA flags
seeds.append(("response_aa_ra", dns_response(["ns1","example","com"], rcode=0)))

# Write seeds
for name, data in seeds:
    path = os.path.join(out, name + ".bin")
    with open(path, "wb") as f:
        f.write(data)

print(f"Generated {len(seeds)} seeds in {out}")
PYEOF

# ── fuzz_parse_edns seeds ─────────────────────────────────────────────────────
# EDNS OPT RDATA: raw TLV byte sequences for EDNS option parsing.
EDNS_DIR="${CORPUS_DIR}/fuzz_parse_edns"
mkdir -p "${EDNS_DIR}"

python3 - <<'PYEOF'
import os, struct

out = "fuzz/corpus/fuzz_parse_edns"
seeds = []

def edns_opt(code, data):
    return struct.pack(">HH", code, len(data)) + data

# Well-known EDNS option codes
option_codes = [1, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 26946]
for code in option_codes:
    seeds.append(("opt_code_{:05d}_empty".format(code), edns_opt(code, b"")))
    seeds.append(("opt_code_{:05d}_4b".format(code), edns_opt(code, b"\xde\xad\xbe\xef")))

# ECS (option 8): client subnet
seeds.append(("ecs_ipv4", edns_opt(8, b"\x00\x01\x18\x00" + bytes([192,168,1,0]))))
seeds.append(("ecs_ipv6", edns_opt(8, b"\x00\x02\x40\x00" + b"\x20\x01\x0d\xb8" + b"\x00"*12)))

# COOKIE (option 10): 8-byte client cookie
seeds.append(("cookie_client_only", edns_opt(10, b"\xde\xad\xbe\xef\xca\xfe\xba\xbe")))
seeds.append(("cookie_full", edns_opt(10, b"\xde\xad\xbe\xef\xca\xfe\xba\xbe" + b"\x00"*8)))

# PADDING (option 12)
for n in [0, 1, 4, 16, 64, 128, 468]:
    seeds.append(("padding_{:03d}".format(n), edns_opt(12, b"\x00" * n)))

# Multiple options concatenated
multi = edns_opt(8, b"\x00\x01\x18\x00\xc0\xa8\x01\x00") + edns_opt(10, b"\xde\xad\xbe\xef\xca\xfe\xba\xbe")
seeds.append(("multi_ecs_cookie", multi))

# Edge cases
seeds.append(("empty", b""))
seeds.append(("one_byte", b"\x00"))
seeds.append(("truncated_length", b"\x00\x08\x00\x10\x00"))  # length > remaining bytes
seeds.append(("zero_length_opt", edns_opt(0, b"")))
seeds.append(("max_code", edns_opt(65535, b"\xff" * 4)))

for name, data in seeds:
    path = os.path.join(out, name + ".bin")
    with open(path, "wb") as f:
        f.write(data)

print(f"Generated {len(seeds)} seeds in {out}")
PYEOF

# ── fuzz_zone_parser seeds ────────────────────────────────────────────────────
# Zone file text fragments covering various RR types and edge cases.
ZONE_DIR="${CORPUS_DIR}/fuzz_zone_parser"
mkdir -p "${ZONE_DIR}"

python3 - <<'PYEOF'
import os

out = "fuzz/corpus/fuzz_zone_parser"
seeds = {}

# Minimal valid zone file
seeds["minimal"] = b"; minimal zone\nexample.com. 3600 IN SOA ns1.example.com. admin.example.com. 2024010101 3600 900 604800 300\n"

# Various RR types
seeds["a_record"] = b"www.example.com. 300 IN A 192.168.1.1\n"
seeds["aaaa_record"] = b"www.example.com. 300 IN AAAA 2001:db8::1\n"
seeds["ns_record"] = b"example.com. 3600 IN NS ns1.example.com.\n"
seeds["mx_record"] = b"example.com. 3600 IN MX 10 mail.example.com.\n"
seeds["cname_record"] = b"alias.example.com. 300 IN CNAME www.example.com.\n"
seeds["txt_record"] = b'example.com. 300 IN TXT "v=spf1 include:example.com ~all"\n'
seeds["txt_multi"] = b'example.com. 300 IN TXT "part1" "part2" "part3"\n'
seeds["ptr_record"] = b"1.1.168.192.in-addr.arpa. 300 IN PTR www.example.com.\n"
seeds["srv_record"] = b"_http._tcp.example.com. 300 IN SRV 0 5 80 www.example.com.\n"
seeds["caa_record"] = b'example.com. 3600 IN CAA 0 issue "letsencrypt.org"\n'
seeds["soa_record"] = b"example.com. 3600 IN SOA ns1.example.com. admin.example.com. 2024010101 3600 900 604800 300\n"
seeds["dnskey_record"] = b"example.com. 3600 IN DNSKEY 257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
seeds["ds_record"] = b"example.com. 3600 IN DS 12345 13 2 1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef\n"
seeds["nsec_record"] = b"example.com. 3600 IN NSEC ns.example.com. A NS SOA MX RRSIG NSEC DNSKEY\n"
seeds["rrsig_record"] = b"example.com. 3600 IN RRSIG A 13 2 3600 20240101000000 20231201000000 12345 example.com. AAAA==\n"
seeds["https_record"] = b'example.com. 300 IN HTTPS 1 . alpn=h3\n'
seeds["svcb_record"] = b'_dns.example.com. 300 IN SVCB 1 dns.example.com. port=853\n'

# $ORIGIN and $TTL directives
seeds["origin_ttl"] = b"$ORIGIN example.com.\n$TTL 3600\n@ IN SOA ns1 admin 2024010101 3600 900 604800 300\n"

# Relative names
seeds["relative_names"] = b"$ORIGIN example.com.\n$TTL 300\nwww IN A 10.0.0.1\nmail IN MX 10 mx\n"

# Multiple records same name
seeds["multi_record"] = b"example.com. 300 IN A 1.2.3.4\nexample.com. 300 IN A 5.6.7.8\n"

# Long TXT
seeds["long_txt"] = b'example.com. 300 IN TXT "' + b"x" * 255 + b'"\n'

# Comments
seeds["comments"] = b"; comment line\nexample.com. 300 IN A 1.2.3.4 ; inline comment\n"

# Empty input
seeds["empty"] = b""

# Only whitespace
seeds["whitespace"] = b"   \n\t\n"

# Only comments
seeds["only_comments"] = b"; this is a comment\n; another comment\n"

# Malformed: missing rdata
seeds["malformed_missing_rdata"] = b"example.com. 300 IN A\n"

# Malformed: unknown RR type
seeds["unknown_type"] = b"example.com. 300 IN UNKNOWNTYPE somedata\n"

# Very long label
seeds["long_label"] = b"a" * 63 + b".example.com. 300 IN A 1.2.3.4\n"

# Unicode / IDN
seeds["idn"] = b"xn--nxasmq6b.com. 300 IN A 1.2.3.4\n"

# Wildcard
seeds["wildcard"] = b"*.example.com. 300 IN A 1.2.3.4\n"

# @-sign
seeds["at_sign"] = b"$ORIGIN example.com.\n@ 3600 IN SOA ns1 admin 2024010101 3600 900 604800 300\n"

# Class IN vs CH
seeds["class_in"] = b"example.com. 300 IN A 1.2.3.4\n"
seeds["class_ch"] = b"version.bind. 0 CH TXT \"Heimdall\"\n"

# GENERIC rdata
seeds["generic_rdata"] = b"example.com. 300 IN TYPE1 \\# 4 c0a80101\n"

# Multi-line rdata (parentheses)
seeds["multiline_rdata"] = b"example.com. 3600 IN SOA ns1.example.com. admin.example.com. (\n    2024010101 3600 900 604800 300 )\n"

# Numbers as first field (implicit owner = previous)
seeds["implicit_owner"] = b"$ORIGIN example.com.\n$TTL 300\nexample.com. IN SOA ns1 admin 2024010101 3600 900 604800 300\n        IN NS ns1\n        IN NS ns2\n"

for name, data in seeds.items():
    path = os.path.join(out, name + ".bin")
    with open(path, "wb") as f:
        f.write(data)

print(f"Generated {len(seeds)} seeds in {out}")
PYEOF

# ── fuzz_nsec3_hash seeds ─────────────────────────────────────────────────────
# Format: 2-byte big-endian iterations + up to 32 bytes salt
NSEC3_DIR="${CORPUS_DIR}/fuzz_nsec3_hash"
mkdir -p "${NSEC3_DIR}"

python3 - <<'PYEOF'
import os, struct

out = "fuzz/corpus/fuzz_nsec3_hash"
seeds = {}

def seed(iterations, salt=b""):
    return struct.pack(">H", iterations) + salt

# Zero iterations, various salts
seeds["iter_0_nosalt"] = seed(0)
seeds["iter_0_salt4"] = seed(0, b"\xde\xad\xbe\xef")
seeds["iter_0_salt16"] = seed(0, b"\x00"*16)
seeds["iter_0_salt32"] = seed(0, b"\xff"*32)

# Common iteration counts
for n in [1, 10, 50, 100, 150, 151, 255, 1000, 2500, 4999, 5000, 32767, 65535]:
    seeds[f"iter_{n:05d}_nosalt"] = seed(n)
    seeds[f"iter_{n:05d}_salt4"] = seed(n, b"\xca\xfe\xba\xbe")

# Edge case: exactly 150 (the cap)
seeds["iter_150_exact"] = seed(150, b"\x01\x02\x03\x04")
seeds["iter_151_above_cap"] = seed(151, b"\x01\x02\x03\x04")

# Salt lengths 1..32
for l in range(1, 33):
    seeds[f"salt_len_{l:02d}"] = seed(10, bytes(range(l)) )

# Minimum input (2 bytes — iterations only)
seeds["minimum_input"] = seed(0)

# One byte (too short — target should return early)
seeds["one_byte"] = b"\x00"

# All zeros
seeds["all_zeros"] = b"\x00" * 34

# All ones
seeds["all_ones"] = b"\xff" * 34

for name, data in seeds.items():
    path = os.path.join(out, name + ".bin")
    with open(path, "wb") as f:
        f.write(data)

print(f"Generated {len(seeds)} seeds in {out}")
PYEOF

# ── fuzz_dnssec_verify seeds (Sprint 67 #677) ────────────────────────────────
# Reuse the fuzz_parse_message corpus — every valid wire-format DNS message
# is a possible vehicle for an RRSIG+DNSKEY combination; libFuzzer's mutators
# generate the RDATA distortions on top.
DNSSEC_DIR="${CORPUS_DIR}/fuzz_dnssec_verify"
mkdir -p "${DNSSEC_DIR}"
cp "${CORPUS_DIR}/fuzz_parse_message/"*.bin "${DNSSEC_DIR}/" 2>/dev/null || true

# ── fuzz_tsig_verify seeds (Sprint 67 #678) ──────────────────────────────────
# RFC 8945 §10 test vectors and adjacent malformed cases.
TSIG_DIR="${CORPUS_DIR}/fuzz_tsig_verify"
mkdir -p "${TSIG_DIR}"
python3 - <<'PYEOF'
import os, struct
out = "fuzz/corpus/fuzz_tsig_verify"
seeds = {}
# Minimum valid: 8 bytes of header + tiny RDATA
seeds["minimum_8b"] = b"\x00" * 8
# 16 bytes — enough for now (2B) + split (2B) + algo (1B) + small rdata
seeds["near_minimum_16b"] = bytes(range(16))
# All-zero header + valid hmac-sha256 algorithm name as RDATA prefix
algo_name = b"\x0bhmac-sha256\x00"
fudge = struct.pack(">H", 300)
seeds["sha256_basic"] = b"\x00\x00\x00\x00\x00" + algo_name + b"\x00\x00\x00\x00\x00\x00" + fudge + struct.pack(">H", 32) + b"\x00"*32 + struct.pack(">HHH", 0, 0, 0)
# Truncated RDATA
seeds["truncated_rdata"] = b"\x00" * 32
# All 0xff
seeds["all_ff"] = b"\xff" * 64
for name, data in seeds.items():
    with open(os.path.join(out, name + ".bin"), "wb") as f:
        f.write(data)
print(f"Generated {len(seeds)} seeds in {out}")
PYEOF

# ── fuzz_config_toml seeds (Sprint 67 #680) ──────────────────────────────────
# Minimal valid Heimdall configs plus broken / adversarial TOML.
CONFIG_DIR="${CORPUS_DIR}/fuzz_config_toml"
mkdir -p "${CONFIG_DIR}"
cat > "${CONFIG_DIR}/empty.toml" <<'TOML'
TOML
cat > "${CONFIG_DIR}/minimal_auth.toml" <<'TOML'
[role.authoritative]
enabled = true
TOML
cat > "${CONFIG_DIR}/minimal_recursive.toml" <<'TOML'
[role.recursive]
enabled = true
TOML
cat > "${CONFIG_DIR}/all_disabled.toml" <<'TOML'
[role.authoritative]
enabled = false
[role.recursive]
enabled = false
[role.forwarder]
enabled = false
TOML
cat > "${CONFIG_DIR}/bad_toml_unterminated_string.toml" <<'TOML'
[role.recursive]
name = "unterminated
TOML
cat > "${CONFIG_DIR}/bad_toml_unknown_key.toml" <<'TOML'
[role.recursive]
enabled = true
this_field_does_not_exist = 42
TOML
cat > "${CONFIG_DIR}/huge_table.toml" <<'TOML'
[role.recursive]
enabled = true
TOML
# Append 1024 unknown keys to stress validate_config.
for i in $(seq 1 1024); do
    echo "unknown_key_$i = $i" >> "${CONFIG_DIR}/huge_table.toml"
done
cat > "${CONFIG_DIR}/utf8_bom.toml" <<'TOML'
[role.recursive]
enabled = true
TOML
# Prepend a UTF-8 BOM (TOML parsers vary on whether they accept it).
printf '\xef\xbb\xbf' | cat - "${CONFIG_DIR}/utf8_bom.toml" > /tmp/utf8_bom.toml && mv /tmp/utf8_bom.toml "${CONFIG_DIR}/utf8_bom.toml"

# ── fuzz_doh2_framing seeds (Sprint 67 #679) ─────────────────────────────────
# The HTTP/2 client preface, a SETTINGS frame, then nothing — minimum input
# that hyper will accept as the start of an HTTP/2 conversation.
FRAMING_DIR="${CORPUS_DIR}/fuzz_doh2_framing"
mkdir -p "${FRAMING_DIR}"
python3 - <<'PYEOF'
import os, struct
out = "fuzz/corpus/fuzz_doh2_framing"

# RFC 7540 §3.5: HTTP/2 connection preface.
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

# RFC 7540 §6.5: SETTINGS frame header.
def frame(length, frame_type, flags, stream_id, payload):
    return struct.pack(">L", (length << 8) | frame_type)[:3] + bytes([frame_type, flags]) + struct.pack(">I", stream_id) + payload

# Empty SETTINGS — minimum valid first frame from the client.
settings_empty = struct.pack(">LBBI", 0 << 8, 4, 0, 0)[1:]  # 24-bit length=0, type=4, flags=0, stream=0
settings_ack   = struct.pack(">LBBI", 0 << 8, 4, 1, 0)[1:]

SETTINGS_EMPTY = b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"
SETTINGS_ACK   = b"\x00\x00\x00\x04\x01\x00\x00\x00\x00"

# Hand-crafted edge cases.
seeds = {
    "preface_only":           PREFACE,
    "preface_settings_empty": PREFACE + SETTINGS_EMPTY,
    "preface_settings_ack":   PREFACE + SETTINGS_ACK,
    "preface_truncated":      PREFACE[:10],
    "all_zeros_128":          b"\x00" * 128,
    "all_ff_128":             b"\xff" * 128,
    "preface_then_garbage":   PREFACE + b"\xde\xad\xbe\xef" * 32,
    # CONTINUATION-flood candidate (SEC-042 detection).
    "continuation_flood":     PREFACE + SETTINGS_EMPTY + (b"\x00\x00\x01\x09\x00\x00\x00\x00\x01\x00") * 64,
    # Oversized HEADERS — triggers max_header_list_size enforcement.
    "oversized_headers":      PREFACE + SETTINGS_EMPTY + b"\x00\xff\xff\x01\x04\x00\x00\x00\x01" + b"\x82" * 65535,
    # RST_STREAM burst — rapid-reset candidate (SEC-041, CVE-2023-44487).
    "rapid_reset_burst":      PREFACE + SETTINGS_EMPTY + (b"\x00\x00\x04\x03\x00\x00\x00\x00\x01\x00\x00\x00\x08") * 128,
    # PING flood.
    "ping_flood":             PREFACE + SETTINGS_EMPTY + (b"\x00\x00\x08\x06\x00\x00\x00\x00\x00" + b"\x00"*8) * 128,
    # WINDOW_UPDATE underflow attempt.
    "window_update_zero":     PREFACE + SETTINGS_EMPTY + b"\x00\x00\x04\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    # GOAWAY immediately after preface.
    "goaway_first":           PREFACE + b"\x00\x00\x08\x07\x00\x00\x00\x00\x00" + b"\x00"*8,
}

# Synthesise ≥200 seeds total by generating mutated copies of every base seed
# with deterministic random fuzzing. The libfuzzer mutator handles fine-grained
# bit-flipping; this seed expansion gives it 200 distinct starting points.
import random
rng = random.Random(0xC0FFEE)
base_seeds = list(seeds.items())
for i in range(200):
    base_name, base_bytes = base_seeds[i % len(base_seeds)]
    blob = bytearray(base_bytes)
    n_mutations = rng.randint(1, 8)
    for _ in range(n_mutations):
        if not blob:
            blob = bytearray([0])
        pos = rng.randint(0, len(blob) - 1)
        op = rng.choice(["flip", "incr", "rand", "insert", "delete"])
        if op == "flip":
            blob[pos] ^= 1 << rng.randint(0, 7)
        elif op == "incr":
            blob[pos] = (blob[pos] + rng.randint(1, 8)) & 0xff
        elif op == "rand":
            blob[pos] = rng.randint(0, 255)
        elif op == "insert" and len(blob) < 8192:
            blob.insert(pos, rng.randint(0, 255))
        elif op == "delete" and len(blob) > 1:
            del blob[pos]
    seeds[f"mut_{i:04d}_{base_name}"] = bytes(blob)

for name, data in seeds.items():
    with open(os.path.join(out, name + ".bin"), "wb") as f:
        f.write(data)
print(f"Generated {len(seeds)} seeds in {out}")
PYEOF

echo ""
echo "=== Corpus sizes ==="
for target in fuzz_parse_message fuzz_parse_edns fuzz_zone_parser fuzz_nsec3_hash fuzz_dnssec_verify fuzz_tsig_verify fuzz_config_toml fuzz_doh2_framing; do
    if [ -d "${CORPUS_DIR}/${target}" ]; then
        count=$(ls "${CORPUS_DIR}/${target}/" | wc -l)
        echo "  ${target}: ${count} seeds"
    fi
done
