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

echo ""
echo "=== Corpus sizes ==="
for target in fuzz_parse_message fuzz_parse_edns fuzz_zone_parser fuzz_nsec3_hash; do
    count=$(ls "${CORPUS_DIR}/${target}/" | wc -l)
    echo "  ${target}: ${count} seeds"
done
