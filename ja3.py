# !/usr/bin/env python

# Copyright (c) 2017, salesforce.com, inc.
#
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS” AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""
generate ja3 fingerprints from raw tls clienthello bytes (not wrapped in a tls record)
process_pcap has been replaced with process_clienthello by MagicHall
"""

import argparse
import struct
from hashlib import md5

__author__ = "Tommy Stallings"
__copyright__ = "Copyright (c) 2017, salesforce.com, inc."
__credits__ = ["John B. Althouse", "Jeff Atkinson", "Josh Atkins"]
__license__ = "BSD 3-Clause License"
__version__ = "1.0.0"
__maintainer__ = "Tommy Stallings, Brandon Dixon"
__email__ = "tommy.stallings@salesforce.com"

GREASE_TABLE = {
    0x0A0A: True,
    0x1A1A: True,
    0x2A2A: True,
    0x3A3A: True,
    0x4A4A: True,
    0x5A5A: True,
    0x6A6A: True,
    0x7A7A: True,
    0x8A8A: True,
    0x9A9A: True,
    0xAAAA: True,
    0xBABA: True,
    0xCACA: True,
    0xDADA: True,
    0xEAEA: True,
    0xFAFA: True,
}


def parse_variable_array(buf, byte_len, offset=0):
    """Unpack data from buffer of specific length.

    :param buf: Buffer to operate on
    :type buf: bytes
    :param byte_len: Length to process
    :type byte_len: int
    :param offset: Starting offset in buffer
    :type offset: int
    :returns: tuple (data, new_offset)
    """
    _SIZE_FORMATS = ["!B", "!H", "!I", "!I"]
    assert byte_len <= 4
    size_format = _SIZE_FORMATS[byte_len - 1]
    padding = b"\x00" if byte_len == 3 else b""
    size = struct.unpack(size_format, padding + buf[offset : offset + byte_len])[0]
    data = buf[offset + byte_len : offset + byte_len + size]
    return data, offset + byte_len + size


def ntoh(buf):
    """Convert to network order.

    :param buf: Bytes to convert
    :type buf: bytes
    :returns: int
    """
    if len(buf) == 1:
        return buf[0]
    elif len(buf) == 2:
        return struct.unpack("!H", buf)[0]
    elif len(buf) == 4:
        return struct.unpack("!I", buf)[0]
    else:
        raise ValueError("Invalid input buffer size for NTOH")


def convert_to_ja3_segment(data, element_width):
    """Convert a packed array of elements to a JA3 segment.

    :param data: Current buffer item
    :type data: bytes
    :param element_width: Byte count to process at a time
    :type element_width: int
    :returns: str
    """
    int_vals = []
    data = bytearray(data)
    if len(data) % element_width:
        raise ValueError(f"{len(data)} is not a multiple of {element_width}")

    for i in range(0, len(data), element_width):
        element = ntoh(data[i : i + element_width])
        if element not in GREASE_TABLE:
            int_vals.append(element)

    return "-".join(str(x) for x in int_vals)


def process_extensions(buf, offset):
    """Process TLS extensions and convert to JA3 segments.

    :param buf: Raw TLS Client Hello bytes
    :type buf: bytes
    :param offset: Starting offset for extensions
    :type offset: int
    :returns: tuple (extensions_segment, elliptic_curve, elliptic_curve_point_format, new_offset)
    """
    exts = []
    elliptic_curve = ""
    elliptic_curve_point_format = ""

    # Check if extensions are present
    if offset >= len(buf):
        return "", "", "", offset

    # Parse extensions length (2 bytes)
    ext_len = ntoh(buf[offset : offset + 2])
    offset += 2
    end_offset = offset + ext_len

    while offset < end_offset and offset < len(buf):
        # Extension type (2 bytes)
        ext_type = ntoh(buf[offset : offset + 2])
        offset += 2
        # Extension length (2 bytes)
        ext_data_len = ntoh(buf[offset : offset + 2])
        offset += 2
        # Extension data
        ext_data = buf[offset : offset + ext_data_len]
        offset += ext_data_len

        if ext_type not in GREASE_TABLE:
            exts.append(ext_type)
        if ext_type == 0x0A:  # Elliptic Curves
            data, _ = parse_variable_array(ext_data, 2)
            elliptic_curve = convert_to_ja3_segment(data, 2)
        elif ext_type == 0x0B:  # EC Point Formats
            data, _ = parse_variable_array(ext_data, 1)
            elliptic_curve_point_format = convert_to_ja3_segment(data, 1)

    return (
        "-".join(str(x) for x in exts),
        elliptic_curve,
        elliptic_curve_point_format,
        offset,
    )


def process_clienthello(tls_data):
    """process raw tls clienthello bytes to generate a ja3 fingerprint.

    :param tls_data: raw tls clienthello bytes (starting with version, no record layer)
    :type tls_data: bytes
    :returns: dict with ja3 fingerprint and digest
    """
    if not tls_data or len(tls_data) < 38:  # minimum length for version & random
        raise ValueError("input is too short for a valid tls clienthello")

    offset = 0
    # tls version 2
    version = ntoh(tls_data[offset : offset + 2])
    offset += 2

    # skip random
    offset += 32

    session_id, offset = parse_variable_array(tls_data, 1, offset)

    cipher_suites, offset = parse_variable_array(tls_data, 2, offset)
    ja3_cipher_suites = convert_to_ja3_segment(cipher_suites, 2)

    comp_methods, offset = parse_variable_array(tls_data, 1, offset)

    ext_segment, elliptic_curve, elliptic_curve_point_format, offset = (
        process_extensions(tls_data, offset)
    )

    ja3 = ",".join(
        [
            str(version),
            ja3_cipher_suites,
            ext_segment,
            elliptic_curve,
            elliptic_curve_point_format,
        ]
    )

    return {"ja3": ja3, "ja3_digest": md5(ja3.encode()).hexdigest()}


def main():
    """process raw tls clienthello bytes and print the ja3 fingerprint"""
    parser = argparse.ArgumentParser(
        description="generate ja3 fingerprints from raw tls clienthello bytes"
    )
    parser.add_argument("input_file", help="file with the client hello bytes")
    parser.add_argument(
        "-j", "--json", action="store_true", default=False, help="output json"
    )
    args = parser.parse_args()

    with open(args.input_file, "rb") as f:
        clienthello = f.read()

    try:
        result = process_clienthello(clienthello)
        if args.json:
            import json

            print(json.dumps([result], indent=4, sort_keys=True))
        else:
            print(f"ja3: {result['ja3']} : {result['ja3_digest']}")
    except Exception as e:
        print(f"failed to process tls client hello: {str(e)}")


if __name__ == "__main__":
    main()
