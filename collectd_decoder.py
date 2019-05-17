# License: 2-Clause BSD

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Hash import SHA
from scapy.all import rdpcap, UDP
import struct
import argparse
import time

TYPE_HOST = 0x0000
TYPE_TIME = 0x0001
TYPE_TIMEHR = 0x0008
TYPE_PLUGIN = 0x0002
TYPE_PLUGIN_INSTANCE = 0x0003
TYPE_TYPE = 0x0004
TYPE_TYPE_INSTANCE = 0x0005
TYPE_VALUES = 0x0006
TYPE_INTERVAL = 0x0007
TYPE_INTERVALHR = 0x0009
TYPE_MESSAGE = 0x0100
TYPE_SEVERITY = 0x0101
TYPE_SIGN_SHA256 = 0x0200
TYPE_ENCR_AES256 = 0x0210

header = struct.Struct("!2H")
num = struct.Struct("!Q")


def decrypt(data, passwd):
    """
    struct part_encryption_aes256_s {
    part_header_t head;
    uint16_t username_length;
    char *username;
    unsigned char iv[16];
    /* <encrypted> */
    unsigned char hash[20];
    /*   <payload /> */
    /* </encrypted> */
    };
    """
    _type, _len, _ulen = struct.unpack('>hhh', data[0:6])
    if _type != 0x210:
        raise ValueError("Unexpected type")

    fmt = ">3h{}s16s".format(_ulen)
    hdrlen = struct.calcsize(fmt)
    _, _, _, _user, _iv = struct.unpack(fmt, data[0:hdrlen])

    # print("type: 0x{:x}, len: {}, ulen: {}, user: {}, iv: {}".format(
    #     _type, _len, _ulen, _user, _iv.hex()))

    key = SHA256.new()
    key.update(passwd.encode('ascii'))

    enc_data = data[hdrlen:]
    # need multiple of 16 bytes
    pad = 16 - (len(enc_data) % 16)
    enc_data = enc_data + (pad * b'0')

    dec_data = AES.new(key.digest(), AES.MODE_OFB, _iv).decrypt(enc_data)

    hdrlen = struct.calcsize(">20s")
    p_hash, = struct.unpack(">20s", dec_data[:hdrlen])
    data = dec_data[hdrlen:-pad]

    hash = SHA.new()
    hash.update(data)

    if p_hash.hex() != hash.hexdigest():
        raise ValueError("Hash mismatch, wrong password or corrupted data")

    return data


def parse_string(_type, _len, data, **kwargs):
    return (data[header.size: _len-1]).decode('ascii')


def parse_num(_type, _len, data, **kwargs):
    return num.unpack_from(data, header.size)[0]


def parse_val(_type, _len, data, **kwargs):
    VAL_TYPES = {
        0: struct.Struct('!Q'),  # COUNTER
        1: struct.Struct('<d'),  # GAUGE
        2: struct.Struct('!q'),  # DERIVE
        3: struct.Struct('!Q'),  # ABSOLUTE
    }
    VAL_NAMES = {
        0: "COUNTER",
        1: "GAUGE",
        2: "DERIVE",
        3: "ABSOLUTE",
    }
    hdr = struct.Struct('!H')
    nvals, = hdr.unpack_from(data, header.size)
    # vals are typ (1 byte) + val (8 byte)
    if _len != (header.size + hdr.size) + nvals * 9:
        raise ValueError("Value size mismatch")

    # In case you have many values, the types need to be defined first, then
    # the values, like this: [type][type][type][value][value][value] and not
    # [type][value][type][value][type][value].

    data = data[header.size + hdr.size:]
    vals = []
    for i in range(0, nvals):
        dtype = VAL_TYPES[data[i]]
        res, = dtype.unpack_from(data, 8*i + nvals)
        vals.append([VAL_NAMES[data[i]], res])
    return vals


def parse_time(_type, _len, data, **kwargs):
    v = parse_num(_type, _len, data)
    pt = cdtime_to_time(v)

    if _type == TYPE_INTERVAL or _type == TYPE_INTERVALHR:
        return pt

    if kwargs.get('parse_time', False):
        return time.ctime(pt) + " (" + str(pt) + ")"
    return pt


DECODE = {
    TYPE_HOST: parse_string,
    TYPE_TIME: parse_time,
    TYPE_TIMEHR: parse_time,
    TYPE_PLUGIN: parse_string,
    TYPE_PLUGIN_INSTANCE: parse_string,
    TYPE_TYPE: parse_string,
    TYPE_TYPE_INSTANCE: parse_string,
    TYPE_VALUES: parse_val,
    TYPE_INTERVAL: parse_time,
    TYPE_INTERVALHR: parse_time,
    TYPE_MESSAGE: parse_string,
    TYPE_SEVERITY: parse_num,
}

TYPES = {
    TYPE_HOST: "HOST",
    TYPE_TIME: "TIME",
    TYPE_TIMEHR: "TIMEHR",
    TYPE_PLUGIN: "PLUGIN",
    TYPE_PLUGIN_INSTANCE: "PLUGIN_INSTANCE",
    TYPE_TYPE: "TYPE",
    TYPE_TYPE_INSTANCE: "TYPE_INSTANCE",
    TYPE_VALUES: "VALUES",
    TYPE_INTERVAL: "INTERVAL",
    TYPE_MESSAGE: "MESSAGE",
    TYPE_SEVERITY: "SEVERITY",
    TYPE_SIGN_SHA256: "SIGN_SHA256",
    TYPE_ENCR_AES256: "ENCR_AES256",
    TYPE_INTERVALHR: "INTERVALHR",
}


def decode(pkt, **kwargs):
    """
    Decode a single packet
    """
    offset = 0
    while True:
        # TODO: bounds checking
        _type, _len = header.unpack_from(pkt, offset)
        data = pkt[offset:offset + header.size + _len]
        if _type == TYPE_ENCR_AES256:
            passwd = kwargs['password']
            if passwd is None:
                raise ValueError("Encrypted packet found but no password set (-p mypasss)")
            decode(decrypt(data, passwd), **kwargs)
        elif _type == TYPE_SIGN_SHA256:
            raise("TYPE_SIGN unimplemented")
        else:
            f = DECODE[_type]
            print("{} {}".format(TYPES[_type], f(_type, _len, data, **kwargs)))
        offset += _len
        if offset >= len(pkt):
            break


def cdtime_to_time(cdt):
    # Stolen from someone on github
    # https://github.com/sayar/python-collectd-parser/blob/master/collectd_parser.py
    sec = cdt >> 30
    nsec = ((cdt & 0b111111111111111111111111111111) / 1.073741824) / 10**9
    assert 0 <= nsec < 1
    return sec + nsec


def main():
    parser = argparse.ArgumentParser(description='Collectd packet decoder')
    parser.add_argument('-f', '--file',
                        help="pcap file containing collctd packets")
    parser.add_argument('-p', '--password',
                        help="Decryption password for encoded packets")
    parser.add_argument('-t', '--parse-time', action="store_true",
                        help="Human readable time format")
    args = parser.parse_args()

    packets = rdpcap(args.file)
    for p in packets:
        if p[UDP] and p[UDP].dport == 25826:
            try:
                print("#"*40)
                decode(p[UDP].load, **vars(args))
            except Exception as e:
                print("Failed to decode packet: {}".format(e))


if __name__ == "__main__":
    main()