import argparse
import socket
import struct

def dns_query(type, name, server):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = (server, 53)  # DNS always runs on port 53

    ID = 0x1234
    QR = 0; OPCODE = 0; AA = 0; TC = 0; RD = 1
    RA = 0; Z = 0; RCODE = 0
    QDCOUNT = 1; ANCOUNT = 0; NSCOUNT = 0; ARCOUNT = 0

    # Flags word: each field shifted to its correct bit position
    # QR=bit15, OPCODE=bits14-11, AA=bit10, TC=bit9, RD=bit8,
    # RA=bit7, Z=bits6-4, RCODE=bits3-0
    header = struct.pack('!HHHHHH',
        ID,
        QR << 15 | OPCODE << 11 | AA << 10 | TC << 9 | RD << 8 | RA << 7 | Z << 4 | RCODE,
        QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT)

    # Encode QNAME: split on '.', prefix each label with its length byte, end with \x00
    qname_parts = name.split('.')
    qname_encoded_parts = [struct.pack('B', len(part)) + part.encode('ascii') for part in qname_parts]
    qname_encoded = b''.join(qname_encoded_parts) + b'\x00'  # null byte terminates the name

    # QTYPE: A=1 (IPv4), AAAA=28 (IPv6)  — RFC 1035 §3.2.2
    if type == 'A':
        qtype = 1
    elif type == 'AAAA':
        qtype = 28

    qclass = 1  # IN (Internet) — RFC 1035 §3.2.4

    question = qname_encoded + struct.pack('!HH', qtype, qclass)

    message = header + question  # always send header + question together
    sock.sendto(message, server_address)

    data, _ = sock.recvfrom(4096)

    # Response header is fixed 12 bytes (6 × 2-byte fields)
    response_header = data[:12]
    ID, FLAGS, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT = struct.unpack('!HHHHHH', response_header)

    # Question section starts right after the 12-byte header
    response_question = data[12:12+len(question)]
    assert response_question == question

    # Answer section starts after header + question
    response_answer = data[12+len(question):]
    offset = 0
    for _ in range(ANCOUNT):
        name_parts = []
        while True:
            length = response_answer[offset]
            offset += 1
            if length == 0:
                break
            elif length & 0xc0 == 0xc0:
                pointer = struct.unpack('!H', response_answer[offset-1:offset+1])[0] & 0x3fff
                offset += 1
                name_parts.append(parse_name(data, pointer))
                break
            else:
                label = response_answer[offset:offset+length].decode('ascii')
                offset += length
                name_parts.append(label)
        name = '.'.join(name_parts)

        # '!HHIH' = 2+2+4+2 = 10 bytes
        type, cls, ttl, rdlength = struct.unpack('!HHIH', response_answer[offset:offset+10])
        offset += 10

        rdata = response_answer[offset:offset+rdlength]
        offset += rdlength

        if type == 1:    # A record
            ipv4 = socket.inet_ntop(socket.AF_INET, rdata)
            print(f'{name} has IPv4 address {ipv4}')
            return ipv4
        elif type == 28:  # AAAA record
            ipv6 = socket.inet_ntop(socket.AF_INET6, rdata)
            print(f'{name} has IPv6 address {ipv6}')
            return ipv6