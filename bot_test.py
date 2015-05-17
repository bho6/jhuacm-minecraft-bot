# Brian Ho
# bho6@jhu.edu
# This is a test script for a simple Minecraft bot. This uses the server
# protocol found at http://wiki.vg/Protocol to authenticate with a server,
# connect to the server, and perform some simple chat and movement operations.
# We later abstract some of these helper functions into a library for
# creating a general purpose bot. As a disclaimer, I am not familiar with a
# binary manipulation in Python, so I might do things inefficiently with
# binary strings. Sue me.

import sys
import socket


# Used as a decorator function to prepend generated packets with a header
# containing the size of the packet ID + payload.
def wrap_packet(func):
    def inner(*args, **kwargs):
        payload = func(*args, **kwargs)
        header = bytearray()
        header.append(len(payload))
        return header + payload
    return inner


# Used to convert a standard Python integer into a VarInt.
# TODO: Fix ordering?
def varint(num):
    binary = "{:b}".format(num)
    while len(binary) % 7 != 0:  # pad until full
        binary = '0' + binary
    bytes = []
    byte_parts = [binary[x:x+7] for x in xrange(0, len(binary), 7)]
    for b in byte_parts[:-1]:
        bytes.append(int('1{}'.format(b), 2))
    bytes.append(int('0{}'.format(byte_parts[-1]), 2))
    return bytes


# Used to convert a standard Python integer into byte form.
def bnum(num, num_bytes):
    binary = "{:b}".format(num)
    while len(binary) < num_bytes * 8:
        binary = '0' + binary
    bytes = []
    for b in xrange(0, num_bytes):
        bytes.append(int(binary[b*8:(b+1)*8], 2))
    return bytes


# Used to convert a Python string into a UTF-8 string prepended with its
# length in bytes.
def string(str_to_encode):
    bytes = []
    bytes.append(len(str_to_encode))
    for c in unicode(str_to_encode, 'utf-8'):
        bytes.append(ord(c))
    return bytes


# Function that appends an element to a given packet using a generator
# function like varint or string.
def append_packet(packet, gen_func, *args):
    result = gen_func(*args)
    for byte in result:
        packet.append(byte)


# Helper function for easily reading a single byte.
def read_byte(socket):
    return read_bytes(socket, 1)[0]


# Read the next num bytes from the stream and return a list of binary strings.
def read_bytes(socket, num_bytes):
    bytes = socket.recv(num_bytes)
    output = []
    for i in xrange(0, num_bytes):
        byte = "{:b}".format(ord(bytes[i]))
        while len(byte) < 8:
            byte = '0' + byte
        output.append(byte)
    return output


# Read the next string from the stream where the first element is a VarInt of
# length, and the next bytes constitute the string in UTF-8.
def read_string(socket):
    length = read_varint(socket)
    return socket.recv(length)


# Read the next num bytes and convert to a Python integer.
def read_number(socket, num_bytes):
    bytes = read_bytes(socket, num_bytes)
    num = ''
    for byte in bytes:
        num += byte
    return int(num, 2)


# Function that reads the next VarInt from the stream.
def read_varint(socket):
    total_int = ''
    while True:
        next_byte = read_byte(socket)
        total_int = next_byte[1:] + total_int
        if next_byte[0] == '0':
            break
    return int(total_int, 2)


# Function that handles reading a packet from the server. 
def read_packet(socket):
    length = read_varint(socket)
    packet_id = read_number(socket, 1)
    # pattern = recv_packet_info[packet_id]


    print read_string(socket)
    print read_string(socket)
    print read_string(socket)



# Prepare a Handshake packet to the server.
@wrap_packet
def s_handshake(version, server_addr, port, mode):
    payload = bytearray()
    append_packet(payload, bnum, 0, 1)
    append_packet(payload, varint, version)
    append_packet(payload, string, server_addr)
    append_packet(payload, bnum, port, 2)
    append_packet(payload, varint, mode)
    return payload


# Prepare a Login Start packet to the server.
@wrap_packet
def s_login_start(name):
    payload = bytearray()
    append_packet(payload, bnum, 0, 1)
    append_packet(payload, string, name)
    return payload


# Main method and program entry point.
def main():
    server = 'london.acm.jhu.edu'
    port = 25565
    buffer_size = 10000
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, port))

    s.send(s_handshake(47, server, port, 2))
    s.send(s_login_start('Turdy'))
    # print len(s.recv(buffer_size))
    read_packet(s)

    s.close()

    # print 'received data:{}'.format(data)

if __name__ == "__main__":
    main()
