# Brian Ho
# bho6@jhu.edu
# This is a test script for a simple Minecraft bot. This uses the server
# protocol found at http://wiki.vg/Protocol to authenticate with a server,
# connect to the server, and perform some simple chat and movement operations.

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
def varint(num):
    binary = "{:b}".format(num)
    while len(binary) % 8 != 0: # pad until full byte
        binary = '0' + binary
    print binary



# Send a handshake packet to the server.
@wrap_packet
def s_handshake(version, server_addr, port, mode):
    payload = bytearray()
    payload.append(version)
    ba.append(59)
    return ba

def main():
    sys.exit(1)
    TCP_IP = 'london.acm.jhu.edu'
    TCP_PORT = 25565
    BUFFER_SIZE = 1024
    MESSAGE = bytearray()
    MESSAGE.append(0)
    MESSAGE.append(47)
    GAME_ADDRESS = 'london.acm.jhu.edu'
    MESSAGE.append(len(GAME_ADDRESS))
    for c in unicode(GAME_ADDRESS, "utf-8"):
        MESSAGE.append(ord(c))

    MESSAGE.append(99)
    MESSAGE.append(221)

    MESSAGE.append(2)

    total_message = bytearray()
    total_message.append(len(MESSAGE))
    total_message = total_message + MESSAGE

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((TCP_IP, TCP_PORT))
    s.send(total_message)

    msg2 = bytearray()
    msg2.append(0)
    player_name = 'Turdy'
    msg2.append(len(player_name))
    for c in unicode(player_name, "utf-8"):
        msg2.append(ord(c))

    msg3 = bytearray()
    msg3.append(len(msg2))
    msg3 = msg3 + msg2
    s.send(msg3)

    data = s.recv(2048)
    s.close()

    print "received data:", data

if __name__ == "__main__":
    main()