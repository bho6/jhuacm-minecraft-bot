# Brian Ho
# bho6@jhu.edu
# This is a test script for a simple Minecraft bot. This uses the server
# protocol found at http://wiki.vg/Protocol to authenticate with a server,
# connect to the server, and perform some simple chat and movement operations.
# We will later abstract some of these helper functions into a library for
# creating a general purpose bot. As a disclaimer, I am not familiar with a
# binary manipulation in Python, so I might do things inefficiently with
# binary strings. Sue me.

import sys
import socket
import getpass
import urllib2
import json
import math
import random
import hashlib
import rsa
import time
import zlib
from Crypto.Cipher import AES


# Global environment info used to store state. This will be implemented with
# a cleaner representation once all the code is factored out of a test script.
environment_info = {
    'secret_iv': None,
    'cipher': None,
    'state': 'login',
    'compress': -1,
    'buffer': ''
}


# Used as a decorator function to prepend generated packets with a header
# containing the size of the packet ID + payload.
def wrap_packet(func):
    def inner(*args, **kwargs):
        payload = func(*args, **kwargs)
        header = bytearray()
        append_packet(header, varint, len(payload))
        return header + payload
    return inner


# Helper function that wraps around recv() to also decrypt when encryption
# is enabled. It also pulls from the buffer instead of the TCP connection
# when the buffer is not empty.
def decrypt_recv(socket, num_bytes):
    buffer_data = environment_info['buffer']
    if num_bytes > len(buffer_data):
        data = buffer_data + socket.recv(num_bytes - len(buffer_data))
    else:
        data = buffer_data[:num_bytes]
        print 'dataasdfasdf', data
        print 'bufferafter', buffer_data[num_bytes:]
        environment_info['buffer'] = buffer_data[num_bytes:]
    secret = environment_info['secret_iv']
    if secret is not None:
        data = environment_info['cipher'].decrypt(data)
    return data


# Used to convert a standard Python integer into a VarInt.
def varint(num):
    binary = '{:b}'.format(num)
    while len(binary) % 7 != 0:  # pad until full
        binary = '0' + binary
    bytes = []
    byte_parts = list(reversed([binary[x:x+7] for x in xrange(0, len(binary), 7)]))
    for b in byte_parts[:-1]:
        bytes.append(int('1{}'.format(b), 2))
    bytes.append(int('0{}'.format(byte_parts[-1]), 2))

    return bytes


# Used to convert a standard Python integer into byte form.
def bnum(num, num_bytes):
    binary = '{:b}'.format(num)
    while len(binary) < num_bytes * 8:
        binary = '0' + binary
    bytes = []
    for b in xrange(0, num_bytes):
        bytes.append(int(binary[b*8:(b+1)*8], 2))
    return bytes


# Used to convert a Python string into a UTF-8 string prepended with its
# length in bytes.
def string(str_to_encode):
    bytes = varint(len(str_to_encode))
    for c in unicode(str_to_encode, 'utf-8'):
        bytes.append(ord(c))
    return bytes


# Used to convert a Python string representing a byte array into an actual
# array of bytes.
def byte_array(str_to_encode):
    return [ord(char) for char in str_to_encode]


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
    bytes = decrypt_recv(socket, num_bytes)
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
    return decrypt_recv(socket, length)


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


# Dictionary to more easily handle receiving packets during the login state.
# In this, each packet ID is mapped to a list of arguments with types.
login_packet_info = {
    # Disconnect
    0: [('reason', 'string')],
    # Encryption Request
    1: [('sid', 'string'), ('key', 'string'), ('token', 'string')],
    # Login Success
    2: [('uuid', 'string'), ('username', 'string')],
    # Set Compression
    3: [('threshold', 'varint')]
}


# Similar to login_packet_info, except used in the play state.
play_packet_info = {}


# Function that handles reading a packet from the server. 
def read_packet(socket, state):
    if environment_info['compress'] != -1:
        packet_length = read_varint(socket)
        data_length = read_varint(socket)
        if data_length == 0:
            length = packet_length - 1
        else:
            length = data_length
            # 204, 394
            print packet_length, data_length
            cl = math.ceil(len('{:b}'.format(length)) / 7.0)
            compressed_data = decrypt_recv(socket, packet_length - int(cl))
            print 'skipped', cl
            data = zlib.decompress(compressed_data)
            environment_info['buffer'] = data + environment_info['buffer']
            print environment_info['buffer']
    else:
        length = read_varint(socket)
    packet_id = read_number(socket, 1)
    if state == 'play':
        pattern = play_packet_info.get(packet_id, None)
    else:
        pattern = login_packet_info.get(packet_id, None)
    if pattern is None:
        print 'Skipping packet id {} of length {}'.format(packet_id, length)
        decrypt_recv(socket, length - 1)
        return None


    response = {'packet_id': packet_id}
    for (arg, arg_type) in pattern:
        if arg_type == 'string':
            response[arg] = read_string(socket)
        elif arg_type == 'varint':
            response[arg] = read_varint(socket)
        else:
            print 'Cannot parse type of {}'.format(arg_type)

    return response


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


# Prepare an Encryption Response packet to the server.
@wrap_packet
def s_encrypt_response(auth_token, key, token, profile):
    payload = bytearray()
    append_packet(payload, bnum, 1, 1)
    shared_secret = ''
    # generate shared secret
    while len(shared_secret) < 16:
        rand_byte = random.randrange(0, 255)
        shared_secret += chr(rand_byte)

    # Store the shared secret.
    environment_info['secret_iv'] = shared_secret
    environment_info['cipher'] = AES.new(
        shared_secret, AES.MODE_CFB, shared_secret)

    # auth with Mojang servers
    authenticate_client(auth_token, profile, key, shared_secret)

    # some RSA cypto mumbo jumbo
    pub = rsa.PublicKey.load_pkcs1_openssl_der(key)
    shared_ctext = rsa.encrypt(shared_secret, pub)
    token_ctext = rsa.encrypt(token, pub)

    append_packet(payload, varint, len(shared_ctext))
    append_packet(payload, byte_array, shared_ctext)
    append_packet(payload, varint, len(token_ctext))
    append_packet(payload, byte_array, token_ctext)
    return payload


# A very ugly helper function to generate the hash used for authentication. I
# will rewrite this soon, I promise.
def generate_auth_hash(server_id, shared_secret, key):
    h = hashlib.sha1()
    h.update(server_id)
    h.update(shared_secret)
    h.update(key)
    dgst = [ord(char) for char in h.digest()]
    total_bin = ''
    for char in dgst:
        binary = "{:b}".format(char)
        while len(binary) < 8:
            binary = '0' + binary
        total_bin += binary
    if total_bin[0] == '1':
        total_bin = '{:b}'.format(int(total_bin, 2) - 1)
        new_str = ''
        for char in total_bin:
            if char == '0':
                new_str += '1'
            else:
                new_str += '0'
        total_bin = new_str
        return '-{:x}'.format(int(total_bin, 2))
    return '{:x}'.format(int(total_bin, 2))


# Queries the Mojang authentication servers with a hash, access token and
# profile to connect to the actual game server.
def authenticate_client(auth_token, profile, key, shared_secret):
    server_hash = generate_auth_hash('', shared_secret, key)
    payload = json.dumps({
        'accessToken': auth_token,
        'selectedProfile': profile,
        'serverId': server_hash
    })
    req = urllib2.Request(
        'https://sessionserver.mojang.com/session/minecraft/join')
    req.add_header('Content-Type', 'application/json')
    try:
        urllib2.urlopen(req, payload).read()
    except urllib2.HTTPError, e:
        print 'Error initiating session'
        sys.exit(1)


# Queries the Mojang authentication servers with a username and a password
# to get an authentication token.
def get_auth_token(username, password):
    payload = json.dumps({
        'agent': {
            'name': 'Minecraft',
            'version': 1
        },
        'username': username,
        'password': password
    })
    req = urllib2.Request('https://authserver.mojang.com/authenticate')
    req.add_header('Content-Type', 'application/json')
    try:
        response = json.loads(urllib2.urlopen(req, payload).read())
    except urllib2.HTTPError:
        print 'Invalid username/password combination'
        sys.exit(1)
    return (response['accessToken'], response['availableProfiles'][0]['id'],
        str(response['availableProfiles'][0]['name']))


# Main method and program entry point.
def main():
    # get login credentials
    sys.stdout.write('Username: ')
    username = sys.stdin.readline().strip()
    password = getpass.getpass().strip()

    auth_token, profile, username = get_auth_token(username, password)
    server = 'london.acm.jhu.edu'
    port = 25565
    buffer_size = 10000
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, port))

    s.send(s_handshake(47, server, port, 2))
    s.send(s_login_start(username))
    response = read_packet(s, environment_info['state'])
    s.send(s_encrypt_response(
        auth_token, response['key'], response['token'], profile))

    response = read_packet(s, environment_info['state'])
    environment_info['compress'] = response['threshold']

    response = read_packet(s, environment_info['state'])
    print response['uuid'], response['username']
    environment_info['state'] = 'play'

    while True:
        read_packet(s, environment_info['state'])

    s.close()

    # print 'received data:{}'.format(data)

if __name__ == "__main__":
    main()
