import socket
import os
import stat
import time
import sys
import hmac
import hashlib
import collections
import random
from binascii import unhexlify
import tkinter as tk
from tkinter import filedialog

# Static
Max_pack_size = 256
Local_ip = '10.1.1.2'
Local_port = 12345
Dest_ip = '10.1.1.4'
Dest_port = 12345
filesys_file_name = []
filesys_file_size = {}


S = [
    b'\x63', b'\x7C', b'\x77', b'\x7B', b'\xF2', b'\x6B', b'\x6F', b'\xC5', b'\x30', b'\x01', b'\x67', b'\x2B', b'\xFE', b'\xD7', b'\xAB', b'\x76',
    b'\xCA', b'\x82', b'\xC9', b'\x7D', b'\xFA', b'\x59', b'\x47', b'\xF0', b'\xAD', b'\xD4', b'\xA2', b'\xAF', b'\x9C', b'\xA4', b'\x72', b'\xC0',
    b'\xB7', b'\xFD', b'\x93', b'\x26', b'\x36', b'\x3F', b'\xF7', b'\xCC', b'\x34', b'\xA5', b'\xE5', b'\xF1', b'\x71', b'\xD8', b'\x31', b'\x15',
    b'\x04', b'\xC7', b'\x23', b'\xC3', b'\x18', b'\x96', b'\x05', b'\x9A', b'\x07', b'\x12', b'\x80', b'\xE2', b'\xEB', b'\x27', b'\xB2', b'\x75',
    b'\x09', b'\x83', b'\x2C', b'\x1A', b'\x1B', b'\x6E', b'\x5A', b'\xA0', b'\x52', b'\x3B', b'\xD6', b'\xB3', b'\x29', b'\xE3', b'\x2F', b'\x84',
    b'\x53', b'\xD1', b'\x00', b'\xED', b'\x20', b'\xFC', b'\xB1', b'\x5B', b'\x6A', b'\xCB', b'\xBE', b'\x39', b'\x4A', b'\x4C', b'\x58', b'\xCF',
    b'\xD0', b'\xEF', b'\xAA', b'\xFB', b'\x43', b'\x4D', b'\x33', b'\x85', b'\x45', b'\xF9', b'\x02', b'\x7F', b'\x50', b'\x3C', b'\x9F', b'\xA8',
    b'\x51', b'\xA3', b'\x40', b'\x8F', b'\x92', b'\x9D', b'\x38', b'\xF5', b'\xBC', b'\xB6', b'\xDA', b'\x21', b'\x10', b'\xFF', b'\xF3', b'\xD2',
    b'\xCD', b'\x0C', b'\x13', b'\xEC', b'\x5F', b'\x97', b'\x44', b'\x17', b'\xC4', b'\xA7', b'\x7E', b'\x3D', b'\x64', b'\x5D', b'\x19', b'\x73',
    b'\x60', b'\x81', b'\x4F', b'\xDC', b'\x22', b'\x2A', b'\x90', b'\x88', b'\x46', b'\xEE', b'\xB8', b'\x14', b'\xDE', b'\x5E', b'\x0B', b'\xDB',
    b'\xE0', b'\x32', b'\x3A', b'\x0A', b'\x49', b'\x06', b'\x24', b'\x5C', b'\xC2', b'\xD3', b'\xAC', b'\x62', b'\x91', b'\x95', b'\xE4', b'\x79',
    b'\xE7', b'\xC8', b'\x37', b'\x6D', b'\x8D', b'\xD5', b'\x4E', b'\xA9', b'\x6C', b'\x56', b'\xF4', b'\xEA', b'\x65', b'\x7A', b'\xAE', b'\x08',
    b'\xBA', b'\x78', b'\x25', b'\x2E', b'\x1C', b'\xA6', b'\xB4', b'\xC6', b'\xE8', b'\xDD', b'\x74', b'\x1F', b'\x4B', b'\xBD', b'\x8B', b'\x8A',
    b'\x70', b'\x3E', b'\xB5', b'\x66', b'\x48', b'\x03', b'\xF6', b'\x0E', b'\x61', b'\x35', b'\x57', b'\xB9', b'\x86', b'\xC1', b'\x1D', b'\x9E',
    b'\xE1', b'\xF8', b'\x98', b'\x11', b'\x69', b'\xD9', b'\x8E', b'\x94', b'\x9B', b'\x1E', b'\x87', b'\xE9', b'\xCE', b'\x55', b'\x28', b'\xDF',
    b'\x8C', b'\xA1', b'\x89', b'\x0D', b'\xBF', b'\xE6', b'\x42', b'\x68', b'\x41', b'\x99', b'\x2D', b'\x0F', b'\xB0', b'\x54', b'\xBB', b'\x16'
]

# Curve
EllipticCurve = collections.namedtuple('EllipticCurve', 'name p a b g n h')

curve = EllipticCurve(
    'secp256k1',
    # Field characteristic.
    p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
    # Curve coefficients.
    a=0,
    b=7,
    # Base point.
    g=(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
       0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8),
    # Subgroup order.
    n=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141,
    # Subgroup cofactor.
    h=1,
)


def long_to_bytes(val, endianness='big'):
    """
    Use :ref:`string formatting` and :func:`~binascii.unhexlify` to
    convert ``val``, a :func:`long`, to a byte :func:`str`.
    :param long val: The value to pack
    :param str endianness: The endianness of the result. ``'big'`` for
      big-endian, ``'little'`` for little-endian.
    If you want byte- and word-ordering to differ, you're on your own.
    Using :ref:`string formatting` lets us use Python's C innards.
    """

    # one (1) hex digit per four (4) bits
    width = val.bit_length()

    # unhexlify wants an even multiple of eight (8) bits, but we don't
    # want more digits than we need (hence the ternary-ish 'or')
    width += 8 - ((width % 8) or 8)

    # format width specifier: four (4) bits per hex digit
    fmt = '%%0%dx' % (width // 4)

    # prepend zero (0) to the width, to zero-pad the output
    s = unhexlify(fmt % val)

    if endianness == 'little':
        # see http://stackoverflow.com/a/931095/309233
        s = s[::-1]

    return s


def inverse_mod(k, p):
    """Returns the inverse of k modulo p.
    This function returns the only integer x such that (x * k) % p == 1.
    k must be non-zero and p must be a prime.
    """
    if k == 0:
        raise ZeroDivisionError('division by zero')

    if k < 0:
        # k ** -1 = p - (-k) ** -1  (mod p)
        return p - inverse_mod(-k, p)

    # Extended Euclidean algorithm.
    s, old_s = 0, 1
    t, old_t = 1, 0
    r, old_r = p, k

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    gcd, x, y = old_r, old_s, old_t

    assert gcd == 1
    assert (k * x) % p == 1

    return x % p


def is_on_curve(point):
    """Returns True if the given point lies on the elliptic curve."""
    if point is None:
        # None represents the point at infinity.
        return True

    x, y = point

    return (y * y - x * x * x - curve.a * x - curve.b) % curve.p == 0


def point_add(point1, point2):
    """Returns the result of point1 + point2 according to the group law."""
    assert is_on_curve(point1)
    assert is_on_curve(point2)

    if point1 is None:
        # 0 + point2 = point2
        return point2
    if point2 is None:
        # point1 + 0 = point1
        return point1

    x1, y1 = point1
    x2, y2 = point2

    if x1 == x2 and y1 != y2:
        # point1 + (-point1) = 0
        return None

    if x1 == x2:
        # This is the case point1 == point2.
        m = (3 * x1 * x1 + curve.a) * inverse_mod(2 * y1, curve.p)
    else:
        # This is the case point1 != point2.
        m = (y1 - y2) * inverse_mod(x1 - x2, curve.p)

    x3 = m * m - x1 - x2
    y3 = y1 + m * (x3 - x1)
    result = (x3 % curve.p, -y3 % curve.p)

    assert is_on_curve(result)

    return result


def scalar_mult(k, point):
    """Returns k * point computed using the double and point_add algorithm."""
    assert is_on_curve(point)

    if k % curve.n == 0 or point is None:
        return None

    if k < 0:
        # k * point = -k * (-point)
        return scalar_mult(-k, point_neg(point))

    result = None
    addend = point

    while k:
        if k & 1:
            # Add.
            result = point_add(result, addend)

        # Double.
        addend = point_add(addend, addend)

        k >>= 1

    assert is_on_curve(result)

    return result


def make_keypair():
    """Generates a random private-public key pair."""
    private_key = random.randrange(1, curve.n)
    public_key = scalar_mult(private_key, curve.g)

    return private_key, public_key


def byte_mul(byte1, byte2):
    mul = hex((int.from_bytes(byte1, 'big') *
               int.from_bytes(byte2, 'big')) & 0xFF)
    result = mul.encode('utf-8')
    return result


def xorbyte(var, key):
    return bytes(a ^ b for a, b in zip(var, key))


def subbyte(var):
    var = bytes(S[int.from_bytes(var,  "big")])
    return var


def shift_row(byte_array, length):
    # Left Shift

    new_array = bytearray(byte_array)
    for i in range(0, length):
        if(i == 4):
            new_array[i:i+1] = byte_array[i+1:i+2]
        elif(i == 5):
            new_array[i:i+1] = byte_array[i+1:i+2]
        elif(i == 6):
            new_array[i:i+1] = byte_array[i+1:i+2]
        elif(i == 7):
            new_array[i:i+1] = byte_array[4:5]
        elif(i == 8):
            new_array[i:i+1] = byte_array[i+2:i+3]
        elif(i == 9):
            new_array[i:i+1] = byte_array[i+2:i+3]
        elif(i == 10):
            new_array[i:i+1] = byte_array[8:9]
        elif(i == 11):
            new_array[i:i+1] = byte_array[9:10]
        elif(i == 12):
            new_array[i:i+1] = byte_array[i+3:i+4]
        elif(i == 13):
            new_array[i:i+1] = byte_array[12:13]
        elif(i == 14):
            new_array[i:i+1] = byte_array[13:14]
        elif(i == 15):
            new_array[i:i+1] = byte_array[14:15]

    return new_array


def mix_column(byte_array, length):

    return byte_array


def AES_encrypt(origin_byte, key, length):

    if(length < 16):
        for i in range(0, 16 - length):
            origin_byte.append(0)

    byte_array = bytearray(origin_byte)

    # Round 0
    for i in range(0, 16):
        byte_array[i:i+1] = xorbyte(bytes(byte_array[i:i+1]), bytes(key[i:i+1]))

    # Round 1 ~ 10
    for j in range(0, 10):
        if(j == 9):
            for i in range(0, 16):
                byte_array[i:i+1] = subbyte(byte_array[i:i+1])
            byte_array = shift_row(byte_array, 16)
            for i in range(0, 16):
                byte_array[i:i+1] = xorbyte(bytes(byte_array[i:i+1]), bytes(key[i:i+1]))
        else:
            for i in range(0, 16):
                byte_array[i:i+1] = subbyte(byte_array[i:i+1])
            byte_array = shift_row(byte_array, 16)
            byte_array = mix_column(byte_array, 16)
            for i in range(0, 16):
                byte_array[i:i+1] = xorbyte(bytes(byte_array[i:i+1]), bytes(key[i:i+1]))

    byte_array = byte_array[0:length]
    return byte_array


def add_packet_control_byte(number, origin_byte):
    byte_array = bytearray()
    byte_array.append(number)
    byte_array += origin_byte
    return byte_array


def read_packet_control_byte(origin_byte):
    control_byte = origin_byte[0:1]
    byte_array = bytearray(origin_byte[1:])
    return control_byte, byte_array


def file_transmission(sender, key, h_key):
    byte_array = bytearray()
    encrypted_array = bytearray()
    ch = bytearray()
    Pack_Size = 0
    send_size = 0
    file_name = ""
    List = []

    # Wait request
    print("Wait for request")
    while(1):
        request_packet = sender.recv(100)
        control_byte, request_packet = read_packet_control_byte(request_packet)
        if(control_byte == b'\x02'):
            file_name = request_packet.decode("utf-8")
            break

    # Read file in binary
    f = open(file_name, "rb")
    file_size = os.stat(file_name)[stat.ST_SIZE]
    for i in range(0, file_size):
        ch = f.read(1)
        List.append(ch)

    start_time = time.time()
    # Sender send file  data
    for i in range(0, file_size):
        Pack_Size = Pack_Size + 1
        byte_array += List[i]
        if(Pack_Size == Max_pack_size or i == file_size - 1):
            if(Pack_Size == Max_pack_size):
                array_offset = 0
                encrypted_array.append(0)
                for j in range(0, 16):
                    encrypted_array += bytearray(AES_encrypt(
                        byte_array[array_offset:array_offset+16], key, 16))
                    array_offset += 16
                send_size += 256
            elif(i == file_size - 1):
                remain_size = file_size - send_size
                encrypted_array.append(0)
                array_offset = 0
                while(1):
                    if(remain_size < 16):
                        encrypted_array += bytearray(AES_encrypt(
                            byte_array[array_offset:array_offset+remain_size], key, remain_size))
                        send_size += remain_size
                        break
                    else:
                        encrypted_array += bytearray(AES_encrypt(
                            byte_array[array_offset:array_offset+16], key, 16))
                        send_size += 16
                        array_offset += 16
                        remain_size -= 16
            # Packet size = 256 + 32  + 1bytes
            encrypted_array += hmac.new(h_key,
                                        encrypted_array[1:], hashlib.sha256).digest()
            sender.send(encrypted_array)
            Pack_Size = 0
            byte_array.clear()
            encrypted_array.clear()
            # time.sleep(1/1000000)
            for j in range(0, 5):
                for k in range(0, 5):
                    k = k

    print("Completed sending")
    print("Consecution time: %s second" % (time.time() - start_time))
    print()
    f.close()


def wait_public_key(sender, key, h_key):

    print("Wait for Key")
    key_packet = sender.recv(65)
    control_byte, key_packet = read_packet_control_byte(key_packet)
    #print("Origin key: ", key)
    #print("Origin h key: ", h_key)
    if(control_byte == b'\x01'):
        r = random.randrange(1, curve.n)
        R = scalar_mult(r, curve.g)
        R_packet = bytearray()
        R_packet = add_packet_control_byte(4, R_packet)
        R_packet += long_to_bytes(R[0])
        R_packet += long_to_bytes(R[1])
        sender.send(R_packet)

        public_key = [int.from_bytes(bytes(key_packet[0:32]), "big"),
                      int.from_bytes(bytes(key_packet[32:64]), "big")]
        ecc_key = scalar_mult(r, public_key)
        ecc_key_byte = bytearray()
        ecc_key_byte += long_to_bytes(ecc_key[0])
        ecc_key_byte += long_to_bytes(ecc_key[1])
        ecc_key_byte = hashlib.sha256(ecc_key_byte).digest()
        key.clear()
        h_key.clear()
        key += ecc_key_byte[0:16]
        h_key += ecc_key_byte[16:32]

        print("Generate ECC key Successed")
        print()
        #print("New key: ", key)
    else:
        print("Generate ECC key failed")


def find_file(sender):
    wait_packet = bytearray()
    send_packet = bytearray()
    number_of_files = 0
    send_packet = add_packet_control_byte(6, send_packet)
    wait_packet = sender.recv(100)
    control_byte, wait_packet = read_packet_control_byte(wait_packet)
    if(control_byte == b'\x05'):
        files = os.listdir(os.getcwd())
        for i in files:
            fullpath = os.path.join(os.getcwd(), i)
            if os.path.isfile(fullpath):
                number_of_files += 1
                filesys_file_name.append(i)
                filesys_file_size[i] = os.stat(i)[stat.ST_SIZE]

        send_packet.append(number_of_files)
        for i in range(0, len(filesys_file_name)):
            send_packet += (filesys_file_name[i] + '\n' +
                            str(filesys_file_size[filesys_file_name[i]]) + '\n').encode("utf-8")

        sender.send(send_packet)
    else:
        print("Requset error")


if __name__ == '__main__':

    # Static
    key = bytearray()
    h_key = bytearray()

    # Encrypt key
    key_count = 0
    for i in range(0, 16):
        key.append(key_count)
        key_count += 1
    # Hmac key
    for i in range(0, 16):
        h_key.append(1)

    # Connect
    sender = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sender.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
    sender.bind((Local_ip, Local_port))
    sender.connect((Dest_ip, Dest_port))
    print("It's Server")
    print("Success connect to", str((Dest_ip, Dest_port)))
    print()
    wait_public_key(sender, key, h_key)
    find_file(sender)
    while(1):
        print("Choose function:")
        print("\tType 1 for file transmission")
        print("\tType 0 exit")
        function = input()
        if(function == '1'):
            file_transmission(sender, key, h_key)
        elif(function == '0'):
            break

    print("Server Closed!")
    sender.shutdown(2)
    sender.close()
