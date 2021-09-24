import socket
import os
import stat
import time
import sys
import hmac
import hashlib


Max_pack_size = 256
Dest_ip = '10.1.1.4'
Dest_port = 54321
Local_ip = '10.1.1.2'
Local_port = 54321
file_name = "test.mp4"

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


def byte_mul(byte1, byte2):
    mul = hex((int.from_bytes(byte1, 'big') * int.from_bytes(byte2, 'big')) & 0xFF)
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
        if(i == length - 1):
            new_array[length-1:length] = byte_array[0:1]
        else:
            new_array[i:i+1] = byte_array[i+1:i+2]

    return new_array


def mix_column(byte_array, length):

    return byte_array


def AES_encrypt(origin_byte, key, length):

    byte_array = bytearray(origin_byte)
    '''
    # Round 0
    for i in range(0, length):
        byte_array[i:i+1] = xorbyte(bytes(byte_array[i:i+1]), bytes(key[i:i+1]))

    # Round 1 ~ 10
    for j in range(0, 10):
        if(j == 9):
            for i in range(0, length):
                byte_array[i:i+1] = subbyte(byte_array[i:i+1])
            byte_array = shift_row(byte_array, length)
            for i in range(0, length):
                byte_array[i:i+1] = xorbyte(bytes(byte_array[i:i+1]), bytes(key[i:i+1]))
        else:
            for i in range(0, length):
                byte_array[i:i+1] = subbyte(byte_array[i:i+1])
            byte_array = shift_row(byte_array, length)
            byte_array = mix_column(byte_array, length)
            for i in range(0, length):
                byte_array[i:i+1] = xorbyte(bytes(byte_array[i:i+1]), bytes(key[i:i+1]))
    '''
    return byte_array


def add_packet_control_byte(number, origin_byte):
    byte_array = bytearray()
    byte_array.append(number)
    byte_array += origin_byte
    return byte_array


if __name__ == '__main__':

    byte_array = bytearray()
    encrypted_array = bytearray()
    ch = bytearray()
    Pack_Size = 0
    send_size = 0
    List = []

    # Encrypt key
    key = bytearray()
    key_count = 0
    for i in range(0, 16):
        key.append(key_count)
        key_count += 1

    # Hmac key
    h_key = bytearray()
    for i in range(0, 16):
        h_key.append(1)

    # Read file in binary
    f = open(file_name, "rb")
    file_size = os.stat(file_name)[stat.ST_SIZE]
    for i in range(0, file_size):
        ch = f.read(1)
        List.append(ch)

    # Connect
    sender = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #sender.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 289)
    sender.bind((Local_ip, Local_port))
    sender.connect((Dest_ip, Dest_port))
    print("Local IP: ", Local_ip)
    print("Local Port: ", Local_port)
    print("Success connect to", str((Dest_ip, Dest_port)))

    trash = input()

    # Send file information: file size, file name
    info_packet = str(file_size) + '\n' + file_name + '\n'
    info_packet = add_packet_control_byte(2, info_packet.encode("utf-8"))
    info_packet += hmac.new(h_key, info_packet[1:], hashlib.sha256).digest()
    sender.send(info_packet)

    # Sender send file data
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
            encrypted_array += hmac.new(h_key, encrypted_array[1:], hashlib.sha256).digest()
            sender.send(encrypted_array)
            print(send_size)
            Pack_Size = 0
            byte_array.clear()
            encrypted_array.clear()
            trash = sender.recv(1000)

    print("Completed sending")
    f.close()
    sender.close()
