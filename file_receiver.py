import socket
import sys
import os
import stat
import time
import hmac
import hashlib

Local_ip = '127.0.0.1'
Local_port = 12345

inv_S = [
    b'\x52', b'\x09', b'\x6A', b'\xD5', b'\x30', b'\x36', b'\xA5', b'\x38', b'\xBF', b'\x40', b'\xA3', b'\x9E', b'\x81', b'\xF3', b'\xD7', b'\xFB',
    b'\x7C', b'\xE3', b'\x39', b'\x82', b'\x9B', b'\x2F', b'\xFF', b'\x87', b'\x34', b'\x8E', b'\x43', b'\x44', b'\xC4', b'\xDE', b'\xE9', b'\xCB',
    b'\x54', b'\x7B', b'\x94', b'\x32', b'\xA6', b'\xC2', b'\x23', b'\x3D', b'\xEE', b'\x4C', b'\x95', b'\x0B', b'\x42', b'\xFA', b'\xC3', b'\x4E',
    b'\x08', b'\x2E', b'\xA1', b'\x66', b'\x28', b'\xD9', b'\x24', b'\xB2', b'\x76', b'\x5B', b'\xA2', b'\x49', b'\x6D', b'\x8B', b'\xD1', b'\x25',
    b'\x72', b'\xF8', b'\xF6', b'\x64', b'\x86', b'\x68', b'\x98', b'\x16', b'\xD4', b'\xA4', b'\x5C', b'\xCC', b'\x5D', b'\x65', b'\xB6', b'\x92',
    b'\x6C', b'\x70', b'\x48', b'\x50', b'\xFD', b'\xED', b'\xB9', b'\xDA', b'\x5E', b'\x15', b'\x46', b'\x57', b'\xA7', b'\x8D', b'\x9D', b'\x84',
    b'\x90', b'\xD8', b'\xAB', b'\x00', b'\x8C', b'\xBC', b'\xD3', b'\x0A', b'\xF7', b'\xE4', b'\x58', b'\x05', b'\xB8', b'\xB3', b'\x45', b'\x06',
    b'\xD0', b'\x2C', b'\x1E', b'\x8F', b'\xCA', b'\x3F', b'\x0F', b'\x02', b'\xC1', b'\xAF', b'\xBD', b'\x03', b'\x01', b'\x13', b'\x8A', b'\x6B',
    b'\x3A', b'\x91', b'\x11', b'\x41', b'\x4F', b'\x67', b'\xDC', b'\xEA', b'\x97', b'\xF2', b'\xCF', b'\xCE', b'\xF0', b'\xB4', b'\xE6', b'\x73',
    b'\x96', b'\xAC', b'\x74', b'\x22', b'\xE7', b'\xAD', b'\x35', b'\x85', b'\xE2', b'\xF9', b'\x37', b'\xE8', b'\x1C', b'\x75', b'\xDF', b'\x6E',
    b'\x47', b'\xF1', b'\x1A', b'\x71', b'\x1D', b'\x29', b'\xC5', b'\x89', b'\x6F', b'\xB7', b'\x62', b'\x0E', b'\xAA', b'\x18', b'\xBE', b'\x1B',
    b'\xFC', b'\x56', b'\x3E', b'\x4B', b'\xC6', b'\xD2', b'\x79', b'\x20', b'\x9A', b'\xDB', b'\xC0', b'\xFE', b'\x78', b'\xCD', b'\x5A', b'\xF4',
    b'\x1F', b'\xDD', b'\xA8', b'\x33', b'\x88', b'\x07', b'\xC7', b'\x31', b'\xB1', b'\x12', b'\x10', b'\x59', b'\x27', b'\x80', b'\xEC', b'\x5F',
    b'\x60', b'\x51', b'\x7F', b'\xA9', b'\x19', b'\xB5', b'\x4A', b'\x0D', b'\x2D', b'\xE5', b'\x7A', b'\x9F', b'\x93', b'\xC9', b'\x9C', b'\xEF',
    b'\xA0', b'\xE0', b'\x3B', b'\x4D', b'\xAE', b'\x2A', b'\xF5', b'\xB0', b'\xC8', b'\xEB', b'\xBB', b'\x3C', b'\x83', b'\x53', b'\x99', b'\x61',
    b'\x17', b'\x2B', b'\x04', b'\x7E', b'\xBA', b'\x77', b'\xD6', b'\x26', b'\xE1', b'\x69', b'\x14', b'\x63', b'\x55', b'\x21', b'\x0C', b'\x7D'
]


def byte_mul(byte1, byte2):
    mul = hex((int.from_bytes(byte1, 'big') *
              int.from_bytes(byte2, 'big')) & 0xFF)
    result = mul.encode('utf-8')
    return result


def xorbyte(var, key):
    return bytes(a ^ b for a, b in zip(var, key))


def reverse_subbyte(var):
    var = bytes(inv_S[int.from_bytes(var,  "big")])
    return var


def reverse_shift_row(byte_array, length):
    # Right Shift

    new_array = bytearray(byte_array)
    for i in range(0, length):
        if(i == 0):
            new_array[0:1] = byte_array[length-1:length]
        elif(i == 1):
            new_array[1:2] = byte_array[0:1]
        else:
            new_array[i:i+1] = byte_array[i-1:i]

    return new_array


def reverse_mix_column(byte_array, length):

    return byte_array


def AES_decrypt(origin_array, key, length):

    byte_array = bytearray(origin_array)

    # Round 10 ~ 1
    for j in range(0, 10):
        if(j == 0):
            for i in range(0, length):
                byte_array[i:i +
                           1] = xorbyte(bytes(byte_array[i:i+1]), bytes(key[i:i+1]))
                byte_array[i:i+1] = reverse_subbyte(byte_array[i:i+1])
            byte_array = reverse_shift_row(byte_array, length)
        else:
            byte_array = reverse_mix_column(byte_array, length)
            for i in range(0, length):
                byte_array[i:i +
                           1] = xorbyte(bytes(byte_array[i:i+1]), bytes(key[i:i+1]))
                byte_array[i:i+1] = reverse_subbyte(byte_array[i:i+1])
            byte_array = reverse_shift_row(byte_array, length)

    # Round 0
    for i in range(0, length):
        byte_array[i:i +
                   1] = xorbyte(bytes(byte_array[i:i+1]), bytes(key[i:i+1]))

    return byte_array


def read_packet_control_byte(origin_byte):
    control_byte = origin_byte[0:1]
    byte_array = bytearray(origin_byte[1:])
    return control_byte, byte_array


if __name__ == '__main__':

    key = bytearray()
    h_key = bytearray()
    byte_array = bytearray()
    Decrypted_array = bytearray()
    hmac_array = bytearray()
    recv_size = 0
    file_size = 0
    file_name = ''

    for i in range(0, 16):
        h_key.append(1)

    key_count = 0
    for i in range(0, 16):
        key.append(key_count)
        key_count += 1

    receiver = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    receiver.bind((Local_ip, Local_port))
    receiver.listen(5)

    print("Wait...")
    conn, addr = receiver.accept()
    start_time = time.time()

    # Receive file information

    info_packet = conn.recv(100)
    control_byte, info_packet = read_packet_control_byte(info_packet)
    file_size = int(float(info_packet.decode("utf-8").split("\n")[0]))
    file_name = info_packet.decode("utf-8").split("\n")[1]

    file_name = "test1.mp4"
    f = open(file_name, "wb")

    # Receive file data
    while not recv_size == file_size:
        if file_size - recv_size > 256:
            # 256 + 32 + 1
            data = conn.recv(289)
            recv_size += 256
            control_byte = data[0:1]
            byte_array += bytearray(data[1:257])
            hmac_array += bytearray(data[257:289])
            print(hmac_array)
            sig = hmac.new(h_key, byte_array, hashlib.sha256).digest()
            if(sig != hmac_array):
                print("MAC ERROR")
                break
            else:
                array_offset = 0
                for i in range(0, 16):
                    Decrypted_array += AES_decrypt(
                        byte_array[array_offset:array_offset+16], key, 16)
                    array_offset += 16
                byte_array.clear()
                hmac_array.clear()

        else:
            data = conn.recv(file_size - recv_size + 32 + 1)
            remain_size = file_size - recv_size
            recv_size += file_size - recv_size
            control_byte = data[0:1]
            byte_array += bytearray(data[1:remain_size + 1])
            hmac_array += bytearray(data[remain_size + 1:remain_size + 1 + 32])
            sig = hmac.new(h_key, byte_array, hashlib.sha256).digest()
            if(sig != hmac_array):
                print("MAC ERROR")
                break
            else:
                array_offset = 0
                while(1):
                    if(remain_size < 16):
                        Decrypted_array += AES_decrypt(
                            byte_array[array_offset:array_offset+remain_size], key, remain_size)
                        break
                    else:
                        Decrypted_array += AES_decrypt(
                            byte_array[array_offset:array_offset+16], key, 16)
                        array_offset += 16
                        remain_size -= 16
                byte_array.clear()
                hmac_array.clear()

    # Write data to file
    f.write(Decrypted_array)
    conn.close()

    print("Completed receiving")
    print("Filename: ", file_name)
    print("Filesize: ", os.stat(file_name)[stat.ST_SIZE])
    print("File from " + str(addr))
    print("Consecution time: %s second" % (time.time() - start_time))

    f.close()
    receiver.close()
