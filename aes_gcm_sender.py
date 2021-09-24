import socket
import os
import stat
import time
import sys
import tkinter as tk
import bitarray



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

R = bytearray()


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


def AES_encrypt(byte_array, key, length):

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

    return byte_array


def GCM_rightshift(byte_array, length):

    bin_array = BitArray(bytearray(byte_array))
    new_array = BitArray(bytearray(byte_array))
    new_length = length * 8

    for i in range(0, new_length):
        if(i == 0):
            new_array.bin[0:1] = bin_array[new_length-1:new_length]
        elif(i == 1):
            new_array.bin[1:2] = bin_array[0:1]
        else:
            new_array.bin[i:i+1] = bin_array[i-1:i]

    return bytearray(new_array)


def GF_mult(X, Y):


    Z = bytearray()
    for i in range(0, 16):
        Z.append(0)

    V = X

    for i in range(0, 16):
        byte = BitArray(Y[i:i+1])
        for j in range(0, 8):
            if(byte.bin[j:j+1] == b'1'):
                for k in range(0, 16):
                    Z[k:k+1] = xorbyte(bytes(Z[k:k+1]), bytes(V[k:k+1]))

            V_byte = BitArray(V[15:16])
            if(V_byte.bin[7:8] == b'0'):
                V = GCM_rightshift(V, 16)
            else:
                V = GCM_rightshift(V, 16)
                for k in range(0, 16):
                    V[k:k+1] = xorbyte(bytes(V[k:k+1]), bytes(R[k:k+1]))

    return Z


def AES_GCM_encrypt(byte_array, key, vector, length):

    # Generate H
    H = AES_encrypt(vector, key, 16)

    # Counter++
    count = int.from_bytes(vector[15:16], 'big')
    count += 1
    vector[15:16] = bytes([count])


def getInfo(ip,port,name):
    global Dest_ip, Dest_port, file_name
    
    Dest_ip= ipEntry.get()
    Dest_port = int(portEntry.get())
    file_name = nameE.get()
    window.quit()


# Main funtion

Max_pack_size = 256
Dest_ip = 'localhost'
Dest_port = 12345
file_name = "test.mp4"

if __name__ == '__main__':

    #export DISPLAY=localhost:0.0
    window = tk.Tk()
    window.title('Project')
    window.geometry('800x600')
    
    titleLabel = tk.Label(window, text='File tranfer')
    titleLabel.pack()

    ipFrame = tk.Frame(window)
    ipFrame.pack(side=tk.TOP)
    ipLabel = tk.Label(ipFrame, text='Destination IP')
    ipLabel.pack(side=tk.LEFT)
    ipEntry = tk.Entry(ipFrame)
    ipEntry.pack(side=tk.LEFT)

    portFrame = tk.Frame(window)
    portFrame.pack(side=tk.TOP)
    portLabel = tk.Label(portFrame, text='Destination Port')
    portLabel.pack(side=tk.LEFT)
    portEntry = tk.Entry(portFrame)
    portEntry.pack(side=tk.LEFT)

    nameFrame = tk.Frame(window)
    nameFrame.pack()
    nameL = tk.Label(nameFrame, text="File name")
    nameL.pack(side=tk.LEFT)
    nameE = tk.Entry(nameFrame)
    nameE.pack(side=tk.LEFT)

    confirmBtn = tk.Button(window, text='OK', command=lambda: getInfo(Dest_ip,Dest_port, file_name))
    confirmBtn.pack()
    
    
    window.mainloop()

    print(Dest_ip,Dest_port,file_name)

    vector = bytearray()
    key = bytearray()
    byte_array = bytearray()

    key_count = 0
    for i in range(0, 16):
        key.append(key_count)
        key_count += 1

    for i in range(0, 16):
        if(i < 15):
            vector.append(255)
        else:
            vector.append(0)

    R += b'\xe1'
    for i in range(0, 15):
        R.append(0)

    List = []
    f = open(file_name, "rb")

    Pack_Size = 0
    send_size = 0

    encrypted_array = bytearray()
    ch = bytearray()
    file_size = os.stat(file_name)[stat.ST_SIZE]
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print('File name : ',file_name)
    print(file_size, ' bytes')

    # Send file size
    sender.sendto(bytearray(bytes(str(file_size),'utf-8')), (Dest_ip, Dest_port))
    # Read file in binary
    count = 0
    for i in range(0, file_size):
        ch = f.read(1)
        List.append(ch)

     # Sender send file data
    for i in range(0, file_size):
        Pack_Size = Pack_Size + 1
        byte_array += List[i]
        if(Pack_Size == Max_pack_size or i == file_size - 1):
            if(Pack_Size == Max_pack_size):
                array_offset = 0
                for j in range(0, 16):
                    encrypted_array += bytearray(AES_encrypt(
                        byte_array[array_offset:array_offset+16], key, 16))
                    array_offset += 16

                send_size += 256
            elif(i == file_size - 1):
                remain_size = file_size - send_size
                array_offset = 0
                while(1):
                    if(remain_size < 16):
                        encrypted_array += bytearray(AES_encrypt(
                            byte_array[array_offset:array_offset+remain_size], key, remain_size))

                        send_size += remain_size
                        break

                    else:
                        encrypted_array += bytearray(AES_encrypt(
                            byte_array[array_offset:array_offset+16], key, remain_size))
                        send_size += 16
                        array_offset += 16
                        remain_size -= 16

            sender.sendto(encrypted_array, (Dest_ip, Dest_port))
            time.sleep(1/1000000.0)
            Pack_Size = 0
            byte_array.clear()
            encrypted_array.clear()

    print("Completed sending")
    f.close()
    sender.close()
