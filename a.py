import sys
import os
import binascii
from Crypto.Cipher import AES
import hashlib
import struct
import logging

# Configuration
logging.basicConfig(level=logging.DEBUG)

# Helper Functions
def hex_dump(data, sep=':'):
    return sep.join([f'{b:02x}' for b in data])

def hash_MD5(input_data):
    return hashlib.md5(input_data).digest()

def aesDecrypt(tmpArr, xArr):
    cipher = AES.new(tmpArr, AES.MODE_ECB)
    return cipher.decrypt(xArr)

def decrypt_buffer(input_data, tmpArr):
    num_blocks = len(input_data) // 16
    output_data = b''
    cipher = AES.new(tmpArr, AES.MODE_ECB)

    for i in range(num_blocks):
        block = input_data[i * 16:(i + 1) * 16]
        decrypted_block = cipher.decrypt(block)
        output_data += decrypted_block

    return output_data

class XignLog:
    def __init__(self):
        self.sign_header = 0
        self.sign_type = 0
        self.unk_buffer = bytearray(16)
        self.key = bytearray(12)
        self.after_key = bytearray(4)
        self.hash = bytearray(4)
        self.after_hash0 = 0
        self.after_hash1 = 0
        self.after_hash2 = 0
        self.v_const = 0
        self.fff = bytearray(16)
        self.second_buffer = bytearray(240)
        self.sign_tail = 0
        self.junk = 0
        self.log_count = 0

def main():
    print("Xigncode Log Unpacker\nmade with python by hendyanwilly\n")
    console = logging.getLogger('console')

    if len(sys.argv) < 3:
        print("Usage: {} input_file output_file".format(sys.argv[0]))
        return 1

    input_file_path = sys.argv[1]
    output_file_path = sys.argv[2]

    if not os.path.exists(input_file_path):
        console.error("Input file does not exist: {}".format(input_file_path))
        return 1

    print(f"Unpacking {input_file_path}...")

    arrXign = []

    with open(input_file_path, 'rb') as file:
        while True:
            data = file.read(320)
            if not data:
                break

            tmp_log = XignLog()
            tmp_log_bytes = struct.unpack('I I 16s 12s 4s 4B B B H I 16s 240s I I I', data)

            (tmp_log.sign_header,
             tmp_log.sign_type,
             tmp_log.unk_buffer,
             tmp_log.key,
             tmp_log.after_key,
             tmp_log.hash[0],
             tmp_log.hash[1],
             tmp_log.hash[2],
             tmp_log.hash[3],
             tmp_log.after_hash0,
             tmp_log.after_hash1,
             tmp_log.after_hash2,
             tmp_log.v_const,
             tmp_log.fff,
             tmp_log.second_buffer,
             tmp_log.sign_tail,
             tmp_log.junk,
             tmp_log.log_count) = tmp_log_bytes

            arrXign.append(tmp_log)

    print(f"Writing to {output_file_path}...")

    with open(output_file_path, 'wb') as output_file:
        for tmp_log in arrXign:
            hash_vector = bytes(tmp_log.hash)
            tmpArr = hash_MD5(hash_vector)
            decrypted_buffer = aesDecrypt(tmpArr, tmp_log.second_buffer)
            #console.info("Output buffer: {}".format(hex_dump(decrypted_buffer)))
            output_file.write(decrypted_buffer)

    print("Finished!")

if __name__ == '__main__':
    sys.exit(main())