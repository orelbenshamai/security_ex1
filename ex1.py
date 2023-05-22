from Cryptodome.Cipher import DES
from Cryptodome.Util.Padding import pad, unpad
import sys


def oracle(ciphertext, key, iv):
    try:
        decrypt(ciphertext, key, iv)
        return True
    except ValueError:
        return False


def xor(a, b, c):
    result = a ^ b ^ c
    return result.to_bytes(1, 'big')


def pad_string(string_to_pad, padded_string_len):
    return pad(string_to_pad, padded_string_len)


def decrypt(ciphertext, key, iv):
    block_size = DES.block_size
    cipher_decrypt = DES.new(key, DES.MODE_CBC, iv)
    decrypted_padded_plaintext = cipher_decrypt.decrypt(ciphertext)
    decrypted_unpadded_plaintext = unpad(decrypted_padded_plaintext, block_size)
    return decrypted_unpadded_plaintext


def increment_ith_byte(i, block):
    byte_array = bytearray(block)
    byte_array[i] += 1
    return byte_array


def extract_plain_byte(pad_value, cipher_value, changed_value):
    return xor(pad_value, cipher_value, changed_value)


def extract_plain_block(c, key, iv, prev_block):
    plain_block = []
    results = [bytearray] * 8
    for i in range(8):
        while oracle(c, key, iv) is not True:
            c = increment_ith_byte(7-i, c)
        # extracted the ith byte from the plain text
        results[i] = extract_plain_byte(i+1, prev_block[7-i], c[7-i])
        plain_block.append(results[i])
        for j in range(i + 1):
            last_byte_to_modify = xor(i + 2, prev_block[7 - j], int.from_bytes(results[j], byteorder='big'))
            byte_array = bytearray(c)
            byte_array[7 - j] = int.from_bytes(last_byte_to_modify, byteorder='big')
            c = bytes(byte_array)
    plain_block.reverse()
    return plain_block


def extract_plain_text(cipher_text, key, iv):
    plain_text = []
    prev_block = iv
    for i in range(int(len(cipher_text) / 8)):
        c = iv + cipher_text[i*8:(i+1)*8]
        plain_text.extend(extract_plain_block(c, key, iv, prev_block))
        prev_block = cipher_text[i*8:(i+1)*8]
    return convert_to_text(plain_text)


def convert_to_text(plain_text):
    return [bytes_obj.decode() for bytes_obj in plain_text]


def main():
    if len(sys.argv) != 4:
        print("Please provide exactly three inputs")
    else:
        cipher_text = bytes.fromhex(sys.argv[1])
        key = bytes.fromhex(sys.argv[2])
        iv = bytes.fromhex(sys.argv[3])
        decrypted_bytes = extract_plain_text(cipher_text, key, iv)
        num_of_bytes_used_for_padding = ord(decrypted_bytes[-1])
        decrypted_text = decrypted_bytes[0:len(decrypted_bytes) - num_of_bytes_used_for_padding]
        print(''.join(decrypted_text))


if __name__ == '__main__':
    main()
