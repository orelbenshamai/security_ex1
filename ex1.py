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
    decrypted_un_padded_plaintext = unpad(decrypted_padded_plaintext, block_size)
    return decrypted_un_padded_plaintext


def increment_ith_byte(i, block):
    byte_array = bytearray(block)
    byte_array[i] = (byte_array[i] + 1) % 256
    return byte_array


def extract_plain_byte(pad_value, cipher_value, changed_value):
    return xor(pad_value, cipher_value, changed_value)


def extract_plain_block(current_encrypted_block, previous_encrypted_block, brute_force_block, key, iv):
    results = [bytearray] * 8
    for i in range(8):
        c = brute_force_block + current_encrypted_block
        for k in range(256):
            if oracle(c, key, iv) is True:
                break
            brute_force_block = increment_ith_byte(7-i, brute_force_block)
            c = brute_force_block + current_encrypted_block
        # extract the ith byte from the plain text
        results[i] = extract_plain_byte(i+1, previous_encrypted_block[7-i], brute_force_block[7-i])
        # end of the attack, already found all the 8 bytes in the block
        if i == 7:
            break
        for j in range(i + 1):
            last_byte_to_modify = xor(i + 2, previous_encrypted_block[7 - j], int.from_bytes(results[j], byteorder='big'))
            byte_array = bytearray(brute_force_block)
            byte_array[7 - j] = int.from_bytes(last_byte_to_modify, byteorder='big')
            brute_force_block = bytes(byte_array)
    return results


def extract_plain_text(cipher_text, key, iv):
    plain_text = []
    block_num = (int(len(cipher_text) / 8))
    for i in range(block_num, 0, -1):
        current_encrypted_block = cipher_text[(i-1)*8:i*8]
        if i == 1:
            previous_encrypted_block = iv
        else:
            previous_encrypted_block = cipher_text[(i-2)*8:(i-1)*8]
        brute_force_block = b'\x00'*8
        plain_block = extract_plain_block(current_encrypted_block, previous_encrypted_block, brute_force_block, key, iv)
        plain_text.extend(plain_block)
    return convert_to_text(plain_text)


def convert_to_text(plain_text):
    return [bytes_obj.decode() for bytes_obj in plain_text]


def main():
    if len(sys.argv) != 4:
        print("Please provide exactly three inputs")
    else:
        cipher_text = bytes.fromhex(sys.argv[1])
        try:
            key = bytes.fromhex(sys.argv[2])
        except ValueError:
            key = sys.argv[2].encode()
        iv = bytes.fromhex(sys.argv[3])
        decrypted_bytes = extract_plain_text(cipher_text, key, iv)
        decrypted_bytes.reverse()
        num_of_bytes_used_for_padding = ord(decrypted_bytes[-1])
        decrypted_text = decrypted_bytes[0:len(decrypted_bytes) - num_of_bytes_used_for_padding]
        print(''.join(decrypted_text))


if __name__ == '__main__':
    main()
    
