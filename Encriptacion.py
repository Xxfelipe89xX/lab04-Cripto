import sys
from Crypto.Cipher import AES, DES, DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def adjust_input(data_bytes, expected_size):
    len_data = len(data_bytes)
    
    if len_data == expected_size:
        return data_bytes
    
    if len_data < expected_size:
        padding_needed = expected_size - len_data
        random_padding = get_random_bytes(padding_needed)
        return data_bytes + random_padding
    
    if len_data > expected_size:
        return data_bytes[:expected_size]

def cifrar_descifrar_demo(cipher_name, cipher_class, key_size, block_size):
    print(f"\n--- {cipher_name} ---")
    
    try:
        key_str = input(f"Ingrese Key para {cipher_name}: ")
        iv_str = input(f"Ingrese IV para {cipher_name}: ")
        plaintext_str = input("Ingrese el texto a cifrar: ")
        
        key_bytes = key_str.encode('utf-8')
        iv_bytes = iv_str.encode('utf-8')
        plaintext_bytes = plaintext_str.encode('utf-8')

        final_key = adjust_input(key_bytes, key_size)
        final_iv = adjust_input(iv_bytes, block_size)
        
        print(f"Key final (hex): {final_key.hex()}")


        cipher_encrypt = cipher_class.new(final_key, cipher_class.MODE_CBC, final_iv)
        padded_text = pad(plaintext_bytes, block_size)
        ciphertext = cipher_encrypt.encrypt(padded_text)
        print(f"Texto cifrado (hex): {ciphertext.hex()}")


        cipher_decrypt = cipher_class.new(final_key, cipher_class.MODE_CBC, final_iv)
        decrypted_padded_text = cipher_decrypt.decrypt(ciphertext)
        decrypted_text = unpad(decrypted_padded_text, block_size)
        
        print(f"Texto descifrado: {decrypted_text.decode('utf-8')}")

    except Exception as e:
        print(f"[ERROR]: {e}")

def main():
    cifrar_descifrar_demo("DES", DES, 8, 8)
    cifrar_descifrar_demo("3DES", DES3, 24, 8)
    cifrar_descifrar_demo("AES-256", AES, 32, 16)

if __name__ == "__main__":
    main()