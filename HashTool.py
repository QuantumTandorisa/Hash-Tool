# -*- coding: utf-8 -*-
'''
    __  __           __    ______            __
   / / / /___ ______/ /_  /_  __/___  ____  / /
  / /_/ / __ `/ ___/ __ \  / / / __ \/ __ \/ / 
 / __  / /_/ (__  ) / / / / / / /_/ / /_/ / /  
/_/ /_/\__,_/____/_/ /_/ /_/  \____/\____/_/   
                                                   
'''
#######################################################
#    HashTool.py
#
# HashTool is an advanced application designed to 
# provide additional security to your files by encrypting
# and splitting their contents using the AES-GCM 
# algorithm. This tool offers robust encryption features 
# and a splitting process that requires both encrypted 
# parts and a secret password for the recovery of the 
# original file.
#
# 02/03/24 - Changed to Python3 (finally)
#
# Author: Facundo Fernandez 
#
#
#######################################################

import sys
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        length=32,
        salt=salt,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_and_split(file_path, password):
    try:
        if not os.path.exists(file_path):
            print("El archivo no existe en la ruta proporcionada.")
            return

        # Read file contents / Leer el contenido del archivo
        with open(file_path, 'rb') as file:
            file_content = file.read()

        # Deriving the encryption key from the password and a random salt / Derivar la clave de cifrado a partir de la contraseña y una sal aleatoria
        salt = os.urandom(16)
        key = derive_key(password, salt)

        # Generate a random IV / Generar un IV aleatorio
        iv = os.urandom(12)  # GCM usualmente usa un IV de 12 bytes

        # Encrypt and authenticate file contents using AES-GCM / Cifrar y autenticar el contenido del archivo utilizando AES-GCM
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_content = encryptor.update(file_content) + encryptor.finalize()
        tag = encryptor.tag

        # Save encrypted content in two separate files / Guardar el contenido cifrado en dos archivos separados
        half = len(encrypted_content) // 2
        with open(file_path + ".part1", 'wb') as part1_file:
            part1_file.write(salt + iv + tag + encrypted_content[:half])

        with open(file_path + ".part2", 'wb') as part2_file:
            part2_file.write(salt + iv + tag + encrypted_content[half:])

        # Delete the original file / Eliminar el archivo original
        os.remove(file_path)

        print("El archivo se ha cifrado, dividido y eliminado exitosamente.")
    except Exception as e:
        print("Error al procesar el archivo:", str(e))

def decrypt_and_recover(file_path, password):
    try:
        # Read both parts of the encrypted file / Leer las dos partes del archivo cifrado
        with open(file_path + ".part1", 'rb') as part1_file:
            part1_data = part1_file.read()

        with open(file_path + ".part2", 'rb') as part2_file:
            part2_data = part2_file.read()

        # Extract the salt, IV, authentication tag, and encrypted content / Extraer la sal, el IV, la etiqueta de autenticación y el contenido cifrado
        salt = part1_data[:16]
        iv = part1_data[16:28]
        tag = part1_data[28:44]
        encrypted_content = part1_data[44:] + part2_data[44:]

        # Deriving the encryption key from the password and salt / Derivar la clave de cifrado a partir de la contraseña y la sal
        key = derive_key(password, salt)

        # Verify and decrypt content using AES-GCM / Verificar y descifrar el contenido utilizando AES-GCM
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_content = decryptor.update(encrypted_content) + decryptor.finalize()

        # Save the retrieved content in a new file / Guardar el contenido recuperado en un nuevo archivo
        with open(file_path + ".recovered", 'wb') as recovered_file:
            recovered_file.write(decrypted_content)

        print("El archivo se ha recuperado exitosamente.")
    except Exception as e:
        print("Error al recuperar el archivo:", str(e))

def main():
    if len(sys.argv) != 4:
        print("Uso: python3 HashTool.py <archivo> <contraseña> <operación>")
        return

    file_path = sys.argv[1]
    password = sys.argv[2]
    operation = sys.argv[3]

    if operation == "encrypt_and_split":
        encrypt_and_split(file_path, password)
    elif operation == "decrypt_and_recover":
        decrypt_and_recover(file_path, password)
    else:
        print("Operación no válida. Use 'encrypt_and_split' o 'decrypt_and_recover'.")

if __name__ == "__main__":
    main()
