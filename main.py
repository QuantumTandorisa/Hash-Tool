import sys
from main import encrypt_and_split, decrypt_and_recover

def main():
    if len(sys.argv) != 4:
        print("Uso: python3 main.py <archivo> <contraseña> <operación>")
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
