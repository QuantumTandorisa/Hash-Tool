HashTool es una aplicación avanzada diseñada para proporcionar seguridad adicional a tus archivos al cifrar y dividir su contenido utilizando el algoritmo AES-GCM. Esta herramienta ofrece funciones de cifrado robustas y un proceso de división que requiere ambas partes cifradas y una contraseña secreta para la recuperación del archivo original.

## Características Principales

- Cifrado AES-GCM: Utiliza el algoritmo de cifrado AES-GCM para garantizar confidencialidad y autenticación del contenido del archivo.
- División de Hash: Divide el hash cifrado en dos partes, proporcionando una capa adicional de seguridad para la recuperación del archivo.
- Derivación de Clave: Deriva la clave de cifrado utilizando PBKDF2, mejorando la resistencia a ataques de fuerza bruta.
- Manejo de Errores: Implementa un manejo robusto de errores para garantizar la integridad y recuperabilidad del archivo.


## Requisitos

Antes de utilizar esta herramienta, asegúrate de tener instalados los siguientes requisitos.

- Python 3.x
- Bibliotecas adicionales, que puedes instalar ejecutando `pip install -r requirements.txt`.

## Uso

- Clona este repositorio en tu sistema.
- Cifra el contenido del archivo, divide el hash cifrado y elimina el archivo original.
  ```python
    python3 HashTool.py "/Home/user/Documents/file.txt" "password" encrypt_and_split
    ```
- Recupera el archivo original utilizando las dos partes del hash cifrado y la contraseña secreta.
  ```python
    python3 HashTool.py "/Home/user/Documents/file.txt" "password" decrypt_and_recover
    ```
  
## Configuración

Es importante señalar que el diseño y la implementación de esta herramienta se han abordado desde una perspectiva ética y con el propósito de proporcionar seguridad y privacidad legítimas. Sin embargo, la responsabilidad de su uso recae en el usuario final.

Almacenar de forma segura la contraseña es crucial para garantizar la recuperación exitosa del archivo. Considera utilizar servicios de gestión de contraseñas.
