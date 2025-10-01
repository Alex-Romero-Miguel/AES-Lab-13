# código ejecutable (main)

'''
Al ser invocado desde la línea de comandos:

python test_Lab_13.py -c -f file -p 0x11d -k 0xe9e03576ec312b3698c3b6f37d49d770
cifra el fichero file usando el polinomio 0x11d y la clave
0xe9e03576ec312b3698c3b6f37d49d770 (en este caso sería una clave de 128 bits)

python test_Lab_13.py -d -f file -p 0x11d -k 0xe9e03576ec312b3698c3b6f37d49d770
descifra el fichero file usando el polinomio 0x11d y la clave
0xe9e03576ec312b3698c3b6f37d49d770
'''

import sys
import os

import aes_Lab_13

def es_hexadecimal(s):
    try:
        if not s.startswith("0x"):
            return False
        int(s, 16)  # intenta convertir a entero base 16
        return True
    except ValueError:
        return False

def main():
    if len(sys.argv) != 8:
        print("Uso: python test_Lab_13.py [-c | -d] -f <fichero> -p <polinomio> -k <clave>")
        sys.exit(1)
    
    args = sys.argv[1:]
    accion = args[0]
    fichero = args[2]
    polinomio = args[4]
    clave = args[6]
    
    if not os.path.exists(fichero):
        print(f"[ERROR] El fichero '{fichero}' no existe.")
    elif not os.access(fichero, os.R_OK):
        print(f"[ERROR] El fichero '{fichero}' no se puede leer (permisos insuficientes).")
    else:
        print(f"[OK] El fichero '{fichero}' está accesible.")

    if es_hexadecimal(polinomio):
        print(f"[OK] El polinomio '{polinomio}' tiene un formato correcto.")
    else:
        print(f"[ERROR] El polinomio '{polinomio}' no tiene un formato hexadecimal (0x123).")
    
    if es_hexadecimal(clave):
        print(f"[OK] La clave '{clave}' tiene un formato correcto.")
    else:
        print(f"[ERROR] La clave '{clave}' no tiene un formato hexadecimal (0x01234567890abcdef01234567890abcd).")

    if accion == "-c":
        print(f"[INFO] Cifrando '{fichero}' con polinomio {polinomio} y clave {clave}")
        aes_Lab_13.AES(clave, polinomio).encrypt_file(fichero)
    elif accion == "-d":
        print(f"[INFO] Descifrando '{fichero}' con polinomio {polinomio} y clave {clave}")
        aes_Lab_13.AES(clave, polinomio).decrypt_file(fichero)
    else:
        print("Uso: python test_Lab_13.py [-c | -d] -f <fichero> -p <polinomio> -k <clave>")
        sys.exit(1)


if __name__ == "__main__":
    main()