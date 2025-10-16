# definición de clases

'''
Vuestra implementación debería ser compatible con openssl2 cuando usáis 0x11B
como polinomio:

el comando
openssl aes-128-cbc -d -K key -iv IV -in infile -out outfile
debería descifrarlo correctamente,

si cifráis un fichero con el comando
openssl aes-128-cbc -e -K key -iv IV -in infile -out outfile
deberíais poder descifrarlo con vuestra implementación.
'''

import os
from hashlib import sha256

class G_F:
    '''
    Genera un cuerpo finito usando como polinomio irreducible el dado
    representado como un entero. Por defecto toma el polinomio del AES.
    Los elementos del cuerpo los representaremos por enteros 0 <= n <= 255.
    '''

    def __init__(self, Polinomio_Irreducible=0x11B):
        '''
        Entrada: un entero que representa el polinomio para construir el cuerpo
        Tabla_EXP y Tabla_LOG dos tablas, la primera tal que en la posición
        i-ésima tenga valor a=g**i y la segunda tal que en la posición a-ésima
        tenga el valor i tal que a=g**i. (g generador del cuerpo finito
        representado por el menor entero entre 0 y 255.)
        '''

        self.Polinomio_Irreducible = Polinomio_Irreducible
        self.Tabla_EXP = [0] * 512 # para evitar módulo 255
        self.Tabla_LOG = [0] * 256
        self.g = 0x03

        # Multiplicación en GF(2^8) sin tablas
        def gf_mult(a, b):
            res = 0
            while b:
                if b & 1:
                    res ^= a
                b >>= 1
                a <<= 1
                if a & 0x100:
                    a ^= self.Polinomio_Irreducible
            return res & 0xFF

        # Construcción de tablas a partir del generador
        x = 1
        for i in range(255):
            self.Tabla_EXP[i] = x
            self.Tabla_LOG[x] = i
            x = gf_mult(x, self.g)

        # Duplicamos Tabla_EXP
        for i in range(255, 512):
            self.Tabla_EXP[i] = self.Tabla_EXP[i - 255]

    def xTimes(self, n):
        '''
        Entrada: un elemento del cuerpo representado por un entero entre 0 y
        255
        Salida: un elemento del cuerpo representado por un entero entre 0 y 255
        que es el producto en el cuerpo de 'n' y 0x02 (el polinomio x).
        '''
        res = n << 1
        if res & 0x100:
            res ^= self.Polinomio_Irreducible
        return res & 0xFF

    def producto(self, a, b):
        '''
        Entrada: dos elementos del cuerpo representados por enteros entre 0 y
        255
        Salida: un elemento del cuerpo representado por un entero entre 0 y 255
        que es el producto en el cuerpo de la entrada.
        Atención: Se valorará la eficiencia. No es lo mismo calcularlo usando
        la definición en términos de polinomios o calcular usando las tablas
        Tabla_EXP y Tabla_LOG.
        '''
        if a == 0 or b == 0:
            return 0
        return self.Tabla_EXP[self.Tabla_LOG[a] + self.Tabla_LOG[b]]

    def inverso(self, n):
        '''
        Entrada: un elementos del cuerpo representado por un entero entre 0 y
        255
        Salida: 0 si la entrada es 0, el inverso multiplicativo de n
        representado por un entero entre 1 y 255 si n <> 0.
        Atención: Se valorará la eficiencia.
        '''
        if n == 0:
            return 0
        return self.Tabla_EXP[255 - self.Tabla_LOG[n]]



def bytes_to_state(block):
    assert len(block) == 16
    s = [[0] * 4 for _ in range(4)]
    for c in range(4):
        for r in range(4):
            s[r][c] = block[r + 4 * c]
    return s

def state_to_bytes(state):
    out = bytearray(16)
    for c in range(4):
        for r in range(4):
            out[r + 4 * c] = state[r][c] & 0xFF
    return out



class AES:
    '''
    Documento de referencia:
    Federal Information Processing Standards Publication (FIPS) 197: Advanced
    Encryption Standard (AES) https://doi.org/10.6028/NIST.FIPS.197-upd1
    El nombre de los métodos, tablas, etc son los mismos (salvo
    capitalización) que los empleados en el FIPS 197
    '''
    def _mat_mul_4x4(self, M, v):
        '''
        Función auxiliar para multiplicar una matriz M 4x4 por un vector v 4x1 en GF(2^8).
        '''
        gf = self.gf
        r0 = gf.producto(v[0], M[0][0]) ^ gf.producto(v[1], M[0][1]) ^ gf.producto(v[2], M[0][2]) ^ gf.producto(v[3], M[0][3])
        r1 = gf.producto(v[0], M[1][0]) ^ gf.producto(v[1], M[1][1]) ^ gf.producto(v[2], M[1][2]) ^ gf.producto(v[3], M[1][3])
        r2 = gf.producto(v[0], M[2][0]) ^ gf.producto(v[1], M[2][1]) ^ gf.producto(v[2], M[2][2]) ^ gf.producto(v[3], M[2][3])
        r3 = gf.producto(v[0], M[3][0]) ^ gf.producto(v[1], M[3][1]) ^ gf.producto(v[2], M[3][2]) ^ gf.producto(v[3], M[3][3])
        return [r0 & 0xFF, r1 & 0xFF, r2 & 0xFF, r3 & 0xFF]

    def __init__(self, key, Polinomio_Irreducible=0x11B):
        '''
        Entrada:
        key: bytearray de 16 24 o 32 bytes
        Polinomio_Irreducible: Entero que representa el polinomio para
        construir el cuerpo
        SBox: equivalente a la tabla 4, pág. 14 (pág. 22 pdf)
        InvSBOX: equivalente a la tabla 6, pág. 23 (pág. 31 pdf)
        Rcon: equivalente a la tabla 5, pág. 17 (pág. 25 pdf)
        InvMixMatrix : equivalente a la matriz usada en 5.3.3, pág. 24 (pág. 32
        pdf)
        '''
        self.key = bytes.fromhex(key[2:])

        self.Nk = len(self.key) // 4

        self.Nr = self.Nk + 6

        self.Polinomio_Irreducible = int(Polinomio_Irreducible, 16)

        self.gf = G_F(self.Polinomio_Irreducible)
        
        self.SBox = [           # se puede generar algorítmicamente
            0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
            0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
            0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
            0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
            0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
            0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
            0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
            0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
            0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
            0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
            0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
            0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
            0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
            0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
            0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
            0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16]
        
        self.InvSBox = [       # se puede generar algorítmicamente
            0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
            0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
            0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
            0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
            0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
            0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
            0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
            0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
            0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
            0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
            0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
            0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
            0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
            0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
            0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
            0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d]
        
        self.Rcon = [           # se puede generar algorítmicamente
            [0x01,0x00,0x00,0x00],
            [0x02,0x00,0x00,0x00],
            [0x04,0x00,0x00,0x00],
            [0x08,0x00,0x00,0x00],
            [0x10,0x00,0x00,0x00],
            [0x20,0x00,0x00,0x00],
            [0x40,0x00,0x00,0x00],
            [0x80,0x00,0x00,0x00],
            [0x1b,0x00,0x00,0x00],
            [0x36,0x00,0x00,0x00],
            [0x6c,0x00,0x00,0x00],
            [0xd8,0x00,0x00,0x00],
            [0xab,0x00,0x00,0x00],
            [0x4d,0x00,0x00,0x00],
            [0x9a,0x00,0x00,0x00]]
        
        self.InvMixMatrix = [   # se puede generar algorítmicamente
            [0x0e,0x0b,0x0d,0x09],
            [0x09,0x0e,0x0b,0x0d],
            [0x0d,0x09,0x0e,0x0b],
            [0x0b,0x0d,0x09,0x0e]
        ]

    def SubBytes(self, State):
        '''
        5.1.1 SUBBYTES()
        FIPS 197: Advanced Encryption Standard (AES)
        '''
        S = self.SBox
        for row in range(4):
            for column in range(4):
                State[row][column] = S[State[row][column] & 0xFF]

    def InvSubBytes(self, State):
        '''
        5.3.2 INVSUBBYTES()
        FIPS 197: Advanced Encryption Standard (AES)
        '''
        I = self.InvSBox
        for row in range(4):
            for column in range(4):
                State[row][column] = I[State[row][column] & 0xFF]

    def ShiftRows(self, State):
        '''
        5.1.2 SHIFTROWS()
        FIPS 197: Advanced Encryption Standard (AES)
        '''
        State[1] = State[1][1:] + State[1][:1]
        State[2] = State[2][2:] + State[2][:2]
        State[3] = State[3][3:] + State[3][:3]

    def InvShiftRows(self, State):
        '''
        5.3.1 INVSHIFTROWS()
        FIPS 197: Advanced Encryption Standard (AES)
        '''
        State[1] = State[1][-1:] + State[1][:-1]
        State[2] = State[2][-2:] + State[2][:-2]
        State[3] = State[3][-3:] + State[3][:-3]

    def MixColumns(self, State):
        '''
        5.1.3 MIXCOLUMNS()
        FIPS 197: Advanced Encryption Standard (AES)
        '''
        M = [
            [0x02, 0x03, 0x01, 0x01],
            [0x01, 0x02, 0x03, 0x01],
            [0x01, 0x01, 0x02, 0x03],
            [0x03, 0x01, 0x01, 0x02],
        ]
        for c in range(4):
            col = [State[r][c] & 0xFF for r in range(4)]
            out = self._mat_mul_4x4(M, col)
            for r in range(4):
                State[r][c] = out[r]

    def InvMixColumns(self, State):
        '''
        5.3.3 INVMIXCOLUMNS()
        FIPS 197: Advanced Encryption Standard (AES)
        '''
        M = self.InvMixMatrix
        for c in range(4):
            col = [State[r][c] & 0xFF for r in range(4)]
            out = self._mat_mul_4x4(M, col)
            for r in range(4):
                State[r][c] = out[r]

    def AddRoundKey(self, State, roundKey):
        '''
        5.1.4 ADDROUNDKEY()
        FIPS 197: Advanced Encryption Standard (AES)
        '''
        for r in range(4):
            for c in range(4):
                State[r][c] ^= roundKey[r][c]

    def RotWord(self, word):
        '''
        Función ROTWORD() de la pág. 17 (pág. 25 pdf)
        FIPS 197: Advanced Encryption Standard (AES)
        '''
        return word[1:] + word[:1]

    def SubWord(self, word):
        '''
        Función SUBWORD() de la pág. 17 (pág. 25 pdf)
        FIPS 197: Advanced Encryption Standard (AES)
        '''
        return [self.SBox[b & 0xFF] for b in word]
    
    def KeyExpansion(self, key):
        '''
        5.2 KEYEXPANSION()
        FIPS 197: Advanced Encryption Standard (AES)
        '''
        w = [[0,0,0,0] for _ in range(4 * (self.Nr + 1))]
        
        i = 0
        while i <= self.Nk -1:
            w[i] = [key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]]
            i += 1
        
        while i <= 4 * self.Nr + 3:
            tmp = w[i-1]
            if i % self.Nk == 0:
                tmp_rot = self.RotWord(tmp)
                tmp_sub = self.SubWord(tmp_rot)
                rc_word = self.Rcon[i // self.Nk]
                tmp = [tmp_sub[j] ^ rc_word[j] for j in range(4)]
            elif (self.Nk > 6) and (i % self.Nk == 4):
                tmp = self.SubWord(tmp)
            w[i] = [(w[i - self.Nk][j] ^ tmp[j]) & 0xFF for j in range(4)]
            i += 1
        return w
        
    def Cipher(self, State, Nr, Expanded_KEY):
        '''
        5.1 Cipher(), Algorithm 1 pág. 12
        FIPS 197: Advanced Encryption Standard (AES)
        '''
        self.AddRoundKey(State, Expanded_KEY[0:4])
        for round in range(1, Nr):
            self.SubBytes(State)
            self.ShiftRows(State)
            self.MixColumns(State)
            self.AddRoundKey(State, Expanded_KEY[4*round:4*round+4])
        self.SubBytes(State)
        self.ShiftRows(State)
        self.AddRoundKey(State, Expanded_KEY[4*Nr:4*Nr+4])
        return State

    def InvCipher(self, State, Nr, Expanded_KEY):
        '''
        5. InvCipher()
        Algorithm 3 pág. 20 o Algorithm 4 pág. 25. Son equivalentes
        FIPS 197: Advanced Encryption Standard (AES)
        '''
        self.AddRoundKey(State, Expanded_KEY[4*Nr:4*Nr+4])
        for round in range(Nr-1, 0, -1):
            self.InvShiftRows(State)
            self.InvSubBytes(State)
            self.AddRoundKey(State, Expanded_KEY[4*round:4*round+4])
            self.InvMixColumns(State)
        self.InvShiftRows(State)
        self.InvSubBytes(State)
        self.AddRoundKey(State, Expanded_KEY[0:4])
        return State

    def encrypt_file(self, fichero):
        '''
        Entrada: Nombre del fichero a cifrar
        Salida: Fichero cifrado usando la clave utilizada en el constructor de
        la clase. Para cifrar se usará el modo CBC, con IV correspondiente a
        los 16 primeros bytes obtenidos al aplicar el sha256 a la concatenación
        de "IV" y la clave usada para cifrar. Por ejemplo:
        Key 0x0aba289662caa5caaa0d073bd0b575f4
        IV asociado 0xeb53bf26511a8c0b67657ccfec7a25ee
        Key 0x46abd80bdcf88518b2bec4b7f9dee187b8c90450696d2b995f26cdf2fe058610
        IV asociado 0x4fe68dfd67d8d269db4ad2ebac646986

        El padding usado será PKCS7.
        El nombre de fichero cifrado será el obtenido al añadir el sufijo
        .enc al nombre del fichero a cifrar:
        NombreFichero --> NombreFichero.enc
        '''
        expanded_key = self.KeyExpansion(self.key)
        
        iv = sha256(b"IV" + self.key).digest()[:16]

        with open(fichero, "rb") as f:
            message = f.read()
        
        pad_len = 16 - (len(message) % 16)
        message = message + bytes([pad_len] * pad_len)

        prev = iv
        encrypted_blocks = []
        for i in range(0, len(message), 16):
            block = bytearray(message[i:i+16])

            for j in range(16):
                block[j] ^= prev[j]
            
            state = bytes_to_state(bytes(block))
            self.Cipher(state, self.Nr, expanded_key)
            enc = bytes(state_to_bytes(state))
            encrypted_blocks.append(enc)
            prev = enc

        encrypted_message = b"".join(encrypted_blocks)
        fichero_enc = os.path.splitext(fichero)[0] + ".enc"
        try:
            with open(fichero_enc, "wb") as f:
                f.write(encrypted_message)
            print(f"[OK] Archivo generado: {fichero_enc}")
            return fichero_enc
        except Exception as e:
            print(f"[ERROR] No se pudo crear el archivo: {e}")
            return None

    def decrypt_file(self, fichero):
        '''
        Entrada: Nombre del fichero a descifrar
        Salida: Fichero descifrado usando la clave utilizada en el constructor
        de la clase.

        Para descifrar se usar ́a el modo CBC, con el IV usado para cifrar.
        El nombre de fichero descifrado ser ́a el obtenido al añadir el sufijo
        .dec al nombre del fichero a descifrar:
        NombreFichero --> NombreFichero.dec
        '''
        expanded_key = self.KeyExpansion(self.key)

        iv = sha256(b"IV" + self.key).digest()[:16]

        with open(fichero, "rb") as f:
            message = f.read()

        if len(message) == 0 or len(message) % 16 != 0:
            raise ValueError("Padding PKCS#7 inválido (longitud).")

        prev = iv
        decrypted_blocks = []

        for i in range(0, len(message), 16):
            block = bytearray(message[i:i+16])
            
            state = bytes_to_state(bytes(block))
            self.InvCipher(state, self.Nr, expanded_key)
            dec = state_to_bytes(state)

            for j in range(16):
                dec[j] ^= prev[j]
            
            dec = bytes(dec)
            decrypted_blocks.append(dec)
            prev = block

        decrypted_message = b"".join(decrypted_blocks)
        
        pad_len = decrypted_message[-1]

        if pad_len < 1 or pad_len > 16:
            raise ValueError("Padding PKCS#7 inválido (rango de valores).")
        if decrypted_message[-pad_len:] != bytes([pad_len] * pad_len):
            raise ValueError("Padding PKCS#7 inválido (patrón).")
        
        decrypted_message = decrypted_message[:-pad_len]

        fichero_dec = os.path.splitext(fichero)[0] + ".dec"
        try:
            with open(fichero_dec, "wb") as f:
                f.write(decrypted_message)
            print(f"[OK] Archivo generado: {fichero_dec}")
            return fichero_dec
        except Exception as e:
            print(f"[ERROR] No se pudo crear el archivo: {e}")
            return None