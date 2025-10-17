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
import copy

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

        # Multiplicación en GF(2^8) sin tablas
        def gf_mult(a, b):
            res = 0
            while b:
                if b & 1:
                    res ^= a
                b >>= 1
                a = self.xTimes(a)
            return res & 0xFF

        # Construcción de tablas a partir del generador
        g = 0x02
        is_generator = False
        while (not is_generator):
            x = 1
            loop_early = False
            for i in range(255):
                self.Tabla_EXP[i] = x
                self.Tabla_LOG[x] = i
                x = gf_mult(x, g)
                if (x == 1) and i < 254:
                    loop_early = True
                    break
            if (loop_early):
                g += 1
            else:
                is_generator = True

        self.g = g
        #print("G_F.g =", self.g + "\n")

        # Duplicamos Tabla_EXP
        for i in range(255, 512):
            self.Tabla_EXP[i] = self.Tabla_EXP[i - 255]

        #print("G_F.Tabla_EXP", self.Tabla_EXP + "\n")
        #print("G_F.Tabla_LOG",self.Tabla_LOG + "\n")

    def xTimes(self, n):
        '''
        Entrada: un elemento del cuerpo representado por un entero entre 0 y
        255
        Salida: un elemento del cuerpo representado por un entero entre 0 y 255
        que es el producto en el cuerpo de 'n' y '0x02' (el polinomio 'x').
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
            s[r][c] = block[r * 4 + c]
    return s

def state_to_bytes(state):
    out = bytearray(16)
    for c in range(4):
        for r in range(4):
            out[r + 4 * c] = state[c][r] & 0xFF
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
        gf = self.G_F
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
        self.key = key

        self.Nk = len(self.key) // 4

        self.Nr = self.Nk + 6

        self.W = 4 * (self.Nr + 1)

        self.Polinomio_Irreducible = Polinomio_Irreducible

        self.G_F = G_F(self.Polinomio_Irreducible)

        self.SBox = [0] * 256
        self.InvSBox = [0] * 256
        for a in range(256):
            inv = self.G_F.inverso(a)
            s = inv
            s_aff = 0
            for i in range(8):
                # XOR de bits i, (i+4)%8, (i+5)%8, (i+6)%8, (i+7)%8
                bit = ((s >> i) & 1) ^ ((s >> ((i+4)%8)) & 1) ^ ((s >> ((i+5)%8)) & 1) \
                    ^ ((s >> ((i+6)%8)) & 1) ^ ((s >> ((i+7)%8)) & 1) ^ ((0x63 >> i) & 1)
                s_aff |= (bit << i)
            self.SBox[a] = s_aff
            self.InvSBox[s_aff] = a
        
        #print("AES.SBox =" + self.SBox + "\n")
        #print("AES.InvSBox =" + self.InvSBox + "\n")

        self.Rcon = []
        val = 0x01
        for i in range(15):
            self.Rcon.append([val & 0xFF, 0x00, 0x00, 0x00])
            val = self.G_F.xTimes(val)
        #print("AES.Rcon =" + self.Rcon + "\n")

        self.MixMatrix = [
            [0x02, 0x03, 0x01, 0x01],
            [0x01, 0x02, 0x03, 0x01],
            [0x01, 0x01, 0x02, 0x03],
            [0x03, 0x01, 0x01, 0x02]]

        M = copy.deepcopy(self.MixMatrix)

        I = [[int(r==c) for c in range(4)] for r in range(4)]
        gf = self.G_F

        for c in range(4):
            if M[c][c] == 0:
                for r in range(c+1,4):
                    if M[r][c] != 0:
                        M[c], M[r] = M[r], M[c]
                        I[c], I[r] = I[r], I[c]
                        break
            inv = gf.inverso(M[c][c])
            for j in range(4):
                M[c][j] = gf.producto(M[c][j], inv)
                I[c][j] = gf.producto(I[c][j], inv)
            for r in range(4):
                if r != c:
                    factor = M[r][c]
                    for j in range(4):
                        M[r][j] ^= gf.producto(factor, M[c][j])
                        I[r][j] ^= gf.producto(factor, I[c][j])

        self.InvMixMatrix = I

        #print("AES.MixMatrix =" + str(self.MixMatrix))
        #print("AES.InvMixMatrix =" + self.InvMixMatrix)

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
        M = self.MixMatrix.copy()
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
            col = [State[c][r] & 0xFF for r in range(4)]
            out = self._mat_mul_4x4(M, col)
            for r in range(4):
                State[c][r] = out[r]

    def AddRoundKey(self, State, roundKey):
        '''
        5.1.4 ADDROUNDKEY()
        FIPS 197: Advanced Encryption Standard (AES)
        '''
        for r in range(4):
            for c in range(4):
                State[c][r] ^= roundKey[r][c]

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
        w = [[0,0,0,0] for _ in range(self.W)]
        
        i = 0
        while i <= self.Nk -1:
            w[i] = [key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]]
            i += 1
        
        while i <= self.W - 1:
            tmp = w[i-1].copy()
            if i % self.Nk == 0:
                tmp_rot = self.RotWord(tmp)
                tmp_sub = self.SubWord(tmp_rot)
                rc_word = self.Rcon[i // self.Nk - 1]
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
        #print("Before AddRoundKey: AES.Expanded_KEY =" + str(Expanded_KEY) + "\n")
        self.AddRoundKey(State, Expanded_KEY[0:4])
        print("After AddRoundKey: AES.State =\n" + "\n".join([" ".join(f"0x{x:02x}" for x in row) for row in State]) + "\n")
        for round in range(1, Nr):
            self.SubBytes(State)
            print("After SubBytes: AES.State =\n" + "\n".join([" ".join(f"0x{x:02x}" for x in row) for row in State]) + "\n")
            self.ShiftRows(State)
            print("After ShiftRows: AES.State =\n" + "\n".join([" ".join(f"0x{x:02x}" for x in row) for row in State]) + "\n")
            self.MixColumns(State)
            print("After MixColumns: AES.State =\n" + "\n".join([" ".join(f"0x{x:02x}" for x in row) for row in State]) + "\n")
            self.AddRoundKey(State, Expanded_KEY[4*round:4*round+4])
            print("After AddRoundKey: AES.State =\n" + "\n".join([" ".join(f"0x{x:02x}" for x in row) for row in State]) + "\n")
        self.SubBytes(State)
        print("After SubBytes: AES.State =\n" + "\n".join([" ".join(f"0x{x:02x}" for x in row) for row in State]) + "\n")
        self.ShiftRows(State)
        print("After ShiftRows: AES.State =\n" + "\n".join([" ".join(f"0x{x:02x}" for x in row) for row in State]) + "\n")
        self.AddRoundKey(State, Expanded_KEY[4*Nr:4*Nr+4])
        print("After AddRoundKey: AES.State =\n" + "\n".join([" ".join(f"0x{x:02x}" for x in row) for row in State]) + "\n")
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
            print("Iteration " + f"{i}" +": AES.State =\n" + "\n".join([" ".join(f"0x{x:02x}" for x in row) for row in state]) + "\n")
            self.Cipher(state, self.Nr, expanded_key)
            enc = bytes(state_to_bytes(state))
            encrypted_blocks.append(enc)
            prev = enc

        encrypted_message = b"".join(encrypted_blocks)

        fichero_enc = os.path.splitext(fichero)[0] + ".enc"
        # fichero_enc = os.path.splitext(fichero) + '_' + hex(self.Polinomio_Irreducible) + "_0x" + self.key.hex() + ".enc"
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