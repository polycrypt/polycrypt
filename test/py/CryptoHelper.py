import struct
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Cipher.AES import AESCipher
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA, SHA256, HMAC
from Crypto.Signature import PKCS1_v1_5 as PKCS1_v1_5_sig
from Crypto.Cipher import PKCS1_v1_5 as PKCS1_v1_5_cipher
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.strxor import strxor

class CryptoHelper:
    @staticmethod
    def random(n):
        return Random.get_random_bytes(n)

    @staticmethod
    def sign_pkcs1_sha256(n, e, d, content):
        key = RSA.construct( (n, e, d) )
        h = SHA256.new(content)
        signer = PKCS1_v1_5_sig.new(key)
        return signer.sign(h)

    @staticmethod
    def verify_pkcs1_sha256(n, e, content, sig):
        key = RSA.construct( (n, e) )
        h = SHA256.new(content)
        verifier = PKCS1_v1_5_sig.new(key)
        return verifier.verify(h, sig)
    
    @staticmethod
    def sign_pkcs1_sha1(n, e, d, content):
        key = RSA.construct( (n, e, d) )
        h = SHA.new(content)
        signer = PKCS1_v1_5_sig.new(key)
        return signer.sign(h)

    @staticmethod
    def verify_pkcs1_sha1(n, e, content, sig):
        key = RSA.construct( (n, e) )
        h = SHA.new(content)
        verifier = PKCS1_v1_5_sig.new(key)
        return verifier.verify(h, sig)

    @staticmethod
    def aes_key_wrap(key, p):
        assert( len(p) % 8 == 0 )
        
        n = len(p)/8
        r = range(n+1)
        r[0] = b'\0\0\0\0\0\0\0\0'
        for i in range(1,n+1):
            r[i] = p[(i-1)*8:i*8]
        a = b'\xA6\xA6\xA6\xA6\xA6\xA6\xA6\xA6'
    
        aes = AESCipher(key)
        for j in range(0,6):
            for i in range(1,n+1):
                t = struct.pack("!q", (n*j)+i)
                b = aes.encrypt(a+r[i])     # B = AES(K, A | R[i])
                a = strxor(b[:8], t)        # A = MSB(64, B) ^ t where t = (n*j)+i
                r[i] = b[8:]                # R[i] = LSB(64, B)
    
        r[0] = a
        return "".join(r)

    @staticmethod
    def aes_key_unwrap(key, c):
        assert( len(c) % 8 == 0 )
        
        n = len(c)/8 - 1
        r = range(n+1)
        r[0] = b'\0\0\0\0\0\0\0\0'
        for i in range(1,n+1):
            r[i] = c[i*8:(i+1)*8]
        a = c[:8]
    
        aes = AESCipher(key)
        for j in range(5,-1,-1):
            for i in range(n,0,-1):
                t = struct.pack("!q", (n*j)+i)
                a = strxor(a, t)
                b = aes.decrypt(a+r[i])     # B = AES-1(K, (A ^ t) | R[i]) where t = n*j+i
                a = b[:8]                   # A = MSB(64, B)
                r[i] = b[8:]                # R[i] = LSB(64, B)
    
        if (a == b'\xA6\xA6\xA6\xA6\xA6\xA6\xA6\xA6'):
            return "".join(r[1:])
        else:
            raise "Key unwrap integrity check failed"

    @staticmethod
    def rsa_oaep_key_wrap(n, e, p):
        key = RSA.construct( (n, e) )
        cipher = PKCS1_OAEP.new(key)
        return cipher.encrypt(p)

    @staticmethod
    def rsa_oaep_key_unwrap(n, e, d, c):
        key = RSA.construct( (n, e, d) )
        cipher = PKCS1_OAEP.new(key)
        return cipher.decrypt(c)
    
    @staticmethod
    def rsa_pkcs1_key_wrap(n, e, p):
        key = RSA.construct( (n, e) )
        cipher = PKCS1_v1_5_cipher.new(key)
        return cipher.encrypt(p)
    
    @staticmethod
    def rsa_pkcs1_key_unwrap(n, e, d, c):
        key = RSA.construct( (n, e, d) )
        cipher = PKCS1_v1_5_cipher.new(key)
        sentinel = 42
        dec = cipher.decrypt(c, sentinel)
        if dec == sentinel:
            raise "Key unwrap failed"
        else:
            return dec
    
    @staticmethod
    def sha256(content):
        h = SHA256.new()
        h.update(content)
        return h.digest()

    @staticmethod
    def hmac_sha256(key, content):
        hmac = HMAC.new(key, digestmod=SHA256)
        hmac.update(content)
        return hmac.digest()

    @staticmethod
    def encrypt_gen_aead_AES128CBC_HMACSHA256(key, n, iv, content):
        # Split the key into encryption and authentication halves
        assert( len(key) == 16 + SHA256.digest_size )
        ke = key[-16:]
        ka = key[:-16]

        # Pad the content
        x = AES.block_size - (len(content) % AES.block_size)
        if x == 0:
            x = AES.block_size
        econtent = content + (struct.pack("B",x) * x)

        # Compute the encrypted body
        assert( len(iv) == AES.block_size )
        cipher = AES.new(ke, AES.MODE_CBC, iv)
        S = cipher.encrypt(econtent)

        # Compute the authentication value
        hmac = HMAC.new(ka, digestmod=SHA256)
        ln = struct.pack("!q", len(n))
        la = struct.pack("!q", 0)
        hmac.update(n + S + ln + la)
        T = hmac.digest()

        return S + T

    @staticmethod
    def decrypt_gen_aead_AES128CBC_HMACSHA256(key, n, iv, content):
        # Split the key into encryption and authentication halves
        assert( len(key) == 16 + SHA256.digest_size )
        ke = key[-16:]
        ka = key[:-16]

        # Split the encrypted content and integrity check
        S = content[:-SHA256.digest_size]
        T = content[-SHA256.digest_size:]

        # Verify the MAC
        hmac = HMAC.new(ka, digestmod=SHA256)
        ln = struct.pack("!q", len(n))
        la = struct.pack("!q", 0)
        hmac.update(n + S + ln + la)
        Tp = hmac.digest() 
        if Tp != T:
            raise Exception("Integrity check failed")

        # Decrypt the contents
        cipher = AES.new(ke, AES.MODE_CBC, iv)
        pcontent = cipher.decrypt(S)

        # Trim the padding
        lp = struct.unpack("B", content[-1])[0]
        pcontent = pcontent[:-lp]
        
        return pcontent

    @staticmethod
    def encrypt_AES128CCM(key, n, M, m, a):
        # Set parameters
        ln = len(n)
        lm = len(m)
        la = len(a)
        lblock = AES.block_size
        L = 15-len(n)  
        assert( L >= 2 and L <= 8 )
        assert( lm < (1<<(8*L)) )
        assert( 2 <= M and M <= 16 and M%2 == 0 )
        aes = AESCipher(key)

        # PART 1: Compute the authentication tag
        # Note: With no data, this is just AES-CBC with B0 as the IV
        Adata = 0
        if la > 0: 
            Adata = 1
        Mp = (M-2)/2
        Lp = L-1
        Flags = 64*Adata + 8*Mp + Lp
        B = struct.pack("B", Flags) + n + struct.pack("!Q", lm)[-L:]
        
        # If there is associated data, append it
        if la > 0:
            # Encode the length
            La = b''
            if (la < 2**16 - 2**8):
                La = struct.pack("!H", la)
            elif (la < 2**32):
                La = b'\xFF\xFE' + struct.pack("!I", la)
            elif (la < 2**64):
                La = b'\xFF\xFE' + struct.pack("!Q", la)
            lla = len(La)
            # Compute the amount of zero-padding we need
            lza = lblock - ((la + lla)%lblock)
            B = B + La + a + b'\0'*lza

        # Append the message
        lzm = lblock - (lm % lblock)
        B = B + m + b'\0'*lzm
        nB = len(B) / lblock

        # Compute the CBC-MAC
        X = aes.encrypt( B[:lblock] )
        for i in range(nB-1):
            X = strxor( X, B[ lblock*(i+1) : lblock*(i+2) ] )
            X = aes.encrypt(X)
        T = X[:M]

        # PART 2: Encrypt the message
        Flags = struct.pack("B", Lp)
        i=0
        A0 = Flags + n + struct.pack("!Q", i)[-L:]
        S0 = aes.encrypt(A0)
        U = strxor(T, S0[:M])
        
        remaining = lm
        S = b''
        while remaining >= lblock:
            remaining -= lblock
            i += 1
            Ai = Flags + n + struct.pack("!Q", i)[-L:]
            Si = aes.encrypt(Ai)
            S = S + Si
        i += 1
        Aend = Flags + n + struct.pack("!Q", i)[-L:]
        Send = aes.encrypt(Aend)[:remaining]
        S = S + Send
        c = strxor(m, S)

        return c+U

    @staticmethod
    def decrypt_AES128CCM(key, n, M, c, a):
        # Set parameters
        L = 15-len(n)  
        ln = len(n)
        la = len(a)
        lm = len(c) - M
        lblock = AES.block_size
        assert( L >= 2 and L <= 8 )
        assert( lm < (1<<(8*L)) )
        aes = AESCipher(key)

        # PART 1: Compute the key stream to get MAC value and authentication tag
        U = c[-M:]
        Lp = L-1
        Flags = struct.pack("B", Lp)
        i = 0
        A0 = Flags + n + struct.pack("!Q", 0)[-L:]
        S0 = aes.encrypt(A0)
        T = strxor(U, S0[:M])
        
        remaining = lm
        S = b''
        while remaining >= lblock:
            remaining -= lblock
            i += 1
            Ai = Flags + n + struct.pack("!Q", i)[-L:]
            Si = aes.encrypt(Ai)
            S = S + Si
        i += 1
        Aend = Flags + n + struct.pack("!Q", i)[-L:]
        Send = aes.encrypt(Aend)[:remaining]
        S = S + Send
        m = strxor(c[:-M], S)

        # PART 2: Compute the MAC to verify the authentication tag
        # Note: With no data, this is just AES-CBC with B0 as the IV
        Adata = 0
        if la > 0: 
            Adata = 1
        Mp = (M-2)/2
        Lp = L-1
        Flags = 64*Adata + 8*Mp + Lp
        B = struct.pack("B", Flags) + n + struct.pack("!Q", lm)[-L:]
        
        # If there is associated data, append it
        if la > 0:
            # Encode the length
            La = b''
            if (la < 2**16 - 2**8):
                La = struct.pack("!H", la)
            elif (la < 2**32):
                La = b'\xFF\xFE' + struct.pack("!I", la)
            elif (la < 2**64):
                La = b'\xFF\xFE' + struct.pack("!Q", la)
            lla = len(La)
            # Compute the amount of zero-padding we need
            lza = lblock - ((la + lla)%lblock)
            B = B + La + a + b'\0'*lza

        # Append the message
        lzm = lblock - (lm % lblock)
        B = B + m + b'\0'*lzm
        nB = len(B) / lblock

        # Compute the CBC-MAC
        X = aes.encrypt( B[:lblock] )
        for i in range(nB-1):
            X = strxor( X, B[ lblock*(i+1) : lblock*(i+2) ] )
            X = aes.encrypt(X)
        if T != X[:M]:
            raise Exception("Integrity check failed")

        return m
        



