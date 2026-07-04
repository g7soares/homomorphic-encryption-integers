from secrets import randbelow, randbits



##### utils
class Parametros:
    def __init__(self, eta=96, gamma=384, rho=8, rho_prime=12, tau=32):
        self.eta = eta                  # tamanho da chave secreta p
        self.gamma = gamma              # tamanho dos inteiros publicos xi
        self.rho = rho                  # ruido usado para gerar a chave publica
        self.rho_prime = rho_prime      # ruido usado na cifragem
        self.tau = tau                  # quantidade de inteiros na chave publica

    def __str__(self):
        return f"Parametros(eta={self.eta}, gamma={self.gamma}, rho={self.rho}, rho_prime={self.rho_prime}, tau={self.tau})"


class SecretKey:
    def __init__(self, p):
        self.p = p

    def __str__(self):
        return f"SecretKey(p={self.p})"

class PublicKey:
    def __init__(self, x0, xs):
        self.x0 = x0
        self.xs = xs

    def __str__(self):
        return f"PublicKey(x0={self.x0}, xs={self.xs})"

class KeyPair:
    def __init__(self, sk, pk):
        self.sk = sk
        self.pk = pk
        
    def __str__(self):
        return f"Secret Key: {self.sk}\nPublic key: {self.pk}"

class Ciphertext:
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return f"Ciphertext(value={self.value})"
#####

class DGHV:
    def __init__(self, params=Parametros()):
        self.params = params
        self.keys = self.keygen()

    def keygen(self):
        p = random_impar(self.params.eta)

        while True:
            public_values = []

            for _ in range(self.params.tau + 1):
                public_values.append(
                    quase_multiplo(
                        p,
                        self.params.gamma,
                        self.params.rho,
                    )
                )

            public_values.sort(reverse=True)
            x0 = public_values[0]
            xs = public_values[1:]

            # Condicao usada no artigo:
            # reiniciar se x0 nao for impar ou se o ruido de x0 nao for par.
            if x0 % 2 == 1 and mod_perto_0(x0, p) % 2 == 0:
                return KeyPair(
                    sk=SecretKey(p=p),
                    pk=PublicKey(x0=x0, xs=xs),
                )

    def enc(self, bit):
        if bit not in (0, 1):
            raise ValueError("Algo de errado não está certo, DGHV cifra apenas bits: 0 ou 1")

        r = random_integer_positivo(self.params.rho_prime)
        subset_sum = 0

        for x in self.keys.pk.xs:
            if randbelow(2) == 1:
                subset_sum += x

        c = bit + 2 * r + 2 * subset_sum
        c = mod_perto_0(c, self.keys.pk.x0)

        return Ciphertext(c)

    def dec(self, ciphertext):
        return mod_perto_0(ciphertext.value, self.keys.sk.p) % 2

    def evaluate(self, circuit, ciphertexts):
        stack = []

        for token in circuit:

            # if token in ciphertexts:
            #     print(ciphertexts[token].value)
            if token == "ADD":
                right = stack.pop()
                left = stack.pop()
                stack.append(self.soma(left, right))
            elif token == "MULT":
                right = stack.pop()
                left = stack.pop()
                stack.append(self.multplicacao(left, right))
            else:
                stack.append(ciphertexts[token])
        if len(stack) != 1:
            raise ValueError("circuito invalido")

        return stack[0]

    def soma(self, left, right):
        return Ciphertext(left.value + right.value)

    def multplicacao(self, left, right):
        return Ciphertext(left.value * right.value)
    
    def __str__(self):
        return f"Parametros: {self.params}\nKey: {self.keys}"

def random_impar(bits):
    return (1 << (bits - 1)) | randbits(bits - 1) | 1


def random_integer_positivo(bits):
    bound = 1 << bits
    return randbelow(2 * bound - 1) - (bound - 1)


def quase_multiplo(p, gamma, rho):
    q_bound = max(1, (1 << gamma) // p)
    q = randbelow(q_bound)
    r = random_integer_positivo(rho)
    return p * q + r


def mod_perto_0(value, modulus):
    remainder = value % modulus

    if remainder > modulus // 2:
        remainder -= modulus

    return remainder


if __name__ == "__main__":
    Cif = DGHV()

    bits = {
        "a": 1,
        "b": 0,
        "c": 1,
        "d": 1,
        "e": 0,
        "f": 1,
        "g": 1,
        "h": 0,
        "i": 1,
        "j": 1,
    }

    ciphertexts = {}
    for nome, bit in bits.items():
        ciphertexts[nome] = Cif.enc(bit)
        # print(Cif.enc(bit))

    # Circuito booleano:
    # (((a XOR b) AND (c XOR d))
    #  XOR ((e AND f) XOR (g AND (h XOR i)))
    #  XOR (j AND (a XOR e)))
    circuit = [
        "a", "b", "ADD",
        "c", "d", "ADD",
        "MULT",
        "e", "f", "MULT",
        "g", "h", "i", "ADD", "MULT",
        "ADD",
        "ADD",
        "j", "a", "e", "ADD", "MULT",
        "ADD",
    ]

    result = Cif.evaluate(
        circuit=circuit,
        ciphertexts=ciphertexts,
    )

    esperado = (
        (((bits["a"] ^ bits["b"]) & (bits["c"] ^ bits["d"]))
         ^ ((bits["e"] & bits["f"]) ^ (bits["g"] & (bits["h"] ^ bits["i"])))
         ^ (bits["j"] & (bits["a"] ^ bits["e"])))
    )
    print("Cifra:", result)
    print("resultado esperado:", esperado)
    print("resultado decifrado:", Cif.dec(result))

    print("\n\n\n")
    params_fracos = Parametros(eta=8, gamma=16, rho=6, rho_prime=6, tau=4)

    Cif_2 = DGHV(params_fracos)
    
    bits_2 = {
        "a": 1,
        "b": 1,
        "c": 1,
        "d": 1,
        "e": 1,
        "f": 1,
        "g": 1,
        "h": 1,
        "i": 1,
        "j": 1,
        "k" : 1,
        "l": 1,
    }

    ciphertexts_2 = {}
    for nome, bit in bits_2.items():
        ciphertexts_2[nome] = Cif_2.enc(bit)

    # Circuito booleano: a AND b AND ... AND l
    # Como todas as entradas sao 1, o esperado e 1.
    # Com parametros fracos e muitas multiplicacoes, o ruido pode fazer falhar.

    circuito_2 = [
        "a", "b", "MULT",
        "c", "MULT",
        "d", "MULT",
        "e", "MULT",
        "f", "MULT",
        "g", "MULT",
        "h", "MULT",
        "i", "MULT",
        "j", "MULT",
        "k", "MULT",
        "l", "MULT",
    ]

    result_falha = Cif_2.evaluate(
        circuit=circuito_2,
        ciphertexts=ciphertexts_2,
    )

    esperado_falha = 1
    decifrado_falha = Cif_2.dec(result_falha)

    print("Cifra:", result_falha)
    print("resultado esperado:", esperado_falha)
    print("resultado decifrado:", decifrado_falha)
