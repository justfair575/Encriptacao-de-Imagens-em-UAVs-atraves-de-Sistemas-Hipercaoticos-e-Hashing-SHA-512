
#!/usr/bin/env python3
"""
Encriptação e desencriptação de imagens usando:
- SHA-512
- HMAC-SHA-512 para derivação determinística
- Mapa caótico 3D-MMHM
- Permutação de píxeis
- S-box dinâmica
- Difusão XOR

AVISO:
Protótipo académico. Não é um sistema criptográfico validado
e não deve ser utilizado para proteger dados reais.
"""

import argparse
import hashlib
import hmac
from pathlib import Path

import numpy as np
from PIL import Image


# ---------------------------------------------------------
# 1. PARÂMETROS DO MAPA CAÓTICO 3D-MMHM
# ---------------------------------------------------------

A = 15.0
B = 10.0
C = 15.0
D = 10.0

MEM_K1 = 0.1
MEM_K2 = 0.1


# ---------------------------------------------------------
# 2. CALCULAR SHA-512 DA IMAGEM
# ---------------------------------------------------------

def sha512_image(image_bytes: bytes) -> bytes:
    """Calcula o SHA-512 dos bytes do ficheiro de imagem."""
    return hashlib.sha512(image_bytes).digest()


# ---------------------------------------------------------
# 3. DERIVAR AS CONDIÇÕES INICIAIS
# ---------------------------------------------------------

def derive_initial_conditions(
    secret: bytes,
    nonce: bytes,
    image_hash: bytes
):
    """
    Deriva x0, y0 e q0 com HMAC-SHA-512.

    A chave secreta, o nonce e o hash da imagem são utilizados
    para produzir condições iniciais reproduzíveis.
    """

    material = (
        b"UAV-3D-MMHM-demo-v1|"
        + nonce
        + image_hash
    )

    seed = hmac.new(
        secret,
        material,
        hashlib.sha512
    ).digest()

    vals = np.frombuffer(
        seed[:24],
        dtype=np.uint64
    )

    vals = vals.astype(np.float64) / float(2**64)

    x0, y0, q0 = 0.05 + 0.10 * vals[:3]

    return float(x0), float(y0), float(q0)


# ---------------------------------------------------------
# 4. GERAR A SEQUÊNCIA CAÓTICA 3D-MMHM
# ---------------------------------------------------------

def mmhm_sequence(length: int, initial):
    """
    Equações do mapa 3D-MMHM:

    x[n+1] = a*sin(b*x[n]) + sin(y[n]*cosh(pi*q[n]))

    y[n+1] = c*cos(x[n]*cosh(pi*q[n]) + d*y[n])

    q[n+1] = k1*q[n] + k2*y[n]
    """

    x, y, q = initial

    output = np.empty(
        (length, 3),
        dtype=np.float64
    )

    for i in range(length):

        modulation = np.cosh(np.pi * q)

        if not np.isfinite(modulation):
            raise RuntimeError(
                "Overflow no mapa 3D-MMHM. "
                "Verifica os parâmetros e as condições iniciais."
            )

        xn = (
            A * np.sin(B * x)
            + np.sin(y * modulation)
        )

        yn = (
            C * np.cos(
                x * modulation + D * y
            )
        )

        qn = MEM_K1 * q + MEM_K2 * y

        x = float(xn)
        y = float(yn)
        q = float(qn)

        if not np.all(np.isfinite([x, y, q])):
            raise RuntimeError(
                "O mapa 3D-MMHM produziu valores inválidos."
            )

        output[i] = (x, y, q)

    return output


# ---------------------------------------------------------
# 5. CONVERTER A SEQUÊNCIA CAÓTICA EM BYTES
# ---------------------------------------------------------

def chaotic_bytes(sequence: np.ndarray) -> np.ndarray:
    """Converte valores caóticos em bytes entre 0 e 255."""

    scaled = np.abs(sequence) * 1_000_003.0

    fractional = scaled - np.floor(scaled)

    result = np.floor(
        fractional * 256.0
    ).astype(np.uint8)

    return result


# ---------------------------------------------------------
# 6. CONSTRUIR A S-BOX DINÂMICA
# ---------------------------------------------------------

def make_sbox(scores: np.ndarray) -> np.ndarray:
    """
    Constrói uma S-box bijetiva através da ordenação
    dos 256 valores caóticos.
    """

    if scores.size != 256:
        raise ValueError(
            "A S-box necessita de exatamente 256 valores."
        )

    sbox = np.argsort(
        scores,
        kind="mergesort"
    ).astype(np.uint8)

    if np.unique(sbox).size != 256:
        raise RuntimeError(
            "A S-box não é uma permutação válida."
        )

    return sbox


# ---------------------------------------------------------
# 7. ENCRIPTAÇÃO DA IMAGEM
# ---------------------------------------------------------

def encrypt_array(
    plain: np.ndarray,
    secret: bytes,
    nonce: bytes,
    image_hash: bytes
):
    """Encripta os píxeis da imagem."""

    flat = np.ascontiguousarray(
        plain
    ).reshape(-1)

    n = flat.size

    initial = derive_initial_conditions(
        secret,
        nonce,
        image_hash
    )

    # Segmentos distintos para permutação, S-box e XOR.
    chaotic = mmhm_sequence(
        2 * n + 256,
        initial
    )

    perm_scores = chaotic[:n, 0]

    sbox_scores = chaotic[
        n:n + 256, 1
    ]

    xor_scores = chaotic[
        n + 256:, 2
    ]

    # Permutação dos píxeis.
    permutation = np.argsort(
        perm_scores,
        kind="mergesort"
    )

    permuted = flat[permutation]

    # S-box e S-box inversa.
    sbox = make_sbox(sbox_scores)

    inverse_sbox = np.empty(
        256,
        dtype=np.uint8
    )

    inverse_sbox[sbox] = np.arange(
        256,
        dtype=np.uint8
    )

    # Sequência utilizada na difusão XOR.
    key_stream = chaotic_bytes(
        xor_scores
    )

    # Substituição seguida de difusão.
    cipher = np.bitwise_xor(
        sbox[permuted],
        key_stream
    )

    return cipher.reshape(plain.shape)


# ---------------------------------------------------------
# 8. DESENCRIPTAÇÃO DA IMAGEM
# ---------------------------------------------------------

def decrypt_array(
    cipher: np.ndarray,
    secret: bytes,
    nonce: bytes,
    image_hash: bytes,
    original_shape
):
    """Recupera os píxeis originais."""

    flat = np.ascontiguousarray(
        cipher
    ).reshape(-1)

    n = flat.size

    initial = derive_initial_conditions(
        secret,
        nonce,
        image_hash
    )

    # Reproduzir a mesma sequência caótica.
    chaotic = mmhm_sequence(
        2 * n + 256,
        initial
    )

    perm_scores = chaotic[:n, 0]

    sbox_scores = chaotic[
        n:n + 256, 1
    ]

    xor_scores = chaotic[
        n + 256:, 2
    ]

    permutation = np.argsort(
        perm_scores,
        kind="mergesort"
    )

    sbox = make_sbox(sbox_scores)

    # Construir a S-box inversa.
    inverse_sbox = np.empty(
        256,
        dtype=np.uint8
    )

    inverse_sbox[sbox] = np.arange(
        256,
        dtype=np.uint8
    )

    key_stream = chaotic_bytes(
        xor_scores
    )

    # Inverter a difusão XOR.
    substituted = np.bitwise_xor(
        flat,
        key_stream
    )

    # Inverter a substituição.
    permuted_plain = inverse_sbox[
        substituted
    ]

    # Inverter a permutação.
    plain = np.empty_like(
        permuted_plain
    )

    plain[permutation] = permuted_plain

    return plain.reshape(original_shape)


# ---------------------------------------------------------
# 9. FUNÇÃO PRINCIPAL
# ---------------------------------------------------------

def main():

    parser = argparse.ArgumentParser(
        description=(
            "Encriptação e desencriptação "
            "de imagens com o mapa 3D-MMHM."
        )
    )

    parser.add_argument(
        "imagem",
        help="Caminho para o ficheiro de imagem a encriptar."
    )

    parser.add_argument(
        "--out",
        default="resultado",
        help="Prefixo dos ficheiros de saída."
    )

    parser.add_argument(
        "--secret",
        default="CHAVE-DE-TESTE-ALTERAR-EM-EXPERIENCIAS",
        help="Chave secreta para a experiência."
    )

    parser.add_argument(
        "--nonce",
        default="nonce-demo-0001",
        help="Nonce utilizado na experiência."
    )

    args = parser.parse_args()

    input_path = Path(args.imagem)

    # Ler o ficheiro original.
    raw_bytes = input_path.read_bytes()

    # Calcular o hash SHA-512.
    image_hash = sha512_image(
        raw_bytes
    )

    secret = args.secret.encode(
        "utf-8"
    )

    nonce = args.nonce.encode(
        "utf-8"
    )

    # Abrir e normalizar a imagem.
    with Image.open(input_path) as im:

        mode = (
            "RGBA"
            if "A" in im.getbands()
            else "RGB"
        )

        original_img = im.convert(mode)

        original = np.asarray(
            original_img,
            dtype=np.uint8
        )

    print("\n========== IMAGEM ORIGINAL ==========")

    print(f"Ficheiro: {input_path}")

    print(
        f"Dimensões: "
        f"{original_img.width} x {original_img.height}"
    )

    print(f"Modo: {mode}")

    print(
        "SHA-512 do ficheiro original:\n"
        f"{image_hash.hex()}"
    )

    # Encriptar.
    print("\n========== ENCRIPTAÇÃO ==========")

    encrypted = encrypt_array(
        original,
        secret,
        nonce,
        image_hash
    )

    encrypted_path = Path(
        f"{args.out}_cifrada.png"
    )

    Image.fromarray(
        encrypted,
        mode=mode
    ).save(encrypted_path)

    print(
        "Imagem cifrada guardada em:\n"
        f"{encrypted_path.resolve()}"
    )

    # Desencriptar.
    print("\n========== DESENCRIPTAÇÃO ==========")

    decrypted = decrypt_array(
        encrypted,
        secret,
        nonce,
        image_hash,
        original.shape
    )

    decrypted_path = Path(
        f"{args.out}_recuperada.png"
    )

    Image.fromarray(
        decrypted,
        mode=mode
    ).save(decrypted_path)

    print(
        "Imagem recuperada guardada em:\n"
        f"{decrypted_path.resolve()}"
    )

    # Comparar os píxeis originais e recuperados.
    identical = np.array_equal(
        original,
        decrypted
    )

    original_pixel_hash = hashlib.sha512(
        original.tobytes()
    ).hexdigest()

    recovered_pixel_hash = hashlib.sha512(
        decrypted.tobytes()
    ).hexdigest()

    print("\n========== VERIFICAÇÃO ==========")

    print(
        "Recuperação pixel a pixel: "
        f"{'OK' if identical else 'FALHOU'}"
    )

    print(
        "SHA-512 dos píxeis originais:\n"
        f"{original_pixel_hash}"
    )

    print(
        "SHA-512 dos píxeis recuperados:\n"
        f"{recovered_pixel_hash}"
    )

    if not identical:
        raise SystemExit(
            "Erro: a imagem recuperada "
            "não coincide com a original."
        )

    print(
        "\nProcesso concluído. "
        "Os píxeis foram recuperados corretamente."
    )

    # Tentar abrir as imagens num visualizador.
    try:
        Image.fromarray(
            encrypted,
            mode=mode
        ).show(title="Imagem cifrada")

        Image.fromarray(
            decrypted,
            mode=mode
        ).show(title="Imagem recuperada")

    except Exception:
        pass


# ---------------------------------------------------------
# 10. EXECUÇÃO DO PROGRAMA
# ---------------------------------------------------------

if __name__ == "__main__":
    main()
