
import numpy as np
import math
import sys
from typing import List, Tuple

# =====================================================================
# I. SHARED/HELPER FUNCTIONS
# =====================================================================

def clean_text_letters(text: str) -> str:
    
    return ''.join(ch for ch in text.upper() if ch.isalpha())

def text_to_numbers(text: str) -> List[int]:
   
    txt = clean_text_letters(text)
    return [ord(char) - ord('A') for char in txt]

def numbers_to_text(numbers: List[int]) -> str:
    
    return "".join([chr(int(num) % 26 + ord('A')) for num in numbers])

# ---------- modular arithmetic helpers ----------
def extended_gcd(a: int, b: int) -> Tuple[int,int,int]:

    if b == 0:
        return (1, 0, a)
    x1, y1, g = extended_gcd(b, a % b)
    return (y1, x1 - (a // b) * y1, g)

def modinv_int(a: int, m: int) -> int:
    
    a = a % m
    x, y, g = extended_gcd(a, m)
    if g != 1:
        raise ValueError(f"No modular inverse for {a} modulo {m} (gcd={g})")
    return x % m

def matrix_mod_inverse(K: np.ndarray, mod: int = 26) -> np.ndarray:
    
    K = np.array(K, dtype=int)
    if K.ndim != 2 or K.shape[0] != K.shape[1]:
        raise ValueError("K must be a square matrix")

    n = K.shape[0]
    
    det = int(round(np.linalg.det(K)))
    det_mod = det % mod

    if math.gcd(det_mod, mod) != 1:
        raise ValueError(f"Matrix not invertible modulo {mod}: det={det} (det mod {mod} = {det_mod}) gcd != 1")

    det_inv = modinv_int(det_mod, mod)

    
    cofactor = np.zeros((n, n), dtype=int)
    for i in range(n):
        for j in range(n):
            minor = np.delete(np.delete(K, i, axis=0), j, axis=1)
            minor_det = int(round(np.linalg.det(minor)))
            sign = (-1) ** (i + j)
            cofactor[i, j] = sign * minor_det

    adjugate = cofactor.T
    K_inv = (det_inv * adjugate) % mod
    return K_inv.astype(int)

# =====================================================================
# II. PLAYFAIR CIPHER FUNCTIONS 
# =====================================================================

def playfair_matrix(key: str) -> List[List[str]]:
    key = key.replace(" ", "").upper()
    Alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ" 
    matrix_str = ""
    for char in key:
        char_to_add = 'I' if char == 'J' else char
        if char_to_add not in matrix_str and char_to_add in Alphabet:
            matrix_str += char_to_add
    for char in Alphabet:
        if char not in matrix_str: 
            matrix_str += char
    matrix = []
    for i in range(0, 25, 5):
        matrix.append(list(matrix_str[i:i+5]))
    return matrix

def get_char_position(matrix: List[List[str]], char: str) -> Tuple[int,int]:
    char = 'I' if char == 'J' else char
    for row in range(5):
        for col in range(5):
            if matrix[row][col] == char:
                return row, col
    return -1, -1 

def encrypt_digraph(matrix: List[List[str]], char1: str, char2: str) -> str:
    r1, c1 = get_char_position(matrix, char1)
    r2, c2 = get_char_position(matrix, char2)
    if r1 == r2:
        c1 = (c1 + 1) % 5
        c2 = (c2 + 1) % 5
    elif c1 == c2:
        r1 = (r1 + 1) % 5
        r2 = (r2 + 1) % 5
    else:
        c1, c2 = c2, c1
    return matrix[r1][c1] + matrix[r2][c2]

def prepare_plaintext(plaintext: str) -> str:
    plaintext = clean_text_letters(plaintext).replace("J", "I")
    prepared_text = ""
    i = 0
    while i < len(plaintext):
        char1 = plaintext[i]
        if i == len(plaintext) - 1:
            prepared_text += char1 + 'X'
            break
        char2 = plaintext[i+1]
        if char1 == char2:
            prepared_text += char1 + 'X' 
            i += 1
        else:
            prepared_text += char1 + char2
            i += 2
    return prepared_text

def playfair_encrypt_for_kpa(plaintext: str, key: str) -> str:
    matrix = playfair_matrix(key)
    prepared_text = prepare_plaintext(plaintext)
    ciphertext = ""
    for i in range(0, len(prepared_text), 2):
        digraph = prepared_text[i:i+2]
        ciphertext += encrypt_digraph(matrix, digraph[0], digraph[1])
    return ciphertext

def decrypt_digraph(matrix: List[List[str]], char1: str, char2: str) -> str:
    r1, c1 = get_char_position(matrix, char1)
    r2, c2 = get_char_position(matrix, char2)
    if r1 == r2:
        c1 = (c1 - 1) % 5
        c2 = (c2 - 1) % 5
    elif c1 == c2:
        r1 = (r1 - 1) % 5
        r2 = (r2 - 1) % 5
    else:
        c1, c2 = c2, c1
    return matrix[r1][c1] + matrix[r2][c2]

def playfair_decrypt(ciphertext: str, key: str) -> str:
    matrix = playfair_matrix(key)
    ct = clean_text_letters(ciphertext)
    if len(ct) % 2 != 0:
        ct += 'X'
    intermediate_plaintext = ""
    for i in range(0, len(ct), 2):
        digraph = ct[i:i+2]
        intermediate_plaintext += decrypt_digraph(matrix, digraph[0], digraph[1])

    final_plaintext = intermediate_plaintext

    if final_plaintext.endswith('X'):
        final_plaintext = final_plaintext[:-1]

    
    output = ""
    i = 0
    while i < len(final_plaintext):
        char = final_plaintext[i]
        if char == 'X' and i > 0 and i < len(final_plaintext) - 1 and final_plaintext[i-1] == final_plaintext[i+1]:
            i += 1
            continue
        output += char
        i += 1
    return output

# =====================================================================
# III. HILL CIPHER KPA CORE FUNCTIONS 
# =====================================================================

def find_hill_key(P_vectors: List[List[int]], C_vectors: List[List[int]], m: int) -> np.ndarray:
   
    P_matrix = np.array(P_vectors, dtype=int).T   
    C_matrix = np.array(C_vectors, dtype=int).T   

   
    P_inv_mod = matrix_mod_inverse(P_matrix, 26)

    K_matrix = (np.dot(C_matrix, P_inv_mod) % 26).astype(int)
    return K_matrix

def get_inverse_matrix(K: np.ndarray) -> np.ndarray:
    
    return matrix_mod_inverse(np.array(K, dtype=int), 26)

def hill_decrypt(ciphertext: str, K: np.ndarray, m: int) -> str:
    
    ct = clean_text_letters(ciphertext)
    
    if len(ct) % m != 0:
        ct += 'X' * (m - (len(ct) % m))

    K_inv = get_inverse_matrix(K)   
    C_nums = text_to_numbers(ct)
    P_nums = []
    for i in range(0, len(C_nums), m):
        block = C_nums[i:i+m]
        
        if len(block) != m:
            block += [ord('X') - ord('A')] * (m - len(block))
        C_vector = np.array(block, dtype=int) 
        plain_vec = np.dot(K_inv, C_vector) % 26
        P_nums.extend([int(x) for x in plain_vec])
    plaintext = numbers_to_text(P_nums)
    while plaintext.endswith('X'):
        plaintext = plaintext[:-1]
    return plaintext

# =====================================================================
# IV. MAIN ATTACK FLOW AND USER INPUT 
# =====================================================================

def attack_chained_cipher(known_plaintext: str, final_ciphertext: str, m_guess: int, playfair_key_guess: str, block_offset: int = 0):
    print("\n\n#####################################################")
    print(f"## KPA on Playfair -> Hill Cipher Cascade (m={m_guess})")
    print("#####################################################")
    print(f"Known Plaintext: {known_plaintext.upper()}")
    print(f"Final Ciphertext: {final_ciphertext}")
    print(f"Playfair Key Guess: {playfair_key_guess.upper()}")
    print(f"*** ATTACK OFFSET: {block_offset} ***")

    print("\n--- Phase 1: Finding Hill Key (L2) ---")
    P_intermediate = playfair_encrypt_for_kpa(known_plaintext, playfair_key_guess)
    print(f"-> Generated Intermediate Plaintext (Hill P): {P_intermediate}")

    P_num = text_to_numbers(P_intermediate)
    C_num = text_to_numbers(final_ciphertext)

    required_len = m_guess * m_guess

    if len(P_num) < required_len + block_offset or len(C_num) < required_len + block_offset:
        print(f"\n[ERROR] Plaintext/Ciphertext length is too short for m={m_guess} and offset={block_offset}. Need {required_len} chars starting at index {block_offset}.")
        return

    P_vectors = []
    C_vectors = []
    start_index = block_offset
    end_index = start_index + required_len

    P_KPA_block = P_num[start_index:end_index]
    C_KPA_block = C_num[start_index:end_index]

    for i in range(0, required_len, m_guess):
        P_vectors.append(P_KPA_block[i:i+m_guess])
        C_vectors.append(C_KPA_block[i:i+m_guess])

    print(f"-> P KPA Block used (char): {numbers_to_text(P_KPA_block)}")

    try:
        K_hill = find_hill_key(P_vectors, C_vectors, m_guess)
        print("\n[SUCCESS] Recovered Hill Key Matrix (K_hill):")
        print(K_hill)
    except Exception as e:
        print(f"\n[FAILURE] Hill Key Recovery failed: {e}")
        return

    print("\n--- Phase 2: Verification and Full Decryption ---")
    try:
        full_intermediate_plaintext = hill_decrypt(final_ciphertext, K_hill, m_guess)
        print(f"-> Hill Decrypted Text (Full Intermediate): {full_intermediate_plaintext}")
    except Exception as e:
        print(f"\n[FAILURE] Hill Decryption failed: {e}")
        return

    recovered_plaintext = playfair_decrypt(full_intermediate_plaintext, playfair_key_guess)
    print(f"-> Playfair Decrypted Text (Recovered): {recovered_plaintext}")

    known_clean = clean_text_letters(known_plaintext).replace('J', 'I')
    recovered_clean = clean_text_letters(recovered_plaintext).replace('J', 'I')

    if recovered_clean == known_clean:
        print("\n\n CIPHER BROKEN SUCCESSFULLY! ")
        print("The guessed keys match the known plaintext.")
    else:
        print("\n\n ATTACK FAILED ")
        print("The recovered plaintext does NOT match the known plaintext.")
        print("This means the Playfair key guess or block offset was incorrect.")

    print("#####################################################")

def get_user_input():
    print("\n--- ATTACK PARAMETER INPUT ---")
    known_p = input("Enter the **Known Plaintext** (P): ").strip()
    if not known_p:
        return None

    final_c = input("Enter the **Final Ciphertext** (C): ").strip().replace(" ", "")
    if not final_c:
        return None

    while True:
        try:
            m = int(input("Enter the guessed Hill key dimension (m, e.g., 2 or 3): "))
            if m < 2:
                print("Dimension must be 2 or greater.")
                continue
            break
        except ValueError:
            print("Invalid input. Please enter an integer.")

    playfair_key = input("Enter the guessed **Playfair Key**: ").strip()
    if not playfair_key:
        return None

    offset = input("Enter the **Block Offset** (0 for default, or try 1 to fix singularity): ")
    try:
        offset = int(offset)
    except ValueError:
        offset = 0

    return known_p, final_c, m, playfair_key, offset

if __name__ == "__main__":
    params = get_user_input()
    if params:
        known_p, final_c, m_guess, playfair_key_guess, offset = params
        attack_chained_cipher(known_p, final_c, m_guess, playfair_key_guess, offset)
    else:
        print("Required input missing. Exiting attack program.")
