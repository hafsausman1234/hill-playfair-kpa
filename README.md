# hill-playfair-kpa

This project demonstrates a Known Plaintext Attack (KPA) on a custom cipher that combines the Playfair and Hill ciphers.  
The goal is to recover the Hill key matrix and decrypt the ciphertext back to the original plaintext.

# Overview

The code takes the following user inputs:
- Known Plaintext – the original message
- Final Ciphertext – encrypted text produced by Playfair → Hill encryption
- Playfair Key – guessed or known key used in Playfair
- Hill Key Dimension (m) – size of the Hill key matrix (e.g., 2×2 or 3×3)
- Block Offset – starting index for the known block (used if singular matrices occur)

# Working

1. Playfair Simulation:  
   Encrypts the known plaintext using the guessed Playfair key to produce the intermediate plaintext that was fed into the Hill cipher.

2. Hill Key Recovery:  
   - Converts letters to numbers (A = 0 … Z = 25).  
   - Takes `m×m` aligned character blocks from the intermediate plaintext and ciphertext.  
   - Computes the Hill key matrix using  
     K = C × P⁻¹ (mod 26) 
     where `P` = plaintext matrix and `C` = ciphertext matrix.

3. Verification & Full Decryption:  
   - Decrypts the entire ciphertext using the recovered Hill key.  
   - Applies Playfair decryption using the provided key.  
   - If the decrypted text matches the original plaintext,it displays: “CIPHER BROKEN SUCCESSFULLY!”


