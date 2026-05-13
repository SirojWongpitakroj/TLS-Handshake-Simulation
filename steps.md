### **Phase 1: Registration (The Precondition)**

The Server must obtain a Digital Certificate from the Certificate Authority (CA) to prove its identity before any live connections with the Client occur.

* **Server $\rightarrow$ CA:** $Server \parallel PU_S$
> 
> *Explanation:* The Server sends its plaintext identity and its public key to the CA.
> 
> 


* **CA $\rightarrow$ Server:** $(Server \Rightarrow PU_S) \parallel hash(Server \Rightarrow PU_S)^{PR_{CA}} \pmod n$
> 
> *Explanation:* The CA mathematically hashes the claim, signs it with its private key ($PR_{CA}$), and returns the Certificate.
> 
> 



---

### **Phase 2: The Hello & Nonces (The Connection)**

The Client initiates the socket connection and ensures the session is fresh to prevent Replay Attacks.

* **Client $\rightarrow$ Server:** $ClientHello \parallel N_C$
> 
> *Explanation:* The Client sends a greeting and crucially generates a fresh, random Nonce ($N_C$).
> 
> 


* **Server $\rightarrow$ Client:** $ServerHello \parallel N_S \parallel Certificate$
> 
> *Explanation:* The Server replies with its own Nonce ($N_S$) and its Digital Certificate.
> 
> 



---

### **Phase 3: The Authentication (The Verification)**

This phase requires no network exchange; it is a mathematical verification performed entirely on the Client's end.

* 
**Internal Math (Client):** The Client takes the CA's encrypted signature from the certificate and decrypts it using the CA's known public key ($PU_{CA}$).



$$Decrypted Hash = Signature^{PU_{CA}} \pmod n$$





* 
**Result:** If the hashes match, the Client safely extracts and trusts the Server's public key ($PU_S$).



---

### **Phase 4: The Key Exchange (Authenticated Diffie-Hellman)**

Both parties negotiate the shared symmetric session key over the open internet, using RSA signatures to prevent the MitM from altering the math.

* **Internal Math (Server):** The Server generates the prime modulus ($p$), base ($g$), and its public piece ($Y_S$). It hashes them together, and encrypts the hash using its RSA Private Key ($PR_S$) to create a Digital Signature.


* **Server $\rightarrow$ Client:** $p \parallel g \parallel Y_S \parallel hash(p \parallel g \parallel Y_S)^{PR_S}$
> 
> *Explanation:* The Server securely sends the plaintext Diffie-Hellman parameters AND the RSA Signature.
> 
> 


* 
**Internal Math (Client):** Before doing any DH math, the Client uses $PU_S$ (extracted in Phase 3) to verify the signature. If it verifies, they know the parameters were not altered by an attacker.


* **Client $\rightarrow$ Server:** $Y_C$
> 
> *Explanation:* The Client securely sends its own public piece.
> 
> 


* 
**Internal Math (Both):** They mathematically derive the exact same, uncompromised symmetric session key ($K$):



$$K = Y_S^{X_C} \pmod p = Y_C^{X_S} \pmod p$$






---

### **Phase 5: The Secure Tunnel (Data Transfer)**

The handshake is complete, and the heavy RSA math is dropped. The actual file or message is now transmitted.

* **Client $\rightarrow$ Server:** $AES_K(M \parallel MAC)$
> 
> *Explanation:* The Client uses a standard symmetric library (like AES) with the secure key ($K$), attaches a Message Authentication Code (MAC), and sends the data.
> 
> 


* **Result:** The Attacker only sees the AES ciphertext. Because they could not bypass the RSA signatures in Phase 4, they do not possess $K$ and cannot decrypt the data.