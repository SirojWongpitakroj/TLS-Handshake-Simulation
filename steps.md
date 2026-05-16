### **Phase 1: Registration (The Precondition)**

The Server must obtain a Digital Certificate from the Certificate Authority (CA) to prove its identity before any live connections with the Client occur.

* **Server $\rightarrow$ CA:** $\text{Server} \parallel PU_S$
> *Explanation:* The Server sends its plaintext identity and its public key to the CA.

* **CA $\rightarrow$ Server:** $(\text{Server} \Rightarrow PU_S) \parallel \text{hash}(\text{Server} \Rightarrow PU_S)^{PR_{CA}} \pmod n$
> *Explanation:* The CA mathematically hashes the claim, signs it with its private key ($PR_{CA}$), and returns the Certificate.

---

### **Phase 2: The Hello & Nonces (The Connection)**

The Client initiates the socket connection and ensures the session is fresh to prevent Replay Attacks.

* **Client $\rightarrow$ Server:** $\text{ClientHello} \parallel N_C$
> *Explanation:* The Client sends a greeting and crucially generates a fresh, random Nonce ($N_C$).

* **Server $\rightarrow$ Client:** $\text{ServerHello} \parallel N_S \parallel \text{Certificate}$
> *Explanation:* The Server replies with its own Nonce ($N_S$) and its Digital Certificate.

---

### **Phase 3: The Authentication (The Verification)**

This phase requires no network exchange; it is a mathematical verification performed entirely on the Client's end to prevent blind trust.

* **Internal Math (Client):** The Client takes the CA's encrypted signature from the certificate and decrypts it using the CA's widely known public key ($PU_{CA}$).

$$DecryptedHash = Signature^{PU_{CA}} \pmod n$$

* **Result:** The Client calculates the hash of the plaintext claim themselves. If it matches the $DecryptedHash$, the Client safely extracts and trusts the Server's public key ($PU_S$).

---

### **Phase 4: The Key Exchange (Authenticated Diffie-Hellman)**

Both parties negotiate the shared symmetric session key over the open internet, using RSA signatures to mathematically block the MitM from altering the exchange.

* **Internal Math (Server):** The Server generates the prime modulus ($p$), base ($g$), and its public piece ($Y_S$). It hashes them together, and encrypts the hash using its own RSA Private Key ($PR_S$) to create a Digital Signature.

* **Server $\rightarrow$ Client:** $p \parallel g \parallel Y_S \parallel \text{hash}(p \parallel g \parallel Y_S)^{PR_S}$
> *Explanation:* The Server securely sends the plaintext Diffie-Hellman parameters AND the RSA Signature.

* **Internal Math (Client):** Before doing any DH math, the Client uses $PU_S$ (extracted in Phase 3) to verify the signature. If it verifies, they know the parameters were not altered by an attacker.

* **Client $\rightarrow$ Server:** $Y_C$
> *Explanation:* The Client securely sends its own public piece.

* **Internal Math (Both):** They mathematically derive the exact same, uncompromised symmetric session key ($K$):

$$K = Y_S^{X_C} \pmod p = Y_C^{X_S} \pmod p$$

---

### **Phase 5: The Handshake Verification (Preventing Downgrade Attacks)**

Because the initial messages in Phase 2 were sent in plaintext, both sides must now mathematically confirm the integrity of the conversation.

* **Both Sides Exchange:** $AES_K(\text{hash(All\_Previous\_Handshake\_Messages)})$
> *Explanation:* Both the Client and Server take a cryptographic hash of every single plaintext message sent during the handshake so far. They encrypt this hash using their newly derived Diffie-Hellman key ($K$) and exchange it.

* **Result:** By successfully decrypting and matching these hashes, both parties mathematically confirm that:
  * They both successfully derived the exact same symmetric key.
  * Absolutely zero bytes of the plaintext handshake were tampered with by an eavesdropper.

---

### **Phase 6: The Secure Tunnel (Data Transfer)**

The handshake is fully verified, and the heavy RSA math is dropped. The actual file or message is now transmitted.

* **Client $\rightarrow$ Server:** $AES_K(M \parallel MAC)$
> *Explanation:* The Client uses a standard symmetric library (like AES) with the secure key ($K$), attaches a Message Authentication Code (MAC), and sends the data.

* **Result:** The Attacker only sees the AES ciphertext. Because they could not forge the RSA signatures in Phase 4, they do not possess the key $K$ and cannot decrypt the data.