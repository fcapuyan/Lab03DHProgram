import hashlib
import secrets
import os



# --- UI HELPER FUNCTIONS ---
def print_header(text):
    print(f"\n{'='*60}\n{text}\n{'='*60}")

def print_step(text):
    print(f"\n>> {text}")

def print_info(label, value):
    print(f"   [{label}]: {str(value)[:70]}...")



# --- Define Diffie-Hellman Constants G and P ---

P = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
        "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)

G = 2



# --- PART A: STATEFUL PRNG ---

class SecurePRNG:
    """
    Rollback-resistant PRNG:
    - internal state is 32 bytes
    - output blocks are SHA256(state)
    - after each block, state is updated one-way so attacker can't roll back
    """
    def __init__(self, seed_int):
        # Convert int shared secret to bytes, then hash to fixed 32-byte state
        seed_bytes = seed_int.to_bytes((seed_int.bit_length() + 7) // 8 or 1, "big")
        self.state = hashlib.sha256(seed_bytes).digest()

    def generate(self, n_bytes):
        output = b""
        while len(output) < n_bytes:
            # 1) produce keystream block
            block = hashlib.sha256(self.state).digest()
            output += block

            # 2) update state immediately after (rollback resistance)
            self.state = hashlib.sha256(self.state + block).digest()

        return output[:n_bytes]



def xor_crypt(data, prng):
    # XOR stream cipher: same function encrypts & decrypts
    keystream = prng.generate(len(data))
    return bytes(a ^ b for a, b in zip(data, keystream))



# --- PART B: COMMUNICATION PROTOCOL ---

class Entity:
    # Calculate public and private keys with global P and G.
    def __init__(self, name):
        self.name = name
        # private key in [2, P-2]
        self.private_key = secrets.randbelow(P - 3) + 2
        self.public_key = pow(G, self.private_key, P)
        self.session_prng = None

    def get_public_hex(self):
        return hex(self.public_key)

    # calculate and initialize shared secret with SecurePRNG
    def establish_session(self, partner_pub_hex):
        partner_pub = int(partner_pub_hex, 16)
        shared_secret = pow(partner_pub, self.private_key, P)
        self.session_prng = SecurePRNG(shared_secret)



# --- DO NOT MODIFY THIS CLASS --- #
class Network:
    def __init__(self):
        self.mallory = None  # The interceptor 'hook'

    def send(self, sender, recipient, payload):
        print(f"[NET] {sender} -> {recipient}: {str(payload)[:60]}...")
        if self.mallory:
            return self.mallory.intercept(sender, recipient, payload)
        return payload



# --- PART C: THE MALLORY MITM PROXY ---

class Mallory:
    def __init__(self):
        self.private_key = secrets.randbelow(P - 3) + 2
        self.public_key = pow(G, self.private_key, P)
        self.public_hex = hex(self.public_key)

        # Mallory maintains TWO sessions
        self.alice_prng = None
        self.bob_prng = None

    def intercept(self, sender, recipient, payload):
        # 1) Key Exchange Interception (payload is hex string public key)
        if isinstance(payload, str) and payload.startswith("0x"):
            remote_pub = int(payload, 16)
            my_shared_secret = pow(remote_pub, self.private_key, P)

            # Establish Mallory's session with whoever sent the key
            if sender.lower() == "alice":
                self.alice_prng = SecurePRNG(my_shared_secret)
                print("[MALLORY] Established session with Alice.")
            elif sender.lower() == "bob":
                self.bob_prng = SecurePRNG(my_shared_secret)
                print("[MALLORY] Established session with Bob.")

            # Return Mallory's public key instead so both sides derive secrets with Mallory
            return self.public_hex

        # 2) Encrypted Message Interception/Modification
        if isinstance(payload, bytes):
            print(f"[MALLORY] Intercepting Encrypted Message from {sender}...")

            # In this template, Alice is the sender of the encrypted message
            if sender.lower() == "alice":
                if self.alice_prng is None or self.bob_prng is None:
                    print("[MALLORY] ERROR: Missing PRNG sessions.")
                    return payload

                # Decrypt using Mallory<->Alice PRNG
                plaintext = xor_crypt(payload, self.alice_prng)
                print(f"[MALLORY] Decrypted plaintext: {plaintext!r}")

                # Modify plaintext
                modified = plaintext.replace(b"9pm", b"3am")
                if modified == plaintext:
                    # fallback visible change
                    modified = plaintext.replace(b"meet", b"MEET", 1)

                print(f"[MALLORY] Modified plaintext:  {modified!r}")

                # Re-encrypt using Mallory<->Bob PRNG
                reencrypted = xor_crypt(modified, self.bob_prng)
                return reencrypted

        return payload



# --- DO NOT MODIFY THIS FUNCTION --- #
def main():
    # ==========================================
    # SCENARIO A: BENIGN (SECURE) COMMUNICATION
    # ==========================================
    print_header("SCENARIO A: BENIGN (SECURE) COMMUNICATION")

    alice = Entity("Alice")
    bob = Entity("Bob")
    net = Network()

    print_step("Step 0: Global Group Parameters")
    print_info("G (Generator)", G)
    print_info("P (Prime)", P)

    print_step("Step 1: Public Key Exchange")
    print_info("Alice Private (a)", alice.private_key)
    print_info("Bob Private (b)", bob.private_key)

    alice_pub = alice.get_public_hex()
    print_info("Alice Public (A = G^a mod P)", alice_pub)
    key_for_bob = net.send("Alice", "Bob", alice_pub)

    bob_pub = bob.get_public_hex()
    print_info("Bob Public (B = G^b mod P)", bob_pub)
    key_for_alice = net.send("Bob", "Alice", bob_pub)

    print_step("Step 2: Establishing Sessions")
    alice.establish_session(key_for_alice)
    bob.establish_session(key_for_bob)
    print("   [Status]: Shared Secret computed: S = B^a mod P = A^b mod P")

    print_step("Step 3: Secure Message Transmission")
    message = b"<Jacob Capuyan Lab 3 secure message>"  # ONLY line you should change in Scenario A per instructions
    encrypted_msg = xor_crypt(message, alice.session_prng)
    delivered_data = net.send("Alice", "Bob", encrypted_msg)
    final_message = xor_crypt(delivered_data, bob.session_prng)

    print_info("Bob decrypted", final_message.decode(errors="replace"))

    # ==========================================
    # SCENARIO B: MALICIOUS (MITM) ATTACK
    # ==========================================
    print_header("SCENARIO B: MALICIOUS (MITM) ATTACK")

    alice = Entity("Alice")
    bob = Entity("Bob")
    mallory = Mallory()
    net = Network()
    net.mallory = mallory

    print_step("Step 1: Mallory's Parameters")
    print_info("Mallory Private (m)", mallory.private_key)
    print_info("Mallory Public (M)", mallory.public_hex)

    print_step("Step 2: Compromised Key Exchange")
    print("Alice sending key to Bob...")
    key_for_bob = net.send("Alice", "Bob", alice.get_public_hex())

    print("Bob sending key to Alice...")
    key_for_alice = net.send("Bob", "Alice", bob.get_public_hex())

    print_step("Step 3: Poisoned Shared Secrets")
    alice.establish_session(key_for_alice)
    bob.establish_session(key_for_bob)

    print("   [Alice Session]: S_am = (Mallory_Pub)^a mod P")
    print("   [Bob Session]:   S_bm = (Mallory_Pub)^b mod P")

    print_step("Step 4: Interception")
    message = b"Meet me at 9pm."
    encrypted_msg = xor_crypt(message, alice.session_prng)
    delivered_data = net.send("Alice", "Bob", encrypted_msg)

    final_message = xor_crypt(delivered_data, bob.session_prng)
    print_info("Bob received", final_message.decode(errors="replace"))

    if b"3am" in final_message:
        print("\n[DANGER] MITM SUCCESS: Mallory used her private key (m) to decrypt and re-encrypt.")

if __name__ == "__main__":
    main()
