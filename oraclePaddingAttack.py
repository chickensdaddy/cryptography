###################################################################
###################################################################
###############     Simple & Correct Vaudenay Attack  #############
###################################################################
###################################################################

class VaudenayAttack:
    def __init__(self, oracle: object):
        """
        Initialize the attack with a padding oracle.
        """
        self._oracle = oracle
        self._query_count = 0

    def get_ciphertext(self) -> bytes:
        return self._oracle.get_ciphertext()

    def query(self, ciphertext: bytes) -> bool:
        self._query_count += 1
        result = self._oracle.query(ciphertext)
        return result

    def decrypt_block(self, ct_block: bytes, prev_block: bytes, is_hex_plaintext: bool = True) -> bytes:
        """
        Classic padding oracle attack - decrypt one block.
        """
        if len(ct_block) != 16 or len(prev_block) != 16:
            raise ValueError("Both blocks must be exactly 16 bytes")

        # The intermediate values (what comes out of AES decryption before XOR)
        intermediate = [0] * 16

        # Character sets to try
        if is_hex_plaintext:
            hex_chars = list(b'0123456789abcdefABCDEF')
            print(f"[*] Using hex optimization - trying {len(hex_chars)} chars per byte")

        print(f"[*] Decrypting block: {ct_block.hex()}")
        print(f"[*] Previous block: {prev_block.hex()}")

        # Attack each byte position from right to left
        for i in range(1, 17):  # i is the padding length we want to create
            pos = 16 - i  # position in the block (0-15)

            print(f"\n[*] Position {pos}: trying to create padding of length {i}")

            # Build a fake previous block
            fake_prev = bytearray(16)

            # Set bytes we already know to create the target padding
            for j in range(16 - i + 1, 16):
                fake_prev[j] = intermediate[j] ^ i

            found = False

            # Try hex characters first if enabled
            if is_hex_plaintext:
                for target_char in hex_chars:
                    # We want the plaintext at this position to be target_char
                    # plaintext = intermediate XOR prev_block
                    # So: intermediate = plaintext XOR prev_block = target_char XOR prev_block[pos]
                    desired_intermediate = target_char ^ prev_block[pos]

                    # For valid padding of length i, we need:
                    # intermediate XOR fake_prev[pos] = i
                    # So: fake_prev[pos] = intermediate XOR i
                    fake_prev[pos] = desired_intermediate ^ i

                    test_ct = bytes(fake_prev) + ct_block
                    if self.query(test_ct):
                        # Success! We found the correct intermediate value
                        intermediate[pos] = desired_intermediate
                        print(f"[+] Found hex char '{chr(target_char)}' at pos {pos}")
                        print(f"    intermediate[{pos}] = 0x{intermediate[pos]:02x}")
                        found = True
                        break

            # Fallback to trying all bytes
            if not found:
                print(f"[!] Hex failed for pos {pos}, trying all bytes...")
                for target_byte in range(256):
                    # We want the plaintext at this position to be target_byte
                    desired_intermediate = target_byte ^ prev_block[pos]
                    fake_prev[pos] = desired_intermediate ^ i

                    test_ct = bytes(fake_prev) + ct_block
                    if self.query(test_ct):
                        intermediate[pos] = desired_intermediate
                        print(f"[+] Found byte 0x{target_byte:02x} at pos {pos}")
                        found = True
                        break

            if not found:
                print(f"[!] FAILED to find anything for position {pos}")
                return None

        # Calculate final plaintext
        plaintext = bytes(intermediate[i] ^ prev_block[i] for i in range(16))
        print(f"[*] Final plaintext: {plaintext.hex()} -> {plaintext}")

        return plaintext

    def decrypt_ciphertext(self, is_hex_plaintext: bool = True) -> bytes:
        """Simple CBC decryption using padding oracle."""

        # Get the ciphertext
        full_ct = self.get_ciphertext()
        print(f"[*] Full ciphertext: {full_ct.hex()}")

        if len(full_ct) % 16 != 0:
            raise ValueError("Ciphertext length not multiple of 16")

        # Split into blocks
        blocks = [full_ct[i:i + 16] for i in range(0, len(full_ct), 16)]
        print(f"[*] Split into {len(blocks)} blocks")

        if len(blocks) < 2:
            raise ValueError("Need at least 2 blocks (IV + 1 ciphertext block)")

        # Decrypt each ciphertext block
        plaintext_blocks = []

        for i in range(1, len(blocks)):  # Skip IV (block 0)
            print(f"\n{'=' * 50}")
            print(f"DECRYPTING BLOCK {i} of {len(blocks) - 1}")
            print(f"{'=' * 50}")

            prev_block = blocks[i - 1]  # Previous block (IV for first, or previous CT block)
            curr_block = blocks[i]  # Current ciphertext block to decrypt

            plaintext_block = self.decrypt_block(curr_block, prev_block, is_hex_plaintext)

            if plaintext_block is None:
                raise Exception(f"Failed to decrypt block {i}")

            plaintext_blocks.append(plaintext_block)

        # Combine all plaintext blocks
        full_plaintext = b''.join(plaintext_blocks)

        # Remove PKCS7 padding
        try:
            pad_len = full_plaintext[-1]
            if 1 <= pad_len <= 16:
                # Check padding is valid
                if all(b == pad_len for b in full_plaintext[-pad_len:]):
                    full_plaintext = full_plaintext[:-pad_len]
                    print(f"[*] Removed {pad_len} bytes of PKCS7 padding")
        except:
            print("[!] Could not remove padding")

        return full_plaintext


###################################################################
###################################################################
###############     Fixed CryptoHack Client        ###############
###################################################################
###################################################################

import socket
import json


class CryptohackClient():
    def __init__(self, hostname, port):
        self.server_host = hostname
        self.server_port = port
        self.sock = None

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.server_host, self.server_port))
        print(f"Connected to server at {self.server_host}:{self.server_port}")

    def disconnect(self):
        if self.sock:
            self.sock.close()
            print("Disconnected from server.")

    def readline(self):
        packet = self.sock.recv(1)
        data = bytearray(packet)
        while packet and data[-1] != ord('\n'):
            packet = self.sock.recv(1)
            if not packet:
                return None
            data.extend(packet)
        return bytes(data)

    def json_recv(self):
        line = self.readline()
        return json.loads(line.decode())

    def json_send(self, data):
        request = json.dumps(data).encode() + b"\n"
        self.sock.sendall(request)


class CryptohackOracle():
    def __init__(self):
        hostname = "socket.cryptohack.org"
        port = 13421
        self.client = CryptohackClient(hostname, port)
        self.client.connect()
        welcome = self.client.readline()
        print(f"Server: {welcome.decode().strip()}")

    def query(self, ciphertext: bytes):
        ct_hex = ciphertext.hex()
        request = {"option": "unpad", "ct": ct_hex}
        self.client.json_send(request)
        response = self.client.json_recv()
        return response.get('result', False)

    def get_ciphertext(self):
        request = {"option": "encrypt"}
        self.client.json_send(request)
        response = self.client.json_recv()
        return bytes.fromhex(response['ct'])

    def check_plaintext(self, pt: bytes):
        try:
            message = pt.decode('utf-8')
        except:
            message = pt.decode('latin-1', errors='replace')

        request = {"option": "check", "message": message}
        self.client.json_send(request)
        return self.client.json_recv()


###################################################################
###################################################################
###############     Run Attack                      ###############
###################################################################
###################################################################

def run_attack():
    print("Starting Padding Oracle Attack")
    print("=" * 50)

    oracle = CryptohackOracle()
    attack = VaudenayAttack(oracle)

    try:
        # Decrypt with hex optimization
        plaintext = attack.decrypt_ciphertext(is_hex_plaintext=True)

        print(f"\n{'=' * 50}")
        print("FINAL RESULTS")
        print(f"{'=' * 50}")
        print(f"Queries made: {attack._query_count}")
        print(f"Plaintext length: {len(plaintext)} bytes")
        print(f"Plaintext (hex): {plaintext.hex()}")

        try:
            decoded = plaintext.decode('utf-8')
            print(f"Plaintext (text): {decoded}")
        except:
            print("Could not decode as UTF-8")

        # Get the flag
        print(f"\nSubmitting to server...")
        result = oracle.check_plaintext(plaintext)
        print(f"Server response: {result}")

        if 'flag' in result:
            print(f"\n🚩 FLAG: {result['flag']}")

        return plaintext

    except Exception as e:
        print(f"Attack failed: {e}")
        import traceback
        traceback.print_exc()
        return None

    finally:
        try:
            oracle.client.disconnect()
        except:
            pass


if __name__ == "__main__":
    run_attack()