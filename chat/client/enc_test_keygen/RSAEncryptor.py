import base64
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pss
from Crypto.Hash import SHA256


def generate_aes_key():
    return get_random_bytes(32)  # AES-256


def encrypt_with_aes(key: bytes, plaintext: str) -> dict:
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    return {
        'ciphertext': base64.b64encode(ciphertext).decode(),
        'nonce': base64.b64encode(cipher.nonce).decode(),
        'tag': base64.b64encode(tag).decode(),
    }


def decrypt_with_aes(key: bytes, data: dict) -> str:
    ciphertext = base64.b64decode(data['ciphertext'])
    nonce = base64.b64decode(data['nonce'])
    tag = base64.b64decode(data['tag'])
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode()


def _as_rsa_key(key_or_pem):
    """Accepts either a PEM string or an already-imported RSA key object,
    so callers can parse a key once and reuse it across many operations."""
    return key_or_pem if isinstance(key_or_pem, RSA.RsaKey) else RSA.import_key(key_or_pem)


def encrypt_aes_key_with_rsa(public_key_pem, aes_key: bytes) -> str:
    public_key = _as_rsa_key(public_key_pem)
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_key = cipher_rsa.encrypt(aes_key)
    return base64.b64encode(encrypted_key).decode()


def decrypt_aes_key_with_rsa(private_key_pem, encrypted_key_b64: str) -> bytes:
    encrypted_key = base64.b64decode(encrypted_key_b64)
    private_key = _as_rsa_key(private_key_pem)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    return cipher_rsa.decrypt(encrypted_key)


def sign_message(private_key_pem, message: str) -> str:
    key = _as_rsa_key(private_key_pem)
    h = SHA256.new(message.encode())
    signer = pss.new(key)
    signature = signer.sign(h)
    return base64.b64encode(signature).decode()


def verify_signature(public_key_pem, message: str, signature_b64: str) -> bool:
    key = _as_rsa_key(public_key_pem)
    h = SHA256.new(message.encode())
    verifier = pss.new(key)
    signature = base64.b64decode(signature_b64)
    try:
        verifier.verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False


