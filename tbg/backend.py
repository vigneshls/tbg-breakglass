"""Cryptographic backends for TBG.

Three backends share one interface so that every experiment can be rerun
with a different primitive set on the same machine:

  pq-oqs      ML-KEM-768 / ML-DSA-65 from liboqs (C) via liboqs-python
  pq-pure     ML-KEM-768 / ML-DSA-65 from kyber-py / dilithium-py (pure Python)
  classical   ECDH P-256 (ephemeral-static, as a KEM) / ECDSA P-256 via OpenSSL

AES-256-GCM, HKDF-SHA-256 and SHA-256 always come from the `cryptography`
package (OpenSSL). Every result row records which backend produced it.
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from typing import Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# --------------------------------------------------------------------------
# Symmetric helpers (identical for all backends)
# --------------------------------------------------------------------------
def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hkdf(ikm: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info).derive(ikm)


def aead_encrypt(key: bytes, nonce: bytes, pt: bytes, ad: bytes) -> bytes:
    return AESGCM(key).encrypt(nonce, pt, ad)


def aead_decrypt(key: bytes, nonce: bytes, ct: bytes, ad: bytes) -> bytes:
    return AESGCM(key).decrypt(nonce, ct, ad)


def random_bytes(n: int) -> bytes:
    return os.urandom(n)


# --------------------------------------------------------------------------
# Backend interface
# --------------------------------------------------------------------------
class Backend:
    name: str = "abstract"
    kem_name: str = ""
    sig_name: str = ""

    # KEM
    def kem_keygen(self) -> Tuple[bytes, bytes]:  # (ek, dk)
        raise NotImplementedError

    def kem_encaps(self, ek: bytes) -> Tuple[bytes, bytes]:  # (ct, ss)
        raise NotImplementedError

    def kem_decaps(self, dk: bytes, ct: bytes) -> bytes:
        raise NotImplementedError

    # Signature
    def sig_keygen(self) -> Tuple[bytes, bytes]:  # (vk, sk)
        raise NotImplementedError

    def sign(self, sk: bytes, msg: bytes) -> bytes:
        raise NotImplementedError

    def verify(self, vk: bytes, msg: bytes, sig: bytes) -> bool:
        raise NotImplementedError

    def describe(self) -> dict:
        return {"backend": self.name, "kem": self.kem_name, "sig": self.sig_name}


# --------------------------------------------------------------------------
# liboqs (C) backend
# --------------------------------------------------------------------------
class OqsBackend(Backend):
    name = "pq-oqs"
    kem_name = "ML-KEM-768"
    sig_name = "ML-DSA-65"

    def __init__(self) -> None:
        import oqs  # raises if liboqs is not available

        self._oqs = oqs
        if self.kem_name not in oqs.get_enabled_kem_mechanisms():
            raise RuntimeError("liboqs build lacks ML-KEM-768")
        if self.sig_name not in oqs.get_enabled_sig_mechanisms():
            raise RuntimeError("liboqs build lacks ML-DSA-65")

    def kem_keygen(self):
        with self._oqs.KeyEncapsulation(self.kem_name) as k:
            ek = k.generate_keypair()
            dk = k.export_secret_key()
        return bytes(ek), bytes(dk)

    def kem_encaps(self, ek):
        with self._oqs.KeyEncapsulation(self.kem_name) as k:
            ct, ss = k.encap_secret(ek)
        return bytes(ct), bytes(ss)

    def kem_decaps(self, dk, ct):
        with self._oqs.KeyEncapsulation(self.kem_name, secret_key=dk) as k:
            return bytes(k.decap_secret(ct))

    def sig_keygen(self):
        with self._oqs.Signature(self.sig_name) as s:
            vk = s.generate_keypair()
            sk = s.export_secret_key()
        return bytes(vk), bytes(sk)

    def sign(self, sk, msg):
        with self._oqs.Signature(self.sig_name, secret_key=sk) as s:
            return bytes(s.sign(msg))

    def verify(self, vk, msg, sig):
        with self._oqs.Signature(self.sig_name) as s:
            return bool(s.verify(msg, sig, vk))

    def describe(self):
        d = super().describe()
        d["liboqs_version"] = self._oqs.oqs_version()
        d["liboqs_python_version"] = self._oqs.oqs_python_version()
        return d


# --------------------------------------------------------------------------
# Pure-Python backend (reference implementations, slow)
# --------------------------------------------------------------------------
class PurePythonBackend(Backend):
    name = "pq-pure"
    kem_name = "ML-KEM-768"
    sig_name = "ML-DSA-65"

    def __init__(self) -> None:
        from kyber_py.ml_kem import ML_KEM_768
        from dilithium_py.ml_dsa import ML_DSA_65

        self._kem = ML_KEM_768
        self._sig = ML_DSA_65

    def kem_keygen(self):
        ek, dk = self._kem.keygen()
        return ek, dk

    def kem_encaps(self, ek):
        ss, ct = self._kem.encaps(ek)  # kyber-py returns (key, ciphertext)
        return ct, ss

    def kem_decaps(self, dk, ct):
        return self._kem.decaps(dk, ct)

    def sig_keygen(self):
        vk, sk = self._sig.keygen()
        return vk, sk

    def sign(self, sk, msg):
        return self._sig.sign(sk, msg)

    def verify(self, vk, msg, sig):
        return bool(self._sig.verify(vk, msg, sig))

    def describe(self):
        d = super().describe()
        try:
            from importlib.metadata import version

            d["kyber_py_version"] = version("kyber-py")
            d["dilithium_py_version"] = version("dilithium-py")
        except Exception:  # pragma: no cover
            pass
        return d


# --------------------------------------------------------------------------
# Classical baseline: ECDH P-256 as a KEM, ECDSA P-256 signatures (OpenSSL)
# --------------------------------------------------------------------------
_P256 = ec.SECP256R1()


def _pub_bytes(pub) -> bytes:
    return pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


class ClassicalBackend(Backend):
    name = "classical"
    kem_name = "ECDH-P256 (ephemeral-static KEM)"
    sig_name = "ECDSA-P256-SHA256"

    def kem_keygen(self):
        sk = ec.generate_private_key(_P256)
        dk = sk.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption())
        return _pub_bytes(sk.public_key()), dk

    def kem_encaps(self, ek):
        peer = ec.EllipticCurvePublicKey.from_encoded_point(_P256, ek)
        eph = ec.generate_private_key(_P256)
        ct = _pub_bytes(eph.public_key())
        z = eph.exchange(ec.ECDH(), peer)
        return ct, hkdf(z, b"TBG-DHKEM" + ct + ek)

    def kem_decaps(self, dk, ct):
        sk = serialization.load_der_private_key(dk, password=None)
        eph = ec.EllipticCurvePublicKey.from_encoded_point(_P256, ct)
        z = sk.exchange(ec.ECDH(), eph)
        return hkdf(z, b"TBG-DHKEM" + ct + _pub_bytes(sk.public_key()))

    def sig_keygen(self):
        sk = ec.generate_private_key(_P256)
        skb = sk.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                               serialization.NoEncryption())
        return _pub_bytes(sk.public_key()), skb

    def sign(self, sk, msg):
        key = serialization.load_der_private_key(sk, password=None)
        return key.sign(msg, ec.ECDSA(hashes.SHA256()))

    def verify(self, vk, msg, sig):
        from cryptography.exceptions import InvalidSignature

        pub = ec.EllipticCurvePublicKey.from_encoded_point(_P256, vk)
        try:
            pub.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False


# --------------------------------------------------------------------------
def get_backend(name: str = "pq") -> Backend:
    """Return a backend. 'pq' prefers liboqs and falls back to pure Python."""
    if name == "pq-oqs":
        return OqsBackend()
    if name == "pq-pure":
        return PurePythonBackend()
    if name == "classical":
        return ClassicalBackend()
    if name == "pq":
        try:
            return OqsBackend()
        except Exception as exc:  # noqa: BLE001
            print(f"[backend] liboqs unavailable ({exc!s:.80}); using pure-Python ML-KEM/ML-DSA")
            return PurePythonBackend()
    raise ValueError(f"unknown backend {name!r}")
