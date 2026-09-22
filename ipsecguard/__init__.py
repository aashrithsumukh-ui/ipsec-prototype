"""IPsecGuard AI — core analysis pipeline.

Two engines, kept strictly separate:
  * parser  -> OBSERVED fields (read from genuinely-plaintext IKE_SA_INIT)
  * ml       -> INFERRED fields (from encrypted-traffic metadata)

Every finding is tagged by how it was derived. The system never decrypts payloads.
"""
__version__ = "0.1.0"
