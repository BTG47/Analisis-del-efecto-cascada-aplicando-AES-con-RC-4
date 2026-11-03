"""Permite que pytest encuentre los módulos de la raíz (aes256, padding, ...).

No contiene tests. Existe para que ``import aes256`` funcione tanto con
``pytest`` como con ``python -m pytest`` desde el directorio AES/.
"""
