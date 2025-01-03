from os.path import join
from os import getcwd

HOST = "0.0.0.0"
PORT = 5000

TEMPLATE_FOLDER = join(getcwd(), "app", "templates")
STATIC_FOLDER = join(getcwd(), "app", "static")

CERTS = join(getcwd(), "certs")
CERT_PEM = join(CERTS, "cert.pem")
KEY_PEM = join(CERTS, "key.pem")
OPENSSL_CONFIG = join(getcwd(), "certs", "openssl.cnf")