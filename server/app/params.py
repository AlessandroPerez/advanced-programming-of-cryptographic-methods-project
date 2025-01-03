from os.path import join, dirname, abspath
from os import getcwd

HOST = "0.0.0.0"
PORT = 5000

ROOT = dirname(abspath(__file__))

TEMPLATE_FOLDER = join(ROOT, "templates")
STATIC_FOLDER = join(ROOT, "static")

CERTS = join(dirname(ROOT), "certs")
CERT_PEM = join(CERTS, "cert.pem")
KEY_PEM = join(CERTS, "key.pem")
OPENSSL_CONFIG = join(getcwd(), "certs", "openssl.cnf")