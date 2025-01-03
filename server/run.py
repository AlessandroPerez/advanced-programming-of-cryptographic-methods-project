from flask import Flask

from app import params
from app import routes

if __name__ == "__main__":

    app = Flask(__name__, template_folder=params.TEMPLATE_FOLDER, static_folder=params.STATIC_FOLDER)
    app.register_blueprint(routes.main)
    app.run(host=params.HOST, port=params.PORT, ssl_context=(params.CERT_PEM, params.KEY_PEM))