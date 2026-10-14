from flask import Flask, jsonify
import requests
import yaml

app = Flask(__name__)


@app.get("/health")
def health():
    return jsonify(status="ok")


@app.get("/version")
def version():
    return jsonify(requests=requests.__version__, yaml=yaml.__version__)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
