"""Safe control fixture for Deep Audit V1 acceptance.

Same routes and the same call chain as the vulnerable fixture, but with the
corresponding security controls. Expected: no Deep Audit candidate findings.
"""
from flask import Flask, abort, jsonify, request
from flask_login import current_user, login_required

from services import create_order, load_profile, run_sql_query

app = Flask(__name__)


@app.route("/user/<int:user_id>/profile", methods=["GET"])
@login_required
def profile(user_id):
    if current_user.id != user_id:
        abort(403)
    return jsonify(load_profile(user_id))


@app.route("/search", methods=["GET"])
def search():
    keyword = request.args.get("q", "")
    return jsonify(run_sql_query(keyword))


@app.route("/order", methods=["POST"])
def order():
    sku = request.json.get("sku")
    quantity = request.json.get("quantity")
    return jsonify(create_order(sku, quantity))
