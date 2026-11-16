"""Intentionally vulnerable fixture for Deep Audit V1 acceptance.

Known expected findings:
  1. authz            /user/<id>/profile -- no ownership check (horizontal IDOR)
  2. injection        /search -- SQL built with string formatting
  3. business_logic   /order -- client-supplied amount trusted by the service
"""
from flask import Flask, jsonify, request

from services import create_order, load_profile, run_sql_query

app = Flask(__name__)


@app.route("/user/<int:user_id>/profile", methods=["GET"])
def profile(user_id):
    user_id = request.args.get("user_id", user_id)
    return jsonify(load_profile(user_id))


@app.route("/search", methods=["GET"])
def search():
    keyword = request.args.get("q", "")
    return jsonify(run_sql_query(keyword))


@app.route("/order", methods=["POST"])
def order():
    amount = request.json.get("amount")
    return jsonify(create_order(amount))
