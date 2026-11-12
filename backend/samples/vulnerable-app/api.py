"""Sample API with authorization and business logic flaws."""

from flask import Flask, request, jsonify

app = Flask(__name__)

# Fake in-memory store
USERS = {1: {"id": 1, "name": "alice", "role": "user", "balance": 100}}
ORDERS = {101: {"id": 101, "user_id": 1, "amount": 50, "status": "pending"}}
COUPONS = {"SAVE10": {"code": "SAVE10", "used": False, "discount": 10}}


def get_current_user_id():
    # Weak: trusts client-supplied header without verification
    return int(request.headers.get("X-User-Id", "1"))


@app.route("/api/orders/<int:order_id>", methods=["GET"])
def get_order(order_id: int):
    # IDOR: no ownership check
    order = ORDERS.get(order_id)
    if not order:
        return jsonify({"error": "not found"}), 404
    return jsonify(order)


@app.route("/api/admin/users", methods=["GET"])
def list_all_users():
    # Missing role check - any logged-in user can access admin API
    user_id = get_current_user_id()
    if user_id:
        return jsonify(list(USERS.values()))
    return jsonify({"error": "unauthorized"}), 401


@app.route("/api/transfer", methods=["POST"])
def transfer():
    data = request.json or {}
    from_id = get_current_user_id()
    to_id = data.get("to_user_id")
    amount = data.get("amount", 0)

    # Business logic: no balance check, no transaction lock (race condition)
    if from_id in USERS and to_id in USERS:
        USERS[from_id]["balance"] -= amount
        USERS[to_id]["balance"] += amount
        return jsonify({"ok": True})
    return jsonify({"error": "invalid users"}), 400


@app.route("/api/coupon/redeem", methods=["POST"])
def redeem_coupon():
    code = (request.json or {}).get("code")
    coupon = COUPONS.get(code)
    if not coupon:
        return jsonify({"error": "invalid"}), 400

    # Business logic: coupon can be redeemed multiple times (no used flag update)
    discount = coupon["discount"]
    return jsonify({"discount": discount, "message": "applied"})


@app.route("/api/orders/<int:order_id>/approve", methods=["POST"])
def approve_order(order_id: int):
    order = ORDERS.get(order_id)
    if not order:
        return jsonify({"error": "not found"}), 404

    # Workflow bypass: client can skip payment and directly approve
    body = request.json or {}
    if body.get("force_approve"):
        order["status"] = "approved"
        return jsonify(order)

    if order["status"] == "paid":
        order["status"] = "approved"
        return jsonify(order)
    return jsonify({"error": "not paid"}), 400


if __name__ == "__main__":
    app.run(debug=True)
