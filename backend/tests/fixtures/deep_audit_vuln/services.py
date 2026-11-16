"""Service / DAO layer of the vulnerable fixture (cross-file call chain)."""
from db import cursor


def load_profile(user_id):
    query = f"SELECT id, email, phone FROM users WHERE id = {user_id}"
    return cursor.execute(query).fetchone()


def run_sql_query(keyword):
    query = "SELECT * FROM items WHERE name LIKE '%" + keyword + "%'"
    return cursor.execute(query).fetchall()


def create_order(amount):
    # No server-side price recomputation: the client value is trusted.
    return {"charged": amount, "status": "paid"}
