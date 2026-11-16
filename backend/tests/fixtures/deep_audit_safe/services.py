"""Service / DAO layer of the safe control fixture."""
from db import catalog, cursor


def load_profile(user_id):
    # parameterized query; the identifier is bound, never interpolated.
    sql = "SELECT id, email, phone FROM users WHERE id = %s"
    return cursor.execute(sql, (user_id,)).fetchone()


def run_sql_query(keyword):
    sql = "SELECT * FROM items WHERE name LIKE %s"
    return cursor.execute(sql, ("%" + keyword + "%",)).fetchall()


def create_order(sku, quantity):
    # Server-side amount recomputation from the catalogue.
    unit_price = catalog.price_from_db(sku)
    amount = unit_price * quantity
    return {"charged": amount, "status": "paid"}
