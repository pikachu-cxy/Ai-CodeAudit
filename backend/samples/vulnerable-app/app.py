"""Intentionally vulnerable sample for security audit demo."""

import os
import sqlite3


def get_user(username: str) -> dict:
  # SQL injection vulnerability
  conn = sqlite3.connect("users.db")
  query = f"SELECT * FROM users WHERE username = '{username}'"
  return conn.execute(query).fetchone()


def run_command(user_input: str) -> str:
  # Command injection vulnerability
  return os.popen(user_input).read()


def render_template(name: str) -> str:
  # XSS-style template injection
  template = "<h1>Hello " + name + "</h1>"
  return template


def eval_code(code: str):
  # Dangerous eval
  return eval(code)


if __name__ == "__main__":
  user = input("Enter username: ")
  print(get_user(user))
