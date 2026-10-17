"""
AVISO: aplicação PROPOSITALMENTE VULNERÁVEL.
Criada apenas como alvo de testes para o scanner do projeto Delivery-DevSecOps.
Nunca use este código em produção.
"""
import hashlib
import logging
import sqlite3

import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Delivery API (vulnerável de propósito)")
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("delivery")

SECRET_KEY = "super-secret-key-123"
DB_PASSWORD = "admin123"

db = sqlite3.connect(":memory:", check_same_thread=False)
db.executescript(
    """
    CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, password_hash TEXT);
    CREATE TABLE orders (
        id INTEGER PRIMARY KEY, user_id INTEGER, item TEXT, total REAL, paid INTEGER
    );
    """
)
db.execute(
    "INSERT INTO users (email, password_hash) VALUES (?, ?)",
    ("entregador1@exemplo.com", hashlib.md5(b"123456").hexdigest()),
)
db.execute(
    "INSERT INTO users (email, password_hash) VALUES (?, ?)",
    ("entregador2@exemplo.com", hashlib.md5(b"senha123").hexdigest()),
)
db.execute("INSERT INTO orders (user_id, item, total, paid) VALUES (1, 'Pizza', 59.9, 1)")
db.execute("INSERT INTO orders (user_id, item, total, paid) VALUES (2, 'Sushi', 89.9, 1)")
db.commit()


class LoginRequest(BaseModel):
    email: str
    password: str


class CheckoutRequest(BaseModel):
    user_id: int
    item: str
    quantity: int
    unit_price: float
    coupon: str | None = None


@app.post("/login")
def login(data: LoginRequest):
    logger.info("Tentativa de login: %s / %s", data.email, data.password)
    password_hash = hashlib.md5(data.password.encode()).hexdigest()
    query = (
        f"SELECT id FROM users WHERE email = '{data.email}' "
        f"AND password_hash = '{password_hash}'"
    )
    row = db.execute(query).fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="Credenciais inválidas")
    token = hashlib.md5((data.email + SECRET_KEY).encode()).hexdigest()
    return {"user_id": row[0], "token": token}


@app.get("/orders/{order_id}")
def get_order(order_id: int):
    row = db.execute(
        "SELECT id, user_id, item, total, paid FROM orders WHERE id = ?", (order_id,)
    ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Pedido não encontrado")
    return {"id": row[0], "user_id": row[1], "item": row[2], "total": row[3], "paid": row[4]}


@app.post("/checkout")
def checkout(data: CheckoutRequest):
    total = data.quantity * data.unit_price
    if data.coupon == "PROMO50":
        total = total * 0.5
    db.execute(
        "INSERT INTO orders (user_id, item, total, paid) VALUES (?, ?, ?, 1)",
        (data.user_id, data.item, total),
    )
    db.commit()
    return {"status": "pago", "total": total}


@app.get("/users/search")
def search_users(term: str):
    query = f"SELECT id, email FROM users WHERE email LIKE '%{term}%'"
    rows = db.execute(query).fetchall()
    return [{"id": r[0], "email": r[1]} for r in rows]


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
