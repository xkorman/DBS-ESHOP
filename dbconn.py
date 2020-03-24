import psycopg2
from psycopg2._psycopg import cursor


def connection():
    conn = psycopg2.connect(
        host="localhost",
        user="xkorman",
        password="password",
        database="dbs_eshop",
        port="5432"
    )

    c = conn.cursor()

    return c, conn
