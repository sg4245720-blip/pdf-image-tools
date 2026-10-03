import os

import psycopg
from dotenv import load_dotenv


load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")


class DatabaseRow:
    def __init__(self, cursor, values):
        self._data = {
            column.name: value
            for column, value in zip(cursor.description, values)
        }

    def __getitem__(self, key):
        if isinstance(key, int):
            return list(self._data.values())[key]

        return self._data[key]

    def keys(self):
        return self._data.keys()

    def get(self, key, default=None):
        return self._data.get(key, default)


class DatabaseConnection:
    def __init__(self, connection):
        self.connection = connection

    def execute(self, query, parameters=()):
        query = query.replace("?", "%s")

        cursor = self.connection.cursor()
        cursor.execute(query, parameters)

        return DatabaseCursor(self.connection, cursor)

    def commit(self):
        self.connection.commit()

    def close(self):
        self.connection.close()


class DatabaseCursor:
    def __init__(self, connection, cursor):
        self.connection = connection
        self.cursor = cursor

    def fetchone(self):
        row = self.cursor.fetchone()

        if row is None:
            return None

        return DatabaseRow(self.cursor, row)

    def fetchall(self):
        rows = self.cursor.fetchall()

        return [
            DatabaseRow(self.cursor, row)
            for row in rows
        ]


def get_connection():
    if not DATABASE_URL:
        raise RuntimeError(
            "DATABASE_URL is missing. "
            "Please add DATABASE_URL to the .env file."
        )

    connection = psycopg.connect(DATABASE_URL)

    return DatabaseConnection(connection)


def create_tables():
    connection = get_connection()

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS files (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            tool_name TEXT NOT NULL,
            file_path TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id)
                REFERENCES users(id)
        )
        """
    )

    connection.commit()
    connection.close()