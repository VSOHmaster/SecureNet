import typer
from getpass import getpass
import json
from sqlalchemy.orm import Session
from typing import Optional

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'server')))

from server import models, utils
from server.database import SessionLocal, init_db as db_init_db
from server.models import User
from server.config import config

app = typer.Typer()

class DBSession:
    def __enter__(self):
        self.db = SessionLocal()
        return self.db
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.db:
            self.db.close()

@app.command(name="init-db")
def init_db_command():
    typer.echo("Initializing database...")
    db_init_db()
    typer.echo("Database initialization complete.")

@app.command(name="create-admin")
def create_admin_command(
    username: str = typer.Option(..., prompt="Enter username for admin"),
    email: Optional[str] = typer.Option(None, prompt="Enter admin email (optional)", prompt_required=False),
    password: str = typer.Option(..., prompt="Enter password", hide_input=True, confirmation_prompt=True)
):
    typer.echo(f"Attempting to create admin user: {username}")

    with DBSession() as db:
        existing_user = User.get_by_username(db, username)
        if existing_user:
            typer.echo(typer.style(f"Error: User '{username}' already exists.", fg=typer.colors.RED))
            raise typer.Exit(code=1)

        admin_user = User(
            username=username,
            email=email if email else None,
            is_admin=True
        )
        admin_user.set_password(password)
        db.add(admin_user)
        try:
            db.commit()
            typer.echo(typer.style(f"Admin user '{username}' created successfully.", fg=typer.colors.GREEN))
        except Exception as e:
            db.rollback()
            typer.echo(typer.style(f"Error creating admin user: {e}", fg=typer.colors.RED))
            raise typer.Exit(code=1)

@app.command(name="update-oui")
def update_oui_command(
    force_download: bool = typer.Option(False, "--force", "-f", help="Force download even if file exists.")
):
    typer.echo("Starting OUI database update...")
    if utils.update_oui_data(force_download=force_download):
         typer.echo(typer.style("OUI update completed successfully.", fg=typer.colors.GREEN))
    else:
         typer.echo(typer.style("OUI update failed.", fg=typer.colors.RED))

if __name__ == "__main__":
    app()
