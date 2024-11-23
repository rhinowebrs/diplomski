from app import create_app, db
from flask_migrate import Migrate
from flask.cli import with_appcontext

app = create_app()
migrate = Migrate(app, db)

# Expose db commands to Flask CLI
import click

@click.command(name='create_db')
@with_appcontext
def create_db():
    db.create_all()

app.cli.add_command(create_db)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
