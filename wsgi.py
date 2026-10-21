
from app import app, init_db

# Create the database tables before Gunicorn serves the website.
init_db()