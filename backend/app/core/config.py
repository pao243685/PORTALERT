import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.environ["DATABASE_URL"]
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173")