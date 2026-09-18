from pathlib import Path
import os

from dotenv import load_dotenv

# 3 parents up to reach project root from this config.py
load_dotenv(Path(__file__).resolve().parents[3] / ".env", override=True)

# Target domain for the whole recon pipeline; override via .env (TARGET=...)
TARGET = os.getenv("TARGET", "qbsco.net")
