"""Centralised configuration loaded from environment / .env file.

All secrets MUST come from the environment. Never commit a populated .env.
"""
from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
BLUEPRINT_DIR = DATA_DIR / "blueprints"
DECOY_DIR = DATA_DIR / "decoys"
LOG_DIR = DATA_DIR / "logs"
TEMPLATE_DIR = BASE_DIR / "generator" / "templates"

for _p in (DATA_DIR, BLUEPRINT_DIR, DECOY_DIR, LOG_DIR):
    _p.mkdir(parents=True, exist_ok=True)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(BASE_DIR.parent / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Architect (offline blueprint generation) ---
    architect_provider: Literal["groq", "ollama"] = "groq"
    groq_api_key: str = Field(default="", description="API key for Groq cloud LLM")
    groq_model: str = "llama-3.1-8b-instant"

    # --- Responder (runtime attack response mutation) ---
    responder_provider: Literal["ollama", "groq"] = "ollama"
    ollama_url: str = "http://localhost:11434/api/generate"
    ollama_model: str = "llama3.2:3b"
    responder_timeout_s: int = 15
    responder_cache_size: int = 512

    # --- ZAP false positives source ---
    fp_alerts_path: Path = BASE_DIR.parent / "ZAP" / "fp_alerts.json"

    # --- Generated artifacts ---
    blueprint_path: Path = BLUEPRINT_DIR / "current_blueprint.json"
    fake_db_path: Path = DATA_DIR / "fake_app.sqlite"
    honeytoken_path: Path = DATA_DIR / "honeytokens.json"
    interactions_log: Path = LOG_DIR / "interactions.jsonl"
    leak_log: Path = LOG_DIR / "honeytoken_leaks.jsonl"

    # --- Runtime ---
    flask_host: str = "0.0.0.0"
    flask_port: int = 5000
    flask_debug: bool = False
    secret_key: str = "change-me-in-prod-32-bytes-or-more"

    # --- Deception behaviour ---
    tarpit_enabled: bool = True
    tarpit_base_delay_ms: int = 80
    tarpit_max_delay_ms: int = 4000
    tarpit_growth: float = 1.4
    fake_db_rows_per_table: int = 50

    # --- SSH bridge (Cowrie) ---
    ssh_bridge_enabled: bool = True
    cowrie_credentials_file: Path = BASE_DIR.parent / "honeypot" / "data" / "ssh_credentials.json"

    # --- Dashboard ---
    dashboard_refresh_s: int = 3


settings = Settings()
