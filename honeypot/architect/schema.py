"""Strongly-typed schema for a Deception Blueprint.

The Architect LLM is constrained to produce JSON matching these models.
The Generator and Runtime both consume the same schema, so any change
propagates type-safely across the project.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal, Optional

from pydantic import BaseModel, Field


# ---------- Persona ----------
class AppPersona(BaseModel):
    name: str = Field(..., description="Display name of the fake application")
    tagline: str = Field(..., description="Short marketing-style tagline shown in the UI")
    industry: str = Field(..., description="e.g. 'e-commerce', 'banking', 'iot dashboard'")
    tech_stack: list[str] = Field(default_factory=list, description="Headers / footer signatures to leak")
    server_header: str = Field(default="Apache/2.4.41 (Ubuntu)")
    powered_by: str = Field(default="PHP/7.4.3")


# ---------- Fake DB ----------
SUPPORTED_FAKER = Literal[
    "name", "first_name", "last_name", "email", "user_name", "password",
    "address", "city", "country", "phone_number", "company", "job",
    "credit_card_number", "iban", "uuid4", "ipv4", "url", "user_agent",
    "date_time", "text", "sentence", "word", "pyint", "pyfloat", "boolean",
    "product_name", "price",
]


class FakeColumn(BaseModel):
    name: str
    sql_type: Literal["INTEGER", "TEXT", "REAL", "BLOB"] = "TEXT"
    faker_provider: SUPPORTED_FAKER = "word"
    primary_key: bool = False


class FakeTable(BaseModel):
    name: str
    columns: list[FakeColumn]
    row_count: int = 50


# ---------- Honeytokens ----------
HONEYTOKEN_TYPE = Literal[
    "ssh_credentials", "aws_key", "jwt", "api_key", "db_password", "admin_session"
]
LEAK_METHOD = Literal[
    "robots_txt", "backup_file", "env_file", "git_config",
    "html_comment", "api_error_message", "directory_listing", "swagger_doc",
]


class Honeytoken(BaseModel):
    token_id: str = Field(..., description="Unique ID embedded in the token for tracking")
    type: HONEYTOKEN_TYPE
    username: Optional[str] = None
    password: Optional[str] = None
    extra: dict = Field(default_factory=dict)
    leak_path: str = Field(..., description="URL path where the token can be discovered")
    leak_method: LEAK_METHOD
    leak_hint: str = Field(..., description="Plain-text explanation of how an attacker stumbles on it")


# ---------- Trap endpoints ----------
VULN_FAMILY = Literal[
    "sql_injection", "reflected_xss", "stored_xss", "open_redirect",
    "private_ip_disclosure", "info_disclosure_debug", "directory_browsing",
    "path_traversal", "ssrf", "broken_auth", "csrf", "command_injection",
    "generic_500",
]


class TrapEndpoint(BaseModel):
    path: str = Field(..., description="URL path, e.g. /rest/products/search")
    method: Literal["GET", "POST", "PUT", "DELETE"] = "GET"
    parameter: Optional[str] = Field(default=None, description="Parameter name the FP was raised on")
    vuln_family: VULN_FAMILY
    source_fp_alert_id: str = Field(..., description="Original alert_id from fp_alerts.json")
    trigger_keywords: list[str] = Field(
        default_factory=list,
        description="Substrings in the payload that activate the deceptive response",
    )
    decoy_template: str = Field(
        ...,
        description="Static fallback used when LLM is unreachable; supports {payload} placeholder",
    )
    llm_mutation_prompt: str = Field(
        ...,
        description="System prompt for the runtime LLM to mutate the response convincingly",
    )
    leaks_honeytoken_id: Optional[str] = Field(
        default=None,
        description="If set, exploiting this trap surfaces the referenced honeytoken",
    )


# ---------- Breadcrumbs ----------
BREADCRUMB_KIND = Literal[
    "robots_txt", "sitemap_xml", "env_file", "backup_archive",
    "git_config", "git_head", "swagger_doc", "directory_listing",
    "html_comment_hint",
]


class Breadcrumb(BaseModel):
    kind: BREADCRUMB_KIND
    path: str
    content: str = Field(..., description="Raw content served at the path (may embed honeytokens)")
    discovery_hint: str = Field(..., description="Where in the app it is hinted at (e.g. footer link, comment in /login)")


# ---------- Blueprint root ----------
class DeceptionBlueprint(BaseModel):
    blueprint_id: str
    generated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    persona: AppPersona
    fake_db: list[FakeTable]
    traps: list[TrapEndpoint]
    honeytokens: list[Honeytoken]
    breadcrumbs: list[Breadcrumb]
    enabled_legit_pages: list[str] = Field(
        default_factory=lambda: ["home", "login", "dashboard", "search", "profile", "about"],
        description="Subset of built-in legit pages to render",
    )
