"""Pydantic-модели запросов и ответов Tinode REST Auth протокола."""

from __future__ import annotations
from pydantic import BaseModel


# ── Входящие от Tinode ────────────────────────────────────────


class AuthRecord(BaseModel):
    """Запись аутентификации (часть запроса)."""
    uid: str | None = None
    authlvl: str | None = None
    lifetime: str | None = None
    features: int | None = None
    tags: list[str] | None = None
    state: str | None = None


class TinodeRequest(BaseModel):
    """Общий формат запроса от Tinode к auth-сервису."""
    endpoint: str | None = None
    secret: str | None = None
    addr: str | None = None
    rec: AuthRecord | None = None


# ── Исходящие к Tinode ────────────────────────────────────────


class AuthRecordResponse(BaseModel):
    """Запись аутентификации (часть ответа)."""
    uid: str | None = None
    authlvl: str | None = None
    lifetime: str | None = None
    features: int | None = None
    tags: list[str] | None = None
    state: str | None = None


class NewAccount(BaseModel):
    """Данные для создания нового аккаунта в Tinode."""
    auth: str = "JRWPS"
    anon: str = "N"
    public: dict | None = None
    trusted: dict | None = None
    private: dict | None = None


class TinodeResponse(BaseModel):
    """Общий формат ответа auth-сервиса для Tinode."""
    err: str | None = None
    rec: AuthRecordResponse | None = None
    byteval: str | None = None
    ts: str | None = None
    boolval: bool | None = None
    strarr: list[str] | None = None
    newacc: NewAccount | None = None

    class Config:
        # Не включать None-поля в JSON
        exclude_none = True  # Убирает из ответа поля, которые не нужны


class ErrorResponse(BaseModel):
    err: str