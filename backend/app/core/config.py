import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Database
    database_url: str = Field(default_factory=lambda: os.getenv("DATABASE_URL", "sqlite:///./trusttrace.db"))
    
    # AI Explanation
    gemini_api_key: str = Field(default_factory=lambda: os.getenv("GEMINI_API_KEY", ""))
    gemini_model: str = Field(default_factory=lambda: os.getenv("GEMINI_MODEL", "gemini-2.5-flash"))
    
    # Threat Intelligence
    urlhaus_auth_key: str = Field(default_factory=lambda: os.getenv("URLHAUS_AUTH_KEY", ""))
    google_safe_browsing_key: str = Field(default_factory=lambda: os.getenv("GOOGLE_SAFE_BROWSING_KEY", ""))
    
    # Web3 / Blockchain
    chain_rpc_url: str = Field(default_factory=lambda: os.getenv("CHAIN_RPC_URL", "http://127.0.0.1:8545"))
    chain_id: int = Field(default_factory=lambda: int(os.getenv("CHAIN_ID", "31337")))
    chain_name: str = Field(default_factory=lambda: os.getenv("CHAIN_NAME", "Hardhat Local"))
    contract_address: str = Field(default_factory=lambda: os.getenv("CONTRACT_ADDRESS", ""))
    relayer_private_key: str = Field(default_factory=lambda: os.getenv("RELAYER_PRIVATE_KEY", ""))
    validator_private_key: str = Field(default_factory=lambda: os.getenv("VALIDATOR_PRIVATE_KEY", ""))
    explorer_base_url: str = Field(default_factory=lambda: os.getenv("EXPLORER_BASE_URL", "https://sepolia.etherscan.io"))
    
    # Host & Security
    frontend_origin: str = Field(default_factory=lambda: os.getenv("FRONTEND_ORIGIN", "http://localhost:3000"))
    next_public_api_base_url: str = Field(default_factory=lambda: os.getenv("NEXT_PUBLIC_API_BASE_URL", "http://localhost:8000"))
    demo_mode: bool = Field(default_factory=lambda: os.getenv("DEMO_MODE", "true").lower() in ("true", "1", "yes"))
    rate_limit_per_minute: int = Field(default_factory=lambda: int(os.getenv("RATE_LIMIT_PER_MINUTE", "60")))

settings = Settings()
