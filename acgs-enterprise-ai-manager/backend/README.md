# ACGS Enterprise Manager Backend

## Environment Variables

Create a `.env` file in the project root with the following variables:

```env
# Database
DATABASE_URL=postgresql+asyncpg://postgres:postgres@localhost:5432/acgs_manager

# Security
SECRET_KEY=your-secret-key-change-in-production

# ACGS Governance
GOVERNANCE_RULES_PATH=config/governance_rules.yaml
FAIL_CLOSED=true
AUDIT_ENABLED=true

# Server
HOST=0.0.0.0
PORT=8000
RELOAD=true
```

## Installation

```bash
# Install dependencies
pip install -r backend/requirements.txt

# Set up database (PostgreSQL required)
createdb acgs_manager
psql acgs_manager < database/schema.sql
```

## Running the Server

```bash
# Development mode
python -m backend.main

# Or with uvicorn directly
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

## API Documentation

Once running, visit:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## Project Structure

```
backend/
├── main.py                 # FastAPI application entry point
├── database.py             # Database connection and session management
├── auth/                   # Authentication and authorization
│   ├── __init__.py
│   └── dependencies.py     # JWT auth dependencies
├── models/                 # SQLAlchemy ORM models
│   └── __init__.py
├── schemas/                # Pydantic schemas for validation
│   └── __init__.py
├── middleware/             # Custom middleware
│   └── governance_interceptor.py
├── governance/             # ACGS-Lite integration
│   ├── acgs_integration.py
│   ├── rules_engine.py
│   └── audit_logger.py
└── api/                    # API route handlers (to be implemented)
    ├── tasks.py
    ├── assets.py
    ├── infrastructure.py
    ├── projects.py
    ├── financial.py
    └── documents.py
```

## Next Steps

1. Implement domain-specific CRUD APIs in `backend/api/`
2. Add comprehensive tests
3. Set up database migrations with Alembic
4. Configure production deployment settings
