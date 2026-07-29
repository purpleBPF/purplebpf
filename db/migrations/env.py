import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

# Alembic Config 객체. alembic.ini의 값에 접근할 수 있다.
config = context.config

# alembic.ini의 로깅 설정을 적용한다.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# sqlalchemy.url은 alembic.ini에 하드코딩하지 않고 DATABASE_URL 환경변수에서 읽는다.
database_url = os.environ.get("DATABASE_URL")
if not database_url:
    raise RuntimeError(
        "DATABASE_URL 환경변수가 설정되어 있지 않다. .env.example을 참고해 .env를 구성한다."
    )
config.set_main_option("sqlalchemy.url", database_url)

# autogenerate를 사용하지 않으므로 target_metadata는 비워둔다.
target_metadata = None


def run_migrations_offline() -> None:
    """--sql 옵션 등으로 커넥션 없이 마이그레이션을 실행할 때 사용한다."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """DB 커넥션을 맺고 마이그레이션을 실행한다."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
