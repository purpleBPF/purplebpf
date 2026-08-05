-include .env
export

.PHONY: up down db-upgrade psql

up:
	docker compose up -d

down:
	docker compose down

db-upgrade:
	alembic upgrade head

psql:
	docker compose exec postgres psql -U $(POSTGRES_USER) -d $(POSTGRES_DB)
