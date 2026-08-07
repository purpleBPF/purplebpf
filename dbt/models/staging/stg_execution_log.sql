-- postgres_plugin이 connection-open 시점에 Postgres를 pg 별칭으로 ATTACH해둔다.
SELECT *
FROM pg.public.execution_log
