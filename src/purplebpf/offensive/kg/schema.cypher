// Technique/Tactic 노드 유일성 제약.
// load_graph.py가 데이터 적재 전에 먼저 실행한다.

CREATE CONSTRAINT technique_id_unique IF NOT EXISTS FOR (t:Technique) REQUIRE t.id IS UNIQUE;
CREATE CONSTRAINT tactic_id_unique IF NOT EXISTS FOR (t:Tactic) REQUIRE t.id IS UNIQUE;
