# Level 3 Technique Rule Matrix

이 Matrix는 `technique_rule_analysis.md`의 결론을 구현 우선순위 관점에서 요약한다.
현재 `technique_action_rules.json`의 8개 Technique만 포함하며 코드나 rule 변경을 의미하지 않는다.

## 상태 해석

- `IMPLEMENTED`: 필요한 Action+Context가 현재 command mapping에서 생성됨
- `PARTIAL`: Action은 생성되지만 핵심 Context/identity가 부족함
- `MISSING_MAPPER`: Level 2 evidence는 있으나 Level 3 변환 규칙이 없음
- `LEVEL2_EVIDENCE_GAP`: Level 3가 필요로 하는 구조화 evidence 자체가 없음
- `STATICALLY_UNVERIFIABLE`: command-only 분석으로 실제 결과를 확정할 수 없음
- Rule 판단은 `KEEP`, `MODIFY`, `DEMOTE_TO_SUPPORTING`, `PROMOTE_TO_CORE`,
  `REMOVE`, `REVIEW_REQUIRED` vocabulary를 사용함

## 전체 Matrix

| Technique | Core Pattern | Supporting | Static 가능성 | Mapper 상태 | Rule 상태 | 우선 작업 |
|---|---|---|---|---|---|---|
| `T1548.001` Setuid and Setgid | Semantic: setuid/setgid 실행+UID 전환. Static proxy: 동일 파일 `CHANGE_FILE_PERMISSION(permission=setuid/setgid)` AND `EXECUTE_FILE` | setuid/setgid permission 설정, privileged-file 탐색 | 설정+실행 chain은 부분 가능; 실제 UID/EUID 전환은 `STATICALLY_UNVERIFIABLE` | chmod Action `IMPLEMENTED`; 일반 실행/identity `PARTIAL`; privilege Context `MISSING_MAPPER` | permission-only는 `DEMOTE_TO_SUPPORTING`; execution rule `MODIFY` | 동일 파일 identity 상관을 지원하고 permission-only false positive 제거 |
| `T1610` Deploy Container | `CREATE_CONTAINER(operation=create/run/start)`; 가능하면 create→start chain | `CONNECT_SOCKET(container_runtime)`, orchestrator endpoint 접근, image 준비 | deployment request는 정적 식별 가능; 실제 기동은 `STATICALLY_UNVERIFIABLE` | `LEVEL2_EVIDENCE_GAP`, `MISSING_MAPPER` | socket-only `DEMOTE_TO_SUPPORTING`; deployment Action `PROMOTE_TO_CORE` | 재사용 가능한 `CREATE_CONTAINER` Action 제안 후 docker/podman/kubectl evidence 설계 |
| `T1552.001` Credentials In Files | `READ_FILE(data_type=credential)`; 고신뢰 시 `credential_type` 포함 | credential path 탐색, provenance가 확인된 credential copy | 알려진 경로 read는 정적 가능; 실제 content/획득은 불가 | `LEVEL2_EVIDENCE_GAP`, `MISSING_MAPPER`; cat CLI만 `PARTIAL` | 현재 Core `KEEP` | read resource/fact와 보수적 credential path classifier 구현 |
| `T1611` Escape to Host | `ENTER_NAMESPACE(namespace_context=host)` OR `MOUNT_FILESYSTEM(target_context=host)` | `CREATE_NAMESPACE`, container runtime socket, host 미확정 mount | 후보 chain은 부분 가능; 실제 host context/escape는 `STATICALLY_UNVERIFIABLE` | namespace create `IMPLEMENTED`; enter `MISSING_MAPPER`; mount `PARTIAL`; host Context evidence gap | 두 Core와 namespace supporting `KEEP`, host Context 조건 명확화 필요 | nsenter fact mapping 후 host 추정은 REVIEW/runtime으로 제한 |
| `T1105` Ingress Tool Transfer | `CREATE_FILE(transfer_source=external)` OR `WRITE_FILE(transfer_source=external)` | remote endpoint, temporary create/write/execute | source/destination이 명시된 command는 정적 가능; 성공·adversary ownership은 불가 | curl transfer fact 있음→`MISSING_MAPPER`; wget/scp는 `LEVEL2_EVIDENCE_GAP`; temp Action `PARTIAL` | Core/supporting `KEEP` | curl fact를 Action으로 연결하고 provenance 없는 file create와 분리 |
| `T1552.005` Cloud Instance Metadata API | `CONNECT_ENDPOINT(endpoint_type=cloud_metadata)` | provenance가 연결된 response file write | well-known endpoint request는 정적 가능; credential 응답은 `STATICALLY_UNVERIFIABLE` | Level 2 endpoint 분류 있음→`MISSING_MAPPER`; provider path/header `PARTIAL` | 현재 Core `KEEP` | 기존 curl endpoint fact를 mapper에 연결; provider별 고신뢰 path 보강 |
| `T1562.001` Disable or Modify Tools | `TERMINATE_PROCESS(process_type=security_agent)` OR `MODIFY_SECURITY_CONTROL(control_type=bpf_security_sensor, operation=detach/disable)` | 대상 미확정 signal/service stop/BPF detach | 명시적 target command는 부분 가능; 실제 impairment는 `STATICALLY_UNVERIFIABLE` | kill fact `PARTIAL`이나 mapper 없음; target classification/BPF evidence는 `LEVEL2_EVIDENCE_GAP` | Technique ID `REVIEW_REQUIRED`; BPF rule `MODIFY`; security-agent termination `KEEP` | revoked T1562.001→현재 T1685 migration 정책을 mapper 작업보다 먼저 결정 |
| `T1620` Reflective Code Loading | `EXECUTE_FILE(backing=memory)`; stronger proxy는 같은 identity의 `CREATE_MEMORY_FILE(memfd)` AND 실행 | memfd 생성; `/dev/shm`은 낮은 신뢰도 supporting | 명시적 memfd/FD chain만 제한적 정적 가능; 실제 reflective control transfer는 `STATICALLY_UNVERIFIABLE` | `/dev/shm` path만 `PARTIAL`; memory-file/execution은 `LEVEL2_EVIDENCE_GAP`, `MISSING_MAPPER` | Core/supporting `KEEP` | memfd/FD lifecycle evidence와 identity 상관을 보수적으로 설계 |

## 권장 구현 순서

| 우선순위 | 대상 | 이유 | 선행 조건 |
|---:|---|---|---|
| 1 | `T1552.005` | Level 2가 cloud metadata endpoint를 이미 분류하며 현재 Rule도 타당함 | curl endpoint fact → `CONNECT_ENDPOINT` mapper |
| 2 | `T1105` | Level 2 curl transfer fact를 재사용할 수 있고 Core 의미가 명확함 | transfer provenance → file/endpoint Action mapper |
| 3 | `T1611` namespace 부분 | Level 2 nsenter fact가 있으나 mapper만 빠져 있음 | `ENTER_NAMESPACE` 생성; host Context는 자동 확정하지 않음 |
| 4 | `T1548.001` | 현재 구현이 permission 설정만으로 false positive Core match 가능 | 실행 identity 및 Action 상관 지원 |
| 5 | `T1552.001` | rule은 타당하지만 read/credential evidence 계층이 없음 | read fact와 credential classifier |
| 6 | `T1610` | 현재 Core가 Technique 의미와 다르고 새 일반 Action이 필요함 | `CREATE_CONTAINER` 승인, container CLI semantics |
| 7 | `T1562.001` | revoked ID 정책과 target classification 없이는 구현 방향이 불안정함 | T1685 migration 결정, security control catalog |
| 8 | `T1620` | command-only 확정 가능성이 가장 낮고 FD/runtime evidence가 필요함 | memory-backed identity 모델 및 runtime 경계 정의 |

## 공통 설계 Gap

| Gap | 영향 Technique | 제안 |
|---|---|---|
| Level 2 `facts`를 Level 3 mapper가 소비하지 않음 | T1105, T1552.005, T1611, T1562.001 | fact type별 generic lookup/emit 구조를 후속 설계 |
| Action 간 동일 identity 상관 없음 | T1548.001, T1610, T1105, T1620 | matcher requirement에 evidence identity 관계를 표현하는 schema 검토 |
| command request와 runtime success 구분 부족 | 전체, 특히 T1611/T1620 | 정적 match는 “의도/요청”으로 명시하고 runtime-only 사실은 REVIEW/Level 4로 유지 |
| target classification 부족 | T1552.001, T1562.001, T1611 | 보수적인 데이터 기반 classifier와 `unknown` 처리; 경로 이름만으로 host/security 의미 추정 금지 |
| revoked Technique 정책 없음 | T1562.001 | ATT&CK lookup metadata의 `revoked`를 rule lifecycle 정책에 반영 |

## 범위 확인

- 분석 Technique: `T1548.001`, `T1610`, `T1552.001`, `T1611`, `T1105`,
  `T1552.005`, `T1562.001`, `T1620`
- 실제 TracingPolicy file: 없음 (`rules/tracingpolicies/.gitkeep`만 존재)
- 방어 측 `T1059.004` mapping: 현재 Level 3 Technique rule 범위 밖
- 제안된 새 Action: `CREATE_CONTAINER` 하나
- 제안된 새 Context: 없음
- 실제 코드/JSON rule 변경: 없음
