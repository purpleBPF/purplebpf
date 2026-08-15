# Level 3 Technique Rule 분석

이 문서는 현재 `technique_action_rules.json`의 8개 Technique을 공식 MITRE ATT&CK 자료,
저장소의 Enterprise ATT&CK 19.2 snapshot, 현재 Action/Context vocabulary, Level 2 evidence,
Level 3 Action Mapper 구현과 대조한 설계 검토 결과다. 분석 기준일은 2026-08-15이다.

코드와 JSON rule을 수정하지 않았으며, 아래의 “Rule 변경”, “Mapper 변경”은 후속 구현을 위한
제안일 뿐이다.

## 분석 범위와 공통 전제

- `technique_action_rules.json`의 대상은 요청 후보와 동일한 8개다.
- `rules/tracingpolicies/`에는 `.gitkeep`만 있어 추가 Technique을 도출할 실제 TracingPolicy가 없다.
- `defensive/mapper/rule_mapping.yaml`의 `T1059.004`는 방어 측 정책 매핑이며 현재 Level 3
  Technique rule 목록에 없으므로 분석 대상에 추가하지 않는다.
- 현재 matcher는 여러 `patterns`를 OR로, 한 pattern의 `required`를 AND로 처리하며 Context를
  부분집합 일치로 비교한다. Action 간 동일 파일/동일 transfer 같은 identity 상관관계는 표현하지 않는다.
- 현재 Action Mapper가 실제로 생성하는 Technique 관련 Action은 `CHANGE_FILE_PERMISSION`,
  `CREATE_NAMESPACE`, Context 없는 `MOUNT_FILESYSTEM`, 임시 경로의 `CREATE_FILE`/`EXECUTE_FILE`
  정도다. Level 2의 `facts`를 일반적으로 소비하는 계층은 아직 없다.
- 상태 값은 `IMPLEMENTED`, `PARTIAL`, `MISSING_MAPPER`, `LEVEL2_EVIDENCE_GAP`,
  `STATICALLY_UNVERIFIABLE`을 사용한다. 한 항목에 둘 이상의 상태가 함께 적용될 수 있다.

# T1548.001 Setuid and Setgid

## 1. ATT&CK 의미

ATT&CK Technique 전체 의미는 setuid/setgid 비트가 설정된 실행 파일을 악용하여 파일 소유자
또는 그룹의, 때로는 더 높은 권한 문맥에서 코드를 실행하는 것이다. 비트를 새로 설정하는
`chmod`뿐 아니라 이미 비트가 설정된 취약한 바이너리를 발견하고 악용하는 경우도 포함한다.
공식 Detection Strategy도 비트 설정과 뒤따르는 실행, 그리고 UID/EUID 차이를 상관 분석한다.

## 2. Static Validator가 확인할 수 있는 범위

정적 command에서는 `chmod u+s`, `chmod g+s`, `chmod 4xxx`, `chmod 2xxx`와 이후 동일 파일
실행을 확인할 수 있다. 그러나 실제 소유자, 실행 당시 UID/EUID 전환, 실행 성공과 획득 권한은
확인할 수 없다. 따라서 권한 비트 설정만으로 전체 Technique을 증명해서는 안 된다.

## 3. Technique 행위 분해

1. 기존 setuid/setgid 파일을 탐색하거나 대상 파일을 준비한다.
2. 선택적으로 대상 실행 파일에 setuid/setgid 비트를 설정한다.
3. 해당 실행 파일을 실행한다.
4. 런타임에서 소유자/그룹 권한 문맥으로 전환된다.

## 4. 기존 Action + Context 대응

| 행위 | Action | Context | 기존 vocabulary 사용 가능 |
|---|---|---|---|
| setuid 비트 설정 | `CHANGE_FILE_PERMISSION` | `permission=setuid` | 가능 |
| setgid 비트 설정 | `CHANGE_FILE_PERMISSION` | `permission=setgid` | 가능 |
| 대상 실행 | `EXECUTE_FILE` 또는 `EXECUTE_PROGRAM` | `privilege_context=setuid/setgid` | 가능 |
| 실제 권한 전환 | `EXECUTE_PROGRAM` | `uid_transition=<from-to>` | 어휘는 가능하지만 command-only로 값 확정 불가 |

## 5. Action / Context 추가 필요 여부

### Action

추가하지 않는다. 파일 권한 변경과 실행은 기존 Action으로 충분하다.

### Context

추가하지 않는다. `permission`, `privilege_context`, `uid_transition`이 이미 있다. 다만 높은
신뢰도의 정적 pattern에는 두 Action이 같은 파일을 가리킨다는 identity 상관 조건이 필요하며,
이는 새 Context보다 rule engine/schema의 관계 표현 문제다.

## 6. Core Pattern 제안

### Pattern A — Semantic Core

Action: `EXECUTE_FILE` 또는 `EXECUTE_PROGRAM`

Context: `privilege_context=setuid|setgid`, 실제 `uid_transition` 존재

왜 Core인가: 비트가 설정된 파일을 실제로 실행하여 다른 권한 문맥에서 코드가 동작하는 것이
Technique의 본질이기 때문이다.

Static verification: `STATICALLY_UNVERIFIABLE`

정적 검증 한계: command만으로 EUID/EGID 변화를 확인할 수 없다.

### Pattern B — Static-verifiable Core 후보

Action: `CHANGE_FILE_PERMISSION(permission=setuid|setgid)` AND `EXECUTE_FILE`

Context: 두 Action이 같은 파일 identity를 참조

왜 Core인가: 준비 행위와 실제 실행을 결합하여 단순한 권한 설정보다 Technique에 가깝다.

Static verification: `PARTIAL`, `MISSING_MAPPER`

정적 검증 한계: 현재 matcher는 Action 간 동일 파일 상관관계를 표현하지 못하며 일반 실행 파일
Action도 제한적으로만 생성한다. 이 pattern도 실제 권한 전환은 증명하지 못한다.

## 7. Supporting Action

- `CHANGE_FILE_PERMISSION(permission=setuid)`
- `CHANGE_FILE_PERMISSION(permission=setgid)`
- setuid/setgid 파일을 찾는 탐색 command는 의미 있는 supporting evidence이지만 현재 적절한
  Action과 Level 2 evidence가 없다.

## 8. 현재 Rule과 비교

| 현재 Rule | 판단 | 제안 |
|---|---|---|
| `setuid-permission` | `DEMOTE_TO_SUPPORTING` | 비트 설정 단독을 Core로 보지 않는다. |
| `setgid-permission` | `DEMOTE_TO_SUPPORTING` | 비트 설정 단독을 Core로 보지 않는다. |
| `setuid-execution` | `MODIFY` | setgid도 포함하고 실행 대상/UID 전환 근거를 명시한다. |

## 9. Command → Action Mapping 상태

| Action + Context | 상태 | 필요한 작업 |
|---|---|---|
| `CHANGE_FILE_PERMISSION(permission=setuid/setgid)` | `IMPLEMENTED` | 현재 chmod symbolic/numeric 규칙 유지 및 경계 case 보강 |
| `EXECUTE_FILE` + 대상 identity | `PARTIAL` | 임시 경로 외 일반 실행 파일 mapping과 파일 identity 보존 |
| `privilege_context=setuid/setgid` | `MISSING_MAPPER` | 파일 mode/owner 또는 선행 permission evidence와 실행 연결 |
| 실제 `uid_transition` | `STATICALLY_UNVERIFIABLE` | Runtime/Level 4 관찰로만 확정 |

## 10. 최종 제안

Core: 실행과 권한 전환이 Semantic Core이며, 정적 대안은 동일 파일에 대한 비트 설정+실행이다.

Supporting: setuid/setgid 비트 설정.

Rule 변경: 현재 permission-only 두 Core를 supporting으로 내리고 실행 결합 pattern을 설계한다.

Mapper 변경: 일반 파일 실행과 대상 identity를 생성한다.

Level 2 변경 필요: 실행 파일 identity 및 선행 chmod 대상과의 상관에 필요한 안정된 evidence가 필요하다.

사람 검토 필요: 실제 UID/EUID 변화와 권한 상승 성공 여부.

## 11. 근거

- [MITRE ATT&CK T1548.001 Setuid and Setgid](https://attack.mitre.org/techniques/T1548/001/)
- 공식 페이지의 `DET0110` Detection Strategy와 `AN0307`/`AN0308` 분석
- 프로젝트 snapshot: `data/enterprise-attack-19.2-techniques.json`

# T1105 Ingress Tool Transfer

## 1. ATT&CK 의미

ATT&CK Technique 전체 의미는 공격 도구나 파일을 외부 시스템에서 침해된 환경 안으로 전송하는
것이다. C2 channel, FTP/HTTP 등 대체 protocol, cloud/web service, package manager와 다양한
utility가 사용될 수 있다. 핵심은 단순 파일 생성이 아니라 외부→피해 환경 방향의 전송이다.

## 2. Static Validator가 확인할 수 있는 범위

정적 command에서는 `curl`, `wget`, `scp` 등의 remote source와 local output을 구조화하여 ingress
방향을 추정할 수 있다. URL이 외부인지, 응답이 실제 tool/file인지, 전송이 성공했는지, 대상 환경이
이미 침해됐는지는 확인할 수 없다. 임시 경로 생성이나 실행만으로 external transfer를 판정해서는 안 된다.

## 3. Technique 행위 분해

1. remote/external source에 연결한다.
2. tool 또는 file content를 수신한다.
3. local file, stdout, pipe 또는 memory destination에 기록한다.
4. 선택적으로 전송된 payload를 검증하고 실행한다.

## 4. 기존 Action + Context 대응

| 행위 | Action | Context | 기존 vocabulary 사용 가능 |
|---|---|---|---|
| remote source 연결 | `CONNECT_ENDPOINT` | `source_type=external` 또는 endpoint 분류 | 가능 |
| local file 생성 | `CREATE_FILE` | `transfer_source=external`, 선택적으로 `path_type` | 가능 |
| 기존 file에 기록 | `WRITE_FILE` | `transfer_source=external` | 가능 |
| 전송된 file 실행 | `EXECUTE_FILE` | `path_type` | 가능, supporting |

## 5. Action / Context 추가 필요 여부

### Action

추가하지 않는다. 현재 전송 semantic fact에서 외부 source를 근거로 `CREATE_FILE`/`WRITE_FILE`을
생성하면 된다. 별도 `TRANSFER_FILE` Action은 향후 upload/lateral direction까지 일관되게 모델링할
명확한 필요가 생길 때 검토한다.

### Context

추가하지 않는다. `transfer_source`와 `source_type`이 이미 있다. direction은 현재 Level 2 transfer
fact의 attribute로 보존하고 필요 시 기존 Context vocabulary 확장을 별도 검토한다.

## 6. Core Pattern 제안

### Pattern A — External file creation

Action: `CREATE_FILE`

Context: `transfer_source=external`

왜 Core인가: 외부 source에서 유입된 content로 local file을 만드는 것은 ingress transfer의 직접적인
정적 표현이다. 이 Context는 단순 touch가 아니라 transfer evidence에서만 생성해야 한다.

Static verification: `MISSING_MAPPER`

정적 검증 한계: Level 2의 curl transfer fact는 존재하지만 external classification과 성공 여부는 제한적이다.

### Pattern B — External content write

Action: `WRITE_FILE`

Context: `transfer_source=external`

왜 Core인가: 기존 destination에 외부 content를 기록하는 경우도 Technique에 포함되기 때문이다.

Static verification: `MISSING_MAPPER`

정적 검증 한계: pipe/stdout, redirect와 command substitution은 현재 단순 shell parser 범위 밖이다.
`wget`, `scp` 등은 Level 2 semantic evidence가 충분하지 않다.

## 7. Supporting Action

- `CONNECT_ENDPOINT` with remote/external source evidence
- `CREATE_FILE(path_type=temporary)`
- `WRITE_FILE(path_type=temporary)`
- `EXECUTE_FILE(path_type=temporary)`

임시 경로 Action은 전송 source를 증명하지 않으므로 supporting으로만 유지한다.

## 8. 현재 Rule과 비교

| 현재 Rule | 판단 | 제안 |
|---|---|---|
| `create-external-file` | `KEEP` | Action은 transfer fact에서만 생성해 provenance를 보장한다. |
| `write-external-file` | `KEEP` | redirect/overwrite semantics가 확보될 때 활성화한다. |
| temporary path supporting 3개 | `KEEP` | 단독 Core로 승격하지 않는다. |

## 9. Command → Action Mapping 상태

| Action + Context | 상태 | 필요한 작업 |
|---|---|---|
| curl transfer fact → `CREATE_FILE/WRITE_FILE(transfer_source=external)` | `MISSING_MAPPER` | 기존 `transfer` fact와 output path를 소비 |
| `CONNECT_ENDPOINT` remote source | `MISSING_MAPPER` | 기존 curl URL fact에서 endpoint Action 생성 |
| wget/scp 등 ingress fact | `LEVEL2_EVIDENCE_GAP` | command별 source/destination/direction semantic extraction |
| temporary `CREATE_FILE`/`EXECUTE_FILE` | `PARTIAL` | 일부 Action은 구현됐지만 external transfer와 연결되지 않음 |
| 실제 전송 성공 | `STATICALLY_UNVERIFIABLE` | Runtime 관찰 필요 |

## 10. 최종 제안

Core: 외부 transfer evidence에서 유도된 `CREATE_FILE` 또는 `WRITE_FILE`.

Supporting: remote endpoint 연결, temporary path 생성/기록/실행.

Rule 변경: 현재 Core와 supporting을 유지하되 Action provenance 조건을 설계 문서와 mapper에 강제한다.

Mapper 변경: Level 2 transfer fact를 file/endpoint Action으로 변환한다.

Level 2 변경 필요: curl 외 wget/scp/rsync 등의 방향·source·destination evidence 보강.

사람 검토 필요: external/adversary-controlled 여부와 실제 전송 성공.

## 11. 근거

- [MITRE ATT&CK T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- 공식 페이지의 Linux/macOS transfer utility 및 Procedure Examples
- 프로젝트 snapshot: `data/enterprise-attack-19.2-techniques.json`

# T1552.005 Cloud Instance Metadata API

## 1. ATT&CK 의미

ATT&CK Technique 전체 의미는 cloud instance metadata service에 접근하여 instance credential,
role credential 또는 기타 민감한 cloud metadata를 획득하는 것이다. 직접 HTTP 요청뿐 아니라
SSRF 등 간접 접근도 포함될 수 있다.

## 2. Static Validator가 확인할 수 있는 범위

정적 command에서는 `169.254.169.254`와 provider별 metadata hostname/path, 필수 header/token
요청을 식별할 수 있다. 현재 Level 2는 curl URL의 well-known IP를 `cloud_metadata`로 분류한다.
하지만 응답에 credential이 있었는지, 요청이 성공했는지, credential을 실제로 저장·사용했는지는
확인할 수 없다.

## 3. Technique 행위 분해

1. metadata endpoint를 식별한다.
2. metadata service에 HTTP/API 요청을 보낸다.
3. role/service credential 또는 sensitive metadata를 응답으로 받는다.
4. 선택적으로 credential을 저장하고 사용한다.

## 4. 기존 Action + Context 대응

| 행위 | Action | Context | 기존 vocabulary 사용 가능 |
|---|---|---|---|
| metadata endpoint 요청 | `CONNECT_ENDPOINT` | `endpoint_type=cloud_metadata` | 가능 |
| credential 응답 수신 | `READ_FILE`로 표현 부적절 | `data_type=credential` | runtime response라 정적 Action 불필요 |
| 응답 저장 | `WRITE_FILE` | `data_type=credential` | 가능하나 content 확정 불가 |

## 5. Action / Context 추가 필요 여부

### Action

추가하지 않는다. command 기반 범위에서는 `CONNECT_ENDPOINT`가 충분하다.

### Context

추가하지 않는다. `endpoint_type=cloud_metadata`가 핵심 구분을 제공한다. provider별 세분화는
evidence에 URL/host를 보존하면 되며 초기 Core에는 불필요하다.

## 6. Core Pattern 제안

### Pattern A — Static-verifiable Core

Action: `CONNECT_ENDPOINT`

Context: `endpoint_type=cloud_metadata`

왜 Core인가: metadata service를 명시적으로 대상으로 한 요청은 command-only 분석에서 Technique에
가장 가까운 관찰 가능한 행위다.

Static verification: `MISSING_MAPPER`

정적 검증 한계: endpoint 접근 시도는 확인하지만 credential 응답·획득은 증명하지 못한다.

### Pattern B — Stronger request candidate

Action: `CONNECT_ENDPOINT`

Context: `endpoint_type=cloud_metadata`, evidence에 credential endpoint path 또는 provider-required header

왜 Core인가: metadata root 조회보다 credential path/token protocol 요청이 더 높은 신뢰도를 제공한다.

Static verification: `PARTIAL`, `LEVEL2_EVIDENCE_GAP`

정적 검증 한계: 모든 cloud provider와 SSRF 형태를 정적으로 포괄할 수 없다.

## 7. Supporting Action

- metadata response를 local file로 저장하는 `WRITE_FILE`은 data provenance가 유지될 때 supporting evidence다.
- 일반 link-local endpoint connection은 cloud metadata 분류가 없으면 supporting으로도 충분하지 않다.

## 8. 현재 Rule과 비교

| 현재 Rule | 판단 | 제안 |
|---|---|---|
| `cloud-metadata-endpoint` | `KEEP` | 현재 정적 범위에 적절하며 mapper를 구현한다. |

## 9. Command → Action Mapping 상태

| Action + Context | 상태 | 필요한 작업 |
|---|---|---|
| curl fact → `CONNECT_ENDPOINT(endpoint_type=cloud_metadata)` | `MISSING_MAPPER` | 기존 endpoint classification을 Level 3가 소비 |
| provider credential path/header | `PARTIAL`, `LEVEL2_EVIDENCE_GAP` | metadata rule data와 header option evidence 확장 |
| credential 응답 획득 | `STATICALLY_UNVERIFIABLE` | Runtime network response evidence 필요 |

## 10. 최종 제안

Core: `CONNECT_ENDPOINT(endpoint_type=cloud_metadata)` 유지.

Supporting: provenance가 연결된 response file write.

Rule 변경: 없음. 향후 고신뢰 credential-path pattern을 선택적으로 추가한다.

Mapper 변경: Level 2 endpoint fact를 `CONNECT_ENDPOINT`로 변환한다.

Level 2 변경 필요: provider별 credential path/header 분류를 보수적으로 확장할 수 있다.

사람 검토 필요: 응답 성공, 실제 credential 포함과 사용 여부.

## 11. 근거

- [MITRE ATT&CK T1552.005 Cloud Instance Metadata API](https://attack.mitre.org/techniques/T1552/005/)
- 공식 페이지의 Procedure Examples와 Detection Strategy
- 프로젝트 snapshot: `data/enterprise-attack-19.2-techniques.json`

# T1562.001 Disable or Modify Tools

## 1. ATT&CK 의미

프로젝트의 Enterprise ATT&CK 19.2 snapshot에서 T1562.001은 보안 도구를 비활성화·수정하여
탐지/방지를 방해하는 행위를 뜻하지만 `revoked=true`다. 현재 ATT&CK live site에서는 이 의미가
독립 Technique `T1685 Disable or Modify Tools`로 이동했다. 이 문서는 새 Technique을 임의 추가하지
않고 현재 프로젝트 key인 T1562.001의 rule 타당성만 검토한다.

의미 범위에는 보안 process/service 종료, agent 제거, 설정 변경, scanning/reporting 방해, exclusion
추가 등이 포함된다. 모든 BPF detach나 모든 process terminate가 이 Technique인 것은 아니다.

## 2. Static Validator가 확인할 수 있는 범위

정적 command에서는 알려진 security agent를 대상으로 한 `kill/pkill/systemctl stop`, 방어용 BPF
program/link detach, agent 설정 변경 등을 식별할 수 있다. 대상이 실제 security control인지,
명령이 성공했는지, 방어 기능이 실제 약화됐는지는 command만으로 확정하기 어렵다. 또한 revoked
Technique ID를 현재 규칙으로 계속 판정할지 정책 결정이 필요하다.

## 3. Technique 행위 분해

1. 보안 도구/process/service/control을 식별한다.
2. 해당 대상을 종료, 중지, 제거, detach 또는 설정 변경한다.
3. 탐지·차단·보고 기능이 약화되거나 비활성화된다.

## 4. 기존 Action + Context 대응

| 행위 | Action | Context | 기존 vocabulary 사용 가능 |
|---|---|---|---|
| security agent 종료 | `TERMINATE_PROCESS` | `process_type=security_agent` | 가능 |
| 방어용 BPF control detach | `MODIFY_SECURITY_CONTROL` | `control_type=bpf_security_sensor`, `operation=detach` | 가능 |
| security service 중지/설정 변경 | `MODIFY_SECURITY_CONTROL` | `control_type=<type>`, `operation=stop|modify` | 가능 |
| 방어 약화 결과 | 위 Action의 runtime effect | - | command-only로 확정 불가 |

## 5. Action / Context 추가 필요 여부

### Action

추가하지 않는다. `TERMINATE_PROCESS`와 `MODIFY_SECURITY_CONTROL`로 핵심 행위를 표현할 수 있다.

### Context

추가하지 않는다. 기존 `process_type`, `control_type`, `operation`을 사용한다. 다만 현재 값
`control_type=bpf`는 대상의 방어 목적을 구분하지 못하므로 `bpf_security_sensor`처럼 더 구체적인
값 또는 별도 신뢰 가능한 target classification이 필요하다.

## 6. Core Pattern 제안

### Pattern A — Security agent termination

Action: `TERMINATE_PROCESS`

Context: `process_type=security_agent`

왜 Core인가: 식별된 보안 agent의 종료는 도구 비활성화의 직접적인 행위다.

Static verification: `LEVEL2_EVIDENCE_GAP`, `MISSING_MAPPER`

정적 검증 한계: 현재 `kill` fact는 PID/signal만 제공하며 PID가 어떤 process인지 알 수 없다.
이름 기반 `pkill`도 known-agent 목록이 없으면 신뢰성이 낮다.

### Pattern B — Defensive control modification

Action: `MODIFY_SECURITY_CONTROL`

Context: `control_type=bpf_security_sensor`, `operation=detach|unload|disable`

왜 Core인가: 방어 목적으로 식별된 control을 명시적으로 제거/비활성화하는 행위다.

Static verification: `LEVEL2_EVIDENCE_GAP`, `MISSING_MAPPER`

정적 검증 한계: 일반 BPF object detach는 개발·운영 행위일 수 있다. 대상 provenance 없이는 Core로
확정하면 안 되며 실제 방어 약화도 runtime에서만 확인된다.

## 7. Supporting Action

- 보안 agent 후보 process에 대한 generic signal/stop request
- `control_type=bpf`만 알려진 detach
- 보안 설정 파일 write는 target classification이 있을 때 supporting evidence

## 8. 현재 Rule과 비교

| 현재 Rule | 판단 | 제안 |
|---|---|---|
| Technique key `T1562.001` | `REVIEW_REQUIRED` | snapshot에서 revoked이므로 현재 T1685와의 migration 정책을 별도 결정한다. |
| `detach-bpf-control` (`control_type=bpf`) | `MODIFY` | 방어용 sensor/control이라는 target classification을 요구한다. |
| `terminate-security-agent` | `KEEP` | 의미는 적절하며 대상 식별 evidence가 필수다. |

## 9. Command → Action Mapping 상태

| Action + Context | 상태 | 필요한 작업 |
|---|---|---|
| `TERMINATE_PROCESS` from kill | `PARTIAL`, `MISSING_MAPPER` | Level 2 process_signal fact 소비 |
| `process_type=security_agent` | `LEVEL2_EVIDENCE_GAP` | PID/name/service와 보수적 security-agent catalog 연결 |
| `MODIFY_SECURITY_CONTROL(operation=detach)` | `LEVEL2_EVIDENCE_GAP`, `MISSING_MAPPER` | bpftool/loader control command semantic extraction |
| `control_type=bpf_security_sensor` | `LEVEL2_EVIDENCE_GAP` | object provenance/policy identity 필요 |
| 실제 방어 기능 약화 | `STATICALLY_UNVERIFIABLE` | Runtime/Level 4 evidence 필요 |

## 10. 최종 제안

Core: 식별된 security agent 종료 또는 식별된 방어 control의 disable/detach.

Supporting: 대상 정체가 불완전한 signal, service stop, BPF detach.

Rule 변경: 현 작업에서는 변경하지 않는다. 후속에서 T1562.001 revoked 처리와 T1685 migration을
먼저 결정하고, BPF pattern의 target classification을 강화한다.

Mapper 변경: process_signal/control command를 Action으로 변환하되 대상 정체가 없으면 supporting만 생성한다.

Level 2 변경 필요: security process/control identity 및 BPF operation evidence.

사람 검토 필요: revoked ID 정책, 대상의 방어 목적, 실제 impairment 결과.

## 11. 근거

- 프로젝트 snapshot `data/enterprise-attack-19.2-techniques.json`의 T1562.001 객체
  (`revoked=true`, version 1.7)
- [MITRE ATT&CK T1685 Disable or Modify Tools](https://attack.mitre.org/techniques/T1685/)
- [기존 T1562.001 URL](https://attack.mitre.org/techniques/T1562/001/)은 현재 live content를 제공하지 않음

# T1620 Reflective Code Loading

## 1. ATT&CK 의미

ATT&CK Technique 전체 의미는 payload를 일반 disk-backed 실행 경로에 두지 않고 현재 process의
memory에 직접 load하여 실행하는 것이다. reflective loader, anonymous/memory-backed file, shellcode
등이 관련될 수 있다. 다른 process에 쓰는 Process Injection과는 구분해야 한다.

## 2. Static Validator가 확인할 수 있는 범위

정적 command에서는 memfd 생성·쓰기·실행, `/proc/self/fd/<n>` 실행, memory-loader의 명시적 option
등 강한 패턴을 확인할 수 있다. `/dev/shm`에서 파일을 실행했다는 사실만으로 reflective loading을
확정할 수 없으며, process 내부 memory allocation과 control transfer는 일반 shell command에서
보이지 않는다.

## 3. Technique 행위 분해

1. payload bytes를 process memory 또는 anonymous memory-backed object에 배치한다.
2. loader가 payload를 resolve/map한다.
3. disk의 일반 executable path 없이 memory-resident code로 control을 전달한다.
4. payload가 현재 process 문맥에서 실행된다.

## 4. 기존 Action + Context 대응

| 행위 | Action | Context | 기존 vocabulary 사용 가능 |
|---|---|---|---|
| memfd/anonymous object 생성 | `CREATE_MEMORY_FILE` | `backing=memfd` | 가능 |
| memory-backed payload 실행 | `EXECUTE_FILE` | `backing=memory` | 가능 |
| 다른 process memory 쓰기 | `WRITE_PROCESS_MEMORY` | 대상 process | 어휘는 있으나 T1620 Core가 아니라 injection 의미에 가까움 |
| current-process reflective load | `EXECUTE_FILE(backing=memory)` 추상화 | - | 부분 가능 |

## 5. Action / Context 추가 필요 여부

### Action

추가하지 않는다. `EXECUTE_FILE(backing=memory)`는 “file”이라는 명칭의 한계가 있지만 현재 schema에서
memory-backed executable object 실행을 충분히 추상화한다. `EXECUTE_MEMORY`는 runtime telemetry까지
통합할 명확한 필요가 생길 때만 검토한다.

### Context

추가하지 않는다. `backing=memory|memfd`로 핵심 차이를 표현할 수 있다.

## 6. Core Pattern 제안

### Pattern A — Memory-backed execution

Action: `EXECUTE_FILE`

Context: `backing=memory`

왜 Core인가: memory-resident object로의 실행 전환은 reflective loading의 본질에 가장 가깝다.

Static verification: `LEVEL2_EVIDENCE_GAP`, `MISSING_MAPPER`, `STATICALLY_UNVERIFIABLE`

정적 검증 한계: 일반 shell command만으로 loader 내부의 memory mapping과 실제 control transfer를
확인하기 어렵다.

### Pattern B — Static chain proxy

Action: `CREATE_MEMORY_FILE(backing=memfd)` AND `EXECUTE_FILE(backing=memory)`

Context: 동일 memfd/file-descriptor identity

왜 Core인가: memfd 준비 단독보다 생성 후 실행 연쇄가 reflective execution에 가깝다.

Static verification: `LEVEL2_EVIDENCE_GAP`, `STATICALLY_UNVERIFIABLE`

정적 검증 한계: command substitution, FD 전달, loader 내부 syscall은 현재 parser/evidence 범위 밖이며
matcher에 identity 상관 기능도 없다.

## 7. Supporting Action

- `CREATE_MEMORY_FILE(backing=memfd)`
- `/dev/shm`의 `CREATE_FILE`/`EXECUTE_FILE`은 memory-related heuristic일 뿐 reflective loading의
  충분한 근거가 아니므로 낮은 신뢰도의 supporting evidence로만 고려한다.
- `WRITE_PROCESS_MEMORY`는 다른 process 대상이면 T1055 계열 의미에 가까워 T1620 supporting으로
  자동 사용하지 않는다.

## 8. 현재 Rule과 비교

| 현재 Rule | 판단 | 제안 |
|---|---|---|
| `execute-memory-backed-file` | `KEEP` | 정적 proxy로 유지하되 runtime 실행 증명과 구분한다. |
| supporting `CREATE_MEMORY_FILE(backing=memfd)` | `KEEP` | 생성 단독은 Core가 아님을 유지한다. |

## 9. Command → Action Mapping 상태

| Action + Context | 상태 | 필요한 작업 |
|---|---|---|
| `CREATE_MEMORY_FILE(backing=memfd)` | `LEVEL2_EVIDENCE_GAP`, `MISSING_MAPPER` | memfd/FD semantic evidence 설계 |
| `EXECUTE_FILE(backing=memory)` | `LEVEL2_EVIDENCE_GAP`, `MISSING_MAPPER` | `/proc/self/fd`, loader option 등 제한된 고신뢰 pattern |
| `/dev/shm` executable | `PARTIAL` | 현재는 `path_type=temporary`만 생성하며 memory backing을 뜻하지 않음 |
| 실제 reflective control transfer | `STATICALLY_UNVERIFIABLE` | Runtime syscall/process telemetry 필요 |

## 10. 최종 제안

Core: `EXECUTE_FILE(backing=memory)` 유지, 가능하면 같은 identity의 memfd 생성과 결합.

Supporting: `CREATE_MEMORY_FILE(backing=memfd)`; `/dev/shm` evidence는 낮은 신뢰도로 제한.

Rule 변경: 현재 구조 유지. 향후 identity 상관을 지원하면 생성+실행 AND pattern을 우선한다.

Mapper 변경: 고신뢰 memory-backed execution pattern만 보수적으로 mapping한다.

Level 2 변경 필요: memfd/FD lifecycle과 executable backing evidence.

사람 검토 필요: 실제 memory load와 execution, Process Injection과의 구분.

## 11. 근거

- [MITRE ATT&CK T1620 Reflective Code Loading](https://attack.mitre.org/techniques/T1620/)
- 공식 페이지의 Procedure Examples 및 memory execution 관련 Detection Strategy
- 프로젝트 snapshot: `data/enterprise-attack-19.2-techniques.json`

# T1610 Deploy Container

## 1. ATT&CK 의미

ATT&CK Technique 전체 의미는 실행 또는 방어 회피를 위해 환경에 새 container/workload를
배포하는 것이다. Docker create/start API, Kubernetes workload 배포 등이 포함되며, 공식 탐지
전략은 create → start → 첫 process/network action의 행위 연쇄를 강조한다.

## 2. Static Validator가 확인할 수 있는 범위

정적 command에서는 `docker create/run/start`, `podman run`, `kubectl create/apply`처럼
container 생성·기동 요청을 식별할 수 있다. manifest 내용이 없는 `kubectl apply -f`는 실제
container workload인지 판단하기 어렵고, API 요청 성공이나 실제 기동은 확인할 수 없다.
container runtime socket에 연결했다는 사실만으로 배포를 판정할 수 없다.

## 3. Technique 행위 분해

1. container runtime 또는 orchestrator에 접근한다.
2. image와 runtime/workload 설정을 선택한다.
3. container 또는 workload 생성 요청을 보낸다.
4. container를 시작하고 그 안에서 process를 실행한다.

## 4. 기존 Action + Context 대응

| 행위 | Action | Context | 기존 vocabulary 사용 가능 |
|---|---|---|---|
| runtime socket/API 접근 | `CONNECT_SOCKET`/`CONNECT_ENDPOINT` | `socket_type=container_runtime` | 가능 |
| container 생성/배포 | 해당 Action 없음 | `operation=create|run` 후보 | 불가 |
| container 내부 실행 | `EXECUTE_PROGRAM` | `program_category=container_workload` 후보 | 부분 가능, 배포 자체는 아님 |

## 5. Action / Context 추가 필요 여부

### Action

`CREATE_CONTAINER` 추가를 제안한다. 기존 `CREATE_FILE`, `EXECUTE_PROGRAM`, `CONNECT_SOCKET`
중 어느 것도 container라는 시스템 객체의 생성 행위를 표현하지 못한다. 이는 Technique 이름을
옮긴 것이 아니라 container runtime 전반에서 재사용 가능하고 `docker/podman/kubectl` command의
구조화 결과로 관찰 가능한 일반 행위다.

### Context

새 Context는 필요하지 않다. 기존 `operation`에 `create`, `start`, `run`을 사용하고 evidence에
image/workload identity를 보존할 수 있다. Kubernetes manifest 종류를 표현해야 할 때만 후속으로
일반적인 `resource_type` Context를 검토한다.

## 6. Core Pattern 제안

### Pattern A — Static-verifiable Core

Action: `CREATE_CONTAINER`

Context: `operation=run` 또는 배포를 포함하는 `operation=create`

왜 Core인가: container 배포 요청 자체를 직접 표현한다.

Static verification: `LEVEL2_EVIDENCE_GAP`, `MISSING_MAPPER`

정적 검증 한계: command 요청은 확인해도 runtime이 수락하고 container가 시작됐는지는 모른다.

### Pattern B — Stronger Semantic Core

Action: `CREATE_CONTAINER(operation=create)` AND `CREATE_CONTAINER(operation=start)` 또는
container 내부 첫 `EXECUTE_PROGRAM`

Context: 동일 container/workload identity

왜 Core인가: 공식 탐지 전략의 생성·시작 연쇄에 더 가깝다.

Static verification: `LEVEL2_EVIDENCE_GAP`, `STATICALLY_UNVERIFIABLE`

정적 검증 한계: 현재 scenario schema와 matcher는 container identity를 통한 상관 및 runtime
첫 행위를 표현하지 못한다.

## 7. Supporting Action

- `CONNECT_SOCKET(socket_type=container_runtime)`
- `CONNECT_ENDPOINT(endpoint_type=container_orchestrator)`가 향후 신뢰성 있게 분류되는 경우 API 접근 근거
- image pull/build는 배포 전 준비 행위이며 단독 Core가 아니다.

## 8. 현재 Rule과 비교

| 현재 Rule | 판단 | 제안 |
|---|---|---|
| `container-runtime-socket` | `DEMOTE_TO_SUPPORTING` | socket 접근은 배포 능력/접근의 근거일 뿐 배포 행위가 아니다. |
| container 생성/기동 pattern 없음 | `PROMOTE_TO_CORE` | `CREATE_CONTAINER` 기반 pattern을 후속 추가한다. |

## 9. Command → Action Mapping 상태

| Action + Context | 상태 | 필요한 작업 |
|---|---|---|
| `CONNECT_SOCKET(container_runtime)` | `LEVEL2_EVIDENCE_GAP`, `MISSING_MAPPER` | Unix socket/API endpoint 추출 |
| `CREATE_CONTAINER(operation=create/run)` | `LEVEL2_EVIDENCE_GAP`, `MISSING_MAPPER` | docker/podman/kubectl CLI metadata와 semantic fact 설계 |
| 생성→시작→첫 실행 상관 | `STATICALLY_UNVERIFIABLE` | command chain identity 및 runtime telemetry 필요 |

## 10. 최종 제안

Core: `CREATE_CONTAINER`의 create/run, 가능하면 start와의 상관.

Supporting: container runtime socket/API 접근과 image 준비.

Rule 변경: socket-only Core를 supporting으로 이동하고 새 Action 도입 후 배포 pattern을 Core로 둔다.

Mapper 변경: container CLI/API command를 `CREATE_CONTAINER`로 변환한다.

Level 2 변경 필요: container operation, image, workload/container identity 추출.

사람 검토 필요: manifest의 실제 workload 종류, API 성공, container 기동 여부.

## 11. 근거

- [MITRE ATT&CK T1610 Deploy Container](https://attack.mitre.org/techniques/T1610/)
- 공식 페이지의 `DET0249`/`AN0693` create-start-first-action Detection Strategy
- 프로젝트 snapshot: `data/enterprise-attack-19.2-techniques.json`

# T1552.001 Credentials In Files

## 1. ATT&CK 의미

ATT&CK Technique 전체 의미는 로컬 파일 시스템 또는 원격 파일 공유에서 안전하지 않게 저장된
credential을 검색하고 읽거나 복사하는 것이다. 사용자 credential 파일, service 설정, source/binary
내 embedded password, cloud/container 설정과 service account credential 등이 포함된다.

## 2. Static Validator가 확인할 수 있는 범위

정적 command에서는 `cat`, `grep`, `find`, `cp` 등의 대상 경로와 option을 통해 알려진 credential
파일을 읽거나 검색하려는 행위를 판별할 수 있다. 임의 파일의 실제 내용이 credential인지, 출력에서
credential을 획득했는지, 이후 인증에 사용했는지는 확인할 수 없다.

## 3. Technique 행위 분해

1. credential이 있을 법한 파일/경로를 탐색한다.
2. 해당 파일을 읽거나 복사한다.
3. 내용에서 credential material을 식별·추출한다.
4. 선택적으로 획득한 credential을 재사용한다.

## 4. 기존 Action + Context 대응

| 행위 | Action | Context | 기존 vocabulary 사용 가능 |
|---|---|---|---|
| credential 파일 읽기 | `READ_FILE` | `data_type=credential`, 선택적으로 `credential_type` | 가능 |
| credential 파일 복사/저장 | `READ_FILE` + `WRITE_FILE` | `data_type=credential` | 가능 |
| 파일 탐색 | `EXECUTE_PROGRAM` | 명확한 search 의미 Context 없음 | 부분 가능 |
| credential 재사용 | 범위 밖 | - | 이번 정적 범위에 불필요 |

## 5. Action / Context 추가 필요 여부

### Action

추가하지 않는다. Core인 파일 읽기는 `READ_FILE`로 표현 가능하다. 단순 search를 별도 Action으로
만들 필요는 없으며 먼저 `READ_FILE`의 정밀도를 높인다.

### Context

추가하지 않는다. `data_type`, `credential_type`, `path_type`으로 충분하다. credential 여부는
허용 목록 기반 path classifier와 command semantics에서 도출해야 한다.

## 6. Core Pattern 제안

### Pattern A — Static-verifiable Core

Action: `READ_FILE`

Context: `data_type=credential`

왜 Core인가: credential material을 담는 것으로 분류된 파일에 대한 읽기는 Technique의 획득 행위에
가장 가까운 command-observable action이다.

Static verification: `LEVEL2_EVIDENCE_GAP`, `MISSING_MAPPER`

정적 검증 한계: 알려진 경로는 강한 heuristic일 뿐 실제 file content는 확인하지 않는다.

### Pattern B — 보수적 고신뢰 후보

Action: `READ_FILE`

Context: `data_type=credential` AND 구체적인 `credential_type`

왜 Core인가: `.aws/credentials`, kubeconfig, service-account token 등 명확한 대상을 분류하면
일반 설정 파일 read의 false positive를 낮춘다.

Static verification: `LEVEL2_EVIDENCE_GAP`, `MISSING_MAPPER`

정적 검증 한계: 동적 경로, glob, 변수, pipe, command substitution은 현재 parser 범위를 벗어난다.

## 7. Supporting Action

- 알려진 credential directory에서의 search/read 시도
- `WRITE_FILE(data_type=credential)`은 복사된 credential의 목적지가 식별될 때 supporting evidence
- 일반 `READ_FILE`은 대상 분류가 없으면 너무 넓어 단독 supporting으로도 신중해야 한다.

## 8. 현재 Rule과 비교

| 현재 Rule | 판단 | 제안 |
|---|---|---|
| `credential-file-read` | `KEEP` | 의미적으로 적절하다. path/data classifier와 mapper 구현이 선행돼야 한다. |

## 9. Command → Action Mapping 상태

| Action + Context | 상태 | 필요한 작업 |
|---|---|---|
| `READ_FILE(data_type=credential)` | `LEVEL2_EVIDENCE_GAP`, `MISSING_MAPPER` | read command의 source operand fact와 credential path classifier |
| `credential_type=<type>` | `LEVEL2_EVIDENCE_GAP` | 제한된 고신뢰 path/signature metadata |
| 일반 `cat` operand mapping | `PARTIAL` | CLI mapping은 있으나 read resource/fact가 없음 |

## 10. 최종 제안

Core: `READ_FILE(data_type=credential)` 유지.

Supporting: credential 경로 탐색과 식별된 credential 복사.

Rule 변경: 현재 Core 유지, 필요 시 구체 credential type pattern을 추가한다.

Mapper 변경: Level 2 read evidence를 `READ_FILE`로 변환한다.

Level 2 변경 필요: read source resource/fact 및 보수적 credential path classification.

사람 검토 필요: 실제 file content, credential 획득과 재사용 여부.

## 11. 근거

- [MITRE ATT&CK T1552.001 Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)
- 공식 페이지의 cloud/container credential file 설명과 Procedure Examples
- 프로젝트 snapshot: `data/enterprise-attack-19.2-techniques.json`

# T1611 Escape to Host

## 1. ATT&CK 의미

ATT&CK Technique 전체 의미는 container 또는 virtualized environment의 경계를 벗어나 underlying
host에 접근하는 것이다. 취약점 악용, host filesystem bind mount, host namespace 진입, container
runtime socket 악용, 과도한 권한 설정 등 여러 경로가 존재한다.

## 2. Static Validator가 확인할 수 있는 범위

정적 command에서는 `nsenter`로 특정 process namespace 진입, host device/filesystem mount,
`chroot`, container runtime socket 사용과 같은 escape chain 후보를 확인할 수 있다. 그러나 command
실행 출발점이 실제 container인지, target namespace/filesystem이 실제 host인지, exploit이 성공했는지는
확정할 수 없다. `/host` 같은 경로 이름만으로 host context를 추론하면 안 된다.

## 3. Technique 행위 분해

1. container/VM 경계 밖으로 이어지는 host primitive를 확보한다.
2. host namespace, filesystem, kernel 또는 runtime control plane에 접근한다.
3. underlying host 문맥에서 파일 또는 process를 조작하거나 코드를 실행한다.
4. 런타임에서 격리 경계 이탈이 실제로 성립한다.

## 4. 기존 Action + Context 대응

| 행위 | Action | Context | 기존 vocabulary 사용 가능 |
|---|---|---|---|
| host namespace 진입 | `ENTER_NAMESPACE` | `namespace_context=host`, `namespace_type=<kind>` | 가능 |
| host filesystem mount | `MOUNT_FILESYSTEM` | `target_context=host` | 가능 |
| runtime socket 접근 | `CONNECT_SOCKET` | `socket_type=container_runtime` | 가능 |
| host kernel module/BPF 조작 | `LOAD_KERNEL_MODULE`/`LOAD_BPF_PROGRAM` | `target_context=host` | 가능 |
| 격리 탈출 성공 | 위 Action의 runtime 결과 | - | command-only로 확정 불가 |

## 5. Action / Context 추가 필요 여부

### Action

추가하지 않는다. host 접근 경로는 기존 namespace, mount, socket, kernel Action으로 표현 가능하다.

### Context

추가하지 않는다. `namespace_context`, `target_context`, `socket_type`이 이미 있다. 문제는 어휘가
아니라 host라는 값을 신뢰성 있게 도출할 evidence다.

## 6. Core Pattern 제안

### Pattern A — Host namespace 진입

Action: `ENTER_NAMESPACE`

Context: `namespace_context=host`

왜 Core인가: container의 격리 경계를 넘어 host namespace에 들어가는 것은 escape의 직접적인 형태다.

Static verification: `MISSING_MAPPER`, `STATICALLY_UNVERIFIABLE`

정적 검증 한계: Level 2는 `nsenter` target PID와 namespace 종류를 추출하지만 PID 1 등이 host PID인지
command만으로 확정하지 못한다.

### Pattern B — Host filesystem 접근

Action: `MOUNT_FILESYSTEM`

Context: `target_context=host`

왜 Core인가: container 내부에 host filesystem을 노출하는 mount는 실제 host object 접근에 가깝다.

Static verification: `PARTIAL`, `STATICALLY_UNVERIFIABLE`

정적 검증 한계: 현재 mapper는 Context 없는 mount만 생성한다. device source와 target path만으로
host filesystem임을 증명할 수 없다.

## 7. Supporting Action

- `CREATE_NAMESPACE`: exploit/escape chain의 준비일 수 있으나 namespace 생성 자체는 escape가 아니다.
- `CONNECT_SOCKET(socket_type=container_runtime)`: host runtime 제어로 이어질 수 있으나 연결만으로 부족하다.
- `MOUNT_FILESYSTEM` without `target_context=host`: 관련 가능성은 있지만 host 의미가 해결되지 않았다.
- `chroot`는 이미 접근 가능한 root tree의 root directory를 바꿀 뿐이며 mount dependency나 escape를
  자체적으로 증명하지 않는다.

## 8. 현재 Rule과 비교

| 현재 Rule | 판단 | 제안 |
|---|---|---|
| `enter-host-namespace` | `KEEP` | 개념적으로 적절하되 host Context를 runtime/환경 근거 없이 생성하지 않는다. |
| `mount-host-filesystem` | `KEEP` | host Context가 검증된 경우에만 Core다. |
| supporting `CREATE_NAMESPACE` | `KEEP` | 단독 match 금지와 낮은 증거 강도를 명시한다. |

## 9. Command → Action Mapping 상태

| Action + Context | 상태 | 필요한 작업 |
|---|---|---|
| `CREATE_NAMESPACE(namespace_type=...)` | `IMPLEMENTED` | supporting으로만 사용 |
| `ENTER_NAMESPACE(namespace_type=...)` | `MISSING_MAPPER` | 기존 Level 2 nsenter fact를 소비하는 mapper 추가 |
| `ENTER_NAMESPACE(namespace_context=host)` | `STATICALLY_UNVERIFIABLE` | container/host PID namespace 관계의 환경 evidence 필요 |
| `MOUNT_FILESYSTEM` | `PARTIAL` | Action은 있으나 `target_context`가 없음 |
| `MOUNT_FILESYSTEM(target_context=host)` | `LEVEL2_EVIDENCE_GAP`, `STATICALLY_UNVERIFIABLE` | trusted host-context evidence 필요 |
| `CONNECT_SOCKET(container_runtime)` | `LEVEL2_EVIDENCE_GAP`, `MISSING_MAPPER` | socket path/API evidence 추출 |

## 10. 최종 제안

Core: host Context가 검증된 namespace 진입 또는 filesystem mount.

Supporting: namespace 생성, runtime socket 접근, host 미확정 mount.

Rule 변경: Core 구조는 유지하되 host Context 생성 조건을 명시하고 supporting을 보강한다.

Mapper 변경: nsenter fact를 `ENTER_NAMESPACE`로 변환하고 mount의 source/target evidence를 보존한다.

Level 2 변경 필요: host Context 자체는 command-only evidence만으로 해결하기 어렵다.

사람 검토 필요: 실행 출발 환경, target이 실제 host인지, escape 성공 여부.

## 11. 근거

- [MITRE ATT&CK T1611 Escape to Host](https://attack.mitre.org/techniques/T1611/)
- 공식 페이지의 Procedure Examples와 Detection Strategy
- 프로젝트 snapshot: `data/enterprise-attack-19.2-techniques.json`

## 공통 구현 우선순위 결론

1. 기존 Level 2 fact가 있는 `curl`, `nsenter`, `kill`을 Level 3 Action Mapper가 소비하도록 연결한다.
2. semantic Core가 잘 정의된 T1552.005와 T1105부터 mapper gap을 닫는다.
3. T1548.001은 permission-only match를 낮추고 동일 파일 실행 상관을 지원한다.
4. T1610은 socket 접근을 Core에서 내리고 `CREATE_CONTAINER` 도입 및 Level 2 evidence를 먼저 설계한다.
5. T1562.001은 mapper보다 먼저 revoked ID/T1685 migration 정책을 결정한다.
6. T1611과 T1620의 host escape/reflective execution 성공은 command-only 결과로 확정하지 않고 REVIEW
   또는 runtime 검증으로 남긴다.
