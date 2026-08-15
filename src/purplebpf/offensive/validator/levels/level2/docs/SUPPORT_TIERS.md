# Level 2 Support Tier 구현 문서

이 문서는 Level 2가 command별 분석 깊이를 `full`, `metadata`, `generic`으로
구분하는 기준과 운영 절차를 설명한다. 전체 parser, resource chain, 최종 판정에
대한 설명은 [README.md](README.md)를 참고한다.

## 1. 도입 목적

Linux command 전체를 한 번에 같은 깊이로 지원하기는 어렵다. 지원 여부를 단순한
boolean으로 표현하면 다음 두 상태를 구분할 수 없다.

- CLI 문법은 검증할 수 있지만 resource/semantic 의미는 아직 모델링하지 않은 command
- executable과 argv만 안전하게 추출할 수 있는 command

Level 2는 이 차이를 명시하기 위해 각 invocation에 `support_tier`를 기록한다.
Tier는 command가 위험한지 또는 scenario가 성공하는지를 나타내지 않는다. 현재
Validator가 해당 invocation을 **어느 깊이까지 정적으로 분석할 수 있는지**를
나타내는 capability 정보다.

## 2. 세 가지 Tier

| Tier | CLI metadata | Resource/semantic rule | 분석 범위 |
|---|---|---|---|
| `full` | 있음 | `facts`가 있는 rule 있음 | CLI, resource, semantic fact |
| `metadata` | 있음 | fact rule 없음 | CLI option/value/operand와 validity |
| `generic` | 없음 | Tier 결정에 사용하지 않음 | executable과 argv 보존 |

### 2.1 Full

`full`은 승인된 CLI metadata와 declarative semantic fact rule을 모두 가진
command다.

- option, option value, operand를 구분한다.
- 잘못된 option이나 operand 구조를 판정한다.
- resource rule이 있으면 `requires`와 `produces`를 계산한다.
- semantic rule에서 정규화된 fact를 만든다.
- 필요한 semantic evidence를 얻지 못하면 `UNRESOLVED_SEMANTIC`으로 REVIEW할 수
  있다.

현재 `full` command:

- `chmod`
- `unshare`
- `nsenter`
- `mount`
- `curl`
- `kill`

### 2.2 Metadata

`metadata`는 승인된 CLI metadata가 있지만 semantic fact rule은 없는 command다.

- executable과 argv를 추출한다.
- known option, option value, operand와 operand position을 매핑한다.
- `INVALID_OPTION`, `INVALID_ARGUMENT`, `UNMAPPED_ARGUMENT`을 구분한다.
- command 의미를 추측해 resource나 fact를 만들지 않는다.

현재 `metadata` command:

- 기존 metadata command: `touch`, `chroot`
- 이번에 승인한 command: `wget`, `cat`, `pkill`, `grep`, `tar`

예를 들어 다음 invocation은 CLI 검증을 통과하지만 resource와 fact는 비어 있다.

```shell
wget -O /tmp/a https://example.com/a
```

```json
{
  "support_tier": "metadata",
  "elements": [
    {"raw": "-O", "type": "option"},
    {"raw": "/tmp/a", "type": "option_value", "option": "-O"},
    {"raw": "https://example.com/a", "type": "operand", "position": 1}
  ],
  "cli_validation": {"valid": true, "code": null},
  "resources": {"requires": [], "produces": []},
  "facts": []
}
```

### 2.3 Generic

`generic`은 승인된 CLI metadata가 없는 command다.

- Shell parser가 executable과 argv를 보존한다.
- option/operand의 의미를 추측하지 않는다.
- `elements`는 비어 있다.
- CLI 상태는 `valid: null`, `code: UNSUPPORTED_COMMAND`다.
- scenario 판정에서는 명백한 오류인 REJECT가 아니라 REVIEW 후보가 된다.

예:

```shell
socat TCP:example.com:80 -
```

```json
{
  "support_tier": "generic",
  "executable": {"raw": "socat", "normalized": "socat"},
  "argv": ["TCP:example.com:80", "-"],
  "elements": [],
  "cli_validation": {
    "valid": null,
    "code": "UNSUPPORTED_COMMAND"
  },
  "resources": {"requires": [], "produces": []},
  "facts": []
}
```

`UNSUPPORTED_COMMAND`는 command가 실제로 존재하지 않는다는 뜻이 아니다. 현재
Validator에 승인된 CLI metadata가 없다는 뜻이다.

## 3. 자동 판정 방식

Tier 판정의 단일 진입점은 `levels/level2/support_tier.py`의
`resolve_support_tier()`다. command 이름 allowlist나 metadata 내부의 수동
`support_tier` 필드를 사용하지 않는다.

```text
승인된 CLI metadata가 있는가?
├─ 아니오 → generic
└─ 예
   └─ command semantic rule에 비어 있지 않은 facts가 있는가?
      ├─ 예   → full
      └─ 아니오 → metadata
```

개념적인 구현은 다음과 같다.

```python
if metadata_provider.get(executable) is None:
    return "generic"

rule = semantic_rule_provider.get(executable)
if rule is not None and bool(rule.get("facts")):
    return "full"

return "metadata"
```

따라서 metadata 또는 semantic rule이 추가·제거되면 별도 allowlist 수정 없이 Tier가
자동으로 바뀐다. `validator.py`와 command usage 통계도 동일한 resolver를 사용한다.

## 4. Tier와 PASS/REVIEW/REJECT의 관계

`support_tier`와 Level 2 `status`는 서로 다른 축이다.

| 항목 | 의미 |
|---|---|
| `support_tier` | Validator가 제공할 수 있는 분석 깊이 |
| `status` | 해당 분석 결과로 내린 scenario/step 판정 |

대표적인 관계는 다음과 같다.

- 유효한 `full` command라도 required semantic evidence가 없으면 REVIEW할 수 있다.
- `metadata` command의 승인 범위에 없는 option은 `INVALID_OPTION`으로 REJECT할 수
  있다.
- `generic` command는 CLI를 검증하지 못하므로 REVIEW 대상이다.
- Tier는 실제 command 실행 성공, 권한, capability 또는 공격 성공을 보장하지 않는다.

최종 status 우선순위는 Tier와 무관하게 기존 정책을 유지한다.

```text
REJECT > REVIEW > PASS
```

## 5. Metadata 신뢰 경계

Tier 판정에 사용되는 CLI metadata는
`levels/level2/rules/cli_metadata.json`에 있는 runtime metadata다.

`JsonMetadataProvider`는 다음 원칙으로 metadata를 로드한다.

1. `provenance`가 없는 기존 정적 항목은 이전 동작과의 호환을 위해 로드한다.
2. `provenance`가 있다면 `review_status`가 `APPROVED`인 항목만 로드한다.
3. `PENDING` 항목은 지원 metadata로 인정하지 않는다.
4. `rules/generated/` 아래 후보 파일은 runtime source로 읽지 않는다.

이 경계를 통해 자동 생성 결과의 오탐이 즉시 runtime 검증이나 Tier 판정에
반영되는 것을 막는다.

## 6. Metadata 후보 생성

개발자는 다음 명령으로 로컬 command의 후보 metadata를 생성할 수 있다.

```bash
export PYTHONPATH=src/purplebpf/offensive/validator

python -m levels.level2.tools.metadata_generator \
  wget cat pkill grep tar \
  --output-dir /tmp/purplebpf-metadata-candidates
```

생성기는 다음 순서로 로컬 문서를 조사한다.

1. `<command> --help`
2. help에서 option을 얻지 못한 경우 noninteractive local man page
3. 확인된 경우에만 `<command> --version`

실제 command operation은 실행하지 않는다. subprocess는 shell 없이 실행하고,
timeout과 고정 locale 및 noninteractive pager 설정을 사용한다.

생성된 후보에는 다음 값이 기록된다.

- command와 schema version
- source type과 실행한 documentation argv
- command version 및 synopsis
- option alias, required/optional value와 value name
- 생성 시각과 generator version
- warning과 source 시도 내역
- `review_status: PENDING`

Positional operand의 `min`, `max`, semantic role은 help synopsis만으로 안전하게
확정하기 어려우므로 자동 생성하지 않는다.

## 7. 승인 및 Tier 승격 절차

새 command는 다음 절차로 `generic`에서 승격한다.

### Generic → Metadata

1. generator로 candidate를 만든다.
2. 실제 대상 버전의 help/man page와 candidate를 대조한다.
3. option alias와 option value 요구 조건을 검토한다.
4. operand `min`, `max`, pattern을 사람이 결정한다.
5. 필요한 경우 `allow_short_option_clusters`를 명시한다.
6. 검증할 수 있는 subset만 `cli_metadata.json`에 복사한다.
7. provenance에 `review_status: APPROVED`와 검토 정보를 기록한다.
8. 정상/오류/경계 테스트를 추가한다.

승인 metadata가 provider에 로드되면 resolver가 자동으로 `metadata` Tier를 반환한다.

### Metadata → Full

1. command가 만들어 내는 ATT&CK 비종속 normalized fact를 정의한다.
2. `resource_rules.json`의 command rule에 non-empty `facts`를 추가한다.
3. 필요한 resource `requires`/`produces`를 실제 chain 의미에 맞게 정의한다.
4. option form별 fact/resource 추출과 unresolved 조건을 테스트한다.
5. Level 3가 실제 evidence를 소비하는지 회귀 테스트한다.

non-empty fact rule이 승인 metadata와 함께 존재하면 resolver가 자동으로 `full`을
반환한다.

## 8. 이번 Tier 2 승인 범위

이번 작업에서는 다음 다섯 command에 검토된 metadata subset을 추가했다.

| Command | 주요 승인 문법 |
|---|---|
| `wget` | URL operand, `-O/--output-document`, quiet/continue/tries/prefix 등 |
| `cat` | file operand와 대표 GNU cat option, short cluster |
| `pkill` | pattern operand, 대표 filter option과 signal option pattern |
| `grep` | pattern/file operand, `-e`, `-f`, recursive/matching option, short cluster |
| `tar` | create/extract/list subset, compression option, `-f`, `-C`, short cluster |

승인 범위 밖의 전체 GNU/POSIX 문법까지 지원한다고 간주하지 않는다.

### tar cluster 예

```shell
tar -xzf payload.tar.gz -C /tmp
```

`allow_short_option_clusters`에 따라 다음처럼 매핑한다.

```json
[
  {"raw": "-x", "type": "option"},
  {"raw": "-z", "type": "option"},
  {"raw": "-f", "type": "option"},
  {"raw": "payload.tar.gz", "type": "option_value", "option": "-f"},
  {"raw": "-C", "type": "option"},
  {"raw": "/tmp", "type": "option_value", "option": "-C"}
]
```

이는 `tar` command 이름에 대한 parser 특례가 아니라 metadata-driven matcher
기능이다. 전통적인 dash 없는 `tar xzf ...` 문법 전체는 현재 모델링하지 않는다.

## 9. 복합 Shell command

한 step에 여러 invocation이 있으면 각 invocation이 독립적인 `support_tier`를 가진다.
step에 포함된 Tier가 하나뿐이면 그 값을 사용하고 둘 이상이면 step 요약은
`support_tier: mixed`가 된다. 상세 결과는 `commands` 트리의 각 invocation에서
확인한다.

예:

```shell
wget https://example.com/a | socat - TCP:example.com:80
```

```text
wget  → metadata
socat → generic
step  → mixed
```

Tier는 pipeline의 데이터 흐름이나 실제 실행 결과를 검증한다는 뜻이 아니다. Shell
operator는 구조적으로 보존되고 각 invocation의 분석 깊이만 구분한다.

## 10. Level 3와의 관계

Level 3는 `support_tier == "full"` 같은 이름 기반 gate로 action을 만들지 않는다.
Level 2가 제공한 실제 fact, resource 또는 executable evidence를 사용한다.

따라서 `metadata` command가 CLI valid여도 evidence가 없다면 Level 3는 action을
임의로 만들지 않는다. 반대로 generic command라도 안전하게 사용할 수 있는 실제
evidence가 있다면 Tier 이름 자체가 mapping을 막지 않는다.

## 11. 테스트

Tier 관련 테스트는 `tests/test_level2_metadata_support.py`와
`tests/test_level2_generic_extraction.py`에 있다.

주요 검증 항목:

- `mount → full`, `wget → metadata`, `socat → generic`
- 다섯 candidate가 help source와 `PENDING` 상태로 생성되는지 확인
- generated candidate가 runtime metadata로 사용되지 않는지 확인
- `PENDING` provenance가 provider에서 제외되는지 확인
- 다섯 승인 command의 정상 CLI mapping
- `wget --definitely-invalid-option`의 `INVALID_OPTION`
- `tar -xzf ... -C ...` cluster mapping
- Level 3가 Tier 2 command를 evidence 없이 action으로 매핑하지 않는지 확인
- 여러 invocation의 Tier 및 usage statistics 계산

실행:

```bash
cd /home/ubuntu/purplebpf

PYTHONDONTWRITEBYTECODE=1 \
PYTHONPATH=src/purplebpf/offensive/validator \
/home/ubuntu/scenario-validator/.venv/bin/python -B \
-m unittest discover -s tests -v
```

## 12. 현재 한계

- 자동 generator 결과는 후보일 뿐 정확성을 보장하지 않는다.
- local help/man 내용은 배포판과 command version에 따라 달라질 수 있다.
- 승인 metadata는 의도적으로 전체 CLI가 아닌 검증 가능한 subset이다.
- help synopsis에서 positional operand 구조를 자동 확정하지 않는다.
- optional value와 short-option cluster의 모든 조합을 지원하지 않는다.
- 전통적인 dash 없는 tar option grammar는 지원하지 않는다.
- `metadata` Tier는 resource나 공격 의미를 자동 부여하지 않는다.
- `generic` Tier는 command의 존재 여부나 유효성을 부정하지 않는다.
- 어떤 Tier도 실제 실행 성공, 환경 조건 또는 공격 성공을 검증하지 않는다.

