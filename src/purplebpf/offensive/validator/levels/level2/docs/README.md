# Scenario Validator Level 2

이 문서는 현재 `levels/level2/` production code, JSON rule, tests와 100-case
evaluation을 기준으로 작성한 구현 문서다. Level 2는 command를 실행하지 않고 Shell
구조, CLI 사용, scenario 내부 resource dependency를 정적으로 검증하며 Level 3가
사용할 Technique 독립적인 Fact를 생성한다.

지원 깊이와 metadata 승인 절차는 [SUPPORT_TIERS.md](SUPPORT_TIERS.md), 평가 실행법은
[Evaluation README](../evaluation/README.md)를 함께 참고한다.

## 1. 목적과 책임 범위

Level 2가 확인하는 것은 Shell invocation과 operator, executable별
option/option-value/operand, 명백한 CLI 오류, scenario-local Resource와 step
dependency, 정규화된 Fact다.

실제 command 성공, 파일·device 존재, 권한, capability, kernel 설정, namespace
관계, mount 성공, seccomp, LSM, container runtime 상태는 확인하지 않는다. 이러한
environment prerequisite는 Level 4의 책임이다.

## 2. 전체 Pipeline

```text
Scenario Step
    ↓
bashlex Shell Parsing
    ↓
Command IR: executable + argv + composition
    ↓
CLI Metadata Lookup
    ↓
Argument Mapping + CLI Validity
    ↓
Resource Mapping        Semantic Fact Mapping
    ↓                         ↓
requires / produces      Technique-independent Facts
    ↓                         ↓
Scenario Chain Check      Level 3 input
    ↓
PASS / REVIEW / REJECT
```

`validate_command()`는 단순 command 하나, `validate_shell()`은 합성 Shell의 모든
invocation, `validate_scenario()`는 order 정렬과 dependency 및 최종 상태를 다룬다.

## 3. Shell Parsing과 Composition

`command_parser.py`는 `bashlex` AST를 사용한다. 첫 word는 executable `raw`,
`os.path.basename()` 결과는 `normalized`로 보존한다. 단순 공백 분할은 하지
않으며 expansion, redirect, assignment처럼 지원하지 않는 AST는
`CommandParseError`로 실패한다.

| 구조 | 현재 처리 |
|---|---|
| `a && b`, `a || b`, `a; b` | invocation과 operator 보존 |
| `a \| b` | pipeline 양쪽 invocation과 `\|` 보존 |
| `bash -c '...'`, `sh -c '...'` | payload를 최대 depth 3까지 재귀 분석 |
| 다른 interpreter의 `-c` | 일반 argv로 유지 |

Operator는 `left_index`, `right_index`를 가진다. 현재
`shell_structure=structural_only`이며 branch 선택, exit status, pipeline data
flow를 시뮬레이션하지 않는다. 최대 depth에서는 `nested_truncated: true`가 붙는다.

단일-command 계약인 `parse_command()`는 pipeline/list/redirect/assignment와
parameter 또는 command substitution을 거부한다. Scenario entry point는 합성 구조를
위해 `validate_shell()`을 사용한다.

## 4. Command IR

```json
{
  "raw_command": "mount -t ext4 /dev/sda1 /host",
  "executable": {"raw": "mount", "normalized": "mount"},
  "argv": ["-t", "ext4", "/dev/sda1", "/host"],
  "index": 1,
  "operator_before": null
}
```

`validate_shell()`은 `raw_command`, `commands`, `operators`, `analysis`를
반환한다. 각 command에는 `support_tier`, `elements`, `cli_validation`,
`resources`, `facts`와 validation 상태가 추가된다. `bash/sh -c` wrapper에는
`nested_commands`와 `nested_operators`가 재귀적으로 붙는다.

## 5. Argument Mapping과 CLI Validity

Argument Mapper는 ExplainShell의 핵심 분리 방식인 다음 흐름을 작은 정적 구현으로
재구성했다.

```text
executable lookup → command metadata → argv 순차 matching
```

ExplainShell 코드나 SQLite/man-page extraction pipeline을 포함하지 않는다. Runtime
source는 승인된 `cli_metadata.json`이며 `MetadataProvider` protocol로 교체할 수
있다.

```json
[
  {"raw": "-t", "type": "option"},
  {"raw": "ext4", "type": "option_value", "option": "-t"},
  {"raw": "/dev/sda1", "type": "operand", "position": 1},
  {"raw": "/host", "type": "operand", "position": 2}
]
```

Mapper는 exact short/long option, `--name=value`, required attached short value,
승인된 short-option cluster와 `--` terminator를 처리한다. Option value는 operand
position에 포함되지 않는다. `chmod +x /tmp/a`의 `+x`는 positional MODE
operand이며 prefix만으로 option을 판정하지 않는다.

CLI metadata는 option aliases와 value mode(`none`, `required`,
`optional_attached`), regex, operand min/max와 position rule, cluster/ambiguous
short-option 정책을 포함한다. Provenance가 있으면 `review_status=APPROVED`만
runtime에 로드한다. `cli_validation.valid`는 `true/false/null`의 3-state다.

## 6. Support Tier

Tier는 command allowlist가 아니라 현재 사용 가능한 layer로 계산된다. JSON 값은
소문자 `full`, `metadata`, `generic`이다.

| Tier | 판정 기준 | 현재 command |
|---|---|---|
| FULL | 승인 CLI metadata + 하나 이상의 semantic Fact rule | `cat`, `chmod`, `curl`, `kill`, `mount`, `nsenter`, `unshare` |
| METADATA | 승인 CLI metadata, Fact rule 없음 | `chroot`, `grep`, `pkill`, `tar`, `touch`, `wget` |
| GENERIC | CLI metadata 없음; executable/argv만 보존 | 그 밖의 command, 예: `socat` |

Resource rule만 있는 `touch`는 현재 계산식상 METADATA다. GENERIC은 parser 오류가
아니지만 CLI를 검증할 수 없어 `UNSUPPORTED_COMMAND`와 REVIEW가 된다. Tier는
안전성이나 실제 command 존재 여부가 아니라 분석 깊이다.

## 7. Resource Model과 Rule

Resource는 scenario 내부 chain 연결용 `type + identity` 값이다.

```json
{"type": "file", "identity": {"path": "/tmp/payload"}}
```

Identity는 정렬된 canonical JSON key로 비교한다. 현재 type은 `file`, `mount`,
`namespace`이며 lifecycle update/delete와 실제 OS state는 모델링하지 않는다.

| Command | requires | produces |
|---|---|---|
| `touch PATH...` | 없음 | 각 operand의 `file(path)` |
| `chmod MODE PATH...` | 각 target의 `file(path)` | 없음 |
| `mount SOURCE TARGET` | 없음 | `mount(source,target)` |
| `unshare` namespace option | 없음 | option별 `namespace(kind)` |
| `chroot`, `nsenter`, `kill`, `cat` | 없음 | 없음 |
| `curl -o/--output PATH URL` | 없음 | `file(path)` |

`mount --source ... --target ...`도 option value를 우선 사용한다. Rule이 없는
command는 resource-free로 resolved이며, 필수 identity를 만들지 못하면
`UNRESOLVED_RESOURCE`다.

## 8. Fact Model

Fact는 ATT&CK에 종속되지 않은 정적 의미다. 값이 없으면 section/key를 만들지 않는다.

```json
{
  "type": "namespace",
  "identity": {"target_pid": "1"},
  "attributes": {"operation": "enter", "kind": "mount"},
  "evidence": {"option": "-m"}
}
```

| Fact type | Source | 주요 내용 |
|---|---|---|
| `permission` | `chmod` | path; permission, operation, path_type; mode |
| `namespace` | `unshare`, `nsenter` | target_pid(enter); operation, kind; option |
| `process` | `nsenter -t/--target` | target_pid; `role=namespace_target`; option |
| `mount` | `mount` | source, target; operation, source_type, filesystem_type |
| `endpoint` | `curl` URL | url; protocol, address, 선택적 class |
| `transfer` | `curl` URL | source/output_path; direction, output_path_type |
| `process_signal` | `kill` | target_pid; normalized signal |
| `file_access` | `cat` operand | path; read와 선택적 path/data/credential type; operand/classifier evidence |

현재 classifier는 temporary path(`/tmp/`, `/var/tmp/`, `/dev/shm/`), 정확한
`169.254.169.254` cloud metadata endpoint, AWS credentials, kubeconfig,
Kubernetes service-account token과 SSH private-key의 고신뢰도 path rule만 쓴다.
경로는 lexical POSIX normalization만 하며 `~`, 환경 변수, symlink, filesystem을
해석하지 않는다.

`required: true`인 Fact를 추출하지 못하면 `UNRESOLVED_SEMANTIC`으로 REVIEW한다.
Fact는 Level 3 generic Fact-to-Action mapper의 입력이다.

## 9. Chain State와 Dependency

Step은 `order` 오름차순으로 처리된다. PASS step의 `requires`가 현재
`ResourceState`에 모두 있으면 `produces`를 추가한다.

```text
touch /tmp/a       → produces file(/tmp/a)
chmod +x /tmp/a    → requires file(/tmp/a) → 충족
```

반대 순서는 `MISSING_CHAIN_RESOURCE`와 REJECT다. 이는 실제 환경에 파일이 없다는
뜻이 아니라 현재 rule이 scenario 앞 단계에서 만들도록 모델링한 Resource가 없다는
뜻이다. 합성 step은 canonical traversal에서 앞 invocation의 produce와 후속
requirement를 aggregate하지만 operator runtime 조건은 평가하지 않는다. PASS가 아닌
step은 state에 반영하지 않는다.

## 10. 판정 정책과 Reason Code

집계 우선순위는 `REJECT > REVIEW > PASS`다.

| Code | Stage | 상태 | 의미 |
|---|---|---|---|
| `PARSER_ERROR` | parsing | REVIEW | 문법 오류 또는 지원하지 않는 AST |
| `UNSUPPORTED_COMMAND` | CLI | REVIEW | metadata 부재 |
| `UNMAPPED_ARGUMENT` | CLI | REVIEW | token 역할/형식 불확실 |
| `UNRESOLVED_RESOURCE` | resource | REVIEW | 필수 Resource 구성 실패 |
| `UNRESOLVED_SEMANTIC` | Fact | REVIEW | 필수 Fact 추출 실패 |
| `INVALID_OPTION` | CLI | REJECT | metadata상 명백한 option 오류 |
| `INVALID_ARGUMENT` | CLI | REJECT | 값, 개수 또는 형식 오류 |
| `MISSING_CHAIN_RESOURCE` | dependency | REJECT | 앞선 scenario Resource 누락 |

## 11. Evaluation Framework

```text
data/ground_truth.json → evaluate.py → validate_shell()
    → comparator.py → metrics.py → report + results/latest.json
```

Ground Truth는 사람이 작성한 정확히 100 cases다: tier1 60, tier2 25, composition
15. Subject는 `chmod`, `unshare`, `nsenter`, `mount`, `curl`, `kill`,
`wget`, `cat`, `pkill`, `grep`, `tar`와 composition이다. Comparator는
command multiset/순서, 3-state CLI, 전체 element, role 포함 Resource, 전체 Fact와
invocation Tier를 비교한다. PR/F1은 micro 집계이며 label은 exact accuracy와
confusion matrix를 쓴다.

현재 `results/latest.json`은 100 cases, 120 invocations에서 다음 결과를 기록한다.

| Metric | 최신 결과 |
|---|---|
| Command extraction P/R/F1, order | 1.0000 / 1.0000 / 1.0000, 1.0000 |
| CLI accuracy | 1.0000 (85/85) |
| Argument mapping P/R/F1 | 1.0000 / 1.0000 / 1.0000 |
| Resource P/R/F1 | 1.0000 / 1.0000 / 1.0000 |
| Fact P/R/F1 | 1.0000 / 1.0000 / 1.0000 |
| Tier accuracy | 1.0000 (120/120) |
| Failed cases / mismatch records | 0 / 0 |

이는 고정 dataset 회귀 결과이며 Linux CLI 전체에 대한 일반화 정확도가 아니다.
positive object가 없는 subject의 0.0은 미평가일 수 있어 TP/FP/FN과 함께 읽는다.

```bash
PYTHONPATH=src python -m \
  purplebpf.offensive.validator.levels.level2.evaluation.evaluate --no-write
```

## 12. Level 3 인터페이스

Level 3는 주어진 `level2_output`을 step `order`로 재사용하거나 자체적으로 각
step에 Level 2 `validate_shell()`을 호출한다. 주요 소비 필드는 executable,
elements, resources, facts와 합성 command tree다. Fact에는 Technique이 없고 Level
3가 generic rule로 Action + Context + Evidence를 만든 뒤 Technique rule과 비교한다.

## 13. 현재 한계

- CLI metadata는 13개 command의 승인 subset이며 전체 man page가 아니다.
- Expansion, redirect, assignment와 control structure는 지원하지 않는다.
- Composition은 구조 추출이며 branch, exit status, pipe data flow는 평가하지 않는다.
- Nested parsing은 `bash/sh -c`와 depth 3으로 제한된다.
- Resource는 exact identity match이며 alias, symlink, path equivalence가 없다.
- GENERIC command는 CLI·Resource·Fact를 확정하지 않는다.
- Classifier는 좁은 고신뢰도 목록만 쓰며 environment context를 추측하지 않는다.
- 실행 성공, exploit 성공, ATT&CK 의미 일치는 Level 2 판정이 아니다.

## 14. 주요 파일

| 파일 | 역할 |
|---|---|
| `validator.py` | command/shell/scenario 진입점과 집계 |
| `parser/command_parser.py` | bashlex, composition, nested shell 추출 |
| `parser/argument_mapper.py` | argv mapping과 CLI validity |
| `parser/metadata_provider.py` | 승인 metadata provider와 모델 |
| `support_tier.py` | layer 기반 Tier 계산 |
| `engine/resource_mapper.py` | Resource mapping |
| `engine/semantic_mapper.py` | Fact extraction |
| `engine/credential_classifier.py` | credential path classification |
| `engine/chain_validator.py` | ResourceState dependency 검사 |
| `rules/*.json` | CLI, Resource/Fact, credential rules |
| `evaluation/` | Ground Truth, comparator, metrics, runner, 결과 |
