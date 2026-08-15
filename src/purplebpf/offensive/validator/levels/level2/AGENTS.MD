# Level 2 — Command & Chain Validation

## 목적

Level 2는 LLM이 생성한 공격 시나리오의 각 Shell command를 정적으로 해석하고,

- 명령어와 인자 구조가 해석 가능한지
- CLI 사용이 명세상 유효한지
- 공격 단계 사이의 resource dependency가 논리적으로 성립하는지

를 검증한다.

Level 2는 실제 명령을 실행하지 않는다.

실제 커널 동작, 권한, capability, namespace, seccomp, LSM, kernel configuration 등
실행 환경에 의존하는 검증은 Level 2의 책임이 아니다.

---

## 전체 흐름

```text
Scenario Step
    ↓
bashlex
    ↓
ExplainShell-style Argument Mapper
    ↓
executable / option / operand
    ↓
CLI Validity Check
    ↓
Resource Mapping
    ↓
Dependency Check
    ↓
PASS / REVIEW / REJECT
````

---

## 1. Shell Parsing

Shell command의 구조 분석에는 `bashlex`를 사용한다.

bashlex의 역할은 다음과 같다.

* executable 추출
* argv 및 shell word 추출
* Shell command 구조 파악

bashlex 자체는 command-specific option이나 operand의 의미를 판단하지 않는다.

복잡한 Shell 구조를 현재 구현이 안전하게 해석하지 못하는 경우,
억지로 추론하지 않고 REVIEW 대상으로 처리한다.

---

## 2. Argument Mapping

bashlex에서 추출된 word를 ExplainShell과 유사한 방식으로 해석한다.

목표는 command argument를 다음과 같은 일반 구조로 분리하는 것이다.

* executable
* option
* option value
* operand

예:

```text
mount -t ext4 /dev/sda1 /host

executable
→ mount

option
→ -t

option value
→ ext4

operand #1
→ /dev/sda1

operand #2
→ /host
```

모든 Linux command의 argument 구조를 직접 하드코딩하는 방식은 지양한다.

가능한 경우 기존 CLI 명세 또는 ExplainShell 계열 구조를 참고해
일반적인 argument mapping을 수행한다.

---

## 3. CLI Validity Check

Argument Mapping 결과를 기반으로 command invocation 자체가 유효한지 확인한다.

대표적인 판정은 다음과 같다.

```text
UNSUPPORTED_COMMAND
→ Validator가 해당 command를 지원하지 않음
→ REVIEW

UNMAPPED_ARGUMENT
→ argument의 역할을 신뢰성 있게 결정하지 못함
→ REVIEW

INVALID_OPTION
→ command 명세에 존재하지 않는 option
→ REJECT

INVALID_ARGUMENT
→ argument 개수, 위치, 형식 등이 명세와 불일치
→ REJECT
```

핵심 원칙은 다음과 같다.

```text
판단할 수 없음
→ REVIEW

명세상 명백히 잘못됨
→ REJECT
```

---

## 4. Resource Mapping

CLI 검증을 통과한 command 중 공격 체인 연결에 필요한 command에 대해서만
resource 의미를 부여한다.

Resource는 공격 단계 사이에서 생성되거나 요구되는 객체 또는 상태를 의미한다.

예:

```text
touch /tmp/payload

→ file(path=/tmp/payload)
```

```text
chmod +x /tmp/payload

→ file(path=/tmp/payload) 필요
```

Resource Mapping은 Linux 전체 command 의미를 모델링하는 것이 목적이 아니다.

공격 체인 검증에 필요한 핵심 command와 resource만 점진적으로 지원한다.

Resource의 정확한 의미를 결정할 수 없는 경우:

```text
UNRESOLVED_RESOURCE
→ REVIEW
```

로 처리한다.

---

## 5. Dependency Check

각 scenario step을 순서대로 처리하면서
이전 단계가 생성한 resource를 state에 누적한다.

개념적으로:

```text
현재 State
    ↓
현재 Step의 required resource 확인
    ↓
충족
    ↓
현재 Step의 effects / produced resource 반영
    ↓
다음 Step
```

예:

```text
Step 1
touch /tmp/a
→ file(/tmp/a) 생성

Step 2
chmod +x /tmp/a
→ file(/tmp/a) 요구

→ dependency 성립
→ PASS
```

반대로 시나리오 내부에서 반드시 선행되어야 하는 resource가 존재하지 않는 경우:

```text
MISSING_CHAIN_RESOURCE
→ REJECT
```

---

## 6. 판정 정책

Level 2는 다음 세 가지 상태를 사용한다.

### PASS

현재 Level 2가 검증하는 범위 내에서

* command parsing 성공
* CLI 구조 유효
* 필요한 resource dependency 충족

조건을 모두 만족한 경우이다.

### REVIEW

시나리오가 잘못되었다고 확정할 수 없지만
현재 Validator가 신뢰성 있게 자동 판정할 수 없는 경우이다.

예:

* parser가 구조를 해석하지 못함
* 지원하지 않는 command
* argument mapping 불확실
* resource 의미 해석 불가

### REJECT

현재 보유한 명세 또는 chain model을 기준으로
명백한 오류가 확인된 경우이다.

예:

* 존재하지 않는 option
* 잘못된 argument 구조
* 시나리오 내부에서 필요한 선행 resource 누락

전체 판정 우선순위는 다음과 같다.

```text
REJECT > REVIEW > PASS
```

---

## 7. Level 2의 책임 범위

Level 2가 검증하는 것:

```text
Shell command 구조
CLI interface validity
Resource dependency
Attack step ordering
```

Level 2가 검증하지 않는 것:

```text
실제 command 실행 성공 여부
실제 exploit 성공 여부
CVE 재현 여부
Kernel race 성공 여부
Privilege / capability 충족 여부
Kernel version / config 적합성
Namespace 구성
seccomp
LSM
Container runtime 환경
Tetragon 탐지/차단 여부
```

이러한 환경 의존 조건은 이후 Environment Validation 단계에서 처리한다.

---

## 구현 원칙

* 실제 공격 command를 실행하지 않는다.
* 정적 분석만 수행한다.
* 판단 근거가 부족하면 추측하지 않는다.
* 자동 분석의 한계는 REVIEW로 표현한다.
* 명백한 명세 위반만 REJECT한다.
* Linux 전체 command를 직접 모델링하지 않는다.
* Resource rule은 공격 체인 검증에 필요한 범위만 추가한다.
* Level 2 외부에서는 내부 parser/engine 세부 구현에 직접 의존하지 않도록 한다.
* Level 2의 최종 진입점은 하나의 validator interface로 유지한다.

```