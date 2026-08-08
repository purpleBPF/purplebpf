# Local Enterprise ATT&CK data

`enterprise-attack-19.2-techniques.json`은 MITRE의 공식
[`attack-stix-data`](https://github.com/mitre-attack/attack-stix-data) 저장소에 있는
Enterprise ATT&CK v19.2 STIX 2.1 bundle에서 Level 3 Technique lookup에 필요한
객체만 필터링한 로컬 bundle이다.

- 원본 파일: `enterprise-attack/enterprise-attack-19.2.json`
- ATT&CK 릴리스: 19.2
- 원본 commit: `6cda5ad8462c79e14fbb872f4e09059b18e0cfc4`
- commit 날짜: 2026-08-05
- 원본 SHA-256: `dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4`
- 로컬 subset SHA-256: `e217a7dc949db52b8f87bc4df34cb0ef51e472588f8012a52d55af161df33694`
- 포함 STIX 객체:
  - `attack-pattern`
  - `x-mitre-tactic`
  - `relationship` 중 `relationship_type == "subtechnique-of"`

Provider 실행 시 네트워크를 사용하지 않는다. 데이터 갱신 시 공식 bundle을 받은 뒤
다음과 같은 필터를 적용해야 한다.

```sh
jq '{type, id, objects: [.objects[] | select(
  .type == "attack-pattern" or
  .type == "x-mitre-tactic" or
  (.type == "relationship" and .relationship_type == "subtechnique-of")
)]}' enterprise-attack-19.2.json > enterprise-attack-19.2-techniques.json
```

데이터 사용 조건은 [LICENSE.txt](LICENSE.txt)를 참고한다.
