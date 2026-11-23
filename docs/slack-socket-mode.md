# Slack 수신 방식 변경: ngrok HTTP → Socket Mode

## 왜 바꾸나

| | 변경 전 (HTTP Request URL) | 변경 후 (Socket Mode) |
|---|---|---|
| 연결을 여는 쪽 | Slack → 우리 서버 (인바운드) | 우리 프로세스 → Slack (아웃바운드 WebSocket) |
| 필요한 것 | 공개 HTTPS 주소(ngrok), Request URL 등록, Signing Secret | App-level Token(`xapp-`) 하나 |
| 수신 모듈 | `review/slack_callback.py` (FastAPI) | `review/slack_socket.py` |

```
[변경 전]  Slack ──POST──▶ ngrok(공개 URL) ──▶ FastAPI /slack/interactions
[변경 후]  slack_socket.py ──WebSocket 연결──▶ Slack
           Slack ──(이미 열린 연결로)── 버튼 클릭 envelope ──▶ slack_socket.py ──ACK──▶ Slack
```

**WebSocket으로 바뀌는 건 "Slack → 우리" 수신뿐이다.** 검수 메시지 발송(`slack_notify.py`, incoming webhook)이나
원본 메시지 갱신(`response_url`)은 지금처럼 HTTPS로 보낸다.

## 코드 구조

```
review/
├── decision.py        # 공통 로직: payload 파싱 → 판정 → 중복 검사 → response_url로 메시지 갱신
├── slack_socket.py    # [기본] Socket Mode 수신부: ACK 먼저 → decision 호출
├── slack_callback.py  # [비상용] HTTP 수신부: 서명 검증 → 200 먼저 → decision 호출(백그라운드)
└── slack_notify.py    # 검수 요청 메시지 발송 (변경 없음)
```

- **ACK 먼저 보내기**: Slack은 3초 안에 ACK가 없으면 같은 envelope를 다시 보낸다. 두 수신부 모두 처리 전에 ACK를 보낸다.
- **멱등 처리**: 버튼 클릭 payload에는 `event_id`가 없다. 그래서 `(channel_id, message_ts)`, 즉 검수 메시지 하나를 키로 쓴다.
  한 메시지에서 한 번 결정되면 그 뒤에 오는 클릭과 재전송은 `DUPLICATE`로 무시하고 메시지도 다시 갱신하지 않는다.
- **상태 전이**: `PENDING(메시지 발송) → APPROVED | REJECTED`. 결과에 `execution=NOT_LINKED`를 따로 남겨서
  **"승인 이벤트를 받음"과 "실제로 Docker에서 실행함"을 구분한다**.
- **재연결**: 연결이 끊기면 slack_sdk 내장 클라이언트가 자동으로 다시 연결한다(`auto_reconnect_enabled=True`). 끊기거나 오류가 날 때마다 WARNING 로그를 남긴다.
  처음 연결할 때 실패하면 이렇게 처리한다.
  - 토큰·권한 오류(`invalid_auth`, `missing_scope` 등): 바로 종료한다. 재시도해도 안 되기 때문이다.
  - 네트워크 오류: 2, 4, 8, 16초 간격으로 최대 5번 다시 시도한다.
- **의존성**: `slack_sdk` 하나만 추가했다. 이 라이브러리 자체는 외부 의존성이 없고, 내장 WebSocket 클라이언트를 쓴다.

## Slack 앱 설정 (앱 관리자)

1. api.slack.com/apps에서 앱을 고르고 **Socket Mode**를 켠다.
2. **Basic Information → App-Level Tokens**에서 토큰을 발급한다. 스코프는 `connections:write`로 하면 되고, 발급된 토큰은 `xapp-...` 형식이다.
3. **Interactivity & Shortcuts**가 켜져 있는지 확인한다. Socket Mode를 켜면 Request URL 칸은 쓰이지 않는다.
4. `.env`에 다음을 추가한다.
   ```
   SLACK_APP_TOKEN=xapp-...
   ```
   - Bot Token(`xoxb-`)은 지금 구조에서는 필요 없다. 메시지는 webhook으로 보내고, 갱신은 response_url로 하기 때문이다.
     나중에 `chat.postMessage`로 바꿀 때 필요해진다.
   - 토큰은 `.env`나 시크릿 저장소에만 둔다. 설정 코드는 토큰 값을 로그나 예외 메시지에 남기지 않는다.

## 실행

```bash
pip install -e .            # slack_sdk 설치
python -m purplebpf.offensive.review.slack_socket
# → "Slack Socket Mode 연결됨" / "승인/반려 이벤트 대기 중"
```

## 완료 기준 확인 방법

| 완료 기준 | 확인 방법 |
|---|---|
| ngrok 없이 로컬에서 승인·반려 이벤트 수신 | ngrok을 끈 채로 `slack_notify.py --sample`을 보내고 버튼을 누른다 → 로그에 `검수 이벤트 처리 완료` |
| ACK와 사용자 피드백 정상 반환 | 버튼이 "✅ 승인됨 — 이름"으로 바뀌고, Slack에 오류 경고가 뜨지 않는다 |
| 중복 클릭·재전송 시 중복 생성 없음 | 같은 메시지에서 다시 누르거나 반려를 눌러 본다 → 로그에 `중복 검수 이벤트 무시` (자동 테스트도 있음) |
| 재연결·재시작 복구 | 네트워크를 잠깐 끊는다 → `연결 닫힘` 다음 자동 재연결 / 프로세스를 다시 띄운다 → 다시 연결됨 |

자동 테스트는 이렇게 돌린다(실제 Slack 연결 없음).

```bash
python -m pytest tests/test_slack_socket_mode.py
```

## 남은 과제 (이번 범위 밖)

- **승인 → 실제 실행 연결**: 아직 표시만 한다. 실행과 연결할 때는 아래 두 가지를 같이 해야 한다.
- **멱등 키 저장소를 DB로 옮기기**: 지금은 프로세스 메모리(최근 1000건)에 저장한다. 그래서 재시작 직후 다시 누르면 한 번 더 처리될 수 있다.
  실행과 연결하면 같은 체인이 두 번 실행될 수 있으므로, 그 전에 반드시 Postgres로 옮겨야 한다.
- 검수 메시지와 `round_id`/`chain_id` 연결: 지금 버튼 값에는 `technique_id`만 들어 있다. 실행과 연결할 때 버튼 `value`에 `chain_id`를 넣어야 한다.
