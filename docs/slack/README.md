# Slack 2차 검수 셋업 — 알림 + 버튼 콜백 + 결정 영속화

REVIEW로 차단된 공격 체인은 Slack으로 승인/반려 버튼이 달린 메시지가 나간다.
버튼을 누르면 콜백 서버가 결정을 `review_decisions` 테이블에 저장한다(승인 시
재실행은 **워크스트림 C**가 담당 — 이 단계는 "결정 저장"까지다).

## 왜 "웹훅만으로는" 버튼이 안 되나

- **Incoming Webhook은 단방향**이다. 채널로 메시지를 밀어넣을 수만 있고, 사용자가
  버튼을 누른 이벤트를 되받지 못한다.
- 버튼 클릭(interactivity)을 받으려면 **별도 Slack App** + **Interactivity Request
  URL**(공개 접근 가능한 콜백 엔드포인트) + **서명 검증용 Signing Secret**이 필요하다.
- 로컬 콜백 서버를 공개로 노출하려면 ngrok 같은 터널이 필요하다.

## 1. App 생성

1. <https://api.slack.com/apps> → **Create New App** → **From an app manifest**
2. 워크스페이스 선택 후 [`app_manifest.yaml`](./app_manifest.yaml) 붙여넣기 → 생성

## 2. 콜백 서버 실행 + ngrok 노출

```bash
# 콜백 서버(FastAPI, 기본 0.0.0.0:8000)
python -m purplebpf.offensive.review.slack_callback

# 다른 터미널에서 8000 포트를 공개로 노출
ngrok http 8000
```

ngrok이 출력한 `https://<subdomain>.ngrok-free.app` 주소를 복사한다.

## 3. Interactivity Request URL 등록

Slack App 관리 페이지 → **Interactivity & Shortcuts** → Interactivity **On** →
Request URL에 아래를 입력(경로 고정):

```
https://<subdomain>.ngrok-free.app/slack/interactions
```

> 매니페스트에도 request_url이 들어있지만, ngrok 주소는 실행마다 바뀌므로 여기서
> 실제 주소로 갱신한다. (매니페스트의 `settings.interactivity.request_url`도 같이
> 바꿔두면 재생성 시 편하다.)

## 4. Incoming Webhook 활성화

**Incoming Webhooks** → **On** → **Add New Webhook to Workspace** → 알림을 받을
채널 선택 → 생성된 `https://hooks.slack.com/services/...` URL 복사.

## 5. Signing Secret 확인

**Basic Information** → **App Credentials** → **Signing Secret**의 값을 복사.
콜백 서버가 "진짜 Slack이 보낸 요청"인지 검증할 때 쓴다.

## 6. `.env` 채우기

```dotenv
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/XXX/YYY/ZZZ   # 4단계
SLACK_SIGNING_SECRET=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx             # 5단계
```

## 7. 엔드투엔드 확인

1. `alembic upgrade head` 로 `review_decisions` 테이블 생성
2. REVIEW로 차단되는 체인을 흘려 Slack 알림을 띄운다
   (예: `python -m purplebpf.offensive.review.slack_notify --sample`)
3. 알림이 뜨면 `review_decisions`에 **PENDING** 행이 1건 생겼는지 확인
4. **승인** 또는 **반려** 버튼 클릭
5. 해당 행이 **APPROVED/REJECTED**로, `decided_by`(클릭한 Slack 사용자)와
   `decided_at`이 채워졌는지 확인:

```sql
SELECT review_id, technique_id, source, status, decided_by, decided_at
FROM review_decisions ORDER BY created_at DESC LIMIT 5;
```

버튼 value에는 `review_id`(UUID)가 실리고, 표시 텍스트에는 `technique_id`가 남는다.
