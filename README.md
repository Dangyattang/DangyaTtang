# 당신은 지금 야식이 땡긴다 🍗

함께 배달 음식을 주문할 사람을 모으는 웹 서비스입니다. 사용자는 음식 종류와 모집 시간을 정해 팀 주문을 열고, 다른 사용자의 주문에 참여할 수 있습니다. 모집 인원이 차거나 시간이 지나면 주문 상태를 갱신하고 Socket.IO로 참여자에게 알립니다.

## 주요 기능

- **회원가입 및 로그인**: 비밀번호를 해시해 MongoDB에 저장하고, JWT를 HTTP 전용 쿠키로 전달합니다.
- **팀 주문 모집**: 음식 카테고리, 상세 메뉴, 카카오톡 오픈채팅 URL, 모집 시간과 최대 인원을 등록합니다.
- **주문 탐색 및 참여**: 진행 중인 주문을 전체 또는 카테고리별로 조회하고 참여합니다.
- **주문 상태 알림**: 모집 인원 충족 또는 모집 시간 만료 시 상태를 변경하고 참여자별 Socket.IO 룸에 이벤트를 보냅니다.
- **개인 페이지**: 현재 참여 중인 주문과 이전 주문 정보를 확인합니다.

## 기술 스택

| 영역 | 기술 |
| --- | --- |
| 백엔드 | Python, Flask, Flask-SocketIO, Flask-CORS |
| 데이터베이스 | MongoDB, PyMongo |
| 인증 | Werkzeug 비밀번호 해시, PyJWT |
| 프론트엔드 | Jinja2 템플릿, JavaScript, jQuery, Tailwind CSS |

## 로컬 실행

Python과 MongoDB가 필요합니다. 이 저장소에는 의존성 잠금 파일이 없으므로 다음 패키지를 직접 설치합니다.

```bash
git clone https://github.com/Dangyattang/DangyaTtang.git
cd DangyaTtang
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# macOS/Linux: source .venv/bin/activate
python -m pip install Flask Flask-SocketIO Flask-Cors pymongo PyJWT requests python-dotenv
```

로컬 MongoDB를 `localhost:27017`에서 실행하고, 프로젝트 루트에 `.env` 파일을 만듭니다. `SECRET_KEY`에는 임의의 긴 문자열을 설정하세요.

```dotenv
SECRET_KEY=replace-with-a-long-random-secret
```

```bash
python app.py
```

브라우저에서 `http://127.0.0.1:5000`에 접속하면 로그인 페이지로 이동합니다. 회원가입 후 로그인해 주문을 만들거나 참여할 수 있습니다. 화면의 API 주소가 `http://127.0.0.1:5000`으로 설정되어 있으므로 이 주소로 접속해야 합니다. 화면에 사용하는 일부 라이브러리와 글꼴은 외부 CDN에서 불러옵니다.

## 사용 흐름

1. 회원가입 화면에서 계정을 만들고 로그인합니다.
2. 메인 화면에서 진행 중인 팀 주문을 확인하거나 음식 카테고리로 찾습니다.
3. 팀 주문을 열 때 오픈채팅 URL, 모집 시간, 최대 인원, 음식 카테고리와 상세 메뉴를 입력합니다.
4. 원하는 주문에 참여합니다. 모집 인원이 차거나 시간이 만료되면 주문 상태가 갱신됩니다.
5. 개인 페이지에서 참여 중인 주문과 이전 주문을 확인합니다.

## 프로젝트 구성

```text
app.py                  Flask 라우트, 인증, MongoDB 연동, 주문 상태 갱신, Socket.IO 이벤트
templates/index.html    주문 목록·카테고리 필터·주문 생성 화면
templates/login.html    로그인 화면
templates/register.html 회원가입 화면
templates/personal.html 개인 주문 화면
```

## 참고

현재 코드는 로컬 개발 환경을 기준으로 작성되어 있습니다. MongoDB 주소와 프론트엔드 API 주소가 로컬 주소로 고정되어 있고, Flask 디버그 모드가 활성화되어 있습니다. 외부에 배포하려면 이 설정과 쿠키 보안 설정을 배포 환경에 맞게 변경해야 합니다.
