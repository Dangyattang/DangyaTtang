from flask import Flask, render_template, request, redirect, url_for, make_response, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
import jwt as pyjwt
import datetime
from bson.objectid import ObjectId  # ObjectId 추가
import re

app = Flask(__name__)

# MongoDB 연결
client = MongoClient("mongodb://localhost:27017/")
db = client["team_order_db"]

# 비밀키
SECRET_KEY = "your_secret_key_here"

# JWT 토큰에서 사용자 정보 가져오는 함수
def get_user_from_token():
    token = request.cookies.get("token")
    if token:
        try:
            decoded_token = pyjwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            user_id = decoded_token.get("user_id")
            if user_id:
                # ObjectId를 제대로 사용해야 하므로, str로 받으면 ObjectId로 변환해야 함
                user = db.users.find_one({"_id": ObjectId(user_id)})
                return user
        except Exception as e:
            print(f"Token decode error: {e}")
            return None
    return None

# 홈 페이지
@app.route('/')
def home():
    user = get_user_from_token()
    if user:
        return render_template('index.html', username=user["name"])
    return render_template('index.html')

# 로그인 페이지
@app.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "POST":
        data = request.form
        username = data.get("username")
        password = data.get("password")

        # MongoDB에서 사용자 찾기
        user = db.users.find_one({"username": username})

        if user and check_password_hash(user["password"], password):
            # JWT 토큰 생성
            token = pyjwt.encode({
                "user_id": str(user["_id"]),
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=2)
            }, SECRET_KEY, algorithm="HS256")

            # JWT 토큰을 쿠키에 담아 클라이언트로 전송
            response = make_response(redirect(url_for("home")))  # 성공 시 홈으로 리디렉션
            response.set_cookie("token", token, httponly=True, secure=True)  # 쿠키에 토큰 저장

            return response
        else:
            return render_template("login.html", error="로그인 실패! 아이디 또는 비밀번호를 확인하세요.")
    return render_template("login.html")

# 아이디 중복확인
@app.route('/check-username', methods=['GET'])
def check_username():
    username = request.args.get('username')
    pattern = r"^정글 \d{1,2}기-\d{1,2}$"  # 올바른 형식 예: "정글 기-12"

    # 🔹 아이디 형식 검사 먼저 수행
    if not re.match(pattern, username):
        return jsonify({'available': False, 'message': '아이디는 "정글 n기-n" 형식이어야 합니다.'})

    # 🔹 중복 검사 진행
    user = db.users.find_one({"username": username})
    if user:
        return jsonify({'available': False, 'message': '이미 사용 중인 아이디입니다.'})

    return jsonify({'available': True, 'message': '사용 가능한 아이디입니다.'})



# 회원가입 페이지
@app.route("/register", methods=["GET", "POST"])
def register_page():
    if request.method == "POST":
        data = request.form
        name = data.get("name")
        username = data.get("username")
        password = data.get("password")
        email = data.get("email")
        phone = data.get("phone")
        hashed_password = generate_password_hash(password)
        db.users.insert_one({
            "name": name,
            "username": username,
            "password": hashed_password,
            "email": email,
            "phone": phone,
            "active_order": None,
            "past_orders": []
        })
        return redirect(url_for("login_page"))
    return render_template("register.html")

# 로그아웃
@app.route("/logout")
def logout():
    response = make_response(redirect(url_for("home")))
    response.delete_cookie("token")  # 쿠키에서 토큰 삭제
    return response

# 앱 실행
if __name__ == '__main__':
    app.run(debug=True)
