from flask import Flask, render_template, request, redirect, url_for, make_response, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
import jwt as pyjwt
import datetime
from bson.objectid import ObjectId  # ObjectId 추가
import re
import requests
import os
from dotenv import load_dotenv

app = Flask(__name__)

# MongoDB 연결
client = MongoClient("mongodb://localhost:27017/")
db = client["team_order_db"]

# 비밀키 로드
load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY")

def create_access_token(user_id):
    return pyjwt.encode({
        "user_id": user_id,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=1)  # 1분 후 만료
    }, SECRET_KEY, algorithm="HS256")

def create_refresh_token(user_id):
    return pyjwt.encode({
        
        "user_id": user_id,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # 1시간 후 만료
    }, SECRET_KEY, algorithm="HS256")

def get_user_from_token():
    access_token = request.cookies.get("access_token")

    if access_token:
        try:
            decoded_token = pyjwt.decode(access_token, SECRET_KEY, algorithms=["HS256"])
            user_id = decoded_token.get("user_id")

            if user_id:
                return db.users.find_one({"_id": ObjectId(user_id)})

        except pyjwt.ExpiredSignatureError:  # 🔥 Access Token이 만료되었을 경우
            refresh_token = request.cookies.get("refresh_token")
            if refresh_token:
                new_access_token = refresh_access_token(refresh_token)
                if new_access_token:
                    # ✅ 새로운 Access Token을 쿠키에 저장
                    response = make_response(redirect(request.url))
                    response.set_cookie("access_token", new_access_token, httponly=True, secure=False)

                    # ✅ 새로운 Access Token이 발급된 후 유저 정보 가져오기
                    user_id = pyjwt.decode(new_access_token, SECRET_KEY, algorithms=["HS256"])["user_id"]
                    user = db.users.find_one({"_id": ObjectId(user_id)})

                    return user  # ✅ 유저 정보 반환 (Response 객체가 아닌)

        except Exception as e:
            print(f"Token decode error: {e}")
            return None

    return None


def refresh_access_token(refresh_token):
    """Refresh Token을 사용하여 새로운 Access Token 발급"""
    try:
        response = requests.post("http://localhost:5000/refresh-token", cookies={"refresh_token": refresh_token})
        
        if response.status_code == 200:
            new_access_token = response.json().get("access_token")
            return new_access_token
        else:
            return None

    except Exception as e:
        print(f"Refresh token request failed: {e}")
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
            # Access Token & Refresh Token 생성
            access_token = create_access_token(str(user["_id"]))
            refresh_token = create_refresh_token(str(user["_id"]))

            # Refresh Token을 DB에 저장 (재사용 방지)
            db.refresh_tokens.insert_one({"user_id": str(user["_id"]), "token": refresh_token})

            # 쿠키에 저장
            response = make_response(redirect(url_for("home")))
            response.set_cookie("access_token", access_token, httponly=True, secure=False)
            response.set_cookie("refresh_token", refresh_token, httponly=True, secure=False)

            return response
        else:
            return render_template("login.html", error="로그인 실패! 아이디 또는 비밀번호를 확인하세요.")
    return render_template("login.html")

# 아이디 중복확인
@app.route('/check-username', methods=['GET'])
def check_username():
    username = request.args.get('username')
    pattern = r"^정글 \d{1,2}기-\d{1,2}$"  # 올바른 형식 예: "정글 8기-12"

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
    response.delete_cookie("access_token")  # Access Token 삭제
    response.delete_cookie("refresh_token")  # Refresh Token 삭제
    return response

# Refresh Token을 사용하여 Access Token 갱신
@app.route("/refresh-token", methods=["POST"])
def refresh_token():
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        return jsonify({"error": "Refresh token required"}), 401

    # DB에서 Refresh Token 확인
    token_data = db.refresh_tokens.find_one({"token": refresh_token})
    if not token_data:
        return jsonify({"error": "Invalid refresh token"}), 401

    try:
        decoded_token = pyjwt.decode(refresh_token, SECRET_KEY, algorithms=["HS256"])
        user_id = decoded_token["user_id"]

        # 새로운 Access Token 발급
        new_access_token = create_access_token(user_id)

        # 새 Access Token을 쿠키에 저장
        response = make_response(jsonify({"access_token": new_access_token}))
        response.set_cookie("access_token", new_access_token, httponly=True, secure=False)

        return response
    except pyjwt.ExpiredSignatureError:
        return jsonify({"error": "Refresh token expired. Please login again."}), 401
    except pyjwt.InvalidTokenError:
        return jsonify({"error": "Invalid refresh token"}), 401

# 앱 실행
if __name__ == '__main__':
    app.run(debug=True)
