from flask import Flask, render_template, request, redirect, url_for, make_response, jsonify, g
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
import jwt as pyjwt
from datetime import datetime, timedelta, timezone
from bson.objectid import ObjectId  # ObjectId 추가
from flask.json.provider import JSONProvider
import json
import re
import requests
import os
from dotenv import load_dotenv
from functools import wraps


app = Flask(__name__)

# MongoDB 연결
client = MongoClient("mongodb://localhost:27017/")
db = client["dangyattang"]

# 비밀키 로드
load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY")

def login_required(f):
    """로그인 상태 확인용 데코레이터"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        access_token = request.cookies.get("access_token")
        print(access_token, "gg")
        if not access_token:
            print("[DEBUG] Access Token이 없음, 로그인 필요")  
            return redirect(url_for("login_page"))  

        try:
            decoded_token = pyjwt.decode(access_token, SECRET_KEY, algorithms=["HS256"])
            g.user_id = decoded_token.get("user_id")  # ✅ 현재 로그인된 유저 ID 저장
            return f(*args, **kwargs)

        except pyjwt.ExpiredSignatureError:
            print("[DEBUG] Access Token 만료됨, Refresh Token 확인")  
            refresh_token = request.cookies.get("refresh_token")

            if refresh_token:
                new_access_token = refresh_access_token(refresh_token)
                if new_access_token:
                    print("[DEBUG] 새로운 Access Token 발급됨")  
                    response = make_response(redirect(request.url))
                    response.set_cookie("access_token", new_access_token, httponly=True, secure=False)
                    return response

            return redirect(url_for("login_page"))  # Refresh Token도 만료되었다면 로그인 페이지로 이동

        except Exception as e:
            print(f"[ERROR] Token decode error: {e}")  
            return redirect(url_for("login_page"))  

    return decorated_function

def create_access_token(user_id):
    return pyjwt.encode({
        "user_id": user_id,
        "exp": datetime.utcnow() + timedelta(minutes=1)  # 30초초 후 만료
    }, SECRET_KEY, algorithm="HS256")

def create_refresh_token(user_id):
    return pyjwt.encode({
        "user_id": user_id,
        "exp": datetime.utcnow() + timedelta(minutes=10)  # 1분 후 만료
    }, SECRET_KEY, algorithm="HS256")

def get_user_from_token():
    access_token = request.cookies.get("access_token")

    if access_token:
        try:
            decoded_token = pyjwt.decode(access_token, SECRET_KEY, algorithms=["HS256"])
            user_id = decoded_token.get("user_id")
            return db.users.find_one({"_id": ObjectId(user_id)})

        except pyjwt.ExpiredSignatureError:
            refresh_token = request.cookies.get("refresh_token")
            if refresh_token:
                new_access_token = refresh_access_token(refresh_token)
                if new_access_token:
                    # ✅ 새로운 Access Token을 쿠키에 저장 (Response 반환 X)
                    response = make_response()
                    response.set_cookie("access_token", new_access_token, httponly=True, secure=False)
                    return db.users.find_one({"_id": ObjectId(pyjwt.decode(new_access_token, SECRET_KEY, algorithms=["HS256"])["user_id"])})

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

def clear_tokens():
    """Access Token과 Refresh Token을 삭제하는 공통 함수"""
    response = make_response(jsonify({"error": "Unauthorized"}), 401)
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")
    return response

# ObjectId 인코딩 처리 함수
class CustomJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        return json.JSONEncoder.default(self, o)

class CustomJSONProvider(JSONProvider):
    def dumps(self, obj, **kwargs):
        return json.dumps(obj, **kwargs, cls=CustomJSONEncoder)

    def loads(self, s, **kwargs):
        return json.loads(s, **kwargs)


app.json = CustomJSONProvider(app)

# JSON 변환을 위한 함수
def serialize_order(order):
    return {
        "_id": str(order["_id"]),
        "created_at": order["created_at"].isoformat(),
        "expires_at": order["expires_at"].isoformat(),
        "host": str(order["host"]),
        "participants": [str(p) for p in order["participants"]],
        "max_participants": order["max_participants"],
        "current_participants": order["current_participants"],
        "status": order["status"],
        "open_chat_url": order["open_chat_url"],
        "food_category": order["food_category"],
        "menu_details": order["menu_details"]
    }

# 홈 페이지
@app.route('/')
@login_required
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
        return clear_tokens()

    token_data = db.refresh_tokens.find_one({"token": refresh_token})
    if not token_data:
        return clear_tokens()

    try:
        decoded_token = pyjwt.decode(refresh_token, SECRET_KEY, algorithms=["HS256"])
        user_id = decoded_token["user_id"]

        # ✅ 새로운 Access Token & Refresh Token 발급
        new_access_token = create_access_token(user_id)
        new_refresh_token = create_refresh_token(user_id)

        # ✅ 기존 Refresh Token 폐기 & 새로운 Refresh Token 저장
        db.refresh_tokens.delete_one({"token": refresh_token})
        db.refresh_tokens.insert_one({"user_id": user_id, "token": new_refresh_token})

        response = make_response(jsonify({"access_token": new_access_token}))
        response.set_cookie("access_token", new_access_token, httponly=True, secure=False)
        response.set_cookie("refresh_token", new_refresh_token, httponly=True, secure=False)
        return response
    except pyjwt.ExpiredSignatureError:
        return clear_tokens()


# ===== 팀 주문 api =====

# 팀 주문 등록 api
@app.route('/order', methods=["POST"])  
def create_Order():
    data = request.json
    minute = int(data["limitTime_give"])
    new_order = {
        "created_at": datetime.now(timezone.utc),
        "expires_at": datetime.now(timezone.utc) + timedelta(minutes=minute),
        "host": ObjectId("67d0254ba0c0fb9bdffbc2e6"),
        "participants": [],
        "max_participants": data["maxPerson_give"],
        "current_participants": 0,
        "status": "active",
        "open_chat_url": data["kakaoUrl_give"],
        "food_category": data["foodCategory_give"],
        "menu_details": data["detailMenu_give"]
    }
    order_id = db.orders.insert_one(new_order).inserted_id

    return jsonify({"message": "주문 생성 완료", "order_id": str(order_id)}), 201

# 팀 주문 전체 조회 api
@app.route('/orders')  
def select_OrderList():
    orders = list(db.orders.find({"status": "active"}).sort("expires_at", 1))
    return jsonify([serialize_order(order) for order in orders])

# 카테고리별 정렬 api
@app.route('/orders/category', methods=["GET"])  
def select_Orders_by_category():
    category = request.args.get("category")
    orders = list(db.orders.find(
        {"food_category": category}).sort("expires_at", 1))
    if len(orders) == 0:
        return jsonify({"message": "해당 음식의 진행중인 주문이 없습니다"})
    return jsonify([serialize_order(order) for order in orders])

@app.route('/order/<string:order_id>', methods=["PUT"])  # 팀 주문 참여 신청 api
def insert_participation_in_orders(order_id):
    data = request.get_json()
    findusername = data["userId_give"]

    # 현재 로그인 유저의 username으로 db에서 해당 유저의 _id값 추출
    user = db.users.find_one({"username": findusername}, {"_id": 1})

    if not user:
        return jsonify({"message": "유저를 찾을 수 없습니다."}), 404

    user_object_id = user["_id"]

    order = db.orders.find_one({"order_id": order_id})

    if not order:
        return jsonify({"message": "주문을 찾을 수 없습니다."}), 404

   # 🔹 이미 참가한 유저인지 확인
    if user_object_id in order["members"]:
        return jsonify({"message": "이미 참가한 유저입니다."}), 400

# 🔹 참가자 목록 업데이트 (ObjectId 저장)
    updated_order = db.orders.update_one(
        {"order_id": order_id},
        {"$push": {"participants": user_object_id}}
    )
    return jsonify({"message": f"{findusername}님이 주문에 참여했습니다!", "order": updated_order})



# 앱 실행
if __name__ == '__main__':
    app.run(debug=True)
