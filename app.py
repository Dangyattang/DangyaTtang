from flask import Flask, render_template, request, redirect, url_for, make_response, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
import jwt as pyjwt
from datetime import datetime, timedelta, timezone
from bson.objectid import ObjectId  # ObjectId 추가
from flask.json.provider import JSONProvider
import json
import re

app = Flask(__name__)

# MongoDB 연결
client = MongoClient("mongodb://localhost:27017/")
db = client["dangyattang"]

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
