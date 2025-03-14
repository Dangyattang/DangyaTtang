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
import threading
import time
from flask_socketio import SocketIO
from flask_cors import CORS

app = Flask(__name__)

CORS(app)  # ✅ CORS 허용
socketio = SocketIO(app, cors_allowed_origins="*")  # 웹소켓 설정

# MongoDB 연결
client = MongoClient('localhost',27017)
db = client["dangyattang"]

# 비밀키 로드
load_dotenv()
SECRET_KEY = str(os.getenv("SECRET_KEY"))

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
        "exp": datetime.utcnow() + timedelta(minutes=10)  # 30초초 후 만료
    }, SECRET_KEY, algorithm="HS256")

def create_refresh_token(user_id):
    return pyjwt.encode({
        "user_id": user_id,
        "exp": datetime.utcnow() + timedelta(minutes=10)  # 1분 후 만료
    }, SECRET_KEY, algorithm="HS256")

def get_user_from_token():
    access_token = request.cookies.get("access_token")
    print(f"🔍 Access Token from Cookie: {access_token}")  # ✅ 추가 디버깅용 출력

    if access_token:
        try:
            decoded_token = pyjwt.decode(access_token, SECRET_KEY, algorithms=["HS256"])
            user_id = decoded_token.get("user_id")
            print(f"✅ Decoded User ID: {user_id}")  # ✅ 추가 디버깅용 출력
            return db.users.find_one({"_id": ObjectId(user_id)})
        except pyjwt.ExpiredSignatureError:
            print("[⚠️] Access Token expired. Checking Refresh Token...")  
            refresh_token = request.cookies.get("refresh_token")
            if refresh_token:
                new_access_token = refresh_access_token(refresh_token)
                if new_access_token:
                    print(f"✅ New Access Token: {new_access_token}")  
                    response = make_response()
                    response.set_cookie("access_token", new_access_token, httponly=True, secure=False)
                    return db.users.find_one({"_id": ObjectId(pyjwt.decode(new_access_token, SECRET_KEY, algorithms=["HS256"])["user_id"])})

    print("[ERROR] Failed to retrieve user from token")  
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

@socketio.on("order_update", namespace="/")
def check_and_update_orders():
    """주문 상태를 주기적으로 업데이트하는 백그라운드 작업"""
    while True:
        now = datetime.now(timezone.utc)
        orders = db.orders.find({"status": "active"})
        for order in orders:
            order_id = str(order["_id"])
            expires_at = order["expires_at"]

            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)

            if expires_at < now:  # 🔥 제한시간 마감 시 failed 처리
                db.orders.update_one({"_id": order["_id"]}, {"$set": {"status": "failed"}})
                print(f"🚨 주문 {order_id} 모집 마감 (Failed) - 알림 전송 중...")
                remove_active_order_from_users(order["participants"], order_id)
                socketio.emit("order_update", {"order_id": order_id, "status": "failed"})  # 알람 전송
                print(f"🚨 주문 {order_id} 모집 마감 (Failed)")

            elif len(order["participants"]) >= int(order["max_participants"]):  # 🔥 인원 충족 시 confirmed 처리
                db.orders.update_one({"_id": order["_id"]}, {"$set": {"status": "confirmed"}})
                print(f"✅ 주문 {order_id} 확정됨 (Confirmed), 알람 전송")
                remove_active_order_from_users(order["participants"], order_id)
                add_to_past_orders(order["participants"], order_id)

                socketio.emit("order_update", {"order_id": order_id, "status": "confirmed"})  # 알람 전송

        time.sleep(10)  # 10초마다 체크

# 🔥 스레드 실행 (앱 시작 시)
thread = threading.Thread(target=check_and_update_orders, daemon=True)
thread.start()

def remove_active_order_from_users(participants, order_id):
    """주문이 완료되거나 실패했을 때 참가자의 active_order에서 제거"""
    for user_id in participants:
        db.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$unset": {"active_order": ""}}  # `active_order` 필드 제거
        )
    print(f"🔄 모든 참가자의 active_order에서 {order_id} 제거 완료")

def add_to_past_orders(participants, order_id):
    """주문이 확정되었을 때 참가자의 past_orders 배열에 추가"""
    for user_id in participants:
        db.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$push": {"past_orders": order_id}}  # ✅ 주문 ID 추가
        )
    print(f"📌 모든 참가자의 past_orders에 {order_id} 추가 완료")


def update_expired_orders():
    """주기적으로 모집 종료된 주문을 'failed' 상태로 변경"""
    while True:
        now = datetime.now()
        db.orders.update_many(
            {"expires_at": {"$lt": now}, "status": "active"},
            {"$set": {"status": "failed"}}
        )
        print("[INFO] 모집 종료된 주문 상태 업데이트 완료", datetime.now())
        time.sleep(30)  # 30초마다 체크
        

# 백그라운드 스레드 시작
threading.Thread(target=update_expired_orders, daemon=True).start()
    
# 야식왕 선정
def get_top_delivery_user():
    """참여 확정된 주문이 가장 많은 사용자 찾기 (동점자 처리 포함)"""
    users = list(db.users.find({}, {"name": 1, "past_orders": 1}))
  
    if not users:
        return None  # 사용자가 없으면 None 반환

    # ✅ 참여 확정된 주문 개수 + 가장 최근 주문 시점 기준 정렬
    sorted_users = sorted(users, key=lambda u: (
        len(u.get("past_orders", [])),  # 1️⃣ past_orders 개수 (내림차순)
        max(u["past_orders"]) if u.get("past_orders") else datetime.min  # 2️⃣ 가장 최근 주문 날짜 기준 (내림차순)
    ), reverse=True)

    top_user = sorted_users[0]  # 가장 많은 주문 참여자 중 가장 최근 참여자
    return top_user["name"] if top_user.get("past_orders") else None


# 홈 페이지
@app.route('/')
@login_required
def home():
    user = get_user_from_token()
    top_user = get_top_delivery_user()
    return render_template('index.html', 
                           username=user["name"] if user else None, 
                           top_delivery_user=top_user,user_id=user["_id"])

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

            print(f"✅ 로그인 성공: {username}, 유저 ID: {user['_id']}")
            print(f"✅ 생성된 Access Token: {access_token}")
            print(f"✅ 생성된 Refresh Token: {refresh_token}")
            print(f"✅ 리디렉트 실행됨: {url_for('home')}")
            return response
        else:
            print(f"❌ 로그인 실패: 아이디 또는 비밀번호 오류 - {username}")
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

# 개인 페이지
@app.route("/personal")
def personal_page():
    return render_template("personal.html")

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


    # 사용자 이름을 조회
@app.route('/user/<user_id>/username', methods=["GET"])
def get_username(user_id):
    user = db.users.find_one({"_id": ObjectId(user_id)})
    if user:
        return jsonify({"username": user.get("username", ""),"phonenum": user.get("phone", "")})
    return jsonify({"error": "User not found"}), 404
# # 사용자 전화번호 조회
# @app.route('/user/<user_id>/phonenum', methods=["GET"])
# def get_phonenum(user_id):
#     user = db.users.find_one({"_id": ObjectId(user_id)})
#     if user:
#         return jsonify({"phonenum": user.get("phone", "")})
#     return jsonify({"error": "User not found"}), 404
# 이전주문 카드 전체 조회 api
@app.route('/orders/prev', methods=["GET"])
def Select_PreviousOrderList():
    user = get_user_from_token()
    user_id = ObjectId(user["_id"])  # ✅ user의 _id를 ObjectId로 변환

    prevorders = list(db.orders.find({"status":"failed", "participants": {"$in": [user_id]}}).sort("expires_at", -1))

    return jsonify([serialize_order(prevorder) for prevorder in prevorders])
# 진행중인 오더 조회
@app.route('/order/current', methods=["GET"])
def select_CurrentOrder():
    user = get_user_from_token()


    user_id = ObjectId(user["_id"])  # ✅ user의 _id를 ObjectId로 변환

    # 현재 진행 중인  주문 중, 해당 유저가 참가자로 있는 것 찾기
    currentorders = db.orders.find({"status": "active", "participants": {"$in": [user_id]}})
    
    currentorders_list = list(currentorders)  # Cursor를 리스트로 변환
    print("현재 진행 중인 주문:", currentorders_list)
    # return jsonify({"currentorder": [serialize_order(order) for order in currentorders_list]})
    return jsonify([serialize_order(order) for order in currentorders_list])
#이전주문에서 전화번호 찾기

@app.route('/order/prev/phonenum', methods=["GET"])
def get_phone():
    username = request.args.get("username") 
    user = db.users.find_one({"name": username})
    return jsonify({"phone": user["phone"]})


# ===== 팀 주문 api =====


# 팀 주문 등록 api,
@app.route('/order', methods=["POST"])  
@login_required
def create_Order():
    data = request.json
    minute = int(data["limitTime_give"])
    max_participants = int(data["maxPerson_give"])  # ✅ max_participants를 int로 변환
    host_id = g.user_id  # 현재 로그인한 사용자의 ID 가져오기

    new_order = {
        "created_at": datetime.now(),
        "expires_at": datetime.now() + timedelta(minutes=minute),
        "host": ObjectId(host_id),
        "participants": [ObjectId(host_id)],
        "max_participants": max_participants,  # ✅ int 타입으로 저장
        "current_participants": 1,
        "status": "active",
        "open_chat_url": data["kakaoUrl_give"],
        "food_category": data["foodCategory_give"],
        "menu_details": data["detailMenu_give"]
    }
    order_id = db.orders.insert_one(new_order).inserted_id

    # ✅ 등록자의 `active_order` 업데이트
    db.users.update_one(
        {"_id": ObjectId(host_id)},
        {"$set": {"active_order": order_id}}
    )

    return jsonify({"message": "주문 생성 완료", "order_id": str(order_id)}), 201

# 팀 주문 전체 조회 api
@app.route('/orders')
def select_OrderList():
    user = get_user_from_token()

    if not user:
        return jsonify({"error": "로그인 필요"}), 401

    orders = list(db.orders.find({"status": "active"}).sort("expires_at", -1))

    for order in orders:
        order["_id"] = str(order["_id"])  # ObjectId → 문자열 변환
        order["participants"] = [str(p) for p in order["participants"]]  # ObjectId → 문자열 변환
        order["created_at"] = order["created_at"].isoformat()  # ✅ datetime → ISO 8601 문자열 변환
        order["expires_at"] = order["expires_at"].isoformat()  # ✅ datetime → ISO 8601 문자열 변환

    return jsonify(orders)

# 카테고리별 정렬 api
@app.route('/orders/category', methods=["GET"])  
def select_Orders_by_category():
    category = request.args.get("category")
    orders = list(db.orders.find(
        {"food_category": category, "status": "active"}).sort("expires_at", 1))
    
    return jsonify([serialize_order(order) for order in orders])

@app.route('/order/<string:order_id>', methods=["PUT"])  # 팀 주문 참여 신청 api
@login_required
def insert_participation_in_orders(order_id):
    userid = g.user_id
    print(f"🛠 신청하는 주문 ID: {order_id}")  # 디버깅 로그 추가

    try:
        order_object_id = ObjectId(order_id)  # ✅ ObjectId 변환
    except:
        return jsonify({"message": "올바르지 않은 주문 ID입니다."}), 400

    # ✅ 유저 정보 조회
    user = db.users.find_one({"_id": ObjectId(userid)}, {"name": 1, "active_order": 1})
    if not user:
        return jsonify({"message": "유저를 찾을 수 없습니다."}), 404

    # ✅ 주문 정보 조회
    order = db.orders.find_one({"_id": order_object_id})
    if not order:
        return jsonify({"message": "주문을 찾을 수 없습니다."}), 404

    # ✅ 참가자 목록 및 최대 인원 확인
    participants = order.get("participants", [])
    max_participants = int(order["max_participants"])  # 문자열일 가능성 제거
    print(f"👥 현재 참가자 수: {len(participants)}/{max_participants}")  # 디버깅 로그 추가

    # ✅ 이미 참여한 주문인지 확인
    if str(userid) in map(str, participants):
        return jsonify({"message": "이미 신청한 주문입니다."}), 400

    # ✅ 주문이 확정된 상태라면 신청 불가
    if order["status"] == "confirmed":
        return jsonify({"message": "해당 주문은 이미 확정되었습니다."}), 400

    # ✅ 참여 가능 여부 확인
    if len(participants) >= max_participants:
        return jsonify({"message": "참여 인원이 가득 찼습니다."}), 400

    # ✅ 참가자 목록 업데이트
    db.orders.update_one(
        {"_id": order_object_id},
        {
            "$push": {"participants": ObjectId(userid)},
            "$set": {"current_participants": len(participants) + 1}  # ✅ 참가자 수 업데이트
        }
    )

    # ✅ 유저의 active_order를 현재 주문 ID로 업데이트
    db.users.update_one(
        {"_id": ObjectId(userid)},
        {"$set": {"active_order": order_object_id}}
    )

    # ✅ 디버깅 로그 추가
    updated_order = db.orders.find_one({"_id": order_object_id}, {"participants": 1})
    print(f"✅ 업데이트된 참가자 수: {len(updated_order['participants'])}/{max_participants}")

    return jsonify({"message": f"{user['name']}님이 주문에 참여했습니다!"}), 200


# 앱 실행
if __name__ == '__main__':
    app.run(debug=True)
