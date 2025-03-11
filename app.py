from bson import ObjectId
from pymongo import MongoClient

from flask import Flask, render_template, jsonify, request
from flask.json.provider import JSONProvider

import json

app = Flask(__name__)

client = MongoClient('localhost', 27017)
db = client.dbjungle


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


@app.route('/')
def home():
    return render_template('index.html')

#로그인
@app.route('/login')
def login():
    return ""
#회원가입

#팀 주문 등록

#팀 주문 전체 조회

#팀 주문 선택조회

#테스트용3

if __name__ == '__main__':
    app.run('0.0.0.0', port=5000, debug=True)

