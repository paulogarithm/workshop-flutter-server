from flask import Flask, jsonify
from flask import request as Request
from dotenv import load_dotenv
# import requests
import os
import psycopg2
import jwt
import datetime as dt
import hashlib
from sys import stderr

load_dotenv("/usr/mount.d/.env")

BACK_KEY = os.environ.get("BACK_KEY")
EXPIRATION = 60 * 30

app = Flask(__name__)

while True:
    try:
        db = psycopg2.connect(
            database=os.environ.get("DB_NAME"),
            user=os.environ.get("DB_USER"),
            password=os.environ.get("DB_PASSWORD"),
            host=os.environ.get("DB_HOST"),
            port=os.environ.get("DB_PORT")
        )
        break
    except psycopg2.OperationalError:
        continue

app = Flask(__name__)

def hash_this(s: str) -> str:
    return hashlib.md5(hashlib.sha256(s.encode()).hexdigest().encode()).hexdigest()

def get_password_from_nickname(nickname: str) -> str | None:
    with db.cursor() as cur:
        cur.execute("select password from users where nickname = %s", (nickname,))
        rows = cur.fetchone()
    if not rows:
        return None
    return rows[0]

def get_id_by_nickname(nickname: str) -> int | None:
    with db.cursor() as cur:
        cur.execute("select id from users where nickname = %s", (nickname,))
        rows = cur.fetchone()
    if not rows:
        return None
    return rows[0]

def get_nickname_by_id(id: int) -> str | None:
    with db.cursor() as cur:
        cur.execute("select nickname from users where id = %s", (id,))
        rows = cur.fetchone()
    if not rows:
        return None
    return rows[0]

def register_someone(nickname: str, hashedpwd: str) -> int | None:
    with db.cursor() as cur:
        cur.execute("insert into users(nickname, password) values (%s, %s) returning id", (nickname, hashedpwd))
        rows = cur.fetchone()
    if not rows:
        return None
    db.commit()
    return rows[0]

def create_token(uid: int) -> str:
    return jwt.encode({
        "id": uid,
        "exp": dt.datetime.now() + dt.timedelta(seconds=EXPIRATION)
    }, BACK_KEY, algorithm="HS256")

def check_nickname_and_password_return_hashed(data: dict) -> tuple[bool, ...]:
    if not "nickname" in data:
        return False, jsonify({ "error": "no nickname" }), 400
    if not "password" in data:
        return False, jsonify({ "error": "no password" }), 400
    if "' or 1=1" in str(data["password"]).lower():
        return False, jsonify({ "error": "nice try you dumbass" }), 400
    try:
        int(data["nickname"])
        return False, jsonify({ "error": "your nickname cant be just numbers" }), 400
    except ValueError:
        return True, hash_this(data["password"]), None

def retrieve_id_from_token(tok: str) -> int | None:
    tok = tok.removeprefix("Bearer ")
    try:
        return jwt.decode(tok, BACK_KEY, algorithms=["HS256"]).get("id")
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def change_soemthing_str(what: str, uid: int, newval: str):
    with db.cursor() as cur:
        cur.execute(f"update users set {what} = %s where id = %s", (newval, uid))
        db.commit()

def get_all_posts_of(uid: int) -> list[dict]:
    res = []
    nickname = get_nickname_by_id(uid)
    with db.cursor() as cur:
        cur.execute("select id, title, content from posts where owner = %s", (uid,))
        rows = cur.fetchall()
    if not rows:
        return jsonify([]), 200
    for e in rows:
        element = {
            "id": e[0],
            "userid": uid,
            "author": nickname,
            "title": e[1],
            "content": e[2],
            "comments": len(get_comments_for_post(e[0]))
        }
        res.append(element)
    return res

def get_all_posts() -> list[dict]:
    res = []
    hmap = {}
    with db.cursor() as cur:
        cur.execute("select id, owner, title, content from posts")
        rows = cur.fetchall()
    if not rows:
        return []
    for e in rows:
        element = {
            "id": e[0],
            "userid": e[1],
            "author": hmap[e[1]] if (e[1] in hmap) else get_nickname_by_id(e[1]),
            "title": e[2],
            "content": e[3],
            "comments": len(get_comments_for_post(e[0]))
        }
        res.append(element)
    return res
    
def create_a_post(uid: int, title: str, content: str) -> int | None:
    with db.cursor() as cur:
        cur.execute(
            "insert into posts(title, content, owner) values (%s, %s, %s) returning id",
            (title, content, uid)
        )
        rows = cur.fetchone()
    if not rows:
        return None
    db.commit()
    return rows[0]

def add_comment_to_post(postid: int, uid: int, content: str) -> int | None:
    with db.cursor() as cur:
        cur.execute(
            "insert into comments(post, owner, content) values (%s, %s, %s) returning id",
            (postid, uid, content)
        )
        rows = cur.fetchone()
    if not rows:
        return None
    db.commit()
    return rows[0]

def get_comments_for_post(postid: int) -> list[dict]:
    res = []
    hmap = {}
    with db.cursor() as cur:
        cur.execute("select id, owner, content from comments where post = %s", (postid,))
        rows = cur.fetchall()
    if not rows:
        return []
    for e in rows:
        element = {
            "id": e[0],
            "userid": e[1],
            "author": hmap[e[1]] if (e[1] in hmap) else get_nickname_by_id(e[1]),
            "content": e[2],
        }
        res.append(element)
    return res

# flask related

@app.route("/register", methods=["POST"])
def register():
    data = Request.get_json()
    success, a, b = check_nickname_and_password_return_hashed(data)
    if not success:
        return a, b
    try:
        if get_password_from_nickname(data["nickname"]) is not None:
            return jsonify({ "error": "nickname already in use" }), 400
        uid = register_someone(data["nickname"], a)
        if uid is None:
            return jsonify({ "error": "couldnt create user" }), 500
        return jsonify({ "token": create_token(uid) })
    except (Exception, psycopg2.Error) as err:
        return jsonify({ "error": "(database) " + str(err)}), 400

@app.route("/login", methods=["POST"])
def login():
    data = Request.get_json()
    success, a, b = check_nickname_and_password_return_hashed(data)
    if not success:
        return a, b
    try:
        real_hash = get_password_from_nickname(data["nickname"])
        if real_hash is None or real_hash != a:
            return jsonify({ "error": "invalid password/user" }), 400
        uid = get_id_by_nickname(data["nickname"])
        if uid is None:
            return jsonify({ "error": "couldnt get user ?" }), 500
        return jsonify({ "token": create_token(uid) })
    except (Exception, psycopg2.Error) as err:
        return jsonify({ "error": "(database) " + str(err)}), 400

@app.route("/change/password", methods=["POST"])
def change_password():
    data = Request.get_json()
    if not "password" in data:
        return jsonify({ "error": "expected password" }), 400
    auth = Request.headers.get("Authorization")
    if auth is None:
        return jsonify({ "error": "invalid/expired token" }), 400
    uid = retrieve_id_from_token(auth)
    if uid is None:
        return jsonify({ "error": "invalid/expired token" }), 400
    newpassword = hash_this(data["password"])
    try:
        change_soemthing_str("password", uid, newpassword)
        return jsonify({ "status": "ok" })
    except (Exception) as err:
        return jsonify({ "error": "(exception) " + str(err) }), 500

@app.route("/change/nickname", methods=["POST"])
def change_nickname():
    data = Request.get_json()
    if not "nickname" in data:
        return jsonify({ "error": "expected nickname" }), 400
    auth = Request.headers.get("Authorization")
    if auth is None:
        return jsonify({ "error": "invalid/expired token" }), 400
    uid = retrieve_id_from_token(auth)
    if uid is None:
        return jsonify({ "error": "invalid/expired token" }), 400
    newnickname = data["nickname"]
    if get_password_from_nickname(newnickname) is not None:
        return jsonify({ "error": "user already exists" }), 400
    try:
        change_soemthing_str("nickname", uid, newnickname)
        return jsonify({ "status": "ok" })
    except (Exception) as err:
        return jsonify({ "error": "(exception) " + str(err) }), 500

@app.route("/posts", methods=["POST", "GET"])
def post():
    auth = Request.headers.get("Authorization")
    if auth is None:
        return jsonify({ "error": "invalid/expired token" }), 400
    uid = retrieve_id_from_token(auth)
    if uid is None:
        return jsonify({ "error": "invalid/expired token" }), 400
    if Request.method == "GET":
        try:
            posts = get_all_posts()
        except (Exception) as err:
            return jsonify({ "error": "(exception) " + str(err) }), 500
        if posts is None:
            return jsonify({ "error": "fail to get posts" }), 500
        return jsonify(posts)
    if Request.method != "POST":
        return jsonify({ "error": "expected POST method" }), 400
    data = Request.get_json()
    if not "title" in data:
        return jsonify({ "error": "expected title" }), 400
    if not "content" in data:
        return jsonify({ "error": "expected content" }), 400
    try:
        pid = create_a_post(uid, data["title"], data["content"])
        if pid is None:
            return jsonify({ "error": "couldnt create post" }), 500
        return jsonify({ "id": pid }), 201
    except (Exception) as err:
        return jsonify({ "error": "(exception) " + str(err) }), 500

@app.route("/users/<int:who>/posts", methods=["GET"])
def get_user_posts(who: int):
    auth = Request.headers.get("Authorization")
    if auth is None or retrieve_id_from_token(auth) is None:
        return jsonify({ "error": "invalid/expired token" }), 400
    try:
        posts = get_all_posts_of(who)
        return jsonify(posts)
    except (Exception) as err:
        return jsonify({ "error": "(exception) " + str(err) }), 500

@app.route("/users/<int:who>", methods=["GET"])
def get_user_infos_from_userid(who: int):
    auth = Request.headers.get("Authorization")
    if auth is None or retrieve_id_from_token(auth) is None:
        return jsonify({ "error": "invalid/expired token" }), 400
    nick = get_nickname_by_id(who)
    if nick is None:
        return jsonify({ "error": "invalid userid" }), 400
    try:
        return jsonify({
            "nickname": nick,
            "postcount": len(get_all_posts_of(who)),
            "userid": who
        })
    except (Exception) as err:
        return jsonify({ "error": "(exception) " + str(err) }), 500

@app.route("/users/<string:who>", methods=["GET"])
def get_user_infos_from_nickname(who: str):
    print("foo", file=stderr)
    auth = Request.headers.get("Authorization")
    if auth is None or retrieve_id_from_token(auth) is None:
        return jsonify({ "error": "invalid/expired token" }), 400
    uid = get_id_by_nickname(who)
    if uid is None:
        return jsonify({ "error": "invalid user nickname" }), 400
    try:
        return jsonify({
            "nickname": who,
            "postcount": len(get_all_posts_of(uid)),
            "userid": uid
        })
    except (Exception) as err:
        return jsonify({ "error": "(exception) " + str(err) }), 500


@app.route("/posts/<int:postid>/comments", methods=["POST"])
def add_comment(postid: int):
    auth = Request.headers.get("Authorization")
    if auth is None or retrieve_id_from_token(auth) is None:
        return jsonify({ "error": "invalid/expired token" }), 400
    uid = retrieve_id_from_token(auth)
    if uid is None:
        return jsonify({ "error": "invalid/expired token" }), 400
    data = Request.get_json()
    if not "content" in data:
        return jsonify({ "error": "expected content" }), 400
    try:
        comment_id = add_comment_to_post(postid, uid, data["content"])
        if comment_id is None:
            return jsonify({ "error": "couldn't add comment" }), 500
        return jsonify({ "id": comment_id }), 201
    except (Exception) as err:
        return jsonify({ "error": "(exception) " + str(err) }), 500

@app.route("/posts/<int:postid>/comments", methods=["GET"])
def get_comments(postid: int):
    try:
        return jsonify(get_comments_for_post(postid))
    except (Exception) as err:
        return jsonify({ "error": "(exception) " + str(err) }), 500

@app.route("/", methods=["GET"])
def hello():
    return "server is online"

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=int(os.getenv("BACK_PORT")))