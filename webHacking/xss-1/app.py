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


# selenium webdriver는 python이 새 인터넷 창을 띄워서 접속하게 할 수 있는 모듈이다.
# 서버 컴퓨터에서 driver.get으로 크롬 창을 띄운다. 이때, url을 우리가 지정한 값으로 접속하므로 쿠키값을 얻어낼 수 있다.
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
    url = f"http://127.0.0.1:8000/vuln?param={urllib.parse.quote(param)}"   #urllib.parse.quote()는 아스키 코드 형식이 아닌 글자를 URL인코딩 시켜준다.
    return read_url(url, cookie)


@app.route("/")
def index():
    return render_template("index.html")

# vuln에 memo를 쓰게 script를 만들 수 있는가? 가능하다.
# <script>new Image().src="/memo?memo=imagesrc01"</script>
@app.route("/vuln")
def vuln():
    param = request.args.get("param", "")
    return param

# <script>new Image().src="/memo?memo=flag01"+document.cookie;</script>
@app.route("/flag", methods=["GET", "POST"])
def flag():
    if request.method == "GET":
        return render_template("flag.html")
    elif request.method == "POST":
        param = request.form.get("param")
        if not check_xss(param, {"name": "flag", "value": FLAG.strip()}):   #strip는 좌우 공백을 없애준다.
            return '<script>alert("wrong??");history.go(-1);</script>'

        return '<script>alert("good");history.go(-1);</script>'


memo_text = ""


@app.route("/memo")
def memo():
    global memo_text
    text = request.args.get("memo", "")
    memo_text += text + "\n"
    return render_template("memo.html", memo=memo_text)


app.run(host="0.0.0.0", port=8000)