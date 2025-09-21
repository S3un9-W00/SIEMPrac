from flask import Flask, render_template, request, jsonify, Response
import sqlite3
import datetime
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import io
import html

plt.rcParams['font.family'] = 'AppleGothic'  # macOS
plt.rcParams['axes.unicode_minus'] = False   # 마이너스 깨짐 방지

app = Flask(__name__)

suspicious_keywords = [
        "brute force", "sql injection", "union select", "drop table"," or ", "or 1 = 1", "or 1=1", "or 1 =1", "or 1= 1",
        "xss", "<script>", "malware", "exploit", "attack"
    ]

@app.after_request
def set_security_headers(resp):
    resp.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:;"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp

def init_db():
    conn = sqlite3.connect("siem.db")
    cur = conn.cursor()
    sql = """
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source TEXT,
                message TEXT,
                TimeStamp TEXT
            )
        """
    sql2 = """
            CREATE TABLE IF NOT EXISTS detect_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule TEXT,
                log_id INTEGER,
                TimeStamp TEXT
            )
        """
        
    cur.execute(sql)
    cur.execute(sql2)
    
    conn.commit()
    conn.close()
    

@app.route('/collect', methods=["POST"])
def collect_log():
    data = request.json
    log_id = data.get('id')
    source = data.get('source')
    message = data.get('message')
    TimeStamp = datetime.datetime.now()
    
    conn = sqlite3.connect("siem.db")
    cur = conn.cursor()
    
    sql = """
        INSERT INTO logs (source, message, TimeStamp) VALUES (?, ?, ?)
    """
    
    cur.execute(sql, (source, message, TimeStamp))
    
    conn.commit()
    conn.close()
    
    detect_log(message, log_id)
    
    return jsonify({"status" : "log stored"}), 202

def detect_log(message, log_id):
    
    for keyword in suspicious_keywords:
        if keyword in message.lower():
            conn = sqlite3.connect("siem.db")
            cur = conn.cursor()
            
            sql = """
                INSERT INTO detect_logs (rule, log_id, TimeStamp) VALUES (?, ?, ?)
            """
            
            cur.execute(sql, ("Strange access DETECTED! -> " + keyword, log_id, datetime.datetime.now()))
            
            conn.commit()
            conn.close()
            
            trigger_response("IP BlOCKING....!")
        elif not keyword in suspicious_keywords and "Failed" in message.lower():
            conn = sqlite3.connect("siem.db")
            cur = conn.cursor()
            
            sql = """
                INSERT INTO detect_logs (rule, log_id, TimeStamp) VALUES (?, ?, ?)
            """
            
            cur.execute(sql, ("Dangerous please analyze this log!", log_id, datetime.datetime.now()))
            
            conn.commit()
            conn.close()

        
    
    
def trigger_response(alert):
    print(f"[SOAR] 대응 시작 : {alert}")
    
    
@app.route('/')
def index():
    conn = sqlite3.connect("siem.db")
    df = pd.read_sql_query("SELECT * FROM logs ORDER BY id ASC", conn)
    conn.close()
    
    if not df.empty:
        df["message_safe"] = df["message"].astype(str).apply(html.escape)
        
        def classify_log(msg):

            for keyword in suspicious_keywords:
                if keyword in msg.lower():
                    return "⚠️ 공격 의심 (키워드 탐지) ⚠️ SOAR 시스템 동작 중....!"

            if "failed login" in msg.lower():
                return "⚠️ 주의 (로그인 실패) ⚠️"
            
            return "💯 정상 💯"
        df["result"] = df["message"].astype(str).apply(classify_log)
        
        rows = [
            {
                "id": r["id"],
                "source": html.escape(str(r["source"])),
                "message": r["message_safe"],
                "TimeStamp": html.escape(str(r["TimeStamp"])),
                "result": html.escape(str(r["result"])),
            }
            for _, r in df.iterrows()
        ]
        columns = ["id", "source", "message", "TimeStamp", "result"]
    else:
        rows = []
        columns = ["id", "source", "message", "TimeStamp", "result"]
    
    #return render_template("index.html", table_html=df.to_html(classes="result_data", index=False, escape=False))
    return render_template("index.html", rows=rows, columns=columns)

@app.route('/chart.png')
def chart():
    conn = sqlite3.connect("siem.db")
    df = pd.read_sql_query("SELECT * FROM logs", conn)
    conn.close()
    
    if not df.empty:
        df['TimeStamp'] = pd.to_datetime(df['TimeStamp'])
        
        df['Attack'] = df['message'].str.contains("Failed", case=False, na=False)
        
        stat = df.groupby(df['TimeStamp'].dt.hour)['Attack'].sum()
        
        # x축 : 시간, y축 : 감지 수
        
        fig, ax = plt.subplots()
        
        stat.plot(kind="bar", ax=ax)
        ax.set_title("시간대별 공격 감지 수(Failed Login)")
        ax.set_xlabel("시간 (Hour)")
        ax.set_ylabel("감지 수")
        
        img = io.BytesIO()
        plt.savefig(img, format="png")
        plt.close()
        img.seek(0)
        
        return Response(img.getvalue(), mimetype="image/png")
               

        

if __name__ == '__main__':
    init_db()
    app.run(port=5000, debug=True)