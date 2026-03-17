"""NetGuard - Flask app using stdlib sqlite3"""
import io, csv, os
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify, request, Response
from database import get_conn, init_db
from alerts import AlertManager
from domain_categorizer import DomainCategorizer

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'netguard-2024')
alert_manager = AlertManager()
categorizer = DomainCategorizer()

def ts_since(hours):
    return (datetime.utcnow() - timedelta(hours=hours)).strftime('%Y-%m-%d %H:%M:%S')

def row_dict(row):
    return dict(row) if row else None

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/stats')
def api_stats():
    since = ts_since(24)
    conn = get_conn(); c = conn.cursor()
    total   = c.execute("SELECT COUNT(*) FROM access_logs WHERE timestamp>=?",(since,)).fetchone()[0]
    blocked = c.execute("SELECT COUNT(*) FROM access_logs WHERE timestamp>=? AND status='Blocked'",(since,)).fetchone()[0]
    devs    = c.execute("SELECT COUNT(*) FROM devices WHERE last_seen>=?",(since,)).fetchone()[0]
    doms    = c.execute("SELECT COUNT(*) FROM blocked_domains WHERE active=1").fetchone()[0]
    unread  = c.execute("SELECT COUNT(*) FROM alerts WHERE read=0").fetchone()[0]
    conn.close()
    return jsonify({'total_requests':total,'blocked_requests':blocked,'allowed_requests':total-blocked,
                    'active_devices':devs,'blocked_domains':doms,'unread_alerts':unread,
                    'block_rate':round(blocked/total*100 if total else 0,1)})

@app.route('/api/logs')
def api_logs():
    page   = request.args.get('page',1,int)
    per    = request.args.get('per_page',30,int)
    status = request.args.get('status','')
    hours  = request.args.get('hours',24,int)
    since  = ts_since(hours)
    offset = (page-1)*per
    conn   = get_conn(); c = conn.cursor()
    where  = "WHERE timestamp>=?" + (" AND status=?" if status else "")
    params = (since, status) if status else (since,)
    total  = c.execute(f"SELECT COUNT(*) FROM access_logs {where}", params).fetchone()[0]
    rows   = c.execute(f"SELECT * FROM access_logs {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?", params+(per,offset)).fetchall()
    conn.close()
    return jsonify({'logs':[dict(r) for r in rows],'total':total,'pages':(total+per-1)//per,'current_page':page})

@app.route('/api/devices')
def api_devices():
    hours = request.args.get('hours',24,int); since = ts_since(hours)
    conn = get_conn(); c = conn.cursor()
    devs = c.execute("SELECT * FROM devices WHERE last_seen>=? ORDER BY last_seen DESC",(since,)).fetchall()
    result=[]
    for d in devs:
        dd=dict(d)
        dd['request_count']=c.execute("SELECT COUNT(*) FROM access_logs WHERE device_ip=? AND timestamp>=?",(d['ip_address'],since)).fetchone()[0]
        dd['blocked_count'] =c.execute("SELECT COUNT(*) FROM access_logs WHERE device_ip=? AND timestamp>=? AND status='Blocked'",(d['ip_address'],since)).fetchone()[0]
        result.append(dd)
    conn.close()
    return jsonify(result)

@app.route('/api/top-domains')
def api_top_domains():
    hours = request.args.get('hours',24,int); limit=request.args.get('limit',10,int); since=ts_since(hours)
    conn=get_conn(); c=conn.cursor()
    rows=c.execute("SELECT domain,COUNT(*) as count,status FROM access_logs WHERE timestamp>=? GROUP BY domain ORDER BY count DESC LIMIT ?",(since,limit)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route('/api/blocked-attempts')
def api_blocked_attempts():
    hours=request.args.get('hours',24,int); since=ts_since(hours)
    conn=get_conn(); c=conn.cursor()
    rows=c.execute("SELECT * FROM access_logs WHERE status='Blocked' AND timestamp>=? ORDER BY timestamp DESC LIMIT 50",(since,)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route('/api/traffic-timeline')
def api_traffic_timeline():
    hours=request.args.get('hours',24,int); since=ts_since(hours)
    conn=get_conn(); c=conn.cursor()
    rows=c.execute("SELECT strftime('%Y-%m-%d %H:00',timestamp) as hour,status,COUNT(*) as count FROM access_logs WHERE timestamp>=? GROUP BY hour,status ORDER BY hour",(since,)).fetchall()
    conn.close()
    timeline={}
    for r in rows:
        h=r['hour']
        if h not in timeline: timeline[h]={'hour':h,'allowed':0,'blocked':0}
        timeline[h]['allowed' if r['status']=='Allowed' else 'blocked']+=r['count']
    return jsonify(list(timeline.values()))

@app.route('/api/blocked-domains', methods=['GET'])
def api_blocked_domains():
    conn=get_conn(); c=conn.cursor()
    rows=c.execute("SELECT * FROM blocked_domains ORDER BY category,domain").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route('/api/blocked-domains', methods=['POST'])
def api_add_blocked_domain():
    data=request.get_json()
    domain=data.get('domain','').lower().strip()
    if not domain: return jsonify({'error':'Domain required'}),400
    conn=get_conn(); c=conn.cursor()
    existing=c.execute("SELECT * FROM blocked_domains WHERE domain=?",(domain,)).fetchone()
    if existing:
        c.execute("UPDATE blocked_domains SET active=1 WHERE domain=?",(domain,)); conn.commit()
        row=c.execute("SELECT * FROM blocked_domains WHERE domain=?",(domain,)).fetchone(); conn.close()
        return jsonify({'message':f'{domain} re-activated','domain':dict(row)})
    c.execute("INSERT INTO blocked_domains (domain,category,reason) VALUES (?,?,?)",(domain,data.get('category','custom'),data.get('reason','')))
    conn.commit(); row=c.execute("SELECT * FROM blocked_domains WHERE domain=?",(domain,)).fetchone(); conn.close()
    return jsonify({'message':f'{domain} added','domain':dict(row)}),201

@app.route('/api/blocked-domains/<int:did>', methods=['DELETE'])
def api_remove_blocked_domain(did):
    conn=get_conn(); c=conn.cursor()
    row=c.execute("SELECT domain FROM blocked_domains WHERE id=?",(did,)).fetchone()
    if not row: conn.close(); return jsonify({'error':'Not found'}),404
    c.execute("UPDATE blocked_domains SET active=0 WHERE id=?",(did,)); conn.commit(); conn.close()
    return jsonify({'message':f'{row["domain"]} removed'})

@app.route('/api/alerts')
def api_alerts():
    conn=get_conn(); c=conn.cursor()
    rows=c.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 30").fetchall(); conn.close()
    return jsonify([dict(r) for r in rows])

@app.route('/api/alerts/<int:aid>/read', methods=['POST'])
def api_mark_alert_read(aid):
    conn=get_conn(); c=conn.cursor()
    c.execute("UPDATE alerts SET read=1 WHERE id=?",(aid,)); conn.commit(); conn.close()
    return jsonify({'message':'Marked as read'})

@app.route('/api/export/logs')
def api_export_logs():
    hours=request.args.get('hours',24,int); since=ts_since(hours)
    conn=get_conn(); c=conn.cursor()
    rows=c.execute("SELECT * FROM access_logs WHERE timestamp>=? ORDER BY timestamp DESC",(since,)).fetchall(); conn.close()
    out=io.StringIO(); w=csv.writer(out)
    w.writerow(['Timestamp','Device IP','MAC Address','Domain','Category','Status'])
    for r in rows: w.writerow([r['timestamp'],r['device_ip'],r['device_mac'] or 'Unknown',r['domain'],r['category'] or 'uncategorized',r['status']])
    out.seek(0)
    fn=f"netguard_logs_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(out.getvalue(),mimetype='text/csv',headers={'Content-Disposition':f'attachment; filename={fn}'})

@app.route('/api/simulate', methods=['POST'])
def api_simulate():
    data=request.get_json()
    domain=data.get('domain','example.com').lower().strip()
    ip=data.get('device_ip','192.168.1.100')
    mac=data.get('device_mac','AA:BB:CC:DD:EE:FF')
    conn=get_conn(); c=conn.cursor()
    bl=c.execute("SELECT * FROM blocked_domains WHERE domain=? AND active=1",(domain,)).fetchone()
    status='Blocked' if bl else 'Allowed'
    category=bl['category'] if bl else categorizer.categorize(domain)
    now=datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    existing=c.execute("SELECT id FROM devices WHERE ip_address=?",(ip,)).fetchone()
    if existing: c.execute("UPDATE devices SET last_seen=?,mac_address=COALESCE(mac_address,?) WHERE ip_address=?",(now,mac,ip))
    else: c.execute("INSERT INTO devices (ip_address,mac_address,hostname,first_seen,last_seen) VALUES (?,?,?,?,?)",(ip,mac,f'device-{ip.split(".")[-1]}',now,now))
    c.execute("INSERT INTO access_logs (device_ip,device_mac,domain,status,category,timestamp) VALUES (?,?,?,?,?,?)",(ip,mac,domain,status,category,now))
    if status=='Blocked':
        msg=f"Blocked {domain} for {ip} ({category})"
        c.execute("INSERT INTO alerts (device_ip,device_mac,domain,category,message,channel,timestamp) VALUES (?,?,?,?,?,?,?)",(ip,mac,domain,category,msg,'log',now))
        alert_manager.send_alert(domain, ip, mac, category)
    conn.commit(); conn.close()
    return jsonify({'domain':domain,'status':status,'category':category})

@app.route('/api/monitor/status')
def api_monitor_status():
    return jsonify({'running':False,'packets':0})

if __name__=='__main__':
    init_db()
    app.run(debug=True,host='0.0.0.0',port=5000)
