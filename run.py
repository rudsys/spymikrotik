import threading
import time
import urllib.request
import urllib.parse
import json
import routeros_api

# --- LOAD KONFIGURASI DARI JSON ---
def load_json_config(file_path):
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Gagal membaca {file_path}: {e}")
        return {}

telegram_config = load_json_config("telegram.json")
routers_config = load_json_config("routers.json")

TELEGRAM_BOT_TOKEN = telegram_config.get("bot_token", "")
TELEGRAM_CHAT_ID = telegram_config.get("chat_id", "")
INTERVAL = 5

# --- Variabel Global ---
last_seen_timestamps = {}  # { router_host: timestamp }
ip_failure_counts = {}     # { router_host: { ip: count } }
is_first_runs = {}         # { router_host: bool }
router_identities = {}     # { router_host: identity }

def send_telegram_message(message, reply_markup=None):
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {
            'chat_id': TELEGRAM_CHAT_ID,
            'text': message,
            'parse_mode': 'Markdown'
        }
        if reply_markup:
            payload['reply_markup'] = json.dumps(reply_markup)
            
        data = urllib.parse.urlencode(payload).encode('utf-8')
        req = urllib.request.Request(url, data=data, method='POST')
        with urllib.request.urlopen(req, timeout=10) as response:
            pass
    except Exception as e:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Gagal kirim Telegram: {e}")

def handle_telegram_callbacks():
    """Polling sederhana untuk mendeteksi klik tombol inline keyboard dari Telegram"""
    offset = None
    try:
        while True:
            url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getUpdates?timeout=3"
            if offset:
                url += f"&offset={offset}"
            
            req = urllib.request.Request(url, method='GET')
            with urllib.request.urlopen(req, timeout=5) as response:
                data = json.loads(response.read().decode('utf-8'))
                if data.get('ok') and data.get('result'):
                    for update in data['result']:
                        offset = update['update_id'] + 1
                        callback_query = update.get('callback_query')
                        if callback_query:
                            callback_data = callback_query.get('data')
                            if callback_data and callback_data.startswith("block_"):
                                parts = callback_data.split("_")
                                ip_to_block = parts[1]
                                
                                # Cari router berdasarkan index yang disimpan di callback_data (lebih aman dari split string)
                                router_idx = int(parts[2]) if len(parts) > 2 else 0
                                target_router = routers_config[router_idx] if router_idx < len(routers_config) else routers_config[0]
                                
                                query_id = callback_query.get('id')
                                chat_id = callback_query.get('message', {}).get('chat', {}).get('id')
                                message_id = callback_query.get('message', {}).get('message_id')
                                
                                # Eksekusi blokir ke MikroTik target
                                success, message_reply = apply_mikrotik_block(ip_to_block, target_router)
                                
                                if chat_id and message_id:
                                    try:
                                        del_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/deleteMessage"
                                        del_data = urllib.parse.urlencode({'chat_id': chat_id, 'message_id': message_id}).encode('utf-8')
                                        del_req = urllib.request.Request(del_url, data=del_data, method='POST')
                                        urllib.request.urlopen(del_req, timeout=5)
                                    except Exception:
                                        pass
                                        
                                if chat_id:
                                    if success:
                                        feedback_text = f"✅ *IP Berhasil Diblokir!*\n\nIP: `{ip_to_block}` telah ditambahkan ke Address-List `blocked-attackers` dan Rule Firewall DROP."
                                    else:
                                        feedback_text = f"❌ *Gagal Memblokir IP!*\n\nIP: `{ip_to_block}`\nAlasan: `{message_reply}`"
                                    send_telegram_message(feedback_text)
                                
                                answer_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/answerCallbackQuery"
                                answer_data = urllib.parse.urlencode({
                                    'callback_query_id': query_id,
                                    'text': message_reply,
                                    'show_alert': False
                                }).encode('utf-8')
                                ans_req = urllib.request.Request(answer_url, data=answer_data, method='POST')
                                try:
                                    urllib.request.urlopen(ans_req, timeout=5)
                                except Exception:
                                    pass
            time.sleep(1)
    except Exception as e:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Telegram Callback Listener Error: {e}")

def apply_mikrotik_block(ip_address, router_cfg):
    try:
        connection = routeros_api.RouterOsApiPool(
            host=router_cfg.get("host"),
            username=router_cfg.get("username"),
            password=router_cfg.get("password"),
            port=router_cfg.get("port", 8728),
            plaintext_login=True
        )
        api = connection.get_api()
        
        list_resource = api.get_resource('/ip/firewall/address-list')
        existing_list = list_resource.get(address=ip_address, list='blocked-attackers')
        if not existing_list:
            list_resource.add(list='blocked-attackers', address=ip_address, comment='Blocked via Telegram Bot')
        
        filter_resource = api.get_resource('/ip/firewall/filter')
        rules = filter_resource.get()
        drop_rule_exists = False
        
        for rule in rules:
            if rule.get('src-address-list') == 'blocked-attackers' and rule.get('action') == 'drop':
                drop_rule_exists = True
                break
                
        if not drop_rule_exists:
            filter_resource.add(
                chain='input',
                action='drop',
                src_address_list='blocked-attackers',
                comment='Drop blocked attackers from Telegram Bot'
            )
            
        connection.disconnect()
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Berhasil memblokir IP: {ip_address}")
        return True, f"IP {ip_address} berhasil diblokir!"
    except Exception as e:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Gagal blokir IP via API: {e}")
        return False, f"Gagal memblokir: {str(e)}"

def get_router_identity(api):
    try:
        identity_resource = api.get_resource('/system/identity')
        res = identity_resource.get()
        if res and len(res) > 0:
            return res[0].get('name', 'Unknown')
    except Exception:
        pass
    return "Unknown"

def monitor_login_failures_api(router_cfg):
    global is_first_runs, last_seen_timestamps, ip_failure_counts, router_identities
    
    host = router_cfg.get("host")
    port = router_cfg.get("port", 8728)
    router_key = f"{host}:{port}"
    
    try:
        connection = routeros_api.RouterOsApiPool(
            host=host,
            username=router_cfg.get("username"),
            password=router_cfg.get("password"),
            port=port,
            plaintext_login=True
        )
        api = connection.get_api()
        
        router_name = router_cfg.get("name", f"{host}:{port}")
        
        if router_key not in is_first_runs:
            is_first_runs[router_key] = True
            last_seen_timestamps[router_key] = None
            ip_failure_counts[router_key] = {}
            router_identities[router_key] = router_name  # Gunakan nama dari config
            
        # Jika identity router belum diambil, ambil dari API
        if router_identities.get(router_key) == router_name:
            fetched_identity = get_router_identity(api)
            if fetched_identity != "Unknown":
                router_identities[router_key] = fetched_identity
                
        log_resource = api.get_resource('/log')
        logs = log_resource.get()
        current_fail_logs = [item for item in logs if 'login failure' in item.get('message', '').lower()]
        
        if is_first_runs[router_key]:
            if current_fail_logs:
                last_seen_timestamps[router_key] = current_fail_logs[-1].get('time')
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Inisialisasi Berhasil. Router: {router_identities[router_key]} ({host}:{port})")
            is_first_runs[router_key] = False
            connection.disconnect()
            return

        new_logs = []
        for log_item in current_fail_logs:
            log_time = log_item.get('time')
            if last_seen_timestamps[router_key] is None or log_time > last_seen_timestamps[router_key]:
                new_logs.append(log_item)

        for log_item in new_logs:
            msg = log_item.get('message', '')
            last_seen_timestamps[router_key] = log_item.get('time')
            
            source_ip = "Unknown"
            username = "Unknown"
            protocol = "Unknown"

            if "from " in msg:
                try:
                    parts = msg.split("from ")
                    if len(parts) > 1:
                        source_ip = parts[1].split(" ")[0]
                except Exception:
                    pass

            if "user " in msg:
                try:
                    parts = msg.split("user ")
                    if len(parts) > 1:
                        username = parts[1].split(" ")[0]
                except Exception:
                    pass

            if "via " in msg:
                try:
                    parts = msg.split("via ")
                    if len(parts) > 1:
                        protocol = parts[1].strip().upper()
                except Exception:
                    pass

            if source_ip not in ip_failure_counts[router_key]:
                ip_failure_counts[router_key][source_ip] = 0
            ip_failure_counts[router_key][source_ip] += 1
            current_ip_count = ip_failure_counts[router_key][source_ip]
            
            formatted_time = time.strftime('%Y-%m-%d %H:%M:%S')

            router_identity = router_identities.get(router_key, "Unknown")

            print(f"🚨 LOGIN FAILURE TERDETEKSI!")
            print(f"============================")
            print(f"Router : {router_identity}")
            print(f"from IP : {source_ip}")
            print(f"user : {username}")
            print(f"via : {protocol}")
            print(f"date : {formatted_time}")
            print(f"Detail : {msg}")
            print(f"=============================")
            print(f"Percobaan Login Ke  : {current_ip_count}\n")

            telegram_msg = (
                f"🚨 *LOGIN FAILURE TERDETEKSI!*\n"
                f"============================\n"
                f"*Router* : `{router_identity}`\n"
                f"*from IP* : `{source_ip}`\n"
                f"*user* : `{username}`\n"
                f"*via* : `{protocol}`\n"
                f"*date* : `{formatted_time}`\n"
                f"*Detail* : `{msg}`\n"
                f"=============================\n"
                f"*Percobaan Login Ke* : `{current_ip_count}`"
            )
            
            inline_keyboard = {
                "inline_keyboard": [
                    [
                        {
                            "text": f"Blockir IP {source_ip}",
                            "callback_data": f"block_{source_ip}_{routers_config.index(router_cfg)}"
                        }
                    ]
                ]
            }
            send_telegram_message(telegram_msg, reply_markup=inline_keyboard)

        connection.disconnect()
        
    except Exception as e:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Error API {host}:{port}: {e}")

if __name__ == "__main__":
    print(f"=== Real-Time Multi-Router Login Failure Monitor ===")
    print(f"Total Router Terdaftar: {len(routers_config)}")
    print(f"Interval: {INTERVAL} detik. Tekan Ctrl+C untuk berhenti.\n")
    
    callback_thread = threading.Thread(target=handle_telegram_callbacks, daemon=True)
    callback_thread.start()
    
    try:
        while True:
            for router_cfg in routers_config:
                monitor_login_failures_api(router_cfg)
                time.sleep(1) # Sedikit delay antar router agar tidak overload
            time.sleep(INTERVAL)
    except KeyboardInterrupt:
        total_failures = sum(sum(ip_counts.values()) for ip_counts in ip_failure_counts.values())
        print(f"\nMonitoring dihentikan oleh pengguna.")
        print(f"Total keseluruhan 'login failure' yang tercatat selama sesi ini: {total_failures} kali.")