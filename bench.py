
import asyncio
import json
import time
import okex_utils
import websocket
import _thread
import time
import rel

api_key = "2a230c3e-bc1b-431c-8dad-f446cfa2181e"
passphrase = "N0v@qu@ant"
secret_key = "256150CC5174231498B2EA240C3B14CC"
login_params = okex_utils.initLoginParams(False,api_key, passphrase, secret_key)
login_send_time = None
subscribe_send_time = None

subscribe_account_params = """{
    "op": "subscribe",
    "args": [{
        "channel": "account",
        "ccy": "BTC"
    }]
}"""

# print(f"login_params = {login_params}")


def on_message(ws, message):
    # 
    message_json = json.loads(message)
    if 'event' not in message_json:
        exit(0)
    if message_json["event"] == "login":
        now = time.time()
        gap = 1000*(now - login_send_time)
        print(f"login gap  = {gap} ms")
        ws.send(subscribe_account_params)
        global subscribe_send_time
        subscribe_send_time = time.time()
    if message_json["event"] == "subscribe":
        now = time.time()
        gap = 1000*(now - subscribe_send_time)
        print(f"subscribe gap  = {gap} ms")


def on_error(ws, error):
    print(error)
    pass

def on_close(ws, close_status_code, close_msg):
    print("### closed ###")

def on_open(ws):
    ws.send(login_params)
    global login_send_time
    login_send_time = time.time()

if __name__ == "__main__":
    # websocket.enableTrace(True)
    ws = websocket.WebSocketApp("wss://ws.okx.com:8443/ws/v5/private",
                              on_open=on_open,
                              on_message=on_message,
                              on_error=on_error,
                              on_close=on_close)

    ws.run_forever(dispatcher=rel, reconnect=5)  # Set dispatcher to automatic reconnection, 5 second reconnect delay if connection closed unexpectedly
    rel.signal(2, rel.abort)  # Keyboard Interrupt
    rel.dispatch()
