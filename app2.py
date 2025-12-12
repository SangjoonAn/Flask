from gevent import monkey
monkey.patch_all()

import os
import socket
import binascii
import time
from datetime import datetime
import json

import gevent
from gevent.queue import Queue

from flask import Flask, render_template, request, redirect, url_for, session
from flask_socketio import SocketIO, emit
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# 사용자 정의 파서 임포트
from define import *

# ------------------------------------------------------
# 전역 설정
# ------------------------------------------------------
UDS_PATH = '/tmp/ems_socket'
uds_conn_queue = Queue()

# ------------------------------------------------------
# Flask / DB / SocketIO 초기화
# ------------------------------------------------------
app = Flask(__name__)
app.secret_key = 'supersecretkey'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode='gevent',
    websocket_compression=False
)

db = SQLAlchemy(app)

# ------------------------------------------------------
# DB 모델
# ------------------------------------------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

# ------------------------------------------------------
# 공용 JSON → Binary 변환 함수
# ------------------------------------------------------
def json_to_jsonstring(data, fixed_size):
    """
    JSON dict → 순서대로 정렬하여 binary payload 생성
    define.py 에 있는 control packet spec 순서에 맞추어 정렬한다고 가정
    """
    try:
        result = bytearray()
        for key in ReqControl_PacketSize:
            val = data.get(key, 0)
            if isinstance(val, int):
                result.append(val & 0xFF)
            elif isinstance(val, bytes):
                result.extend(val)
            elif isinstance(val, list):
                result.extend(bytes(val))
            else:
                result.append(0)
        return bytes(result[:fixed_size])
    except Exception as e:
        print(f"json_to_jsonstring error: {e}")
        return bytes([0] * fixed_size)


def process_hex_packet(data, sio):
    """
    HEX 패킷 처리 함수 (웹소켓 emit 포함)
    - UDS에서 호출 시: sio 파라미터로 socketio 객체 전달
    - 웹소켓 이벤트에서 호출 시: sio=None (전역 socketio 사용)
    """   
    
    try:
        # 타입 변환
        if isinstance(data, bytes):
            binary_data = data
        elif isinstance(data, str):
            binary_data = binascii.unhexlify(data)
        else:
            raise ValueError("Unsupported data type")

        cmd = binary_data[6]
        #print(f"📦 Received cmd: 0x{cmd:02X}")

        # ------------------------------------------------
        # 상태 패킷 처리 0x55
        # ------------------------------------------------
        if cmd == 0x55:
            rcv_main_sys = binary_data[0]

            if rcv_main_sys == 0x30:      # DU 패킷
                #print(f"📦 DU cmd: ")
                update_status = parse_Du_StatusPacket(binary_data, sio)
                src_info = "DU"

            elif rcv_main_sys == 0x40:    # SU 패킷
                original_sub = binary_data[1]
                update_status = None
                
                # SU별로 적절한 파서 사용
                if original_sub == 0x11:
                    update_status = parse_AllStatusPacket2(binary_data, sio)
                    update_status['su_id'] = 'su1'
                    src_info = "SU1(0x11)"
                elif original_sub == 0x12:
                    update_status = parse_AllStatusPacket3(binary_data, sio)
                    update_status['su_id'] = 'su2'
                    src_info = "SU2(0x12)"
                elif original_sub == 0x13:
                    update_status = parse_AllStatusPacket4(binary_data, sio)
                    update_status['su_id'] = 'su3'
                    src_info = "SU3(0x13)"
                elif original_sub == 0x14:
                    update_status = parse_AllStatusPacket5(binary_data, sio)
                    update_status['su_id'] = 'su4'
                    src_info = "SU4(0x14)"
                else:
                    print(f"⚠️ Unknown SU ID: 0x{original_sub:02X}")
                    return {"status": "error", "message": f"Unknown SU ID: 0x{original_sub:02X}"}
                
                # 원본 SU 식별값 기록
                update_status['original_Rcv_Sub_Sys'] = f"0x{original_sub:02X}"

            else:
                print(f"⚠️ Unknown Rcv_Main_Sys: 0x{rcv_main_sys:02X}")
                return {"status": "error", "message": f"Unknown Rcv_Main_Sys: 0x{rcv_main_sys:02X}"}

            # 웹으로 전송
            if rcv_main_sys == 0x30:  # DU 패킷
                sio.emit("update_status", {"packet": update_status})
            elif rcv_main_sys == 0x40:  # SU 패킷
                su_id = update_status['su_id']
                sio.emit(f"{su_id}_status_update", {"packet": update_status})

            # 알람 상태 전송 (있을 때만)
            if 'AlarmStatus' in update_status:
                sio.emit("alarm_status_update", {"AlarmStatus": update_status['AlarmStatus']})

            # 마스크 알람 상태 전송 (있을 때만)
            if 'MaskAlarmStatus' in update_status:
                sio.emit("mask_alarm_status_update", {"MaskAlarmStatus": update_status['MaskAlarmStatus']})

            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{current_time}] 📥 Received Status Packet: {src_info}")
            return {"status": "success", "message": f"Processed {src_info} packet"}

        # ------------------------------------------------
        # TDD Packet 0x91
        # ------------------------------------------------
        elif cmd == 0x91:
            tdd_status = parse_TddStatusPacket(binary_data)
            sio.emit("tdd_status", {"packet": tdd_status})
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{current_time}] 📥 Received TDD Packet")
            return {"status": "success", "message": "Processed TDD packet"}

        else:
            print(f"⚠️ Unknown CMD: 0x{cmd:02X}")
            return {"status": "error", "message": f"Unknown CMD: 0x{cmd:02X}"}

    except binascii.Error as e:
        print(f"❌ Invalid HEX format: {e}")
        return {"status": "error", "message": "Invalid HEX format"}
    except Exception as e:
        print(f"❌ process_hex_packet error: {e}")
        return {"status": "error", "message": str(e)}



# ------------------------------------------------------
# UDS 수신 처리
# ------------------------------------------------------
def handle_uds_receive(conn, sio):
    """UDS 단일 커넥션 처리"""
    try:
        while True:
            data = conn.recv(2048)
            if not data:
                print("[UDS] Client disconnected")
                break

            # UDS 패킷을 hex parser 에 전달
            print(f"[UDS] Received {len(data)} bytes")
            process_hex_packet(data, sio)

    except ConnectionResetError:
        print("[UDS] Connection reset")
    except Exception as e:
        print(f"❌ UDS receive error: {e}")
    finally:
        conn.close()


# ------------------------------------------------------
# UDS 서버
# ------------------------------------------------------
def uds_server():
    if os.path.exists(UDS_PATH):
        os.remove(UDS_PATH)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(UDS_PATH)
    server.listen(5)
    print(f"[UDS] Server listening on {UDS_PATH}")

    while True:
        try:
            conn, _ = server.accept()
            uds_conn_queue.put(conn)
            print("[UDS] Client connected")
            gevent.spawn(handle_uds_receive, conn, socketio)
        except Exception as e:
            print(f"UDS server error: {e}")
            break


# ---------------------------- 라우트 ----------------------------
@app.route('/')
def home():
    # 로그인된 사용자만 메인 페이지 접근 허용
    if 'user_id' in session:
        return render_template('main.html')
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    # 로그인 폼 제출 처리
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id  # 로그인 성공 시 세션 저장
            return redirect(url_for('home'))
        return render_template('Login.html', error='Invalid credentials')  # 로그인 실패
    return render_template('Login.html')  # GET 요청 시 로그인 페이지 표시

@app.route('/logout')
def logout():
    session.pop('user_id', None)  # 세션 제거 (로그아웃 처리)
    return redirect(url_for('login'))

# ---------------------------- 소켓 이벤트 ----------------------------
@socketio.on('connect')
def handle_connect():
    print('✅ Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    print('❌ Client disconnected')




@socketio.on('Req_RptPacket')
def handle_Req_RptPacket(data):
    """ HEX 데이터 수신 및 변환 """
    try:
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        print(f"[{current_time}] 📤 Client : handle_Req_RptPacket")
        #print("📦 Received hex data:", data)
        
        binary_data = data  # HEX → Binary 변환
        cmd = binary_data[6]
        print("📦 Received cmd data:", cmd)

        if cmd == 0x55:
            # Rcv_Main_Sys 값에 따라 DU vs SU 패킷 구분
            rcv_main_sys = binary_data[0]

            if rcv_main_sys == 0x30:  # DU 패킷
                update_status = parse_Du_StatusPacket(binary_data)
                src_info = "DU"

            elif rcv_main_sys == 0x40:  # SU 패킷
                # 원본 SU 식별값(0x11~0x14) 확인
                original_sub = binary_data[1]
                update_status = None
                
                # SU별로 적절한 파서 사용
                if original_sub == 0x11:  # SU1
                    update_status = parse_AllStatusPacket2(binary_data)
                    update_status['su_id'] = 'su1'
                    src_info = "SU1(0x11)"
                elif original_sub == 0x12:  # SU2
                    update_status = parse_AllStatusPacket3(binary_data)
                    update_status['su_id'] = 'su2'
                    src_info = "SU2(0x12)"
                elif original_sub == 0x13:  # SU3
                    update_status = parse_AllStatusPacket4(binary_data)
                    update_status['su_id'] = 'su3'
                    src_info = "SU3(0x13)"
                elif original_sub == 0x14:  # SU4
                    update_status = parse_AllStatusPacket5(binary_data)
                    update_status['su_id'] = 'su4'
                    src_info = "SU4(0x14)"
                else:
                    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ⚠️ Unknown SU ID: 0x{original_sub:02X}")
                    return {"status": "error", "message": f"Unknown SU ID: 0x{original_sub:02X}"}
                
                # 원본 SU 식별값 기록
                update_status['original_Rcv_Sub_Sys'] = f"0x{original_sub:02X}"

            else:
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ⚠️ Unknown Rcv_Main_Sys: 0x{rcv_main_sys:02X}")
                return {"status": "error", "message": f"Unknown Rcv_Main_Sys: 0x{rcv_main_sys:02X}"}

            # SU별로 적절한 이벤트로 전송
            if rcv_main_sys == 0x30:  # DU 패킷
                socketio.emit("update_status", {"packet": update_status})
            elif rcv_main_sys == 0x40:  # SU 패킷
                su_id = update_status.get('su_id', 'su1')
                if su_id == 'su1':
                    socketio.emit("update_status", {"packet": update_status})
                elif su_id == 'su2':
                    socketio.emit("su2_status_update", {"packet": update_status})
                elif su_id == 'su3':
                    socketio.emit("su3_status_update", {"packet": update_status})
                elif su_id == 'su4':
                    socketio.emit("su4_status_update", {"packet": update_status})

            # 알람 상태 전송 (있을 때만)
            if 'AlarmStatus' in update_status:
                socketio.emit("alarm_status_update", {"AlarmStatus": update_status['AlarmStatus']})

            # 마스크 알람 상태 전송 (있을 때만)
            if 'MaskAlarmStatus' in update_status:
                socketio.emit("mask_alarm_status_update", {"MaskAlarmStatus": update_status['MaskAlarmStatus']})

            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{current_time}] 📥 Received Status Packet: {src_info}")
            return {"status": "success", "received_hex": data}

        elif cmd == 0x91:
            tdd_status = parse_TddStatusPacket(binary_data)
            socketio.emit("tdd_status", {"packet": tdd_status})
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{current_time}] 📥 Received Tdd Status Packet")
            return {"Tddstatus": "success", "received_hex": data}

    except binascii.Error:
        return {"status": "error", "message": "Invalid HEX format"}
    except Exception as e:
        print(f"❌ Unexpected Error: {e}")
        return {"status": "error", "message": str(e)}


@socketio.on('request_update_status')
def handle_request_update_status(data):
        
    if data['rcv_main_sys'] == PACKET_MAIN_DU_ID:
        REQ_STATUS_PACKET['Rcv_Main_Sys'] = data['rcv_main_sys'].to_bytes(1, 'big')
    else :
        REQ_STATUS_PACKET['Rcv_Main_Sys'] = PACKET_MAIN_SU_ID.to_bytes(1, 'big')
        REQ_STATUS_PACKET['Rcv_Sub_Sys'] = data['rcv_main_sys'].to_bytes(1, 'big')

    payload = b''.join(REQ_STATUS_PACKET.values())
   

    try:
        # 큐에서 UDS 연결 객체를 가져옴 (없으면 대기)
        # timeout을 줘서 무한정 기다리지 않도록 함
        conn = uds_conn_queue.get(timeout=5)
        conn.sendall(payload)   
        # 사용 후 연결 객체를 다시 큐에 넣음
        uds_conn_queue.put(conn)
        
        print(f"📤 Sent Binary ({len(payload)} bytes): {payload.hex()}")
    except gevent.queue.Empty:
        print(f"❌ Send error: No UDS client connected.")
        return {"status": "error", "message": "No UDS client connected."}
    except Exception as e:
        print(f"❌ Send error: {e}")
        return {"status": "error", "message": str(e)}



@socketio.on('request_tdd_status')
def handle_request_tdd_status(data=None):
    
    payload = b''.join(REQ_TDD_STATUS_PACKET.values())

    try:
        # 큐에서 UDS 연결 객체를 가져옴 (없으면 대기)
        # timeout을 줘서 무한정 기다리지 않도록 함
        conn = uds_conn_queue.get(timeout=5)
        conn.sendall(payload)   
        # 사용 후 연결 객체를 다시 큐에 넣음
        uds_conn_queue.put(conn)
        
        print(f"📤 Sent Binary ({len(payload)} bytes): {payload.hex()}")
    except gevent.queue.Empty:
        print(f"❌ Send error: No UDS client connected.")
        return {"status": "error", "message": "No UDS client connected."}
    except Exception as e:
        print(f"❌ Send error: {e}")
        return {"status": "error", "message": str(e)}

@socketio.on('du_Ctrl_packet')
def handle_du_control_packet(data):
    """ DU 제어 패킷 수신 및 처리 """
    
    data['Rcv_Main_Sys']        = 0x30
    data['Rcv_Object']          = 0x20
    #data['Trans_Main_Sys']      = 0x20
    #data['Trans_Object']        = 0x20
    data['Trans_Main_Sys']      = 0x30
    data['Trans_Object']        = 0x10
    data['CMD']                 = 0x58
    
    try:
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        print(f"[{current_time}] 🎛️ Received DU Control Packet")
        #print("📦 Received data:", data)
        
            
        # ConMuFlag 비트 기반 명령 처리
        if 'ConMuFlag' in data and data['ConMuFlag']:
            current_flag = data['ConMuFlag'][0]
            print(f"🔍 ConMuFlag[0] 값: {current_flag} (0x{current_flag:02X})")
            print(f"🔍 ConMuFlag[0] 비트: {bin(current_flag)[2:].zfill(8)}")
            
            # Reset 명령 확인 (비트 0)
            if current_flag & 0x01:
                print("🔄 DU Reset 명령 감지됨 (비트 0 = 1)")
                # TODO: 실제 DU 장비로 Reset 명령 전송
                # 여기에 실제 하드웨어 통신 로직 추가
            else:
                print("🔄 DU Reset 명령 없음 (비트 0 = 0)")

        
        # ConEmsModemReset 값 기반 명령 처리
        if 'ConEmsModemReset' in data:
            ems_modem_value = data['ConEmsModemReset']
            print(f"🔍 ConEmsModemReset 값: {ems_modem_value} (0x{ems_modem_value:02X})")
            
            if ems_modem_value == 0x01:
                print("🔄 Modem Reset 명령 감지됨 (0x01)")
                # TODO: 실제 DU 장비로 Modem Reset 명령 전송
                # 여기에 실제 하드웨어 통신 로직 추가
            elif ems_modem_value == 0x02:
                print("🔄 EMS Reset 명령 감지됨 (0x02)")
                # TODO: 실제 DU 장비로 EMS Reset 명령 전송
                # 여기에 실제 하드웨어 통신 로직 추가
            elif ems_modem_value == 0x00:
                print("🔄 ConEmsModemReset 명령 없음 (0x00)")
            else:
                print(f"⚠️ 알 수 없는 ConEmsModemReset 값: 0x{ems_modem_value:02X}")

        payload = json_to_jsonstring(data, ReqControl_PacketSize)
        try:
            #print(f"📤 Sent ACK: {payload}")
            # 큐에서 UDS 연결 객체를 가져옴 (없으면 대기)
            # timeout을 줘서 무한정 기다리지 않도록 함
            conn = uds_conn_queue.get(timeout=5)
            conn.sendall(payload)   
            # 사용 후 연결 객체를 다시 큐에 넣음
            uds_conn_queue.put(conn)
            
            print(f"📤 Sent Binary ({len(payload)} bytes): {payload.hex()}")
        except gevent.queue.Empty:
            print(f"❌ Send error: No UDS client connected.")
            return {"status": "error", "message": "No UDS client connected."}
        except Exception as e:
            print(f"❌ Send error: {e}")
            return {"status": "error", "message": str(e)}
               

        
        # test.py로 전송
        #socketio.emit('du_Ctrl_packet', data, include_self=False)
        return {"status": "success", "message": "DU Control packet received"}
        
    except Exception as e:
        print(f"❌ DU Control Packet Error: {e}")
        socketio.emit("du_control_response", {"status": "error", "message": str(e)})
        return {"status": "error", "message": str(e)}

@socketio.on("enter_set_mode")
def enter_set_mode(payload=None):
    print(f"🔧 Client entering Set Mode")
    emit("du_set_mode_ack", {"ok": True})

@socketio.on("leave_set_mode")
def leave_set_mode(payload=None):
    print(f"🔧 Client leaving Set Mode")
    emit("du_status_mode_ack", {"ok": True})

@socketio.on("enter_beam_info_set_mode")
def enter_beam_info_set_mode(payload=None):
    print(f"🔧 Client entering Beam Info Modal Set Mode")
    emit("beam_info_set_mode_ack", {"ok": True})

@socketio.on("leave_beam_info_set_mode")
def leave_beam_info_set_mode(payload=None):
    print(f"🔧 Client leaving Beam Info Modal Set Mode")
    emit("beam_info_status_mode_ack", {"ok": True})


@socketio.on("enter_su1_set_mode")
def enter_su1_set_mode(payload=None):
    print(f"🔧 Client entering SU1 Set Mode")
    emit("su1_set_mode_ack", {"ok": True})

@socketio.on("leave_su1_set_mode")
def leave_su1_set_mode(payload=None):
    print(f"🔧 Client leaving SU1 Set Mode")
    emit("su1_status_mode_ack", {"ok": True})

@socketio.on("enter_beam_info_set_mode_su1")
def enter_beam_info_set_mode_su1(payload=None):
    print(f"🔧 Client entering SU1 Beam Info Modal Set Mode")
    emit("beam_info_set_mode_su1_ack", {"ok": True})

@socketio.on("leave_beam_info_set_mode_su1")
def leave_beam_info_set_mode_su1(payload=None):
    print(f"🔧 Client leaving SU1 Beam Info Modal Set Mode")
    emit("beam_info_status_mode_su1_ack", {"ok": True})

# =========================
# SU2 / SU3 / SU4 handlers
# (SU1과 동일 로직을 그대로 확장)
# =========================

# --- SU2 ---
@socketio.on("enter_su2_set_mode")
def enter_su2_set_mode(_payload=None):
    print("[SU2] enter set mode")
    # SU1과 동일하게 OK 응답
    emit("su2_set_mode_ack", {"ok": True})

@socketio.on("leave_su2_set_mode")
def leave_su2_set_mode(_payload=None):
    print("[SU2] leave set mode → status mode")
    # SU1과 동일하게 status mode 진입 OK 응답
    emit("su2_status_mode_ack", {"ok": True})

@socketio.on("enter_beam_info_set_mode_su2")
def enter_beam_info_set_mode_su2(payload=None):
    print(f"🔧 Client entering SU2 Beam Info Modal Set Mode")
    emit("beam_info_set_mode_su2_ack", {"ok": True})

@socketio.on("leave_beam_info_set_mode_su2")
def leave_beam_info_set_mode_su2(payload=None):
    print(f"🔧 Client leaving SU2 Beam Info Modal Set Mode")
    emit("beam_info_status_mode_su2_ack", {"ok": True})

@socketio.on("apply_su2_values")
def apply_su2_values(payload):
    try:
        print(f"🔧 Applying SU2 values: {payload}")
        
        # payload 검증
        if not payload:
            raise ValueError("Payload is empty")
        
        # test.py로 전송 (SU1과 동일한 방식)
        socketio.emit("su2_Ctrl_packet", payload, include_self=False)
        
        # 클라이언트에게 성공 응답
        emit("su2_apply_ack", {"ok": True})
        
        print("✅ SU2 values successfully sent to test.py")
        return {"status": "success", "message": "SU2 values packet received and sent to test.py"}
        
    except ValueError as ve:
        error_msg = f"Validation error: {str(ve)}"
        print(f"❌ {error_msg}")
        emit("su2_apply_ack", {"ok": False, "error": error_msg})
        return {"status": "error", "message": error_msg}
        
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        print(f"❌ {error_msg}")
        emit("su2_apply_ack", {"ok": False, "error": error_msg})
        return {"status": "error", "message": error_msg}


# --- SU3 ---
@socketio.on("enter_su3_set_mode")
def enter_su3_set_mode(_payload=None):
    print("[SU3] enter set mode")
    emit("su3_set_mode_ack", {"ok": True})

@socketio.on("leave_su3_set_mode")
def leave_su3_set_mode(_payload=None):
    print("[SU3] leave set mode → status mode")
    emit("su3_status_mode_ack", {"ok": True})

@socketio.on("enter_beam_info_set_mode_su3")
def enter_beam_info_set_mode_su3(payload=None):
    print(f"🔧 Client entering SU3 Beam Info Modal Set Mode")
    emit("beam_info_set_mode_su3_ack", {"ok": True})

@socketio.on("leave_beam_info_set_mode_su3")
def leave_beam_info_set_mode_su3(payload=None):
    print(f"🔧 Client leaving SU3 Beam Info Modal Set Mode")
    emit("beam_info_status_mode_su3_ack", {"ok": True})

@socketio.on("apply_su3_values")
def apply_su3_values(payload):
    print(f"[SU3] apply values: {payload}")
    emit("su3_Ctrl_packet", payload, broadcast=True)
    emit("su3_apply_ack", payload, broadcast=True)


# --- SU4 ---
@socketio.on("enter_su4_set_mode")
def enter_su4_set_mode(_payload=None):
    print("[SU4] enter set mode")
    emit("su4_set_mode_ack", {"ok": True})

@socketio.on("leave_su4_set_mode")
def leave_su4_set_mode(_payload=None):
    print("[SU4] leave set mode → status mode")
    emit("su4_status_mode_ack", {"ok": True})

@socketio.on("enter_beam_info_set_mode_su4")
def enter_beam_info_set_mode_su4(payload=None):
    print(f"🔧 Client entering SU4 Beam Info Modal Set Mode")
    emit("beam_info_set_mode_su4_ack", {"ok": True})

@socketio.on("leave_beam_info_set_mode_su4")
def leave_beam_info_set_mode_su4(payload=None):
    print(f"🔧 Client leaving SU4 Beam Info Modal Set Mode")
    emit("beam_info_status_mode_su4_ack", {"ok": True})

@socketio.on("apply_su4_values")
def apply_su4_values(payload):
    print(f"[SU4] apply values: {payload}")
    emit("su4_Ctrl_packet", payload, broadcast=True)
    emit("su4_apply_ack", payload, broadcast=True)


@socketio.on("apply_du_values")
def apply_du_values(payload):
    try:
        print(f"🔧 Applying DU values: {payload}")
        
        # payload 검증
        if not payload:
            raise ValueError("Payload is empty")
        
        
        
        payload = json_to_jsonstring(payload, ReqControl_PacketSize)
        try:
            #print(f"📤 Sent ACK: {payload}")
            # 큐에서 UDS 연결 객체를 가져옴 (없으면 대기)
            # timeout을 줘서 무한정 기다리지 않도록 함
            conn = uds_conn_queue.get(timeout=5)
            conn.sendall(payload)   
            # 사용 후 연결 객체를 다시 큐에 넣음
            uds_conn_queue.put(conn)
            
            print(f"📤 Sent Binary ({len(payload)} bytes): {payload.hex()}")
        except gevent.queue.Empty:
            print(f"❌ Send error: No UDS client connected.")
            return {"status": "error", "message": "No UDS client connected."}
        except Exception as e:
            print(f"❌ Send error: {e}")
            return {"status": "error", "message": str(e)}
        
        
        
        #emit("du_apply_ack", {"ok": True})
        
        print("✅ DU values successfully sent to test.py")
        return {"status": "success", "message": "DU values packet received and sent to test.py"}
        
    except ValueError as ve:
        error_msg = f"Validation error: {str(ve)}"
        print(f"❌ {error_msg}")
        emit("du_apply_ack", {"ok": False, "error": error_msg})
        return {"status": "error", "message": error_msg}
        
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        print(f"❌ {error_msg}")
        emit("du_apply_ack", {"ok": False, "error": error_msg})
        return {"status": "error", "message": error_msg}

@socketio.on("apply_su1_values")
def apply_su1_values(payload):
    try:
        print(f"🔧 Applying SU1 values: {payload}")
        
        # payload 검증
        if not payload:
            raise ValueError("Payload is empty")
        
        # test.py로 전송 (DU와 동일한 방식)
        socketio.emit("su1_Ctrl_packet", payload, include_self=False)
        
        # 클라이언트에게 성공 응답
        emit("su1_apply_ack", {"ok": True})
        
        print("✅ SU1 values successfully sent to test.py")
        return {"status": "success", "message": "SU1 values packet received and sent to test.py"}
        
    except ValueError as ve:
        error_msg = f"Validation error: {str(ve)}"
        print(f"❌ {error_msg}")
        emit("su1_apply_ack", {"ok": False, "error": error_msg})
        return {"status": "error", "message": error_msg}
        
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        print(f"❌ {error_msg}")
        emit("su1_apply_ack", {"ok": False, "error": error_msg})
        return {"status": "error", "message": error_msg}

@socketio.on("enter_sync_set_mode")
def enter_sync_set_mode(payload=None):
    print(f"🔧 Client entering Sync Module Set Mode")
    emit("sync_set_mode_ack", {"ok": True})

@socketio.on("leave_sync_set_mode")
def leave_sync_set_mode(payload=None):
    print(f"🔧 Client leaving Sync Module Set Mode")
    emit("sync_status_mode_ack", {"ok": True})

@socketio.on("apply_sync_values")
def apply_sync_values(payload):
    try:
        print(f"🔧 Applying Sync Module values: {payload}")
        
        # payload 검증
        if not payload:
            raise ValueError("Payload is empty")
        
        # ConMuFlag 비트 기반 명령 처리 (DU와 동일한 방식)
        if 'ConMuFlag' in payload and payload['ConMuFlag']:
            print(f"🔍 Sync Module ConMuFlag: {payload['ConMuFlag']}")
            
            # 4바이트 ConMuFlag 처리
            if len(payload['ConMuFlag']) >= 4:
                # packet[12] (index 0) 처리
                flag_0 = payload['ConMuFlag'][0]
                print(f"🔍 Sync ConMuFlag[0] 값: {flag_0} (0x{flag_0:02X})")
                print(f"🔍 Sync ConMuFlag[0] 비트: {bin(flag_0)[2:].zfill(8)}")
                
                # TSYNC OUT SEL #1 (Bit3)
                if flag_0 & 0x08:
                    print("🔄 TSYNC OUT SEL #1 명령 감지됨 (Bit3 = 1)")
                
                # TSYNC OUT SEL #2 (Bit7)
                if flag_0 & 0x80:
                    print("🔄 TSYNC OUT SEL #2 명령 감지됨 (Bit7 = 1)")
                
                # packet[13] (index 1) 처리
                flag_1 = payload['ConMuFlag'][1]
                print(f"🔍 Sync ConMuFlag[1] 값: {flag_1} (0x{flag_1:02X})")
                print(f"🔍 Sync ConMuFlag[1] 비트: {bin(flag_1)[2:].zfill(8)}")
                
                # TSYNC OUT SEL #3 (Bit3)
                if flag_1 & 0x08:
                    print("🔄 TSYNC OUT SEL #3 명령 감지됨 (Bit3 = 1)")
                
                # TDD SLOT FORMAT (Bit4)
                if flag_1 & 0x10:
                    print("🔄 TDD SLOT FORMAT 명령 감지됨 (Bit4 = 1)")
                
                # TDD FORMAT 3GPP TABLE (Bit5)
                if flag_1 & 0x20:
                    print("🔄 TDD FORMAT 3GPP TABLE 명령 감지됨 (Bit5 = 1)")
                
                # TDD Frequency (Bit6)
                if flag_1 & 0x40:
                    print("🔄 TDD Frequency 명령 감지됨 (Bit6 = 1)")
                
                # TDD ARFCN (Bit7)
                if flag_1 & 0x80:
                    print("🔄 TDD ARFCN 명령 감지됨 (Bit7 = 1)")
                
                # packet[14] (index 2) 처리
                flag_2 = payload['ConMuFlag'][2]
                print(f"🔍 Sync ConMuFlag[2] 값: {flag_2} (0x{flag_2:02X})")
                print(f"🔍 Sync ConMuFlag[2] 비트: {bin(flag_2)[2:].zfill(8)}")
                
                # MVBX SSB MU (Bit0)
                if flag_2 & 0x01:
                    print("🔄 MVBX SSB MU 명령 감지됨 (Bit0 = 1)")
                
                # MVBX TDD RATE (Bit3)
                if flag_2 & 0x08:
                    print("🔄 MVBX TDD RATE 명령 감지됨 (Bit3 = 1)")
                
                # F Mode (Bit4)
                if flag_2 & 0x10:
                    print("🔄 F Mode 명령 감지됨 (Bit4 = 1)")
        
        # test.py로 전송 (DU, SU1과 동일한 방식)
        socketio.emit("sync_Ctrl_packet", payload, include_self=False)
        
        # 클라이언트에게 성공 응답
        emit("sync_apply_ack", {"ok": True})
        
        print("✅ Sync Module values successfully sent to test.py")
        return {"status": "success", "message": "Sync Module values packet received and sent to test.py"}
        
    except ValueError as ve:
        error_msg = f"Validation error: {str(ve)}"
        print(f"❌ {error_msg}")
        emit("sync_apply_ack", {"ok": False, "error": error_msg})
        return {"status": "error", "message": error_msg}
        
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        print(f"❌ {error_msg}")
        emit("sync_apply_ack", {"ok": False, "error": error_msg})
        return {"status": "error", "message": error_msg}





# ---------------------------- 서버 실행 ----------------------------
if __name__ == '__main__':
    # 애플리케이션 컨텍스트 내에서 초기 사용자 생성
    with app.app_context():
        db.create_all() # 데이터베이스 테이블 생성
        # 'primaer' 사용자 존재 여부 확인 후 없으면 추가
        if not User.query.filter_by(username='primaer').first():
            db.session.add(User(username='primaer', password=generate_password_hash('frtek69728!')))
        # 'user1' 사용자 존재 여부 확인 후 없으면 추가
        if not User.query.filter_by(username='user1').first():
            db.session.add(User(username='user1', password=generate_password_hash('test123')))
        db.session.commit() # 변경사항 커밋

    # ---------------------------- UDS 서버 스레드 시작 ----------------------------
    # UDS 서버 시작
    gevent.spawn(uds_server)
    print("[MAIN] UDS server thread started.")

    # ---------------------------- 서버 실행 ----------------------------
    socketio.run(app, host="0.0.0.0", port=5001, debug=True, use_reloader=False)
