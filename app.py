from flask import Flask, render_template, request, redirect, url_for, session
from flask_socketio import SocketIO, emit
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import binascii
import struct
import time # 시간을 측정하기 위해 time 모듈 추가
from datetime import datetime # 현재 시간을 가져오기 위해 datetime 모듈 추가

import os

# Flask 애플리케이션 생성 및 설정
app = Flask(__name__)
app.secret_key = 'supersecretkey'  # 세션 보안을 위한 비밀 키 설정
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # SQLite DB 경로 설정
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # 추적 기능 비활성화로 성능 향상

# Flask-SocketIO 및 SQLAlchemy 초기화
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
db = SQLAlchemy(app)

# ---------------------------- DB 모델 ----------------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # 사용자 고유 ID
    username = db.Column(db.String(80), unique=True, nullable=False)  # 사용자 이름
    password = db.Column(db.String(200), nullable=False)  # 암호화된 비밀번호

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


'''
@socketio.on('hex_packet')
def handle_hex_packet(data):
    """ HEX 데이터 수신 및 변환 """
    try:
        binary_data = binascii.unhexlify(data)  # HEX → Binary 변환
        cmd = binary_data[6]
        if cmd == 0x55 :
            # Rcv_Main_Sys 값에 따라 DU vs SU 패킷 구분
            rcv_main_sys = binary_data[0]
            if rcv_main_sys == 0x30:  # DU 패킷
                update_status = parse_AllStatusPacket(binary_data)
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 📥 Received DU Status Packet")
            elif rcv_main_sys == 0x40:  # SU 패킷
                update_status = parse_AllStatusPacket2(binary_data)
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 📥 Received SU Status Packet")
            else:
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ⚠️ Unknown Rcv_Main_Sys: 0x{rcv_main_sys:02X}")
                return {"status": "error", "message": f"Unknown Rcv_Main_Sys: 0x{rcv_main_sys:02X}"}
            
            socketio.emit("update_status", {"packet": update_status})
                    
            # 알람 상태를 별도로 전송 (DU와 SU 패킷 모두)
            if 'AlarmStatus' in update_status:
                socketio.emit("alarm_status_update", {"AlarmStatus": update_status['AlarmStatus']})
            
            # Mask 알람 상태도 전송 (DU와 SU 패킷 모두)
            if 'MaskAlarmStatus' in update_status:
                socketio.emit("mask_alarm_status_update", {"MaskAlarmStatus": update_status['MaskAlarmStatus']})
            
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S") # 밀리초까지 포함 (뒤 3자리는 잘라내어 마이크로초 대신 밀리초 단위로 표시)
            print(f"[{current_time}] 📥 Received Status Packet")
            return {"status": "success", "received_hex": data}
        elif cmd == 0x91 :
            tdd_status = parse_TddStatusPacket(binary_data)
            socketio.emit("tdd_status", {"packet": tdd_status})
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S") # 밀리초까지 포함 (뒤 3자리는 잘라내어 마이크로초 대신 밀리초 단위로 표시)
            print(f"[{current_time}] 📥 Received Tdd Status Packet")
            return {"Tddstatus": "success", "received_hex": data}

    except binascii.Error:
        return {"status": "error", "message": "Invalid HEX format"}
    except Exception as e:
        print(f"❌ Unexpected Error: {e}")
        return {"status": "error", "message": str(e)}

'''

@socketio.on('hex_packet')
def handle_hex_packet(data):
    """ HEX 데이터 수신 및 변환 """
    try:
        # 데이터 타입 확인 및 변환
        if isinstance(data, bytes):
            # 이미 바이너리 데이터인 경우
            binary_data = data
        elif isinstance(data, str):
            # HEX 문자열인 경우
            binary_data = binascii.unhexlify(data)
        else:
            raise ValueError(f"Unexpected data type: {type(data)}")
        
        cmd = binary_data[6]

        if cmd == 0x55:
            # Rcv_Main_Sys 값에 따라 DU vs SU 패킷 구분
            rcv_main_sys = binary_data[0]

            if rcv_main_sys == 0x30:  # DU 패킷
                update_status = parse_AllStatusPacket(binary_data)
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
def handle_request_update_status(data=None):
    try:
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        print(f"[{current_time}] 📤 Client requested: update_status packet")
        # 시뮬레이터(test.py)에게 요청을 "payload 포함" 재전파
        socketio.emit('request_update_status', data or {}, include_self=False)
        return {"status": "success", "message": "update_status request forwarded"}
    except Exception as e:
        print(f"❌ Update Status Request Error: {e}")
        return {"status": "error", "message": str(e)}



@socketio.on('request_tdd_status')
def handle_request_tdd_status(data=None):
    try:
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        print(f"[{current_time}] 📤 Client requested: tdd_status packet")
        # 시뮬레이터(test.py)에게 요청을 "payload 포함" 재전파
        socketio.emit('request_tdd_status', data or {}, include_self=False)
        return {"status": "success", "message": "tdd_status request forwarded"}
    except Exception as e:
        print(f"❌ TDD Status Request Error: {e}")
        return {"status": "error", "message": str(e)}

@socketio.on('du_Ctrl_packet')
def handle_du_control_packet(data):
    """ DU 제어 패킷 수신 및 처리 """
    try:
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        print(f"[{current_time}] 🎛️ Received DU Control Packet")
        print("📦 Received data:", data)
        
        # 패킷 데이터 처리
        
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
            
            # PLL Relock 명령 확인 (비트 7)
            if current_flag & 0x80:
                print("🔄 PLL Relock 명령 감지됨 (비트 7 = 1)")
                # TODO: 실제 DU 장비로 PLL Relock 명령 전송
                # 여기에 실제 하드웨어 통신 로직 추가
            else:
                print("🔄 PLL Relock 명령 없음 (비트 7 = 0)")
            
            # ConMuFlag[14] (packet[594]) 비트 기반 명령 처리
            if len(data['ConMuFlag']) > 14:
                flag_14 = data['ConMuFlag'][14]
                print(f"🔍 ConMuFlag[14] 값: {flag_14} (0x{flag_14:02X})")
                print(f"🔍 ConMuFlag[14] 비트: {bin(flag_14)[2:].zfill(8)}")
                
                # RSRP Request 명령 확인 (비트 5)
                if flag_14 & 0x20:
                    print("🔄 RSRP Request 명령 감지됨 (비트 5 = 1)")
                    # TODO: 실제 DU 장비로 RSRP Request 명령 전송
                    # 여기에 실제 하드웨어 통신 로직 추가
                else:
                    print("🔄 RSRP Request 명령 없음 (비트 5 = 0)")
                
                # Beam Scan 명령 확인 (비트 6)
                if flag_14 & 0x40:
                    print("🔄 Beam Scan 명령 감지됨 (비트 6 = 1)")
                    # TODO: 실제 DU 장비로 Beam Scan 명령 전송
                    # 여기에 실제 하드웨어 통신 로직 추가
                else:
                    print("🔄 Beam Scan 명령 없음 (비트 6 = 0)")
        
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
        
        # test.py로 전송
        socketio.emit('du_Ctrl_packet', data, include_self=False)
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

@socketio.on("enter_su1_set_mode")
def enter_su1_set_mode(payload=None):
    print(f"🔧 Client entering SU1 Set Mode")
    emit("su1_set_mode_ack", {"ok": True})

@socketio.on("leave_su1_set_mode")
def leave_su1_set_mode(payload=None):
    print(f"🔧 Client leaving SU1 Set Mode")
    emit("su1_status_mode_ack", {"ok": True})

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
        
        # test.py로 전송 (134라인 함수와 동일한 방식)
        socketio.emit("du_Ctrl_packet", payload, include_self=False)
        
        # 클라이언트에게 성공 응답
        emit("du_apply_ack", {"ok": True})
        
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






# ---------------------------- 샘플 파서 함수 ----------------------------
def parse_AllStatusPacket(packet):


    parsed_data = {}
    
    # 단위 변환 함수들
    def convert_to_01dbm(raw_value):
        """0.1dBm 단위로 변환 (예: -517 → -51.7 dBm)"""
        return round(raw_value / 10.0, 1)
    
    def convert_att_4_to_2(raw_value):
        """ATT 변환 (4→2dB, Step: 0.5dB)"""
        return raw_value * 0.5
    
    def convert_to_1dbm(raw_value):
        """1dBm 단위로 변환"""
        return raw_value
    
    def convert_iso_att(raw_value):
        """ISO ATT 변환 (4→2dB, Step: 0.5dB, Range: 0~20dB)"""
        return raw_value * 0.5
    
    def convert_att_test(raw_value):
        """ATT Test 변환 (50: 5dB, 0.5dB 단위, Range: 0~30dB)"""
        return raw_value * 0.5
    
    def convert_polling_time(raw_value):
        """Polling Time 변환 (2바이트 uint, 범위: 100~5,000ms)"""
        return raw_value  # 이미 ms 단위로 저장되어 있음
    
    #Du 상태
    parsed_data['Rcv_Main_Sys'] = packet[0]
    # Rcv_Main_Sys 감지 시 RX 박스 켜기
    socketio.emit("rx_on")
    parsed_data['Rcv_Sub_Sys'] = packet[1]
    parsed_data['Rcv_Object'] = packet[2]
    parsed_data['Trans_Main_Sys'] = packet[3]
    # Trans_Main_Sys 감지 시 TX 박스 토글 (1이면 켜기, 0이면 끄기)
    if packet[3] != 0:
        socketio.emit("tx_on")
    else:
        socketio.emit("tx_off")
    parsed_data['Trans_Sub_Sys'] = packet[4]
    parsed_data['Trans_Object'] = packet[5]
    parsed_data['CMD'] = packet[6]
    parsed_data['EQUIP_TYPE'] = packet[7]
    parsed_data['RESERVED'] = packet[8:10]
    parsed_data['SubData_Size'] = struct.unpack('<h', bytes([packet[10], packet[11]]))[0]
    parsed_data['McuSwVer'] = f"{packet[13]}.{packet[12]}" 
    parsed_data['RptMaker'] = packet[14]
    parsed_data['DU_SU_Status'] = packet[15]
    parsed_data['Reserved0_1'] = packet[16]
    parsed_data['StatusPollingUnit'] = packet[17]
    parsed_data['RtpKind'] = packet[18]
    parsed_data['Reserved0'] = packet[19]
    parsed_data['StaMuAlarm'] = list(packet[20:32])
    
    # 알람 비트 매핑 정의
    alarm_bit_map = [
        {'bit': 1,  'id': 'alarm_dc'},
        {'bit': 2,  'id': 'alarm_ac'},
        {'bit': 3,  'id': 'alarm_temp'},
        {'bit': 4,  'id': 'alarm_bat'},
        {'bit': 49, 'id': 'alarm_fpga_link'},
        {'bit': 53, 'id': 'alarm_if_pll'},
        {'bit': 54, 'id': 'alarm_sync_pll'},
        {'bit': 52, 'id': 'alarm_tsync_link'},  # 비트 51 → 52로 수정
        {'bit': 66, 'id': 'alarm_decoding'},
        {'bit': 70, 'id': 'alarm_aa_link'}
    ]
    
    # 알람 비트 추출 함수
    def get_alarm_bit(alarm_bytes, bit_position):
        byte_index = (bit_position - 1) // 8
        bit_in_byte = (bit_position - 1) % 8
        if byte_index < len(alarm_bytes):
            return (alarm_bytes[byte_index] >> bit_in_byte) & 1
        return 0
    
    # 각 알람 비트 상태 추출
    alarm_status = {}
    for alarm in alarm_bit_map:
        alarm_status[alarm['id']] = get_alarm_bit(packet[20:32], alarm['bit'])
    
    parsed_data['AlarmStatus'] = alarm_status
    
    # ALA2 링크 알람 비트 추출 (packet[21]의 비트 0~3)
    ala2_link_alarms = {
        'ALA2_SU1_LINK_ALARM': (packet[21] >> 0) & 1,  # 비트 0
        'ALA2_SU2_LINK_ALARM': (packet[21] >> 1) & 1,  # 비트 1
        'ALA2_SU3_LINK_ALARM': (packet[21] >> 2) & 1,  # 비트 2
        'ALA2_SU4_LINK_ALARM': (packet[21] >> 3) & 1   # 비트 3
    }
    parsed_data['ALA2_Link_Alarms'] = ala2_link_alarms
    parsed_data['SuLinkFail'] = packet[32:44]
    # SuLinkFail에서 1비트씩 추출 - SU1~SU4만
    su_link_fail_bits = {
        'SU1_LINK_FAIL': (packet[32] >> 0) & 1,  # 비트 0
        'SU2_LINK_FAIL': (packet[32] >> 1) & 1,  # 비트 1
        'SU3_LINK_FAIL': (packet[32] >> 2) & 1,  # 비트 2
        'SU4_LINK_FAIL': (packet[32] >> 3) & 1   # 비트 3
        #추후 SU5, SU6 추가 해야할수도 있음
    }
    parsed_data['SuLinkFailBits'] = su_link_fail_bits
    parsed_data['SuSumAlarm'] = packet[44:56]
    parsed_data['SuRptAlarm'] = packet[56:68] 
    parsed_data['StsApiVenderFreq'] = struct.unpack('<I', bytes([packet[68], packet[69], packet[70], packet[71]]))[0]
    parsed_data['System_Year'] = '.'.join(['{:02d}'.format((packet[72] << 8) | packet[73]), '{:02d}'.format(packet[74]), '{:02d}'.format(packet[75])])
    parsed_data['System_hour'] = ':'.join(['{:02d}'.format(packet[76]), '{:02d}'.format(packet[77]), '{:02d}'.format(packet[78])])
    parsed_data['SysTemper'] = packet[79]
    parsed_data['PackSendCount'] = packet[80:120]
    parsed_data['PackErrorCount'] = packet[120:160]
    parsed_data['FPGA_Boot_Status'] = packet[160]
    parsed_data['FPGA_Init_Status'] = packet[161]
    parsed_data['Beam_Scan_Status'] = packet[162]
    parsed_data['DU_SumAlarmStatus'] = packet[163]
    parsed_data['ALC_Atten_DL0_SISO'] = struct.unpack('<h', bytes([packet[164], packet[165]]))[0]
    parsed_data['ALC_Atten_DL1_MIMO'] = struct.unpack('<h', bytes([packet[166], packet[167]]))[0]
    parsed_data['ALC_Atten_UL0_SISO'] = struct.unpack('<h', bytes([packet[168], packet[169]]))[0]
    parsed_data['ALC_Atten_UL1_MIMO'] = struct.unpack('<h', bytes([packet[170], packet[171]]))[0]
    # SISO/MIMO OPTIC DET (0.1dBm 단위로 변환)
    parsed_data['LD1_DET_DL0_SISO'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[172], packet[173]]))[0])
    parsed_data['LD2_DET_DL1_MIMO'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[174], packet[175]]))[0])
    parsed_data['PD1_DET_UL0_SISO'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[176], packet[177]]))[0])
    parsed_data['PD2_DET_UL1_MIMO'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[178], packet[179]]))[0])
    # SISO/MIMO RF DET (0.1dBm 단위로 변환)
    parsed_data['SISO_RF_DET_DL0_OUT'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[180], packet[181]]))[0])
    parsed_data['SISO_RF_DET_UL0_OUT'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[182], packet[183]]))[0])
    parsed_data['MIMO_RF_DET_DL1_OUT'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[184], packet[185]]))[0])
    parsed_data['MIMO_RF_DET_UL1_OUT'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[186], packet[187]]))[0])
    parsed_data['LD3_DET_DL0_SISO'] = struct.unpack('<h', bytes([packet[188], packet[189]]))[0]
    parsed_data['LD4_DET_DL1_MIMO'] = struct.unpack('<h', bytes([packet[190], packet[191]]))[0]
    parsed_data['PD3_DET_UL0_SISO'] = struct.unpack('<h', bytes([packet[192], packet[193]]))[0]
    parsed_data['PD4_DET_UL1_MIMO'] = struct.unpack('<h', bytes([packet[194], packet[195]]))[0]
    parsed_data['SuModeStatus'] = packet[196]
    parsed_data['SdStatusSiso'] = packet[197]
    parsed_data['SdStatusMimo'] = packet[198]
    parsed_data['Reserved3'] = packet[199:220] 
    #MVBX 상태
    parsed_data['FPGA_Ver'] = '.'.join([str(packet[220]), str(packet[221]), str(packet[222])])
    parsed_data['ApiOldNewVer'] = packet[223]
    parsed_data['Reserved3p1'] = packet[224:232] 
    parsed_data['Gumstick_Ver'] = '.'.join([str(packet[232]), str(packet[233]), str(packet[234])])
    parsed_data['SyncStatus'] = packet[235]
    parsed_data['TryBeamScanCont'] = struct.unpack('<h', bytes([packet[236], packet[237]]))[0]
    parsed_data['Reserved4'] = packet[238:244]
    parsed_data['MVBX_pci'] = struct.unpack('<h', bytes([packet[244], packet[245]]))[0]
    parsed_data['MVBX_ssb'] = struct.unpack('<h', bytes([packet[246], packet[247]]))[0]
    parsed_data['MVBX_rsrp'] = f"{struct.unpack('<f', bytes(packet[248:252]))[0]:.2f} [dBm]"
    parsed_data['MVBX_snr'] = f"{struct.unpack('<f', bytes(packet[252:256]))[0]:.2f} [dB]"
    parsed_data['MVBX_BeamInfo_beamId1'] = struct.unpack('<h', bytes([packet[256], packet[257]]))[0]
    parsed_data['MVBX_BeamInfo_beamId2'] = struct.unpack('<h', bytes([packet[258], packet[259]]))[0]
    parsed_data['MVBX_BeamInfo_beamId3'] = struct.unpack('<h', bytes([packet[260], packet[261]]))[0]
    parsed_data['MVBX_BeamInfo_beamId4'] = struct.unpack('<h', bytes([packet[262], packet[263]]))[0]
    parsed_data['MVBX_BeamInfo_pci1'] = struct.unpack('<h', bytes([packet[264], packet[265]]))[0]
    parsed_data['MVBX_BeamInfo_pci2'] = struct.unpack('<h', bytes([packet[266], packet[267]]))[0]
    parsed_data['MVBX_BeamInfo_pci3'] = struct.unpack('<h', bytes([packet[268], packet[269]]))[0]
    parsed_data['MVBX_BeamInfo_pci4'] = struct.unpack('<h', bytes([packet[270], packet[271]]))[0]
    parsed_data['MVBX_BeamInfo_ssbldx1'] = struct.unpack('<I', bytes([packet[272], packet[273], packet[274], packet[275]]))[0]
    parsed_data['MVBX_BeamInfo_ssbldx2'] = struct.unpack('<I', bytes([packet[276], packet[277], packet[278], packet[279]]))[0]
    parsed_data['MVBX_BeamInfo_ssbldx3'] = struct.unpack('<I', bytes([packet[280], packet[281], packet[282], packet[283]]))[0]
    parsed_data['MVBX_BeamInfo_ssbldx4'] = struct.unpack('<I', bytes([packet[284], packet[285], packet[286], packet[287]]))[0]
    parsed_data['MVBX_BeamInfo_energy1'] = struct.unpack('<I', bytes([packet[288], packet[289], packet[290], packet[291]]))[0]
    parsed_data['MVBX_BeamInfo_energy2'] = struct.unpack('<I', bytes([packet[292], packet[293], packet[294], packet[295]]))[0]
    parsed_data['MVBX_BeamInfo_energy3'] = struct.unpack('<I', bytes([packet[296], packet[297], packet[298], packet[299]]))[0]
    parsed_data['MVBX_BeamInfo_energy4'] = struct.unpack('<I', bytes([packet[300], packet[301], packet[302], packet[303]]))[0]
    parsed_data['MVBX_BeamInfo_psstype1'] = struct.unpack('<I', bytes([packet[304], packet[305], packet[306], packet[307]]))[0]
    parsed_data['MVBX_BeamInfo_psstype2'] = struct.unpack('<I', bytes([packet[308], packet[309], packet[310], packet[311]]))[0]
    parsed_data['MVBX_BeamInfo_psstype3'] = struct.unpack('<I', bytes([packet[312], packet[313], packet[314], packet[315]]))[0]
    parsed_data['MVBX_BeamInfo_psstype4'] = struct.unpack('<I', bytes([packet[316], packet[317], packet[318], packet[319]]))[0]
    # SNR 값 처리 (소수점 2자리, -999이면 "- - -")
    snr1 = struct.unpack('<f', bytes(packet[320:324]))[0]
    parsed_data['MVBX_BeamInfo_snr1'] = "- - -" if snr1 == -999 else f"{snr1:.2f}"
    
    snr2 = struct.unpack('<f', bytes(packet[324:328]))[0]
    parsed_data['MVBX_BeamInfo_snr2'] = "- - -" if snr2 == -999 else f"{snr2:.2f}"
    
    snr3 = struct.unpack('<f', bytes(packet[328:332]))[0]
    parsed_data['MVBX_BeamInfo_snr3'] = "- - -" if snr3 == -999 else f"{snr3:.2f}"
    
    snr4 = struct.unpack('<f', bytes(packet[332:336]))[0]
    parsed_data['MVBX_BeamInfo_snr4'] = "- - -" if snr4 == -999 else f"{snr4:.2f}"
    
    # RSRP 값 처리 (소수점 2자리, -999이면 "- - -")
    rsrp1 = struct.unpack('<f', bytes(packet[336:340]))[0]
    parsed_data['MVBX_BeamInfo_rsrp1'] = "- - -" if rsrp1 == -999 else f"{rsrp1:.2f}"
    
    rsrp2 = struct.unpack('<f', bytes(packet[340:344]))[0]
    parsed_data['MVBX_BeamInfo_rsrp2'] = "- - -" if rsrp2 == -999 else f"{rsrp2:.2f}"
    
    rsrp3 = struct.unpack('<f', bytes(packet[344:348]))[0]
    parsed_data['MVBX_BeamInfo_rsrp3'] = "- - -" if rsrp3 == -999 else f"{rsrp3:.2f}"
    
    rsrp4 = struct.unpack('<f', bytes(packet[348:352]))[0]
    parsed_data['MVBX_BeamInfo_rsrp4'] = "- - -" if rsrp4 == -999 else f"{rsrp4:.2f}"
    parsed_data['pss_pulse_count'] = struct.unpack('<I', bytes([packet[352], packet[353], packet[354], packet[355]]))[0]
    parsed_data['decoded_ssb_count'] = struct.unpack('<I', bytes([packet[356], packet[357], packet[358], packet[359]]))[0]
    parsed_data['decoded_ssb_no_error_count'] = struct.unpack('<I', bytes([packet[360], packet[361], packet[362], packet[363]]))[0]
    parsed_data['LicStatus'] = packet[364]
    parsed_data['LicStartDateMonth'] = packet[365]
    parsed_data['LicStartDateDay'] = packet[366]
    parsed_data['LicStopDateMonth'] = packet[367]
    parsed_data['LicStopDateDay'] = packet[368]
    parsed_data['Reserved4_new'] = packet[369:412]
    # Modem 상태
    parsed_data['ModRsrp'] = struct.unpack('<h', bytes([packet[412], packet[413]]))[0]
    parsed_data['ModRsrq'] = struct.unpack('<h', bytes([packet[414], packet[415]]))[0]
    parsed_data['InitTemper'] = packet[416]
    parsed_data['ModVersion'] = f"{packet[417] / 100:.2f}"
    parsed_data['ModLanUseMode'] = packet[418]
    parsed_data['ModPci'] = packet[419]
    parsed_data['SU_DlIsoAtten_SISO'] = packet[420]
    parsed_data['SU_DlIsoAtten_MIMO'] = packet[421]
    parsed_data['SU_UlIsoAtten_SISO'] = packet[422]
    parsed_data['SU_UlIsoAtten_MIMO'] = packet[423]
    parsed_data['SU_ISO_SATUS'] = packet[424:428]
    
    parsed_data['DU_ISO_STATUS'] = packet[428]
    
    parsed_data['ModStatus'] = packet[429]
    parsed_data['ModSinr'] = packet[430]
    parsed_data['Reserved6'] = packet[431]
    parsed_data['ModRssi'] = struct.unpack('<h', bytes([packet[432], packet[433]]))[0]
    parsed_data['ModTxPwr'] = struct.unpack('<h', bytes([packet[434], packet[435]]))[0]
    
    """
    # 16진수 바이트 배열을 10진수 문자열로 변환 (15자리만)
    def hex_bytes_to_decimal_string(byte_array):
        try:
            # 16진수 값을 10진수 문자열로 변환
            result = ''.join([f"{b:02d}" for b in byte_array if b != 0])
            # 15자리만 사용
            return result[:15] if result else "N/A"
        except:
            return "N/A"
    """
    
    # 널문자를 만날 때까지 문자열 변환
    def bytes_to_string_until_null(byte_array):
        result = ''
        for b in byte_array:
            if b == 0:  # 널문자 만나면 중단
                break
            result += chr(b)
        return result
    
    parsed_data['ModIMSINum'] = bytes_to_string_until_null(packet[436:452])
    parsed_data['ModIMEINum'] = bytes_to_string_until_null(packet[452:476])
    parsed_data['ModIpAddress'] =f"{packet[476]}.{packet[477]}.{packet[478]}.{packet[479]}"
    parsed_data['ModServerIpAddress'] = packet[480:484]
    parsed_data['ModPhonNumber'] = bytes_to_string_until_null(packet[484:495])
    parsed_data['ModEmsFwVer'] = f"{struct.unpack('<h', bytes([packet[496], packet[497]]))[0] / 100:.2f}"
    parsed_data['Gumstick_CurTemper'] = struct.unpack('<h', bytes([packet[498], packet[499]]))[0]
    parsed_data['Gumstick_StartTemper'] = struct.unpack('<h', bytes([packet[500], packet[501]]))[0]
    parsed_data['DlTemperCompensation'] = packet[502]
    parsed_data['UlTemperCompensation'] = packet[503]
    parsed_data['PllRelockCount'] = struct.unpack('<h', bytes([packet[504], packet[505]]))[0]
    parsed_data['DecodedRate'] = packet[506]
    parsed_data['Reserved6p1'] = packet[507]
    parsed_data['DsOutputPower_SISO'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[508], packet[509]]))[0])
    parsed_data['EmsModemReset'] = packet[510]
    parsed_data['Reserved6p2'] = packet[511]
    agc_input_raw = struct.unpack('<h', bytes([packet[512], packet[513]]))[0]
    parsed_data['AGC_Input_Power'] = f"{agc_input_raw / 10:.1f}"
    parsed_data['DsOutputPower_MIMO'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[514], packet[515]]))[0])
    parsed_data['Actual_Orientation'] = struct.unpack('<h', bytes([packet[516], packet[517]]))[0]
    parsed_data['Actual_Tilt'] = struct.unpack('<h', bytes([packet[518], packet[519]]))[0]
    parsed_data['Reserved6p3'] = packet[520:576]
    #DU Control
    parsed_data['InitCheckNum'] = packet[576:580]
    parsed_data['ConMuFlag'] = packet[580:604]
    parsed_data['ConSysTime_Year'] = '.'.join(['{:02d}'.format((packet[604] << 8) | packet[605]), '{:02d}'.format(packet[606]), '{:02d}'.format(packet[607])])
    parsed_data['ConSysTime_hour'] = ':'.join(['{:02d}'.format(packet[608]), '{:02d}'.format(packet[609]), '{:02d}'.format(packet[610])])
    parsed_data['RptMakerCode'] = packet[611]
    parsed_data['SysTemperHighLvl'] = packet[612]
    parsed_data['SysTemperLowLvl'] = packet[613]
    parsed_data['SubInitCheckNum'] = packet[614]
    parsed_data['DebugMode'] = packet[615]
    parsed_data['SuEnableInfo'] = packet[616:628]
    # SU Enable Info 비트 추출 (packet[616]의 비트 0~3)
    su_enable_bits = {
        'SU1_ENABLE': (packet[616] >> 0) & 1,  # 비트 0
        'SU2_ENABLE': (packet[616] >> 1) & 1,  # 비트 1
        'SU3_ENABLE': (packet[616] >> 2) & 1,  # 비트 2
        'SU4_ENABLE': (packet[616] >> 3) & 1   # 비트 3
    }
    parsed_data['SuEnableBits'] = su_enable_bits
    

    parsed_data['MaskMuAlarm'] = list(packet[628:640])
    
    # packet[635]에서 0번째, 2번째, 5번째 비트 추출
    dl_alc_bits = {
        'SISO_MASK_DL_ALC': (packet[635] >> 0) & 1,  # 비트 0
        'MIMO_MASK_DL_ALC': (packet[635] >> 2) & 1,  # 비트 2
        'EMS_DU_Link_MASK': (packet[635] >> 5) & 1   # 비트 5
    }
    parsed_data['DL_ALC_Bits'] = dl_alc_bits

    # packet[634]에서 0번째, 1번째, 2번째, 3번째 비트 추출
    det_mask_bits = {
        'LD1_DET_DL0_SISO_MASK': (packet[634] >> 0) & 1,  # 비트 0
        'LD2_DET_DL1_MIMO_MASK': (packet[634] >> 1) & 1,  # 비트 1
        'PD1_DET_UL0_SISO_MASK': (packet[634] >> 2) & 1,  # 비트 2
        'PD2_DET_UL1_MIMO_MASK': (packet[634] >> 3) & 1   # 비트 3
    }
    parsed_data['DET_MASK_Bits'] = det_mask_bits

        # 알람 비트 매핑 정의
    alarm_mask_bit_map = [
        {'bit': 1,  'id': 'alarm_mask_madc'},
        {'bit': 2,  'id': 'alarm_mask_ac'},
        {'bit': 3,  'id': 'alarm_mask_temp'},
        {'bit': 4,  'id': 'alarm_mask_bat'},
        {'bit': 49, 'id': 'alarm_mask_fpga_link'},
        {'bit': 53, 'id': 'alarm_mask_if_pll'},
        {'bit': 54, 'id': 'alarm_mask_sync_pll'},
        {'bit': 52, 'id': 'alarm_mask_tsync_link'},  # 비트 51 → 52로 수정
        {'bit': 66, 'id': 'alarm_mask_decoding'},
        {'bit': 70, 'id': 'alarm_mask_aa_link'}
    ]

    # Mask 알람 비트 추출 함수
    def get_mask_alarm_bit(mask_bytes, bit_position):
        byte_index = (bit_position - 1) // 8
        bit_in_byte = (bit_position - 1) % 8
        if byte_index < len(mask_bytes):
            return (mask_bytes[byte_index] >> bit_in_byte) & 1
        return 0
    
    # 각 Mask 알람 비트 상태 추출
    mask_alarm_status = {}
    for alarm in alarm_mask_bit_map:
        mask_alarm_status[alarm['id']] = get_mask_alarm_bit(packet[628:640], alarm['bit'])
    
    parsed_data['MaskAlarmStatus'] = mask_alarm_status

    



    parsed_data['MaskSuLinkFail'] = packet[640:652]

    # SuLinkFail에서 1비트씩 추출 - SU1~SU4만
    su_mask_link_fail_bits = {
        'SU1_MASK_LINK_FAIL': (packet[640] >> 0) & 1,  # 비트 0
        'SU2_MASK_LINK_FAIL': (packet[640] >> 1) & 1,  # 비트 1
        'SU3_MASK_LINK_FAIL': (packet[640] >> 2) & 1,  # 비트 2
        'SU4_MASK_LINK_FAIL': (packet[640] >> 3) & 1   # 비트 3
        #추후 SU5, SU6 추가 해야할수도 있음
    }
    parsed_data['MaskSuLinkFail'] = su_mask_link_fail_bits
    
    parsed_data['MaskSuSumAlarm'] = packet[652:664]
    parsed_data['MaskSuRptAlarm'] = packet[664:676]
    parsed_data['ConEmsModemReset'] = packet[676]
    parsed_data['DownloadPath_GuiOrEms'] = packet[677]
    parsed_data['PollingTime'] = struct.unpack('<H', bytes([packet[678], packet[679]]))[0]
    parsed_data['ApiInitMode'] = packet[680]
    parsed_data['AttTestMode'] = packet[681]
    parsed_data['SuId'] = packet[682]
    parsed_data['DL_UL_TEST'] = packet[683]
    parsed_data['LocalInfo'] = packet[684:744]
    parsed_data['SuOpticalEnStatus'] = packet[744]
    parsed_data['PreStaAlarm'] = packet[745:757] 
    parsed_data['Mu_Su_Buadrate'] = packet[757]
    parsed_data['ModemOnOff'] = packet[758]
    parsed_data['RsrpOffset'] = packet[759]
    parsed_data['SuOpticalEnStatus'] = packet[744]
    parsed_data['PreStaAlarm'] = packet[745:757] # Changed to 745:757
    parsed_data['Mu_Su_Buadrate'] = packet[757]
    parsed_data['ModemOnOff'] = packet[758]
    parsed_data['RsrpOffset'] = packet[759]
    #RF 제어
    parsed_data['ALC_DL0_SISO_Mode'] = packet[760]
    parsed_data['ALC_DL1_MIMO_Mode'] = packet[761]
    parsed_data['ALC_UL0_SISO_Mode'] = packet[762]
    parsed_data['ALC_UL1_MIMO_Mode'] = packet[763]
    # ALC Level (1dBm 단위)
    parsed_data['ALC_DL0_SISO_Level'] = convert_to_1dbm(struct.unpack('<h', bytes([packet[764], packet[765]]))[0])
    parsed_data['ALC_DL1_MIMO_Level'] = convert_to_1dbm(struct.unpack('<h', bytes([packet[766], packet[767]]))[0])
    parsed_data['ALC_UL0_SISO_Level'] = convert_to_1dbm(struct.unpack('<h', bytes([packet[768], packet[769]]))[0])
    parsed_data['ALC_UL1_MIMO_Level'] = convert_to_1dbm(struct.unpack('<h', bytes([packet[770], packet[771]]))[0])
    parsed_data['SISO_RF_DET_DL0_OUT_High'] = struct.unpack('<h', bytes([packet[772], packet[773]]))[0]
    parsed_data['SISO_RF_DET_UL0_OUT_High'] = struct.unpack('<h', bytes([packet[774], packet[775]]))[0]
    parsed_data['MIMO_RF_DET_DL1_OUT_High'] = struct.unpack('<h', bytes([packet[776], packet[777]]))[0]
    parsed_data['MIMO_RF_DET_UL1_OUT_High'] = struct.unpack('<h', bytes([packet[778], packet[779]]))[0]
    # SISO/MIMO OPTIC DET Low (0.1dBm 단위로 변환)
    parsed_data['LD1_DET_DL0_SISO_Low'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[780], packet[781]]))[0])
    parsed_data['LD2_DET_DL1_MIMO_Low'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[782], packet[783]]))[0])
    parsed_data['PD1_DET_UL0_SISO_Low'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[784], packet[785]]))[0])
    parsed_data['PD2_DET_UL1_MIMO_Low'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[786], packet[787]]))[0])
    parsed_data['LD3_DET_DL0_SISO_Low'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[788], packet[789]]))[0])
    parsed_data['LD4_DET_DL1_MIMO_Low'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[790], packet[791]]))[0])
    parsed_data['PD3_DET_UL0_SISO_Low'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[792], packet[793]]))[0])
    parsed_data['PD4_DET_UL1_MIMO_Low'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[794], packet[795]]))[0])
    parsed_data['LD1_DET_DL0_SISO_Offset'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[796], packet[797]]))[0])
    parsed_data['LD2_DET_DL1_MIMO_Offset'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[798], packet[799]]))[0])
    parsed_data['PD1_DET_UL0_SISO_Offset'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[800], packet[801]]))[0])
    parsed_data['PD2_DET_UL1_MIMO_Offset'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[802], packet[803]]))[0])
    parsed_data['LD3_DET_DL0_SISO_Offset'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[804], packet[805]]))[0])
    parsed_data['LD4_DET_DL1_MIMO_Offset'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[806], packet[807]]))[0])
    parsed_data['PD3_DET_UL0_SISO_Offset'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[808], packet[809]]))[0])
    parsed_data['PD4_DET_UL1_MIMO_Offset'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[810], packet[811]]))[0])
    # DU ATT (0.5dB 단위로 변환)
    parsed_data['DU_DlManualAtten_SISO'] = convert_att_4_to_2(packet[812])
    parsed_data['DU_DlSubAtten_SISO'] = convert_att_4_to_2(packet[813])
    parsed_data['DU_DlManualAtten_MIMO'] = convert_att_4_to_2(packet[814])
    parsed_data['DU_DlSubAtten_MIMO'] = convert_att_4_to_2(packet[815])
    parsed_data['DU_UlManualAtten_SISO'] = convert_att_4_to_2(packet[816])
    parsed_data['DU_UlSubAtten_SISO'] = convert_att_4_to_2(packet[817])
    parsed_data['DU_UlIsoAtten_SISO'] = convert_iso_att(packet[818])
    parsed_data['DU_UlManualAtten_MIMO'] = convert_att_4_to_2(packet[819])
    parsed_data['DU_UlSubAtten_MIMO'] = convert_att_4_to_2(packet[820])
    parsed_data['DU_UlIsoAtten_MIMO'] = convert_iso_att(packet[821])
    parsed_data['SU_DlManualAtten_SISO'] = packet[822]
    parsed_data['SU_DlSubAtten_SISO'] = packet[823]
    parsed_data['SU_DlManualAtten_MIMO'] = packet[824]
    parsed_data['SU_DlSubAtten_MIMO'] = packet[825]
    parsed_data['SU_UlManualAtten_SISO'] = packet[826]
    parsed_data['SU_UlSubAtten_SISO'] = packet[827]
    parsed_data['SU_UlManualAtten_MIMO'] = packet[828]
    parsed_data['SU_UlSubAtten_MIMO'] = packet[829]
    parsed_data['LicPassword'] = struct.unpack('<h', bytes([packet[830], packet[831]]))[0]
    parsed_data['DL_OutputOffset_SISO'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[832], packet[833]]))[0])
    parsed_data['DL_OutputOffset_MIMO'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[834], packet[835]]))[0])
    parsed_data['UL_InputOffset_SISO'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[836], packet[837]]))[0])
    parsed_data['UL_InputOffset_MIMO'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[838], packet[839]]))[0])
    parsed_data['SU_UlCasSisoAtten_SISO'] = packet[840]
    parsed_data['SU_UlCasSisoAtten_MIMO'] = packet[841]
    parsed_data['SdOnOffSiso'] = packet[842]
    parsed_data['SdOnOffMimo'] = packet[843]
    parsed_data['DuFixBeam'] = packet[844]
    parsed_data['Reserved4_Local'] = packet[845:852]
    parsed_data['Dl_Siso_Att_Test'] = convert_att_test(struct.unpack('<h', bytes([packet[852], packet[853]]))[0])
    parsed_data['Dl_Mimo_Att_Test'] = convert_att_test(struct.unpack('<h', bytes([packet[854], packet[855]]))[0])
    parsed_data['Ul_Siso_Att_Test'] = convert_att_test(struct.unpack('<h', bytes([packet[856], packet[857]]))[0])
    parsed_data['Ul_Mimo_Att_Test'] = convert_att_test(struct.unpack('<h', bytes([packet[858], packet[859]]))[0])
    parsed_data['Reserved10p1'] = packet[860:892]
    # MVBX 제어
    parsed_data['Mvbx_BeamSet'] = packet[892]
    parsed_data['InstallUseMode'] = packet[893]
    parsed_data['Reserved14'] = packet[894:896]
    parsed_data['Mvbx_FpagImageSize'] = packet[896:900]
    parsed_data['Mvbx_FpagImageStartAddressOffset'] = packet[900:904]
    parsed_data['Reserved15'] = packet[904:920]
    parsed_data['FpgaWriteAddress'] = packet[920:922]
    parsed_data['FpgaWriteData'] = packet[922:924]
    parsed_data['FpgaReadAddress'] = packet[924:926]
    parsed_data['FpgaReadData'] = packet[926:928]
    parsed_data['Reserved31'] = packet[928:940]
    parsed_data['Mvbx_TddSignalMode'] = packet[940]
    parsed_data['Mvbx_RsAgcThreshold'] = packet[941]
    parsed_data['Mvbx_RsAgcMode'] = packet[942]
    parsed_data['Reserved32'] = packet[943]
    parsed_data['Mvbx_Mv2853TxGainSiso'] = packet[944]
    parsed_data['Mvbx_Mv2853RxGainSiso'] = packet[945]
    parsed_data['Mvbx_Mv2850TxGainSiso'] = packet[946]
    parsed_data['Mvbx_Mv2850RxGainSiso'] = packet[947]
    parsed_data['Mvbx_Mv2853TxGainMimo'] = packet[948]
    parsed_data['Mvbx_Mv2853RxGainMimo'] = packet[949]
    parsed_data['Mvbx_Mv2850TxGainMimo'] = packet[950]
    parsed_data['Mvbx_Mv2850RxGainMimo'] = packet[951]
    parsed_data['Mvbx_TxGainSetSiso'] = packet[952]
    parsed_data['Mvbx_RxGainSetSiso'] = packet[953]
    parsed_data['Mvbx_TxGainSetMiso'] = packet[954]
    parsed_data['Mvbx_RxGainSetMiso'] = packet[955]
    parsed_data['beam_info_pss_type'] = struct.unpack('<I', bytes([packet[956], packet[957], packet[958], packet[959]]))[0]
    parsed_data['beam_info_adc_sel'] = struct.unpack('<I', bytes([packet[960], packet[961], packet[962], packet[963]]))[0]
    parsed_data['beam_info_spg '] = struct.unpack('<I', bytes([packet[964], packet[965], packet[966], packet[967]]))[0]
    parsed_data['beam_info_ssbIdx'] = struct.unpack('<I', bytes([packet[968], packet[969], packet[970], packet[971]]))[0]
    parsed_data['beam_info_beamID'] = struct.unpack('<h', bytes([packet[972], packet[973]]))[0]
    parsed_data['Reserved34'] = struct.unpack('<h', bytes([packet[974], packet[975]]))[0]
    parsed_data['beam_info_energy'] = struct.unpack('<I', bytes([packet[976], packet[977], packet[978], packet[979]]))[0]
    parsed_data['beam_info_rsrp '] = struct.unpack('<I', bytes([packet[980], packet[981], packet[982], packet[983]]))[0]
    parsed_data['beam_info_snr'] = struct.unpack('<I', bytes([packet[984], packet[985], packet[986], packet[987]]))[0]
    parsed_data['PllSet'] = struct.unpack('<I', bytes([packet[988], packet[989], packet[990], packet[991]]))[0]
    parsed_data['IsoMeasSet'] = packet[992]
    parsed_data['SuGsOnOff'] = packet[993]
    parsed_data['SuIsoAttSet'] = packet[994]
    parsed_data['GumStick_OnOff'] = packet[995]
    parsed_data['BeamScan_OnOff'] = packet[996]
    parsed_data['IsoDetectMode'] = packet[997]
    parsed_data['ApiLogLevel'] = packet[998]
    parsed_data['ApiAdcSel'] = packet[999]
    parsed_data['ApiSyncPathGain'] = packet[1000]
    parsed_data['ApiDuTimeAdvance'] = packet[1001]
    parsed_data['ApiSuTimeAdvance'] = packet[1002]
    parsed_data['TemperCompensationMode'] = packet[1003]
    parsed_data['ApiVenderFreq'] = struct.unpack('<I', bytes([packet[1004], packet[1005], packet[1006], packet[1007]]))[0]
    parsed_data['ApiGsOutputPowerOffsetSiso'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[1008], packet[1009]]))[0])
    parsed_data['BeamAntSelect'] = packet[1010]
    parsed_data['DecodeRecoveryFuncOnOff'] = packet[1011]
    parsed_data['gNB_ScanOnOff'] = packet[1012]
    parsed_data['SuEndMode'] = packet[1013]
    parsed_data['ApiGsOutputPowerOffsetMimo'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[1014], packet[1015]]))[0])
    parsed_data['gNB_Vendor'] = packet[1016]
    parsed_data['Gs_Gain_Siso'] = packet[1017]
    parsed_data['Gs_Gain_Mimo'] = packet[1018]
    parsed_data['ApiInitRetryMode'] = packet[1019]
    parsed_data['Orientation'] = f"{struct.unpack('<h', bytes([packet[1020], packet[1021]]))[0]:.3f}"
    parsed_data['Tilt'] = f"{struct.unpack('<h', bytes([packet[1022], packet[1023]]))[0]:.3f}"
    parsed_data['GS_AttenOffset_DL_Siso'] = struct.unpack('<b', bytes([packet[1024]]))[0]
    parsed_data['GS_AttenOffset_DL_Mimo'] = struct.unpack('<b', bytes([packet[1025]]))[0]
    parsed_data['GS_AttenOffset_UL_Siso'] = struct.unpack('<b', bytes([packet[1026]]))[0]
    parsed_data['GS_AttenOffset_UL_Mimo'] = struct.unpack('<b', bytes([packet[1027]]))[0]
    parsed_data['ConSerialNum'] = ''.join([chr(b) for b in packet[1028:1044] if b != 0])
    parsed_data['AomTemperConperMode'] = packet[1044]
    parsed_data['GS_AttenOffset_30by15_DL_Siso'] = packet[1045]
    parsed_data['GS_AttenOffset_30by30_DL_Siso'] = packet[1046]
    parsed_data['GS_AttenOffset_60by15_DL_Siso'] = packet[1047]
    parsed_data['GS_AttenOffset_60by30_DL_Siso'] = packet[1048]
    parsed_data['GS_AttenOffset_60by60_DL_Siso'] = packet[1049]
    parsed_data['GS_AttenOffset_30by15_DL_Mimo'] = packet[1050]
    parsed_data['GS_AttenOffset_30by30_DL_Mimo'] = packet[1051]
    parsed_data['GS_AttenOffset_60by15_DL_Mimo'] = packet[1052]
    parsed_data['GS_AttenOffset_60by30_DL_Mimo'] = packet[1053]
    parsed_data['GS_AttenOffset_60by60_DL_Mimo'] = packet[1054]
    parsed_data['GS_AttenOffset_30by15_UL_Siso'] = packet[1055]
    parsed_data['GS_AttenOffset_30by30_UL_Siso'] = packet[1056]
    parsed_data['GS_AttenOffset_60by15_UL_Siso'] = packet[1057]
    parsed_data['GS_AttenOffset_60by30_UL_Siso'] = packet[1058]
    parsed_data['GS_AttenOffset_60by60_UL_Siso'] = packet[1059]
    parsed_data['GS_AttenOffset_30by15_UL_Mimo'] = packet[1060]
    parsed_data['GS_AttenOffset_30by30_UL_Mimo'] = packet[1061]
    parsed_data['GS_AttenOffset_60by15_UL_Mimo'] = packet[1062]
    parsed_data['GS_AttenOffset_60by30_UL_Mimo'] = packet[1063]
    parsed_data['GS_AttenOffset_60by60_UL_Mimo'] = packet[1064]
    parsed_data['Reserved41'] = packet[1065:1089]
    parsed_data['LowRsrpStillTime'] = packet[1089]
    parsed_data['LowRsrpLevel'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[1090], packet[1091]]))[0])
    parsed_data['SU_DlCasSisoAtten_SISO'] = packet[1092]
    parsed_data['SU_DlCasSisoAtten_MIMO'] = packet[1093]
    parsed_data['SU_DlCasSisoAttenTest_SISO'] = packet[1094]
    parsed_data['SU_DlCasSisoAttenTest_MIMO'] = packet[1095]
    parsed_data['SU_UlCasSisoAttenTest_SISO'] = packet[1096]
    parsed_data['SU_UlCasSisoAttenTest_MIMO'] = packet[1097]
    parsed_data['Reserved41p1'] = packet[1098:1101]
    parsed_data['PciResetOnOff'] = packet[1101]
    parsed_data['PciNo'] = struct.unpack('<h', bytes([packet[1102], packet[1103]]))[0]
    parsed_data['PciTime'] = packet[1104]
    parsed_data['Reserved42'] = packet[1105:1112]
    # Reserved42 감지 시 RX 박스 끄기
    socketio.emit("rx_off")

    return parsed_data

def parse_AllStatusPacket2(packet):


    parsed_data = {}
    
    # 단위 변환 함수들
    def convert_to_01dbm(raw_value):
        """0.1dBm 단위로 변환 (예: -517 → -51.7 dBm)"""
        return round(raw_value / 10.0, 1)
    
    def convert_att_4_to_2(raw_value):
        """ATT 변환 (4→2dB, Step: 0.5dB)"""
        return raw_value * 0.5
    
    def convert_to_1dbm(raw_value):
        """1dBm 단위로 변환"""
        return raw_value
    
    def convert_iso_att(raw_value):
        """ISO ATT 변환 (4→2dB, Step: 0.5dB, Range: 0~20dB)"""
        return raw_value * 0.5
    
    def convert_att_test(raw_value):
        """ATT Test 변환 (50: 5dB, 0.5dB 단위, Range: 0~30dB)"""
        return raw_value * 0.5
    
    def convert_polling_time(raw_value):
        """Polling Time 변환 (2바이트 uint, 범위: 100~5,000ms)"""
        return raw_value  # 이미 ms 단위로 저장되어 있음
    
    #su1 상태
    parsed_data['Rcv_Main_Sys'] = packet[0]
    # Rcv_Main_Sys 감지 시 RX 박스 켜기
    socketio.emit("rx_on")
    parsed_data['Rcv_Sub_Sys'] = packet[1]
    parsed_data['Rcv_Object'] = packet[2]
    parsed_data['Trans_Main_Sys'] = packet[3]
    # Trans_Main_Sys 감지 시 TX 박스 토글 (1이면 켜기, 0이면 끄기)
    if packet[3] != 0:
        socketio.emit("tx_on")
    else:
        socketio.emit("tx_off")
    parsed_data['Trans_Sub_Sys'] = packet[4]
    parsed_data['Trans_Object'] = packet[5]
    parsed_data['CMD'] = packet[6]
    parsed_data['EQUIP_TYPE'] = packet[7]
    parsed_data['RESERVED'] = packet[8:10]
    parsed_data['SubData_Size'] = struct.unpack('<h', bytes([packet[10], packet[11]]))[0]
    parsed_data['McuSwVer'] = f"{packet[13]}.{packet[12]}" 
    parsed_data['RptMaker'] = packet[14]
    parsed_data['DU_SU_Status'] = packet[15]
    parsed_data['Reserved0_1'] = packet[16]
    parsed_data['StatusPollingUnit'] = packet[17]
    parsed_data['RtpKind'] = packet[18]
    parsed_data['Reserved0'] = packet[19]
    parsed_data['StaMuAlarm'] = list(packet[20:32])
    
    # 알람 비트 매핑 정의
    alarm_bit_map = [
        {'bit': 1,  'id': 'su1_alarm_dc'},
        {'bit': 2,  'id': 'su1_alarm_ac'},
        {'bit': 3,  'id': 'su1_alarm_temp'},
        {'bit': 4,  'id': 'su1_alarm_bat'},
        {'bit': 48, 'id': 'su1_alarm_du_link'},
        {'bit': 53, 'id': 'su1_alarm_if_pll'},
        {'bit': 52, 'id': 'su1_alarm_tsync_link'},  # 비트 51 → 52로 수정
        {'bit': 63, 'id': 'su1_alarm_ref_pll'},
        {'bit': 70, 'id': 'su1_alarm_aa_link'}
    ]
    
    # 알람 비트 추출 함수
    def get_alarm_bit(alarm_bytes, bit_position):
        byte_index = (bit_position - 1) // 8
        bit_in_byte = (bit_position - 1) % 8
        if byte_index < len(alarm_bytes):
            return (alarm_bytes[byte_index] >> bit_in_byte) & 1
        return 0
    
    # 각 알람 비트 상태 추출
    alarm_status = {}
    for alarm in alarm_bit_map:
        alarm_status[alarm['id']] = get_alarm_bit(packet[20:32], alarm['bit'])
    
    parsed_data['AlarmStatus'] = alarm_status
    
    # ALA2 링크 알람 비트 추출 (packet[21]의 비트 0~3)
    ala2_link_alarms = {
        'ALA2_SU1_LINK_ALARM': (packet[21] >> 0) & 1,  # 비트 0
        'ALA2_SU2_LINK_ALARM': (packet[21] >> 1) & 1,  # 비트 1
        'ALA2_SU3_LINK_ALARM': (packet[21] >> 2) & 1,  # 비트 2
        'ALA2_SU4_LINK_ALARM': (packet[21] >> 3) & 1   # 비트 3
    }
    parsed_data['ALA2_Link_Alarms'] = ala2_link_alarms
    parsed_data['SuLinkFail'] = packet[32:44]
    # SuLinkFail에서 1비트씩 추출 - SU1~SU4만
    su_link_fail_bits = {
        'SU1_LINK_FAIL': (packet[32] >> 0) & 1,  # 비트 0
        'SU2_LINK_FAIL': (packet[32] >> 1) & 1,  # 비트 1
        'SU3_LINK_FAIL': (packet[32] >> 2) & 1,  # 비트 2
        'SU4_LINK_FAIL': (packet[32] >> 3) & 1   # 비트 3
        #추후 SU5, SU6 추가 해야할수도 있음
    }
    parsed_data['SuLinkFailBits'] = su_link_fail_bits
    parsed_data['SuSumAlarm'] = packet[44:56]
    parsed_data['SuRptAlarm'] = packet[56:68] 
    parsed_data['StsApiVenderFreq'] = struct.unpack('<I', bytes([packet[68], packet[69], packet[70], packet[71]]))[0]
    parsed_data['System_Year'] = '.'.join(['{:02d}'.format((packet[72] << 8) | packet[73]), '{:02d}'.format(packet[74]), '{:02d}'.format(packet[75])])
    parsed_data['System_hour'] = ':'.join(['{:02d}'.format(packet[76]), '{:02d}'.format(packet[77]), '{:02d}'.format(packet[78])])
    parsed_data['SysTemper'] = packet[79]
    parsed_data['PackSendCount'] = packet[80:120]
    parsed_data['PackErrorCount'] = packet[120:160]
    parsed_data['FPGA_Boot_Status'] = packet[160]
    parsed_data['FPGA_Init_Status'] = packet[161]
    parsed_data['Beam_Scan_Status'] = packet[162]
    parsed_data['DU_SumAlarmStatus'] = packet[163]
    parsed_data['ALC_Atten_DL0_SISO'] = struct.unpack('<h', bytes([packet[164], packet[165]]))[0]
    parsed_data['ALC_Atten_DL1_MIMO'] = struct.unpack('<h', bytes([packet[166], packet[167]]))[0]
    parsed_data['ALC_Atten_UL0_SISO'] = struct.unpack('<h', bytes([packet[168], packet[169]]))[0]
    parsed_data['ALC_Atten_UL1_MIMO'] = struct.unpack('<h', bytes([packet[170], packet[171]]))[0]
    # SISO/MIMO OPTIC DET (0.1dBm 단위로 변환)
    parsed_data['LD1_DET_DL0_SISO'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[172], packet[173]]))[0])
    parsed_data['LD2_DET_DL1_MIMO'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[174], packet[175]]))[0])
    parsed_data['PD1_DET_UL0_SISO'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[176], packet[177]]))[0])
    parsed_data['PD2_DET_UL1_MIMO'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[178], packet[179]]))[0])
    # SISO/MIMO RF DET (0.1dBm 단위로 변환)
    parsed_data['SISO_RF_DET_DL0_OUT'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[180], packet[181]]))[0])
    parsed_data['SISO_RF_DET_UL0_OUT'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[182], packet[183]]))[0])
    parsed_data['MIMO_RF_DET_DL1_OUT'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[184], packet[185]]))[0])
    parsed_data['MIMO_RF_DET_UL1_OUT'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[186], packet[187]]))[0])
    parsed_data['LD3_DET_DL0_SISO'] = struct.unpack('<h', bytes([packet[188], packet[189]]))[0]
    parsed_data['LD4_DET_DL1_MIMO'] = struct.unpack('<h', bytes([packet[190], packet[191]]))[0]
    parsed_data['PD3_DET_UL0_SISO'] = struct.unpack('<h', bytes([packet[192], packet[193]]))[0]
    parsed_data['PD4_DET_UL1_MIMO'] = struct.unpack('<h', bytes([packet[194], packet[195]]))[0]
    parsed_data['SuModeStatus'] = packet[196]
    parsed_data['SdStatusSiso'] = packet[197]
    parsed_data['SdStatusMimo'] = packet[198]
    parsed_data['Reserved3'] = packet[199:220] 
    #MVBX 상태
    parsed_data['FPGA_Ver'] = '.'.join([str(packet[220]), str(packet[221]), str(packet[222])])
    parsed_data['ApiOldNewVer'] = packet[223]
    parsed_data['Reserved3p1'] = packet[224:232] 
    parsed_data['Gumstick_Ver'] = '.'.join([str(packet[232]), str(packet[233]), str(packet[234])])
    parsed_data['SyncStatus'] = packet[235]
    parsed_data['TryBeamScanCont'] = struct.unpack('<h', bytes([packet[236], packet[237]]))[0]
    parsed_data['Reserved4'] = packet[238:244]
    parsed_data['MVBX_pci'] = struct.unpack('<h', bytes([packet[244], packet[245]]))[0]
    parsed_data['MVBX_ssb'] = struct.unpack('<h', bytes([packet[246], packet[247]]))[0]
    parsed_data['MVBX_rsrp'] = f"{struct.unpack('<f', bytes(packet[248:252]))[0]:.2f} [dBm]"
    parsed_data['MVBX_snr'] = f"{struct.unpack('<f', bytes(packet[252:256]))[0]:.2f} [dB]"
    parsed_data['MVBX_BeamInfo_beamId1'] = struct.unpack('<h', bytes([packet[256], packet[257]]))[0]
    parsed_data['MVBX_BeamInfo_beamId2'] = struct.unpack('<h', bytes([packet[258], packet[259]]))[0]
    parsed_data['MVBX_BeamInfo_beamId3'] = struct.unpack('<h', bytes([packet[260], packet[261]]))[0]
    parsed_data['MVBX_BeamInfo_beamId4'] = struct.unpack('<h', bytes([packet[262], packet[263]]))[0]
    parsed_data['MVBX_BeamInfo_pci1'] = struct.unpack('<h', bytes([packet[264], packet[265]]))[0]
    parsed_data['MVBX_BeamInfo_pci2'] = struct.unpack('<h', bytes([packet[266], packet[267]]))[0]
    parsed_data['MVBX_BeamInfo_pci3'] = struct.unpack('<h', bytes([packet[268], packet[269]]))[0]
    parsed_data['MVBX_BeamInfo_pci4'] = struct.unpack('<h', bytes([packet[270], packet[271]]))[0]
    parsed_data['MVBX_BeamInfo_ssbldx1'] = struct.unpack('<I', bytes([packet[272], packet[273], packet[274], packet[275]]))[0]
    parsed_data['MVBX_BeamInfo_ssbldx2'] = struct.unpack('<I', bytes([packet[276], packet[277], packet[278], packet[279]]))[0]
    parsed_data['MVBX_BeamInfo_ssbldx3'] = struct.unpack('<I', bytes([packet[280], packet[281], packet[282], packet[283]]))[0]
    parsed_data['MVBX_BeamInfo_ssbldx4'] = struct.unpack('<I', bytes([packet[284], packet[285], packet[286], packet[287]]))[0]
    parsed_data['MVBX_BeamInfo_energy1'] = struct.unpack('<I', bytes([packet[288], packet[289], packet[290], packet[291]]))[0]
    parsed_data['MVBX_BeamInfo_energy2'] = struct.unpack('<I', bytes([packet[292], packet[293], packet[294], packet[295]]))[0]
    parsed_data['MVBX_BeamInfo_energy3'] = struct.unpack('<I', bytes([packet[296], packet[297], packet[298], packet[299]]))[0]
    parsed_data['MVBX_BeamInfo_energy4'] = struct.unpack('<I', bytes([packet[300], packet[301], packet[302], packet[303]]))[0]
    parsed_data['MVBX_BeamInfo_psstype1'] = struct.unpack('<I', bytes([packet[304], packet[305], packet[306], packet[307]]))[0]
    parsed_data['MVBX_BeamInfo_psstype2'] = struct.unpack('<I', bytes([packet[308], packet[309], packet[310], packet[311]]))[0]
    parsed_data['MVBX_BeamInfo_psstype3'] = struct.unpack('<I', bytes([packet[312], packet[313], packet[314], packet[315]]))[0]
    parsed_data['MVBX_BeamInfo_psstype4'] = struct.unpack('<I', bytes([packet[316], packet[317], packet[318], packet[319]]))[0]
    # SNR 값 처리 (소수점 2자리, -999이면 "- - -")
    snr1 = struct.unpack('<f', bytes(packet[320:324]))[0]
    parsed_data['MVBX_BeamInfo_snr1'] = "- - -" if snr1 == -999 else f"{snr1:.2f}"
    
    snr2 = struct.unpack('<f', bytes(packet[324:328]))[0]
    parsed_data['MVBX_BeamInfo_snr2'] = "- - -" if snr2 == -999 else f"{snr2:.2f}"
    
    snr3 = struct.unpack('<f', bytes(packet[328:332]))[0]
    parsed_data['MVBX_BeamInfo_snr3'] = "- - -" if snr3 == -999 else f"{snr3:.2f}"
    
    snr4 = struct.unpack('<f', bytes(packet[332:336]))[0]
    parsed_data['MVBX_BeamInfo_snr4'] = "- - -" if snr4 == -999 else f"{snr4:.2f}"
    
    # RSRP 값 처리 (소수점 2자리, -999이면 "- - -")
    rsrp1 = struct.unpack('<f', bytes(packet[336:340]))[0]
    parsed_data['MVBX_BeamInfo_rsrp1'] = "- - -" if rsrp1 == -999 else f"{rsrp1:.2f}"
    
    rsrp2 = struct.unpack('<f', bytes(packet[340:344]))[0]
    parsed_data['MVBX_BeamInfo_rsrp2'] = "- - -" if rsrp2 == -999 else f"{rsrp2:.2f}"
    
    rsrp3 = struct.unpack('<f', bytes(packet[344:348]))[0]
    parsed_data['MVBX_BeamInfo_rsrp3'] = "- - -" if rsrp3 == -999 else f"{rsrp3:.2f}"
    
    rsrp4 = struct.unpack('<f', bytes(packet[348:352]))[0]
    parsed_data['MVBX_BeamInfo_rsrp4'] = "- - -" if rsrp4 == -999 else f"{rsrp4:.2f}"
    parsed_data['pss_pulse_count'] = struct.unpack('<I', bytes([packet[352], packet[353], packet[354], packet[355]]))[0]
    parsed_data['decoded_ssb_count'] = struct.unpack('<I', bytes([packet[356], packet[357], packet[358], packet[359]]))[0]
    parsed_data['decoded_ssb_no_error_count'] = struct.unpack('<I', bytes([packet[360], packet[361], packet[362], packet[363]]))[0]
    parsed_data['LicStatus'] = packet[364]
    parsed_data['LicStartDateMonth'] = packet[365]
    parsed_data['LicStartDateDay'] = packet[366]
    parsed_data['LicStopDateMonth'] = packet[367]
    parsed_data['LicStopDateDay'] = packet[368]
    parsed_data['Reserved4_new'] = packet[369:412]
    # Modem 상태
    parsed_data['ModRsrp'] = struct.unpack('<h', bytes([packet[412], packet[413]]))[0]
    parsed_data['ModRsrq'] = struct.unpack('<h', bytes([packet[414], packet[415]]))[0]
    parsed_data['InitTemper'] = packet[416]
    parsed_data['ModVersion'] = f"{packet[417] / 100:.2f}"
    parsed_data['ModLanUseMode'] = packet[418]
    parsed_data['ModPci'] = packet[419]
    parsed_data['SU_DlIsoAtten_SISO'] = packet[420]
    parsed_data['SU_DlIsoAtten_MIMO'] = packet[421]
    parsed_data['SU_UlIsoAtten_SISO'] = packet[422]
    parsed_data['SU_UlIsoAtten_MIMO'] = packet[423]
    parsed_data['SU_ISO_SATUS'] = packet[424:428]
    
    parsed_data['DU_ISO_STATUS'] = packet[428]
    
    parsed_data['ModStatus'] = packet[429]
    parsed_data['ModSinr'] = packet[430]
    parsed_data['Reserved6'] = packet[431]
    parsed_data['ModRssi'] = struct.unpack('<h', bytes([packet[432], packet[433]]))[0]
    parsed_data['ModTxPwr'] = struct.unpack('<h', bytes([packet[434], packet[435]]))[0]
    
    """
    # 16진수 바이트 배열을 10진수 문자열로 변환 (15자리만)
    def hex_bytes_to_decimal_string(byte_array):
        try:
            # 16진수 값을 10진수 문자열로 변환
            result = ''.join([f"{b:02d}" for b in byte_array if b != 0])
            # 15자리만 사용
            return result[:15] if result else "N/A"
        except:
            return "N/A"
    """
    
    # 널문자를 만날 때까지 문자열 변환
    def bytes_to_string_until_null(byte_array):
        result = ''
        for b in byte_array:
            if b == 0:  # 널문자 만나면 중단
                break
            result += chr(b)
        return result
    
    parsed_data['ModIMSINum'] = bytes_to_string_until_null(packet[436:452])
    parsed_data['ModIMEINum'] = bytes_to_string_until_null(packet[452:476])
    parsed_data['ModIpAddress'] =f"{packet[476]}.{packet[477]}.{packet[478]}.{packet[479]}"
    parsed_data['ModServerIpAddress'] = packet[480:484]
    parsed_data['ModPhonNumber'] = bytes_to_string_until_null(packet[484:495])
    parsed_data['ModEmsFwVer'] = f"{struct.unpack('<h', bytes([packet[496], packet[497]]))[0] / 100:.2f}"
    parsed_data['Gumstick_CurTemper'] = struct.unpack('<h', bytes([packet[498], packet[499]]))[0]
    parsed_data['Gumstick_StartTemper'] = struct.unpack('<h', bytes([packet[500], packet[501]]))[0]
    parsed_data['DlTemperCompensation'] = packet[502]
    parsed_data['UlTemperCompensation'] = packet[503]
    parsed_data['PllRelockCount'] = struct.unpack('<h', bytes([packet[504], packet[505]]))[0]
    parsed_data['DecodedRate'] = packet[506]
    parsed_data['Reserved6p1'] = packet[507]
    parsed_data['DsOutputPower_SISO'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[508], packet[509]]))[0])
    parsed_data['EmsModemReset'] = packet[510]
    parsed_data['Reserved6p2'] = packet[511]
    agc_input_raw = struct.unpack('<h', bytes([packet[512], packet[513]]))[0]
    parsed_data['AGC_Input_Power'] = f"{agc_input_raw / 10:.1f}"
    parsed_data['DsOutputPower_MIMO'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[514], packet[515]]))[0])
    parsed_data['Actual_Orientation'] = struct.unpack('<h', bytes([packet[516], packet[517]]))[0]
    parsed_data['Actual_Tilt'] = struct.unpack('<h', bytes([packet[518], packet[519]]))[0]
    parsed_data['Reserved6p3'] = packet[520:576]
    #DU Control
    parsed_data['InitCheckNum'] = packet[576:580]
    parsed_data['ConMuFlag'] = packet[580:604]
    parsed_data['ConSysTime_Year'] = '.'.join(['{:02d}'.format((packet[604] << 8) | packet[605]), '{:02d}'.format(packet[606]), '{:02d}'.format(packet[607])])
    parsed_data['ConSysTime_hour'] = ':'.join(['{:02d}'.format(packet[608]), '{:02d}'.format(packet[609]), '{:02d}'.format(packet[610])])
    parsed_data['RptMakerCode'] = packet[611]
    parsed_data['SysTemperHighLvl'] = packet[612]
    parsed_data['SysTemperLowLvl'] = packet[613]
    parsed_data['SubInitCheckNum'] = packet[614]
    parsed_data['DebugMode'] = packet[615]
    parsed_data['SuEnableInfo'] = packet[616:628]
    # SU Enable Info 비트 추출 (packet[616]의 비트 0~3)
    su_enable_bits = {
        'SU1_ENABLE': (packet[616] >> 0) & 1,  # 비트 0
        'SU2_ENABLE': (packet[616] >> 1) & 1,  # 비트 1
        'SU3_ENABLE': (packet[616] >> 2) & 1,  # 비트 2
        'SU4_ENABLE': (packet[616] >> 3) & 1   # 비트 3
    }
    parsed_data['SuEnableBits'] = su_enable_bits
    

    parsed_data['MaskMuAlarm'] = list(packet[628:640])
    
    # packet[635]에서 0번째, 2번째, 5번째 비트 추출
    dl_alc_bits = {
        'SISO_MASK_DL_ALC': (packet[635] >> 0) & 1,  # 비트 0
        'MIMO_MASK_DL_ALC': (packet[635] >> 2) & 1,  # 비트 2
        'EMS_DU_Link_MASK': (packet[635] >> 5) & 1   # 비트 5
    }
    parsed_data['DL_ALC_Bits'] = dl_alc_bits

    # packet[634]에서 0번째, 1번째, 2번째, 3번째 비트 추출
    det_mask_bits = {
        'LD1_DET_DL0_SISO_MASK': (packet[634] >> 0) & 1,  # 비트 0
        'LD2_DET_DL1_MIMO_MASK': (packet[634] >> 1) & 1,  # 비트 1
        'PD1_DET_UL0_SISO_MASK': (packet[634] >> 2) & 1,  # 비트 2
        'PD2_DET_UL1_MIMO_MASK': (packet[634] >> 3) & 1   # 비트 3
    }
    parsed_data['DET_MASK_Bits'] = det_mask_bits

        # 알람 비트 매핑 정의
    alarm_mask_bit_map = [
        {'bit': 1,  'id': 'alarm_mask_madc'},
        {'bit': 2,  'id': 'alarm_mask_ac'},
        {'bit': 3,  'id': 'alarm_mask_temp'},
        {'bit': 4,  'id': 'alarm_mask_bat'},
        {'bit': 49, 'id': 'alarm_mask_fpga_link'},
        {'bit': 53, 'id': 'alarm_mask_if_pll'},
        {'bit': 54, 'id': 'alarm_mask_sync_pll'},
        {'bit': 52, 'id': 'alarm_mask_tsync_link'},  # 비트 51 → 52로 수정
        {'bit': 66, 'id': 'alarm_mask_decoding'},
        {'bit': 70, 'id': 'alarm_mask_aa_link'}
    ]

    # Mask 알람 비트 추출 함수
    def get_mask_alarm_bit(mask_bytes, bit_position):
        byte_index = (bit_position - 1) // 8
        bit_in_byte = (bit_position - 1) % 8
        if byte_index < len(mask_bytes):
            return (mask_bytes[byte_index] >> bit_in_byte) & 1
        return 0
    
    # 각 Mask 알람 비트 상태 추출
    mask_alarm_status = {}
    for alarm in alarm_mask_bit_map:
        mask_alarm_status[alarm['id']] = get_mask_alarm_bit(packet[628:640], alarm['bit'])
    
    parsed_data['MaskAlarmStatus'] = mask_alarm_status

    



    parsed_data['MaskSuLinkFail'] = packet[640:652]

    # SuLinkFail에서 1비트씩 추출 - SU1~SU4만
    su_mask_link_fail_bits = {
        'SU1_MASK_LINK_FAIL': (packet[640] >> 0) & 1,  # 비트 0
        'SU2_MASK_LINK_FAIL': (packet[640] >> 1) & 1,  # 비트 1
        'SU3_MASK_LINK_FAIL': (packet[640] >> 2) & 1,  # 비트 2
        'SU4_MASK_LINK_FAIL': (packet[640] >> 3) & 1   # 비트 3
        #추후 SU5, SU6 추가 해야할수도 있음
    }
    parsed_data['MaskSuLinkFail'] = su_mask_link_fail_bits
    
    parsed_data['MaskSuSumAlarm'] = packet[652:664]
    parsed_data['MaskSuRptAlarm'] = packet[664:676]
    parsed_data['ConEmsModemReset'] = packet[676]
    parsed_data['DownloadPath_GuiOrEms'] = packet[677]
    parsed_data['PollingTime'] = struct.unpack('<H', bytes([packet[678], packet[679]]))[0]
    parsed_data['ApiInitMode'] = packet[680]
    parsed_data['AttTestMode'] = packet[681]
    parsed_data['SuId'] = packet[682]
    parsed_data['DL_UL_TEST'] = packet[683]
    parsed_data['LocalInfo'] = packet[684:744]
    parsed_data['SuOpticalEnStatus'] = packet[744]
    parsed_data['PreStaAlarm'] = packet[745:757] 
    parsed_data['Mu_Su_Buadrate'] = packet[757]
    parsed_data['ModemOnOff'] = packet[758]
    parsed_data['RsrpOffset'] = packet[759]
    parsed_data['SuOpticalEnStatus'] = packet[744]
    parsed_data['PreStaAlarm'] = packet[745:757] # Changed to 745:757
    parsed_data['Mu_Su_Buadrate'] = packet[757]
    parsed_data['ModemOnOff'] = packet[758]
    parsed_data['RsrpOffset'] = packet[759]
    #RF 제어
    parsed_data['ALC_DL0_SISO_Mode'] = packet[760]
    parsed_data['ALC_DL1_MIMO_Mode'] = packet[761]
    parsed_data['ALC_UL0_SISO_Mode'] = packet[762]
    parsed_data['ALC_UL1_MIMO_Mode'] = packet[763]
    # ALC Level (1dBm 단위)
    parsed_data['ALC_DL0_SISO_Level'] = convert_to_1dbm(struct.unpack('<h', bytes([packet[764], packet[765]]))[0])
    parsed_data['ALC_DL1_MIMO_Level'] = convert_to_1dbm(struct.unpack('<h', bytes([packet[766], packet[767]]))[0])
    parsed_data['ALC_UL0_SISO_Level'] = convert_to_1dbm(struct.unpack('<h', bytes([packet[768], packet[769]]))[0])
    parsed_data['ALC_UL1_MIMO_Level'] = convert_to_1dbm(struct.unpack('<h', bytes([packet[770], packet[771]]))[0])
    parsed_data['SISO_RF_DET_DL0_OUT_High'] = struct.unpack('<h', bytes([packet[772], packet[773]]))[0]
    parsed_data['SISO_RF_DET_UL0_OUT_High'] = struct.unpack('<h', bytes([packet[774], packet[775]]))[0]
    parsed_data['MIMO_RF_DET_DL1_OUT_High'] = struct.unpack('<h', bytes([packet[776], packet[777]]))[0]
    parsed_data['MIMO_RF_DET_UL1_OUT_High'] = struct.unpack('<h', bytes([packet[778], packet[779]]))[0]
    # SISO/MIMO OPTIC DET Low (0.1dBm 단위로 변환)
    parsed_data['LD1_DET_DL0_SISO_Low'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[780], packet[781]]))[0])
    parsed_data['LD2_DET_DL1_MIMO_Low'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[782], packet[783]]))[0])
    parsed_data['PD1_DET_UL0_SISO_Low'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[784], packet[785]]))[0])
    parsed_data['PD2_DET_UL1_MIMO_Low'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[786], packet[787]]))[0])
    parsed_data['LD3_DET_DL0_SISO_Low'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[788], packet[789]]))[0])
    parsed_data['LD4_DET_DL1_MIMO_Low'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[790], packet[791]]))[0])
    parsed_data['PD3_DET_UL0_SISO_Low'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[792], packet[793]]))[0])
    parsed_data['PD4_DET_UL1_MIMO_Low'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[794], packet[795]]))[0])
    parsed_data['LD1_DET_DL0_SISO_Offset'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[796], packet[797]]))[0])
    parsed_data['LD2_DET_DL1_MIMO_Offset'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[798], packet[799]]))[0])
    parsed_data['PD1_DET_UL0_SISO_Offset'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[800], packet[801]]))[0])
    parsed_data['PD2_DET_UL1_MIMO_Offset'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[802], packet[803]]))[0])
    parsed_data['LD3_DET_DL0_SISO_Offset'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[804], packet[805]]))[0])
    parsed_data['LD4_DET_DL1_MIMO_Offset'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[806], packet[807]]))[0])
    parsed_data['PD3_DET_UL0_SISO_Offset'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[808], packet[809]]))[0])
    parsed_data['PD4_DET_UL1_MIMO_Offset'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[810], packet[811]]))[0])
    # DU ATT (0.5dB 단위로 변환)
    parsed_data['DU_DlManualAtten_SISO'] = convert_att_4_to_2(packet[812])
    parsed_data['DU_DlSubAtten_SISO'] = convert_att_4_to_2(packet[813])
    parsed_data['DU_DlManualAtten_MIMO'] = convert_att_4_to_2(packet[814])
    parsed_data['DU_DlSubAtten_MIMO'] = convert_att_4_to_2(packet[815])
    parsed_data['DU_UlManualAtten_SISO'] = convert_att_4_to_2(packet[816])
    parsed_data['DU_UlSubAtten_SISO'] = convert_att_4_to_2(packet[817])
    parsed_data['DU_UlIsoAtten_SISO'] = convert_iso_att(packet[818])
    parsed_data['DU_UlManualAtten_MIMO'] = convert_att_4_to_2(packet[819])
    parsed_data['DU_UlSubAtten_MIMO'] = convert_att_4_to_2(packet[820])
    parsed_data['DU_UlIsoAtten_MIMO'] = convert_iso_att(packet[821])
    parsed_data['SU_DlManualAtten_SISO'] = packet[822]
    parsed_data['SU_DlSubAtten_SISO'] = packet[823]
    parsed_data['SU_DlManualAtten_MIMO'] = packet[824]
    parsed_data['SU_DlSubAtten_MIMO'] = packet[825]
    parsed_data['SU_UlManualAtten_SISO'] = packet[826]
    parsed_data['SU_UlSubAtten_SISO'] = packet[827]
    parsed_data['SU_UlManualAtten_MIMO'] = packet[828]
    parsed_data['SU_UlSubAtten_MIMO'] = packet[829]
    parsed_data['LicPassword'] = struct.unpack('<h', bytes([packet[830], packet[831]]))[0]
    parsed_data['DL_OutputOffset_SISO'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[832], packet[833]]))[0])
    parsed_data['DL_OutputOffset_MIMO'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[834], packet[835]]))[0])
    parsed_data['UL_InputOffset_SISO'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[836], packet[837]]))[0])
    parsed_data['UL_InputOffset_MIMO'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[838], packet[839]]))[0])
    parsed_data['SU_UlCasSisoAtten_SISO'] = packet[840]
    parsed_data['SU_UlCasSisoAtten_MIMO'] = packet[841]
    parsed_data['SdOnOffSiso'] = packet[842]
    parsed_data['SdOnOffMimo'] = packet[843]
    parsed_data['DuFixBeam'] = packet[844]
    parsed_data['Reserved4_Local'] = packet[845:852]
    parsed_data['Dl_Siso_Att_Test'] = convert_att_test(struct.unpack('<h', bytes([packet[852], packet[853]]))[0])
    parsed_data['Dl_Mimo_Att_Test'] = convert_att_test(struct.unpack('<h', bytes([packet[854], packet[855]]))[0])
    parsed_data['Ul_Siso_Att_Test'] = convert_att_test(struct.unpack('<h', bytes([packet[856], packet[857]]))[0])
    parsed_data['Ul_Mimo_Att_Test'] = convert_att_test(struct.unpack('<h', bytes([packet[858], packet[859]]))[0])
    parsed_data['Reserved10p1'] = packet[860:892]
    # MVBX 제어
    parsed_data['Mvbx_BeamSet'] = packet[892]
    parsed_data['InstallUseMode'] = packet[893]
    parsed_data['Reserved14'] = packet[894:896]
    parsed_data['Mvbx_FpagImageSize'] = packet[896:900]
    parsed_data['Mvbx_FpagImageStartAddressOffset'] = packet[900:904]
    parsed_data['Reserved15'] = packet[904:920]
    parsed_data['FpgaWriteAddress'] = packet[920:922]
    parsed_data['FpgaWriteData'] = packet[922:924]
    parsed_data['FpgaReadAddress'] = packet[924:926]
    parsed_data['FpgaReadData'] = packet[926:928]
    parsed_data['Reserved31'] = packet[928:940]
    parsed_data['Mvbx_TddSignalMode'] = packet[940]
    parsed_data['Mvbx_RsAgcThreshold'] = packet[941]
    parsed_data['Mvbx_RsAgcMode'] = packet[942]
    parsed_data['Reserved32'] = packet[943]
    parsed_data['Mvbx_Mv2853TxGainSiso'] = packet[944]
    parsed_data['Mvbx_Mv2853RxGainSiso'] = packet[945]
    parsed_data['Mvbx_Mv2850TxGainSiso'] = packet[946]
    parsed_data['Mvbx_Mv2850RxGainSiso'] = packet[947]
    parsed_data['Mvbx_Mv2853TxGainMimo'] = packet[948]
    parsed_data['Mvbx_Mv2853RxGainMimo'] = packet[949]
    parsed_data['Mvbx_Mv2850TxGainMimo'] = packet[950]
    parsed_data['Mvbx_Mv2850RxGainMimo'] = packet[951]
    parsed_data['Mvbx_TxGainSetSiso'] = packet[952]
    parsed_data['Mvbx_RxGainSetSiso'] = packet[953]
    parsed_data['Mvbx_TxGainSetMiso'] = packet[954]
    parsed_data['Mvbx_RxGainSetMiso'] = packet[955]
    parsed_data['beam_info_pss_type'] = struct.unpack('<I', bytes([packet[956], packet[957], packet[958], packet[959]]))[0]
    parsed_data['beam_info_adc_sel'] = struct.unpack('<I', bytes([packet[960], packet[961], packet[962], packet[963]]))[0]
    parsed_data['beam_info_spg '] = struct.unpack('<I', bytes([packet[964], packet[965], packet[966], packet[967]]))[0]
    parsed_data['beam_info_ssbIdx'] = struct.unpack('<I', bytes([packet[968], packet[969], packet[970], packet[971]]))[0]
    parsed_data['beam_info_beamID'] = struct.unpack('<h', bytes([packet[972], packet[973]]))[0]
    parsed_data['Reserved34'] = struct.unpack('<h', bytes([packet[974], packet[975]]))[0]
    parsed_data['beam_info_energy'] = struct.unpack('<I', bytes([packet[976], packet[977], packet[978], packet[979]]))[0]
    parsed_data['beam_info_rsrp '] = struct.unpack('<I', bytes([packet[980], packet[981], packet[982], packet[983]]))[0]
    parsed_data['beam_info_snr'] = struct.unpack('<I', bytes([packet[984], packet[985], packet[986], packet[987]]))[0]
    parsed_data['PllSet'] = struct.unpack('<I', bytes([packet[988], packet[989], packet[990], packet[991]]))[0]
    parsed_data['IsoMeasSet'] = packet[992]
    parsed_data['SuGsOnOff'] = packet[993]
    parsed_data['SuIsoAttSet'] = packet[994]
    parsed_data['GumStick_OnOff'] = packet[995]
    parsed_data['BeamScan_OnOff'] = packet[996]
    parsed_data['IsoDetectMode'] = packet[997]
    parsed_data['ApiLogLevel'] = packet[998]
    parsed_data['ApiAdcSel'] = packet[999]
    parsed_data['ApiSyncPathGain'] = packet[1000]
    parsed_data['ApiDuTimeAdvance'] = packet[1001]
    parsed_data['ApiSuTimeAdvance'] = packet[1002]
    parsed_data['TemperCompensationMode'] = packet[1003]
    parsed_data['ApiVenderFreq'] = struct.unpack('<I', bytes([packet[1004], packet[1005], packet[1006], packet[1007]]))[0]
    parsed_data['ApiGsOutputPowerOffsetSiso'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[1008], packet[1009]]))[0])
    parsed_data['BeamAntSelect'] = packet[1010]
    parsed_data['DecodeRecoveryFuncOnOff'] = packet[1011]
    parsed_data['gNB_ScanOnOff'] = packet[1012]
    parsed_data['SuEndMode'] = packet[1013]
    parsed_data['ApiGsOutputPowerOffsetMimo'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[1014], packet[1015]]))[0])
    parsed_data['gNB_Vendor'] = packet[1016]
    parsed_data['Gs_Gain_Siso'] = packet[1017]
    parsed_data['Gs_Gain_Mimo'] = packet[1018]
    parsed_data['ApiInitRetryMode'] = packet[1019]
    parsed_data['Orientation'] = f"{struct.unpack('<h', bytes([packet[1020], packet[1021]]))[0]:.3f}"
    parsed_data['Tilt'] = f"{struct.unpack('<h', bytes([packet[1022], packet[1023]]))[0]:.3f}"
    parsed_data['GS_AttenOffset_DL_Siso'] = struct.unpack('<b', bytes([packet[1024]]))[0]
    parsed_data['GS_AttenOffset_DL_Mimo'] = struct.unpack('<b', bytes([packet[1025]]))[0]
    parsed_data['GS_AttenOffset_UL_Siso'] = struct.unpack('<b', bytes([packet[1026]]))[0]
    parsed_data['GS_AttenOffset_UL_Mimo'] = struct.unpack('<b', bytes([packet[1027]]))[0]
    parsed_data['ConSerialNum'] = ''.join([chr(b) for b in packet[1028:1044] if b != 0])
    parsed_data['AomTemperConperMode'] = packet[1044]
    parsed_data['GS_AttenOffset_30by15_DL_Siso'] = packet[1045]
    parsed_data['GS_AttenOffset_30by30_DL_Siso'] = packet[1046]
    parsed_data['GS_AttenOffset_60by15_DL_Siso'] = packet[1047]
    parsed_data['GS_AttenOffset_60by30_DL_Siso'] = packet[1048]
    parsed_data['GS_AttenOffset_60by60_DL_Siso'] = packet[1049]
    parsed_data['GS_AttenOffset_30by15_DL_Mimo'] = packet[1050]
    parsed_data['GS_AttenOffset_30by30_DL_Mimo'] = packet[1051]
    parsed_data['GS_AttenOffset_60by15_DL_Mimo'] = packet[1052]
    parsed_data['GS_AttenOffset_60by30_DL_Mimo'] = packet[1053]
    parsed_data['GS_AttenOffset_60by60_DL_Mimo'] = packet[1054]
    parsed_data['GS_AttenOffset_30by15_UL_Siso'] = packet[1055]
    parsed_data['GS_AttenOffset_30by30_UL_Siso'] = packet[1056]
    parsed_data['GS_AttenOffset_60by15_UL_Siso'] = packet[1057]
    parsed_data['GS_AttenOffset_60by30_UL_Siso'] = packet[1058]
    parsed_data['GS_AttenOffset_60by60_UL_Siso'] = packet[1059]
    parsed_data['GS_AttenOffset_30by15_UL_Mimo'] = packet[1060]
    parsed_data['GS_AttenOffset_30by30_UL_Mimo'] = packet[1061]
    parsed_data['GS_AttenOffset_60by15_UL_Mimo'] = packet[1062]
    parsed_data['GS_AttenOffset_60by30_UL_Mimo'] = packet[1063]
    parsed_data['GS_AttenOffset_60by60_UL_Mimo'] = packet[1064]
    parsed_data['Reserved41'] = packet[1065:1089]
    parsed_data['LowRsrpStillTime'] = packet[1089]
    parsed_data['LowRsrpLevel'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[1090], packet[1091]]))[0])
    parsed_data['SU_DlCasSisoAtten_SISO'] = packet[1092]
    parsed_data['SU_DlCasSisoAtten_MIMO'] = packet[1093]
    parsed_data['SU_DlCasSisoAttenTest_SISO'] = packet[1094]
    parsed_data['SU_DlCasSisoAttenTest_MIMO'] = packet[1095]
    parsed_data['SU_UlCasSisoAttenTest_SISO'] = packet[1096]
    parsed_data['SU_UlCasSisoAttenTest_MIMO'] = packet[1097]
    parsed_data['Reserved41p1'] = packet[1098:1101]
    parsed_data['PciResetOnOff'] = packet[1101]
    parsed_data['PciNo'] = struct.unpack('<h', bytes([packet[1102], packet[1103]]))[0]
    parsed_data['PciTime'] = packet[1104]
    parsed_data['Reserved42'] = packet[1105:1112]
    # Reserved42 감지 시 RX 박스 끄기
    socketio.emit("rx_off")

    return parsed_data

def parse_AllStatusPacket3(packet):


    parsed_data = {}
    
    # 단위 변환 함수들
    def convert_to_01dbm(raw_value):
        """0.1dBm 단위로 변환 (예: -517 → -51.7 dBm)"""
        return round(raw_value / 10.0, 1)
    
    def convert_att_4_to_2(raw_value):
        """ATT 변환 (4→2dB, Step: 0.5dB)"""
        return raw_value * 0.5
    
    def convert_to_1dbm(raw_value):
        """1dBm 단위로 변환"""
        return raw_value
    
    def convert_iso_att(raw_value):
        """ISO ATT 변환 (4→2dB, Step: 0.5dB, Range: 0~20dB)"""
        return raw_value * 0.5
    
    def convert_att_test(raw_value):
        """ATT Test 변환 (50: 5dB, 0.5dB 단위, Range: 0~30dB)"""
        return raw_value * 0.5
    
    def convert_polling_time(raw_value):
        """Polling Time 변환 (2바이트 uint, 범위: 100~5,000ms)"""
        return raw_value  # 이미 ms 단위로 저장되어 있음
    
    #su1 상태
    parsed_data['Rcv_Main_Sys'] = packet[0]
    # Rcv_Main_Sys 감지 시 RX 박스 켜기
    socketio.emit("rx_on")
    parsed_data['Rcv_Sub_Sys'] = packet[1]
    parsed_data['Rcv_Object'] = packet[2]
    parsed_data['Trans_Main_Sys'] = packet[3]
    # Trans_Main_Sys 감지 시 TX 박스 토글 (1이면 켜기, 0이면 끄기)
    if packet[3] != 0:
        socketio.emit("tx_on")
    else:
        socketio.emit("tx_off")
    parsed_data['Trans_Sub_Sys'] = packet[4]
    parsed_data['Trans_Object'] = packet[5]
    parsed_data['CMD'] = packet[6]
    parsed_data['EQUIP_TYPE'] = packet[7]
    parsed_data['RESERVED'] = packet[8:10]
    parsed_data['SubData_Size'] = struct.unpack('<h', bytes([packet[10], packet[11]]))[0]
    parsed_data['McuSwVer'] = f"{packet[13]}.{packet[12]}" 
    parsed_data['RptMaker'] = packet[14]
    parsed_data['DU_SU_Status'] = packet[15]
    parsed_data['Reserved0_1'] = packet[16]
    parsed_data['StatusPollingUnit'] = packet[17]
    parsed_data['RtpKind'] = packet[18]
    parsed_data['Reserved0'] = packet[19]
    parsed_data['StaMuAlarm'] = list(packet[20:32])
    
    # 알람 비트 매핑 정의
    alarm_bit_map = [
        {'bit': 1,  'id': 'su2_alarm_dc'},
        {'bit': 2,  'id': 'su2_alarm_ac'},
        {'bit': 3,  'id': 'su2_alarm_temp'},
        {'bit': 4,  'id': 'su2_alarm_bat'},
        {'bit': 48, 'id': 'su2_alarm_du_link'},
        {'bit': 53, 'id': 'su2_alarm_if_pll'},
        {'bit': 52, 'id': 'su2_alarm_tsync_link'},  # 비트 51 → 52로 수정
        {'bit': 63, 'id': 'su2_alarm_ref_pll'},
        {'bit': 70, 'id': 'su2_alarm_aa_link'}
    ]

    # 알람 비트 추출 함수
    def get_alarm_bit(alarm_bytes, bit_position):
        byte_index = (bit_position - 1) // 8
        bit_in_byte = (bit_position - 1) % 8
        if byte_index < len(alarm_bytes):
            return (alarm_bytes[byte_index] >> bit_in_byte) & 1
        return 0
    
    # 각 알람 비트 상태 추출
    alarm_status = {}
    for alarm in alarm_bit_map:
        alarm_status[alarm['id']] = get_alarm_bit(packet[20:32], alarm['bit'])
    
    parsed_data['AlarmStatus'] = alarm_status
    
    # ALA2 링크 알람 비트 추출 (packet[21]의 비트 0~3)
    ala2_link_alarms = {
        'ALA2_SU1_LINK_ALARM': (packet[21] >> 0) & 1,  # 비트 0
        'ALA2_SU2_LINK_ALARM': (packet[21] >> 1) & 1,  # 비트 1
        'ALA2_SU3_LINK_ALARM': (packet[21] >> 2) & 1,  # 비트 2
        'ALA2_SU4_LINK_ALARM': (packet[21] >> 3) & 1   # 비트 3
    }
    parsed_data['ALA2_Link_Alarms'] = ala2_link_alarms
    parsed_data['SuLinkFail'] = packet[32:44]
    # SuLinkFail에서 1비트씩 추출 - SU1~SU4만
    su_link_fail_bits = {
        'SU1_LINK_FAIL': (packet[32] >> 0) & 1,  # 비트 0
        'SU2_LINK_FAIL': (packet[32] >> 1) & 1,  # 비트 1
        'SU3_LINK_FAIL': (packet[32] >> 2) & 1,  # 비트 2
        'SU4_LINK_FAIL': (packet[32] >> 3) & 1   # 비트 3
        #추후 SU5, SU6 추가 해야할수도 있음
    }
    parsed_data['SuLinkFailBits'] = su_link_fail_bits
    parsed_data['SuSumAlarm'] = packet[44:56]
    parsed_data['SuRptAlarm'] = packet[56:68] 
    parsed_data['StsApiVenderFreq'] = struct.unpack('<I', bytes([packet[68], packet[69], packet[70], packet[71]]))[0]
    parsed_data['System_Year'] = '.'.join(['{:02d}'.format((packet[72] << 8) | packet[73]), '{:02d}'.format(packet[74]), '{:02d}'.format(packet[75])])
    parsed_data['System_hour'] = ':'.join(['{:02d}'.format(packet[76]), '{:02d}'.format(packet[77]), '{:02d}'.format(packet[78])])
    parsed_data['SysTemper'] = packet[79]
    parsed_data['PackSendCount'] = packet[80:120]
    parsed_data['PackErrorCount'] = packet[120:160]
    parsed_data['FPGA_Boot_Status'] = packet[160]
    parsed_data['FPGA_Init_Status'] = packet[161]
    parsed_data['Beam_Scan_Status'] = packet[162]
    parsed_data['DU_SumAlarmStatus'] = packet[163]
    parsed_data['ALC_Atten_DL0_SISO'] = struct.unpack('<h', bytes([packet[164], packet[165]]))[0]
    parsed_data['ALC_Atten_DL1_MIMO'] = struct.unpack('<h', bytes([packet[166], packet[167]]))[0]
    parsed_data['ALC_Atten_UL0_SISO'] = struct.unpack('<h', bytes([packet[168], packet[169]]))[0]
    parsed_data['ALC_Atten_UL1_MIMO'] = struct.unpack('<h', bytes([packet[170], packet[171]]))[0]
    # SISO/MIMO OPTIC DET (0.1dBm 단위로 변환)
    parsed_data['LD1_DET_DL0_SISO'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[172], packet[173]]))[0])
    parsed_data['LD2_DET_DL1_MIMO'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[174], packet[175]]))[0])
    parsed_data['PD1_DET_UL0_SISO'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[176], packet[177]]))[0])
    parsed_data['PD2_DET_UL1_MIMO'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[178], packet[179]]))[0])
    # SISO/MIMO RF DET (0.1dBm 단위로 변환)
    parsed_data['SISO_RF_DET_DL0_OUT'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[180], packet[181]]))[0])
    parsed_data['SISO_RF_DET_UL0_OUT'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[182], packet[183]]))[0])
    parsed_data['MIMO_RF_DET_DL1_OUT'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[184], packet[185]]))[0])
    parsed_data['MIMO_RF_DET_UL1_OUT'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[186], packet[187]]))[0])
    parsed_data['LD3_DET_DL0_SISO'] = struct.unpack('<h', bytes([packet[188], packet[189]]))[0]
    parsed_data['LD4_DET_DL1_MIMO'] = struct.unpack('<h', bytes([packet[190], packet[191]]))[0]
    parsed_data['PD3_DET_UL0_SISO'] = struct.unpack('<h', bytes([packet[192], packet[193]]))[0]
    parsed_data['PD4_DET_UL1_MIMO'] = struct.unpack('<h', bytes([packet[194], packet[195]]))[0]
    parsed_data['SuModeStatus'] = packet[196]
    parsed_data['SdStatusSiso'] = packet[197]
    parsed_data['SdStatusMimo'] = packet[198]
    parsed_data['Reserved3'] = packet[199:220] 
    #MVBX 상태
    parsed_data['FPGA_Ver'] = '.'.join([str(packet[220]), str(packet[221]), str(packet[222])])
    parsed_data['ApiOldNewVer'] = packet[223]
    parsed_data['Reserved3p1'] = packet[224:232] 
    parsed_data['Gumstick_Ver'] = '.'.join([str(packet[232]), str(packet[233]), str(packet[234])])
    parsed_data['SyncStatus'] = packet[235]
    parsed_data['TryBeamScanCont'] = struct.unpack('<h', bytes([packet[236], packet[237]]))[0]
    parsed_data['Reserved4'] = packet[238:244]
    parsed_data['MVBX_pci'] = struct.unpack('<h', bytes([packet[244], packet[245]]))[0]
    parsed_data['MVBX_ssb'] = struct.unpack('<h', bytes([packet[246], packet[247]]))[0]
    parsed_data['MVBX_rsrp'] = f"{struct.unpack('<f', bytes(packet[248:252]))[0]:.2f} [dBm]"
    parsed_data['MVBX_snr'] = f"{struct.unpack('<f', bytes(packet[252:256]))[0]:.2f} [dB]"
    parsed_data['MVBX_BeamInfo_beamId1'] = struct.unpack('<h', bytes([packet[256], packet[257]]))[0]
    parsed_data['MVBX_BeamInfo_beamId2'] = struct.unpack('<h', bytes([packet[258], packet[259]]))[0]
    parsed_data['MVBX_BeamInfo_beamId3'] = struct.unpack('<h', bytes([packet[260], packet[261]]))[0]
    parsed_data['MVBX_BeamInfo_beamId4'] = struct.unpack('<h', bytes([packet[262], packet[263]]))[0]
    parsed_data['MVBX_BeamInfo_pci1'] = struct.unpack('<h', bytes([packet[264], packet[265]]))[0]
    parsed_data['MVBX_BeamInfo_pci2'] = struct.unpack('<h', bytes([packet[266], packet[267]]))[0]
    parsed_data['MVBX_BeamInfo_pci3'] = struct.unpack('<h', bytes([packet[268], packet[269]]))[0]
    parsed_data['MVBX_BeamInfo_pci4'] = struct.unpack('<h', bytes([packet[270], packet[271]]))[0]
    parsed_data['MVBX_BeamInfo_ssbldx1'] = struct.unpack('<I', bytes([packet[272], packet[273], packet[274], packet[275]]))[0]
    parsed_data['MVBX_BeamInfo_ssbldx2'] = struct.unpack('<I', bytes([packet[276], packet[277], packet[278], packet[279]]))[0]
    parsed_data['MVBX_BeamInfo_ssbldx3'] = struct.unpack('<I', bytes([packet[280], packet[281], packet[282], packet[283]]))[0]
    parsed_data['MVBX_BeamInfo_ssbldx4'] = struct.unpack('<I', bytes([packet[284], packet[285], packet[286], packet[287]]))[0]
    parsed_data['MVBX_BeamInfo_energy1'] = struct.unpack('<I', bytes([packet[288], packet[289], packet[290], packet[291]]))[0]
    parsed_data['MVBX_BeamInfo_energy2'] = struct.unpack('<I', bytes([packet[292], packet[293], packet[294], packet[295]]))[0]
    parsed_data['MVBX_BeamInfo_energy3'] = struct.unpack('<I', bytes([packet[296], packet[297], packet[298], packet[299]]))[0]
    parsed_data['MVBX_BeamInfo_energy4'] = struct.unpack('<I', bytes([packet[300], packet[301], packet[302], packet[303]]))[0]
    parsed_data['MVBX_BeamInfo_psstype1'] = struct.unpack('<I', bytes([packet[304], packet[305], packet[306], packet[307]]))[0]
    parsed_data['MVBX_BeamInfo_psstype2'] = struct.unpack('<I', bytes([packet[308], packet[309], packet[310], packet[311]]))[0]
    parsed_data['MVBX_BeamInfo_psstype3'] = struct.unpack('<I', bytes([packet[312], packet[313], packet[314], packet[315]]))[0]
    parsed_data['MVBX_BeamInfo_psstype4'] = struct.unpack('<I', bytes([packet[316], packet[317], packet[318], packet[319]]))[0]
    # SNR 값 처리 (소수점 2자리, -999이면 "- - -")
    snr1 = struct.unpack('<f', bytes(packet[320:324]))[0]
    parsed_data['MVBX_BeamInfo_snr1'] = "- - -" if snr1 == -999 else f"{snr1:.2f}"
    
    snr2 = struct.unpack('<f', bytes(packet[324:328]))[0]
    parsed_data['MVBX_BeamInfo_snr2'] = "- - -" if snr2 == -999 else f"{snr2:.2f}"
    
    snr3 = struct.unpack('<f', bytes(packet[328:332]))[0]
    parsed_data['MVBX_BeamInfo_snr3'] = "- - -" if snr3 == -999 else f"{snr3:.2f}"
    
    snr4 = struct.unpack('<f', bytes(packet[332:336]))[0]
    parsed_data['MVBX_BeamInfo_snr4'] = "- - -" if snr4 == -999 else f"{snr4:.2f}"
    
    # RSRP 값 처리 (소수점 2자리, -999이면 "- - -")
    rsrp1 = struct.unpack('<f', bytes(packet[336:340]))[0]
    parsed_data['MVBX_BeamInfo_rsrp1'] = "- - -" if rsrp1 == -999 else f"{rsrp1:.2f}"
    
    rsrp2 = struct.unpack('<f', bytes(packet[340:344]))[0]
    parsed_data['MVBX_BeamInfo_rsrp2'] = "- - -" if rsrp2 == -999 else f"{rsrp2:.2f}"
    
    rsrp3 = struct.unpack('<f', bytes(packet[344:348]))[0]
    parsed_data['MVBX_BeamInfo_rsrp3'] = "- - -" if rsrp3 == -999 else f"{rsrp3:.2f}"
    
    rsrp4 = struct.unpack('<f', bytes(packet[348:352]))[0]
    parsed_data['MVBX_BeamInfo_rsrp4'] = "- - -" if rsrp4 == -999 else f"{rsrp4:.2f}"
    parsed_data['pss_pulse_count'] = struct.unpack('<I', bytes([packet[352], packet[353], packet[354], packet[355]]))[0]
    parsed_data['decoded_ssb_count'] = struct.unpack('<I', bytes([packet[356], packet[357], packet[358], packet[359]]))[0]
    parsed_data['decoded_ssb_no_error_count'] = struct.unpack('<I', bytes([packet[360], packet[361], packet[362], packet[363]]))[0]
    parsed_data['LicStatus'] = packet[364]
    parsed_data['LicStartDateMonth'] = packet[365]
    parsed_data['LicStartDateDay'] = packet[366]
    parsed_data['LicStopDateMonth'] = packet[367]
    parsed_data['LicStopDateDay'] = packet[368]
    parsed_data['Reserved4_new'] = packet[369:412]
    # Modem 상태
    parsed_data['ModRsrp'] = struct.unpack('<h', bytes([packet[412], packet[413]]))[0]
    parsed_data['ModRsrq'] = struct.unpack('<h', bytes([packet[414], packet[415]]))[0]
    parsed_data['InitTemper'] = packet[416]
    parsed_data['ModVersion'] = f"{packet[417] / 100:.2f}"
    parsed_data['ModLanUseMode'] = packet[418]
    parsed_data['ModPci'] = packet[419]
    parsed_data['SU_DlIsoAtten_SISO'] = packet[420]
    parsed_data['SU_DlIsoAtten_MIMO'] = packet[421]
    parsed_data['SU_UlIsoAtten_SISO'] = packet[422]
    parsed_data['SU_UlIsoAtten_MIMO'] = packet[423]
    parsed_data['SU_ISO_SATUS'] = packet[424:428]
    
    parsed_data['DU_ISO_STATUS'] = packet[428]
    
    parsed_data['ModStatus'] = packet[429]
    parsed_data['ModSinr'] = packet[430]
    parsed_data['Reserved6'] = packet[431]
    parsed_data['ModRssi'] = struct.unpack('<h', bytes([packet[432], packet[433]]))[0]
    parsed_data['ModTxPwr'] = struct.unpack('<h', bytes([packet[434], packet[435]]))[0]
    
    """
    # 16진수 바이트 배열을 10진수 문자열로 변환 (15자리만)
    def hex_bytes_to_decimal_string(byte_array):
        try:
            # 16진수 값을 10진수 문자열로 변환
            result = ''.join([f"{b:02d}" for b in byte_array if b != 0])
            # 15자리만 사용
            return result[:15] if result else "N/A"
        except:
            return "N/A"
    """
    
    # 널문자를 만날 때까지 문자열 변환
    def bytes_to_string_until_null(byte_array):
        result = ''
        for b in byte_array:
            if b == 0:  # 널문자 만나면 중단
                break
            result += chr(b)
        return result
    
    parsed_data['ModIMSINum'] = bytes_to_string_until_null(packet[436:452])
    parsed_data['ModIMEINum'] = bytes_to_string_until_null(packet[452:476])
    parsed_data['ModIpAddress'] =f"{packet[476]}.{packet[477]}.{packet[478]}.{packet[479]}"
    parsed_data['ModServerIpAddress'] = packet[480:484]
    parsed_data['ModPhonNumber'] = bytes_to_string_until_null(packet[484:495])
    parsed_data['ModEmsFwVer'] = f"{struct.unpack('<h', bytes([packet[496], packet[497]]))[0] / 100:.2f}"
    parsed_data['Gumstick_CurTemper'] = struct.unpack('<h', bytes([packet[498], packet[499]]))[0]
    parsed_data['Gumstick_StartTemper'] = struct.unpack('<h', bytes([packet[500], packet[501]]))[0]
    parsed_data['DlTemperCompensation'] = packet[502]
    parsed_data['UlTemperCompensation'] = packet[503]
    parsed_data['PllRelockCount'] = struct.unpack('<h', bytes([packet[504], packet[505]]))[0]
    parsed_data['DecodedRate'] = packet[506]
    parsed_data['Reserved6p1'] = packet[507]
    parsed_data['DsOutputPower_SISO'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[508], packet[509]]))[0])
    parsed_data['EmsModemReset'] = packet[510]
    parsed_data['Reserved6p2'] = packet[511]
    agc_input_raw = struct.unpack('<h', bytes([packet[512], packet[513]]))[0]
    parsed_data['AGC_Input_Power'] = f"{agc_input_raw / 10:.1f}"
    parsed_data['DsOutputPower_MIMO'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[514], packet[515]]))[0])
    parsed_data['Actual_Orientation'] = struct.unpack('<h', bytes([packet[516], packet[517]]))[0]
    parsed_data['Actual_Tilt'] = struct.unpack('<h', bytes([packet[518], packet[519]]))[0]
    parsed_data['Reserved6p3'] = packet[520:576]
    #DU Control
    parsed_data['InitCheckNum'] = packet[576:580]
    parsed_data['ConMuFlag'] = packet[580:604]
    parsed_data['ConSysTime_Year'] = '.'.join(['{:02d}'.format((packet[604] << 8) | packet[605]), '{:02d}'.format(packet[606]), '{:02d}'.format(packet[607])])
    parsed_data['ConSysTime_hour'] = ':'.join(['{:02d}'.format(packet[608]), '{:02d}'.format(packet[609]), '{:02d}'.format(packet[610])])
    parsed_data['RptMakerCode'] = packet[611]
    parsed_data['SysTemperHighLvl'] = packet[612]
    parsed_data['SysTemperLowLvl'] = packet[613]
    parsed_data['SubInitCheckNum'] = packet[614]
    parsed_data['DebugMode'] = packet[615]
    parsed_data['SuEnableInfo'] = packet[616:628]
    # SU Enable Info 비트 추출 (packet[616]의 비트 0~3)
    su_enable_bits = {
        'SU1_ENABLE': (packet[616] >> 0) & 1,  # 비트 0
        'SU2_ENABLE': (packet[616] >> 1) & 1,  # 비트 1
        'SU3_ENABLE': (packet[616] >> 2) & 1,  # 비트 2
        'SU4_ENABLE': (packet[616] >> 3) & 1   # 비트 3
    }
    parsed_data['SuEnableBits'] = su_enable_bits
    

    parsed_data['MaskMuAlarm'] = list(packet[628:640])
    
    # packet[635]에서 0번째, 2번째, 5번째 비트 추출
    dl_alc_bits = {
        'SISO_MASK_DL_ALC': (packet[635] >> 0) & 1,  # 비트 0
        'MIMO_MASK_DL_ALC': (packet[635] >> 2) & 1,  # 비트 2
        'EMS_DU_Link_MASK': (packet[635] >> 5) & 1   # 비트 5
    }
    parsed_data['DL_ALC_Bits'] = dl_alc_bits

    # packet[634]에서 0번째, 1번째, 2번째, 3번째 비트 추출
    det_mask_bits = {
        'LD1_DET_DL0_SISO_MASK': (packet[634] >> 0) & 1,  # 비트 0
        'LD2_DET_DL1_MIMO_MASK': (packet[634] >> 1) & 1,  # 비트 1
        'PD1_DET_UL0_SISO_MASK': (packet[634] >> 2) & 1,  # 비트 2
        'PD2_DET_UL1_MIMO_MASK': (packet[634] >> 3) & 1   # 비트 3
    }
    parsed_data['DET_MASK_Bits'] = det_mask_bits

        # 알람 비트 매핑 정의
    alarm_mask_bit_map = [
        {'bit': 1,  'id': 'alarm_mask_madc'},
        {'bit': 2,  'id': 'alarm_mask_ac'},
        {'bit': 3,  'id': 'alarm_mask_temp'},
        {'bit': 4,  'id': 'alarm_mask_bat'},
        {'bit': 49, 'id': 'alarm_mask_fpga_link'},
        {'bit': 53, 'id': 'alarm_mask_if_pll'},
        {'bit': 54, 'id': 'alarm_mask_sync_pll'},
        {'bit': 52, 'id': 'alarm_mask_tsync_link'},  # 비트 51 → 52로 수정
        {'bit': 66, 'id': 'alarm_mask_decoding'},
        {'bit': 70, 'id': 'alarm_mask_aa_link'}
    ]

    # Mask 알람 비트 추출 함수
    def get_mask_alarm_bit(mask_bytes, bit_position):
        byte_index = (bit_position - 1) // 8
        bit_in_byte = (bit_position - 1) % 8
        if byte_index < len(mask_bytes):
            return (mask_bytes[byte_index] >> bit_in_byte) & 1
        return 0
    
    # 각 Mask 알람 비트 상태 추출
    mask_alarm_status = {}
    for alarm in alarm_mask_bit_map:
        mask_alarm_status[alarm['id']] = get_mask_alarm_bit(packet[628:640], alarm['bit'])
    
    parsed_data['MaskAlarmStatus'] = mask_alarm_status

    



    parsed_data['MaskSuLinkFail'] = packet[640:652]

    # SuLinkFail에서 1비트씩 추출 - SU1~SU4만
    su_mask_link_fail_bits = {
        'SU1_MASK_LINK_FAIL': (packet[640] >> 0) & 1,  # 비트 0
        'SU2_MASK_LINK_FAIL': (packet[640] >> 1) & 1,  # 비트 1
        'SU3_MASK_LINK_FAIL': (packet[640] >> 2) & 1,  # 비트 2
        'SU4_MASK_LINK_FAIL': (packet[640] >> 3) & 1   # 비트 3
        #추후 SU5, SU6 추가 해야할수도 있음
    }
    parsed_data['MaskSuLinkFail'] = su_mask_link_fail_bits
    
    parsed_data['MaskSuSumAlarm'] = packet[652:664]
    parsed_data['MaskSuRptAlarm'] = packet[664:676]
    parsed_data['ConEmsModemReset'] = packet[676]
    parsed_data['DownloadPath_GuiOrEms'] = packet[677]
    parsed_data['PollingTime'] = struct.unpack('<H', bytes([packet[678], packet[679]]))[0]
    parsed_data['ApiInitMode'] = packet[680]
    parsed_data['AttTestMode'] = packet[681]
    parsed_data['SuId'] = packet[682]
    parsed_data['DL_UL_TEST'] = packet[683]
    parsed_data['LocalInfo'] = packet[684:744]
    parsed_data['SuOpticalEnStatus'] = packet[744]
    parsed_data['PreStaAlarm'] = packet[745:757] 
    parsed_data['Mu_Su_Buadrate'] = packet[757]
    parsed_data['ModemOnOff'] = packet[758]
    parsed_data['RsrpOffset'] = packet[759]
    parsed_data['SuOpticalEnStatus'] = packet[744]
    parsed_data['PreStaAlarm'] = packet[745:757] # Changed to 745:757
    parsed_data['Mu_Su_Buadrate'] = packet[757]
    parsed_data['ModemOnOff'] = packet[758]
    parsed_data['RsrpOffset'] = packet[759]
    #RF 제어
    parsed_data['ALC_DL0_SISO_Mode'] = packet[760]
    parsed_data['ALC_DL1_MIMO_Mode'] = packet[761]
    parsed_data['ALC_UL0_SISO_Mode'] = packet[762]
    parsed_data['ALC_UL1_MIMO_Mode'] = packet[763]
    # ALC Level (1dBm 단위)
    parsed_data['ALC_DL0_SISO_Level'] = convert_to_1dbm(struct.unpack('<h', bytes([packet[764], packet[765]]))[0])
    parsed_data['ALC_DL1_MIMO_Level'] = convert_to_1dbm(struct.unpack('<h', bytes([packet[766], packet[767]]))[0])
    parsed_data['ALC_UL0_SISO_Level'] = convert_to_1dbm(struct.unpack('<h', bytes([packet[768], packet[769]]))[0])
    parsed_data['ALC_UL1_MIMO_Level'] = convert_to_1dbm(struct.unpack('<h', bytes([packet[770], packet[771]]))[0])
    parsed_data['SISO_RF_DET_DL0_OUT_High'] = struct.unpack('<h', bytes([packet[772], packet[773]]))[0]
    parsed_data['SISO_RF_DET_UL0_OUT_High'] = struct.unpack('<h', bytes([packet[774], packet[775]]))[0]
    parsed_data['MIMO_RF_DET_DL1_OUT_High'] = struct.unpack('<h', bytes([packet[776], packet[777]]))[0]
    parsed_data['MIMO_RF_DET_UL1_OUT_High'] = struct.unpack('<h', bytes([packet[778], packet[779]]))[0]
    # SISO/MIMO OPTIC DET Low (0.1dBm 단위로 변환)
    parsed_data['LD1_DET_DL0_SISO_Low'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[780], packet[781]]))[0])
    parsed_data['LD2_DET_DL1_MIMO_Low'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[782], packet[783]]))[0])
    parsed_data['PD1_DET_UL0_SISO_Low'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[784], packet[785]]))[0])
    parsed_data['PD2_DET_UL1_MIMO_Low'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[786], packet[787]]))[0])
    parsed_data['LD3_DET_DL0_SISO_Low'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[788], packet[789]]))[0])
    parsed_data['LD4_DET_DL1_MIMO_Low'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[790], packet[791]]))[0])
    parsed_data['PD3_DET_UL0_SISO_Low'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[792], packet[793]]))[0])
    parsed_data['PD4_DET_UL1_MIMO_Low'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[794], packet[795]]))[0])
    parsed_data['LD1_DET_DL0_SISO_Offset'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[796], packet[797]]))[0])
    parsed_data['LD2_DET_DL1_MIMO_Offset'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[798], packet[799]]))[0])
    parsed_data['PD1_DET_UL0_SISO_Offset'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[800], packet[801]]))[0])
    parsed_data['PD2_DET_UL1_MIMO_Offset'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[802], packet[803]]))[0])
    parsed_data['LD3_DET_DL0_SISO_Offset'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[804], packet[805]]))[0])
    parsed_data['LD4_DET_DL1_MIMO_Offset'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[806], packet[807]]))[0])
    parsed_data['PD3_DET_UL0_SISO_Offset'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[808], packet[809]]))[0])
    parsed_data['PD4_DET_UL1_MIMO_Offset'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[810], packet[811]]))[0])
    # DU ATT (0.5dB 단위로 변환)
    parsed_data['DU_DlManualAtten_SISO'] = convert_att_4_to_2(packet[812])
    parsed_data['DU_DlSubAtten_SISO'] = convert_att_4_to_2(packet[813])
    parsed_data['DU_DlManualAtten_MIMO'] = convert_att_4_to_2(packet[814])
    parsed_data['DU_DlSubAtten_MIMO'] = convert_att_4_to_2(packet[815])
    parsed_data['DU_UlManualAtten_SISO'] = convert_att_4_to_2(packet[816])
    parsed_data['DU_UlSubAtten_SISO'] = convert_att_4_to_2(packet[817])
    parsed_data['DU_UlIsoAtten_SISO'] = convert_iso_att(packet[818])
    parsed_data['DU_UlManualAtten_MIMO'] = convert_att_4_to_2(packet[819])
    parsed_data['DU_UlSubAtten_MIMO'] = convert_att_4_to_2(packet[820])
    parsed_data['DU_UlIsoAtten_MIMO'] = convert_iso_att(packet[821])
    parsed_data['SU_DlManualAtten_SISO'] = packet[822]
    parsed_data['SU_DlSubAtten_SISO'] = packet[823]
    parsed_data['SU_DlManualAtten_MIMO'] = packet[824]
    parsed_data['SU_DlSubAtten_MIMO'] = packet[825]
    parsed_data['SU_UlManualAtten_SISO'] = packet[826]
    parsed_data['SU_UlSubAtten_SISO'] = packet[827]
    parsed_data['SU_UlManualAtten_MIMO'] = packet[828]
    parsed_data['SU_UlSubAtten_MIMO'] = packet[829]
    parsed_data['LicPassword'] = struct.unpack('<h', bytes([packet[830], packet[831]]))[0]
    parsed_data['DL_OutputOffset_SISO'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[832], packet[833]]))[0])
    parsed_data['DL_OutputOffset_MIMO'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[834], packet[835]]))[0])
    parsed_data['UL_InputOffset_SISO'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[836], packet[837]]))[0])
    parsed_data['UL_InputOffset_MIMO'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[838], packet[839]]))[0])
    parsed_data['SU_UlCasSisoAtten_SISO'] = packet[840]
    parsed_data['SU_UlCasSisoAtten_MIMO'] = packet[841]
    parsed_data['SdOnOffSiso'] = packet[842]
    parsed_data['SdOnOffMimo'] = packet[843]
    parsed_data['DuFixBeam'] = packet[844]
    parsed_data['Reserved4_Local'] = packet[845:852]
    parsed_data['Dl_Siso_Att_Test'] = convert_att_test(struct.unpack('<h', bytes([packet[852], packet[853]]))[0])
    parsed_data['Dl_Mimo_Att_Test'] = convert_att_test(struct.unpack('<h', bytes([packet[854], packet[855]]))[0])
    parsed_data['Ul_Siso_Att_Test'] = convert_att_test(struct.unpack('<h', bytes([packet[856], packet[857]]))[0])
    parsed_data['Ul_Mimo_Att_Test'] = convert_att_test(struct.unpack('<h', bytes([packet[858], packet[859]]))[0])
    parsed_data['Reserved10p1'] = packet[860:892]
    # MVBX 제어
    parsed_data['Mvbx_BeamSet'] = packet[892]
    parsed_data['InstallUseMode'] = packet[893]
    parsed_data['Reserved14'] = packet[894:896]
    parsed_data['Mvbx_FpagImageSize'] = packet[896:900]
    parsed_data['Mvbx_FpagImageStartAddressOffset'] = packet[900:904]
    parsed_data['Reserved15'] = packet[904:920]
    parsed_data['FpgaWriteAddress'] = packet[920:922]
    parsed_data['FpgaWriteData'] = packet[922:924]
    parsed_data['FpgaReadAddress'] = packet[924:926]
    parsed_data['FpgaReadData'] = packet[926:928]
    parsed_data['Reserved31'] = packet[928:940]
    parsed_data['Mvbx_TddSignalMode'] = packet[940]
    parsed_data['Mvbx_RsAgcThreshold'] = packet[941]
    parsed_data['Mvbx_RsAgcMode'] = packet[942]
    parsed_data['Reserved32'] = packet[943]
    parsed_data['Mvbx_Mv2853TxGainSiso'] = packet[944]
    parsed_data['Mvbx_Mv2853RxGainSiso'] = packet[945]
    parsed_data['Mvbx_Mv2850TxGainSiso'] = packet[946]
    parsed_data['Mvbx_Mv2850RxGainSiso'] = packet[947]
    parsed_data['Mvbx_Mv2853TxGainMimo'] = packet[948]
    parsed_data['Mvbx_Mv2853RxGainMimo'] = packet[949]
    parsed_data['Mvbx_Mv2850TxGainMimo'] = packet[950]
    parsed_data['Mvbx_Mv2850RxGainMimo'] = packet[951]
    parsed_data['Mvbx_TxGainSetSiso'] = packet[952]
    parsed_data['Mvbx_RxGainSetSiso'] = packet[953]
    parsed_data['Mvbx_TxGainSetMiso'] = packet[954]
    parsed_data['Mvbx_RxGainSetMiso'] = packet[955]
    parsed_data['beam_info_pss_type'] = struct.unpack('<I', bytes([packet[956], packet[957], packet[958], packet[959]]))[0]
    parsed_data['beam_info_adc_sel'] = struct.unpack('<I', bytes([packet[960], packet[961], packet[962], packet[963]]))[0]
    parsed_data['beam_info_spg '] = struct.unpack('<I', bytes([packet[964], packet[965], packet[966], packet[967]]))[0]
    parsed_data['beam_info_ssbIdx'] = struct.unpack('<I', bytes([packet[968], packet[969], packet[970], packet[971]]))[0]
    parsed_data['beam_info_beamID'] = struct.unpack('<h', bytes([packet[972], packet[973]]))[0]
    parsed_data['Reserved34'] = struct.unpack('<h', bytes([packet[974], packet[975]]))[0]
    parsed_data['beam_info_energy'] = struct.unpack('<I', bytes([packet[976], packet[977], packet[978], packet[979]]))[0]
    parsed_data['beam_info_rsrp '] = struct.unpack('<I', bytes([packet[980], packet[981], packet[982], packet[983]]))[0]
    parsed_data['beam_info_snr'] = struct.unpack('<I', bytes([packet[984], packet[985], packet[986], packet[987]]))[0]
    parsed_data['PllSet'] = struct.unpack('<I', bytes([packet[988], packet[989], packet[990], packet[991]]))[0]
    parsed_data['IsoMeasSet'] = packet[992]
    parsed_data['SuGsOnOff'] = packet[993]
    parsed_data['SuIsoAttSet'] = packet[994]
    parsed_data['GumStick_OnOff'] = packet[995]
    parsed_data['BeamScan_OnOff'] = packet[996]
    parsed_data['IsoDetectMode'] = packet[997]
    parsed_data['ApiLogLevel'] = packet[998]
    parsed_data['ApiAdcSel'] = packet[999]
    parsed_data['ApiSyncPathGain'] = packet[1000]
    parsed_data['ApiDuTimeAdvance'] = packet[1001]
    parsed_data['ApiSuTimeAdvance'] = packet[1002]
    parsed_data['TemperCompensationMode'] = packet[1003]
    parsed_data['ApiVenderFreq'] = struct.unpack('<I', bytes([packet[1004], packet[1005], packet[1006], packet[1007]]))[0]
    parsed_data['ApiGsOutputPowerOffsetSiso'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[1008], packet[1009]]))[0])
    parsed_data['BeamAntSelect'] = packet[1010]
    parsed_data['DecodeRecoveryFuncOnOff'] = packet[1011]
    parsed_data['gNB_ScanOnOff'] = packet[1012]
    parsed_data['SuEndMode'] = packet[1013]
    parsed_data['ApiGsOutputPowerOffsetMimo'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[1014], packet[1015]]))[0])
    parsed_data['gNB_Vendor'] = packet[1016]
    parsed_data['Gs_Gain_Siso'] = packet[1017]
    parsed_data['Gs_Gain_Mimo'] = packet[1018]
    parsed_data['ApiInitRetryMode'] = packet[1019]
    parsed_data['Orientation'] = f"{struct.unpack('<h', bytes([packet[1020], packet[1021]]))[0]:.3f}"
    parsed_data['Tilt'] = f"{struct.unpack('<h', bytes([packet[1022], packet[1023]]))[0]:.3f}"
    parsed_data['GS_AttenOffset_DL_Siso'] = struct.unpack('<b', bytes([packet[1024]]))[0]
    parsed_data['GS_AttenOffset_DL_Mimo'] = struct.unpack('<b', bytes([packet[1025]]))[0]
    parsed_data['GS_AttenOffset_UL_Siso'] = struct.unpack('<b', bytes([packet[1026]]))[0]
    parsed_data['GS_AttenOffset_UL_Mimo'] = struct.unpack('<b', bytes([packet[1027]]))[0]
    parsed_data['ConSerialNum'] = ''.join([chr(b) for b in packet[1028:1044] if b != 0])
    parsed_data['AomTemperConperMode'] = packet[1044]
    parsed_data['GS_AttenOffset_30by15_DL_Siso'] = packet[1045]
    parsed_data['GS_AttenOffset_30by30_DL_Siso'] = packet[1046]
    parsed_data['GS_AttenOffset_60by15_DL_Siso'] = packet[1047]
    parsed_data['GS_AttenOffset_60by30_DL_Siso'] = packet[1048]
    parsed_data['GS_AttenOffset_60by60_DL_Siso'] = packet[1049]
    parsed_data['GS_AttenOffset_30by15_DL_Mimo'] = packet[1050]
    parsed_data['GS_AttenOffset_30by30_DL_Mimo'] = packet[1051]
    parsed_data['GS_AttenOffset_60by15_DL_Mimo'] = packet[1052]
    parsed_data['GS_AttenOffset_60by30_DL_Mimo'] = packet[1053]
    parsed_data['GS_AttenOffset_60by60_DL_Mimo'] = packet[1054]
    parsed_data['GS_AttenOffset_30by15_UL_Siso'] = packet[1055]
    parsed_data['GS_AttenOffset_30by30_UL_Siso'] = packet[1056]
    parsed_data['GS_AttenOffset_60by15_UL_Siso'] = packet[1057]
    parsed_data['GS_AttenOffset_60by30_UL_Siso'] = packet[1058]
    parsed_data['GS_AttenOffset_60by60_UL_Siso'] = packet[1059]
    parsed_data['GS_AttenOffset_30by15_UL_Mimo'] = packet[1060]
    parsed_data['GS_AttenOffset_30by30_UL_Mimo'] = packet[1061]
    parsed_data['GS_AttenOffset_60by15_UL_Mimo'] = packet[1062]
    parsed_data['GS_AttenOffset_60by30_UL_Mimo'] = packet[1063]
    parsed_data['GS_AttenOffset_60by60_UL_Mimo'] = packet[1064]
    parsed_data['Reserved41'] = packet[1065:1089]
    parsed_data['LowRsrpStillTime'] = packet[1089]
    parsed_data['LowRsrpLevel'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[1090], packet[1091]]))[0])
    parsed_data['SU_DlCasSisoAtten_SISO'] = packet[1092]
    parsed_data['SU_DlCasSisoAtten_MIMO'] = packet[1093]
    parsed_data['SU_DlCasSisoAttenTest_SISO'] = packet[1094]
    parsed_data['SU_DlCasSisoAttenTest_MIMO'] = packet[1095]
    parsed_data['SU_UlCasSisoAttenTest_SISO'] = packet[1096]
    parsed_data['SU_UlCasSisoAttenTest_MIMO'] = packet[1097]
    parsed_data['Reserved41p1'] = packet[1098:1101]
    parsed_data['PciResetOnOff'] = packet[1101]
    parsed_data['PciNo'] = struct.unpack('<h', bytes([packet[1102], packet[1103]]))[0]
    parsed_data['PciTime'] = packet[1104]
    parsed_data['Reserved42'] = packet[1105:1112]
    # Reserved42 감지 시 RX 박스 끄기
    socketio.emit("rx_off")

    return parsed_data

def parse_AllStatusPacket4(packet):


    parsed_data = {}
    
    # 단위 변환 함수들
    def convert_to_01dbm(raw_value):
        """0.1dBm 단위로 변환 (예: -517 → -51.7 dBm)"""
        return round(raw_value / 10.0, 1)
    
    def convert_att_4_to_2(raw_value):
        """ATT 변환 (4→2dB, Step: 0.5dB)"""
        return raw_value * 0.5
    
    def convert_to_1dbm(raw_value):
        """1dBm 단위로 변환"""
        return raw_value
    
    def convert_iso_att(raw_value):
        """ISO ATT 변환 (4→2dB, Step: 0.5dB, Range: 0~20dB)"""
        return raw_value * 0.5
    
    def convert_att_test(raw_value):
        """ATT Test 변환 (50: 5dB, 0.5dB 단위, Range: 0~30dB)"""
        return raw_value * 0.5
    
    def convert_polling_time(raw_value):
        """Polling Time 변환 (2바이트 uint, 범위: 100~5,000ms)"""
        return raw_value  # 이미 ms 단위로 저장되어 있음
    
    #su1 상태
    parsed_data['Rcv_Main_Sys'] = packet[0]
    # Rcv_Main_Sys 감지 시 RX 박스 켜기
    socketio.emit("rx_on")
    parsed_data['Rcv_Sub_Sys'] = packet[1]
    parsed_data['Rcv_Object'] = packet[2]
    parsed_data['Trans_Main_Sys'] = packet[3]
    # Trans_Main_Sys 감지 시 TX 박스 토글 (1이면 켜기, 0이면 끄기)
    if packet[3] != 0:
        socketio.emit("tx_on")
    else:
        socketio.emit("tx_off")
    parsed_data['Trans_Sub_Sys'] = packet[4]
    parsed_data['Trans_Object'] = packet[5]
    parsed_data['CMD'] = packet[6]
    parsed_data['EQUIP_TYPE'] = packet[7]
    parsed_data['RESERVED'] = packet[8:10]
    parsed_data['SubData_Size'] = struct.unpack('<h', bytes([packet[10], packet[11]]))[0]
    parsed_data['McuSwVer'] = f"{packet[13]}.{packet[12]}" 
    parsed_data['RptMaker'] = packet[14]
    parsed_data['DU_SU_Status'] = packet[15]
    parsed_data['Reserved0_1'] = packet[16]
    parsed_data['StatusPollingUnit'] = packet[17]
    parsed_data['RtpKind'] = packet[18]
    parsed_data['Reserved0'] = packet[19]
    parsed_data['StaMuAlarm'] = list(packet[20:32])
    
    # 알람 비트 매핑 정의
    alarm_bit_map = [
        {'bit': 1,  'id': 'su3_alarm_dc'},
        {'bit': 2,  'id': 'su3_alarm_ac'},
        {'bit': 3,  'id': 'su3_alarm_temp'},
        {'bit': 4,  'id': 'su3_alarm_bat'},
        {'bit': 48, 'id': 'su3_alarm_du_link'},
        {'bit': 53, 'id': 'su3_alarm_if_pll'},
        {'bit': 52, 'id': 'su3_alarm_tsync_link'},  # 비트 51 → 52로 수정
        {'bit': 63, 'id': 'su3_alarm_ref_pll'},
        {'bit': 70, 'id': 'su3_alarm_aa_link'}
    ]
    
    # 알람 비트 추출 함수
    def get_alarm_bit(alarm_bytes, bit_position):
        byte_index = (bit_position - 1) // 8
        bit_in_byte = (bit_position - 1) % 8
        if byte_index < len(alarm_bytes):
            return (alarm_bytes[byte_index] >> bit_in_byte) & 1
        return 0
    
    # 각 알람 비트 상태 추출
    alarm_status = {}
    for alarm in alarm_bit_map:
        alarm_status[alarm['id']] = get_alarm_bit(packet[20:32], alarm['bit'])
    
    parsed_data['AlarmStatus'] = alarm_status
    
    # ALA2 링크 알람 비트 추출 (packet[21]의 비트 0~3)
    ala2_link_alarms = {
        'ALA2_SU1_LINK_ALARM': (packet[21] >> 0) & 1,  # 비트 0
        'ALA2_SU2_LINK_ALARM': (packet[21] >> 1) & 1,  # 비트 1
        'ALA2_SU3_LINK_ALARM': (packet[21] >> 2) & 1,  # 비트 2
        'ALA2_SU4_LINK_ALARM': (packet[21] >> 3) & 1   # 비트 3
    }
    parsed_data['ALA2_Link_Alarms'] = ala2_link_alarms
    parsed_data['SuLinkFail'] = packet[32:44]
    # SuLinkFail에서 1비트씩 추출 - SU1~SU4만
    su_link_fail_bits = {
        'SU1_LINK_FAIL': (packet[32] >> 0) & 1,  # 비트 0
        'SU2_LINK_FAIL': (packet[32] >> 1) & 1,  # 비트 1
        'SU3_LINK_FAIL': (packet[32] >> 2) & 1,  # 비트 2
        'SU4_LINK_FAIL': (packet[32] >> 3) & 1   # 비트 3
        #추후 SU5, SU6 추가 해야할수도 있음
    }
    parsed_data['SuLinkFailBits'] = su_link_fail_bits
    parsed_data['SuSumAlarm'] = packet[44:56]
    parsed_data['SuRptAlarm'] = packet[56:68] 
    parsed_data['StsApiVenderFreq'] = struct.unpack('<I', bytes([packet[68], packet[69], packet[70], packet[71]]))[0]
    parsed_data['System_Year'] = '.'.join(['{:02d}'.format((packet[72] << 8) | packet[73]), '{:02d}'.format(packet[74]), '{:02d}'.format(packet[75])])
    parsed_data['System_hour'] = ':'.join(['{:02d}'.format(packet[76]), '{:02d}'.format(packet[77]), '{:02d}'.format(packet[78])])
    parsed_data['SysTemper'] = packet[79]
    parsed_data['PackSendCount'] = packet[80:120]
    parsed_data['PackErrorCount'] = packet[120:160]
    parsed_data['FPGA_Boot_Status'] = packet[160]
    parsed_data['FPGA_Init_Status'] = packet[161]
    parsed_data['Beam_Scan_Status'] = packet[162]
    parsed_data['DU_SumAlarmStatus'] = packet[163]
    parsed_data['ALC_Atten_DL0_SISO'] = struct.unpack('<h', bytes([packet[164], packet[165]]))[0]
    parsed_data['ALC_Atten_DL1_MIMO'] = struct.unpack('<h', bytes([packet[166], packet[167]]))[0]
    parsed_data['ALC_Atten_UL0_SISO'] = struct.unpack('<h', bytes([packet[168], packet[169]]))[0]
    parsed_data['ALC_Atten_UL1_MIMO'] = struct.unpack('<h', bytes([packet[170], packet[171]]))[0]
    # SISO/MIMO OPTIC DET (0.1dBm 단위로 변환)
    parsed_data['LD1_DET_DL0_SISO'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[172], packet[173]]))[0])
    parsed_data['LD2_DET_DL1_MIMO'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[174], packet[175]]))[0])
    parsed_data['PD1_DET_UL0_SISO'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[176], packet[177]]))[0])
    parsed_data['PD2_DET_UL1_MIMO'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[178], packet[179]]))[0])
    # SISO/MIMO RF DET (0.1dBm 단위로 변환)
    parsed_data['SISO_RF_DET_DL0_OUT'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[180], packet[181]]))[0])
    parsed_data['SISO_RF_DET_UL0_OUT'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[182], packet[183]]))[0])
    parsed_data['MIMO_RF_DET_DL1_OUT'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[184], packet[185]]))[0])
    parsed_data['MIMO_RF_DET_UL1_OUT'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[186], packet[187]]))[0])
    parsed_data['LD3_DET_DL0_SISO'] = struct.unpack('<h', bytes([packet[188], packet[189]]))[0]
    parsed_data['LD4_DET_DL1_MIMO'] = struct.unpack('<h', bytes([packet[190], packet[191]]))[0]
    parsed_data['PD3_DET_UL0_SISO'] = struct.unpack('<h', bytes([packet[192], packet[193]]))[0]
    parsed_data['PD4_DET_UL1_MIMO'] = struct.unpack('<h', bytes([packet[194], packet[195]]))[0]
    parsed_data['SuModeStatus'] = packet[196]
    parsed_data['SdStatusSiso'] = packet[197]
    parsed_data['SdStatusMimo'] = packet[198]
    parsed_data['Reserved3'] = packet[199:220] 
    #MVBX 상태
    parsed_data['FPGA_Ver'] = '.'.join([str(packet[220]), str(packet[221]), str(packet[222])])
    parsed_data['ApiOldNewVer'] = packet[223]
    parsed_data['Reserved3p1'] = packet[224:232] 
    parsed_data['Gumstick_Ver'] = '.'.join([str(packet[232]), str(packet[233]), str(packet[234])])
    parsed_data['SyncStatus'] = packet[235]
    parsed_data['TryBeamScanCont'] = struct.unpack('<h', bytes([packet[236], packet[237]]))[0]
    parsed_data['Reserved4'] = packet[238:244]
    parsed_data['MVBX_pci'] = struct.unpack('<h', bytes([packet[244], packet[245]]))[0]
    parsed_data['MVBX_ssb'] = struct.unpack('<h', bytes([packet[246], packet[247]]))[0]
    parsed_data['MVBX_rsrp'] = f"{struct.unpack('<f', bytes(packet[248:252]))[0]:.2f} [dBm]"
    parsed_data['MVBX_snr'] = f"{struct.unpack('<f', bytes(packet[252:256]))[0]:.2f} [dB]"
    parsed_data['MVBX_BeamInfo_beamId1'] = struct.unpack('<h', bytes([packet[256], packet[257]]))[0]
    parsed_data['MVBX_BeamInfo_beamId2'] = struct.unpack('<h', bytes([packet[258], packet[259]]))[0]
    parsed_data['MVBX_BeamInfo_beamId3'] = struct.unpack('<h', bytes([packet[260], packet[261]]))[0]
    parsed_data['MVBX_BeamInfo_beamId4'] = struct.unpack('<h', bytes([packet[262], packet[263]]))[0]
    parsed_data['MVBX_BeamInfo_pci1'] = struct.unpack('<h', bytes([packet[264], packet[265]]))[0]
    parsed_data['MVBX_BeamInfo_pci2'] = struct.unpack('<h', bytes([packet[266], packet[267]]))[0]
    parsed_data['MVBX_BeamInfo_pci3'] = struct.unpack('<h', bytes([packet[268], packet[269]]))[0]
    parsed_data['MVBX_BeamInfo_pci4'] = struct.unpack('<h', bytes([packet[270], packet[271]]))[0]
    parsed_data['MVBX_BeamInfo_ssbldx1'] = struct.unpack('<I', bytes([packet[272], packet[273], packet[274], packet[275]]))[0]
    parsed_data['MVBX_BeamInfo_ssbldx2'] = struct.unpack('<I', bytes([packet[276], packet[277], packet[278], packet[279]]))[0]
    parsed_data['MVBX_BeamInfo_ssbldx3'] = struct.unpack('<I', bytes([packet[280], packet[281], packet[282], packet[283]]))[0]
    parsed_data['MVBX_BeamInfo_ssbldx4'] = struct.unpack('<I', bytes([packet[284], packet[285], packet[286], packet[287]]))[0]
    parsed_data['MVBX_BeamInfo_energy1'] = struct.unpack('<I', bytes([packet[288], packet[289], packet[290], packet[291]]))[0]
    parsed_data['MVBX_BeamInfo_energy2'] = struct.unpack('<I', bytes([packet[292], packet[293], packet[294], packet[295]]))[0]
    parsed_data['MVBX_BeamInfo_energy3'] = struct.unpack('<I', bytes([packet[296], packet[297], packet[298], packet[299]]))[0]
    parsed_data['MVBX_BeamInfo_energy4'] = struct.unpack('<I', bytes([packet[300], packet[301], packet[302], packet[303]]))[0]
    parsed_data['MVBX_BeamInfo_psstype1'] = struct.unpack('<I', bytes([packet[304], packet[305], packet[306], packet[307]]))[0]
    parsed_data['MVBX_BeamInfo_psstype2'] = struct.unpack('<I', bytes([packet[308], packet[309], packet[310], packet[311]]))[0]
    parsed_data['MVBX_BeamInfo_psstype3'] = struct.unpack('<I', bytes([packet[312], packet[313], packet[314], packet[315]]))[0]
    parsed_data['MVBX_BeamInfo_psstype4'] = struct.unpack('<I', bytes([packet[316], packet[317], packet[318], packet[319]]))[0]
    # SNR 값 처리 (소수점 2자리, -999이면 "- - -")
    snr1 = struct.unpack('<f', bytes(packet[320:324]))[0]
    parsed_data['MVBX_BeamInfo_snr1'] = "- - -" if snr1 == -999 else f"{snr1:.2f}"
    
    snr2 = struct.unpack('<f', bytes(packet[324:328]))[0]
    parsed_data['MVBX_BeamInfo_snr2'] = "- - -" if snr2 == -999 else f"{snr2:.2f}"
    
    snr3 = struct.unpack('<f', bytes(packet[328:332]))[0]
    parsed_data['MVBX_BeamInfo_snr3'] = "- - -" if snr3 == -999 else f"{snr3:.2f}"
    
    snr4 = struct.unpack('<f', bytes(packet[332:336]))[0]
    parsed_data['MVBX_BeamInfo_snr4'] = "- - -" if snr4 == -999 else f"{snr4:.2f}"
    
    # RSRP 값 처리 (소수점 2자리, -999이면 "- - -")
    rsrp1 = struct.unpack('<f', bytes(packet[336:340]))[0]
    parsed_data['MVBX_BeamInfo_rsrp1'] = "- - -" if rsrp1 == -999 else f"{rsrp1:.2f}"
    
    rsrp2 = struct.unpack('<f', bytes(packet[340:344]))[0]
    parsed_data['MVBX_BeamInfo_rsrp2'] = "- - -" if rsrp2 == -999 else f"{rsrp2:.2f}"
    
    rsrp3 = struct.unpack('<f', bytes(packet[344:348]))[0]
    parsed_data['MVBX_BeamInfo_rsrp3'] = "- - -" if rsrp3 == -999 else f"{rsrp3:.2f}"
    
    rsrp4 = struct.unpack('<f', bytes(packet[348:352]))[0]
    parsed_data['MVBX_BeamInfo_rsrp4'] = "- - -" if rsrp4 == -999 else f"{rsrp4:.2f}"
    parsed_data['pss_pulse_count'] = struct.unpack('<I', bytes([packet[352], packet[353], packet[354], packet[355]]))[0]
    parsed_data['decoded_ssb_count'] = struct.unpack('<I', bytes([packet[356], packet[357], packet[358], packet[359]]))[0]
    parsed_data['decoded_ssb_no_error_count'] = struct.unpack('<I', bytes([packet[360], packet[361], packet[362], packet[363]]))[0]
    parsed_data['LicStatus'] = packet[364]
    parsed_data['LicStartDateMonth'] = packet[365]
    parsed_data['LicStartDateDay'] = packet[366]
    parsed_data['LicStopDateMonth'] = packet[367]
    parsed_data['LicStopDateDay'] = packet[368]
    parsed_data['Reserved4_new'] = packet[369:412]
    # Modem 상태
    parsed_data['ModRsrp'] = struct.unpack('<h', bytes([packet[412], packet[413]]))[0]
    parsed_data['ModRsrq'] = struct.unpack('<h', bytes([packet[414], packet[415]]))[0]
    parsed_data['InitTemper'] = packet[416]
    parsed_data['ModVersion'] = f"{packet[417] / 100:.2f}"
    parsed_data['ModLanUseMode'] = packet[418]
    parsed_data['ModPci'] = packet[419]
    parsed_data['SU_DlIsoAtten_SISO'] = packet[420]
    parsed_data['SU_DlIsoAtten_MIMO'] = packet[421]
    parsed_data['SU_UlIsoAtten_SISO'] = packet[422]
    parsed_data['SU_UlIsoAtten_MIMO'] = packet[423]
    parsed_data['SU_ISO_SATUS'] = packet[424:428]
    
    parsed_data['DU_ISO_STATUS'] = packet[428]
    
    parsed_data['ModStatus'] = packet[429]
    parsed_data['ModSinr'] = packet[430]
    parsed_data['Reserved6'] = packet[431]
    parsed_data['ModRssi'] = struct.unpack('<h', bytes([packet[432], packet[433]]))[0]
    parsed_data['ModTxPwr'] = struct.unpack('<h', bytes([packet[434], packet[435]]))[0]
    
    """
    # 16진수 바이트 배열을 10진수 문자열로 변환 (15자리만)
    def hex_bytes_to_decimal_string(byte_array):
        try:
            # 16진수 값을 10진수 문자열로 변환
            result = ''.join([f"{b:02d}" for b in byte_array if b != 0])
            # 15자리만 사용
            return result[:15] if result else "N/A"
        except:
            return "N/A"
    """
    
    # 널문자를 만날 때까지 문자열 변환
    def bytes_to_string_until_null(byte_array):
        result = ''
        for b in byte_array:
            if b == 0:  # 널문자 만나면 중단
                break
            result += chr(b)
        return result
    
    parsed_data['ModIMSINum'] = bytes_to_string_until_null(packet[436:452])
    parsed_data['ModIMEINum'] = bytes_to_string_until_null(packet[452:476])
    parsed_data['ModIpAddress'] =f"{packet[476]}.{packet[477]}.{packet[478]}.{packet[479]}"
    parsed_data['ModServerIpAddress'] = packet[480:484]
    parsed_data['ModPhonNumber'] = bytes_to_string_until_null(packet[484:495])
    parsed_data['ModEmsFwVer'] = f"{struct.unpack('<h', bytes([packet[496], packet[497]]))[0] / 100:.2f}"
    parsed_data['Gumstick_CurTemper'] = struct.unpack('<h', bytes([packet[498], packet[499]]))[0]
    parsed_data['Gumstick_StartTemper'] = struct.unpack('<h', bytes([packet[500], packet[501]]))[0]
    parsed_data['DlTemperCompensation'] = packet[502]
    parsed_data['UlTemperCompensation'] = packet[503]
    parsed_data['PllRelockCount'] = struct.unpack('<h', bytes([packet[504], packet[505]]))[0]
    parsed_data['DecodedRate'] = packet[506]
    parsed_data['Reserved6p1'] = packet[507]
    parsed_data['DsOutputPower_SISO'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[508], packet[509]]))[0])
    parsed_data['EmsModemReset'] = packet[510]
    parsed_data['Reserved6p2'] = packet[511]
    agc_input_raw = struct.unpack('<h', bytes([packet[512], packet[513]]))[0]
    parsed_data['AGC_Input_Power'] = f"{agc_input_raw / 10:.1f}"
    parsed_data['DsOutputPower_MIMO'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[514], packet[515]]))[0])
    parsed_data['Actual_Orientation'] = struct.unpack('<h', bytes([packet[516], packet[517]]))[0]
    parsed_data['Actual_Tilt'] = struct.unpack('<h', bytes([packet[518], packet[519]]))[0]
    parsed_data['Reserved6p3'] = packet[520:576]
    #DU Control
    parsed_data['InitCheckNum'] = packet[576:580]
    parsed_data['ConMuFlag'] = packet[580:604]
    parsed_data['ConSysTime_Year'] = '.'.join(['{:02d}'.format((packet[604] << 8) | packet[605]), '{:02d}'.format(packet[606]), '{:02d}'.format(packet[607])])
    parsed_data['ConSysTime_hour'] = ':'.join(['{:02d}'.format(packet[608]), '{:02d}'.format(packet[609]), '{:02d}'.format(packet[610])])
    parsed_data['RptMakerCode'] = packet[611]
    parsed_data['SysTemperHighLvl'] = packet[612]
    parsed_data['SysTemperLowLvl'] = packet[613]
    parsed_data['SubInitCheckNum'] = packet[614]
    parsed_data['DebugMode'] = packet[615]
    parsed_data['SuEnableInfo'] = packet[616:628]
    # SU Enable Info 비트 추출 (packet[616]의 비트 0~3)
    su_enable_bits = {
        'SU1_ENABLE': (packet[616] >> 0) & 1,  # 비트 0
        'SU2_ENABLE': (packet[616] >> 1) & 1,  # 비트 1
        'SU3_ENABLE': (packet[616] >> 2) & 1,  # 비트 2
        'SU4_ENABLE': (packet[616] >> 3) & 1   # 비트 3
    }
    parsed_data['SuEnableBits'] = su_enable_bits
    

    parsed_data['MaskMuAlarm'] = list(packet[628:640])
    
    # packet[635]에서 0번째, 2번째, 5번째 비트 추출
    dl_alc_bits = {
        'SISO_MASK_DL_ALC': (packet[635] >> 0) & 1,  # 비트 0
        'MIMO_MASK_DL_ALC': (packet[635] >> 2) & 1,  # 비트 2
        'EMS_DU_Link_MASK': (packet[635] >> 5) & 1   # 비트 5
    }
    parsed_data['DL_ALC_Bits'] = dl_alc_bits

    # packet[634]에서 0번째, 1번째, 2번째, 3번째 비트 추출
    det_mask_bits = {
        'LD1_DET_DL0_SISO_MASK': (packet[634] >> 0) & 1,  # 비트 0
        'LD2_DET_DL1_MIMO_MASK': (packet[634] >> 1) & 1,  # 비트 1
        'PD1_DET_UL0_SISO_MASK': (packet[634] >> 2) & 1,  # 비트 2
        'PD2_DET_UL1_MIMO_MASK': (packet[634] >> 3) & 1   # 비트 3
    }
    parsed_data['DET_MASK_Bits'] = det_mask_bits

        # 알람 비트 매핑 정의
    alarm_mask_bit_map = [
        {'bit': 1,  'id': 'alarm_mask_madc'},
        {'bit': 2,  'id': 'alarm_mask_ac'},
        {'bit': 3,  'id': 'alarm_mask_temp'},
        {'bit': 4,  'id': 'alarm_mask_bat'},
        {'bit': 49, 'id': 'alarm_mask_fpga_link'},
        {'bit': 53, 'id': 'alarm_mask_if_pll'},
        {'bit': 54, 'id': 'alarm_mask_sync_pll'},
        {'bit': 52, 'id': 'alarm_mask_tsync_link'},  # 비트 51 → 52로 수정
        {'bit': 66, 'id': 'alarm_mask_decoding'},
        {'bit': 70, 'id': 'alarm_mask_aa_link'}
    ]

    # Mask 알람 비트 추출 함수
    def get_mask_alarm_bit(mask_bytes, bit_position):
        byte_index = (bit_position - 1) // 8
        bit_in_byte = (bit_position - 1) % 8
        if byte_index < len(mask_bytes):
            return (mask_bytes[byte_index] >> bit_in_byte) & 1
        return 0
    
    # 각 Mask 알람 비트 상태 추출
    mask_alarm_status = {}
    for alarm in alarm_mask_bit_map:
        mask_alarm_status[alarm['id']] = get_mask_alarm_bit(packet[628:640], alarm['bit'])
    
    parsed_data['MaskAlarmStatus'] = mask_alarm_status

    



    parsed_data['MaskSuLinkFail'] = packet[640:652]

    # SuLinkFail에서 1비트씩 추출 - SU1~SU4만
    su_mask_link_fail_bits = {
        'SU1_MASK_LINK_FAIL': (packet[640] >> 0) & 1,  # 비트 0
        'SU2_MASK_LINK_FAIL': (packet[640] >> 1) & 1,  # 비트 1
        'SU3_MASK_LINK_FAIL': (packet[640] >> 2) & 1,  # 비트 2
        'SU4_MASK_LINK_FAIL': (packet[640] >> 3) & 1   # 비트 3
        #추후 SU5, SU6 추가 해야할수도 있음
    }
    parsed_data['MaskSuLinkFail'] = su_mask_link_fail_bits
    
    parsed_data['MaskSuSumAlarm'] = packet[652:664]
    parsed_data['MaskSuRptAlarm'] = packet[664:676]
    parsed_data['ConEmsModemReset'] = packet[676]
    parsed_data['DownloadPath_GuiOrEms'] = packet[677]
    parsed_data['PollingTime'] = struct.unpack('<H', bytes([packet[678], packet[679]]))[0]
    parsed_data['ApiInitMode'] = packet[680]
    parsed_data['AttTestMode'] = packet[681]
    parsed_data['SuId'] = packet[682]
    parsed_data['DL_UL_TEST'] = packet[683]
    parsed_data['LocalInfo'] = packet[684:744]
    parsed_data['SuOpticalEnStatus'] = packet[744]
    parsed_data['PreStaAlarm'] = packet[745:757] 
    parsed_data['Mu_Su_Buadrate'] = packet[757]
    parsed_data['ModemOnOff'] = packet[758]
    parsed_data['RsrpOffset'] = packet[759]
    parsed_data['SuOpticalEnStatus'] = packet[744]
    parsed_data['PreStaAlarm'] = packet[745:757] # Changed to 745:757
    parsed_data['Mu_Su_Buadrate'] = packet[757]
    parsed_data['ModemOnOff'] = packet[758]
    parsed_data['RsrpOffset'] = packet[759]
    #RF 제어
    parsed_data['ALC_DL0_SISO_Mode'] = packet[760]
    parsed_data['ALC_DL1_MIMO_Mode'] = packet[761]
    parsed_data['ALC_UL0_SISO_Mode'] = packet[762]
    parsed_data['ALC_UL1_MIMO_Mode'] = packet[763]
    # ALC Level (1dBm 단위)
    parsed_data['ALC_DL0_SISO_Level'] = convert_to_1dbm(struct.unpack('<h', bytes([packet[764], packet[765]]))[0])
    parsed_data['ALC_DL1_MIMO_Level'] = convert_to_1dbm(struct.unpack('<h', bytes([packet[766], packet[767]]))[0])
    parsed_data['ALC_UL0_SISO_Level'] = convert_to_1dbm(struct.unpack('<h', bytes([packet[768], packet[769]]))[0])
    parsed_data['ALC_UL1_MIMO_Level'] = convert_to_1dbm(struct.unpack('<h', bytes([packet[770], packet[771]]))[0])
    parsed_data['SISO_RF_DET_DL0_OUT_High'] = struct.unpack('<h', bytes([packet[772], packet[773]]))[0]
    parsed_data['SISO_RF_DET_UL0_OUT_High'] = struct.unpack('<h', bytes([packet[774], packet[775]]))[0]
    parsed_data['MIMO_RF_DET_DL1_OUT_High'] = struct.unpack('<h', bytes([packet[776], packet[777]]))[0]
    parsed_data['MIMO_RF_DET_UL1_OUT_High'] = struct.unpack('<h', bytes([packet[778], packet[779]]))[0]
    # SISO/MIMO OPTIC DET Low (0.1dBm 단위로 변환)
    parsed_data['LD1_DET_DL0_SISO_Low'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[780], packet[781]]))[0])
    parsed_data['LD2_DET_DL1_MIMO_Low'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[782], packet[783]]))[0])
    parsed_data['PD1_DET_UL0_SISO_Low'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[784], packet[785]]))[0])
    parsed_data['PD2_DET_UL1_MIMO_Low'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[786], packet[787]]))[0])
    parsed_data['LD3_DET_DL0_SISO_Low'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[788], packet[789]]))[0])
    parsed_data['LD4_DET_DL1_MIMO_Low'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[790], packet[791]]))[0])
    parsed_data['PD3_DET_UL0_SISO_Low'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[792], packet[793]]))[0])
    parsed_data['PD4_DET_UL1_MIMO_Low'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[794], packet[795]]))[0])
    parsed_data['LD1_DET_DL0_SISO_Offset'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[796], packet[797]]))[0])
    parsed_data['LD2_DET_DL1_MIMO_Offset'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[798], packet[799]]))[0])
    parsed_data['PD1_DET_UL0_SISO_Offset'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[800], packet[801]]))[0])
    parsed_data['PD2_DET_UL1_MIMO_Offset'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[802], packet[803]]))[0])
    parsed_data['LD3_DET_DL0_SISO_Offset'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[804], packet[805]]))[0])
    parsed_data['LD4_DET_DL1_MIMO_Offset'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[806], packet[807]]))[0])
    parsed_data['PD3_DET_UL0_SISO_Offset'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[808], packet[809]]))[0])
    parsed_data['PD4_DET_UL1_MIMO_Offset'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[810], packet[811]]))[0])
    # DU ATT (0.5dB 단위로 변환)
    parsed_data['DU_DlManualAtten_SISO'] = convert_att_4_to_2(packet[812])
    parsed_data['DU_DlSubAtten_SISO'] = convert_att_4_to_2(packet[813])
    parsed_data['DU_DlManualAtten_MIMO'] = convert_att_4_to_2(packet[814])
    parsed_data['DU_DlSubAtten_MIMO'] = convert_att_4_to_2(packet[815])
    parsed_data['DU_UlManualAtten_SISO'] = convert_att_4_to_2(packet[816])
    parsed_data['DU_UlSubAtten_SISO'] = convert_att_4_to_2(packet[817])
    parsed_data['DU_UlIsoAtten_SISO'] = convert_iso_att(packet[818])
    parsed_data['DU_UlManualAtten_MIMO'] = convert_att_4_to_2(packet[819])
    parsed_data['DU_UlSubAtten_MIMO'] = convert_att_4_to_2(packet[820])
    parsed_data['DU_UlIsoAtten_MIMO'] = convert_iso_att(packet[821])
    parsed_data['SU_DlManualAtten_SISO'] = packet[822]
    parsed_data['SU_DlSubAtten_SISO'] = packet[823]
    parsed_data['SU_DlManualAtten_MIMO'] = packet[824]
    parsed_data['SU_DlSubAtten_MIMO'] = packet[825]
    parsed_data['SU_UlManualAtten_SISO'] = packet[826]
    parsed_data['SU_UlSubAtten_SISO'] = packet[827]
    parsed_data['SU_UlManualAtten_MIMO'] = packet[828]
    parsed_data['SU_UlSubAtten_MIMO'] = packet[829]
    parsed_data['LicPassword'] = struct.unpack('<h', bytes([packet[830], packet[831]]))[0]
    parsed_data['DL_OutputOffset_SISO'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[832], packet[833]]))[0])
    parsed_data['DL_OutputOffset_MIMO'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[834], packet[835]]))[0])
    parsed_data['UL_InputOffset_SISO'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[836], packet[837]]))[0])
    parsed_data['UL_InputOffset_MIMO'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[838], packet[839]]))[0])
    parsed_data['SU_UlCasSisoAtten_SISO'] = packet[840]
    parsed_data['SU_UlCasSisoAtten_MIMO'] = packet[841]
    parsed_data['SdOnOffSiso'] = packet[842]
    parsed_data['SdOnOffMimo'] = packet[843]
    parsed_data['DuFixBeam'] = packet[844]
    parsed_data['Reserved4_Local'] = packet[845:852]
    parsed_data['Dl_Siso_Att_Test'] = convert_att_test(struct.unpack('<h', bytes([packet[852], packet[853]]))[0])
    parsed_data['Dl_Mimo_Att_Test'] = convert_att_test(struct.unpack('<h', bytes([packet[854], packet[855]]))[0])
    parsed_data['Ul_Siso_Att_Test'] = convert_att_test(struct.unpack('<h', bytes([packet[856], packet[857]]))[0])
    parsed_data['Ul_Mimo_Att_Test'] = convert_att_test(struct.unpack('<h', bytes([packet[858], packet[859]]))[0])
    parsed_data['Reserved10p1'] = packet[860:892]
    # MVBX 제어
    parsed_data['Mvbx_BeamSet'] = packet[892]
    parsed_data['InstallUseMode'] = packet[893]
    parsed_data['Reserved14'] = packet[894:896]
    parsed_data['Mvbx_FpagImageSize'] = packet[896:900]
    parsed_data['Mvbx_FpagImageStartAddressOffset'] = packet[900:904]
    parsed_data['Reserved15'] = packet[904:920]
    parsed_data['FpgaWriteAddress'] = packet[920:922]
    parsed_data['FpgaWriteData'] = packet[922:924]
    parsed_data['FpgaReadAddress'] = packet[924:926]
    parsed_data['FpgaReadData'] = packet[926:928]
    parsed_data['Reserved31'] = packet[928:940]
    parsed_data['Mvbx_TddSignalMode'] = packet[940]
    parsed_data['Mvbx_RsAgcThreshold'] = packet[941]
    parsed_data['Mvbx_RsAgcMode'] = packet[942]
    parsed_data['Reserved32'] = packet[943]
    parsed_data['Mvbx_Mv2853TxGainSiso'] = packet[944]
    parsed_data['Mvbx_Mv2853RxGainSiso'] = packet[945]
    parsed_data['Mvbx_Mv2850TxGainSiso'] = packet[946]
    parsed_data['Mvbx_Mv2850RxGainSiso'] = packet[947]
    parsed_data['Mvbx_Mv2853TxGainMimo'] = packet[948]
    parsed_data['Mvbx_Mv2853RxGainMimo'] = packet[949]
    parsed_data['Mvbx_Mv2850TxGainMimo'] = packet[950]
    parsed_data['Mvbx_Mv2850RxGainMimo'] = packet[951]
    parsed_data['Mvbx_TxGainSetSiso'] = packet[952]
    parsed_data['Mvbx_RxGainSetSiso'] = packet[953]
    parsed_data['Mvbx_TxGainSetMiso'] = packet[954]
    parsed_data['Mvbx_RxGainSetMiso'] = packet[955]
    parsed_data['beam_info_pss_type'] = struct.unpack('<I', bytes([packet[956], packet[957], packet[958], packet[959]]))[0]
    parsed_data['beam_info_adc_sel'] = struct.unpack('<I', bytes([packet[960], packet[961], packet[962], packet[963]]))[0]
    parsed_data['beam_info_spg '] = struct.unpack('<I', bytes([packet[964], packet[965], packet[966], packet[967]]))[0]
    parsed_data['beam_info_ssbIdx'] = struct.unpack('<I', bytes([packet[968], packet[969], packet[970], packet[971]]))[0]
    parsed_data['beam_info_beamID'] = struct.unpack('<h', bytes([packet[972], packet[973]]))[0]
    parsed_data['Reserved34'] = struct.unpack('<h', bytes([packet[974], packet[975]]))[0]
    parsed_data['beam_info_energy'] = struct.unpack('<I', bytes([packet[976], packet[977], packet[978], packet[979]]))[0]
    parsed_data['beam_info_rsrp '] = struct.unpack('<I', bytes([packet[980], packet[981], packet[982], packet[983]]))[0]
    parsed_data['beam_info_snr'] = struct.unpack('<I', bytes([packet[984], packet[985], packet[986], packet[987]]))[0]
    parsed_data['PllSet'] = struct.unpack('<I', bytes([packet[988], packet[989], packet[990], packet[991]]))[0]
    parsed_data['IsoMeasSet'] = packet[992]
    parsed_data['SuGsOnOff'] = packet[993]
    parsed_data['SuIsoAttSet'] = packet[994]
    parsed_data['GumStick_OnOff'] = packet[995]
    parsed_data['BeamScan_OnOff'] = packet[996]
    parsed_data['IsoDetectMode'] = packet[997]
    parsed_data['ApiLogLevel'] = packet[998]
    parsed_data['ApiAdcSel'] = packet[999]
    parsed_data['ApiSyncPathGain'] = packet[1000]
    parsed_data['ApiDuTimeAdvance'] = packet[1001]
    parsed_data['ApiSuTimeAdvance'] = packet[1002]
    parsed_data['TemperCompensationMode'] = packet[1003]
    parsed_data['ApiVenderFreq'] = struct.unpack('<I', bytes([packet[1004], packet[1005], packet[1006], packet[1007]]))[0]
    parsed_data['ApiGsOutputPowerOffsetSiso'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[1008], packet[1009]]))[0])
    parsed_data['BeamAntSelect'] = packet[1010]
    parsed_data['DecodeRecoveryFuncOnOff'] = packet[1011]
    parsed_data['gNB_ScanOnOff'] = packet[1012]
    parsed_data['SuEndMode'] = packet[1013]
    parsed_data['ApiGsOutputPowerOffsetMimo'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[1014], packet[1015]]))[0])
    parsed_data['gNB_Vendor'] = packet[1016]
    parsed_data['Gs_Gain_Siso'] = packet[1017]
    parsed_data['Gs_Gain_Mimo'] = packet[1018]
    parsed_data['ApiInitRetryMode'] = packet[1019]
    parsed_data['Orientation'] = f"{struct.unpack('<h', bytes([packet[1020], packet[1021]]))[0]:.3f}"
    parsed_data['Tilt'] = f"{struct.unpack('<h', bytes([packet[1022], packet[1023]]))[0]:.3f}"
    parsed_data['GS_AttenOffset_DL_Siso'] = struct.unpack('<b', bytes([packet[1024]]))[0]
    parsed_data['GS_AttenOffset_DL_Mimo'] = struct.unpack('<b', bytes([packet[1025]]))[0]
    parsed_data['GS_AttenOffset_UL_Siso'] = struct.unpack('<b', bytes([packet[1026]]))[0]
    parsed_data['GS_AttenOffset_UL_Mimo'] = struct.unpack('<b', bytes([packet[1027]]))[0]
    parsed_data['ConSerialNum'] = ''.join([chr(b) for b in packet[1028:1044] if b != 0])
    parsed_data['AomTemperConperMode'] = packet[1044]
    parsed_data['GS_AttenOffset_30by15_DL_Siso'] = packet[1045]
    parsed_data['GS_AttenOffset_30by30_DL_Siso'] = packet[1046]
    parsed_data['GS_AttenOffset_60by15_DL_Siso'] = packet[1047]
    parsed_data['GS_AttenOffset_60by30_DL_Siso'] = packet[1048]
    parsed_data['GS_AttenOffset_60by60_DL_Siso'] = packet[1049]
    parsed_data['GS_AttenOffset_30by15_DL_Mimo'] = packet[1050]
    parsed_data['GS_AttenOffset_30by30_DL_Mimo'] = packet[1051]
    parsed_data['GS_AttenOffset_60by15_DL_Mimo'] = packet[1052]
    parsed_data['GS_AttenOffset_60by30_DL_Mimo'] = packet[1053]
    parsed_data['GS_AttenOffset_60by60_DL_Mimo'] = packet[1054]
    parsed_data['GS_AttenOffset_30by15_UL_Siso'] = packet[1055]
    parsed_data['GS_AttenOffset_30by30_UL_Siso'] = packet[1056]
    parsed_data['GS_AttenOffset_60by15_UL_Siso'] = packet[1057]
    parsed_data['GS_AttenOffset_60by30_UL_Siso'] = packet[1058]
    parsed_data['GS_AttenOffset_60by60_UL_Siso'] = packet[1059]
    parsed_data['GS_AttenOffset_30by15_UL_Mimo'] = packet[1060]
    parsed_data['GS_AttenOffset_30by30_UL_Mimo'] = packet[1061]
    parsed_data['GS_AttenOffset_60by15_UL_Mimo'] = packet[1062]
    parsed_data['GS_AttenOffset_60by30_UL_Mimo'] = packet[1063]
    parsed_data['GS_AttenOffset_60by60_UL_Mimo'] = packet[1064]
    parsed_data['Reserved41'] = packet[1065:1089]
    parsed_data['LowRsrpStillTime'] = packet[1089]
    parsed_data['LowRsrpLevel'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[1090], packet[1091]]))[0])
    parsed_data['SU_DlCasSisoAtten_SISO'] = packet[1092]
    parsed_data['SU_DlCasSisoAtten_MIMO'] = packet[1093]
    parsed_data['SU_DlCasSisoAttenTest_SISO'] = packet[1094]
    parsed_data['SU_DlCasSisoAttenTest_MIMO'] = packet[1095]
    parsed_data['SU_UlCasSisoAttenTest_SISO'] = packet[1096]
    parsed_data['SU_UlCasSisoAttenTest_MIMO'] = packet[1097]
    parsed_data['Reserved41p1'] = packet[1098:1101]
    parsed_data['PciResetOnOff'] = packet[1101]
    parsed_data['PciNo'] = struct.unpack('<h', bytes([packet[1102], packet[1103]]))[0]
    parsed_data['PciTime'] = packet[1104]
    parsed_data['Reserved42'] = packet[1105:1112]
    # Reserved42 감지 시 RX 박스 끄기
    socketio.emit("rx_off")

    return parsed_data

def parse_AllStatusPacket5(packet):


    parsed_data = {}
    
    # 단위 변환 함수들
    def convert_to_01dbm(raw_value):
        """0.1dBm 단위로 변환 (예: -517 → -51.7 dBm)"""
        return round(raw_value / 10.0, 1)
    
    def convert_att_4_to_2(raw_value):
        """ATT 변환 (4→2dB, Step: 0.5dB)"""
        return raw_value * 0.5
    
    def convert_to_1dbm(raw_value):
        """1dBm 단위로 변환"""
        return raw_value
    
    def convert_iso_att(raw_value):
        """ISO ATT 변환 (4→2dB, Step: 0.5dB, Range: 0~20dB)"""
        return raw_value * 0.5
    
    def convert_att_test(raw_value):
        """ATT Test 변환 (50: 5dB, 0.5dB 단위, Range: 0~30dB)"""
        return raw_value * 0.5
    
    def convert_polling_time(raw_value):
        """Polling Time 변환 (2바이트 uint, 범위: 100~5,000ms)"""
        return raw_value  # 이미 ms 단위로 저장되어 있음
    
    #su1 상태
    parsed_data['Rcv_Main_Sys'] = packet[0]
    # Rcv_Main_Sys 감지 시 RX 박스 켜기
    socketio.emit("rx_on")
    parsed_data['Rcv_Sub_Sys'] = packet[1]
    parsed_data['Rcv_Object'] = packet[2]
    parsed_data['Trans_Main_Sys'] = packet[3]
    # Trans_Main_Sys 감지 시 TX 박스 토글 (1이면 켜기, 0이면 끄기)
    if packet[3] != 0:
        socketio.emit("tx_on")
    else:
        socketio.emit("tx_off")
    parsed_data['Trans_Sub_Sys'] = packet[4]
    parsed_data['Trans_Object'] = packet[5]
    parsed_data['CMD'] = packet[6]
    parsed_data['EQUIP_TYPE'] = packet[7]
    parsed_data['RESERVED'] = packet[8:10]
    parsed_data['SubData_Size'] = struct.unpack('<h', bytes([packet[10], packet[11]]))[0]
    parsed_data['McuSwVer'] = f"{packet[13]}.{packet[12]}" 
    parsed_data['RptMaker'] = packet[14]
    parsed_data['DU_SU_Status'] = packet[15]
    parsed_data['Reserved0_1'] = packet[16]
    parsed_data['StatusPollingUnit'] = packet[17]
    parsed_data['RtpKind'] = packet[18]
    parsed_data['Reserved0'] = packet[19]
    parsed_data['StaMuAlarm'] = list(packet[20:32])
    
    # 알람 비트 매핑 정의
    alarm_bit_map = [
        {'bit': 1,  'id': 'su4_alarm_dc'},
        {'bit': 2,  'id': 'su4_alarm_ac'},
        {'bit': 3,  'id': 'su4_alarm_temp'},
        {'bit': 4,  'id': 'su4_alarm_bat'},
        {'bit': 48, 'id': 'su4_alarm_du_link'},
        {'bit': 53, 'id': 'su4_alarm_if_pll'},
        {'bit': 52, 'id': 'su4_alarm_tsync_link'},  # 비트 51 → 52로 수정
        {'bit': 63, 'id': 'su4_alarm_ref_pll'},
        {'bit': 70, 'id': 'su4_alarm_aa_link'}
    ]
    
    # 알람 비트 추출 함수
    def get_alarm_bit(alarm_bytes, bit_position):
        byte_index = (bit_position - 1) // 8
        bit_in_byte = (bit_position - 1) % 8
        if byte_index < len(alarm_bytes):
            return (alarm_bytes[byte_index] >> bit_in_byte) & 1
        return 0
    
    # 각 알람 비트 상태 추출
    alarm_status = {}
    for alarm in alarm_bit_map:
        alarm_status[alarm['id']] = get_alarm_bit(packet[20:32], alarm['bit'])
    
    parsed_data['AlarmStatus'] = alarm_status
    
    # ALA2 링크 알람 비트 추출 (packet[21]의 비트 0~3)
    ala2_link_alarms = {
        'ALA2_SU1_LINK_ALARM': (packet[21] >> 0) & 1,  # 비트 0
        'ALA2_SU2_LINK_ALARM': (packet[21] >> 1) & 1,  # 비트 1
        'ALA2_SU3_LINK_ALARM': (packet[21] >> 2) & 1,  # 비트 2
        'ALA2_SU4_LINK_ALARM': (packet[21] >> 3) & 1   # 비트 3
    }
    parsed_data['ALA2_Link_Alarms'] = ala2_link_alarms
    parsed_data['SuLinkFail'] = packet[32:44]
    # SuLinkFail에서 1비트씩 추출 - SU1~SU4만
    su_link_fail_bits = {
        'SU1_LINK_FAIL': (packet[32] >> 0) & 1,  # 비트 0
        'SU2_LINK_FAIL': (packet[32] >> 1) & 1,  # 비트 1
        'SU3_LINK_FAIL': (packet[32] >> 2) & 1,  # 비트 2
        'SU4_LINK_FAIL': (packet[32] >> 3) & 1   # 비트 3
        #추후 SU5, SU6 추가 해야할수도 있음
    }
    parsed_data['SuLinkFailBits'] = su_link_fail_bits
    parsed_data['SuSumAlarm'] = packet[44:56]
    parsed_data['SuRptAlarm'] = packet[56:68] 
    parsed_data['StsApiVenderFreq'] = struct.unpack('<I', bytes([packet[68], packet[69], packet[70], packet[71]]))[0]
    parsed_data['System_Year'] = '.'.join(['{:02d}'.format((packet[72] << 8) | packet[73]), '{:02d}'.format(packet[74]), '{:02d}'.format(packet[75])])
    parsed_data['System_hour'] = ':'.join(['{:02d}'.format(packet[76]), '{:02d}'.format(packet[77]), '{:02d}'.format(packet[78])])
    parsed_data['SysTemper'] = packet[79]
    parsed_data['PackSendCount'] = packet[80:120]
    parsed_data['PackErrorCount'] = packet[120:160]
    parsed_data['FPGA_Boot_Status'] = packet[160]
    parsed_data['FPGA_Init_Status'] = packet[161]
    parsed_data['Beam_Scan_Status'] = packet[162]
    parsed_data['DU_SumAlarmStatus'] = packet[163]
    parsed_data['ALC_Atten_DL0_SISO'] = struct.unpack('<h', bytes([packet[164], packet[165]]))[0]
    parsed_data['ALC_Atten_DL1_MIMO'] = struct.unpack('<h', bytes([packet[166], packet[167]]))[0]
    parsed_data['ALC_Atten_UL0_SISO'] = struct.unpack('<h', bytes([packet[168], packet[169]]))[0]
    parsed_data['ALC_Atten_UL1_MIMO'] = struct.unpack('<h', bytes([packet[170], packet[171]]))[0]
    # SISO/MIMO OPTIC DET (0.1dBm 단위로 변환)
    parsed_data['LD1_DET_DL0_SISO'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[172], packet[173]]))[0])
    parsed_data['LD2_DET_DL1_MIMO'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[174], packet[175]]))[0])
    parsed_data['PD1_DET_UL0_SISO'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[176], packet[177]]))[0])
    parsed_data['PD2_DET_UL1_MIMO'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[178], packet[179]]))[0])
    # SISO/MIMO RF DET (0.1dBm 단위로 변환)
    parsed_data['SISO_RF_DET_DL0_OUT'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[180], packet[181]]))[0])
    parsed_data['SISO_RF_DET_UL0_OUT'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[182], packet[183]]))[0])
    parsed_data['MIMO_RF_DET_DL1_OUT'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[184], packet[185]]))[0])
    parsed_data['MIMO_RF_DET_UL1_OUT'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[186], packet[187]]))[0])
    parsed_data['LD3_DET_DL0_SISO'] = struct.unpack('<h', bytes([packet[188], packet[189]]))[0]
    parsed_data['LD4_DET_DL1_MIMO'] = struct.unpack('<h', bytes([packet[190], packet[191]]))[0]
    parsed_data['PD3_DET_UL0_SISO'] = struct.unpack('<h', bytes([packet[192], packet[193]]))[0]
    parsed_data['PD4_DET_UL1_MIMO'] = struct.unpack('<h', bytes([packet[194], packet[195]]))[0]
    parsed_data['SuModeStatus'] = packet[196]
    parsed_data['SdStatusSiso'] = packet[197]
    parsed_data['SdStatusMimo'] = packet[198]
    parsed_data['Reserved3'] = packet[199:220] 
    #MVBX 상태
    parsed_data['FPGA_Ver'] = '.'.join([str(packet[220]), str(packet[221]), str(packet[222])])
    parsed_data['ApiOldNewVer'] = packet[223]
    parsed_data['Reserved3p1'] = packet[224:232] 
    parsed_data['Gumstick_Ver'] = '.'.join([str(packet[232]), str(packet[233]), str(packet[234])])
    parsed_data['SyncStatus'] = packet[235]
    parsed_data['TryBeamScanCont'] = struct.unpack('<h', bytes([packet[236], packet[237]]))[0]
    parsed_data['Reserved4'] = packet[238:244]
    parsed_data['MVBX_pci'] = struct.unpack('<h', bytes([packet[244], packet[245]]))[0]
    parsed_data['MVBX_ssb'] = struct.unpack('<h', bytes([packet[246], packet[247]]))[0]
    parsed_data['MVBX_rsrp'] = f"{struct.unpack('<f', bytes(packet[248:252]))[0]:.2f} [dBm]"
    parsed_data['MVBX_snr'] = f"{struct.unpack('<f', bytes(packet[252:256]))[0]:.2f} [dB]"
    parsed_data['MVBX_BeamInfo_beamId1'] = struct.unpack('<h', bytes([packet[256], packet[257]]))[0]
    parsed_data['MVBX_BeamInfo_beamId2'] = struct.unpack('<h', bytes([packet[258], packet[259]]))[0]
    parsed_data['MVBX_BeamInfo_beamId3'] = struct.unpack('<h', bytes([packet[260], packet[261]]))[0]
    parsed_data['MVBX_BeamInfo_beamId4'] = struct.unpack('<h', bytes([packet[262], packet[263]]))[0]
    parsed_data['MVBX_BeamInfo_pci1'] = struct.unpack('<h', bytes([packet[264], packet[265]]))[0]
    parsed_data['MVBX_BeamInfo_pci2'] = struct.unpack('<h', bytes([packet[266], packet[267]]))[0]
    parsed_data['MVBX_BeamInfo_pci3'] = struct.unpack('<h', bytes([packet[268], packet[269]]))[0]
    parsed_data['MVBX_BeamInfo_pci4'] = struct.unpack('<h', bytes([packet[270], packet[271]]))[0]
    parsed_data['MVBX_BeamInfo_ssbldx1'] = struct.unpack('<I', bytes([packet[272], packet[273], packet[274], packet[275]]))[0]
    parsed_data['MVBX_BeamInfo_ssbldx2'] = struct.unpack('<I', bytes([packet[276], packet[277], packet[278], packet[279]]))[0]
    parsed_data['MVBX_BeamInfo_ssbldx3'] = struct.unpack('<I', bytes([packet[280], packet[281], packet[282], packet[283]]))[0]
    parsed_data['MVBX_BeamInfo_ssbldx4'] = struct.unpack('<I', bytes([packet[284], packet[285], packet[286], packet[287]]))[0]
    parsed_data['MVBX_BeamInfo_energy1'] = struct.unpack('<I', bytes([packet[288], packet[289], packet[290], packet[291]]))[0]
    parsed_data['MVBX_BeamInfo_energy2'] = struct.unpack('<I', bytes([packet[292], packet[293], packet[294], packet[295]]))[0]
    parsed_data['MVBX_BeamInfo_energy3'] = struct.unpack('<I', bytes([packet[296], packet[297], packet[298], packet[299]]))[0]
    parsed_data['MVBX_BeamInfo_energy4'] = struct.unpack('<I', bytes([packet[300], packet[301], packet[302], packet[303]]))[0]
    parsed_data['MVBX_BeamInfo_psstype1'] = struct.unpack('<I', bytes([packet[304], packet[305], packet[306], packet[307]]))[0]
    parsed_data['MVBX_BeamInfo_psstype2'] = struct.unpack('<I', bytes([packet[308], packet[309], packet[310], packet[311]]))[0]
    parsed_data['MVBX_BeamInfo_psstype3'] = struct.unpack('<I', bytes([packet[312], packet[313], packet[314], packet[315]]))[0]
    parsed_data['MVBX_BeamInfo_psstype4'] = struct.unpack('<I', bytes([packet[316], packet[317], packet[318], packet[319]]))[0]
    # SNR 값 처리 (소수점 2자리, -999이면 "- - -")
    snr1 = struct.unpack('<f', bytes(packet[320:324]))[0]
    parsed_data['MVBX_BeamInfo_snr1'] = "- - -" if snr1 == -999 else f"{snr1:.2f}"
    
    snr2 = struct.unpack('<f', bytes(packet[324:328]))[0]
    parsed_data['MVBX_BeamInfo_snr2'] = "- - -" if snr2 == -999 else f"{snr2:.2f}"
    
    snr3 = struct.unpack('<f', bytes(packet[328:332]))[0]
    parsed_data['MVBX_BeamInfo_snr3'] = "- - -" if snr3 == -999 else f"{snr3:.2f}"
    
    snr4 = struct.unpack('<f', bytes(packet[332:336]))[0]
    parsed_data['MVBX_BeamInfo_snr4'] = "- - -" if snr4 == -999 else f"{snr4:.2f}"
    
    # RSRP 값 처리 (소수점 2자리, -999이면 "- - -")
    rsrp1 = struct.unpack('<f', bytes(packet[336:340]))[0]
    parsed_data['MVBX_BeamInfo_rsrp1'] = "- - -" if rsrp1 == -999 else f"{rsrp1:.2f}"
    
    rsrp2 = struct.unpack('<f', bytes(packet[340:344]))[0]
    parsed_data['MVBX_BeamInfo_rsrp2'] = "- - -" if rsrp2 == -999 else f"{rsrp2:.2f}"
    
    rsrp3 = struct.unpack('<f', bytes(packet[344:348]))[0]
    parsed_data['MVBX_BeamInfo_rsrp3'] = "- - -" if rsrp3 == -999 else f"{rsrp3:.2f}"
    
    rsrp4 = struct.unpack('<f', bytes(packet[348:352]))[0]
    parsed_data['MVBX_BeamInfo_rsrp4'] = "- - -" if rsrp4 == -999 else f"{rsrp4:.2f}"
    parsed_data['pss_pulse_count'] = struct.unpack('<I', bytes([packet[352], packet[353], packet[354], packet[355]]))[0]
    parsed_data['decoded_ssb_count'] = struct.unpack('<I', bytes([packet[356], packet[357], packet[358], packet[359]]))[0]
    parsed_data['decoded_ssb_no_error_count'] = struct.unpack('<I', bytes([packet[360], packet[361], packet[362], packet[363]]))[0]
    parsed_data['LicStatus'] = packet[364]
    parsed_data['LicStartDateMonth'] = packet[365]
    parsed_data['LicStartDateDay'] = packet[366]
    parsed_data['LicStopDateMonth'] = packet[367]
    parsed_data['LicStopDateDay'] = packet[368]
    parsed_data['Reserved4_new'] = packet[369:412]
    # Modem 상태
    parsed_data['ModRsrp'] = struct.unpack('<h', bytes([packet[412], packet[413]]))[0]
    parsed_data['ModRsrq'] = struct.unpack('<h', bytes([packet[414], packet[415]]))[0]
    parsed_data['InitTemper'] = packet[416]
    parsed_data['ModVersion'] = f"{packet[417] / 100:.2f}"
    parsed_data['ModLanUseMode'] = packet[418]
    parsed_data['ModPci'] = packet[419]
    parsed_data['SU_DlIsoAtten_SISO'] = packet[420]
    parsed_data['SU_DlIsoAtten_MIMO'] = packet[421]
    parsed_data['SU_UlIsoAtten_SISO'] = packet[422]
    parsed_data['SU_UlIsoAtten_MIMO'] = packet[423]
    parsed_data['SU_ISO_SATUS'] = packet[424:428]
    
    parsed_data['DU_ISO_STATUS'] = packet[428]
    
    parsed_data['ModStatus'] = packet[429]
    parsed_data['ModSinr'] = packet[430]
    parsed_data['Reserved6'] = packet[431]
    parsed_data['ModRssi'] = struct.unpack('<h', bytes([packet[432], packet[433]]))[0]
    parsed_data['ModTxPwr'] = struct.unpack('<h', bytes([packet[434], packet[435]]))[0]
    
    """
    # 16진수 바이트 배열을 10진수 문자열로 변환 (15자리만)
    def hex_bytes_to_decimal_string(byte_array):
        try:
            # 16진수 값을 10진수 문자열로 변환
            result = ''.join([f"{b:02d}" for b in byte_array if b != 0])
            # 15자리만 사용
            return result[:15] if result else "N/A"
        except:
            return "N/A"
    """
    
    # 널문자를 만날 때까지 문자열 변환
    def bytes_to_string_until_null(byte_array):
        result = ''
        for b in byte_array:
            if b == 0:  # 널문자 만나면 중단
                break
            result += chr(b)
        return result
    
    parsed_data['ModIMSINum'] = bytes_to_string_until_null(packet[436:452])
    parsed_data['ModIMEINum'] = bytes_to_string_until_null(packet[452:476])
    parsed_data['ModIpAddress'] =f"{packet[476]}.{packet[477]}.{packet[478]}.{packet[479]}"
    parsed_data['ModServerIpAddress'] = packet[480:484]
    parsed_data['ModPhonNumber'] = bytes_to_string_until_null(packet[484:495])
    parsed_data['ModEmsFwVer'] = f"{struct.unpack('<h', bytes([packet[496], packet[497]]))[0] / 100:.2f}"
    parsed_data['Gumstick_CurTemper'] = struct.unpack('<h', bytes([packet[498], packet[499]]))[0]
    parsed_data['Gumstick_StartTemper'] = struct.unpack('<h', bytes([packet[500], packet[501]]))[0]
    parsed_data['DlTemperCompensation'] = packet[502]
    parsed_data['UlTemperCompensation'] = packet[503]
    parsed_data['PllRelockCount'] = struct.unpack('<h', bytes([packet[504], packet[505]]))[0]
    parsed_data['DecodedRate'] = packet[506]
    parsed_data['Reserved6p1'] = packet[507]
    parsed_data['DsOutputPower_SISO'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[508], packet[509]]))[0])
    parsed_data['EmsModemReset'] = packet[510]
    parsed_data['Reserved6p2'] = packet[511]
    agc_input_raw = struct.unpack('<h', bytes([packet[512], packet[513]]))[0]
    parsed_data['AGC_Input_Power'] = f"{agc_input_raw / 10:.1f}"
    parsed_data['DsOutputPower_MIMO'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[514], packet[515]]))[0])
    parsed_data['Actual_Orientation'] = struct.unpack('<h', bytes([packet[516], packet[517]]))[0]
    parsed_data['Actual_Tilt'] = struct.unpack('<h', bytes([packet[518], packet[519]]))[0]
    parsed_data['Reserved6p3'] = packet[520:576]
    #DU Control
    parsed_data['InitCheckNum'] = packet[576:580]
    parsed_data['ConMuFlag'] = packet[580:604]
    parsed_data['ConSysTime_Year'] = '.'.join(['{:02d}'.format((packet[604] << 8) | packet[605]), '{:02d}'.format(packet[606]), '{:02d}'.format(packet[607])])
    parsed_data['ConSysTime_hour'] = ':'.join(['{:02d}'.format(packet[608]), '{:02d}'.format(packet[609]), '{:02d}'.format(packet[610])])
    parsed_data['RptMakerCode'] = packet[611]
    parsed_data['SysTemperHighLvl'] = packet[612]
    parsed_data['SysTemperLowLvl'] = packet[613]
    parsed_data['SubInitCheckNum'] = packet[614]
    parsed_data['DebugMode'] = packet[615]
    parsed_data['SuEnableInfo'] = packet[616:628]
    # SU Enable Info 비트 추출 (packet[616]의 비트 0~3)
    su_enable_bits = {
        'SU1_ENABLE': (packet[616] >> 0) & 1,  # 비트 0
        'SU2_ENABLE': (packet[616] >> 1) & 1,  # 비트 1
        'SU3_ENABLE': (packet[616] >> 2) & 1,  # 비트 2
        'SU4_ENABLE': (packet[616] >> 3) & 1   # 비트 3
    }
    parsed_data['SuEnableBits'] = su_enable_bits
    

    parsed_data['MaskMuAlarm'] = list(packet[628:640])
    
    # packet[635]에서 0번째, 2번째, 5번째 비트 추출
    dl_alc_bits = {
        'SISO_MASK_DL_ALC': (packet[635] >> 0) & 1,  # 비트 0
        'MIMO_MASK_DL_ALC': (packet[635] >> 2) & 1,  # 비트 2
        'EMS_DU_Link_MASK': (packet[635] >> 5) & 1   # 비트 5
    }
    parsed_data['DL_ALC_Bits'] = dl_alc_bits

    # packet[634]에서 0번째, 1번째, 2번째, 3번째 비트 추출
    det_mask_bits = {
        'LD1_DET_DL0_SISO_MASK': (packet[634] >> 0) & 1,  # 비트 0
        'LD2_DET_DL1_MIMO_MASK': (packet[634] >> 1) & 1,  # 비트 1
        'PD1_DET_UL0_SISO_MASK': (packet[634] >> 2) & 1,  # 비트 2
        'PD2_DET_UL1_MIMO_MASK': (packet[634] >> 3) & 1   # 비트 3
    }
    parsed_data['DET_MASK_Bits'] = det_mask_bits

        # 알람 비트 매핑 정의
    alarm_mask_bit_map = [
        {'bit': 1,  'id': 'alarm_mask_madc'},
        {'bit': 2,  'id': 'alarm_mask_ac'},
        {'bit': 3,  'id': 'alarm_mask_temp'},
        {'bit': 4,  'id': 'alarm_mask_bat'},
        {'bit': 49, 'id': 'alarm_mask_fpga_link'},
        {'bit': 53, 'id': 'alarm_mask_if_pll'},
        {'bit': 54, 'id': 'alarm_mask_sync_pll'},
        {'bit': 52, 'id': 'alarm_mask_tsync_link'},  # 비트 51 → 52로 수정
        {'bit': 66, 'id': 'alarm_mask_decoding'},
        {'bit': 70, 'id': 'alarm_mask_aa_link'}
    ]

    # Mask 알람 비트 추출 함수
    def get_mask_alarm_bit(mask_bytes, bit_position):
        byte_index = (bit_position - 1) // 8
        bit_in_byte = (bit_position - 1) % 8
        if byte_index < len(mask_bytes):
            return (mask_bytes[byte_index] >> bit_in_byte) & 1
        return 0
    
    # 각 Mask 알람 비트 상태 추출
    mask_alarm_status = {}
    for alarm in alarm_mask_bit_map:
        mask_alarm_status[alarm['id']] = get_mask_alarm_bit(packet[628:640], alarm['bit'])
    
    parsed_data['MaskAlarmStatus'] = mask_alarm_status

    



    parsed_data['MaskSuLinkFail'] = packet[640:652]

    # SuLinkFail에서 1비트씩 추출 - SU1~SU4만
    su_mask_link_fail_bits = {
        'SU1_MASK_LINK_FAIL': (packet[640] >> 0) & 1,  # 비트 0
        'SU2_MASK_LINK_FAIL': (packet[640] >> 1) & 1,  # 비트 1
        'SU3_MASK_LINK_FAIL': (packet[640] >> 2) & 1,  # 비트 2
        'SU4_MASK_LINK_FAIL': (packet[640] >> 3) & 1   # 비트 3
        #추후 SU5, SU6 추가 해야할수도 있음
    }
    parsed_data['MaskSuLinkFail'] = su_mask_link_fail_bits
    
    parsed_data['MaskSuSumAlarm'] = packet[652:664]
    parsed_data['MaskSuRptAlarm'] = packet[664:676]
    parsed_data['ConEmsModemReset'] = packet[676]
    parsed_data['DownloadPath_GuiOrEms'] = packet[677]
    parsed_data['PollingTime'] = struct.unpack('<H', bytes([packet[678], packet[679]]))[0]
    parsed_data['ApiInitMode'] = packet[680]
    parsed_data['AttTestMode'] = packet[681]
    parsed_data['SuId'] = packet[682]
    parsed_data['DL_UL_TEST'] = packet[683]
    parsed_data['LocalInfo'] = packet[684:744]
    parsed_data['SuOpticalEnStatus'] = packet[744]
    parsed_data['PreStaAlarm'] = packet[745:757] 
    parsed_data['Mu_Su_Buadrate'] = packet[757]
    parsed_data['ModemOnOff'] = packet[758]
    parsed_data['RsrpOffset'] = packet[759]
    parsed_data['SuOpticalEnStatus'] = packet[744]
    parsed_data['PreStaAlarm'] = packet[745:757] # Changed to 745:757
    parsed_data['Mu_Su_Buadrate'] = packet[757]
    parsed_data['ModemOnOff'] = packet[758]
    parsed_data['RsrpOffset'] = packet[759]
    #RF 제어
    parsed_data['ALC_DL0_SISO_Mode'] = packet[760]
    parsed_data['ALC_DL1_MIMO_Mode'] = packet[761]
    parsed_data['ALC_UL0_SISO_Mode'] = packet[762]
    parsed_data['ALC_UL1_MIMO_Mode'] = packet[763]
    # ALC Level (1dBm 단위)
    parsed_data['ALC_DL0_SISO_Level'] = convert_to_1dbm(struct.unpack('<h', bytes([packet[764], packet[765]]))[0])
    parsed_data['ALC_DL1_MIMO_Level'] = convert_to_1dbm(struct.unpack('<h', bytes([packet[766], packet[767]]))[0])
    parsed_data['ALC_UL0_SISO_Level'] = convert_to_1dbm(struct.unpack('<h', bytes([packet[768], packet[769]]))[0])
    parsed_data['ALC_UL1_MIMO_Level'] = convert_to_1dbm(struct.unpack('<h', bytes([packet[770], packet[771]]))[0])
    parsed_data['SISO_RF_DET_DL0_OUT_High'] = struct.unpack('<h', bytes([packet[772], packet[773]]))[0]
    parsed_data['SISO_RF_DET_UL0_OUT_High'] = struct.unpack('<h', bytes([packet[774], packet[775]]))[0]
    parsed_data['MIMO_RF_DET_DL1_OUT_High'] = struct.unpack('<h', bytes([packet[776], packet[777]]))[0]
    parsed_data['MIMO_RF_DET_UL1_OUT_High'] = struct.unpack('<h', bytes([packet[778], packet[779]]))[0]
    # SISO/MIMO OPTIC DET Low (0.1dBm 단위로 변환)
    parsed_data['LD1_DET_DL0_SISO_Low'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[780], packet[781]]))[0])
    parsed_data['LD2_DET_DL1_MIMO_Low'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[782], packet[783]]))[0])
    parsed_data['PD1_DET_UL0_SISO_Low'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[784], packet[785]]))[0])
    parsed_data['PD2_DET_UL1_MIMO_Low'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[786], packet[787]]))[0])
    parsed_data['LD3_DET_DL0_SISO_Low'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[788], packet[789]]))[0])
    parsed_data['LD4_DET_DL1_MIMO_Low'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[790], packet[791]]))[0])
    parsed_data['PD3_DET_UL0_SISO_Low'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[792], packet[793]]))[0])
    parsed_data['PD4_DET_UL1_MIMO_Low'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[794], packet[795]]))[0])
    parsed_data['LD1_DET_DL0_SISO_Offset'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[796], packet[797]]))[0])
    parsed_data['LD2_DET_DL1_MIMO_Offset'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[798], packet[799]]))[0])
    parsed_data['PD1_DET_UL0_SISO_Offset'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[800], packet[801]]))[0])
    parsed_data['PD2_DET_UL1_MIMO_Offset'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[802], packet[803]]))[0])
    parsed_data['LD3_DET_DL0_SISO_Offset'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[804], packet[805]]))[0])
    parsed_data['LD4_DET_DL1_MIMO_Offset'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[806], packet[807]]))[0])
    parsed_data['PD3_DET_UL0_SISO_Offset'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[808], packet[809]]))[0])
    parsed_data['PD4_DET_UL1_MIMO_Offset'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[810], packet[811]]))[0])
    # DU ATT (0.5dB 단위로 변환)
    parsed_data['DU_DlManualAtten_SISO'] = convert_att_4_to_2(packet[812])
    parsed_data['DU_DlSubAtten_SISO'] = convert_att_4_to_2(packet[813])
    parsed_data['DU_DlManualAtten_MIMO'] = convert_att_4_to_2(packet[814])
    parsed_data['DU_DlSubAtten_MIMO'] = convert_att_4_to_2(packet[815])
    parsed_data['DU_UlManualAtten_SISO'] = convert_att_4_to_2(packet[816])
    parsed_data['DU_UlSubAtten_SISO'] = convert_att_4_to_2(packet[817])
    parsed_data['DU_UlIsoAtten_SISO'] = convert_iso_att(packet[818])
    parsed_data['DU_UlManualAtten_MIMO'] = convert_att_4_to_2(packet[819])
    parsed_data['DU_UlSubAtten_MIMO'] = convert_att_4_to_2(packet[820])
    parsed_data['DU_UlIsoAtten_MIMO'] = convert_iso_att(packet[821])
    parsed_data['SU_DlManualAtten_SISO'] = packet[822]
    parsed_data['SU_DlSubAtten_SISO'] = packet[823]
    parsed_data['SU_DlManualAtten_MIMO'] = packet[824]
    parsed_data['SU_DlSubAtten_MIMO'] = packet[825]
    parsed_data['SU_UlManualAtten_SISO'] = packet[826]
    parsed_data['SU_UlSubAtten_SISO'] = packet[827]
    parsed_data['SU_UlManualAtten_MIMO'] = packet[828]
    parsed_data['SU_UlSubAtten_MIMO'] = packet[829]
    parsed_data['LicPassword'] = struct.unpack('<h', bytes([packet[830], packet[831]]))[0]
    parsed_data['DL_OutputOffset_SISO'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[832], packet[833]]))[0])
    parsed_data['DL_OutputOffset_MIMO'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[834], packet[835]]))[0])
    parsed_data['UL_InputOffset_SISO'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[836], packet[837]]))[0])
    parsed_data['UL_InputOffset_MIMO'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[838], packet[839]]))[0])
    parsed_data['SU_UlCasSisoAtten_SISO'] = packet[840]
    parsed_data['SU_UlCasSisoAtten_MIMO'] = packet[841]
    parsed_data['SdOnOffSiso'] = packet[842]
    parsed_data['SdOnOffMimo'] = packet[843]
    parsed_data['DuFixBeam'] = packet[844]
    parsed_data['Reserved4_Local'] = packet[845:852]
    parsed_data['Dl_Siso_Att_Test'] = convert_att_test(struct.unpack('<h', bytes([packet[852], packet[853]]))[0])
    parsed_data['Dl_Mimo_Att_Test'] = convert_att_test(struct.unpack('<h', bytes([packet[854], packet[855]]))[0])
    parsed_data['Ul_Siso_Att_Test'] = convert_att_test(struct.unpack('<h', bytes([packet[856], packet[857]]))[0])
    parsed_data['Ul_Mimo_Att_Test'] = convert_att_test(struct.unpack('<h', bytes([packet[858], packet[859]]))[0])
    parsed_data['Reserved10p1'] = packet[860:892]
    # MVBX 제어
    parsed_data['Mvbx_BeamSet'] = packet[892]
    parsed_data['InstallUseMode'] = packet[893]
    parsed_data['Reserved14'] = packet[894:896]
    parsed_data['Mvbx_FpagImageSize'] = packet[896:900]
    parsed_data['Mvbx_FpagImageStartAddressOffset'] = packet[900:904]
    parsed_data['Reserved15'] = packet[904:920]
    parsed_data['FpgaWriteAddress'] = packet[920:922]
    parsed_data['FpgaWriteData'] = packet[922:924]
    parsed_data['FpgaReadAddress'] = packet[924:926]
    parsed_data['FpgaReadData'] = packet[926:928]
    parsed_data['Reserved31'] = packet[928:940]
    parsed_data['Mvbx_TddSignalMode'] = packet[940]
    parsed_data['Mvbx_RsAgcThreshold'] = packet[941]
    parsed_data['Mvbx_RsAgcMode'] = packet[942]
    parsed_data['Reserved32'] = packet[943]
    parsed_data['Mvbx_Mv2853TxGainSiso'] = packet[944]
    parsed_data['Mvbx_Mv2853RxGainSiso'] = packet[945]
    parsed_data['Mvbx_Mv2850TxGainSiso'] = packet[946]
    parsed_data['Mvbx_Mv2850RxGainSiso'] = packet[947]
    parsed_data['Mvbx_Mv2853TxGainMimo'] = packet[948]
    parsed_data['Mvbx_Mv2853RxGainMimo'] = packet[949]
    parsed_data['Mvbx_Mv2850TxGainMimo'] = packet[950]
    parsed_data['Mvbx_Mv2850RxGainMimo'] = packet[951]
    parsed_data['Mvbx_TxGainSetSiso'] = packet[952]
    parsed_data['Mvbx_RxGainSetSiso'] = packet[953]
    parsed_data['Mvbx_TxGainSetMiso'] = packet[954]
    parsed_data['Mvbx_RxGainSetMiso'] = packet[955]
    parsed_data['beam_info_pss_type'] = struct.unpack('<I', bytes([packet[956], packet[957], packet[958], packet[959]]))[0]
    parsed_data['beam_info_adc_sel'] = struct.unpack('<I', bytes([packet[960], packet[961], packet[962], packet[963]]))[0]
    parsed_data['beam_info_spg '] = struct.unpack('<I', bytes([packet[964], packet[965], packet[966], packet[967]]))[0]
    parsed_data['beam_info_ssbIdx'] = struct.unpack('<I', bytes([packet[968], packet[969], packet[970], packet[971]]))[0]
    parsed_data['beam_info_beamID'] = struct.unpack('<h', bytes([packet[972], packet[973]]))[0]
    parsed_data['Reserved34'] = struct.unpack('<h', bytes([packet[974], packet[975]]))[0]
    parsed_data['beam_info_energy'] = struct.unpack('<I', bytes([packet[976], packet[977], packet[978], packet[979]]))[0]
    parsed_data['beam_info_rsrp '] = struct.unpack('<I', bytes([packet[980], packet[981], packet[982], packet[983]]))[0]
    parsed_data['beam_info_snr'] = struct.unpack('<I', bytes([packet[984], packet[985], packet[986], packet[987]]))[0]
    parsed_data['PllSet'] = struct.unpack('<I', bytes([packet[988], packet[989], packet[990], packet[991]]))[0]
    parsed_data['IsoMeasSet'] = packet[992]
    parsed_data['SuGsOnOff'] = packet[993]
    parsed_data['SuIsoAttSet'] = packet[994]
    parsed_data['GumStick_OnOff'] = packet[995]
    parsed_data['BeamScan_OnOff'] = packet[996]
    parsed_data['IsoDetectMode'] = packet[997]
    parsed_data['ApiLogLevel'] = packet[998]
    parsed_data['ApiAdcSel'] = packet[999]
    parsed_data['ApiSyncPathGain'] = packet[1000]
    parsed_data['ApiDuTimeAdvance'] = packet[1001]
    parsed_data['ApiSuTimeAdvance'] = packet[1002]
    parsed_data['TemperCompensationMode'] = packet[1003]
    parsed_data['ApiVenderFreq'] = struct.unpack('<I', bytes([packet[1004], packet[1005], packet[1006], packet[1007]]))[0]
    parsed_data['ApiGsOutputPowerOffsetSiso'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[1008], packet[1009]]))[0])
    parsed_data['BeamAntSelect'] = packet[1010]
    parsed_data['DecodeRecoveryFuncOnOff'] = packet[1011]
    parsed_data['gNB_ScanOnOff'] = packet[1012]
    parsed_data['SuEndMode'] = packet[1013]
    parsed_data['ApiGsOutputPowerOffsetMimo'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[1014], packet[1015]]))[0])
    parsed_data['gNB_Vendor'] = packet[1016]
    parsed_data['Gs_Gain_Siso'] = packet[1017]
    parsed_data['Gs_Gain_Mimo'] = packet[1018]
    parsed_data['ApiInitRetryMode'] = packet[1019]
    parsed_data['Orientation'] = f"{struct.unpack('<h', bytes([packet[1020], packet[1021]]))[0]:.3f}"
    parsed_data['Tilt'] = f"{struct.unpack('<h', bytes([packet[1022], packet[1023]]))[0]:.3f}"
    parsed_data['GS_AttenOffset_DL_Siso'] = struct.unpack('<b', bytes([packet[1024]]))[0]
    parsed_data['GS_AttenOffset_DL_Mimo'] = struct.unpack('<b', bytes([packet[1025]]))[0]
    parsed_data['GS_AttenOffset_UL_Siso'] = struct.unpack('<b', bytes([packet[1026]]))[0]
    parsed_data['GS_AttenOffset_UL_Mimo'] = struct.unpack('<b', bytes([packet[1027]]))[0]
    parsed_data['ConSerialNum'] = ''.join([chr(b) for b in packet[1028:1044] if b != 0])
    parsed_data['AomTemperConperMode'] = packet[1044]
    parsed_data['GS_AttenOffset_30by15_DL_Siso'] = packet[1045]
    parsed_data['GS_AttenOffset_30by30_DL_Siso'] = packet[1046]
    parsed_data['GS_AttenOffset_60by15_DL_Siso'] = packet[1047]
    parsed_data['GS_AttenOffset_60by30_DL_Siso'] = packet[1048]
    parsed_data['GS_AttenOffset_60by60_DL_Siso'] = packet[1049]
    parsed_data['GS_AttenOffset_30by15_DL_Mimo'] = packet[1050]
    parsed_data['GS_AttenOffset_30by30_DL_Mimo'] = packet[1051]
    parsed_data['GS_AttenOffset_60by15_DL_Mimo'] = packet[1052]
    parsed_data['GS_AttenOffset_60by30_DL_Mimo'] = packet[1053]
    parsed_data['GS_AttenOffset_60by60_DL_Mimo'] = packet[1054]
    parsed_data['GS_AttenOffset_30by15_UL_Siso'] = packet[1055]
    parsed_data['GS_AttenOffset_30by30_UL_Siso'] = packet[1056]
    parsed_data['GS_AttenOffset_60by15_UL_Siso'] = packet[1057]
    parsed_data['GS_AttenOffset_60by30_UL_Siso'] = packet[1058]
    parsed_data['GS_AttenOffset_60by60_UL_Siso'] = packet[1059]
    parsed_data['GS_AttenOffset_30by15_UL_Mimo'] = packet[1060]
    parsed_data['GS_AttenOffset_30by30_UL_Mimo'] = packet[1061]
    parsed_data['GS_AttenOffset_60by15_UL_Mimo'] = packet[1062]
    parsed_data['GS_AttenOffset_60by30_UL_Mimo'] = packet[1063]
    parsed_data['GS_AttenOffset_60by60_UL_Mimo'] = packet[1064]
    parsed_data['Reserved41'] = packet[1065:1089]
    parsed_data['LowRsrpStillTime'] = packet[1089]
    parsed_data['LowRsrpLevel'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[1090], packet[1091]]))[0])
    parsed_data['SU_DlCasSisoAtten_SISO'] = packet[1092]
    parsed_data['SU_DlCasSisoAtten_MIMO'] = packet[1093]
    parsed_data['SU_DlCasSisoAttenTest_SISO'] = packet[1094]
    parsed_data['SU_DlCasSisoAttenTest_MIMO'] = packet[1095]
    parsed_data['SU_UlCasSisoAttenTest_SISO'] = packet[1096]
    parsed_data['SU_UlCasSisoAttenTest_MIMO'] = packet[1097]
    parsed_data['Reserved41p1'] = packet[1098:1101]
    parsed_data['PciResetOnOff'] = packet[1101]
    parsed_data['PciNo'] = struct.unpack('<h', bytes([packet[1102], packet[1103]]))[0]
    parsed_data['PciTime'] = packet[1104]
    parsed_data['Reserved42'] = packet[1105:1112]
    # Reserved42 감지 시 RX 박스 끄기
    socketio.emit("rx_off")

    return parsed_data

def parse_TddStatusPacket(packet):
    parsed_data = {}
    #Du 상태
    parsed_data['Rcv_Main_Sys'] = packet[0]
    parsed_data['Rcv_Sub_Sys'] = packet[1]
    parsed_data['Rcv_Object'] = packet[2]
    parsed_data['Trans_Main_Sys'] = packet[3]
    parsed_data['Trans_Sub_Sys'] = packet[4]
    parsed_data['Trans_Object'] = packet[5]
    parsed_data['CMD'] = packet[6]
    parsed_data['EQUIP_TYPE'] = packet[7]
    parsed_data['RESERVED'] = packet[8:10]
    parsed_data['SubData_Size'] = struct.unpack('<h', bytes([packet[10], packet[11]]))[0]
    parsed_data['ConMuFlag'] = packet[12:16]
    # TTG/RTG/TSYNC Delay: 500 → 50us 변환 (단위: 0.5dBm)
    parsed_data['TTG_CTRL1'] = round(struct.unpack('<h', bytes([packet[16], packet[17]]))[0] / 10, 1)
    parsed_data['RTG_CTRL1'] = round(struct.unpack('<h', bytes([packet[18], packet[19]]))[0] / 10, 1)
    parsed_data['TSYNC_DELAY1'] = round(struct.unpack('<h', bytes([packet[20], packet[21]]))[0] / 10, 1)
    parsed_data['TSYNC_OUT_SEL1'] = packet[22]
    parsed_data['Resved1'] = packet[23]
    parsed_data['TTG_CTRL2'] = round(struct.unpack('<h', bytes([packet[24], packet[25]]))[0] / 10, 1)
    parsed_data['RTG_CTRL2'] = round(struct.unpack('<h', bytes([packet[26], packet[27]]))[0] / 10, 1)
    parsed_data['TSYNC_DELAY2'] = round(struct.unpack('<h', bytes([packet[28], packet[29]]))[0] / 10, 1)
    parsed_data['TSYNC_OUT_SEL2'] = packet[30]
    parsed_data['Resved2'] = packet[31]
    parsed_data['TTG_CTRL3'] = round(struct.unpack('<h', bytes([packet[32], packet[33]]))[0] / 10, 1)
    parsed_data['RTG_CTRL3'] = round(struct.unpack('<h', bytes([packet[34], packet[35]]))[0] / 10, 1)
    parsed_data['TSYNC_DELAY3'] = round(struct.unpack('<h', bytes([packet[36], packet[37]]))[0] / 10, 1)
    parsed_data['TSYNC_OUT_SEL3'] = packet[38]
    parsed_data['F_Mode'] = packet[39]
    parsed_data['TDD_Slot_Format'] = packet[40:200]
    parsed_data['TDD_3gpp_table'] = packet[200:984]
    # TDD Frequency (60KHz 단위를 MHz로 변환하여 2자리까지 표시)
    parsed_data['TDD_Freq'] = format(round(struct.unpack('<I', bytes(packet[984:988]))[0] / 1000, 2), '.2f')
    parsed_data['TDD_Arfcn'] = struct.unpack('<I', bytes([packet[988], packet[989], packet[990], packet[991]]))[0]
    parsed_data['MvbxSsbMu'] = packet[992]
    parsed_data['MvbxPssType'] = packet[993]
    parsed_data['MvbxAdcSel'] = packet[994]
    parsed_data['MvbxTddRate'] = packet[995]
    parsed_data['TddSyncTest'] = packet[996]
    parsed_data['Tdd_Famode'] = packet[997]
    parsed_data['Resved3'] = packet[998:1008]

    return parsed_data



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

    # ---------------------------- 서버 실행 ----------------------------
    socketio.run(app, host="0.0.0.0", port=5001, debug=True, use_reloader=False)
