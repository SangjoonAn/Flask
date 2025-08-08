from flask import Flask, render_template, request, redirect, url_for, session
from flask_socketio import SocketIO
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



@socketio.on('hex_packet')
def handle_hex_packet(data):
    """ HEX 데이터 수신 및 변환 """
    try:
        binary_data = binascii.unhexlify(data)  # HEX → Binary 변환
        cmd = binary_data[6]
        if cmd == 0x55 :
            update_status = parse_AllStatusPacket(binary_data)
            socketio.emit("update_status", {"packet": update_status})
                    
            # 알람 상태를 별도로 전송
            if 'AlarmStatus' in update_status:
                socketio.emit("alarm_status_update", {"AlarmStatus": update_status['AlarmStatus']})
            
            # Mask 알람 상태도 전송
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

@socketio.on('du_Ctrl_packet')
def handle_du_control_packet(data):
    """ DU 제어 패킷 수신 및 처리 """
    try:
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        print(f"[{current_time}] 🎛️ Received DU Control Packet")
        print("📦 Received data:", data)
        
        # 패킷 데이터 처리
        if 'ConMuFlag' in data and data['ConMuFlag']:
            if data['ConMuFlag'][0] == 0x01:
                print("🔄 DU Reset 명령 감지됨")
                # TODO: 실제 DU 장비로 Reset 명령 전송
                # 여기에 실제 하드웨어 통신 로직 추가
        
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
            
            # Polling Time 상태 확인 (비트 7)
            if current_flag & 0x80:  # 0x80 = 10000000 (비트 7)
                print("⏱️ Polling Time 활성화됨 (비트 7 = 1)")
                # TODO: 실제 DU 장비로 Polling Time 활성화 전송
                # 여기에 실제 하드웨어 통신 로직 추가
            else:
                print("⏱️ Polling Time 비활성화됨 (비트 7 = 0)")
                # TODO: 실제 DU 장비로 Polling Time 비활성화 전송
                # 여기에 실제 하드웨어 통신 로직 추가
        
        # Polling Time 값 확인 (별도 필드로 전송된 경우)
        if 'PollingTime' in data:
            polling_time = data['PollingTime']
            print(f"⏱️ 사용자 입력 Polling Time: {polling_time}ms")
        elif 'pollingTime' in data:
            polling_time = data['pollingTime']
            print(f"⏱️ 사용자 입력 Polling Time: {polling_time}ms")
        
        # 성공 응답
        socketio.emit("du_control_response", {"status": "success", "message": "DU Control packet processed"})
        return {"status": "success", "message": "DU Control packet received"}
        
    except Exception as e:
        print(f"❌ DU Control Packet Error: {e}")
        socketio.emit("du_control_response", {"status": "error", "message": str(e)})
        return {"status": "error", "message": str(e)}




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
    
    # packet[635]에서 0번째와 2번째 비트 추출
    dl_alc_bits = {
        'SISO_MASK_DL_ALC': (packet[635] >> 0) & 1,  # 비트 0
        'MIMO_MASK_DL_ALC': (packet[635] >> 2) & 1   # 비트 2
    }
    parsed_data['DL_ALC_Bits'] = dl_alc_bits

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
    parsed_data['LD3_DET_DL0_SISO_Low'] = struct.unpack('<h', bytes([packet[788], packet[789]]))[0]
    parsed_data['LD4_DET_DL1_MIMO_Low'] = struct.unpack('<h', bytes([packet[790], packet[791]]))[0]
    parsed_data['PD3_DET_UL0_SISO_Low'] = struct.unpack('<h', bytes([packet[792], packet[793]]))[0]
    parsed_data['PD4_DET_UL1_MIMO_Low'] = struct.unpack('<h', bytes([packet[794], packet[795]]))[0]
    parsed_data['LD1_DET_DL0_SISO_Offset'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[796], packet[797]]))[0])
    parsed_data['LD2_DET_DL1_MIMO_Offset'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[798], packet[799]]))[0])
    parsed_data['PD1_DET_UL0_SISO_Offset'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[800], packet[801]]))[0])
    parsed_data['PD2_DET_UL1_MIMO_Offset'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[802], packet[803]]))[0])
    parsed_data['LD3_DET_DL0_SISO_Offset'] = struct.unpack('<h', bytes([packet[804], packet[805]]))[0]
    parsed_data['LD4_DET_DL1_MIMO_Offset'] = struct.unpack('<h', bytes([packet[806], packet[807]]))[0]
    parsed_data['PD3_DET_UL0_SISO_Offset'] = struct.unpack('<h', bytes([packet[808], packet[809]]))[0]
    parsed_data['PD4_DET_UL1_MIMO_Offset'] = struct.unpack('<h', bytes([packet[810], packet[811]]))[0]
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
    parsed_data['Reserved33'] = packet[1013]
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
    parsed_data['McuSwVer'] = (packet[13] << 8) | packet[12]
    parsed_data['RptMaker'] = packet[14]
    parsed_data['RtpKind'] = packet[15]
    parsed_data['StaAlarmFlag'] = packet[16:21]
    parsed_data['System_Year'] = '.'.join(['{:02d}'.format((packet[21] << 8) | packet[20]), '{:02d}'.format(packet[22]), '{:02d}'.format(packet[23])])
    parsed_data['System_hour'] = ':'.join(['{:02d}'.format(packet[24]), '{:02d}'.format(packet[25]), '{:02d}'.format(packet[26])])
    parsed_data['SysTemper'] = packet[27]
    parsed_data['Packet_Send_Count'] = struct.unpack('<I', bytes([packet[28], packet[29], packet[30], packet[31]]))[0]
    parsed_data['Packet_Req_Count'] = struct.unpack('<I', bytes([packet[32], packet[33], packet[34], packet[35]]))[0]
    parsed_data['FPGA_Boot_Status'] = packet[36]
    parsed_data['FPGA_Init_Status'] = packet[37]
    parsed_data['Beam_Scan_Status'] = packet[38]
    parsed_data['ApiOldNewVer'] = packet[39]
    parsed_data['RF_ALC_Att_DL0_Siso'] = struct.unpack('<h', bytes([packet[40], packet[41]]))[0]
    parsed_data['RF_ALC_Att_DL1_Mimo'] = struct.unpack('<h', bytes([packet[42], packet[43]]))[0]
    parsed_data['RF_ALC_Att_UL0_Siso'] = struct.unpack('<h', bytes([packet[44], packet[45]]))[0]
    parsed_data['RF_ALC_Att_UL1_Mimo'] = struct.unpack('<h', bytes([packet[46], packet[47]]))[0]
    parsed_data['RF_DET_DL0_OUT'] = struct.unpack('<h', bytes([packet[48], packet[49]]))[0]
    parsed_data['RF_DET_UL0_OUT'] = struct.unpack('<h', bytes([packet[50], packet[51]]))[0]
    parsed_data['RF_DET_DL1_OUT'] = struct.unpack('<h', bytes([packet[52], packet[53]]))[0]
    parsed_data['RF_DET_UL1_OUT'] = struct.unpack('<h', bytes([packet[54], packet[55]]))[0]
    parsed_data['FPGA_Ver'] = '.'.join([str(packet[56]), str(packet[57]), str(packet[58])])
    parsed_data['Gumstick_Ver'] = '.'.join([str(packet[59]), str(packet[60]), str(packet[61])])
    parsed_data['SyncStatus'] = packet[62]
    parsed_data['TryBeamScanCont'] = struct.unpack('<h', bytes([packet[63], packet[64]]))[0]
    parsed_data['MVBX_pci'] = struct.unpack('<h', bytes([packet[65], packet[66]]))[0]
    parsed_data['MVBX_ssb'] = struct.unpack('<h', bytes([packet[67], packet[68]]))[0]
    parsed_data['MVBX_rsrp'] = struct.unpack('<f', bytes([packet[69], packet[70], packet[71], packet[72]]))[0]
    parsed_data['MVBX_snr'] = struct.unpack('<f', bytes([packet[73], packet[74], packet[75], packet[76]]))[0]
    parsed_data['MVBX_BeamInfo_beamId1'] = struct.unpack('<h', bytes([packet[77], packet[78]]))[0]
    parsed_data['MVBX_BeamInfo_beamId2'] = struct.unpack('<h', bytes([packet[79], packet[80]]))[0]
    parsed_data['MVBX_BeamInfo_beamId3'] = struct.unpack('<h', bytes([packet[81], packet[82]]))[0]
    parsed_data['MVBX_BeamInfo_beamId4'] = struct.unpack('<h', bytes([packet[83], packet[84]]))[0]
    parsed_data['MVBX_BeamInfo_pci1'] = struct.unpack('<h', bytes([packet[85], packet[86]]))[0]
    parsed_data['MVBX_BeamInfo_pci2'] = struct.unpack('<h', bytes([packet[87], packet[88]]))[0]
    parsed_data['MVBX_BeamInfo_pci3'] = struct.unpack('<h', bytes([packet[89], packet[90]]))[0]
    parsed_data['MVBX_BeamInfo_pci4'] = struct.unpack('<h', bytes([packet[91], packet[92]]))[0]
    parsed_data['MVBX_BeamInfo_ssbldx1'] = struct.unpack('<I', bytes([packet[93], packet[94], packet[95], packet[96]]))[0]
    parsed_data['MVBX_BeamInfo_ssbldx2'] = struct.unpack('<I', bytes([packet[97], packet[98], packet[99], packet[100]]))[0]
    parsed_data['MVBX_BeamInfo_ssbldx3'] = struct.unpack('<I', bytes([packet[101], packet[102], packet[103], packet[104]]))[0]
    parsed_data['MVBX_BeamInfo_ssbldx4'] = struct.unpack('<I', bytes([packet[105], packet[106], packet[107], packet[108]]))[0]
    parsed_data['MVBX_BeamInfo_energy1'] = struct.unpack('<I', bytes([packet[109], packet[110], packet[111], packet[112]]))[0]
    parsed_data['MVBX_BeamInfo_energy2'] = struct.unpack('<I', bytes([packet[113], packet[114], packet[115], packet[116]]))[0]
    parsed_data['MVBX_BeamInfo_energy3'] = struct.unpack('<I', bytes([packet[117], packet[118], packet[119], packet[120]]))[0]
    parsed_data['MVBX_BeamInfo_energy4'] = struct.unpack('<I', bytes([packet[121], packet[122], packet[123], packet[124]]))[0]
    parsed_data['MVBX_BeamInfo_psstype1'] = struct.unpack('<I', bytes([packet[125], packet[126], packet[127], packet[128]]))[0]
    parsed_data['MVBX_BeamInfo_psstype2'] = struct.unpack('<I', bytes([packet[129], packet[130], packet[131], packet[132]]))[0]
    parsed_data['MVBX_BeamInfo_psstype3'] = struct.unpack('<I', bytes([packet[133], packet[134], packet[135], packet[136]]))[0]
    parsed_data['MVBX_BeamInfo_psstype4'] = struct.unpack('<I', bytes([packet[137], packet[138], packet[139], packet[140]]))[0]
    parsed_data['MVBX_BeamInfo_snr1'] = struct.unpack('<f', bytes([packet[141], packet[142], packet[143], packet[144]]))[0]
    parsed_data['MVBX_BeamInfo_snr2'] = struct.unpack('<f', bytes([packet[145], packet[146], packet[147], packet[148]]))[0]
    parsed_data['MVBX_BeamInfo_snr3'] = struct.unpack('<f', bytes([packet[149], packet[150], packet[151], packet[152]]))[0]
    parsed_data['MVBX_BeamInfo_snr4'] = struct.unpack('<f', bytes([packet[153], packet[154], packet[155], packet[156]]))[0]
    parsed_data['MVBX_BeamInfo_rsrp1'] = struct.unpack('<f', bytes([packet[157], packet[158], packet[159], packet[160]]))[0]
    parsed_data['MVBX_BeamInfo_rsrp2'] = struct.unpack('<f', bytes([packet[161], packet[162], packet[163], packet[164]]))[0]
    parsed_data['MVBX_BeamInfo_rsrp3'] = struct.unpack('<f', bytes([packet[165], packet[166], packet[167], packet[168]]))[0]
    parsed_data['MVBX_BeamInfo_rsrp4'] = struct.unpack('<f', bytes([packet[169], packet[170], packet[171], packet[172]]))[0]
    parsed_data['pss_pulse_count'] = struct.unpack('<I', bytes([packet[173], packet[174], packet[175], packet[176]]))[0]
    parsed_data['decoded_ssb_count'] = struct.unpack('<I', bytes([packet[177], packet[178], packet[179], packet[180]]))[0]
    parsed_data['decoded_ssb_no_error_count'] = struct.unpack('<I', bytes([packet[181], packet[182], packet[183], packet[184]]))[0]
    parsed_data['Gumstick_CurTemper'] = struct.unpack('<h', bytes([packet[185], packet[186]]))[0]
    parsed_data['Gumstick_StartTemper'] = struct.unpack('<h', bytes([packet[187], packet[188]]))[0]
    parsed_data['DlTemperCompensation'] = packet[189]
    parsed_data['UlTemperCompensation'] = packet[190]
    parsed_data['PllRelockCount'] = struct.unpack('<h', bytes([packet[191], packet[192]]))[0]
    parsed_data['DecodedRate'] = packet[193]
    parsed_data['DsOutputPower_SISO'] = struct.unpack('<h', bytes([packet[194], packet[195]]))[0]
    parsed_data['AGC_Input_Power'] = struct.unpack('<h', bytes([packet[196], packet[197]]))[0]
    parsed_data['DsOutputPower_MIMO'] = struct.unpack('<h', bytes([packet[198], packet[199]]))[0]
    parsed_data['Actual_Orientation'] = struct.unpack('<h', bytes([packet[200], packet[201]]))[0]
    parsed_data['Actual_Tilt'] = struct.unpack('<h', bytes([packet[202], packet[203]]))[0]
    #Du 제어
    parsed_data['cDu_InitCheckNum'] = packet[204:208]
    parsed_data['cDu_ConMuFlag'] = packet[208:220]
    parsed_data['cDu_GW'] = packet[220:224]
    parsed_data['cDu_ServerIP'] = packet[224:228]
    parsed_data['cDu_ClientIP'] = packet[228:232]
    parsed_data['cDu_ConSysTime'] = packet[232:239]
    parsed_data['cDu_RptMakerCode'] = packet[239]
    parsed_data['cDu_SysTemperHighLvl'] = packet[240]
    parsed_data['cDu_SysTemperLowLvl'] = packet[241]
    parsed_data['cDu_SubInitCheckNum'] = packet[242]
    parsed_data['cDu_DebugMode'] = packet[243]
    parsed_data['cDu_AlarmMask'] = packet[244:248]
    parsed_data['cDu_DownloadPath_GuiOrEms'] = packet[248]
    parsed_data['cDu_ApiInitMode'] = packet[249]
    parsed_data['cDu_AttTestMode'] = packet[250]
    parsed_data['cDu_DL_UL_TEST'] = packet[251]
    parsed_data['cDu_PreStaAlarm'] = packet[252:256]
    parsed_data['cDu_RsrpOffset'] = packet[256]
    parsed_data['cDU_ALC_DL0_SISO_Mode'] = packet[260]
    parsed_data['cDU_ALC_DL1_MIMO_Mode'] = packet[261]
    parsed_data['cDU_ALC_UL0_SISO_Mode'] = packet[262]
    parsed_data['cDU_ALC_UL1_MIMO_Mode'] = packet[263]
    parsed_data['cDU_ALC_DL0_SISO_Level'] = struct.unpack('<h', bytes([packet[264], packet[265]]))[0]
    parsed_data['cDu_FaMode'] = packet[266]
    parsed_data['cDU_DlManualAtten_SISO1'] = packet[267]    
    parsed_data['cDU_ALC_UL0_SISO_Level'] = struct.unpack('<h', bytes([packet[268], packet[269]]))[0]
    parsed_data['cDU_DlManualAtten_SISO2'] = packet[270]    
    parsed_data['cDU_DlManualAtten_SISO3'] = packet[271]    
    parsed_data['cDU_SISO_RF_DET_DL0_OUT_High'] = struct.unpack('<h', bytes([packet[272], packet[273]]))[0]
    parsed_data['cDU_SISO_RF_DET_UL0_OUT_High'] = struct.unpack('<h', bytes([packet[274], packet[275]]))[0]
    parsed_data['cDU_DlManualAtten_SISO4'] = packet[276]    
    parsed_data['cDU_DlManualAtten_SISO5'] = packet[277]   
    parsed_data['cDU_SISO_RF_DET_UL1_OUT_High'] = struct.unpack('<h', bytes([packet[278], packet[279]]))[0]
    parsed_data['cDU_DlManualAtten_SISO'] = packet[280]
    parsed_data['cDU_DlSubAtten_SISO'] = packet[281]
    parsed_data['cDU_DlManualAtten_SISO0'] = packet[282]
    parsed_data['cDU_UlManualAtten_SISO0'] = packet[283]
    parsed_data['cDU_UlManualAtten_SISO'] = packet[284]
    parsed_data['cDU_UlSubAtten_SISO'] = packet[285]
    parsed_data['cDU_UlIsoAtten_SISO'] = packet[286]
    parsed_data['cDU_UlManualAtten_SISO1'] = packet[287]
    parsed_data['cDU_UlManualAtten_SISO2'] = packet[288]
    parsed_data['cDU_UlManualAtten_SISO3'] = packet[289]
    parsed_data['cDU_DL_OutputOffset_SISO'] = struct.unpack('<h', bytes([packet[290], packet[291]]))[0]
    parsed_data['cDU_UlManualAtten_SISO4'] = packet[292]
    parsed_data['cDU_UlManualAtten_SISO5'] = packet[293]
    parsed_data['cDU_UL_InputOffset_SISO'] = struct.unpack('<h', bytes([packet[294], packet[295]]))[0]
    parsed_data['cDU_UL_InputOffset_MIMO'] = struct.unpack('<h', bytes([packet[296], packet[297]]))[0]
    parsed_data['cDu_FixBeam'] = packet[298]
    parsed_data['cDU_Dl_Siso_Att_Test'] = struct.unpack('<h', bytes([packet[299], packet[300]]))[0]
    parsed_data['cDU_Ul_Siso_Att_Test'] = struct.unpack('<h', bytes([packet[301], packet[302]]))[0]
    parsed_data['cDU_RF_Switch'] = packet[303]
    parsed_data['cDU_Mvbx_BeamSet'] = packet[304]
    parsed_data['cDU_LowAutoScanStdCount'] = packet[305]
    parsed_data['cDU_Mvbx_FpagImageSize'] = packet[306:310]
    parsed_data['cDU_Mvbx_FpagImageStartAddressOffset'] = packet[310:314]
    parsed_data['cDU_LowAutoScanStdLevel'] = struct.unpack('<f', bytes([packet[314], packet[315], packet[316], packet[317]]))[0]
    parsed_data['cDU_FpgaWriteAddress'] = packet[318:320]
    parsed_data['cDU_FpgaWriteData'] = packet[320:322]
    parsed_data['cDU_FpgaReadAddress'] = packet[322:324]
    parsed_data['cDU_FpgaReadData'] = packet[324:326]
    parsed_data['cDU_Mvbx_TddSignalMode'] = packet[326]
    parsed_data['cDU_Mvbx_RsAgcThreshold'] = packet[327]
    parsed_data['cDU_Mvbx_RsAgcMode'] = packet[328]
    parsed_data['cDU_Mvbx_Mv2853TxGainSiso'] = packet[329]
    parsed_data['cDU_Mvbx_Mv2853RxGainSiso'] = packet[330]
    parsed_data['cDU_Mvbx_Mv2850TxGainSiso'] = packet[331]
    parsed_data['cDU_Mvbx_Mv2850RxGainSiso'] = packet[332]
    parsed_data['cDU_Mvbx_Mv2853TxGainMimo'] = packet[333]
    parsed_data['cDU_Mvbx_Mv2853RxGainMimo'] = packet[334]
    parsed_data['cDU_Mvbx_Mv2850TxGainMimo'] = packet[335]
    parsed_data['cDU_Mvbx_Mv2850RxGainMimo'] = packet[336]
    parsed_data['cDU_Mvbx_TxGainSetSiso'] = packet[337]
    parsed_data['cDU_Mvbx_RxGainSetSiso'] = packet[338]
    parsed_data['cDU_Mvbx_TxGainSetMiso'] = packet[339]
    parsed_data['cDU_Mvbx_RxGainSetMiso'] = packet[340]
    parsed_data['cDU_beam_info_pss_type'] = struct.unpack('<I', bytes([packet[341], packet[342], packet[343], packet[344]]))[0]
    parsed_data['cDU_beam_info_adc_sel'] = struct.unpack('<I', bytes([packet[345], packet[346], packet[347], packet[348]]))[0]
    parsed_data['cDU_beam_info_spg '] = struct.unpack('<I', bytes([packet[349], packet[350], packet[351], packet[352]]))[0]
    parsed_data['cDU_beam_info_ssbIdx'] = struct.unpack('<I', bytes([packet[353], packet[354], packet[355], packet[356]]))[0]
    parsed_data['cDU_beam_info_beamID'] = struct.unpack('<h', bytes([packet[357], packet[358]]))[0]
    parsed_data['cDU_beam_info_energy'] = struct.unpack('<I', bytes([packet[359], packet[360], packet[361], packet[362]]))[0]
    parsed_data['cDU_beam_info_rsrp '] = struct.unpack('<I', bytes([packet[363], packet[364], packet[365], packet[366]]))[0]
    parsed_data['cDU_beam_info_snr'] = struct.unpack('<I', bytes([packet[367], packet[368], packet[369], packet[370]]))[0]
    parsed_data['cDU_GumStick_OnOff'] = packet[371]
    parsed_data['cDU_BeamScan_OnOff'] = packet[372]
    parsed_data['cDU_ApiLogLevel'] = packet[373]
    parsed_data['cDU_ApiAdcSel'] = packet[374]
    parsed_data['cDU_ApiSyncPathGain'] = packet[375]
    parsed_data['cDU_ApiDuTimeAdvance'] = packet[376]
    parsed_data['cDU_ApiSuTimeAdvance'] = packet[377]
    parsed_data['cDU_TemperCompensationMode'] = packet[378]
    parsed_data['cDU_ApiVenderFreq'] = struct.unpack('<I', bytes([packet[379], packet[380], packet[381], packet[382]]))[0]
    parsed_data['cDU_ApiGsOutputPowerOffsetSiso'] = struct.unpack('<h', bytes([packet[383], packet[384]]))[0]
    parsed_data['cDU_DecodeRecoveryFuncOnOff'] = packet[385]
    parsed_data['cDU_gNB_ScanOnOff'] = packet[386]
    parsed_data['cDU_ApiGsOutputPowerOffsetMimo'] = struct.unpack('<h', bytes([packet[387], packet[388]]))[0]
    parsed_data['cDU_gNB_Vendor'] = packet[389]
    parsed_data['cDU_Gs_Gain_Siso'] = packet[390]
    parsed_data['cDU_Gs_Gain_Mimo'] = packet[391]
    parsed_data['cDU_ApiInitRetryMode'] = packet[392]
    parsed_data['cDU_Orientation'] = struct.unpack('<h', bytes([packet[393], packet[394]]))[0]
    parsed_data['cDU_Tilt'] = struct.unpack('<h', bytes([packet[395], packet[396]]))[0]
    parsed_data['cDU_GS_AttenOffset_DL_Siso'] = packet[397]
    parsed_data['cDU_GS_AttenOffset_DL_Mimo'] = packet[398]
    parsed_data['cDU_GS_AttenOffset_UL_Siso'] = packet[399]
    parsed_data['cDU_GS_AttenOffset_UL_Mimo'] = packet[400]
    parsed_data['cDU_AomTemperConperMode'] = packet[401]
    parsed_data['cDU_LowRsrpStillTime'] = packet[402]
    parsed_data['cDU_LowRsrpLevel'] = convert_to_01dbm(struct.unpack('<h', bytes([packet[403], packet[404]]))[0])
    parsed_data['cDU_PciResetOnOff'] = packet[405]
    parsed_data['cDU_PciNo'] = struct.unpack('<h', bytes([packet[406], packet[407]]))[0]
    parsed_data['cDU_PciTime'] = packet[408]
    parsed_data['cDU_Mvbx_AutoScanStdOnOff'] = packet[409]
    parsed_data['cDU_MVBX_Beam_AutoScanStd'] = packet[410]
    parsed_data['cDU_MVBX_Beam_ManualScanStdOnOff'] = packet[411]
    parsed_data['cICS_DL_DSPInTh_Offset'] = packet[412]
    parsed_data['cICS_UL_DSPInTh_Offset'] = packet[413]
    parsed_data['cDU_DacValue'] = struct.unpack('<h', bytes([packet[414], packet[415]]))[0]
    #Su상태
    parsed_data['Su_McuSwVer'] = packet[416] | (packet[417] << 8) 
    parsed_data['Su_RtpKind'] = packet[418]
    parsed_data['Su_FPGA_Init_Status'] = packet[419]
    parsed_data['Su_StaAlarmFlag'] = packet[420:424]
    parsed_data['Su_System_Year'] = '.'.join(['{:02d}'.format((packet[424] | packet[425] << 8)), '{:02d}'.format(packet[426]), '{:02d}'.format(packet[427])])
    parsed_data['Su_System_hour'] = ':'.join(['{:02d}'.format(packet[428]), '{:02d}'.format(packet[429]), '{:02d}'.format(packet[430])])
    parsed_data['Su_SysTemper'] = packet[431]
    parsed_data['Su_Packet_Send_Count'] = struct.unpack('<I', bytes([packet[432], packet[433], packet[434], packet[435]]))[0]
    parsed_data['Su_Packet_Req_Count'] = struct.unpack('<I', bytes([packet[436], packet[437], packet[438], packet[439]]))[0]
    parsed_data['SU_DlIsoAtten_SISO'] = packet[440]
    parsed_data['SU_DlIsoAtten_MIMO'] = packet[441]
    parsed_data['SU_UlIsoAtten_SISO'] = packet[442]
    parsed_data['SU_UlIsoAtten_MIMO'] = packet[443]
    parsed_data['Su_RF_DET_DL0_OUT'] = struct.unpack('<h', bytes([packet[444], packet[445]]))[0]
    parsed_data['Su_RF_DET_UL0_OUT'] = struct.unpack('<h', bytes([packet[446], packet[447]]))[0]
    parsed_data['Su_RF_DET_DL1_OUT'] = struct.unpack('<h', bytes([packet[448], packet[449]]))[0]
    parsed_data['Su_RF_DET_UL1_OUT'] = struct.unpack('<h', bytes([packet[450], packet[451]]))[0]
    parsed_data['Su_Gumstick_Ver'] = '.'.join([str(packet[452]), str(packet[453]), str(packet[454])])
    parsed_data['Su_SyncStatus'] = packet[455]
    parsed_data['Su_MVBX_BeamInfo_beamId1'] = struct.unpack('<h', bytes([packet[456], packet[457]]))[0]
    parsed_data['Su_Gumstick_CurTemper'] = struct.unpack('<h', bytes([packet[458], packet[459]]))[0]
    parsed_data['Su_Gumstick_StartTemper'] = struct.unpack('<h', bytes([packet[460], packet[461]]))[0]
    parsed_data['Su_DlTemperCompensation'] = packet[462]
    parsed_data['Su_UlTemperCompensation'] = packet[463]
    parsed_data['Su_PllRelockCount'] = struct.unpack('<h', bytes([packet[464], packet[465]]))[0]
    parsed_data['Su_DsOutputPower_SISO'] = struct.unpack('<h', bytes([packet[466], packet[467]]))[0]
    parsed_data['Su_AGC_Input_Power'] = struct.unpack('<h', bytes([packet[468], packet[469]]))[0]
    parsed_data['Su_DsOutputPower_MIMO'] = struct.unpack('<h', bytes([packet[470], packet[471]]))[0]
    parsed_data['Su_Actual Orientation'] = struct.unpack('<h', bytes([packet[472], packet[473]]))[0]
    parsed_data['Su_Actual Tilt'] = struct.unpack('<h', bytes([packet[474], packet[475]]))[0]
    #Su 제어
    parsed_data['cSu_InitCheckNum'] = packet[476:480]
    parsed_data['cSu_ConMuFlag'] = packet[480:484]
    parsed_data['cSu_DL_OutputOffset_SISO1'] = struct.unpack('<h', bytes([packet[484], packet[485]]))[0]
    parsed_data['cSu_DL_OutputOffset_SISO2'] = struct.unpack('<h', bytes([packet[486], packet[487]]))[0]
    parsed_data['cSu_DL_OutputOffset_SISO3'] = struct.unpack('<h', bytes([packet[488], packet[489]]))[0]
    parsed_data['cSu_DL_OutputOffset_SISO4'] = struct.unpack('<h', bytes([packet[490], packet[491]]))[0]
    parsed_data['cSu_DL_OutputOffset_SISO5'] = struct.unpack('<h', bytes([packet[492], packet[493]]))[0]
    parsed_data['cSu_UL_InputOffset_SISO1'] = struct.unpack('<h', bytes([packet[494], packet[495]]))[0]
    parsed_data['cSu_UL_InputOffset_SISO2'] = struct.unpack('<h', bytes([packet[496], packet[497]]))[0]
    parsed_data['cSu_UL_InputOffset_SISO3'] = struct.unpack('<h', bytes([packet[498], packet[499]]))[0]
    parsed_data['cSu_UL_InputOffset_SISO4'] = struct.unpack('<h', bytes([packet[500], packet[501]]))[0]
    parsed_data['cSu_UL_InputOffset_SISO5'] = struct.unpack('<h', bytes([packet[502], packet[503]]))[0]
    parsed_data['cSu_ConSysTime'] = packet[504:511]
    parsed_data['cSu_SysTemperHighLvl'] = packet[511]
    parsed_data['cSu_SysTemperLowLvl'] = packet[512]
    parsed_data['cSu_SubInitCheckNum'] = packet[513]
    parsed_data['cSu_DebugMode'] = packet[514]
    parsed_data['cSu_Alarm Mask'] = packet[515:519]
    parsed_data['cSu_ApiInitMode'] = packet[519]
    parsed_data['cSu_AttTestMode'] = packet[520]
    parsed_data['cSu_DL_UL_TEST'] = packet[521]
    parsed_data['cSu_PreStaAlarm'] = packet[522:526]
    parsed_data['cSu_DL_OutputOffset_SISO0'] = struct.unpack('<h', bytes([packet[526], packet[527]]))[0]
    parsed_data['cSU_ALC_DL0_SISO_Level'] = struct.unpack('<h', bytes([packet[532], packet[533]]))[0]
    parsed_data['cSU_DlManualAtten_SISO1'] = packet[534]
    parsed_data['cSU_DlManualAtten_SISO2'] = packet[535]    
    parsed_data['cSU_ALC_UL0_SISO_Level'] = struct.unpack('<h', bytes([packet[536], packet[537]]))[0]
    parsed_data['cSU_DlManualAtten_SISO3'] = packet[538]
    parsed_data['cSU_DlManualAtten_SISO4'] = packet[539]    
    parsed_data['cSU_SISO_RF_DET_DL0_OUT_High'] = struct.unpack('<h', bytes([packet[540], packet[541]]))[0]
    parsed_data['cSU_SISO_RF_DET_UL0_OUT_High'] = struct.unpack('<h', bytes([packet[542], packet[543]]))[0]
    parsed_data['cSU_DlManualAtten_SISO5'] = packet[544]
    parsed_data['cSU_UlManualAtten_SISO1'] = packet[545]   
    parsed_data['cSU_UlManualAtten_SISO2'] = packet[546]   
    parsed_data['cSU_UlManualAtten_SISO3'] = convert_att_4_to_2(packet[547])   
    parsed_data['cSU_DlManualAtten_SISO'] = packet[548]
    parsed_data['cSU_DlSubAtten_SISO'] = packet[549]
    parsed_data['cSU_UlManualAtten_SISO4'] = packet[550]
    parsed_data['cSU_UlManualAtten_SISO5'] = packet[551]
    parsed_data['cSU_UlManualAtten_SISO'] = packet[552]
    parsed_data['cSU_UlSubAtten_SISO'] = packet[553]
    parsed_data['cSU_UlManualAtten_MIMO'] = packet[554]
    parsed_data['cSU_FaMode'] = packet[555]
    parsed_data['cSU_DL_OutputOffset_SISO'] = struct.unpack('<h', bytes([packet[556], packet[557]]))[0]
    parsed_data['cSU_UL_InputOffset_SISO0'] = struct.unpack('<h', bytes([packet[558], packet[559]]))[0]
    parsed_data['cSU_UL_InputOffset_SISO'] = struct.unpack('<h', bytes([packet[560], packet[561]]))[0]
    parsed_data['cSU_DlManualAtten_SISO0'] = packet[562]
    parsed_data['cSU_UlManualAtten_SISO0'] = packet[563]
    parsed_data['cSU_Dl_Siso_Att_Test'] = struct.unpack('<h', bytes([packet[564], packet[565]]))[0]
    parsed_data['cSU_Dl_Mimo_Att_Test'] = struct.unpack('<h', bytes([packet[566], packet[567]]))[0]
    parsed_data['cSU_Ul_Siso_Att_Test'] = struct.unpack('<h', bytes([packet[568], packet[569]]))[0]
    parsed_data['cSU_Ul_Mimo_Att_Test'] = struct.unpack('<h', bytes([packet[570], packet[571]]))[0]
    parsed_data['cSU_RF_Switch'] = packet[572]
    parsed_data['cSU_ApiOldNew'] = packet[573]
    parsed_data['cSU_Mvbx_BeamSet'] = packet[574]
    parsed_data['cSU_Mvbx_TddSignalMode'] = packet[575]
    parsed_data['cSU_Mvbx_Mv2853TxGainSiso'] = packet[576]
    parsed_data['cSU_Mvbx_Mv2853RxGainSiso'] = packet[577]
    parsed_data['cSU_Mvbx_Mv2850TxGainSiso'] = packet[578]
    parsed_data['cSU_Mvbx_Mv2850RxGainSiso'] = packet[579]
    parsed_data['cSU_Mvbx_Mv2853TxGainMimo'] = packet[580]
    parsed_data['cSU_Mvbx_Mv2853RxGainMimo'] = packet[581]
    parsed_data['cSU_Mvbx_Mv2850TxGainMimo'] = packet[582]
    parsed_data['cSU_Mvbx_Mv2850RxGainMimo'] = packet[583]
    parsed_data['cSU_Mvbx_TxGainSetSiso'] = packet[584]
    parsed_data['cSU_Mvbx_RxGainSetSiso'] = packet[585]
    parsed_data['cSU_Mvbx_TxGainSetMiso'] = packet[586]
    parsed_data['cSU_Mvbx_RxGainSetMiso'] = packet[587]
    parsed_data['cSU_GumStick_OnOff'] = packet[588]
    parsed_data['cSU_ApiLogLevel'] = packet[589]
    parsed_data['cSU_ApiAdcSel'] = packet[590]
    parsed_data['cSU_TemperCompensationMode'] = packet[591]
    parsed_data['cSU_ApiVenderFreq'] = struct.unpack('<I', bytes([packet[592], packet[593], packet[594], packet[595]]))[0]
    parsed_data['cSU_ApiGsOutputPowerOffsetSiso'] = struct.unpack('<h', bytes([packet[596], packet[597]]))[0]
    parsed_data['cSU_BeamAntSelect'] = packet[598]
    parsed_data['cSU_ApiGsOutputPowerOffsetMimo'] = struct.unpack('<h', bytes([packet[599], packet[600]]))[0]
    parsed_data['cSU_Gs_Gain_Siso'] = packet[601]
    parsed_data['cSU_Gs_Gain_Mimo'] = packet[602]
    parsed_data['cSU_ApiInitRetryMode'] = packet[603]
    parsed_data['cSU_Orientation'] = struct.unpack('<h', bytes([packet[604], packet[605]]))[0]
    parsed_data['cSU_Tilt'] = struct.unpack('<h', bytes([packet[606], packet[607]]))[0]
    parsed_data['cSU_GS_AttenOffset_DL_Siso'] = packet[608]
    parsed_data['cSU_GS_AttenOffset_DL_Mimo'] = packet[609]
    parsed_data['cSU_GS_AttenOffset_UL_Siso'] = packet[610]
    parsed_data['cSU_GS_AttenOffset_UL_Mimo'] = packet[611]
    parsed_data['cSU_AomTemperConperMode'] = packet[612]
    parsed_data['cSU_GS_AttenOffset_30by15_DL_Siso'] = packet[613]
    parsed_data['cSU_GS_AttenOffset_30by30_DL_Siso'] = packet[614]
    parsed_data['cSU_GS_AttenOffset_60by15_DL_Siso'] = packet[615]
    parsed_data['cSU_GS_AttenOffset_60by30_DL_Siso'] = packet[616]
    parsed_data['cSU_GS_AttenOffset_60by60_DL_Siso'] = packet[617]
    parsed_data['cSU_GS_AttenOffset_30by15_DL_Mimo'] = packet[618]
    parsed_data['cSU_GS_AttenOffset_30by30_DL_Mimo'] = packet[619]
    parsed_data['cSU_GS_AttenOffset_60by15_DL_Mimo'] = packet[620]
    parsed_data['cSU_GS_AttenOffset_60by30_DL_Mimo'] = packet[621]
    parsed_data['cSU_GS_AttenOffset_60by60_DL_Mimo'] = packet[622]
    parsed_data['cSU_GS_AttenOffset_30by15_UL_Siso'] = packet[623]
    parsed_data['cSU_GS_AttenOffset_30by30_UL_Siso'] = packet[624]
    parsed_data['cSU_GS_AttenOffset_60by15_UL_Siso'] = packet[625]
    parsed_data['cSU_GS_AttenOffset_60by30_UL_Siso'] = packet[626]
    parsed_data['cSU_GS_AttenOffset_60by60_UL_Siso'] = packet[627]
    parsed_data['cSU_GS_AttenOffset_30by15_UL_Mimo'] = packet[628]
    parsed_data['cSU_GS_AttenOffset_30by30_UL_Mimo'] = packet[629]
    parsed_data['cSU_GS_AttenOffset_60by15_UL_Mimo'] = packet[630]
    parsed_data['cSU_GS_AttenOffset_60by30_UL_Mimo'] = packet[631]
    parsed_data['cSU_GS_AttenOffset_60by60_UL_Mimo'] = packet[632]
    parsed_data['cSU_Reserved10'] = packet[633:636]
    #SDU
    parsed_data['SDU_FW_Ver'] = packet[636]
    parsed_data['SDU_FPGA_Ver'] = packet[637]
    parsed_data['SDU_Script_Ver'] = packet[638]
    parsed_data['SDU_Reserved1'] = struct.unpack('<h', bytes([packet[639], packet[640]]))[0]
    parsed_data['SDU_Reserved2'] = struct.unpack('<h', bytes([packet[641], packet[642]]))[0]
    parsed_data['SDU_FRT_Cen_Frequency'] = struct.unpack('<I', bytes([packet[643], packet[644], packet[645], packet[646]]))[0]
    parsed_data['SDU_Center_Frequency'] = struct.unpack('<h', bytes([packet[647], packet[648]]))[0]
    parsed_data['SDU_PSS'] = packet[649]
    parsed_data['SDU_SSS'] = packet[650]
    parsed_data['SDU_SCS'] = packet[651]
    parsed_data['SDU_PWR_Level'] = struct.unpack('<h', bytes([packet[652], packet[653]]))[0]
    parsed_data['SDU_reserved3'] = packet[654]
    parsed_data['SDU_Threshold_Level'] = packet[655]
    parsed_data['SDU_Center_Frequency_High'] = packet[656]
    parsed_data['SDU_Special_Sub_Frame_Config'] = packet[657]
    parsed_data['SDU_Reserved4'] = packet[658]
    parsed_data['SDU_TDD_Mode'] = packet[659]
    parsed_data['SDU_Reserved5'] = packet[660]
    parsed_data['SDU_SDM_Alarm'] = packet[661]
    parsed_data['SDU_Sync_Offset_Time'] = packet[662]
    parsed_data['SDU_DL Sync_ON_Time'] = packet[663]
    parsed_data['SDU_DL Sync_OFF_Time'] = packet[664]
    parsed_data['SDU_UL Sync_ON_Time'] = packet[665]
    parsed_data['SDU_UL Sync_OFF_Time'] = packet[666]
    parsed_data['SDU_Antenna_Type'] = packet[667]
    parsed_data['SDU_Simulation_status'] = packet[668]
    parsed_data['SDU_Power_Offset'] = packet[669]
    parsed_data['SDU_Pss_Counter'] = struct.unpack('<h', bytes([packet[670], packet[671]]))[0]
    parsed_data['SDU_Correlation'] = struct.unpack('<h', bytes([packet[672], packet[673]]))[0]
    parsed_data['SDU_Shift_Counter'] = packet[674]
    parsed_data['SDU_A'] = struct.unpack('<h', bytes([packet[675], packet[676]]))[0]
    parsed_data['SDU_B'] = struct.unpack('<h', bytes([packet[677], packet[678]]))[0]
    parsed_data['SDU_C'] = struct.unpack('<h', bytes([packet[679], packet[680]]))[0]
    parsed_data['SDU_T'] = packet[681]
    parsed_data['SDU_V'] = packet[682]
    parsed_data['SDU_S'] = packet[683]
    parsed_data['SDU_W'] = packet[684]
    parsed_data['SDU_X'] = packet[685]
    parsed_data['SDU_Y'] = packet[686]
    parsed_data['SDU_Reserved'] = struct.unpack('<I', bytes([packet[687], packet[688], packet[689], packet[690]]))[0]
    parsed_data['SDU_PCI_0'] = struct.unpack('<h', bytes([packet[691], packet[692]]))[0]
    parsed_data['SDU_PCI_1'] = struct.unpack('<h', bytes([packet[693], packet[694]]))[0]
    parsed_data['SDU_PCI_2'] = struct.unpack('<h', bytes([packet[695], packet[696]]))[0]
    parsed_data['SDU_PCI_3'] = struct.unpack('<h', bytes([packet[697], packet[698]]))[0]
    parsed_data['SDU_RSRP_0'] = struct.unpack('<h', bytes([packet[699], packet[700]]))[0]
    parsed_data['SDU_RSRP_1'] = struct.unpack('<h', bytes([packet[701], packet[702]]))[0]
    parsed_data['SDU_RSRP_2'] = struct.unpack('<h', bytes([packet[703], packet[704]]))[0]
    parsed_data['SDU_RSRP_3'] = struct.unpack('<h', bytes([packet[705], packet[706]]))[0]
    parsed_data['SDU_RSRQ_0'] = struct.unpack('<h', bytes([packet[707], packet[708]]))[0]
    parsed_data['SDU_RSRQ_1'] = struct.unpack('<h', bytes([packet[709], packet[710]]))[0]
    parsed_data['SDU_RSRQ_2'] = struct.unpack('<h', bytes([packet[711], packet[712]]))[0]
    parsed_data['SDU_RSRQ_3'] = struct.unpack('<h', bytes([packet[713], packet[714]]))[0]
    parsed_data['SDU_SINR_0'] = struct.unpack('<h', bytes([packet[715], packet[716]]))[0]
    parsed_data['SDU_SINR_1'] = struct.unpack('<h', bytes([packet[717], packet[718]]))[0]
    parsed_data['SDU_SINR_2'] = struct.unpack('<h', bytes([packet[719], packet[720]]))[0]
    parsed_data['SDU_SINR_3'] = struct.unpack('<h', bytes([packet[721], packet[722]]))[0]
    parsed_data['SDU_Period'] = struct.unpack('<h', bytes([packet[723], packet[724]]))[0]
    parsed_data['SDU_DownlinkSlots_1'] = struct.unpack('<h', bytes([packet[725], packet[726]]))[0]
    parsed_data['SDU_DownlinkSymbols_1'] = struct.unpack('<h', bytes([packet[727], packet[728]]))[0]
    parsed_data['SDU_DownlinkSlots_2'] = struct.unpack('<h', bytes([packet[729], packet[730]]))[0]
    parsed_data['SDU_DownlinkSymbols_2'] = struct.unpack('<h', bytes([packet[731], packet[732]]))[0]
    parsed_data['SDU_TSYNC_MODE1'] = packet[733]
    parsed_data['SDU_TSYNC_DELAY1'] = struct.unpack('<h', bytes([packet[734], packet[735]]))[0]
    parsed_data['SDU_TTG_CTRL1'] = struct.unpack('<h', bytes([packet[736], packet[737]]))[0]
    parsed_data['SDU_RTG_CTRL1'] = struct.unpack('<h', bytes([packet[738], packet[739]]))[0]
    parsed_data['SDU_TSYNC_MODE2'] = packet[740]
    parsed_data['SDU_TSYNC_DELAY2'] = struct.unpack('<h', bytes([packet[741], packet[742]]))[0]
    parsed_data['SDU_TTG_CTRL2'] = struct.unpack('<h', bytes([packet[743], packet[744]]))[0]
    parsed_data['SDU_RTG_CTRL2'] = struct.unpack('<h', bytes([packet[745], packet[746]]))[0]
    parsed_data['SDU_TSYNC_MODE3'] = packet[747]
    parsed_data['SDU_TSYNC_DELAY3'] = struct.unpack('<h', bytes([packet[748], packet[749]]))[0]
    parsed_data['SDU_TTG_CTRL3'] = struct.unpack('<h', bytes([packet[750], packet[751]]))[0]
    parsed_data['SDU_RTG_CTRL3'] = struct.unpack('<h', bytes([packet[752], packet[753]]))[0]
    parsed_data['SDU_TSYNC_MODE4'] = packet[754]
    parsed_data['SDU_TSYNC_DELAY4'] = struct.unpack('<h', bytes([packet[755], packet[756]]))[0]
    parsed_data['SDU_TTG_CTRL4'] = struct.unpack('<h', bytes([packet[757], packet[758]]))[0]
    parsed_data['SDU_RTG_CTRL4'] = struct.unpack('<h', bytes([packet[759], packet[760]]))[0]
    parsed_data['SDU_Candidate_SSB_FREQ1'] = struct.unpack('<I', bytes([packet[761], packet[762], packet[763], packet[764]]))[0]
    parsed_data['SDU_Candidate_SSB_FREQ2'] = struct.unpack('<I', bytes([packet[765], packet[766], packet[767], packet[768]]))[0]
    parsed_data['SDU_Candidate_SSB_FREQ3'] = struct.unpack('<I', bytes([packet[769], packet[770], packet[771], packet[772]]))[0]
    parsed_data['SDU_Candidate_SSB_FREQ4'] = struct.unpack('<I', bytes([packet[773], packet[774], packet[775], packet[776]]))[0]
    parsed_data['SDU_Candidate_SSB_FREQ5'] = struct.unpack('<I', bytes([packet[777], packet[778], packet[779], packet[780]]))[0]
    parsed_data['SDU_RSV9'] = packet[781:784]
    parsed_data['cSDU_CtrFlag'] = packet[784:789]
    parsed_data['cSDU_FRT_Cen_Frequency'] = struct.unpack('<I', bytes([packet[789], packet[790], packet[791], packet[792]]))[0]
    parsed_data['cSDU_Center_Frequency'] = struct.unpack('<h', bytes([packet[793], packet[794]]))[0]
    parsed_data['cSDU_Threshold_Level'] = packet[795]
    parsed_data['cSDU_TDD_Mode'] = packet[796]
    parsed_data['cSDU_Sync_Offset_Time'] = packet[797]
    parsed_data['cSDU_DL_Sync_ON_Time'] = packet[798]
    parsed_data['cSDU_DL_Sync_OFF_Time'] = packet[799]
    parsed_data['cSDU_UL_Sync_ON_Time'] = packet[800]
    parsed_data['cSDU_UL_Sync_OFF_Time'] = packet[801]
    parsed_data['cSDU_Cyclic_Prefix'] = packet[802]
    parsed_data['cSDU_Center_Frequency_High'] = packet[803]
    parsed_data['cSDU_Special_Sub_Frame_Config'] = packet[804]
    parsed_data['cSDU_Power_Offset'] = packet[805]
    parsed_data['cSDU_CPrefix_reserved'] = packet[806]  # Adjusted index for reserved
    parsed_data['cSDU_Period'] = struct.unpack('<h', bytes([packet[807], packet[808]]))[0]
    parsed_data['cSDU_DownlinkSlots_1'] = struct.unpack('<h', bytes([packet[809], packet[810]]))[0]
    parsed_data['cSDU_DownlinkSymbols_1'] = struct.unpack('<h', bytes([packet[811], packet[812]]))[0]
    parsed_data['cSDU_DownlinkSlots_2'] = struct.unpack('<h', bytes([packet[813], packet[814]]))[0]
    parsed_data['cSDU_DownlinkSymbols_2'] = struct.unpack('<h', bytes([packet[815], packet[816]]))[0]
    parsed_data['cSDU_TSYNC_MODE1'] = packet[817]
    parsed_data['cSDU_TSYNC_DELAY1'] = struct.unpack('<h', bytes([packet[818], packet[819]]))[0]
    parsed_data['cSDU_TTG_CTRL1'] = struct.unpack('<h', bytes([packet[820], packet[821]]))[0]
    parsed_data['cSDU_RTG_CTRL1'] = struct.unpack('<h', bytes([packet[822], packet[823]]))[0]
    parsed_data['cSDU_TSYNC_MODE2'] = packet[824]
    parsed_data['cSDU_TSYNC_DELAY2'] = struct.unpack('<h', bytes([packet[825], packet[826]]))[0]
    parsed_data['cSDU_TTG_CTRL2'] = struct.unpack('<h', bytes([packet[827], packet[828]]))[0]
    parsed_data['cSDU_RTG_CTRL2'] = struct.unpack('<h', bytes([packet[829], packet[830]]))[0]
    parsed_data['cSDU_TSYNC_MODE3'] = packet[831]
    parsed_data['cSDU_TSYNC_DELAY3'] = struct.unpack('<h', bytes([packet[832], packet[833]]))[0]
    parsed_data['cSDU_TTG_CTRL3'] = struct.unpack('<h', bytes([packet[834], packet[835]]))[0]
    parsed_data['cSDU_RTG_CTRL3'] = struct.unpack('<h', bytes([packet[836], packet[837]]))[0]
    parsed_data['cSDU_TSYNC_MODE4'] = packet[838]
    parsed_data['cSDU_TSYNC_DELAY4'] = struct.unpack('<h', bytes([packet[839], packet[840]]))[0]
    parsed_data['cSDU_TTG_CTRL4'] = struct.unpack('<h', bytes([packet[841], packet[842]]))[0]
    parsed_data['cSDU_RTG_CTRL4'] = struct.unpack('<h', bytes([packet[843], packet[844]]))[0]
    parsed_data['cSDU_Candidate_SSB_FREQ1'] = struct.unpack('<I', bytes([packet[845], packet[846], packet[847], packet[848]]))[0]
    parsed_data['cSDU_Candidate_SSB_FREQ2'] = struct.unpack('<I', bytes([packet[849], packet[850], packet[851], packet[852]]))[0]
    parsed_data['cSDU_Candidate_SSB_FREQ3'] = struct.unpack('<I', bytes([packet[853], packet[854], packet[855], packet[856]]))[0]
    parsed_data['cSDU_Candidate_SSB_FREQ4'] = struct.unpack('<I', bytes([packet[857], packet[858], packet[859], packet[860]]))[0]
    parsed_data['cSDU_Candidate_SSB_FREQ5'] = struct.unpack('<I', bytes([packet[861], packet[862], packet[863], packet[864]]))[0]
    parsed_data['cSDU_Rsv4'] = packet[865:868]

    parsed_data['ICS_SW_Version'] = packet[868:870]
    parsed_data['ICS_FPGA_Version'] = packet[870:872]
    parsed_data['ICS_DL_IDU'] = struct.unpack('<h', bytes([packet[872], packet[873]]))[0]
    parsed_data['ICS_UL_IDU'] = struct.unpack('<h', bytes([packet[874], packet[875]]))[0]
    parsed_data['ICS_DL_Digital_Input_Power'] = struct.unpack('<h', bytes([packet[876], packet[877]]))[0]
    parsed_data['ICS_UL_Digital_Input_Power'] = struct.unpack('<h', bytes([packet[878], packet[879]]))[0]
    parsed_data['ICS_DL_RF_Input_Power'] = struct.unpack('<h', bytes([packet[880], packet[881]]))[0]
    parsed_data['ICS_UL_RF_Input_Power'] = struct.unpack('<h', bytes([packet[882], packet[883]]))[0]
    parsed_data['ICS_DL_RF_Input_ATT'] = packet[884]
    parsed_data['ICS_UL_RF_Input_ATT'] = packet[885]
    parsed_data['ICS_DL_Set_Gain'] = packet[886]
    parsed_data['ICS_UL_Set_Gain'] = packet[887]
    parsed_data['ICS_DL_Current_Gain'] = packet[888]
    parsed_data['ICS_UL_Current_Gain'] = packet[889]
    parsed_data['ICS_DL_Digital_Output_Power'] = struct.unpack('<h', bytes([packet[890], packet[891]]))[0]
    parsed_data['ICS_UL_Digital_Output_Power'] = struct.unpack('<h', bytes([packet[892], packet[893]]))[0]
    parsed_data['ICS_DL_IDU_Offset'] = packet[894]
    parsed_data['ICS_UL_IDU_Offset'] = packet[895]
    parsed_data['ICS_UL_RF_Output_Power'] = struct.unpack('<h', bytes([packet[896], packet[897]]))[0]
    parsed_data['ICS_DL_RF_Output_ATT'] = packet[898]
    parsed_data['ICS_UL_RF_Output_ATT'] = packet[899]
    parsed_data['ICS_DL_Isolation'] = packet[900]
    parsed_data['ICS_UL_Isolation'] = packet[901]
    parsed_data['ICS_DL_AMP_Enable'] = packet[902]
    parsed_data['ICS_UL_AMP_Enable'] = packet[903]
    parsed_data['ICS_DL_Input_ALC_Enable'] = packet[904]
    parsed_data['ICS_UL_Input_ALC_Enable'] = packet[905]
    parsed_data['ICS_DL_Input_ALC_Level'] = packet[906]
    parsed_data['ICS_UL_Input_ALC_Level'] = packet[907]
    parsed_data['ICS_DL_Input_ALC_Low_Level'] = packet[908]
    parsed_data['ICS_UL_Input_ALC_Low_Level'] = packet[909]
    parsed_data['ICS_DL_Output_ALC_Enable'] = packet[910]
    parsed_data['ICS_UL_Output_ALC_Enable'] = packet[911]
    parsed_data['ICS_DL_Output_ALC_Level'] = packet[912]
    parsed_data['ICS_UL_Output_ALC_Level'] = packet[913]
    parsed_data['ICS_Gain_Balance_Enable'] = packet[914]
    parsed_data['ICS_Gain_Balance_Level'] = packet[915]
    parsed_data['ICS_ILC_Enable'] = packet[916]
    parsed_data['ICS_ILC_Level'] = packet[917]
    parsed_data['ICS_ICS_Enable'] = packet[918]
    parsed_data['ICS_Window_Shift'] = packet[919]
    parsed_data['ICS_System_Delay'] = packet[920]
    parsed_data['ICS_DL_Shutdown_Enable'] = packet[921]
    parsed_data['ICS_UL_Shutdown_Enable'] = packet[922]
    parsed_data['ICS_DL_Shutdown_Level'] = packet[923]
    parsed_data['ICS_UL_Shutdown_Level'] = packet[924]
    parsed_data['ICS_DSP_Temperature'] = packet[925]
    parsed_data['ICS_Temp_Alarm_Threshold'] = packet[926]
    parsed_data['ICS_DL_ISOL_Alarm_Threshold'] = packet[927]
    parsed_data['ICS_UL_ISOL_Alarm_Threshold'] = packet[928]
    parsed_data['ICS_Alarm_1'] = packet[929]
    parsed_data['ICS_Alarm_2'] = packet[930]
    parsed_data['ICS_DL_TSync_status'] = packet[931]
    parsed_data['ICS_UL_TSync_status'] = packet[932]
    parsed_data['ICS_TDD_Mode'] = packet[933]
    parsed_data['ICS_TSync_Timing_Offset'] = packet[934]
    parsed_data['ICS_DL_Offset'] = packet[935]
    parsed_data['ICS_UL_Offset'] = packet[936]
    parsed_data['ICS_NR_Band_Configration'] = packet[937]
    parsed_data['ICS_DL_DSP_GAIN_OFFSET'] = packet[938]
    parsed_data['ICS_UL_DSP_GAIN_OFFSET'] = packet[939]
    parsed_data['ICS_RFMODE'] = packet[940]
    parsed_data['ICS_DL_OutPwr_Offset'] = packet[941]
    parsed_data['ICS_UL_OutPwr_Offset'] = packet[942]
    parsed_data['ICS_TempCompMode'] = packet[943]
    parsed_data['ICS_AttACCEnable'] = packet[944]
    parsed_data['ICS_DL_DSP_InputTh_Offset'] = packet[945]
    parsed_data['ICS_UL_DSP_InputTh_Offset'] = packet[946]
    parsed_data['ICS_Resved10'] = packet[947]
    parsed_data['cICS_DL_Gain'] = packet[948]
    parsed_data['cICS_DL_AMP_Enable'] = packet[949]
    parsed_data['cICS_DL_Input_ALC_Enable'] = packet[950]
    parsed_data['cICS_DL_Input_ALC_Level'] = packet[951]
    parsed_data['cICS_DL_Input_ALC_Low_Level'] = packet[952]
    parsed_data['cICS_DL_Shutdown_Level'] = packet[953]
    parsed_data['cICS_DL_Window_Shift'] = packet[954]
    parsed_data['cICS_DL_RF_Input_ATT'] = packet[955]
    parsed_data['cICS_DL_RF_Output_ATT'] = packet[956]
    parsed_data['cICS_DL_Output_ALC_Enable'] = packet[957]
    parsed_data['cICS_DL_Output_ALC_Level'] = packet[958]
    parsed_data['cICS_DL_ISOL_Alarm_Threshold'] = packet[959]
    parsed_data['cICS_UL_Gain'] = packet[960]
    parsed_data['cICS_UL_AMP_Enable'] = packet[961]
    parsed_data['cICS_UL_Input_ALC_Enable'] = packet[962]
    parsed_data['cICS_UL_Input_ALC_Level'] = packet[963]
    parsed_data['cICS_UL_Input_ALC_Low_Level'] = packet[964]
    parsed_data['cICS_UL_Shutdown_Level'] = packet[965]
    parsed_data['cICS_UL_Window_Shift'] = packet[966]
    parsed_data['cICS_UL_RF_Input_ATT'] = packet[967]
    parsed_data['cICS_UL_RF_Output_ATT'] = packet[968]
    parsed_data['cICS_UL_Output_ALC_Enable'] = packet[969]
    parsed_data['cICS_UL_Output_ALC_Level'] = packet[970]
    parsed_data['cICS_UL_ISOL_Alarm_Threshold'] = packet[971]
    parsed_data['cICS_Gain_Balance_Enable'] = packet[972]
    parsed_data['cICS_ILC_Enable'] = packet[973]
    parsed_data['cICS_ILC_Level'] = packet[974]
    parsed_data['cICS_ICS_Enable'] = packet[975]
    parsed_data['cICS_DL_Shutdown_Enable'] = packet[976]
    parsed_data['cICS_Temp_Alarm_Threshold'] = packet[977]
    parsed_data['cICS_TDD_Mode'] = packet[978]
    parsed_data['cICS_TSync_Timing_Offset'] = packet[979]
    parsed_data['cICS_TSync_Offset_DL'] = packet[980]
    parsed_data['cICS_TSync_Offset_UL'] = packet[981]
    parsed_data['cICS_NR_Band_Configration'] = packet[982]
    parsed_data['cICS_UL_Shutdown_Enable'] = packet[983]
    parsed_data['cDU_DL_OutputOffset_SISO0'] = struct.unpack('<h', bytes([packet[984], packet[985]]))[0]
    parsed_data['cDU_DL_OutputOffset_SISO1'] = struct.unpack('<h', bytes([packet[986], packet[987]]))[0]
    parsed_data['cDU_DL_OutputOffset_SISO2'] = struct.unpack('<h', bytes([packet[988], packet[989]]))[0]
    parsed_data['cDU_DL_OutputOffset_SISO3'] = struct.unpack('<h', bytes([packet[990], packet[991]]))[0]
    parsed_data['cDU_DL_OutputOffset_SISO4'] = struct.unpack('<h', bytes([packet[992], packet[993]]))[0]
    parsed_data['cDU_DL_OutputOffset_SISO5'] = struct.unpack('<h', bytes([packet[994], packet[995]]))[0]
    parsed_data['cDU_UL_InputOffset_SISO0'] = struct.unpack('<h', bytes([packet[996], packet[997]]))[0]
    parsed_data['cDU_UL_InputOffset_SISO1'] = struct.unpack('<h', bytes([packet[998], packet[999]]))[0]
    parsed_data['cDU_UL_InputOffset_SISO2'] = struct.unpack('<h', bytes([packet[1000], packet[1001]]))[0]
    parsed_data['cDU_UL_InputOffset_SISO3'] = struct.unpack('<h', bytes([packet[1002], packet[1003]]))[0]
    parsed_data['cDU_UL_InputOffset_SISO4'] = struct.unpack('<h', bytes([packet[1004], packet[1005]]))[0]
    parsed_data['cDU_UL_InputOffset_SISO5'] = struct.unpack('<h', bytes([packet[1006], packet[1007]]))[0]

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
