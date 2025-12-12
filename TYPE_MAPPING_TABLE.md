# 타입 및 엔디안 매핑 테이블

## 📋 기본 타입 정의

### Python struct 형식 (파싱 시 사용)
| struct 형식 | 설명 | 크기 | 엔디안 | 범위 |
|------------|------|------|--------|------|
| 직접 접근 `packet[i]` | unsigned 8-bit | 1바이트 | - | 0 ~ 255 |
| `<b` | signed 8-bit | 1바이트 | - | -128 ~ 127 |
| `<h` | signed 16-bit | 2바이트 | **Little-Endian** | -32768 ~ 32767 |
| `<H` | unsigned 16-bit | 2바이트 | **Little-Endian** | 0 ~ 65535 |
| `<I` | unsigned 32-bit | 4바이트 | **Little-Endian** | 0 ~ 4294967295 |
| `<f` | float 32-bit | 4바이트 | **Little-Endian** | IEEE 754 |
| `packet[i:j]` | 바이트 배열 | N바이트 | - | - |

### JavaScript/HTML 타입 (전송 시 사용)
| HTML 타입 | 설명 | Python 변환 | struct 형식 |
|-----------|------|-------------|-------------|
| `u8` | unsigned 8-bit | `int(value)` | 직접 접근 또는 `<B` |
| `i8` | signed 8-bit | `int(value)` | `<b` |
| `u16le` | unsigned 16-bit | `int(value)` | `<H` (little-endian) |
| `u32` | unsigned 32-bit | `int(value)` | `<I` (little-endian) |
| `string` | 문자열 | `str(value).encode()` | 바이트 배열 + null-padding |

---

## 🔄 변환 규칙

### 1. u8 (unsigned 8-bit)
```python
# 파싱: packet[i]
# 전송: struct.pack('<B', value) 또는 bytes([value])
# 예: value = 100 → b'\x64'
```

### 2. i8 (signed 8-bit)
```python
# 파싱: struct.unpack('<b', bytes([packet[i]]))[0]
# 전송: struct.pack('<b', value)
# 예: value = -10 → b'\xf6'
```

### 3. u16le (unsigned 16-bit little-endian)
```python
# 파싱: struct.unpack('<H', bytes([packet[i], packet[i+1]]))[0]
# 전송: struct.pack('<H', value)
# 예: value = 1000 → b'\xe8\x03' (0x03E8 → little-endian: [0xE8, 0x03])
```

### 4. i16le (signed 16-bit little-endian)
```python
# 파싱: struct.unpack('<h', bytes([packet[i], packet[i+1]]))[0]
# 전송: struct.pack('<h', value)
# 예: value = -1000 → b'\x18\xfc' (0xFC18 → little-endian: [0x18, 0xFC])
```

### 5. u32le (unsigned 32-bit little-endian)
```python
# 파싱: struct.unpack('<I', bytes([packet[i], packet[i+1], packet[i+2], packet[i+3]]))[0]
# 전송: struct.pack('<I', value)
# 예: value = 1000000 → b'\x40\x42\x0f\x00' (0x000F4240 → little-endian)
```

### 6. f32le (float 32-bit little-endian)
```python
# 파싱: struct.unpack('<f', bytes(packet[i:i+4]))[0]
# 전송: struct.pack('<f', value)
# 예: value = 3.14 → b'\xc3\xf5H@'
```

### 7. string (문자열)
```python
# 파싱: bytes_to_string_until_null(packet[i:j])
# 전송: value.encode('utf-8') + b'\x00' * (max_len - len(value.encode()))
# 예: value = "ABC", max_len=16 → b'ABC\x00\x00...' (16바이트)
```

---

## 📊 실제 필드별 타입 매핑

### DU 필드 (FIELD_MAP 기준)

| HTML 필드 ID | 필드 키 | HTML 타입 | 파싱 타입 | 바이트 위치 | 변환 함수 |
|-------------|---------|-----------|----------|------------|-----------|
| `tempupper` | `SysTemperHighLvl` | `i8` | `struct.unpack('<b', ...)` | `packet[1020]` | - |
| `templower` | `SysTemperLowLvl` | `i8` | `struct.unpack('<b', ...)` | `packet[1021]` | - |
| `gumstick_onoff` | `GumStick_OnOff` | `u8` | `packet[995]` | 직접 접근 | - |
| `mvbx_rsagc_mode` | `Mvbx_RsAgcMode` | `u8` | `packet[942]` | 직접 접근 | - |
| `mvbx_rsagc_threshold` | `Mvbx_RsAgcThreshold` | `i8` | `packet[941]` | 직접 접근 | - |
| `gNB_Vendor` | `gNB_Vendor` | `u8` | `packet[?]` | 직접 접근 | - |
| `dl_att_siso` | `DU_DlManualAtten_SISO` | `u8` | `packet[812]` | 직접 접근 | `convert_att_4_to_2` (역변환: ×2) |
| `dl_alc_level_siso` | `ALC_DL0_SISO_Level` | `u16le` | `struct.unpack('<h', ...)` | `packet[764:766]` | `convert_to_1dbm` |
| `alc_dl0_siso_mode` | `ALC_DL0_SISO_Mode` | `u8` | `packet[?]` | 직접 접근 | - |
| `mvbx_tx_gain_set_siso` | `Mvbx_TxGainSetSiso` | `u8` | `packet[952]` | 직접 접근 | - |
| `ul_att_siso` | `DU_UlManualAtten_SISO` | `u8` | `packet[818]` | 직접 접근 | `convert_iso_att` (역변환: ×2) |
| `ul_iso_level_siso` | `ALC_UL0_SISO_Level` | `u16le` | `struct.unpack('<h', ...)` | `packet[?]` | - |
| `mvbx_rx_gain_set_siso` | `Mvbx_RxGainSetSiso` | `u8` | `packet[953]` | 직접 접근 | - |
| `dl_att_mimo` | `DU_DlManualAtten_MIMO` | `u8` | `packet[813]` | 직접 접근 | `convert_att_4_to_2` (역변환: ×2) |
| `dl_alc_level_mimo` | `ALC_DL1_MIMO_Level` | `u16le` | `struct.unpack('<h', ...)` | `packet[?]` | - |
| `alc_dl1_mimo_mode` | `ALC_DL1_MIMO_Mode` | `u8` | `packet[?]` | 직접 접근 | - |
| `mvbx_tx_gain_set_miso` | `Mvbx_TxGainSetMiso` | `u8` | `packet[954]` | 직접 접근 | - |
| `ul_att_mimo` | `DU_UlManualAtten_MIMO` | `u8` | `packet[819]` | 직접 접근 | `convert_iso_att` (역변환: ×2) |
| `ul_iso_level_mimo` | `ALC_UL1_MIMO_Level` | `u16le` | `struct.unpack('<h', ...)` | `packet[?]` | - |
| `mvbx_rx_gain_set_miso` | `Mvbx_RxGainSetMiso` | `u8` | `packet[955]` | 직접 접근 | - |
| `ld1_det_dl0_siso_low` | `LD1_DET_DL0_SISO_Low` | `u16le` | `struct.unpack('<h', ...)` | `packet[780:782]` | `convert_to_01dbm` (역변환: ×10) |
| `pd1_det_ul0_siso_low` | `PD1_DET_UL0_SISO_Low` | `u16le` | `struct.unpack('<h', ...)` | `packet[?]` | `convert_to_01dbm` (역변환: ×10) |
| `ld2_det_dl1_mimo_low` | `LD2_DET_DL1_MIMO_Low` | `u16le` | `struct.unpack('<h', ...)` | `packet[?]` | `convert_to_01dbm` (역변환: ×10) |
| `pd2_det_ul1_mimo_low` | `PD2_DET_UL1_MIMO_Low` | `u16le` | `struct.unpack('<h', ...)` | `packet[?]` | `convert_to_01dbm` (역변환: ×10) |

### SU 필드 (SU1_FIELD_MAP 기준)

| HTML 필드 ID | 필드 키 | HTML 타입 | 파싱 타입 | 바이트 위치 | 변환 함수 |
|-------------|---------|-----------|----------|------------|-----------|
| `su1_suid` | `SuId` | `u8` | `packet[?]` | 직접 접근 | - |
| `su1_tempupper` | `SysTemperHighLvl` | `i8` | `struct.unpack('<b', ...)` | `packet[?]` | - |
| `su1_templower` | `SysTemperLowLvl` | `i8` | `struct.unpack('<b', ...)` | `packet[?]` | - |
| `su1_cascade_mode` | `SuEndMode` | `u8` | `packet[?]` | 직접 접근 | - |
| `su1_gumstick_onoff` | `GumStick_OnOff` | `u8` | `packet[?]` | 직접 접근 | - |
| `su1_dl_att_siso` | `DlManualAtten_SISO` | `u8` | `packet[?]` | 직접 접근 | `convert_att_4_to_2` (역변환: ×2) |
| `su1_dl_alc_level_siso` | `ALC_DL0_SISO_Level` | `u16le` | `struct.unpack('<h', ...)` | `packet[?]` | - |
| `su1_dl_alc_onoff_siso` | `ALC_DL0_SISO_Mode` | `u8` | `packet[?]` | 직접 접근 | - |
| `su1_mvbx_tx_gain_set_siso` | `Mvbx_TxGainSetSiso` | `u8` | `packet[?]` | 직접 접근 | - |
| `su1_ul_att_siso` | `UlManualAtten_SISO` | `u8` | `packet[?]` | 직접 접근 | `convert_iso_att` (역변환: ×2) |
| `su1_ul_alc_level_siso` | `ALC_UL0_SISO_Level` | `u16le` | `struct.unpack('<h', ...)` | `packet[?]` | - |
| `su1_ul_alc_onoff_siso` | `ALC_UL0_SISO_Mode` | `u8` | `packet[?]` | 직접 접근 | - |
| `su1_mvbx_rx_gain_set_siso` | `Mvbx_RxGainSetSiso` | `u8` | `packet[?]` | 직접 접근 | - |
| `su1_ld1_det_dl0_siso_low` | `LD1_DET_DL0_SISO_Low` | `u16le` | `struct.unpack('<h', ...)` | `packet[?]` | `convert_to_01dbm` (역변환: ×10) |

### Sync Module 필드 (SYNC_FIELD_MAP 기준)

| HTML 필드 ID | 필드 키 | HTML 타입 | 파싱 타입 | 바이트 위치 | 변환 함수 |
|-------------|---------|-----------|----------|------------|-----------|
| `tsync_out_sel_1` | `TSYNC_OUT_SEL1` | `u8` | `packet[?]` | 직접 접근 | - |
| `tsync_out_sel_2` | `TSYNC_OUT_SEL2` | `u8` | `packet[?]` | 직접 접근 | - |
| `tsync_out_sel_3` | `TSYNC_OUT_SEL3` | `u8` | `packet[?]` | 직접 접근 | - |
| `TDD_Freq2` | `TDD_Freq` | `u32` | `struct.unpack('<I', ...)` | `packet[?]` | - |
| `TDD_Arfcn2` | `TDD_Arfcn` | `u16` | `struct.unpack('<H', ...)` | `packet[?]` | - |
| `F_Mode` | `F_Mode` | `u8` | `packet[?]` | 직접 접근 | - |
| `ssb_mu` | `MVBX_SSB_MU` | `u8` | `packet[?]` | 직접 접근 | - |
| `tdd_rate` | `MVBX_TDD_RATE` | `u8` | `packet[?]` | 직접 접근 | - |

---

## 🔧 변환 함수 역변환 규칙

### 1. convert_to_01dbm (0.1dBm 단위)
```python
# 파싱: raw_value / 10.0
# 전송: int(value * 10)
# 예: -51.7 dBm → -517 (raw)
```

### 2. convert_to_1dbm (1dBm 단위)
```python
# 파싱: raw_value (그대로)
# 전송: int(value)
# 예: 100 dBm → 100 (raw)
```

### 3. convert_att_4_to_2 (ATT 변환, 4→2dB, Step: 0.5dB)
```python
# 파싱: raw_value * 0.5
# 전송: int(value / 0.5) = int(value * 2)
# 예: 10.0 dB → 20 (raw)
```

### 4. convert_iso_att (ISO ATT 변환, 4→2dB, Step: 0.5dB)
```python
# 파싱: raw_value * 0.5
# 전송: int(value / 0.5) = int(value * 2)
# 예: 10.0 dB → 20 (raw)
```

### 5. convert_att_test (ATT Test 변환, 50: 5dB, 0.5dB 단위)
```python
# 파싱: raw_value * 0.5
# 전송: int(value / 0.5) = int(value * 2)
# 예: 15.0 dB → 30 (raw)
```

---

## 📝 JSON → 바이너리 변환 예시

### 예시 1: u8 필드
```python
# JSON: {"DU_DlManualAtten_SISO": 100}
# 변환: struct.pack('<B', 100) → b'\x64'
```

### 예시 2: i8 필드
```python
# JSON: {"SysTemperHighLvl": -10}
# 변환: struct.pack('<b', -10) → b'\xf6'
```

### 예시 3: u16le 필드
```python
# JSON: {"ALC_DL0_SISO_Level": 1000}
# 변환: struct.pack('<H', 1000) → b'\xe8\x03'
# (1000 = 0x03E8 → little-endian: [0xE8, 0x03])
```

### 예시 4: u32le 필드
```python
# JSON: {"TDD_Freq": 1000000}
# 변환: struct.pack('<I', 1000000) → b'\x40\x42\x0f\x00'
# (1000000 = 0x000F4240 → little-endian)
```

### 예시 5: 변환 함수 적용 (convert_to_01dbm 역변환)
```python
# JSON: {"LD1_DET_DL0_SISO_Low": -51.7}
# 역변환: int(-51.7 * 10) = -517
# 변환: struct.pack('<h', -517) → b'\xfb\xfd'
# (-517 = 0xFDFB → little-endian: [0xFB, 0xFD])
```

### 예시 6: 변환 함수 적용 (convert_att_4_to_2 역변환)
```python
# JSON: {"DU_DlManualAtten_SISO": 10.0}
# 역변환: int(10.0 / 0.5) = int(10.0 * 2) = 20
# 변환: struct.pack('<B', 20) → b'\x14'
```

### 예시 7: 문자열 필드
```python
# JSON: {"ConSerialNum": "ABC123"}
# 변환: "ABC123".encode('utf-8') + b'\x00' * (16 - 6)
# → b'ABC123\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' (16바이트)
```

---

## ⚠️ 중요 사항

1. **모든 다바이트 값은 Little-Endian**
   - `<h`, `<H`, `<I`, `<f` 모두 little-endian
   - Big-endian은 사용하지 않음

2. **변환 함수 역변환 필수**
   - 파싱 시 변환 함수를 사용했다면, 전송 시 역변환 필요
   - 예: `convert_to_01dbm` → 역변환: `× 10`

3. **타입 일치 확인**
   - HTML의 `u16le` → Python의 `struct.pack('<H', ...)`
   - HTML의 `i8` → Python의 `struct.pack('<b', ...)`

4. **문자열 null-padding**
   - 고정 길이 문자열은 null(`\x00`)로 패딩
   - 예: 16바이트 문자열 → 실제 값 + null 패딩

5. **바이트 배열 필드**
   - `ConMuFlag`: 24바이트 배열 (DU/SU), 4바이트 배열 (Sync)
   - 각 바이트는 0~255 정수

---

## 🎯 변환 함수 템플릿

```python
def json_to_binary_packet(json_data, field_mapping):
    """
    JSON 데이터를 바이너리 패킷으로 변환
    
    Args:
        json_data: JSON 딕셔너리 (예: {"SysTemperHighLvl": 50, ...})
        field_mapping: 필드별 타입 및 위치 정보
    
    Returns:
        bytes: 바이너리 패킷
    """
    packet = bytearray(MAX_PACKET_SIZE)  # 최대 패킷 크기
    
    for field_key, value in json_data.items():
        if field_key == 'ConMuFlag':
            # ConMuFlag는 바이트 배열
            for i, byte_val in enumerate(value):
                packet[580 + i] = byte_val
            continue
        
        # 필드 매핑에서 타입 정보 가져오기
        field_info = field_mapping.get(field_key)
        if not field_info:
            continue
        
        field_type = field_info['type']
        byte_offset = field_info['offset']
        conversion_func = field_info.get('conversion', None)
        
        # 역변환 함수 적용
        if conversion_func:
            if conversion_func == 'convert_to_01dbm':
                value = int(value * 10)
            elif conversion_func == 'convert_att_4_to_2':
                value = int(value * 2)
            elif conversion_func == 'convert_iso_att':
                value = int(value * 2)
            elif conversion_func == 'convert_att_test':
                value = int(value * 2)
        
        # 타입별 바이너리 변환
        if field_type == 'u8':
            packet[byte_offset] = value & 0xFF
        elif field_type == 'i8':
            packet[byte_offset:byte_offset+1] = struct.pack('<b', value)
        elif field_type == 'u16le':
            packet[byte_offset:byte_offset+2] = struct.pack('<H', value)
        elif field_type == 'i16le':
            packet[byte_offset:byte_offset+2] = struct.pack('<h', value)
        elif field_type == 'u32le' or field_type == 'u32':
            packet[byte_offset:byte_offset+4] = struct.pack('<I', value)
        elif field_type == 'f32le' or field_type == 'float':
            packet[byte_offset:byte_offset+4] = struct.pack('<f', value)
        elif field_type == 'string':
            max_len = field_info.get('max_len', 16)
            encoded = value.encode('utf-8')[:max_len]
            packet[byte_offset:byte_offset+len(encoded)] = encoded
            # 나머지는 이미 0으로 초기화됨
    
    return bytes(packet)
```

