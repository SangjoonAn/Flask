import struct
import socket, os, json

PACKET_MAIN_EMS_ID           = 0x20
PACKET_MAIN_DU_ID            = 0x30
PACKET_MAIN_SU_ID            = 0x40
PACKET_MAIN_WEB_ID            = 0x50

PACKET_SUB_MCU_ID            = 0x00
PACKET_SUB_SU11_ID           = 0x11
PACKET_SUB_SU12_ID           = 0x12
PACKET_SUB_SU13_ID           = 0x13
PACKET_SUB_SU14_ID           = 0x14

REQ_STATUS_PACKET = {
    'Rcv_Main_Sys': b'\x00',
    'Rcv_Sub_Sys': b'\x00',
    'Rcv_Object': b'\x20',
    'Trans_Main_Sys': b'\x30',  # EMS로 변경할것.0x20 
    'Trans_Sub_Sys': b'\x00',
    'Trans_Object': b'\x10',
    'cmd': b'\x54',
    'equip_type': b'\x00',
    'reserved': b'\x00\x00',
    'subdataSize': b'\x00\x00',
}

REQ_TDD_STATUS_PACKET = {
    'Rcv_Main_Sys': b'\x30',
    'Rcv_Sub_Sys': b'\x00',
    'Rcv_Object': b'\x20',
    'Trans_Main_Sys': b'\x30',  # EMS로 변경할것.0x20 
    'Trans_Sub_Sys': b'\x00',
    'Trans_Object': b'\x10',
    'cmd': b'\x90',
    'equip_type': b'\x00',
    'reserved': b'\x00\x00',
    'subdataSize': b'\x00\x04',
}


ReqControl_PacketSize = {
    'Rcv_Main_Sys': 1,
    'Rcv_Sub_Sys': 1,
    'Rcv_Object': 1,
    'Trans_Main_Sys': 1,
    'Trans_Sub_Sys': 1,
    'Trans_Object': 1,
    'CMD': 1,
    'EQUIP_TYPE': 1,
    'RESERVED': 2,
    'SubData_Size': 2,
    'InitCheckNum': 4,
    'ConMuFlag': 24,
    'ConSysTime': 7,
    'RptMakerCode': 1,
    'SysTemperHighLvl': 1,
    'SysTemperLowLvl': 1,
    'SubInitCheckNum': 1,
    'DebugMode': 1,
    'SuEnableInfo': 12,
    'MaskMuAlarm': 12,
    'MaskSuLinkFail': 12,
    'MaskSuSumAlarm': 12,
    'MaskSuRptAlarm': 12,
    'ConEmsModemReset': 1,
    'DownloadPath_GuiOrEms': 1,
    'PollingTime': 2,
    'ApiInitMode': 1,
    'AttTestMode': 1,
    'SuId': 1,
    'DL_UL_TEST': 1,
    'LocalInfo': 60,
    'SuOpticalEnStatus': 1,
    'PreStaAlarm': 12,
    'Mu_Su_Buadrate': 1,
    'ModemOnOff': 1,
    'RsrpOffset': 1,
    # RF 제어
    'ALC_DL0_SISO_Mode': 1,
    'ALC_DL1_MIMO_Mode': 1,
    'ALC_UL0_SISO_Mode': 1,
    'ALC_UL1_MIMO_Mode': 1,
    'ALC_DL0_SISO_Level': 2,
    'ALC_DL1_MIMO_Level': 2,
    'ALC_UL0_SISO_Level': 2,
    'ALC_UL1_MIMO_Level': 2,
    'SISO_RF_DET_DL0_OUT_High': 2,
    'SISO_RF_DET_UL0_OUT_High': 2,
    'MIMO_RF_DET_DL1_OUT_High': 2,
    'MIMO_RF_DET_UL1_OUT_High': 2,
    'LD1_DET_DL0_SISO_Low': 2,
    'LD2_DET_DL1_MIMO_Low': 2,
    'PD1_DET_UL0_SISO_Low': 2,
    'PD2_DET_UL1_MIMO_Low': 2,
    'LD3_DET_DL0_SISO_Low': 2,
    'LD4_DET_DL1_MIMO_Low': 2,
    'PD3_DET_UL0_SISO_Low': 2,
    'PD4_DET_UL1_MIMO_Low': 2,
    'LD1_DET_DL0_SISO_Offset': 2,
    'LD2_DET_DL1_MIMO_Offset': 2,
    'PD1_DET_UL0_SISO_Offset': 2,
    'PD2_DET_UL1_MIMO_Offset': 2,
    'LD3_DET_DL0_SISO_Offset': 2,
    'LD4_DET_DL1_MIMO_Offset': 2,
    'PD3_DET_UL0_SISO_Offset': 2,
    'PD4_DET_UL1_MIMO_Offset': 2,
    'DU_DlManualAtten_SISO': 1,
    'DU_DlSubAtten_SISO': 1,
    'DU_DlManualAtten_MIMO': 1,
    'DU_DlSubAtten_MIMO': 1,
    'DU_UlManualAtten_SISO': 1,
    'DU_UlSubAtten_SISO': 1,
    'DU_UlIsoAtten_SISO': 1,
    'DU_UlManualAtten_MIMO': 1,
    'DU_UlSubAtten_MIMO': 1,
    'DU_UlIsoAtten_MIMO': 1,
    'SU_DlManualAtten_SISO': 1,
    'SU_DlSubAtten_SISO': 1,
    'SU_DlManualAtten_MIMO': 1,
    'SU_DlSubAtten_MIMO': 1,
    'SU_UlManualAtten_SISO': 1,
    'SU_UlSubAtten_SISO': 1,
    'SU_UlManualAtten_MIMO': 1,
    'SU_UlSubAtten_MIMO': 1,
    'LicPassword': 2,
    'DL_OutputOffset_SISO': 2,
    'DL_OutputOffset_MIMO': 2,
    'UL_InputOffset_SISO': 2,
    'UL_InputOffset_MIMO': 2,
    'SU_UlCasSisoAtten_SISO': 1,
    'SU_UlCasSisoAtten_MIMO': 1,
    'SdOnOffSiso': 1,
    'SdOnOffMimo': 1,
    'DuFixBeam': 1,
    'Reserved4_Local': 7,
    'Dl_Siso_Att_Test': 2,
    'Dl_Mimo_Att_Test': 2,
    'Ul_Siso_Att_Test': 2,
    'Ul_Mimo_Att_Test': 2,
    'Reserved10p1': 32,
    # MVBX 제어
    'Mvbx_BeamSet': 1,
    'InstallUseMode': 1,
    'Reserved14': 2,
    'Mvbx_FpagImageSize': 4,
    'Mvbx_FpagImageStartAddressOffset': 4,
    'Reserved15': 16,
    'FpgaWriteAddress': 2,
    'FpgaWriteData': 2,
    'FpgaReadAddress': 2,
    'FpgaReadData': 2,
    'Reserved31': 12,
    'Mvbx_TddSignalMode': 1,
    'Mvbx_RsAgcThreshold': 1,
    'Mvbx_RsAgcMode': 1,
    'Reserved32': 1,
    'Mvbx_Mv2853TxGainSiso': 1,
    'Mvbx_Mv2853RxGainSiso': 1,
    'Mvbx_Mv2850TxGainSiso': 1,
    'Mvbx_Mv2850RxGainSiso': 1,
    'Mvbx_Mv2853TxGainMimo': 1,
    'Mvbx_Mv2853RxGainMimo': 1,
    'Mvbx_Mv2850TxGainMimo': 1,
    'Mvbx_Mv2850RxGainMimo': 1,
    'Mvbx_TxGainSetSiso': 1,
    'Mvbx_RxGainSetSiso': 1,
    'Mvbx_TxGainSetMiso': 1,
    'Mvbx_RxGainSetMiso': 1,
    'beam_info_pss_type': 4,
    'beam_info_adc_sel': 4,
    'beam_info_spg': 4,
    'beam_info_ssbIdx': 4,
    'beam_info_beamID': 2,
    'Reserved34': 2,
    'beam_info_energy': 4,
    'beam_info_rsrp': 4,
    'beam_info_snr': 4,
    'PllSet': 4,
    'IsoMeasSet': 1,
    'SuGsOnOff': 1,
    'SuIsoAttSet': 1,
    'GumStick_OnOff': 1,
    'BeamScan_OnOff': 1,
    'IsoDetectMode': 1,
    'ApiLogLevel': 1,
    'ApiAdcSel': 1,
    'ApiSyncPathGain': 1,
    'ApiDuTimeAdvance': 1,
    'ApiSuTimeAdvance': 1,
    'TemperCompensationMode': 1,
    'ApiVenderFreq': 4,
    'ApiGsOutputPowerOffsetSiso': 2,
    'BeamAntSelect': 1,
    'DecodeRecoveryFuncOnOff': 1,
    'gNB_ScanOnOff': 1,
    'Reserved33': 1,
    'ApiGsOutputPowerOffsetMimo': 2,
    'gNB_Vendor': 1,
    'Gs_Gain_Siso': 1,
    'Gs_Gain_Mimo': 1,
    'ApiInitRetryMode': 1,
    'Orientation': 2,
    'Tilt': 2,
    'GS_AttenOffset_DL_Siso': 1,
    'GS_AttenOffset_DL_Mimo': 1,
    'GS_AttenOffset_UL_Siso': 1,
    'GS_AttenOffset_UL_Mimo': 1,
    'ConSerialNum': 16,
    'AomTemperConperMode': 1,
    'GS_AttenOffset_30by15_DL_Siso': 1,
    'GS_AttenOffset_30by30_DL_Siso': 1,
    'GS_AttenOffset_60by15_DL_Siso': 1,
    'GS_AttenOffset_60by30_DL_Siso': 1,
    'GS_AttenOffset_60by60_DL_Siso': 1,
    'GS_AttenOffset_30by15_DL_Mimo': 1,
    'GS_AttenOffset_30by30_DL_Mimo': 1,
    'GS_AttenOffset_60by15_DL_Mimo': 1,
    'GS_AttenOffset_60by30_DL_Mimo': 1,
    'GS_AttenOffset_60by60_DL_Mimo': 1,
    'GS_AttenOffset_30by15_UL_Siso': 1,
    'GS_AttenOffset_30by30_UL_Siso': 1,
    'GS_AttenOffset_60by15_UL_Siso': 1,
    'GS_AttenOffset_60by30_UL_Siso': 1,
    'GS_AttenOffset_60by60_UL_Siso': 1,
    'GS_AttenOffset_30by15_UL_Mimo': 1,
    'GS_AttenOffset_30by30_UL_Mimo': 1,
    'GS_AttenOffset_60by15_UL_Mimo': 1,
    'GS_AttenOffset_60by30_UL_Mimo': 1,
    'GS_AttenOffset_60by60_UL_Mimo': 1,
    'Reserved41': 24,
    'LowRsrpStillTime': 1,
    'LowRsrpLevel': 2,
    'SU_DlCasSisoAtten_SISO': 1,
    'SU_DlCasSisoAtten_MIMO': 1,
    'SU_DlCasSisoAttenTest_SISO': 1,
    'SU_DlCasSisoAttenTest_MIMO': 1,
    'SU_UlCasSisoAttenTest_SISO': 1,
    'SU_UlCasSisoAttenTest_MIMO': 1,
    'Reserved41p1': 3,
    'PciResetOnOff': 1,
    'PciNo': 2,
    'PciTime': 1,
    'Reserved42': 7,
}

ReqStatus_PacketSize = {
    'Rcv_Main_Sys': 1,
    'Rcv_Sub_Sys': 1,
    'Rcv_Object': 1,
    'Trans_Main_Sys': 1,
    'Trans_Sub_Sys': 1,
    'Trans_Object': 1,
    'CMD': 1,
    'EQUIP_TYPE': 1,
    'RESERVED': 2,
    'SubData_Size': 2,
}

# 필드 타입 매핑: 각 필드의 타입과 변환 함수 정보
ReqControl_PacketType = {
    # 헤더 필드 (u8)
    'Rcv_Main_Sys': {'type': 'u8', 'conversion': None},
    'Rcv_Sub_Sys': {'type': 'u8', 'conversion': None},
    'Rcv_Object': {'type': 'u8', 'conversion': None},
    'Trans_Main_Sys': {'type': 'u8', 'conversion': None},
    'Trans_Sub_Sys': {'type': 'u8', 'conversion': None},
    'Trans_Object': {'type': 'u8', 'conversion': None},
    'CMD': {'type': 'u8', 'conversion': None},
    'EQUIP_TYPE': {'type': 'u8', 'conversion': None},
    'RESERVED': {'type': 'bytes', 'conversion': None},
    'SubData_Size': {'type': 'u16le', 'conversion': None},
    'InitCheckNum': {'type': 'u32le', 'conversion': None},
    'ConMuFlag': {'type': 'bytes', 'conversion': None},  # 24바이트 배열
    'ConSysTime': {'type': 'bytes', 'conversion': None},  # 7바이트
    'RptMakerCode': {'type': 'u8', 'conversion': None},
    
    # System 필드
    'SysTemperHighLvl': {'type': 'i8', 'conversion': None},
    'SysTemperLowLvl': {'type': 'i8', 'conversion': None},
    'SubInitCheckNum': {'type': 'u8', 'conversion': None},
    'DebugMode': {'type': 'u8', 'conversion': None},
    'SuEnableInfo': {'type': 'bytes', 'conversion': None},  # 12바이트
    'MaskMuAlarm': {'type': 'bytes', 'conversion': None},  # 12바이트
    'MaskSuLinkFail': {'type': 'bytes', 'conversion': None},  # 12바이트
    'MaskSuSumAlarm': {'type': 'bytes', 'conversion': None},  # 12바이트
    'MaskSuRptAlarm': {'type': 'bytes', 'conversion': None},  # 12바이트
    'ConEmsModemReset': {'type': 'u8', 'conversion': None},
    'DownloadPath_GuiOrEms': {'type': 'u8', 'conversion': None},
    'PollingTime': {'type': 'u16le', 'conversion': None},
    'ApiInitMode': {'type': 'u8', 'conversion': None},
    'AttTestMode': {'type': 'u8', 'conversion': None},
    'SuId': {'type': 'u8', 'conversion': None},
    'DL_UL_TEST': {'type': 'u8', 'conversion': None},
    'LocalInfo': {'type': 'bytes', 'conversion': None},  # 60바이트
    'SuOpticalEnStatus': {'type': 'u8', 'conversion': None},
    'PreStaAlarm': {'type': 'bytes', 'conversion': None},  # 12바이트
    'Mu_Su_Buadrate': {'type': 'u8', 'conversion': None},
    'ModemOnOff': {'type': 'u8', 'conversion': None},
    'RsrpOffset': {'type': 'i8', 'conversion': None},
    
    # RF 제어 필드
    'ALC_DL0_SISO_Mode': {'type': 'u8', 'conversion': None},
    'ALC_DL1_MIMO_Mode': {'type': 'u8', 'conversion': None},
    'ALC_UL0_SISO_Mode': {'type': 'u8', 'conversion': None},
    'ALC_UL1_MIMO_Mode': {'type': 'u8', 'conversion': None},
    'ALC_DL0_SISO_Level': {'type': 'i16le', 'conversion': None},  # signed short
    'ALC_DL1_MIMO_Level': {'type': 'i16le', 'conversion': None},
    'ALC_UL0_SISO_Level': {'type': 'i16le', 'conversion': None},
    'ALC_UL1_MIMO_Level': {'type': 'i16le', 'conversion': None},
    'SISO_RF_DET_DL0_OUT_High': {'type': 'i16le', 'conversion': None},  # signed short (변환 함수 없음)
    'SISO_RF_DET_UL0_OUT_High': {'type': 'i16le', 'conversion': None},
    'MIMO_RF_DET_DL1_OUT_High': {'type': 'i16le', 'conversion': None},
    'MIMO_RF_DET_UL1_OUT_High': {'type': 'i16le', 'conversion': None},
    
    # OPTIC 필드 (convert_to_01dbm 역변환 필요)
    'LD1_DET_DL0_SISO_Low': {'type': 'i16le', 'conversion': 'convert_to_01dbm'},  # ×10
    'LD2_DET_DL1_MIMO_Low': {'type': 'i16le', 'conversion': 'convert_to_01dbm'},  # ×10
    'PD1_DET_UL0_SISO_Low': {'type': 'i16le', 'conversion': 'convert_to_01dbm'},  # ×10
    'PD2_DET_UL1_MIMO_Low': {'type': 'i16le', 'conversion': 'convert_to_01dbm'},  # ×10
    'LD3_DET_DL0_SISO_Low': {'type': 'i16le', 'conversion': 'convert_to_01dbm'},  # ×10
    'LD4_DET_DL1_MIMO_Low': {'type': 'i16le', 'conversion': 'convert_to_01dbm'},  # ×10
    'PD3_DET_UL0_SISO_Low': {'type': 'i16le', 'conversion': 'convert_to_01dbm'},  # ×10
    'PD4_DET_UL1_MIMO_Low': {'type': 'i16le', 'conversion': 'convert_to_01dbm'},  # ×10
    
    # ATT 필드 (convert_att_4_to_2 역변환 필요)
    'DU_DlManualAtten_SISO': {'type': 'u8', 'conversion': 'convert_att_4_to_2'},  # ×2
    'DU_DlSubAtten_SISO': {'type': 'u8', 'conversion': None},
    'DU_DlManualAtten_MIMO': {'type': 'u8', 'conversion': 'convert_att_4_to_2'},  # ×2
    'DU_DlSubAtten_MIMO': {'type': 'u8', 'conversion': None},
    'DU_UlManualAtten_SISO': {'type': 'u8', 'conversion': 'convert_att_4_to_2'},  # ×2
    'DU_UlSubAtten_SISO': {'type': 'u8', 'conversion': None},
    'DU_UlIsoAtten_SISO': {'type': 'u8', 'conversion': 'convert_iso_att'},  # ×2
    'DU_UlManualAtten_MIMO': {'type': 'u8', 'conversion': 'convert_att_4_to_2'},  # ×2
    'DU_UlSubAtten_MIMO': {'type': 'u8', 'conversion': None},
    'DU_UlIsoAtten_MIMO': {'type': 'u8', 'conversion': 'convert_iso_att'},  # ×2
    
    # SU ATT 필드
    'SU_DlManualAtten_SISO': {'type': 'u8', 'conversion': 'convert_att_4_to_2'},  # ×2
    'SU_DlSubAtten_SISO': {'type': 'u8', 'conversion': None},
    'SU_DlManualAtten_MIMO': {'type': 'u8', 'conversion': 'convert_att_4_to_2'},  # ×2
    'SU_DlSubAtten_MIMO': {'type': 'u8', 'conversion': None},
    'SU_UlManualAtten_SISO': {'type': 'u8', 'conversion': 'convert_att_4_to_2'},  # ×2
    'SU_UlSubAtten_SISO': {'type': 'u8', 'conversion': None},
    'SU_UlManualAtten_MIMO': {'type': 'u8', 'conversion': 'convert_att_4_to_2'},  # ×2
    'SU_UlSubAtten_MIMO': {'type': 'u8', 'conversion': None},
    
    # Offset 필드 (convert_to_01dbm 역변환 필요)
    'LD1_DET_DL0_SISO_Offset': {'type': 'i16le', 'conversion': 'convert_to_01dbm'},  # ×10
    'LD2_DET_DL1_MIMO_Offset': {'type': 'i16le', 'conversion': 'convert_to_01dbm'},  # ×10
    'PD1_DET_UL0_SISO_Offset': {'type': 'i16le', 'conversion': 'convert_to_01dbm'},  # ×10
    'PD2_DET_UL1_MIMO_Offset': {'type': 'i16le', 'conversion': 'convert_to_01dbm'},  # ×10
    'LD3_DET_DL0_SISO_Offset': {'type': 'i16le', 'conversion': 'convert_to_01dbm'},  # ×10
    'LD4_DET_DL1_MIMO_Offset': {'type': 'i16le', 'conversion': 'convert_to_01dbm'},  # ×10
    'PD3_DET_UL0_SISO_Offset': {'type': 'i16le', 'conversion': 'convert_to_01dbm'},  # ×10
    'PD4_DET_UL1_MIMO_Offset': {'type': 'i16le', 'conversion': 'convert_to_01dbm'},  # ×10
    'DL_OutputOffset_SISO': {'type': 'i16le', 'conversion': 'convert_to_01dbm'},  # ×10
    'DL_OutputOffset_MIMO': {'type': 'i16le', 'conversion': 'convert_to_01dbm'},  # ×10
    'UL_InputOffset_SISO': {'type': 'i16le', 'conversion': 'convert_to_01dbm'},  # ×10
    'UL_InputOffset_MIMO': {'type': 'i16le', 'conversion': 'convert_to_01dbm'},  # ×10
    'ApiGsOutputPowerOffsetSiso': {'type': 'i16le', 'conversion': 'convert_to_01dbm'},  # ×10
    'ApiGsOutputPowerOffsetMimo': {'type': 'i16le', 'conversion': 'convert_to_01dbm'},  # ×10
    
    # ATT Test 필드 (convert_att_test 역변환 필요)
    'Dl_Siso_Att_Test': {'type': 'i16le', 'conversion': 'convert_att_test'},  # ×2
    'Dl_Mimo_Att_Test': {'type': 'i16le', 'conversion': 'convert_att_test'},  # ×2
    'Ul_Siso_Att_Test': {'type': 'i16le', 'conversion': 'convert_att_test'},  # ×2
    'Ul_Mimo_Att_Test': {'type': 'i16le', 'conversion': 'convert_att_test'},  # ×2
    
    # MVBX 제어 필드
    'Mvbx_BeamSet': {'type': 'u8', 'conversion': None},
    'InstallUseMode': {'type': 'u8', 'conversion': None},
    'Mvbx_FpagImageSize': {'type': 'u32le', 'conversion': None},
    'Mvbx_FpagImageStartAddressOffset': {'type': 'u32le', 'conversion': None},
    'FpgaWriteAddress': {'type': 'u16le', 'conversion': None},
    'FpgaWriteData': {'type': 'u16le', 'conversion': None},
    'FpgaReadAddress': {'type': 'u16le', 'conversion': None},
    'FpgaReadData': {'type': 'u16le', 'conversion': None},
    'Mvbx_TddSignalMode': {'type': 'u8', 'conversion': None},
    'Mvbx_RsAgcThreshold': {'type': 'i8', 'conversion': None},
    'Mvbx_RsAgcMode': {'type': 'u8', 'conversion': None},
    'Mvbx_Mv2853TxGainSiso': {'type': 'u8', 'conversion': None},
    'Mvbx_Mv2853RxGainSiso': {'type': 'u8', 'conversion': None},
    'Mvbx_Mv2850TxGainSiso': {'type': 'u8', 'conversion': None},
    'Mvbx_Mv2850RxGainSiso': {'type': 'u8', 'conversion': None},
    'Mvbx_Mv2853TxGainMimo': {'type': 'u8', 'conversion': None},
    'Mvbx_Mv2853RxGainMimo': {'type': 'u8', 'conversion': None},
    'Mvbx_Mv2850TxGainMimo': {'type': 'u8', 'conversion': None},
    'Mvbx_Mv2850RxGainMimo': {'type': 'u8', 'conversion': None},
    'Mvbx_TxGainSetSiso': {'type': 'u8', 'conversion': None},
    'Mvbx_RxGainSetSiso': {'type': 'u8', 'conversion': None},
    'Mvbx_TxGainSetMiso': {'type': 'u8', 'conversion': None},
    'Mvbx_RxGainSetMiso': {'type': 'u8', 'conversion': None},
    
    # Beam Info 필드
    'beam_info_pss_type': {'type': 'u32le', 'conversion': None},
    'beam_info_adc_sel': {'type': 'u32le', 'conversion': None},
    'beam_info_spg': {'type': 'u32le', 'conversion': None},
    'beam_info_ssbIdx': {'type': 'u32le', 'conversion': None},
    'beam_info_beamID': {'type': 'i16le', 'conversion': None},
    'beam_info_energy': {'type': 'u32le', 'conversion': None},
    'beam_info_rsrp': {'type': 'u32le', 'conversion': None},
    'beam_info_snr': {'type': 'u32le', 'conversion': None},
    'PllSet': {'type': 'u32le', 'conversion': None},
    'IsoMeasSet': {'type': 'u8', 'conversion': None},
    'SuGsOnOff': {'type': 'u8', 'conversion': None},
    'SuIsoAttSet': {'type': 'u8', 'conversion': None},
    'GumStick_OnOff': {'type': 'u8', 'conversion': None},
    'BeamScan_OnOff': {'type': 'u8', 'conversion': None},
    'IsoDetectMode': {'type': 'u8', 'conversion': None},
    'ApiLogLevel': {'type': 'u8', 'conversion': None},
    'ApiAdcSel': {'type': 'u8', 'conversion': None},
    'ApiSyncPathGain': {'type': 'u8', 'conversion': None},
    'ApiDuTimeAdvance': {'type': 'u8', 'conversion': None},
    'ApiSuTimeAdvance': {'type': 'u8', 'conversion': None},
    'TemperCompensationMode': {'type': 'u8', 'conversion': None},
    'ApiVenderFreq': {'type': 'u32le', 'conversion': None},
    'ApiGsOutputPowerOffsetSiso': {'type': 'i16le', 'conversion': 'convert_to_01dbm'},  # ×10
    'BeamAntSelect': {'type': 'u8', 'conversion': None},
    'DecodeRecoveryFuncOnOff': {'type': 'u8', 'conversion': None},
    'gNB_ScanOnOff': {'type': 'u8', 'conversion': None},
    'gNB_Vendor': {'type': 'u8', 'conversion': None},
    'Gs_Gain_Siso': {'type': 'u8', 'conversion': None},
    'Gs_Gain_Mimo': {'type': 'u8', 'conversion': None},
    'ApiInitRetryMode': {'type': 'u8', 'conversion': None},
    'Orientation': {'type': 'i16le', 'conversion': None},
    'Tilt': {'type': 'i16le', 'conversion': None},
    'GS_AttenOffset_DL_Siso': {'type': 'i8', 'conversion': None},
    'GS_AttenOffset_DL_Mimo': {'type': 'i8', 'conversion': None},
    'GS_AttenOffset_UL_Siso': {'type': 'i8', 'conversion': None},
    'GS_AttenOffset_UL_Mimo': {'type': 'i8', 'conversion': None},
    'ConSerialNum': {'type': 'string', 'conversion': None, 'max_len': 16},
    'AomTemperConperMode': {'type': 'u8', 'conversion': None},
    'LowRsrpStillTime': {'type': 'u8', 'conversion': None},
    'LowRsrpLevel': {'type': 'u16le', 'conversion': None},
    'PciResetOnOff': {'type': 'u8', 'conversion': None},
    'PciNo': {'type': 'u16le', 'conversion': None},
    'PciTime': {'type': 'u8', 'conversion': None},
    
    # 기타 필드들
    'LicPassword': {'type': 'i16le', 'conversion': None},
    'SU_UlCasSisoAtten_SISO': {'type': 'u8', 'conversion': None},
    'SU_UlCasSisoAtten_MIMO': {'type': 'u8', 'conversion': None},
    'SdOnOffSiso': {'type': 'u8', 'conversion': None},
    'SdOnOffMimo': {'type': 'u8', 'conversion': None},
    'DuFixBeam': {'type': 'u8', 'conversion': None},
    'SuEndMode': {'type': 'u8', 'conversion': None},
    
    # Sync Module 필드
    'TSYNC_OUT_SEL1': {'type': 'u8', 'conversion': None},
    'TSYNC_OUT_SEL2': {'type': 'u8', 'conversion': None},
    'TSYNC_OUT_SEL3': {'type': 'u8', 'conversion': None},
    'F_Mode': {'type': 'u8', 'conversion': None},
    'TDD_Freq': {'type': 'u32le', 'conversion': None},  # 실제로는 kHz 단위로 저장 (×1000)
    'TDD_Arfcn': {'type': 'u32le', 'conversion': None},  # 또는 u16le일 수도 있음
    'MVBX_SSB_MU': {'type': 'u8', 'conversion': None},
    'MVBX_TDD_RATE': {'type': 'u8', 'conversion': None},
    'TDD_SLOT_FORMAT': {'type': 'bytes', 'conversion': None},  # 160바이트 배열
    'TDD_FORMAT_3GPP_TABLE': {'type': 'bytes', 'conversion': None},  # 784바이트 배열
}

def json_to_jsonstring(data, packet_size_map):
    """
    JSON 데이터를 바이너리 패킷으로 변환
    
    Args:
        data: JSON 딕셔너리 (예: {"SysTemperHighLvl": 50, "ALC_DL0_SISO_Level": 1000, ...})
        packet_size_map: 필드별 바이트 크기 매핑 (ReqControl_PacketSize)
    
    Returns:
        bytes: 바이너리 패킷
    """
    try:
        packet_parts = []
        
        # 변환 함수 역변환 매핑
        def apply_reverse_conversion(value, conversion_name):
            """변환 함수의 역변환 적용"""
            if conversion_name == 'convert_to_01dbm':
                # 파싱: raw / 10.0 → 전송: raw * 10
                return int(value * 10)
            elif conversion_name == 'convert_att_4_to_2':
                # 파싱: raw * 0.5 → 전송: raw / 0.5 = raw * 2
                return int(value * 2)
            elif conversion_name == 'convert_iso_att':
                # 파싱: raw * 0.5 → 전송: raw / 0.5 = raw * 2
                return int(value * 2)
            elif conversion_name == 'convert_att_test':
                # 파싱: raw * 0.5 → 전송: raw / 0.5 = raw * 2
                return int(value * 2)
            elif conversion_name == 'convert_to_1dbm':
                # 파싱: raw (그대로) → 전송: raw (그대로)
                return int(value)
            else:
                return value
        
        # 딕셔너리를 바이트 배열로 역변환
        def dict_to_bytes(dict_value, size, field_key=None):
            """
            딕셔너리를 바이트 배열로 역변환
            parse_Du_StatusPacket에서 딕셔너리로 변환된 필드들을 원래 바이너리로 복원
            """
            if not isinstance(dict_value, dict):
                return None
            
            # size 검증
            if not isinstance(size, int) or size <= 0:
                print(f"⚠️ Warning: Invalid size for dict_to_bytes: {type(size)}. Using default size.")
                # 필드별 기본 크기 설정
                if field_key == 'SuEnableInfo':
                    size = 12
                elif field_key == 'MaskMuAlarm':
                    size = 12
                elif field_key == 'MaskSuLinkFail':
                    size = 12
                else:
                    size = 1  # 기본값
            
            # 바이트 배열 초기화
            try:
                byte_array = bytearray(size)
            except (TypeError, ValueError) as e:
                print(f"⚠️ Warning: Failed to create bytearray with size {size}: {e}")
                return None
            
            # 필드별 비트 매핑 정의
            if field_key == 'SuEnableInfo':
                # SuEnableBits: packet[616]의 비트 0~3
                # {'SU1_ENABLE': 0/1, 'SU2_ENABLE': 0/1, 'SU3_ENABLE': 0/1, 'SU4_ENABLE': 0/1}
                if isinstance(size, int) and size > 0:
                    if 'SU1_ENABLE' in dict_value:
                        byte_array[0] |= (1 if dict_value['SU1_ENABLE'] else 0) << 0
                    if 'SU2_ENABLE' in dict_value:
                        byte_array[0] |= (1 if dict_value['SU2_ENABLE'] else 0) << 1
                    if 'SU3_ENABLE' in dict_value:
                        byte_array[0] |= (1 if dict_value['SU3_ENABLE'] else 0) << 2
                    if 'SU4_ENABLE' in dict_value:
                        byte_array[0] |= (1 if dict_value['SU4_ENABLE'] else 0) << 3
                return bytes(byte_array)
            
            elif field_key == 'MaskMuAlarm':
                # MaskMuAlarm: packet[628:640] (12바이트)
                # 여러 딕셔너리 필드가 합쳐져서 하나의 바이트 배열이 됨
                # - DET_MASK_Bits: packet[634]의 비트 0~3
                # - DL_ALC_Bits: packet[635]의 비트 0, 2, 5
                # - MaskAlarmStatus: packet[628:640]의 여러 비트들
                
                # DET_MASK_Bits: packet[634] (인덱스 6)의 비트 0~3
                if isinstance(size, int) and size > 6:
                    if 'LD1_DET_DL0_SISO_MASK' in dict_value:
                        byte_array[6] |= (1 if dict_value['LD1_DET_DL0_SISO_MASK'] else 0) << 0
                    if 'LD2_DET_DL1_MIMO_MASK' in dict_value:
                        byte_array[6] |= (1 if dict_value['LD2_DET_DL1_MIMO_MASK'] else 0) << 1
                    if 'PD1_DET_UL0_SISO_MASK' in dict_value:
                        byte_array[6] |= (1 if dict_value['PD1_DET_UL0_SISO_MASK'] else 0) << 2
                    if 'PD2_DET_UL1_MIMO_MASK' in dict_value:
                        byte_array[6] |= (1 if dict_value['PD2_DET_UL1_MIMO_MASK'] else 0) << 3
                
                # DL_ALC_Bits: packet[635] (인덱스 7)의 비트 0, 2, 5
                if isinstance(size, int) and size > 7:
                    if 'SISO_MASK_DL_ALC' in dict_value:
                        byte_array[7] |= (1 if dict_value['SISO_MASK_DL_ALC'] else 0) << 0
                    if 'MIMO_MASK_DL_ALC' in dict_value:
                        byte_array[7] |= (1 if dict_value['MIMO_MASK_DL_ALC'] else 0) << 2
                    if 'EMS_DU_Link_MASK' in dict_value:
                        byte_array[7] |= (1 if dict_value['EMS_DU_Link_MASK'] else 0) << 5
                
                # MaskAlarmStatus: packet[628:640]의 여러 비트들
                # 비트 매핑: {'bit': 1, 'id': 'alarm_mask_madc'}, ...
                alarm_mask_bit_map = {
                    'alarm_mask_madc': 1,
                    'alarm_mask_ac': 2,
                    'alarm_mask_temp': 3,
                    'alarm_mask_bat': 4,
                    'alarm_mask_fpga_link': 49,
                    'alarm_mask_if_pll': 53,
                    'alarm_mask_sync_pll': 54,
                    'alarm_mask_tsync_link': 52,
                    'alarm_mask_decoding': 66,
                    'alarm_mask_aa_link': 70
                }
                for alarm_id, bit_pos in alarm_mask_bit_map.items():
                    if alarm_id in dict_value:
                        byte_index = (bit_pos - 1) // 8
                        bit_in_byte = (bit_pos - 1) % 8
                        if isinstance(size, int) and byte_index < size:
                            bit_value = 1 if dict_value[alarm_id] else 0
                            byte_array[byte_index] |= (bit_value << bit_in_byte)
                
                return bytes(byte_array)
            
            elif field_key == 'MaskSuLinkFail':
                # MaskSuLinkFail: packet[640]의 비트 0~3
                # {'SU1_MASK_LINK_FAIL': 0/1, 'SU2_MASK_LINK_FAIL': 0/1, ...}
                if 'SU1_MASK_LINK_FAIL' in dict_value:
                    byte_array[0] |= (1 if dict_value['SU1_MASK_LINK_FAIL'] else 0) << 0
                if 'SU2_MASK_LINK_FAIL' in dict_value:
                    byte_array[0] |= (1 if dict_value['SU2_MASK_LINK_FAIL'] else 0) << 1
                if 'SU3_MASK_LINK_FAIL' in dict_value:
                    byte_array[0] |= (1 if dict_value['SU3_MASK_LINK_FAIL'] else 0) << 2
                if 'SU4_MASK_LINK_FAIL' in dict_value:
                    byte_array[0] |= (1 if dict_value['SU4_MASK_LINK_FAIL'] else 0) << 3
                return bytes(byte_array)
            
            # 알 수 없는 딕셔너리 구조: 기본값 반환
            return None
        
        # packet_size_map에 정의된 순서와 크기를 기반으로 데이터 변환
        for key, size in packet_size_map.items():
            # size가 정수인지 먼저 확인 (안전장치)
            if not isinstance(size, int):
                print(f"⚠️ Warning: Invalid size type for key '{key}': {type(size)}. Using 0.")
                size = 0
            
            value = data.get(key)
            
            # 필드 타입 정보 가져오기
            field_type_info = ReqControl_PacketType.get(key, {})
            field_type = field_type_info.get('type', 'u8')  # 기본값: u8
            conversion_name = field_type_info.get('conversion', None)
            
            # 특수 처리: 여러 딕셔너리 필드가 하나의 바이트 배열로 합쳐지는 경우
            # SuEnableInfo: SuEnableBits 딕셔너리에서 변환
            if key == 'SuEnableInfo' and value is None:
                su_enable_bits = data.get('SuEnableBits')
                if isinstance(su_enable_bits, dict):
                    value = dict_to_bytes(su_enable_bits, size, field_key=key)
                    if value is None:
                        safe_size = size if isinstance(size, int) and size > 0 else 0
                        value = b'\x00' * safe_size
            
            # MaskMuAlarm: 여러 딕셔너리 필드가 합쳐짐
            # - DET_MASK_Bits, DL_ALC_Bits, MaskAlarmStatus
            elif key == 'MaskMuAlarm':
                if isinstance(value, dict):
                    # 딕셔너리인 경우 직접 변환
                    value = dict_to_bytes(value, size, field_key=key)
                    if value is None:
                        safe_size = size if isinstance(size, int) and size > 0 else 0
                        value = b'\x00' * safe_size
                elif value is None or (isinstance(value, list) and len(value) == 0):
                    # None이거나 빈 리스트인 경우, 관련 딕셔너리 필드들에서 재구성 시도
                    det_mask_bits = data.get('DET_MASK_Bits', {})
                    dl_alc_bits = data.get('DL_ALC_Bits', {})
                    mask_alarm_status = data.get('MaskAlarmStatus', {})
                    
                    # 모든 딕셔너리를 하나로 합치기
                    combined_dict = {}
                    if isinstance(det_mask_bits, dict):
                        combined_dict.update(det_mask_bits)
                    if isinstance(dl_alc_bits, dict):
                        combined_dict.update(dl_alc_bits)
                    if isinstance(mask_alarm_status, dict):
                        combined_dict.update(mask_alarm_status)
                    
                    if combined_dict:
                        value = dict_to_bytes(combined_dict, size, field_key=key)
                        if value is None:
                            safe_size = size if isinstance(size, int) and size > 0 else 0
                            value = b'\x00' * safe_size
                    else:
                        safe_size = size if isinstance(size, int) and size > 0 else 0
                        value = b'\x00' * safe_size
            
            # MaskSuLinkFail: 딕셔너리에서 변환
            elif key == 'MaskSuLinkFail':
                if isinstance(value, dict):
                    # 딕셔너리인 경우 직접 변환
                    value = dict_to_bytes(value, size, field_key=key)
                    if value is None:
                        safe_size = size if isinstance(size, int) and size > 0 else 0
                        value = b'\x00' * safe_size
                elif value is None:
                    # None인 경우 기본값
                    safe_size = size if isinstance(size, int) and size > 0 else 0
                    value = b'\x00' * safe_size
            
            # 값이 None이거나 딕셔너리/리스트인 경우 기본값 처리
            if value is None:
                # 기본값 설정
                safe_size = size if isinstance(size, int) and size > 0 else 0
                if field_type == 'bytes' or field_type == 'string':
                    value = b'\x00' * safe_size if field_type == 'bytes' else '\x00' * safe_size
                elif field_type in ['u8', 'u16le', 'u32le']:
                    value = 0
                elif field_type in ['i8', 'i16le']:
                    value = 0
                else:
                    value = 0
            elif isinstance(value, dict):
                # 딕셔너리인 경우: 원래 바이너리였는데 파싱 과정에서 딕셔너리로 변환된 경우
                # 바이트 배열 필드인 경우 딕셔너리를 바이트로 역변환 시도
                if field_type == 'bytes':
                    try:
                        # 딕셔너리를 바이트 배열로 역변환 (필드 키 전달)
                        converted_bytes = dict_to_bytes(value, size, field_key=key)
                        if converted_bytes is not None:
                            value = converted_bytes
                            print(f"✅ Converted dict to bytes for '{key}': {len(value)} bytes")
                        else:
                            # 역변환 실패: 기본값 사용
                            print(f"⚠️ Warning: Could not convert dict to bytes for '{key}'. Using default.")
                            safe_size = size if isinstance(size, int) and size > 0 else 0
                            value = b'\x00' * safe_size
                    except Exception as e:
                        print(f"⚠️ Warning: Failed to convert dict to bytes for '{key}': {e}. Using default.")
                        import traceback
                        traceback.print_exc()
                        safe_size = size if isinstance(size, int) and size > 0 else 0
                        value = b'\x00' * safe_size
                else:
                    # 바이트 배열이 아닌 필드에 딕셔너리가 들어온 경우
                    print(f"⚠️ Warning: Value for key '{key}' is a dict but field type is '{field_type}'. Using default.")
                    safe_size = size if isinstance(size, int) and size > 0 else 0
                    if field_type == 'string':
                        value = '\x00' * safe_size
                    else:
                        value = 0
            else:
                # 변환 함수 역변환 적용 (숫자 타입만)
                # value가 딕셔너리나 리스트인 경우 먼저 체크
                if isinstance(value, (dict, list)):
                    # 딕셔너리나 리스트는 변환 함수 적용 불가
                    print(f"⚠️ Warning: Value for key '{key}' is {type(value).__name__}, cannot apply conversion. Using default.")
                    safe_size = size if isinstance(size, int) and size > 0 else 0
                    if field_type == 'bytes':
                        value = b'\x00' * safe_size
                    elif field_type == 'string':
                        value = '\x00' * safe_size
                    else:
                        value = 0
                elif conversion_name and isinstance(value, (int, float)):
                    try:
                        value = apply_reverse_conversion(value, conversion_name)
                    except (TypeError, ValueError) as e:
                        print(f"⚠️ Warning: Reverse conversion failed for key '{key}': {e}. Using original value.")
                elif conversion_name and not isinstance(value, (int, float)):
                    # 변환 함수가 필요한데 숫자가 아닌 경우
                    print(f"⚠️ Warning: Conversion needed for key '{key}' but value is not numeric: {type(value)}. Using default.")
                    safe_size = size if isinstance(size, int) and size > 0 else 0
                    if field_type == 'bytes':
                        value = b'\x00' * safe_size
                    elif field_type == 'string':
                        value = '\x00' * safe_size
                    else:
                        value = 0
            
            # 타입별 바이너리 변환
            if field_type == 'u8':
                # unsigned 8-bit
                if isinstance(value, (int, float)):
                    packet_parts.append(struct.pack('<B', int(value) & 0xFF))
                else:
                    packet_parts.append(b'\x00')
                    
            elif field_type == 'i8':
                # signed 8-bit
                if isinstance(value, (int, float)):
                    packet_parts.append(struct.pack('<b', int(value)))
                else:
                    packet_parts.append(b'\x00')
                    
            elif field_type == 'u16le':
                # unsigned 16-bit little-endian
                if isinstance(value, (int, float)):
                    packet_parts.append(struct.pack('<H', int(value) & 0xFFFF))
                else:
                    packet_parts.append(b'\x00\x00')
                    
            elif field_type == 'i16le':
                # signed 16-bit little-endian
                if isinstance(value, (int, float)):
                    packet_parts.append(struct.pack('<h', int(value)))
                else:
                    packet_parts.append(b'\x00\x00')
                    
            elif field_type == 'u32le':
                # unsigned 32-bit little-endian
                if isinstance(value, (int, float)):
                    packet_parts.append(struct.pack('<I', int(value) & 0xFFFFFFFF))
                else:
                    packet_parts.append(b'\x00\x00\x00\x00')
                    
            elif field_type == 'i32le':
                # signed 32-bit little-endian
                if isinstance(value, (int, float)):
                    packet_parts.append(struct.pack('<i', int(value)))
                else:
                    packet_parts.append(b'\x00\x00\x00\x00')
                    
            elif field_type == 'f32le' or field_type == 'float':
                # float 32-bit little-endian
                if isinstance(value, (int, float)):
                    packet_parts.append(struct.pack('<f', float(value)))
                else:
                    packet_parts.append(b'\x00\x00\x00\x00')
                    
            elif field_type == 'string':
                # 문자열 (null-padding)
                max_len = field_type_info.get('max_len', size)
                if isinstance(value, str):
                    encoded = value.encode('utf-8')[:max_len]
                    padded = encoded + b'\x00' * (max_len - len(encoded))
                    packet_parts.append(padded)
                else:
                    packet_parts.append(b'\x00' * max_len)
                    
            elif field_type == 'bytes':
                # 바이트 배열
                if isinstance(value, list):
                    # 리스트를 바이트로 변환
                    try:
                        byte_array = bytes([int(b) & 0xFF for b in value])
                        # 크기에 맞게 패딩 또는 자르기
                        if isinstance(size, int) and size > 0:
                            if len(byte_array) < size:
                                byte_array = byte_array + b'\x00' * (size - len(byte_array))
                            else:
                                byte_array = byte_array[:size]
                        packet_parts.append(byte_array)
                    except (TypeError, ValueError) as e:
                        print(f"⚠️ Warning: Failed to convert list to bytes for '{key}': {e}. Using default.")
                        packet_parts.append(b'\x00' * (size if isinstance(size, int) else 0))
                elif isinstance(value, bytes):
                    # 이미 바이트인 경우
                    if isinstance(size, int) and size > 0:
                        if len(value) < size:
                            value = value + b'\x00' * (size - len(value))
                        else:
                            value = value[:size]
                    packet_parts.append(value)
                else:
                    # 기본값: 0으로 채운 바이트 배열
                    safe_size = size if isinstance(size, int) and size > 0 else 0
                    packet_parts.append(b'\x00' * safe_size)
            else:
                # 기본 처리: 크기만큼 0으로 채움
                print(f"⚠️ Warning: Unknown field type '{field_type}' for key '{key}'. Using default.")
                safe_size = size if isinstance(size, int) and size > 0 else 0
                packet_parts.append(b'\x00' * safe_size)

        # 모든 바이트 파트를 하나의 바이너리 객체로 병합
        binary_data = b''.join(packet_parts)
        
        #payload = binary_data.hex()
        
        #payload = {"data": encoded_data}
        
        # 바이너리 데이터를 헥스 문자열로 인코딩하여 반환
        return binary_data

    except Exception as e:
        print(f"❌ Error during JSON to Hex conversion: {e}")
        #import traceback
        #traceback.print_exc()
        return None

def send_to_client(hex_str: str):
    """C 클라이언트로 HEX 문자열 전송"""
    try:
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.connect(SOCKET_PATH)
        client.sendall(hex_str.encode())
        print(f"📤 C 클라이언트로 전송: {hex_str}")
        # 응답 수신 (옵션)
        response = client.recv(1024)
        print(f"📥 C 클라이언트 응답: {response.decode()}")
        client.close()
    except Exception as e:
        print(f"❌ C 클라이언트 전송 오류: {e}")



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

# 널문자를 만날 때까지 문자열 변환
def bytes_to_string_until_null(byte_array):
    result = ''
    for b in byte_array:
        if b == 0:  # 널문자 만나면 중단
            break
        result += chr(b)
    return result

# Mask 알람 비트 추출 함수
def get_mask_alarm_bit(mask_bytes, bit_position):
    byte_index = (bit_position - 1) // 8
    bit_in_byte = (bit_position - 1) % 8
    if byte_index < len(mask_bytes):
        return (mask_bytes[byte_index] >> bit_in_byte) & 1
    return 0

# ---------------------------- 샘플 파서 함수 ----------------------------
def parse_Du_StatusPacket(packet, socketio=None):

    parsed_data = {}
    
    
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

