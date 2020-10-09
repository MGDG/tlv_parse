
/**
 * @file mlibTLVParse.c
 * @author MGDG
 * @brief lib for tlv parse
 * @version 0.1
 * @date 2020-09-21
 * 
 * @copyright Copyright (c) 2020
 * 
 */
#include "stdio.h"
#include "mlibTLVParse.h"

#define PRINT_PBOC_TAG_NAME         1       /*是否打印tag对应的名称*/

typedef enum {
    PRIMITIVE_DATA = 0,                 /*原始类型、基本类型*/
    CONSTRUCTED_DATA,                   /*复合类型，value里嵌套着其他的TLV数据*/
}tlv_tag_data_type_t;

#if (PRINT_PBOC_TAG_NAME==1)
static const char *pboc_tag_descrip(int tag);
#endif /*#if (PRINT_PBOC_TAG_NAME==1)*/

static int _mlib_tlv_get_tag(const uint8_t *data, int dataLen, int *tag, tlv_tag_data_type_t *dataType) {
    int tagLen = 1;
    *tag = data[0];
    *dataType = (data[0] & 0x20) ? CONSTRUCTED_DATA : PRIMITIVE_DATA;
    if((data[0] & 0x1F) == 0x1F) {
        for(tagLen=1;tagLen<dataLen;tagLen++) {
            *tag <<= 8;
            *tag |= data[tagLen];
            if( (data[tagLen] & 0x80) == 0x00) {
                tagLen++;
                break;
            }else if(tagLen == dataLen-1) {
                return -1;
            }
        }
    }
    return tagLen;
}

static int _mlib_tlv_get_len(const uint8_t *data, int dataLen, int *len) {
    if(dataLen <= 0) {
        return -1;
    }
    int lenLen = 1;
    if(data[0] & 0x80) {
        lenLen = 1 + (data[0]&0x7F);
        if((lenLen > dataLen) || (lenLen > 5)) {
            return -1;
        }
        *len = 0;
        for(int i=1;i<lenLen;i++) {
            *len <<= 8;
            *len |= data[i];
        }
    }else {
        *len = data[0];
    }
    return lenLen;
}

static void _mlib_tlv_parse(mlib_tlv_t **item,const uint8_t *data, int dataLen, int loopFlg) {
    int tag,tagLen,len,lenLen;
    tlv_tag_data_type_t tagType;
    while(dataLen >= 3) {
        /*get tag*/
        if((tagLen = _mlib_tlv_get_tag(data,dataLen,&tag,&tagType)) <= 0) {
            return;
        }
        data += tagLen;
        dataLen -= tagLen;

        /*get len*/
        if((lenLen = _mlib_tlv_get_len(data,dataLen,&len)) <= 0) {
            return;
        }
        data += lenLen;
        dataLen -= lenLen;

        /*get value*/
        if(dataLen < len) {
            return;
        }
        const uint8_t *value = data;
        data += len;
        dataLen -= len;

        mlib_tlv_t *new_tlv = (mlib_tlv_t *)calloc(1,sizeof(mlib_tlv_t));
        if(NULL == new_tlv) {
            return;
        }
        new_tlv->tag = tag;
        new_tlv->len = len;
        new_tlv->value = value;
        mlib_tlv_t **tlvItem = loopFlg==0?(item):&((*item)->sub);
        #if 0
        new_tlv->next = *tlvItem;
        *tlvItem = new_tlv;
        #else
        if(NULL==*tlvItem) {
            *tlvItem = new_tlv;
        }else {
            mlib_tlv_t *pre = *tlvItem;
            mlib_tlv_t *tmp = pre;
            while(NULL != tmp) {
                pre = tmp;
                tmp = tmp->next;
            }
            pre->next = new_tlv;
        }
        #endif

        /*tag 是复合类型的话，则获取复合类型的数据*/
        if(CONSTRUCTED_DATA == tagType) {
            _mlib_tlv_parse( &new_tlv, value, len,1);
        }
    }
}

mlib_tlv_t *mlib_tlv_parse(const uint8_t *data, int dataLen) {
    mlib_tlv_t *item = NULL;
    _mlib_tlv_parse( &item, data, dataLen,0);
    return item;
}

static void _mlib_tlv_printf(const mlib_tlv_t *tlv,int index) {
    while(NULL != tlv) {
        for(int i=0;i<index;i++) {
            printf("\t");
        }
        #if (PRINT_PBOC_TAG_NAME==1)
        printf("%X(%s)\t",tlv->tag,pboc_tag_descrip(tlv->tag));
        #else 
        printf("%X\t",tlv->tag);
        #endif /*#if (PRINT_PBOC_TAG_NAME==1)*/
        for(int i=0;i<tlv->len;i++) {
            printf("%02X",tlv->value[i]);
        }
        printf("\n");
        _mlib_tlv_printf(tlv->sub,index+1);
        tlv = tlv->next;
    }
}

void mlib_tlv_printf(const mlib_tlv_t *tlv) {
    _mlib_tlv_printf(tlv,0);
}

void mlib_tlv_delete(mlib_tlv_t *tlv) {
    while(NULL != tlv) {
        mlib_tlv_delete(tlv->sub);
        mlib_tlv_t *tmp = tlv;
        tlv = tlv->next;
        free(tmp);
    }
}

int mlib_tlv_get_value(const mlib_tlv_t *tlv,int tag, const uint8_t **value) {
    while(NULL != tlv) {
        if(tag == tlv->tag) {
            *value = tlv->value;
            return tlv->len;
        }
        int valueLen = mlib_tlv_get_value(tlv->sub,tag,value);
        if(valueLen > 0) {
            return valueLen;
        }
        tlv = tlv->next;
    }
    return 0;
}

void mlib_tlv_test(void) {
    const uint8_t hex[] = { 
        0x1F, 0x88, 0x01,	// Extended tag
        0x82, 0x01, 0x01, 	// Extended length: 257 bytes
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
        0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
        0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
        0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
        0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
        0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF,
        0x01,
        0x02,		// Short tag
        0x04,		// Short length: 4 bytes
        0x00, 0x00, 0x01, 0x01,
        
        0x24,		// Short tag
        0x08,
        0x24,		// Short tag
        0x06,		// Short length: 4 bytes
        0x02,		// Short tag
        0x04,		// Short length: 4 bytes
        0x00, 0x00, 0x01, 0x02,
        
        0x24,		// Short tag
        0x08,
        0x24,		// Short tag
        0x06,		// Short length: 4 bytes
        0x02,		// Short tag
        0x04,		// Short length: 4 bytes
        0x00, 0x00, 0x01, 0x03,
    // };

    // const uint8_t hex[] = {
        0x6F, 0x30, 0x84, 0x10, 0xA0, 0x00, 0x00, 0x00, 0x48, 0x57, 0x50, 0x41, 0x59, 0x06, 0x00, 0x00,
        0x01, 0x01, 0x01, 0x01, 0xA5, 0x1C, 0x5A, 0x08, 0x12, 0x34, 0x56, 0x00, 0x01, 0x00, 0x04, 0x04,
        0x50, 0x0A, 0x42, 0x45, 0x41, 0x4E, 0x20, 0x54, 0x45, 0x43, 0x48, 0x53, 0x9F, 0x0C, 0x03, 0x07,
        0x00, 0x00
    };

    mlib_tlv_delete(mlib_tlv_parse(hex,sizeof(hex)));

    mlib_tlv_t *tlv = mlib_tlv_parse(hex,sizeof(hex));
    if(NULL != tlv) {
        mlib_tlv_printf(tlv);
        int tag = 0x9F0C;
        const uint8_t *value = NULL;
        int len = mlib_tlv_get_value(tlv,tag,&value);
        if(len && value) {
            printf("get tag %X: \t",tag);
            for(int i=0;i<len;i++) {
                printf("%02X",value[i]);
            }
            printf("\r\n");
        }

        tag = 0x84;
        len = mlib_tlv_get_value(tlv,tag,&value);
        if(len && value) {
            printf("get tag %X: \t",tag);
            for(int i=0;i<len;i++) {
                printf("%02X",value[i]);
            }
            printf("\r\n");
        }

        tag = 0x1F8801;
        len = mlib_tlv_get_value(tlv,tag,&value);
        if(len && value) {
            printf("get tag %X: \t",tag);
            for(int i=0;i<len;i++) {
                printf("%02X",value[i]);
            }
            printf("\r\n");
        }
    }
    mlib_tlv_delete(tlv);
}

#if (PRINT_PBOC_TAG_NAME==1)
static const struct {
	int         value;
    const char  *string;
}pboc_tag[]= {
    {.value = 0x42,             .string = "行业识别码(IIN)"},
    {.value = 0x4F,             .string = "应用标识符(AID)"},
    {.value = 0x50,             .string = "应用标签"},
    {.value = 0x57,             .string = "磁条2等效数据"},
    {.value = 0x5A,             .string = "应用主账号(PAN)"},
    {.value = 0x5D,             .string = "目录定义文件(DDF)名称"},
    {.value = 0x5F20,           .string = "持卡人姓名"},
    {.value = 0x5F24,           .string = "应用失效日期"},
    {.value = 0x5F25,           .string = "应用生效日期"},
    {.value = 0x5F28,           .string = "发卡行国家代码"},
    {.value = 0x5F2A,           .string = "交易货币代码"},
    {.value = 0x5F2D,           .string = "首选语言"},
    {.value = 0x5F30,           .string = "服务码"},
    {.value = 0x5F34,           .string = "应用主帐号序列号"},
    {.value = 0x5F50,           .string = "发卡行URL"},
    {.value = 0x5F53,           .string = "国际银行账号(IBAN)"},
    {.value = 0x5F54,           .string = "银行标识符代码(BIC)"},
    {.value = 0x5F55,           .string = "发卡行国家代码(alpha2格式)"},
    {.value = 0x5F56,           .string = "发卡行国家代码(alpha3格式)"},
    {.value = 0x61,             .string = "应用模板"},
    {.value = 0x6F,             .string = "文件控制信息(FCI)模板"},
    {.value = 0x70,             .string = "响应报文数据"},
    {.value = 0x77,             .string = "响应报文模板格式2"},
    {.value = 0x71,             .string = "发卡行脚本模板1"},
    {.value = 0x72,             .string = "发卡行脚本模板2"},
    {.value = 0x73,             .string = "目录自定义模板"},
    {.value = 0x80,             .string = "响应报文模板格式"},
    {.value = 0x82,             .string = "应用交互特征(AIP)"},
    {.value = 0x84,             .string = "专用文件(DF)名称"},
    {.value = 0x86,             .string = "发卡行脚本命令"},
    {.value = 0x87,             .string = "应用优先级权指示符"},
    {.value = 0x88,             .string = "短文件标识符(SFI)"},
    {.value = 0x8A,             .string = "授权响应码"},
    {.value = 0x8C,             .string = "卡片风险管理数据对象列表1"},
    {.value = 0x8D,             .string = "卡片风险管理数据对象列表2"},
    {.value = 0x8E,             .string = "持卡人验证方法(CVM)列表"},
    {.value = 0x8F,             .string = "CA公钥索引(PKI)"},
    {.value = 0x90,             .string = "发卡行公钥证书"},
    {.value = 0x91,             .string = "发卡行认证数据"},
    {.value = 0x92,             .string = "发卡行公钥余数"},
    {.value = 0x93,             .string = "签名的静态应用数据(SAD)"},
    {.value = 0x94,             .string = "应用文件定位器(AFL)"},
    {.value = 0x95,             .string = "终端验证结果"},
    {.value = 0x97,             .string = "交易证书数据对象列表(TDOL)"},
    {.value = 0x9A,             .string = "交易日期"},
    {.value = 0x9C,             .string = "交易类型"},
    {.value = 0x9D,             .string = "目录数据文件(DDF)名称"},
    {.value = 0x9F02,           .string = "授权金额"},
    {.value = 0x9F03,           .string = "其它金额"},
    {.value = 0x9F05,           .string = "应用自定义数据"},
    {.value = 0x9F06,           .string = "应用标识符(AID)-终端"},
    {.value = 0x9F07,           .string = "应用用途控制(AUC)"},
    {.value = 0x9F08,           .string = "卡片应用版本号"},
    {.value = 0x9F09,           .string = "终端应用版本号"},
    {.value = 0x9F0B,           .string = "持卡人姓名扩展"},
    {.value = 0x9F0C,           .string = "发卡机构自定数据的FCI"},
    {.value = 0x9F0D,           .string = "发卡行行为代码(IAC)-缺省"},
    {.value = 0x9F0E,           .string = "发卡行行为代码(IAC)-拒绝"},
    {.value = 0x9F0F,           .string = "发卡行行为代码(IAC)-联机"},
    {.value = 0x9F10,           .string = "发卡行应用数据"},
    {.value = 0x9F11,           .string = "发卡行代码表索引"},
    {.value = 0x9F12,           .string = "应用首选名称"},
    {.value = 0x9F13,           .string = "上次联机应用交易计数器(ATC)寄存器"},
    {.value = 0x9F14,           .string = "连续脱机交易下限"},
    {.value = 0x9F17,           .string = "PIN尝试计数器"},
    {.value = 0x9F1A,           .string = "终端国家代码"},
    {.value = 0x9F1B,           .string = "终端最低限额"},
    {.value = 0x9F1F,           .string = "磁条1自定义数据"},
    {.value = 0x9F21,           .string = "交易时间"},
    {.value = 0x9F23,           .string = "连续脱机交易上限"},
    {.value = 0x9F26,           .string = "应用密文(AC)"},
    {.value = 0x9F27,           .string = "密文信息数据(CID)"},
    {.value = 0x9F32,           .string = "发卡行公钥指数"},
    {.value = 0x9F36,           .string = "应用交易计数器(ATC)"},
    {.value = 0x9F37,           .string = "不可预知数"},
    {.value = 0x9F38,           .string = "处理选项数据对象列表PDOL"},
    {.value = 0x9F42,           .string = "应用货币代码"},
    {.value = 0x9F44,           .string = "应用货币指数"},
    {.value = 0x9F45,           .string = "数据认证码"},
    {.value = 0x9F46,           .string = "IC卡公钥证书"},
    {.value = 0x9F47,           .string = "IC卡公钥指数"},
    {.value = 0x9F48,           .string = "IC卡公钥余数"},
    {.value = 0x9F49,           .string = "动态数据认证数据对象列表(DDOL)"},
    {.value = 0x9F4A,           .string = "静态数据认证标签列表"},
    {.value = 0x9F4B,           .string = "签名的动态应用数据"},
    {.value = 0x9F4C,           .string = "IC动态数"},
    {.value = 0x9F4D,           .string = "日志入口"},
    {.value = 0x9F4E,           .string = "商户名称"},
    {.value = 0x9F4F,           .string = "日志格式"},
    {.value = 0x9F50,           .string = "发卡行URL"},
    {.value = 0x9F51,           .string = "应用货币代码"},
    {.value = 0x9F52,           .string = "应用缺省行为(ADA)"},
    {.value = 0x9F53,           .string = "连续脱机交易限制数(国际-货币)"},
    {.value = 0x9F54,           .string = "累计脱机交易金额限制数"},
    {.value = 0x9F56,           .string = "发卡行认证指示位"},
    {.value = 0x9F57,           .string = "发卡行国家代码"},
    {.value = 0x9F58,           .string = "连续脱机交易下限"},
    {.value = 0x9F59,           .string = "连续脱机交易上限"},
    {.value = 0x9F5A,           .string = "发卡行URL2"},
    {.value = 0x9F5C,           .string = "累计脱机交易金额上限"},
    {.value = 0x9F5D,           .string = "可用脱机消费金额"},
    {.value = 0x9F61,           .string = "持卡人证件号"},
    {.value = 0x9F62,           .string = "持卡人证件类型"},
    {.value = 0x9F63,           .string = "卡产品标识信息"},
    {.value = 0x9F66,           .string = "终端交易属性"},
    {.value = 0x9F6C,           .string = "卡片交易属性"},
    {.value = 0x9F6D,           .string = "电子现金重置阈值(EC Reset Threshold)"},
    {.value = 0x9F72,           .string = "连续脱机交易限制数(国际-国家)"},
    {.value = 0x9F73,           .string = "货币转换因子"},
    {.value = 0x9F74,           .string = "电子现金发卡行授权码(EC Issuer Authorization Code)"},
    {.value = 0x9F75,           .string = "累计脱机交易金额限制数(双货币)"},
    {.value = 0x9F76,           .string = "第2应用货币代码"},
    {.value = 0x9F77,           .string = "电子现金余额上限(EC Balance Limit)"},
    {.value = 0x9F78,           .string = "电子现金单笔交易限额(EC Single Transaction Limit)"},
    {.value = 0x9F79,           .string = "电子现金余额(EC Balance)"},
    {.value = 0x9F7A,           .string = "电子现金终端支持指示器(EC Terminal Support Indicator)"},
    {.value = 0x9F7B,           .string = "电子现金终端交易限额(EC Terminal Transaction Limit)"},
    {.value = 0xA5,             .string = "文件控制信息(FCI)专有模板"},
    {.value = 0xBF0C,           .string = "发卡行自定义数据FCI"},
    {.value = 0xDF02,           .string = "认证中心公钥模"},
    {.value = 0xDF03,           .string = "认证中心公钥校验值"},
    {.value = 0xDF04,           .string = "认证中心公钥指数"},
    {.value = 0xDF05,           .string = "认证中心规定的有效期限"},
    {.value = 0xDF06,           .string = "认证中心公钥哈什算法标识"},
    {.value = 0xDF07,           .string = "认证中心公钥算法标识"},
    {.value = 0xDF4D,           .string = "电子现金圈存日志入口"},
    {.value = 0xDF4F,           .string = "电子现金圈存日志格式"},
    {.value = 0xDF60,           .string = "CAPP交易指示位"},
    {.value = 0xDF61,           .string = "分段扣费应用标识"},
    {.value = 0xDF62,           .string = "电子现金分段扣费抵扣限额"},
    {.value = 0xDF63,           .string = "电子现金分段扣费已抵扣额"},
    {.value = 0xDF69,           .string = "国际算法和国密算法通过此标签切换"},
};

static const char *pboc_tag_descrip(int tag) {
    for(int i=0;i<(sizeof(pboc_tag)/sizeof(pboc_tag[0]));i++) {
        if(tag == pboc_tag[i].value) {
            return pboc_tag[i].string;
        }
    }
    return "null";
}
#endif /*#if (PRINT_PBOC_TAG_NAME==1)*/
