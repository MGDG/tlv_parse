#include <stdio.h>
#include "mlibTLVParse.h"

typedef enum {
    PRIMITIVE_FRAME,                    /*基本结构体*/
    PRIVATE_FRAME,                      /*私有结构体*/
}tlv_tag_frame_type_t;

typedef enum {
    PRIMITIVE_DATA = 0,                 /*原始类型、基本类型*/
    CONSTRUCTED_DATA,                   /*复合类型，value里嵌套着其他的TLV数据*/
}tlv_tag_data_type_t;

static int _mlib_tlv_get_tag(const uint8_t *data, int dataLen, int *tag, tlv_tag_data_type_t *dataType) {
    int tagLen = 0;
    *tag = data[0];
    *dataType = (data[0] & 0x20) ? CONSTRUCTED_DATA : PRIMITIVE_DATA;
    if((data[0] & 0x1F) < 0x1F) {
        tagLen = 1;
    }else {
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
    int lenLen;
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
        lenLen = 1;
    }
    return lenLen;
}

void _mlib_tlv_parse(mlib_tlv_t **item,const uint8_t *data, int dataLen, int loopFlg) {
    int tag,tagLen,len,lenLen;
    tlv_tag_data_type_t tagType;
    while(dataLen >= 3) {
        /*get tag*/
        tagLen = _mlib_tlv_get_tag(data,dataLen,&tag,&tagType);
        if(tagLen <= 0) {
            return;
        }
        data += tagLen;
        dataLen -= tagLen;

        /*get len*/
        lenLen = _mlib_tlv_get_len(data,dataLen,&len);
        if(lenLen <= 0) {
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
        printf("%X\t",tlv->tag);
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
        int valueLen = mlib_tlv_get_value(tlv->sub,tag,value);
        if(valueLen > 0) {
            return valueLen;
        }
        if(tag == tlv->tag) {
            *value = tlv->value;
            return tlv->len;
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
