## tlv_parse


*tlv格式的数据解析，用于处理nfc中读取到的数据。*



#### 示例
```c
    /*示例数据*/
    const uint8_t hex[] = {
        0x6F, 0x30, 0x84, 0x10, 0xA0, 0x00, 0x00, 0x00, 0x48, 0x57, 0x50, 0x41, 0x59, 0x06, 0x00, 0x00,
        0x01, 0x01, 0x01, 0x01, 0xA5, 0x1C, 0x5A, 0x08, 0x12, 0x34, 0x56, 0x00, 0x01, 0x00, 0x04, 0x04,
        0x50, 0x0A, 0x42, 0x45, 0x41, 0x4E, 0x20, 0x54, 0x45, 0x43, 0x48, 0x53, 0x9F, 0x0C, 0x03, 0x07,
        0x00, 0x00
    };

    /*解析数据，获取tlv对象*/
    mlib_tlv_t *tlv = mlib_tlv_parse(hex,sizeof(hex));
    if(NULL != tlv) {
        /*打印tlv对象方便查看*/
        mlib_tlv_printf(tlv);

        /*获取tag为 0x9F0C 的数据并打印出来*/
        int tag = 0x9F0C;
        const uint8_t *value = NULL;
        int len = mlib_tlv_get_value(tlv,tag,&value);
        if(len && value) {
            printf("get tag %X: \t",tag);
            for(int i=0;i<len;i++) {
                printf("%02X",value[i]);
            }
            printf("\n");
        }else{
            printf("tag %X not found\n",tag);
        }

        /*获取tag为 0x84 的数据*/
        tag = 0x84;
        len = mlib_tlv_get_value(tlv,tag,&value);
        if(len && value) {
            printf("get tag %X: \t",tag);
            for(int i=0;i<len;i++) {
                printf("%02X",value[i]);
            }
            printf("\r\n");
        }else{
            printf("tag %X not found\n",tag);
        }
    }

    /*删除tlv对象*/
    mlib_tlv_delete(tlv);

```

