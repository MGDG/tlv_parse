#ifndef _MLIB_TLV_PARSE_H_
#define _MLIB_TLV_PARSE_H_

#include <stdlib.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*TLV对象*/
typedef struct mlib_tlv {
    struct mlib_tlv *next;
    struct mlib_tlv *sub;

    int tag;                            /*未解码的tag值*/
    int len;                            /*value的长度*/
    const uint8_t *value;               /*value,不开辟空间，直接指向源数据内存空间*/
}mlib_tlv_t;


/**
 * @brief 解析一段TLV格式的数据，返回解析后的对象，解析失败则返回NULL
 * 
 * @param data TLV格式的数据
 * @param dataLen 数据长度
 * @return mlib_tlv_t tlv对象指针
 */
mlib_tlv_t *mlib_tlv_parse(const uint8_t *data, int dataLen);


/**
 * @brief 删除TLV对象
 * 
 * @param tlv tlv对象指针
 */
void mlib_tlv_delete(mlib_tlv_t *tlv);


/**
 * @brief 打印tlv
 * 
 * @param tlv tlv对象指针
 */
void mlib_tlv_printf(const mlib_tlv_t *tlv);


/**
 * @brief 从TLV对象中获取对应TAG的值,存在多个相同TAG的话只返回第一个找到的
 * 
 * @param tlv tlv对象指针
 * @param tag 标签值
 * @param value 输出参数，返回对应的value指针，不需要释放
 * @return int 获取到的value数据长度
 *              <=0 :获取失败，找不到对应的tag
 *              其他: 获取成功，返回对应value的长度
 */
int mlib_tlv_get_value(const mlib_tlv_t *tlv,int tag, const uint8_t **value);


/**
 * @brief tlv测试
 * 
 */
void mlib_tlv_test(void);

#ifdef __cplusplus
}
#endif


#endif
