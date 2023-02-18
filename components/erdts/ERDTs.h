//
// Created by dagra on 04/12/2022.
//

#ifndef SENDER_MODULE_ERDTS_H
#define SENDER_MODULE_ERDTS_H

#include "stdio.h"
#include "string.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "driver/uart.h"
#include "driver/gpio.h"
#include "aes/esp_aes.h"


#define ERDTS_TX_PIN GPIO_NUM_17
#define ERDTS_RX_PIN GPIO_NUM_16
#define ERDTS_SET_PIN GPIO_NUM_4
#define ERDTS_UART_NUM UART_NUM_1

#define erdts_key_length 256
#define erdts_iv_length 16

typedef struct {
    uint8_t delimiter;
    int overhead;
    int lengthBytes;
    int lengthOffset;
    int maxLen;
    int queueSize;
} parser_packet_ctx;

void erdts_init(const parser_packet_ctx *ctx, int rx_buff_size, int tx_buff_size);

void erdts_start_session(const parser_packet_ctx *, esp_aes_context *, uint8_t *, uint8_t *, uint8_t *, int);

int max_cargo(const parser_packet_ctx *);

uint8_t *parse_packet(const parser_packet_ctx *, const void *, int);

int erdts_getPacketLen(const parser_packet_ctx *, uint8_t *);

int erdts_getCargoLen(const parser_packet_ctx *, uint8_t *);

_Noreturn static void erdts_tx_task(void *);

int erdts_send(const parser_packet_ctx *, uint8_t *, int);

_Noreturn void erdts_encrypt_task(void *);

void erdts_setkey(esp_aes_context *, uint8_t *);

void getRandomString(char *, int);

void generate_key(uint8_t *, unsigned int, uint8_t *);

int sendData(const parser_packet_ctx *, const void *, unsigned int);

#endif //SENDER_MODULE_ERDTS_H
