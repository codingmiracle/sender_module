//
// Created by dagra on 04/12/2022.
//

#ifndef UART_ASYNC_RXTXTASKS_ERDTS_H
#define UART_ASYNC_RXTXTASKS_ERDTS_H
#include "stdio.h"
#include "string.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "driver/uart.h"
#include "driver/gpio.h"

#define PARSE_ERROR -1

#define ERDTS_TX_PIN GPIO_NUM_17
#define ERDTS_RX_PIN GPIO_NUM_16
#define ERDTS_SET_PIN GPIO_NUM_4
#define ERDTS_UART_NUM UART_NUM_1

typedef struct {
    uint8_t delimiter;
    int overhead;
    int lengthBytes;
    int lengthOffset;
    int maxLen;
    int queueSize;
} parser_packet_ctx;

void erdts_config(const parser_packet_ctx *, int, int);

int max_cargo(const parser_packet_ctx *);

int parse_packet(const parser_packet_ctx *, const void* , uint8_t*, int);

int extractLen(const parser_packet_ctx *, uint8_t*);

_Noreturn static void erdts_tx_task(parser_packet_ctx *);

int erdts_send_string(const parser_packet_ctx *, const char*);

int erdts_send_int(const parser_packet_ctx *, int*, int);

int erdts_send_bytes(const parser_packet_ctx *, uint8_t *, int);

QueueHandle_t packetQueue = NULL;

#endif //UART_ASYNC_RXTXTASKS_ERDTS_H