//
// Created by dagra on 04/12/2022.
//
#include "ERDTs.h"

void erdts_config(const parser_packet_ctx *ctx, int rx_buff_size, int tx_buff_size) {
    const uart_config_t uart_config_start = {
            .baud_rate = 9600,
            .data_bits = UART_DATA_8_BITS,
            .parity = UART_PARITY_DISABLE,
            .stop_bits = UART_STOP_BITS_1,
            .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
            .source_clk = UART_SCLK_DEFAULT,
    };

    uart_driver_install(UART_NUM_1, rx_buff_size, tx_buff_size, 0, NULL, 0);
    uart_param_config(UART_NUM_1, &uart_config_start);
    uart_set_pin(UART_NUM_1, ERDTS_TX_PIN, ERDTS_RX_PIN, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);

    packetQueue = xQueueCreate(ctx->queueSize, ctx->maxLen);
}

int max_cargo(const parser_packet_ctx *ctx) {
    return  ctx->maxLen - ctx->overhead;
}

int parse_packet(const parser_packet_ctx *ctx, const void* data, uint8_t* packet_buff, int len) {
    if(len < max_cargo(ctx)) {
        packet_buff = malloc(len+ctx->overhead);
        packet_buff[0] = ctx->delimiter;
        memcpy(packet_buff + ctx->lengthOffset, &len, ctx->lengthBytes);
        memcpy(packet_buff + ctx->overhead, data, len);
        return sizeof (packet_buff);
    }
    return PARSE_ERROR;
}

int extractLen(const parser_packet_ctx *ctx, uint8_t *packet) {
    int len;
    memcpy(&len, packet+ctx->lengthOffset, ctx->lengthBytes);
    return len;
}

_Noreturn static void erdts_tx_task(parser_packet_ctx *ctx) {
    static const char *TX_TASK_TAG = "TX_PACKET";
    esp_log_level_set(TX_TASK_TAG, ESP_LOG_INFO);
    uint8_t packet[ctx->maxLen];
    while (1) {
        if(packetQueue != NULL) {
            if(uxQueueMessagesWaiting(packetQueue)){
                xQueueReceive(packetQueue,packet,0);
                const int txBytes = uart_write_bytes(UART_NUM_1, packet, sizeof(packet));
                uart_wait_tx_done(UART_NUM_1, 0);
                ESP_LOGI(TX_TASK_TAG, "tx done");
            }
        }
    }
}

int erdts_send_bytes(const parser_packet_ctx *ctx, uint8_t *bytes, int byte_len) {
    uint8_t *packet = NULL;
    int result = parse_packet(ctx, bytes, packet, byte_len);
    xQueueSendToBack(packetQueue, packet, 0);
    free(packet);
    return result;
}

int erdts_send_string(const parser_packet_ctx *ctx, const char *string) {
    uint8_t *packet = NULL;
    int result = parse_packet(ctx, string, packet, strlen(string));
    xQueueSendToBack(packetQueue, packet, 0);
    free(packet);
    return result;
}

int erdts_send_int(const parser_packet_ctx *ctx, int *values, int num_vals) {
    uint8_t *packet = NULL;
    int result = parse_packet(ctx, values, packet, num_vals* sizeof(int));
    xQueueSendToBack(packetQueue, packet, 0);
    free(packet);
    return result;
}