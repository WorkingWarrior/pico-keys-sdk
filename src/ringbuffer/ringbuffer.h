#ifndef RINGBUFFER_H
#define RINGBUFFER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdatomic.h>

/**
 * @brief Ring buffer structure
 */
typedef struct {
    uint32_t *buffer;                    /**< Pointer to buffer memory */
    uint8_t size;                       /**< Size of buffer in elements */
    atomic_uint_least8_t read_index;    /**< Current read position */
    atomic_uint_least8_t write_index;   /**< Current write position */
    atomic_uint_least8_t count;         /**< Number of elements in buffer */
} ring_buffer_t;

/**
 * @brief Initialize ring buffer
 * @param rb Pointer to ring buffer structure
 * @param buffer Pointer to buffer memory
 * @param size Size of buffer in elements
 */
void ring_buffer_init(ring_buffer_t *rb, uint32_t *buffer, uint8_t size);

/**
 * @brief Put value into ring buffer
 * @param rb Pointer to ring buffer structure
 * @param value Value to store
 * @return true if successful, false if buffer is full
 */
bool ring_buffer_put(ring_buffer_t *rb, uint32_t value);

/**
 * @brief Get value from ring buffer
 * @param rb Pointer to ring buffer structure
 * @param value Pointer where to store retrieved value
 * @return true if successful, false if buffer is empty
 */
bool ring_buffer_get(ring_buffer_t *rb, uint32_t *value);

/**
 * @brief Check if ring buffer is empty
 * @param rb Pointer to ring buffer structure
 * @return true if empty, false otherwise
 */
bool ring_buffer_is_empty(const ring_buffer_t *rb);

/**
 * @brief Check if ring buffer is full
 * @param rb Pointer to ring buffer structure
 * @return true if full, false otherwise
 */
bool ring_buffer_is_full(const ring_buffer_t *rb);

/**
 * @brief Clear ring buffer
 * @param rb Pointer to ring buffer structure
 */
void ring_buffer_clear(ring_buffer_t *rb);

#endif /* RINGBUFFER_H */
