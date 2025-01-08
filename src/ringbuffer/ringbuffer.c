#include "ringbuffer.h"
#include <string.h>

/**
 * @brief Securely zero memory
 * @param ptr Pointer to memory
 * @param size Size of memory in bytes
 */
static void secure_zero(void *ptr, size_t size) {
    volatile uint8_t *p = ptr;
    while (size--) {
        *p++ = 0;
    }
}

void ring_buffer_init(ring_buffer_t *rb, uint32_t *buffer, uint8_t size)
{
    if (!rb || !buffer || size == 0) {
        return;
    }

    rb->buffer = buffer;
    rb->size = size;
    ring_buffer_clear(rb);
}

bool ring_buffer_put(ring_buffer_t *rb, uint32_t value)
{
    if (!rb || ring_buffer_is_full(rb)) {
        return false;
    }

    uint8_t current_write = atomic_load(&rb->write_index);
    rb->buffer[current_write] = value;
    
    atomic_store(&rb->write_index, (current_write + 1) % rb->size);
    atomic_fetch_add(&rb->count, 1);

    return true;
}

bool ring_buffer_get(ring_buffer_t *rb, uint32_t *value)
{
    if (!rb || !value || ring_buffer_is_empty(rb)) {
        return false;
    }

    uint8_t current_read = atomic_load(&rb->read_index);
    *value = rb->buffer[current_read];
    
    atomic_store(&rb->read_index, (current_read + 1) % rb->size);
    atomic_fetch_sub(&rb->count, 1);

    return true;
}

bool ring_buffer_is_empty(const ring_buffer_t *rb)
{
    return rb ? (atomic_load(&rb->count) == 0) : true;
}

bool ring_buffer_is_full(const ring_buffer_t *rb)
{
    return rb ? (atomic_load(&rb->count) >= rb->size) : true;
}

void ring_buffer_clear(ring_buffer_t *rb)
{
    if (!rb) {
        return;
    }

    atomic_store(&rb->read_index, 0);
    atomic_store(&rb->write_index, 0);
    atomic_store(&rb->count, 0);
    
    if (rb->buffer) {
        secure_zero(rb->buffer, rb->size * sizeof(uint32_t));
    }
}
