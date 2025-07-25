/*
 * VFM JIT Code Cache Implementation
 * Cross-platform JIT compilation cache for VelocityFilterMachine
 * 
 * Provides hash-based caching of compiled JIT code with LRU eviction,
 * memory pool management, and cross-platform optimizations.
 */

#include "../include/vfm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/mman.h>
#include <unistd.h>
#include <assert.h>

#ifdef VFM_PLATFORM_MACOS
    #include <mach/mach_time.h>
    // pthread_jit_write_protect_np is declared in pthread.h
#endif

// Global JIT cache instance
typedef struct vfm_jit_cache {
    vfm_jit_cache_entry_t **buckets;   // Hash table buckets
    uint32_t bucket_count;             // Number of hash buckets (power of 2)
    uint32_t bucket_mask;              // bucket_count - 1 for fast modulo
    
    // Memory pool management
    void **memory_pools;               // Pre-allocated JIT memory pools
    size_t *pool_sizes;                // Size of each memory pool
    uint32_t pool_count;               // Number of memory pools
    uint32_t current_pool;             // Current allocation pool
    
    // Statistics and management
    uint64_t total_entries;            // Current cache entries
    uint64_t max_entries;              // Maximum cache size
    uint64_t total_memory;             // Total JIT memory allocated
    uint64_t max_memory;               // Memory limit
    vfm_jit_cache_stats_t stats;       // Performance statistics
    
    // Configuration
    vfm_jit_cache_config_t config;     // Cache configuration
    
    // Thread safety
    pthread_mutex_t cache_mutex;       // Protects cache operations
    bool initialized;                  // Initialization flag
} vfm_jit_cache_t;

static vfm_jit_cache_t g_jit_cache = {0};

// Forward declarations
static uint32_t hash_program_fast(const uint8_t *data, uint32_t len);
static void free_jit_memory(void *ptr, size_t size);
static void cache_entry_destroy(vfm_jit_cache_entry_t *entry);
static uint64_t get_timestamp_ns(void);

// Fast hash function for program data
static uint32_t hash_program_fast(const uint8_t *data, uint32_t len) {
    // FNV-1a hash - simple but effective
    uint32_t hash = 2166136261U;
    for (uint32_t i = 0; i < len; i++) {
        hash ^= data[i];
        hash *= 16777619U;
    }
    return hash;
}


static void free_jit_memory(void *ptr, size_t size) {
    if (ptr) {
        munmap(ptr, size);
    }
}

static uint64_t get_timestamp_ns(void) {
#ifdef VFM_PLATFORM_MACOS
    return mach_absolute_time();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
#endif
}

// Program hash computation with collision resistance
vfm_program_hash_t vfm_compute_program_hash(const uint8_t *program, uint32_t len) {
    vfm_program_hash_t hash = {0};
    
    if (!program || len == 0) {
        return hash;
    }
    
    // Compute primary hash
    uint32_t primary = hash_program_fast(program, len);
    hash.hash_high = primary;
    
    // Compute secondary hash with different seed for better distribution
    uint32_t secondary = 2166136261U;
    for (uint32_t i = 0; i < len; i += 4) {
        uint32_t chunk = 0;
        uint32_t remaining = (len - i < 4) ? (len - i) : 4;
        memcpy(&chunk, program + i, remaining);
        secondary ^= chunk;
        secondary *= 16777619U;
    }
    hash.hash_low = secondary;
    
    // Store length and simple checksum for collision detection
    hash.length = len;
    hash.checksum = 0;
    for (uint32_t i = 0; i < len; i++) {
        hash.checksum ^= program[i];
    }
    
    return hash;
}

bool vfm_program_hash_equal(const vfm_program_hash_t *a, const vfm_program_hash_t *b) {
    return a && b &&
           a->hash_high == b->hash_high &&
           a->hash_low == b->hash_low &&
           a->length == b->length &&
           a->checksum == b->checksum;
}

// Initialize JIT cache with configuration
int vfm_jit_cache_init(const vfm_jit_cache_config_t *config) {
    if (g_jit_cache.initialized) {
        return VFM_SUCCESS; // Already initialized
    }
    
    // Use default config if none provided
    vfm_jit_cache_config_t default_config = {
        .max_entries = VFM_JIT_CACHE_MAX_ENTRIES,
        .max_memory_mb = VFM_JIT_CACHE_MAX_MEMORY_MB,
        .bucket_count = VFM_JIT_CACHE_BUCKET_COUNT,
        .enable_stats = true,
        .enable_prefetch = true,
        .eviction_batch_size = 16
    };
    
    const vfm_jit_cache_config_t *cfg = config ? config : &default_config;
    
    // Validate configuration
    if (cfg->bucket_count == 0 || (cfg->bucket_count & (cfg->bucket_count - 1)) != 0) {
        return VFM_ERROR_INVALID_PROGRAM; // Must be power of 2
    }
    
    // Initialize mutex
    if (pthread_mutex_init(&g_jit_cache.cache_mutex, NULL) != 0) {
        return VFM_ERROR_NO_MEMORY;
    }
    
    // Allocate hash table buckets
    g_jit_cache.bucket_count = cfg->bucket_count;
    g_jit_cache.bucket_mask = cfg->bucket_count - 1;
    g_jit_cache.buckets = calloc(cfg->bucket_count, sizeof(vfm_jit_cache_entry_t*));
    if (!g_jit_cache.buckets) {
        pthread_mutex_destroy(&g_jit_cache.cache_mutex);
        return VFM_ERROR_NO_MEMORY;
    }
    
    // Initialize configuration and limits
    g_jit_cache.config = *cfg;
    g_jit_cache.max_entries = cfg->max_entries;
    g_jit_cache.max_memory = cfg->max_memory_mb * 1024 * 1024;
    
    // Initialize statistics
    memset(&g_jit_cache.stats, 0, sizeof(g_jit_cache.stats));
    
    g_jit_cache.initialized = true;
    return VFM_SUCCESS;
}

void vfm_jit_cache_destroy(void) {
    if (!g_jit_cache.initialized) {
        return;
    }
    
    pthread_mutex_lock(&g_jit_cache.cache_mutex);
    
    // Free all cache entries
    for (uint32_t i = 0; i < g_jit_cache.bucket_count; i++) {
        vfm_jit_cache_entry_t *entry = g_jit_cache.buckets[i];
        while (entry) {
            vfm_jit_cache_entry_t *next = entry->next;
            cache_entry_destroy(entry);
            entry = next;
        }
    }
    
    // Free hash table
    free(g_jit_cache.buckets);
    g_jit_cache.buckets = NULL;
    
    // Free memory pools if allocated
    if (g_jit_cache.memory_pools) {
        for (uint32_t i = 0; i < g_jit_cache.pool_count; i++) {
            if (g_jit_cache.memory_pools[i]) {
                free_jit_memory(g_jit_cache.memory_pools[i], g_jit_cache.pool_sizes[i]);
            }
        }
        free(g_jit_cache.memory_pools);
        free(g_jit_cache.pool_sizes);
    }
    
    g_jit_cache.initialized = false;
    
    pthread_mutex_unlock(&g_jit_cache.cache_mutex);
    pthread_mutex_destroy(&g_jit_cache.cache_mutex);
    
    // Clear the structure
    memset(&g_jit_cache, 0, sizeof(g_jit_cache));
}

// Cache lookup operation
vfm_jit_cache_entry_t* vfm_jit_cache_lookup(const vfm_program_hash_t *hash) {
    if (!g_jit_cache.initialized || !hash) {
        return NULL;
    }
    
    uint32_t bucket = hash->hash_high & g_jit_cache.bucket_mask;
    
    pthread_mutex_lock(&g_jit_cache.cache_mutex);
    
    vfm_jit_cache_entry_t *entry = g_jit_cache.buckets[bucket];
    while (entry) {
        if (vfm_program_hash_equal(&entry->program_hash, hash)) {
            // Cache hit - update statistics and LRU
            entry->hit_count++;
            entry->last_used = get_timestamp_ns();
            entry->ref_count++;
            
            if (g_jit_cache.config.enable_stats) {
                g_jit_cache.stats.cache_hits++;
                g_jit_cache.stats.cache_hit_ratio = 
                    (double)g_jit_cache.stats.cache_hits / 
                    (g_jit_cache.stats.cache_hits + g_jit_cache.stats.cache_misses) * 100.0;
            }
            
            // Prefetch JIT code if enabled
            if (g_jit_cache.config.enable_prefetch && entry->jit_code) {
                VFM_PREFETCH(entry->jit_code, 0, 3);
            }
            
            pthread_mutex_unlock(&g_jit_cache.cache_mutex);
            return entry;
        }
        entry = entry->next;
    }
    
    // Cache miss
    if (g_jit_cache.config.enable_stats) {
        g_jit_cache.stats.cache_misses++;
        g_jit_cache.stats.cache_hit_ratio = 
            (double)g_jit_cache.stats.cache_hits / 
            (g_jit_cache.stats.cache_hits + g_jit_cache.stats.cache_misses) * 100.0;
    }
    
    pthread_mutex_unlock(&g_jit_cache.cache_mutex);
    return NULL;
}

// Store compiled JIT code in cache
vfm_jit_cache_entry_t* vfm_jit_cache_store(const vfm_program_hash_t *hash, 
                                           void *jit_code, size_t code_size) {
    if (!g_jit_cache.initialized || !hash || !jit_code || code_size == 0) {
        return NULL;
    }
    
    pthread_mutex_lock(&g_jit_cache.cache_mutex);
    
    // Check if we need to evict entries
    if (g_jit_cache.total_entries >= g_jit_cache.max_entries ||
        g_jit_cache.total_memory + code_size > g_jit_cache.max_memory) {
        vfm_jit_cache_evict_lru(code_size);
    }
    
    // Allocate new cache entry
    vfm_jit_cache_entry_t *entry = aligned_alloc(VFM_CACHE_LINE_SIZE, sizeof(vfm_jit_cache_entry_t));
    if (!entry) {
        pthread_mutex_unlock(&g_jit_cache.cache_mutex);
        return NULL;
    }
    
    // Initialize entry
    entry->program_hash = *hash;
    entry->jit_code = jit_code;
    entry->jit_code_size = code_size;
    entry->ref_count = 1;
    entry->last_used = get_timestamp_ns();
    entry->hit_count = 0;
    entry->compile_time_ns = 0; // Will be set by caller
    
    // Insert into hash table
    uint32_t bucket = hash->hash_high & g_jit_cache.bucket_mask;
    entry->next = g_jit_cache.buckets[bucket];
    g_jit_cache.buckets[bucket] = entry;
    
    // Update statistics
    g_jit_cache.total_entries++;
    g_jit_cache.total_memory += code_size;
    
    if (g_jit_cache.config.enable_stats) {
        g_jit_cache.stats.total_compilations++;
        g_jit_cache.stats.memory_used = g_jit_cache.total_memory;
        if (g_jit_cache.total_memory > g_jit_cache.stats.memory_peak) {
            g_jit_cache.stats.memory_peak = g_jit_cache.total_memory;
        }
        g_jit_cache.stats.active_entries = g_jit_cache.total_entries;
    }
    
    pthread_mutex_unlock(&g_jit_cache.cache_mutex);
    return entry;
}

// Release reference to cache entry
void vfm_jit_cache_release(vfm_jit_cache_entry_t *entry) {
    if (!g_jit_cache.initialized || !entry) {
        return;
    }
    
    pthread_mutex_lock(&g_jit_cache.cache_mutex);
    
    if (entry->ref_count > 0) {
        entry->ref_count--;
    }
    
    pthread_mutex_unlock(&g_jit_cache.cache_mutex);
}

// LRU eviction implementation
void vfm_jit_cache_evict_lru(size_t bytes_needed) {
    if (!g_jit_cache.initialized) {
        return;
    }
    
    // Find LRU entries across all buckets
    vfm_jit_cache_entry_t *lru_entries[32]; // Batch eviction
    uint32_t lru_count = 0;
    uint64_t oldest_time = UINT64_MAX;
    
    // Find oldest entries that aren't referenced
    for (uint32_t bucket = 0; bucket < g_jit_cache.bucket_count && lru_count < 32; bucket++) {
        vfm_jit_cache_entry_t *entry = g_jit_cache.buckets[bucket];
        while (entry && lru_count < 32) {
            if (entry->ref_count == 0 && entry->last_used < oldest_time) {
                lru_entries[lru_count++] = entry;
                oldest_time = entry->last_used;
            }
            entry = entry->next;
        }
    }
    
    // Evict oldest entries
    for (uint32_t i = 0; i < lru_count; i++) {
        vfm_jit_cache_entry_t *victim = lru_entries[i];
        
        // Remove from hash table
        uint32_t bucket = victim->program_hash.hash_high & g_jit_cache.bucket_mask;
        vfm_jit_cache_entry_t **current = &g_jit_cache.buckets[bucket];
        
        while (*current) {
            if (*current == victim) {
                *current = victim->next;
                break;
            }
            current = &(*current)->next;
        }
        
        // Update statistics
        g_jit_cache.total_entries--;
        g_jit_cache.total_memory -= victim->jit_code_size;
        
        if (g_jit_cache.config.enable_stats) {
            g_jit_cache.stats.evictions++;
            g_jit_cache.stats.memory_used = g_jit_cache.total_memory;
            g_jit_cache.stats.active_entries = g_jit_cache.total_entries;
        }
        
        // Free the entry
        cache_entry_destroy(victim);
        
        // Check if we've freed enough space
        if (g_jit_cache.total_memory + bytes_needed <= g_jit_cache.max_memory) {
            break;
        }
    }
}

void vfm_jit_cache_update_lru(vfm_jit_cache_entry_t *entry) {
    if (entry) {
        entry->last_used = get_timestamp_ns();
    }
}

static void cache_entry_destroy(vfm_jit_cache_entry_t *entry) {
    if (entry) {
        if (entry->jit_code) {
            free_jit_memory(entry->jit_code, entry->jit_code_size);
        }
        free(entry);
    }
}

// Statistics and monitoring functions
void vfm_jit_cache_get_stats(vfm_jit_cache_stats_t *stats) {
    if (!g_jit_cache.initialized || !stats) {
        return;
    }
    
    pthread_mutex_lock(&g_jit_cache.cache_mutex);
    *stats = g_jit_cache.stats;
    pthread_mutex_unlock(&g_jit_cache.cache_mutex);
}

void vfm_jit_cache_reset_stats(void) {
    if (!g_jit_cache.initialized) {
        return;
    }
    
    pthread_mutex_lock(&g_jit_cache.cache_mutex);
    memset(&g_jit_cache.stats, 0, sizeof(g_jit_cache.stats));
    pthread_mutex_unlock(&g_jit_cache.cache_mutex);
}

void vfm_jit_cache_print_stats(void) {
    if (!g_jit_cache.initialized) {
        printf("JIT Cache not initialized\n");
        return;
    }
    
    vfm_jit_cache_stats_t stats;
    vfm_jit_cache_get_stats(&stats);
    
    printf("VFM JIT Cache Statistics:\n");
    printf("  Cache Hits: %llu\n", stats.cache_hits);
    printf("  Cache Misses: %llu\n", stats.cache_misses);
    printf("  Hit Ratio: %.2f%%\n", stats.cache_hit_ratio);
    printf("  Total Compilations: %llu\n", stats.total_compilations);
    printf("  Active Entries: %u\n", stats.active_entries);
    printf("  Memory Used: %llu KB\n", stats.memory_used / 1024);
    printf("  Memory Peak: %llu KB\n", stats.memory_peak / 1024);
    printf("  Evictions: %llu\n", stats.evictions);
    printf("  Avg Compile Time: %.2f ms\n", stats.avg_compile_time_ms);
}

int vfm_jit_cache_configure(const vfm_jit_cache_config_t *config) {
    if (!config) {
        return VFM_ERROR_INVALID_PROGRAM;
    }
    
    // If cache is already initialized, destroy and reinitialize
    if (g_jit_cache.initialized) {
        vfm_jit_cache_destroy();
    }
    
    return vfm_jit_cache_init(config);
}