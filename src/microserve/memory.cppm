// SPDX-FileCopyrightText: 2025-2026 Igal Alkon
// SPDX-FileCopyrightText: 2026 ALKONTEK <git@alkontek.com>
// SPDX-License-Identifier: BSD-3-Clause

/**
 * @file
 * Pinned byte-span cache over a first-fit arena.
 */

module;

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#else
#  include <sys/mman.h>
#  include <unistd.h>
#  ifndef MAP_ANONYMOUS
#    define MAP_ANONYMOUS MAP_ANON
#  endif
#endif

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <span>
#include <stdexcept>
#include <utility>

export module microserve.memory;

/**
 * @brief In-process byte cache with pinned allocations.
 */
export namespace microserve::cache {

/**
 * @brief Which pool implementation Cache constructs.
 */
enum class StrategyKind {
    Simple,  ///< First-fit arena; evicts unpinned spans to place a blob.
};

/**
 * @brief Sizing for a cache pool.
 */
struct PoolConfig {
    std::size_t capacity_bytes = 128ull * 1024ull * 1024ull;  ///< Requested usable bytes. Rounded up to 16.
};

class SimpleStrategy;

/**
 * @brief Pin on one cached blob.
 *
 * Copies share the pin; moves transfer it. The bytes stay allocated until
 * every Allocation is gone and the strategy later evicts the slot. A pin
 * keeps the arena alive, so it may outlive the Cache that created it.
 * Eviction will not reuse the slot while any Allocation exists.
 */
class Allocation {
public:
    /**
     * @brief Empty pin. Holds no slot.
     */
    Allocation() = default;

    /**
     * @brief Drop this pin. The slot can be evicted only after the last one.
     */
    ~Allocation();

    /**
     * @brief Share @p other's pin. Both keep the slot live.
     * @param other Source pin. Unchanged.
     */
    Allocation(const Allocation& other);

    /**
     * @brief Drop this pin and share @p other's.
     * @param other Source pin. Unchanged.
     * @return *this.
     */
    Allocation& operator=(const Allocation& other);

    /**
     * @brief Take @p other's pin. @p other becomes empty.
     * @param other Source pin. Left empty.
     */
    Allocation(Allocation&& other) noexcept;

    /**
     * @brief Drop this pin and take @p other's. @p other becomes empty.
     * @param other Source pin. Left empty.
     * @return *this.
     */
    Allocation& operator=(Allocation&& other) noexcept;

    /**
     * @brief Pointer to the cached bytes.
     *
     * May be read without the pool lock while this pin is held. An empty pin
     * returns nullptr. A zero-length blob still has a non-null pointer.
     * @return Payload address, or nullptr if this pin holds no slot.
     */
    [[nodiscard]] std::byte* data() const noexcept;

    /**
     * @brief Payload length in bytes.
     *
     * This is the copied count, not the aligned slot size. A zero-length blob
     * and an empty pin both report 0; use operator bool to tell them apart.
     * @return Byte count.
     */
    [[nodiscard]] std::size_t size() const noexcept;

    /**
     * @brief True when this pin holds a slot, including a zero-length blob.
     * @return False if default, moved-from, or a failed insert.
     */
    [[nodiscard]] explicit operator bool() const noexcept;

    /**
     * @brief Mark the slot most recently used. No-op if this pin is empty.
     */
    void touch() const noexcept;

private:
    friend class SimpleStrategy;

    using EntryFn = void (*)(void* strategy, void* entry) noexcept;  ///< Pin, unpin, or touch callback.

    std::shared_ptr<void> owner_;  ///< Keeps the strategy alive. Null for a direct insert.
    void* strategy_ = nullptr;     ///< Strategy that owns entry_. Null if empty.
    void* entry_ = nullptr;        ///< Pinned slot. Null if empty.
    EntryFn pin_ = nullptr;        ///< Increments the slot pin count.
    EntryFn unpin_ = nullptr;      ///< Decrements the slot pin count.
    EntryFn touch_ = nullptr;      ///< Moves the slot to the newest end.
    std::byte* data_ = nullptr;    ///< Payload start. Null if empty.
    std::size_t size_ = 0;         ///< Payload length, not the aligned reservation.

    /**
     * @brief Drop the pin and clear this object. Safe when already empty.
     */
    void release() noexcept;
};

/**
 * @brief First-fit arena with coalescing of free ranges.
 *
 * Live ranges are never relocated. The mutex covers insert, pin, unpin, and
 * touch; a pinned pointer may be read without the lock.
 *
 * If a blob does not fit, the strategy frees the contiguous run of free
 * ranges and unpinned entries that destroys the fewest entries. A recency
 * list is updated by insert and touch, but it does not select victims. A
 * failed insert does not discard cached entries.
 */
class SimpleStrategy {
public:
    /**
     * @brief Map an arena of at least @p config.capacity_bytes.
     * @param config Pool size. Zero is rejected.
     */
    explicit SimpleStrategy(PoolConfig config = {});

    /**
     * @brief Destroy every entry and unmap the arena.
     *
     * Pins from insert() do not keep this object alive. Pins from Cache do.
     */
    ~SimpleStrategy();

    SimpleStrategy(const SimpleStrategy&) = delete;
    SimpleStrategy& operator=(const SimpleStrategy&) = delete;

    /**
     * @brief Copy @p bytes into the pool and return a pin.
     *
     * Evicts unpinned entries only to form one contiguous span large enough
     * for the blob. Returns empty if the blob exceeds the cap or no such span
     * exists. Failure does not discard cached entries. An empty blob still
     * reserves one aligned slot. This call does not keep the strategy alive.
     * @param bytes Payload to copy. May be empty.
     * @return Pin on the new slot, or an empty Allocation.
     */
    [[nodiscard]] Allocation insert(std::span<const std::byte> bytes);

    /**
     * @brief Insert @p bytes and keep @p owner alive for the pin's lifetime.
     * @param owner Shared owner, usually the Cache implementation.
     * @param bytes Payload to copy. May be empty.
     * @return Pin bound to @p owner, or empty on failure.
     */
    [[nodiscard]] Allocation insert_shared(const std::shared_ptr<void>& owner,
                                           std::span<const std::byte> bytes);

    /**
     * @brief Usable capacity after alignment.
     * @return Allocatable bytes. Does not include page-rounding slack.
     */
    [[nodiscard]] std::size_t capacity() const noexcept;

    /**
     * @brief Bytes reserved by live entries, including alignment padding.
     * @return Occupied bytes.
     */
    [[nodiscard]] std::size_t used() const noexcept;

    /**
     * @brief Entries destroyed to make room since construction.
     * @return Eviction count.
     */
    [[nodiscard]] std::size_t evictions() const noexcept;

    /**
     * @brief Live entries, pinned and unpinned.
     * @return Entry count.
     */
    [[nodiscard]] std::size_t resident() const noexcept;

private:
    /**
     * @brief One reserved span in the arena.
     */
    struct Entry {
        std::size_t offset = 0;   ///< Start of the aligned reservation.
        std::size_t size = 0;     ///< Aligned bytes reserved, including padding.
        std::size_t payload = 0;  ///< Caller-visible byte count.
        std::uint32_t pins = 0;   ///< Outstanding pins. Non-zero blocks eviction.
        Entry* newer = nullptr;   ///< More recently used neighbor. Null at the newest end.
        Entry* older = nullptr;   ///< Less recently used neighbor. Null at the oldest end.
    };

    static constexpr std::size_t align_ = 16;                          ///< Reservation alignment.
    static constexpr std::size_t npos_ = static_cast<std::size_t>(-1);  ///< Missing-offset sentinel.

    std::byte* base_ = nullptr;  ///< Mapped arena. Null after destruction.
    std::size_t mapped_ = 0;     ///< Bytes requested from the OS, rounded up to a page.
    std::size_t capacity_ = 0;   ///< Allocatable prefix of the mapping.
    std::size_t used_ = 0;       ///< Sum of live Entry::size values.
    std::size_t evictions_ = 0;  ///< Entries destroyed by make_room().
    std::size_t resident_ = 0;   ///< Live entry count.
    Entry* oldest_ = nullptr;    ///< Least recently used live entry.
    Entry* newest_ = nullptr;    ///< Most recently used live entry.
    std::map<std::size_t, std::size_t> free_;  ///< Free ranges as offset to length. Coalesced.
    mutable std::mutex mu_;                    ///< Guards the free map, recency list, and counters.

    /**
     * @brief Round @p n up to a multiple of align_.
     * @param n Byte count. Zero stays zero.
     * @return Aligned size.
     */
    [[nodiscard]] static std::size_t align_up(std::size_t n) noexcept;

    /**
     * @brief Host page size used to round the mapping.
     * @return Page size in bytes, or 4096 if the query fails.
     */
    [[nodiscard]] static std::size_t page_size() noexcept;

    /**
     * @brief Address-order first free range of at least @p need bytes.
     * @param need Aligned byte count.
     * @return Range offset, or npos_.
     */
    [[nodiscard]] std::size_t find_fit(std::size_t need) const;

    /**
     * @brief Carve @p need bytes from the free range at @p offset.
     * @param offset Start of a free range that is at least @p need.
     * @param need Aligned byte count.
     * @return @p offset.
     */
    std::size_t take_fit(std::size_t offset, std::size_t need);

    /**
     * @brief Return a span to the free map, merging adjacent ranges.
     * @param offset Start of the released reservation.
     * @param size Aligned length.
     */
    void release_range(std::size_t offset, std::size_t size);

    /**
     * @brief Link @p entry as most recently used.
     * @param entry Unlinked entry.
     */
    void lru_push(Entry* entry) noexcept;

    /**
     * @brief Unlink @p entry from the recency list. Does not free it.
     * @param entry Linked entry.
     */
    void lru_unlink(Entry* entry) noexcept;

    /**
     * @brief Unlink @p entry, return its range, and delete it.
     *
     * Does not bump the eviction counter. The caller does that.
     * @param entry Live entry. Must not be pinned.
     */
    void destroy_entry(Entry* entry);

    /**
     * @brief Ensure a free span of @p need bytes, evicting if required.
     *
     * Picks the reclaimable run that destroys the fewest entries. A pinned
     * entry breaks a run. Nothing is freed until a run is chosen.
     * @param need Aligned byte count.
     * @return True if a fit exists afterwards.
     */
    [[nodiscard]] bool make_room(std::size_t need);

    /**
     * @brief Pin callback. Saturates at the maximum pin count.
     * @param strategy SimpleStrategy instance.
     * @param entry Entry to pin.
     */
    static void pin(void* strategy, void* entry) noexcept;

    /**
     * @brief Unpin callback. Ignores a zero count.
     * @param strategy SimpleStrategy instance.
     * @param entry Entry to unpin.
     */
    static void unpin(void* strategy, void* entry) noexcept;

    /**
     * @brief Touch callback. No-op when the entry has no pins.
     * @param strategy SimpleStrategy instance.
     * @param entry Entry to mark newest.
     */
    static void touch(void* strategy, void* entry) noexcept;

    /**
     * @brief Bind a pin to an entry that is already pinned.
     *
     * Does not increment the pin count. @p owner may be null; then the pin
     * does not keep this strategy alive.
     * @param owner Shared strategy owner, or null.
     * @param entry Freshly inserted entry.
     * @param payload Caller-visible size.
     * @return Pin on @p entry.
     */
    Allocation adopt(std::shared_ptr<void> owner, Entry* entry, std::size_t payload);
};

/**
 * @brief Type-erased cache handle.
 *
 * Only SimpleStrategy is implemented. Another strategy can be added without
 * changing callers. Pins may outlive this handle. A moved-from handle rejects
 * insert and reports zero for the size queries.
 */
class Cache {
public:
    /**
     * @brief Build the strategy named by @p kind.
     * @param kind Placement strategy.
     * @param config Pool size. Zero is rejected.
     */
    explicit Cache(StrategyKind kind, PoolConfig config = {});

    /**
     * @brief Drop this handle. Outstanding pins may keep the pool alive.
     */
    ~Cache();

    /**
     * @brief Take @p other's pool. @p other becomes empty.
     * @param other Source handle. Left empty.
     */
    Cache(Cache&& other) noexcept;

    /**
     * @brief Drop this handle and take @p other's. @p other becomes empty.
     * @param other Source handle. Left empty.
     * @return *this.
     */
    Cache& operator=(Cache&& other) noexcept;

    Cache(const Cache&) = delete;
    Cache& operator=(const Cache&) = delete;

    /**
     * @brief Copy @p bytes into the pool.
     *
     * Throws if this handle was moved-from. The pin keeps the pool alive
     * after this Cache is destroyed.
     * @param bytes Payload to copy. May be empty.
     * @return Pin, or empty if the blob cannot be placed.
     */
    [[nodiscard]] Allocation insert(std::span<const std::byte> bytes) const;

    /**
     * @brief Usable capacity in bytes.
     * @return Aligned cap, or 0 if moved-from.
     */
    [[nodiscard]] std::size_t capacity() const noexcept;

    /**
     * @brief Bytes reserved by live entries, including alignment padding.
     * @return Occupied bytes, or 0 if moved-from.
     */
    [[nodiscard]] std::size_t used() const noexcept;

    /**
     * @brief Entries destroyed to make room.
     * @return Eviction count, or 0 if moved-from.
     */
    [[nodiscard]] std::size_t evictions() const noexcept;

    /**
     * @brief Live entries, pinned and unpinned.
     * @return Entry count, or 0 if moved-from.
     */
    [[nodiscard]] std::size_t resident() const noexcept;

private:
    using InsertFn = Allocation (*)(const std::shared_ptr<void>&, std::span<const std::byte>);  ///< Strategy insert.
    using SizeFn = std::size_t (*)(void*) noexcept;  ///< Strategy size query.

    std::shared_ptr<void> impl_;  ///< Concrete strategy. Pins share this owner.
    InsertFn insert_ = nullptr;   ///< Bound insert. Null after move.
    SizeFn capacity_ = nullptr;   ///< Bound capacity query.
    SizeFn used_ = nullptr;       ///< Bound occupied-byte query.
    SizeFn evictions_ = nullptr;  ///< Bound eviction counter.
    SizeFn resident_ = nullptr;   ///< Bound live-entry counter.

    /**
     * @brief Throw if this handle was moved-from.
     */
    void require() const;
};

}  // namespace microserve::cache

namespace microserve::cache {

namespace {

/**
 * @brief Throw std::runtime_error.
 * @param what Exception text.
 */
[[noreturn]] void fail(const char* what) {
    throw std::runtime_error(what);
}

/**
 * @brief Host page size.
 * @return Page size in bytes, or 4096 if the query fails.
 */
std::size_t os_page_size() noexcept {
#ifdef _WIN32
    SYSTEM_INFO info{};
    ::GetSystemInfo(&info);
    return info.dwPageSize == 0 ? 4096u : static_cast<std::size_t>(info.dwPageSize);
#else
    const long page = ::sysconf(_SC_PAGESIZE);
    return page > 0 ? static_cast<std::size_t>(page) : 4096u;
#endif
}

/**
 * @brief Reserve and commit a private writable mapping.
 * @param bytes Length to map.
 * @return Mapping base. Throws if the OS call fails.
 */
std::byte* reserve_arena(std::size_t bytes) {
#ifdef _WIN32
    void* p = ::VirtualAlloc(nullptr, bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (p == nullptr)
        fail("VirtualAlloc failed");
    return static_cast<std::byte*>(p);
#else
    void* p = ::mmap(nullptr, bytes, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED)
        fail("mmap failed");
    return static_cast<std::byte*>(p);
#endif
}

/**
 * @brief Unmap a block from reserve_arena(). No-op if @p p is null.
 * @param p Mapping base.
 * @param bytes Length originally mapped. Ignored on Windows.
 */
void release_arena(std::byte* p, const std::size_t bytes) noexcept {
    if (p == nullptr)
        return;
#ifdef _WIN32
    ::VirtualFree(p, 0, MEM_RELEASE);
    (void)bytes;
#else
    ::munmap(p, bytes);
#endif
}

}  // namespace

Allocation::~Allocation() { release(); }

Allocation::Allocation(const Allocation& other)
    : owner_(other.owner_), strategy_(other.strategy_), entry_(other.entry_),
      pin_(other.pin_), unpin_(other.unpin_), touch_(other.touch_),
      data_(other.data_), size_(other.size_) {
    if (pin_ != nullptr && strategy_ != nullptr && entry_ != nullptr)
        pin_(strategy_, entry_);
}

Allocation& Allocation::operator=(const Allocation& other) {
    if (this == &other)
        return *this;
    release();
    owner_ = other.owner_;
    strategy_ = other.strategy_;
    entry_ = other.entry_;
    pin_ = other.pin_;
    unpin_ = other.unpin_;
    touch_ = other.touch_;
    data_ = other.data_;
    size_ = other.size_;
    if (pin_ != nullptr && strategy_ != nullptr && entry_ != nullptr)
        pin_(strategy_, entry_);
    return *this;
}

Allocation::Allocation(Allocation&& other) noexcept
    : owner_(std::move(other.owner_)), strategy_(other.strategy_),
      entry_(other.entry_), pin_(other.pin_), unpin_(other.unpin_),
      touch_(other.touch_), data_(other.data_), size_(other.size_) {
    other.strategy_ = nullptr;
    other.entry_ = nullptr;
    other.pin_ = nullptr;
    other.unpin_ = nullptr;
    other.touch_ = nullptr;
    other.data_ = nullptr;
    other.size_ = 0;
}

Allocation& Allocation::operator=(Allocation&& other) noexcept {
    if (this == &other)
        return *this;
    release();
    owner_ = std::move(other.owner_);
    strategy_ = other.strategy_;
    entry_ = other.entry_;
    pin_ = other.pin_;
    unpin_ = other.unpin_;
    touch_ = other.touch_;
    data_ = other.data_;
    size_ = other.size_;
    other.strategy_ = nullptr;
    other.entry_ = nullptr;
    other.pin_ = nullptr;
    other.unpin_ = nullptr;
    other.touch_ = nullptr;
    other.data_ = nullptr;
    other.size_ = 0;
    return *this;
}

std::byte* Allocation::data() const noexcept { return data_; }

std::size_t Allocation::size() const noexcept { return size_; }

Allocation::operator bool() const noexcept { return entry_ != nullptr; }

void Allocation::touch() const noexcept {
    if (touch_ != nullptr && strategy_ != nullptr && entry_ != nullptr)
        touch_(strategy_, entry_);
}

void Allocation::release() noexcept {
    if (unpin_ != nullptr && strategy_ != nullptr && entry_ != nullptr)
        unpin_(strategy_, entry_);
    owner_.reset();
    strategy_ = nullptr;
    entry_ = nullptr;
    pin_ = nullptr;
    unpin_ = nullptr;
    touch_ = nullptr;
    data_ = nullptr;
    size_ = 0;
}

std::size_t SimpleStrategy::align_up(const std::size_t n) noexcept {
    return (n + align_ - 1) & ~(align_ - 1);
}

std::size_t SimpleStrategy::page_size() noexcept { return os_page_size(); }

SimpleStrategy::SimpleStrategy(const PoolConfig config) {
    if (config.capacity_bytes == 0)
        fail("cache capacity must be non-zero");

    const std::size_t page = page_size();
    capacity_ = align_up(config.capacity_bytes);
    mapped_ = (capacity_ + page - 1) & ~(page - 1);
    base_ = reserve_arena(mapped_);
    free_.emplace(0, capacity_);
}

SimpleStrategy::~SimpleStrategy() {
    std::lock_guard lock(mu_);
    const Entry* cursor = oldest_;
    while (cursor != nullptr) {
        const Entry* next = cursor->newer;
        delete cursor;
        cursor = next;
    }
    oldest_ = newest_ = nullptr;
    release_arena(base_, mapped_);
    base_ = nullptr;
}

std::size_t SimpleStrategy::find_fit(const std::size_t need) const {
    for (const auto& [offset, size] : free_) {
        if (size >= need)
            return offset;
    }
    return npos_;
}

std::size_t SimpleStrategy::take_fit(const std::size_t offset, const std::size_t need) {
    const auto it = free_.find(offset);
    const std::size_t have = it->second;
    free_.erase(it);
    if (have > need)
        free_.emplace(offset + need, have - need);
    return offset;
}

void SimpleStrategy::release_range(std::size_t offset, std::size_t size) {
    auto next = free_.lower_bound(offset);
    if (next != free_.begin()) {
        if (const auto prev = std::prev(next);
            prev->first + prev->second == offset) {
            offset = prev->first;
            size += prev->second;
            free_.erase(prev);
            next = free_.lower_bound(offset);
        }
    }
    if (next != free_.end() && offset + size == next->first) {
        size += next->second;
        next = free_.erase(next);
    }
    free_.emplace(offset, size);
}

void SimpleStrategy::lru_push(Entry* entry) noexcept {
    entry->older = newest_;
    entry->newer = nullptr;
    if (newest_ != nullptr)
        newest_->newer = entry;
    else
        oldest_ = entry;
    newest_ = entry;
}

void SimpleStrategy::lru_unlink(Entry* entry) noexcept {
    if (entry->older != nullptr)
        entry->older->newer = entry->newer;
    else
        oldest_ = entry->newer;
    if (entry->newer != nullptr)
        entry->newer->older = entry->older;
    else
        newest_ = entry->older;
    entry->older = entry->newer = nullptr;
}

void SimpleStrategy::destroy_entry(Entry* entry) {
    lru_unlink(entry);
    release_range(entry->offset, entry->size);
    used_ -= entry->size;
    --resident_;
    delete entry;
}

bool SimpleStrategy::make_room(const std::size_t need) {
    if (find_fit(need) != npos_)
        return true;

    struct Seg {
        std::size_t offset;
        std::size_t size;
        Entry* entry;
    };
    const std::size_t nsegs = free_.size() + resident_;
    auto segs = std::make_unique<Seg[]>(nsegs);
    std::size_t n = 0;
    for (const auto& [offset, size] : free_)
        segs[n++] = Seg{.offset = offset, .size = size, .entry = nullptr};
    for (Entry* cursor = oldest_; cursor != nullptr; cursor = cursor->newer)
        segs[n++] = Seg{.offset = cursor->offset, .size = cursor->size, .entry = cursor};
    std::sort(segs.get(), segs.get() + n, [](const Seg& a, const Seg& b) {
        return a.offset < b.offset;
    });

    // Fewest-entry reclaimable run (free ranges plus unpinned entries) that
    // can hold `need`. A pinned entry breaks a run. Nothing is freed until a
    // run is chosen, so a failure leaves the cache intact.
    std::size_t best_lo = npos_;
    std::size_t best_hi = npos_;
    std::size_t best_cost = npos_;
    for (std::size_t i = 0; i < n; ++i) {
        if (segs[i].entry != nullptr && segs[i].entry->pins != 0)
            continue;
        std::size_t sum = 0;
        std::size_t cost = 0;
        for (std::size_t j = i; j < n; ++j) {
            if (segs[j].entry != nullptr && segs[j].entry->pins != 0)
                break;
            sum += segs[j].size;
            if (segs[j].entry != nullptr)
                ++cost;
            if (sum >= need) {
                if (cost < best_cost) {
                    best_cost = cost;
                    best_lo = i;
                    best_hi = j;
                }
                break;
            }
        }
    }
    if (best_lo == npos_)
        return false;

    auto victims = std::make_unique<Entry*[]>(best_cost == 0 ? 1 : best_cost);
    std::size_t nv = 0;
    for (std::size_t k = best_lo; k <= best_hi; ++k) {
        if (segs[k].entry != nullptr)
            victims[nv++] = segs[k].entry;
    }
    segs.reset();
    for (std::size_t i = 0; i < nv; ++i) {
        destroy_entry(victims[i]);
        ++evictions_;
    }
    return find_fit(need) != npos_;
}

void SimpleStrategy::pin(void* strategy, void* entry) noexcept {
    const auto* self = static_cast<SimpleStrategy*>(strategy);
    auto* node = static_cast<Entry*>(entry);
    std::lock_guard lock(self->mu_);
    if (node->pins != static_cast<std::uint32_t>(-1))
        ++node->pins;
}

void SimpleStrategy::unpin(void* strategy, void* entry) noexcept {
    const auto* self = static_cast<SimpleStrategy*>(strategy);
    auto* node = static_cast<Entry*>(entry);
    std::lock_guard lock(self->mu_);
    if (node->pins == 0)
        return;
    --node->pins;
}

void SimpleStrategy::touch(void* strategy, void* entry) noexcept {
    auto* self = static_cast<SimpleStrategy*>(strategy);
    auto* node = static_cast<Entry*>(entry);
    std::lock_guard lock(self->mu_);
    if (node->pins == 0)
        return;
    self->lru_unlink(node);
    self->lru_push(node);
}

Allocation SimpleStrategy::adopt(std::shared_ptr<void> owner, Entry* entry,
                                 const std::size_t payload) {
    Allocation out;
    out.owner_ = std::move(owner);
    out.strategy_ = this;
    out.entry_ = entry;
    out.pin_ = &SimpleStrategy::pin;
    out.unpin_ = &SimpleStrategy::unpin;
    out.touch_ = &SimpleStrategy::touch;
    out.data_ = base_ + entry->offset;
    out.size_ = payload;
    return out;
}

Allocation SimpleStrategy::insert(const std::span<const std::byte> bytes) {
    if (bytes.size() > capacity_)
        return {};

    const std::size_t need = align_up(bytes.empty() ? align_ : bytes.size());
    if (need > capacity_)
        return {};

    auto entry = std::make_unique<Entry>();
    std::lock_guard lock(mu_);
    if (!make_room(need))
        return {};

    const std::size_t offset = take_fit(find_fit(need), need);
    entry->offset = offset;
    entry->size = need;
    entry->payload = bytes.size();
    entry->pins = 1;
    if (!bytes.empty())
        std::memcpy(base_ + offset, bytes.data(), bytes.size());

    Entry* raw = entry.release();
    lru_push(raw);
    used_ += need;
    ++resident_;
    // Direct use does not extend the strategy lifetime. Cache::insert passes
    // a shared owner so an in-flight Allocation can outlive the Cache.
    return adopt(nullptr, raw, bytes.size());
}

Allocation SimpleStrategy::insert_shared(const std::shared_ptr<void>& owner,
                                         const std::span<const std::byte> bytes) {
    Allocation slot = insert(bytes);
    if (!slot)
        return {};
    slot.owner_ = owner;
    return slot;
}

std::size_t SimpleStrategy::capacity() const noexcept {
    std::lock_guard lock(mu_);
    return capacity_;
}
std::size_t SimpleStrategy::used() const noexcept {
    std::lock_guard lock(mu_);
    return used_;
}
std::size_t SimpleStrategy::evictions() const noexcept {
    std::lock_guard lock(mu_);
    return evictions_;
}
std::size_t SimpleStrategy::resident() const noexcept {
    std::lock_guard lock(mu_);
    return resident_;
}

namespace {

/**
 * @brief Insert through a shared SimpleStrategy and bind the pin to @p impl.
 * @param impl Strategy kept alive by the returned pin.
 * @param bytes Payload to copy.
 * @return Pin, or empty if the blob cannot be placed.
 */
Allocation simple_insert(const std::shared_ptr<void>& impl, const std::span<const std::byte> bytes) {
    return static_cast<SimpleStrategy*>(impl.get())->insert_shared(impl, bytes);
}

/**
 * @brief Usable capacity of a SimpleStrategy.
 * @param impl Strategy pointer.
 * @return Aligned capacity in bytes.
 */
std::size_t simple_capacity(void* impl) noexcept {
    return static_cast<SimpleStrategy*>(impl)->capacity();
}

/**
 * @brief Occupied bytes of a SimpleStrategy.
 * @param impl Strategy pointer.
 * @return Reserved bytes, including alignment padding.
 */
std::size_t simple_used(void* impl) noexcept {
    return static_cast<SimpleStrategy*>(impl)->used();
}

/**
 * @brief Eviction count of a SimpleStrategy.
 * @param impl Strategy pointer.
 * @return Entries destroyed to make room.
 */
std::size_t simple_evictions(void* impl) noexcept {
    return static_cast<SimpleStrategy*>(impl)->evictions();
}

/**
 * @brief Live-entry count of a SimpleStrategy.
 * @param impl Strategy pointer.
 * @return Pinned and unpinned entries.
 */
std::size_t simple_resident(void* impl) noexcept {
    return static_cast<SimpleStrategy*>(impl)->resident();
}

}  // namespace

void Cache::require() const {
    if (impl_ == nullptr || insert_ == nullptr)
        fail("cache used after move");
}

Cache::Cache(const StrategyKind kind, PoolConfig config) {
    switch (kind) {
    case StrategyKind::Simple:
        impl_ = std::make_shared<SimpleStrategy>(config);
        insert_ = &simple_insert;
        capacity_ = &simple_capacity;
        used_ = &simple_used;
        evictions_ = &simple_evictions;
        resident_ = &simple_resident;
        return;
    }
    fail("unsupported cache strategy");
}

Cache::~Cache() = default;

Cache::Cache(Cache&& other) noexcept
    : impl_(std::move(other.impl_)), insert_(other.insert_),
      capacity_(other.capacity_), used_(other.used_),
      evictions_(other.evictions_), resident_(other.resident_) {
    other.insert_ = nullptr;
    other.capacity_ = nullptr;
    other.used_ = nullptr;
    other.evictions_ = nullptr;
    other.resident_ = nullptr;
}

Cache& Cache::operator=(Cache&& other) noexcept {
    if (this == &other)
        return *this;
    impl_ = std::move(other.impl_);
    insert_ = other.insert_;
    capacity_ = other.capacity_;
    used_ = other.used_;
    evictions_ = other.evictions_;
    resident_ = other.resident_;
    other.insert_ = nullptr;
    other.capacity_ = nullptr;
    other.used_ = nullptr;
    other.evictions_ = nullptr;
    other.resident_ = nullptr;
    return *this;
}

Allocation Cache::insert(const std::span<const std::byte> bytes) const {
    require();
    return insert_(impl_, bytes);
}
std::size_t Cache::capacity() const noexcept {
    return impl_ == nullptr ? 0 : capacity_(impl_.get());
}
std::size_t Cache::used() const noexcept {
    return impl_ == nullptr ? 0 : used_(impl_.get());
}
std::size_t Cache::evictions() const noexcept {
    return impl_ == nullptr ? 0 : evictions_(impl_.get());
}
std::size_t Cache::resident() const noexcept {
    return impl_ == nullptr ? 0 : resident_(impl_.get());
}

}  // namespace microserve::cache
