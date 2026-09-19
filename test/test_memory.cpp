// SPDX-FileCopyrightText: 2025-2026 Igal Alkon
// SPDX-FileCopyrightText: 2026 ALKONTEK <git@alkontek.com>
// SPDX-License-Identifier: BSD-3-Clause

#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <cstring>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

import microserve.memory;

using microserve::cache::Allocation;
using microserve::cache::Cache;
using microserve::cache::PoolConfig;
using microserve::cache::SimpleStrategy;
using microserve::cache::StrategyKind;

namespace {

std::vector<std::byte> bytes_of(const std::string_view text) {
    std::vector<std::byte> out(text.size());
    if (!text.empty())
        std::memcpy(out.data(), text.data(), text.size());
    return out;
}

std::vector<std::byte> filled(const std::size_t n, const std::byte value) {
    return std::vector<std::byte>(n, value);
}

std::span<const std::byte> view_of(const std::vector<std::byte>& bytes) {
    return {bytes.data(), bytes.size()};
}

bool same_bytes(const Allocation& slot, const std::string_view text) {
    if (!slot || slot.size() != text.size())
        return false;
    return text.empty() || std::memcmp(slot.data(), text.data(), text.size()) == 0;
}

bool same_bytes(const Allocation& slot, const std::vector<std::byte>& bytes) {
    if (!slot || slot.size() != bytes.size())
        return false;
    return bytes.empty() || std::memcmp(slot.data(), bytes.data(), bytes.size()) == 0;
}

} // namespace

TEST_CASE("PoolConfig defaults to 128 MiB", "[memory][cache]") {
    constexpr PoolConfig cfg;
    CHECK(cfg.capacity_bytes == 128ull * 1024ull * 1024ull);
}

TEST_CASE("SimpleStrategy rejects a zero pool and aligns capacity", "[memory][cache]") {
    CHECK_THROWS_AS(SimpleStrategy(PoolConfig{.capacity_bytes = 0}), std::runtime_error);

    SimpleStrategy pool(PoolConfig{.capacity_bytes = 50});
    CHECK(pool.capacity() == 64);
    CHECK(pool.used() == 0);
    CHECK(pool.evictions() == 0);
    CHECK(pool.resident() == 0);
}

TEST_CASE("default Allocation is empty", "[memory][cache]") {
    const Allocation slot;
    CHECK_FALSE(slot);
    CHECK(slot.data() == nullptr);
    CHECK(slot.size() == 0);
    CHECK_NOTHROW(slot.touch());

    const Allocation& copy = slot;
    CHECK_FALSE(copy);
    Allocation moved = copy;
    CHECK_FALSE(moved);
}

TEST_CASE("insert copies bytes and updates counters", "[memory][cache]") {
    SimpleStrategy pool(PoolConfig{.capacity_bytes = 256});
    auto src = bytes_of("hello");
    const auto slot = pool.insert(view_of(src));

    REQUIRE(slot);
    CHECK(slot.size() == 5);
    CHECK(same_bytes(slot, "hello"));
    CHECK(pool.used() == 16);
    CHECK(pool.resident() == 1);
    CHECK(pool.evictions() == 0);

    src[0] = std::byte{'X'};
    CHECK(slot.data()[0] == std::byte{'h'});

    Allocation dropped;
    {
        const auto tmp = bytes_of("ephemeral");
        dropped = pool.insert(view_of(tmp));
    }
    REQUIRE(dropped);
    CHECK(same_bytes(dropped, "ephemeral"));
    CHECK(pool.resident() == 2);
}

TEST_CASE("payloads are rounded up to the slot alignment", "[memory][cache]") {
    SimpleStrategy pool(PoolConfig{.capacity_bytes = 64});

    const auto one = pool.insert(view_of(filled(1, std::byte{1})));
    REQUIRE(one);
    CHECK(one.size() == 1);
    CHECK(pool.used() == 16);

    const auto seventeen = pool.insert(view_of(filled(17, std::byte{2})));
    REQUIRE(seventeen);
    CHECK(seventeen.size() == 17);
    CHECK(pool.used() == 48);

    const auto fifteen = pool.insert(view_of(filled(15, std::byte{3})));
    REQUIRE(fifteen);
    CHECK(pool.used() == 64);
    CHECK(pool.resident() == 3);

    CHECK_FALSE(pool.insert(view_of(filled(1, std::byte{4}))));
    CHECK(pool.evictions() == 0);
    CHECK(pool.resident() == 3);
    CHECK(same_bytes(one, filled(1, std::byte{1})));
}

TEST_CASE("an empty insert still occupies one aligned slot", "[memory][cache]") {
    SimpleStrategy pool(PoolConfig{.capacity_bytes = 16});
    const auto slot = pool.insert({});

    REQUIRE(slot);
    CHECK(slot.size() == 0);
    CHECK(slot.data() != nullptr);
    CHECK(pool.used() == 16);
    CHECK(pool.resident() == 1);
    CHECK_FALSE(pool.insert({}));
    CHECK(pool.evictions() == 0);
}

TEST_CASE("a blob larger than the pool fails and discards nothing", "[memory][cache]") {
    SimpleStrategy pool(PoolConfig{.capacity_bytes = 64});
    CHECK_FALSE(pool.insert(view_of(filled(65, std::byte{9}))));
    CHECK(pool.used() == 0);
    CHECK(pool.resident() == 0);
    CHECK(pool.evictions() == 0);

    const auto kept = pool.insert(view_of(bytes_of("kept")));
    REQUIRE(kept);
    const auto used = pool.used();
    CHECK_FALSE(pool.insert(view_of(filled(65, std::byte{9}))));
    CHECK(pool.used() == used);
    CHECK(pool.resident() == 1);
    CHECK(pool.evictions() == 0);
    CHECK(same_bytes(kept, "kept"));
}

TEST_CASE("Allocation copy and move share or transfer the pin", "[memory][cache]") {
    SimpleStrategy pool(PoolConfig{.capacity_bytes = 128});
    Allocation first = pool.insert(view_of(bytes_of("one")));
    Allocation second = pool.insert(view_of(bytes_of("two")));
    REQUIRE(first);
    REQUIRE(second);

    Allocation copy = first;
    CHECK(copy.data() == first.data());
    CHECK(same_bytes(copy, "one"));
    first.data()[0] = std::byte{'Z'};
    CHECK(copy.data()[0] == std::byte{'Z'});

    first = second;
    CHECK(same_bytes(first, "two"));
    CHECK(first.data() == second.data());
    CHECK(same_bytes(copy, "Zne"));

    Allocation moved = std::move(second);
    CHECK_FALSE(second);
    CHECK(second.data() == nullptr);
    CHECK(second.size() == 0);
    CHECK(same_bytes(moved, "two"));
    CHECK(moved.data() == first.data());

    Allocation& self = first;
    first = self;
    Allocation& moved_self = moved;
    moved = std::move(moved_self);
    CHECK(same_bytes(moved, "two"));
    CHECK(same_bytes(first, "two"));
    CHECK(pool.resident() == 2);
    CHECK(pool.evictions() == 0);
}

TEST_CASE("releasing a pin leaves the slot resident until eviction", "[memory][cache]") {
    SimpleStrategy pool(PoolConfig{.capacity_bytes = 32});
    Allocation slot = pool.insert(view_of(filled(16, std::byte{'a'})));
    REQUIRE(slot);
    const auto used = pool.used();

    slot = {};
    CHECK_FALSE(slot);
    CHECK(pool.used() == used);
    CHECK(pool.resident() == 1);
    CHECK(pool.evictions() == 0);

    const auto again = pool.insert(view_of(filled(16, std::byte{'b'})));
    REQUIRE(again);
    CHECK(pool.evictions() == 0);
    CHECK(pool.resident() == 2);
    CHECK(pool.used() == 32);
    CHECK(same_bytes(again, filled(16, std::byte{'b'})));
}

TEST_CASE("a full pool of pinned entries refuses an insert", "[memory][cache]") {
    SimpleStrategy pool(PoolConfig{.capacity_bytes = 48});
    const auto a = pool.insert(view_of(filled(16, std::byte{'a'})));
    const auto b = pool.insert(view_of(filled(16, std::byte{'b'})));
    const auto c = pool.insert(view_of(filled(16, std::byte{'c'})));
    REQUIRE(a);
    REQUIRE(b);
    REQUIRE(c);

    CHECK_FALSE(pool.insert(view_of(filled(16, std::byte{'d'}))));
    CHECK(pool.evictions() == 0);
    CHECK(pool.resident() == 3);
    CHECK(pool.used() == 48);
    CHECK(same_bytes(a, filled(16, std::byte{'a'})));
    CHECK(same_bytes(b, filled(16, std::byte{'b'})));
    CHECK(same_bytes(c, filled(16, std::byte{'c'})));
}

TEST_CASE("unpinned entries are evicted to make a contiguous span", "[memory][cache]") {
    SimpleStrategy pool(PoolConfig{.capacity_bytes = 48});
    Allocation a = pool.insert(view_of(filled(16, std::byte{'a'})));
    Allocation b = pool.insert(view_of(filled(16, std::byte{'b'})));
    Allocation c = pool.insert(view_of(filled(16, std::byte{'c'})));
    REQUIRE(a);
    REQUIRE(b);
    REQUIRE(c);

    a = {};
    b = {};
    c = {};
    const auto blob = filled(48, std::byte{0xAB});
    const auto slot = pool.insert(view_of(blob));

    REQUIRE(slot);
    CHECK(slot.size() == 48);
    CHECK(same_bytes(slot, blob));
    CHECK(pool.evictions() == 3);
    CHECK(pool.resident() == 1);
    CHECK(pool.used() == 48);
}

TEST_CASE("a pinned entry blocks coalescing and a failed insert drops nothing", "[memory][cache]") {
    SimpleStrategy pool(PoolConfig{.capacity_bytes = 64});
    Allocation a = pool.insert(view_of(filled(16, std::byte{'a'})));
    Allocation b = pool.insert(view_of(filled(16, std::byte{'b'})));
    Allocation c = pool.insert(view_of(filled(16, std::byte{'c'})));
    Allocation d = pool.insert(view_of(filled(16, std::byte{'d'})));
    REQUIRE(a);
    REQUIRE(b);
    REQUIRE(c);
    REQUIRE(d);

    a = {};
    c = {};
    CHECK_FALSE(pool.insert(view_of(filled(32, std::byte{1}))));
    CHECK(pool.evictions() == 0);
    CHECK(pool.resident() == 4);
    CHECK(pool.used() == 64);
    CHECK(same_bytes(b, filled(16, std::byte{'b'})));
    CHECK(same_bytes(d, filled(16, std::byte{'d'})));

    const auto* d_data = d.data();
    b = {};
    const auto slot = pool.insert(view_of(filled(32, std::byte{2})));
    REQUIRE(slot);
    CHECK(pool.evictions() == 2);
    CHECK(pool.resident() == 3);
    CHECK(pool.used() == 64);
    CHECK(d.data() == d_data);
    CHECK(same_bytes(d, filled(16, std::byte{'d'})));
    CHECK(same_bytes(slot, filled(32, std::byte{2})));
}

TEST_CASE("eviction takes the cheapest unpinned run and does not relocate pins", "[memory][cache]") {
    SimpleStrategy pool(PoolConfig{.capacity_bytes = 64});
    Allocation a = pool.insert(view_of(filled(16, std::byte{'a'})));
    Allocation b = pool.insert(view_of(filled(16, std::byte{'b'})));
    Allocation c = pool.insert(view_of(filled(16, std::byte{'c'})));
    Allocation d = pool.insert(view_of(filled(16, std::byte{'d'})));
    REQUIRE(a);
    REQUIRE(b);
    REQUIRE(c);
    REQUIRE(d);

    const auto* a_data = a.data();
    const auto* d_data = d.data();
    b = {};
    c = {};

    const auto slot = pool.insert(view_of(filled(32, std::byte{'e'})));
    REQUIRE(slot);
    CHECK(pool.evictions() == 2);
    CHECK(pool.resident() == 3);
    CHECK(pool.used() == 64);
    CHECK(a.data() == a_data);
    CHECK(d.data() == d_data);
    CHECK(same_bytes(a, filled(16, std::byte{'a'})));
    CHECK(same_bytes(d, filled(16, std::byte{'d'})));
    CHECK(same_bytes(slot, filled(32, std::byte{'e'})));
}

TEST_CASE("touch is a no-op on an empty Allocation and keeps a live slot", "[memory][cache]") {
    SimpleStrategy pool(PoolConfig{.capacity_bytes = 64});
    const auto slot = pool.insert(view_of(bytes_of("touch")));
    REQUIRE(slot);

    CHECK_NOTHROW(slot.touch());
    CHECK(same_bytes(slot, "touch"));
    CHECK(pool.used() == 16);
    CHECK(pool.resident() == 1);
    CHECK(pool.evictions() == 0);
    CHECK_NOTHROW(Allocation{}.touch());
}

TEST_CASE("insert_shared retains the caller owner only when the insert lands", "[memory][cache]") {
    const auto owner = std::make_shared<int>(7);
    SimpleStrategy pool(PoolConfig{.capacity_bytes = 64});

    auto slot = pool.insert_shared(owner, view_of(bytes_of("owned")));
    REQUIRE(slot);
    CHECK(same_bytes(slot, "owned"));
    CHECK(owner.use_count() == 2);

    slot = {};
    CHECK(owner.use_count() == 1);

    SimpleStrategy tiny(PoolConfig{.capacity_bytes = 16});
    CHECK_FALSE(tiny.insert_shared(owner, view_of(filled(32, std::byte{1}))));
    CHECK(owner.use_count() == 1);
}

TEST_CASE("Cache fronts SimpleStrategy and rejects an unknown kind", "[memory][cache]") {
    CHECK_THROWS_AS(Cache(StrategyKind::Simple, PoolConfig{.capacity_bytes = 0}), std::runtime_error);
    CHECK_THROWS_AS(Cache(static_cast<StrategyKind>(42), PoolConfig{.capacity_bytes = 64}),
                    std::runtime_error);

    const Cache cache(StrategyKind::Simple, PoolConfig{.capacity_bytes = 32});
    CHECK(cache.capacity() == 32);
    auto a = cache.insert(view_of(filled(16, std::byte{'a'})));
    auto b = cache.insert(view_of(filled(16, std::byte{'b'})));
    REQUIRE(a);
    REQUIRE(b);
    CHECK(cache.used() == 32);
    CHECK(cache.resident() == 2);
    CHECK(cache.evictions() == 0);

    a = {};
    b = {};
    const auto c = cache.insert(view_of(filled(32, std::byte{'c'})));
    REQUIRE(c);
    CHECK(c.size() == 32);
    CHECK(cache.evictions() == 2);
    CHECK(cache.resident() == 1);
    CHECK(cache.used() == 32);
}

TEST_CASE("a moved-from Cache rejects insert and reports empty counters", "[memory][cache]") {
    Cache src(StrategyKind::Simple, PoolConfig{.capacity_bytes = 256});
    const auto slot = src.insert(view_of(bytes_of("stay")));
    REQUIRE(slot);

    Cache dst(std::move(src));
    CHECK_THROWS_AS(src.insert({}), std::runtime_error);
    CHECK(src.capacity() == 0);
    CHECK(src.used() == 0);
    CHECK(src.evictions() == 0);
    CHECK(src.resident() == 0);
    CHECK(same_bytes(slot, "stay"));
    CHECK(dst.capacity() == 256);
    CHECK(dst.resident() == 1);

    Cache assigned(StrategyKind::Simple, PoolConfig{.capacity_bytes = 128});
    assigned = std::move(dst);
    CHECK_THROWS_AS(dst.insert({}), std::runtime_error);
    CHECK(same_bytes(slot, "stay"));

    assigned = std::move(assigned);
    CHECK(assigned.capacity() == 256);
    const auto more = assigned.insert(view_of(bytes_of("more")));
    REQUIRE(more);
    CHECK(same_bytes(more, "more"));
}

TEST_CASE("an Allocation keeps the arena alive after Cache is destroyed", "[memory][cache]") {
    Allocation kept;
    Allocation copy;
    {
        Cache cache(StrategyKind::Simple, PoolConfig{.capacity_bytes = 256});
        kept = cache.insert(view_of(bytes_of("persist")));
        copy = kept;
        REQUIRE(cache.resident() == 1);
    }

    REQUIRE(kept);
    CHECK(copy.data() == kept.data());
    CHECK(same_bytes(kept, "persist"));
    CHECK_NOTHROW(kept.touch());
    copy = {};
    CHECK(same_bytes(kept, "persist"));
}

TEST_CASE("SimpleStrategy insert is safe across threads", "[memory][cache]") {
    constexpr int k_threads = 4;
    constexpr int k_each = 40;
    SimpleStrategy pool(PoolConfig{.capacity_bytes = 64 * 1024});

    struct Item {
        std::string text;
        Allocation slot;
    };
    std::vector<std::vector<Item>> got(k_threads);
    std::atomic<int> failures{0};

    std::vector<std::thread> threads;
    threads.reserve(k_threads);
    for (int t = 0; t < k_threads; ++t) {
        threads.emplace_back([&, t] {
            got[static_cast<std::size_t>(t)].reserve(k_each);
            for (int i = 0; i < k_each; ++i) {
                Item item;
                item.text = std::to_string(t) + "-" + std::to_string(i);
                const auto raw = bytes_of(item.text);
                item.slot = pool.insert(view_of(raw));
                if (!same_bytes(item.slot, item.text))
                    failures.fetch_add(1, std::memory_order_relaxed);
                got[static_cast<std::size_t>(t)].push_back(std::move(item));
            }
        });
    }
    for (auto& thread : threads)
        thread.join();

    CHECK(failures.load() == 0);
    CHECK(pool.resident() == static_cast<std::size_t>(k_threads * k_each));
    CHECK(pool.evictions() == 0);
    CHECK(pool.used() == static_cast<std::size_t>(k_threads * k_each) * 16);
    for (const auto& batch : got) {
        for (const auto&[_text, _slot] : batch)
            CHECK(same_bytes(_slot, _text));
    }
}

TEST_CASE("Allocation pin and unpin are safe across threads", "[memory][cache]") {
    SimpleStrategy pool(PoolConfig{.capacity_bytes = 4096});
    std::vector<Allocation> live;
    live.reserve(8);
    for (int i = 0; i < 8; ++i) {
        auto slot = pool.insert(view_of(filled(32, static_cast<std::byte>(i + 1))));
        REQUIRE(slot);
        live.push_back(std::move(slot));
    }

    std::atomic<int> failures{0};
    std::vector<std::thread> threads;
    for (int t = 0; t < 4; ++t) {
        threads.emplace_back([&] {
            for (int n = 0; n < 100; ++n) {
                const auto& copy = live[static_cast<std::size_t>(n % live.size())];
                copy.touch();
                if (!copy || copy.size() != 32)
                    failures.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }
    for (auto& thread : threads)
        thread.join();

    CHECK(failures.load() == 0);
    CHECK(pool.resident() == 8);
    CHECK(pool.evictions() == 0);
    CHECK(pool.used() == 256);
    for (std::size_t i = 0; i < live.size(); ++i)
        CHECK(same_bytes(live[i], filled(32, static_cast<std::byte>(i + 1))));
}
