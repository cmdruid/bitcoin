// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <crypto/sphincsplus.h>
#include <uint256.h>

#include <array>
#include <cstdint>
#include <vector>

static void SphincsVerify(benchmark::Bench& bench)
{
    // Generate a deterministic key pair
    const std::array<uint8_t, 16> sk_seed{1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1};
    const std::array<uint8_t, 16> sk_prf{2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2};
    const std::array<uint8_t, 16> pk_seed{3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3};

    std::array<uint8_t, 64> sk;
    std::array<uint8_t, 32> pk;
    SphincsKeygen(sk.data(), pk.data(), sk_seed.data(), sk_prf.data(), pk_seed.data());

    // Sign a test message
    uint256 msg{};
    std::vector<uint8_t> sig(4080);
    SphincsSign(sig.data(), msg.data(), 32, sk.data());

    // Benchmark verification only
    bench.run([&] {
        bool result = VerifySphincsSignature(pk, sig, msg);
        ankerl::nanobench::doNotOptimizeAway(result);
    });
}

static void SphincsSign_Bench(benchmark::Bench& bench)
{
    const std::array<uint8_t, 16> sk_seed{1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1};
    const std::array<uint8_t, 16> sk_prf{2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2};
    const std::array<uint8_t, 16> pk_seed{3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3};

    std::array<uint8_t, 64> sk;
    std::array<uint8_t, 32> pk;
    SphincsKeygen(sk.data(), pk.data(), sk_seed.data(), sk_prf.data(), pk_seed.data());

    uint256 msg{};
    std::vector<uint8_t> sig(4080);

    bench.run([&] {
        size_t result = SphincsSign(sig.data(), msg.data(), 32, sk.data());
        ankerl::nanobench::doNotOptimizeAway(result);
    });
}

BENCHMARK(SphincsVerify);
BENCHMARK(SphincsSign_Bench);
