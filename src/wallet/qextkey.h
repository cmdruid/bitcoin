// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Backward compatibility — QExtPubKey/QExtKey moved to common layer.
// This header re-exports them into the wallet namespace.

#ifndef BITCOIN_WALLET_QEXTKEY_H
#define BITCOIN_WALLET_QEXTKEY_H

#include <qextkey.h>

namespace wallet {
using ::QExtPubKey;
using ::QExtKey;
using ::DecodeQExtPubKey;
using ::EncodeQExtPubKey;
using ::DecodeQExtKey;
using ::EncodeQExtKey;
} // namespace wallet

#endif // BITCOIN_WALLET_QEXTKEY_H
