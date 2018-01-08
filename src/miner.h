// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MINER_H
#define BITCOIN_MINER_H

#include "primitives/block.h"

#include <stdint.h>

class CBlockIndex;
class CChainParams;
class CConnman;
class CReserveKey;
class CScript;
class CWallet;
namespace Consensus { struct Params; };

static const bool DEFAULT_GENERATE = false;  //缺省不挖矿
static const int DEFAULT_GENERATE_THREADS = 1; //缺省挖矿线程数

static const bool DEFAULT_PRINTPRIORITY = false; // 挖矿日志　，是否输出每笔记录的优先级，费用和　　hash

//挖矿内部所有数据结构
struct CBlockTemplate
{
    CBlock block;                   //块数据
    std::vector<CAmount> vTxFees;   //费用
    std::vector<int64_t> vTxSigOps; //签名列表
};

/** Run the miner threads */  //启动挖矿线程
void GenerateBitcoins(bool fGenerate, int nThreads, const CChainParams& chainparams, CConnman& connman);
/** Generate a new block, without valid proof-of-work */ //创建新块
CBlockTemplate* CreateNewBlock(const CChainParams& chainparams, const CScript& scriptPubKeyIn);
/** Modify the extranonce in a block */ //填充块的信息，计算　BlockMerkleRoot
void IncrementExtraNonce(CBlock* pblock, const CBlockIndex* pindexPrev, unsigned int& nExtraNonce);
int64_t UpdateTime(CBlockHeader* pblock, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev);

#endif // BITCOIN_MINER_H
