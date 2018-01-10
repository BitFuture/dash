// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2014-2017 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "miner.h"

#include "amount.h"
#include "chain.h"
#include "chainparams.h"
#include "coins.h"
#include "consensus/consensus.h"
#include "consensus/merkle.h"
#include "consensus/validation.h"
#include "hash.h"
#include "validation.h"
#include "net.h"
#include "policy/policy.h"
#include "pow.h"
#include "primitives/transaction.h"
#include "script/standard.h"
#include "timedata.h"
#include "txmempool.h"
#include "util.h"
#include "utilmoneystr.h"
#include "masternode-payments.h"
#include "masternode-sync.h"
#include "validationinterface.h"

#include <boost/thread.hpp>
#include <boost/tuple/tuple.hpp>
#include <queue>

using namespace std;

//////////////////////////////////////////////////////////////////////////////
//
// DashMiner
//

//
// Unconfirmed transactions in the memory pool often depend on other
// transactions in the memory pool. When we select transactions from the
// pool, we select by highest priority or fee rate, so we might consider
// transactions that depend on transactions that aren't yet in the block.

uint64_t nLastBlockTx = 0;
uint64_t nLastBlockSize = 0;

class ScoreCompare
{
public:
    ScoreCompare() {}

    bool operator()(const CTxMemPool::txiter a, const CTxMemPool::txiter b)
    {
        return CompareTxMemPoolEntryByScore()(*b,*a); // Convert to less than
    }
};

int64_t UpdateTime(CBlockHeader* pblock, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev)
{
    int64_t nOldTime = pblock->nTime;
    //取得11个时间的平均值
    int64_t nNewTime = std::max(pindexPrev->GetMedianTimePast()+1, GetAdjustedTime());

    if (nOldTime < nNewTime)
        pblock->nTime = nNewTime;

    // Updating time can change work required on testnet:
    if (consensusParams.fPowAllowMinDifficultyBlocks) //regnet testnet 动态调整难度值
        pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, consensusParams);

    return nNewTime - nOldTime;
}
//创建新块
CBlockTemplate* CreateNewBlock(const CChainParams& chainparams, const CScript& scriptPubKeyIn)
{
    // Create new block
    std::unique_ptr<CBlockTemplate> pblocktemplate(new CBlockTemplate());
    //判断数据指针是否存在
    if(!pblocktemplate.get())
        return NULL;
    CBlock *pblock = &pblocktemplate->block; // pointer for convenience

    // Create coinbase tx
    //压入奖励交易
    CMutableTransaction txNew;
    txNew.vin.resize(1);
    txNew.vin[0].prevout.SetNull();
    txNew.vout.resize(1);
    txNew.vout[0].scriptPubKey = scriptPubKeyIn;  //奖励矿工的公钥
    std::string sKey = FormatScript(scriptPubKeyIn);
   // scriptPubKeyIn    >> sKey;

   // sKey

    // Largest block you're willing to create: 最大块尺寸 750000
    unsigned int nBlockMaxSize = GetArg("-blockmaxsize", DEFAULT_BLOCK_MAX_SIZE);
    // Limit to between 1K and MAX_BLOCK_SIZE-1K for sanity: 大于 DEFAULT_BLOCK_PRIORITY_SIZE 小于   MAX_DIP0001_BLOCK_SIZE -  DEFAULT_BLOCK_PRIORITY_SIZE
    nBlockMaxSize = std::max((unsigned int)1000, std::min((unsigned int)(MaxBlockSize(fDIP0001ActiveAtTip)-1000), nBlockMaxSize));

    // How much of the block should be dedicated to high-priority transactions,
    // included regardless of the fees they pay 
    // 必须提供 DEFAULT_BLOCK_PRIORITY_SIZE 给高优先级的交易，无论是否有交易费
    unsigned int nBlockPrioritySize = GetArg("-blockprioritysize", DEFAULT_BLOCK_PRIORITY_SIZE);
    nBlockPrioritySize = std::min(nBlockMaxSize, nBlockPrioritySize);

    // Minimum block size you want to create; block will be filled with free transactions
    // until there are no more or the block reaches this size:
    //最小块大小
    unsigned int nBlockMinSize = GetArg("-blockminsize", DEFAULT_BLOCK_MIN_SIZE);
    nBlockMinSize = std::min(nBlockMaxSize, nBlockMinSize);

    // Collect memory pool transactions into the block
    CTxMemPool::setEntries inBlock;
    CTxMemPool::setEntries waitSet;

    // This vector will be sorted into a priority queue:
    vector<TxCoinAgePriority> vecPriority;  //交易优先级排序
    TxCoinAgePriorityCompare pricomparer;   //交易优先级比较函数 
    std::map<CTxMemPool::txiter, double, CTxMemPool::CompareIteratorByHash> waitPriMap;
    typedef std::map<CTxMemPool::txiter, double, CTxMemPool::CompareIteratorByHash>::iterator waitPriIter;
    double actualPriority = -1;

    // 排序函数   CompareTxMemPoolEntryByScore/
    std::priority_queue<CTxMemPool::txiter, std::vector<CTxMemPool::txiter>, ScoreCompare> clearedTxs;

    bool fPrintPriority = GetBoolArg("-printpriority", DEFAULT_PRINTPRIORITY);
    uint64_t nBlockSize = 1000; //块大小
    uint64_t nBlockTx = 0; //块个数
    unsigned int nBlockSigOps = 100;
    int lastFewTxs = 0;
    CAmount nFees = 0;

    {
        LOCK(cs_main);

        CBlockIndex* pindexPrev = chainActive.Tip(); //取得最后块
        const int nHeight = pindexPrev->nHeight + 1; //当前块高度
        pblock->nTime = GetAdjustedTime();//取得世界时间，本机时间矫正时区
        const int64_t nMedianTimePast = pindexPrev->GetMedianTimePast(); //取得最后块 前面 11 个块的中间时间

        // Add our coinbase tx as first transaction
        pblock->vtx.push_back(txNew);
        pblocktemplate->vTxFees.push_back(-1); // updated at end
        pblocktemplate->vTxSigOps.push_back(-1); // updated at end
        pblock->nVersion = ComputeBlockVersion(pindexPrev, chainparams.GetConsensus()); //计算版本号
        // -regtest only: allow overriding block.nVersion with
        // -blockversion=N to test forking scenarios
        if (chainparams.MineBlocksOnDemand()) //testnet模式为 true
            pblock->nVersion = GetArg("-blockversion", pblock->nVersion);

        int64_t nLockTimeCutoff = (STANDARD_LOCKTIME_VERIFY_FLAGS & LOCKTIME_MEDIAN_TIME_PAST)
                                ? nMedianTimePast
                                : pblock->GetBlockTime();

        {
            LOCK(mempool.cs);

            bool fPriorityBlock = nBlockPrioritySize > 0;
            if (fPriorityBlock) {
                vecPriority.reserve(mempool.mapTx.size());
                for (CTxMemPool::indexed_transaction_set::iterator mi = mempool.mapTx.begin();
                     mi != mempool.mapTx.end(); ++mi)
                {
                    double dPriority = mi->GetPriority(nHeight); //优先级别首先与块的高度相关
                    CAmount dummy;
                    mempool.ApplyDeltas(mi->GetTx().GetHash(), dPriority, dummy); //计算对应hash的优先级别
                    vecPriority.push_back(TxCoinAgePriority(dPriority, mi));
                }
                //将[start, end)范围进行堆排序，默认使用less, 即最大元素放在第一个
                std::make_heap(vecPriority.begin(), vecPriority.end(), pricomparer); //pricomparer 优先级比较函数 对优先级排序，
            }
             //数组 3 是交易池中  按score 排序 sorted by score (for mining prioritization)  
             // 这个排序使用的函数 TxCoinAgePriorityCompare 和 pricomparer 是一样的 pricomparer 先比较优先级
            CTxMemPool::indexed_transaction_set::nth_index<3>::type::iterator mi = mempool.mapTx.get<3>().begin();
            CTxMemPool::txiter iter;
            //递归内存交易池 
            while (mi != mempool.mapTx.get<3>().end() || !clearedTxs.empty())
            {
                bool priorityTx = false;
                //首先按高优先级处理，当高优先级别的 sizd > nBlockPrioritySize   时候 fPriorityBlock = false 就不走这个流程
                if (fPriorityBlock && !vecPriority.empty()) { // add a tx from priority queue to fill the blockprioritysize
                    priorityTx = true;  //标记这个是高优先级操作
                    iter = vecPriority.front().second; //交易
                    actualPriority = vecPriority.front().first;//优先级
                    // 将front（即第一个最大元素）移动到end的前部，同时将剩下的元素重新构造成(堆排序)一个新的heap
                    std::pop_heap(vecPriority.begin(), vecPriority.end(), pricomparer);
                    //删除最高优先级的
                    vecPriority.pop_back();
                }
                //如果没有推迟交易的记录，直接从交易池中取得，     
                else if (clearedTxs.empty()) { // add tx with next highest score
                //从第o个索引表中找到 mi对应的数据指针
                    iter = mempool.mapTx.project<0>(mi);
                    mi++;
                }
                // clearedTxs 记录的是当子交易没有找到父交易，先放到 waitSet ，当父交易找到后，移到 clearedTxs 处理
                else {  // try to add a previously postponed child tx
                    iter = clearedTxs.top();
                    clearedTxs.pop();
                }
                //因为同时从高优先级，交易池中取数据，所以非常有可能是重复的数据
                if (inBlock.count(iter))  //如果交易已经在块中，忽略
                    continue; // could have been added to the priorityBlock

                const CTransaction& tx = iter->GetTx();

                bool fOrphan = false;
                //取得当前交易的父交易，递归查询是否在块中。
                BOOST_FOREACH(CTxMemPool::txiter parent, mempool.GetMemPoolParents(iter))
                {
                    if (!inBlock.count(parent)) {
                        fOrphan = true;
                        break;
                    }
                }
                //如果当前交易的父交易不在块中，临时把当前交易保存在 waitPriMap  waitSet 中，一个是高优先级，一个是普通交易，然后继续查询
                if (fOrphan) {
                    if (priorityTx)
                        waitPriMap.insert(std::make_pair(iter,actualPriority));
                    else
                        waitSet.insert(iter);
                    continue;
                }
                //如果当前交易是高优先级交易，两个条件退出高优先级，1个是 块大小达到高优先级大小，一个是当前块的费用小于某个特定值  COIN * 144 / 250 
                unsigned int nTxSize = iter->GetTxSize();
                if (fPriorityBlock &&
                    (nBlockSize + nTxSize >= nBlockPrioritySize || !AllowFree(actualPriority))) {
                    fPriorityBlock = false;
                    waitPriMap.clear();
                }
                //非高优先级  两个条件同时具备 ，退出准备数据  一个是块的大小达到预订值，一个是当前条目手续费低于 当前交易size应该交的最小手续费 
                if (!priorityTx &&
                    (iter->GetModifiedFee() < ::minRelayTxFee.GetFee(nTxSize) && nBlockSize >= nBlockMinSize)) {
                    break;
                }
                //当前交易尺寸和总尺寸之和大于 最大尺寸，并不是马上退出准备数据，而是后面继续找 50次，尺寸小的，保证 nBlockMaxSize 填满。
                if (nBlockSize + nTxSize >= nBlockMaxSize) {
                    if (nBlockSize >  nBlockMaxSize - 100 || lastFewTxs > 50) {
                        break;
                    }
                    // Once we're within 1000 bytes of a full block, only look at 50 more txs
                    // to try to fill the remaining space.
                    if (nBlockSize > nBlockMaxSize - 1000) {
                        lastFewTxs++;
                    }
                    continue;
                }
                // nLockTime  锁定时间 nSequence 多重签名控制，不能进入块
                // nLockTimeCutoff 这个时间是上面计算得来的，一般为当前块时间，允许是当前时间加2小时，以应对网络时间不同步
                // 锁定时间小于这个时间的，不加入块
                if (!IsFinalTx(tx, nHeight, nLockTimeCutoff))
                    continue;
                //签名数量
                unsigned int nTxSigOps = iter->GetSigOpCount();
                //最大签名数量
                unsigned int nMaxBlockSigOps = MaxBlockSigOps(fDIP0001ActiveAtTip);
                if (nBlockSigOps + nTxSigOps >= nMaxBlockSigOps) {
                    if (nBlockSigOps > nMaxBlockSigOps - 2) { //超出最大签名数量
                        break;
                    }
                    continue; //签名数量超了，循环下一个
                }
                //取得交易费用
                CAmount nTxFees = iter->GetFee();
                // Added
                pblock->vtx.push_back(tx);
                pblocktemplate->vTxFees.push_back(nTxFees);
                pblocktemplate->vTxSigOps.push_back(nTxSigOps);
                nBlockSize += nTxSize;  //总内存大小
                ++nBlockTx;//总交易量
                nBlockSigOps += nTxSigOps;//总签名数量
                nFees += nTxFees;//总交易费

                if (fPrintPriority) //打印当前加入的交易的日志
                {
                    double dPriority = iter->GetPriority(nHeight);
                    CAmount dummy;
                    mempool.ApplyDeltas(tx.GetHash(), dPriority, dummy);
                    LogPrintf("priority %.1f fee %s txid %s\n",
                              dPriority , CFeeRate(iter->GetModifiedFee(), nTxSize).ToString(), tx.GetHash().ToString());
                }
                //插入交易
                inBlock.insert(iter);

                // Add transactions that depend on this one to the priority queue
                // 前面有些孤儿交易，当前如果是他的父交易，尝试加入交易池
                BOOST_FOREACH(CTxMemPool::txiter child, mempool.GetMemPoolChildren(iter))
                {
                    if (fPriorityBlock) {
                        waitPriIter wpiter = waitPriMap.find(child);
                        if (wpiter != waitPriMap.end()) {//如果是高优先级交易，继续把子交易返回优先级池子
                            vecPriority.push_back(TxCoinAgePriority(wpiter->second,child));
                            std::push_heap(vecPriority.begin(), vecPriority.end(), pricomparer); //排序
                            waitPriMap.erase(wpiter);
                        }
                    }
                    else {
                        if (waitSet.count(child)) {  //把等待的交易放入  clearedTxs， 而不是删除，因为这些交易是合法的，所以直接进行下一次判断
                            clearedTxs.push(child);
                            waitSet.erase(child);
                        }
                    }
                }
            }
        }

        // NOTE: unlike in bitcoin, we need to pass PREVIOUS block height here
        //计算奖励费，分为两部分，交易费和挖矿费，挖矿费 GetBlockSubsidy 计算，公式比较复杂。
        CAmount blockReward = nFees + GetBlockSubsidy(pindexPrev->nBits, pindexPrev->nHeight, Params().GetConsensus());

        // Compute regular coinbase transaction.
        txNew.vout[0].nValue = blockReward;
        txNew.vin[0].scriptSig = CScript() << nHeight << OP_0;

        // Update coinbase transaction with additional info about masternode and governance payments,
        // get some info back to pass to getblocktemplate
        //执行了3不，如果没有superblock则创建之，否则计算最有主节点费用，从矿工费用中去掉。
        // GetMasternodePayment  blockValue/5  +  blockValue/40 给了主节点   跟块的高度有关  如何选取最优的费用，待调查
        // 当区块高度满足　IsSuperblockTriggered　CreateSuperblock　奖励给　super　如何选取最优的待调查　
        FillBlockPayments(txNew, nHeight, blockReward, pblock->txoutMasternode, pblock->voutSuperblock);
        // LogPrintf("CreateNewBlock -- nBlockHeight %d blockReward %lld txoutMasternode %s txNew %s",
        //             nHeight, blockReward, pblock->txoutMasternode.ToString(), txNew.ToString());

        nLastBlockTx = nBlockTx;
        nLastBlockSize = nBlockSize;
        LogPrintf("CreateNewBlock(): total size %u txs: %u fees: %ld sigops %d\n", nBlockSize, nBlockTx, nFees, nBlockSigOps);

        // Update block coinbase
        pblock->vtx[0] = txNew; //奖励交易，必须是第一个交易
        pblocktemplate->vTxFees[0] = -nFees; //？？？？？？ 为啥是负数 

        // Fill in header
        pblock->hashPrevBlock  = pindexPrev->GetBlockHash();   //填入上一块 hash
        UpdateTime(pblock, chainparams.GetConsensus(), pindexPrev); //重新填入时间 时间为当前时间和上11块的中间时间最大值
        pblock->nBits          = GetNextWorkRequired(pindexPrev, pblock, chainparams.GetConsensus()); //计算 难度系数
        pblock->nNonce         = 0;//重置POW的开始为 0
        pblocktemplate->vTxSigOps[0] = GetLegacySigOpCount(pblock->vtx[0]); //计算 奖励交易的 签名数 有何用 ？？？？

        //重新检查块的合法性 这个流程比较复杂，主要检查时间，前一块，难度系数等等。
        CValidationState state;
        if (!TestBlockValidity(state, chainparams, *pblock, pindexPrev, false, false)) {
            throw std::runtime_error(strprintf("%s: TestBlockValidity failed: %s", __func__, FormatStateMessage(state)));
        }
    }

    return pblocktemplate.release();
}

void IncrementExtraNonce(CBlock* pblock, const CBlockIndex* pindexPrev, unsigned int& nExtraNonce)
{
    // Update nExtraNonce
    static uint256 hashPrevBlock;
    if (hashPrevBlock != pblock->hashPrevBlock)
    {
        nExtraNonce = 0;
        hashPrevBlock = pblock->hashPrevBlock;
    }
    ++nExtraNonce;
    unsigned int nHeight = pindexPrev->nHeight+1; // Height first in coinbase required for block.version=2
    CMutableTransaction txCoinbase(pblock->vtx[0]);
    txCoinbase.vin[0].scriptSig = (CScript() << nHeight << CScriptNum(nExtraNonce)) + COINBASE_FLAGS;
    assert(txCoinbase.vin[0].scriptSig.size() <= 100);

    pblock->vtx[0] = txCoinbase;
    pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
}

//////////////////////////////////////////////////////////////////////////////
//
// Internal miner
//

// ***TODO*** ScanHash is not yet used in Dash
//
// ScanHash scans nonces looking for a hash with at least some zero bits.
// The nonce is usually preserved between calls, but periodically or if the
// nonce is 0xffff0000 or above, the block is rebuilt and nNonce starts over at
// zero.
//
//bool static ScanHash(const CBlockHeader *pblock, uint32_t& nNonce, uint256 *phash)
//{
//    // Write the first 76 bytes of the block header to a double-SHA256 state.
//    CHash256 hasher;
//    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
//    ss << *pblock;
//    assert(ss.size() == 80);
//    hasher.Write((unsigned char*)&ss[0], 76);

//    while (true) {
//        nNonce++;

//        // Write the last 4 bytes of the block header (the nonce) to a copy of
//        // the double-SHA256 state, and compute the result.
//        CHash256(hasher).Write((unsigned char*)&nNonce, 4).Finalize((unsigned char*)phash);

//        // Return the nonce if the hash has at least some zero bits,
//        // caller will check if it has enough to reach the target
//        if (((uint16_t*)phash)[15] == 0)
//            return true;

//        // If nothing found after trying for a while, return -1
//        if ((nNonce & 0xfff) == 0)
//            return false;
//    }
//}

static bool ProcessBlockFound(const CBlock* pblock, const CChainParams& chainparams)
{
    LogPrintf("%s\n", pblock->ToString());
    LogPrintf("generated %s\n", FormatMoney(pblock->vtx[0].vout[0].nValue));

    // Found a solution
    {
        LOCK(cs_main);
        if (pblock->hashPrevBlock != chainActive.Tip()->GetBlockHash())
            return error("ProcessBlockFound -- generated block is stale");
    }

    // Inform about the new block
    GetMainSignals().BlockFound(pblock->GetHash());

    // Process this block the same as if we had received it from another node
    if (!ProcessNewBlock(chainparams, pblock, true, NULL, NULL))
        return error("ProcessBlockFound -- ProcessNewBlock() failed, block not accepted");

    return true;
}

// ***TODO*** that part changed in bitcoin, we are using a mix with old one here for now
//挖矿主执行函数 多线程貌似没有意义吧。
void static BitcoinMiner(int iIndex,const CChainParams& chainparams, CConnman& connman)
{
    LogPrintf("DashMiner -- started %d\n",iIndex);
    SetThreadPriority(THREAD_PRIORITY_LOWEST); //设置线程级别
    RenameThread("dash-miner");  //修改线程名称

    unsigned int nExtraNonce = 0;

    boost::shared_ptr<CReserveScript> coinbaseScript;
    //虚函数，调用到　CWallet::GetScriptForMining　　　CWallet::ReserveKeyFromKeyPool　　从key池中找到有效的一个地址
    // setInternalKeyPool : setExternalKeyPool 两种类型的　　key 池没有弄明白什么区别
    GetMainSignals().ScriptForMining(coinbaseScript);

    try {
        // Throw an error if no script was provided.  This can happen
        // due to some internal error but also if the keypool is empty.
        // In the latter case, already the pointer is NULL.
        // 判断接收奖励的签名是否有效
        if (!coinbaseScript || coinbaseScript->reserveScript.empty())
            throw std::runtime_error("No coinbase script available (mining requires a wallet)");

        while (true) { //循环挖矿  大循环
            // 系统参数，fMiningRequiresPeers　决定挖矿是否检查网络连接，根据　启动网络　main = true testnet = true regnet = false
            if (chainparams.MiningRequiresPeers()) {
                // Busy-wait for the network to come online so we don't waste time mining
                // on an obsolete chain. In regtest mode we expect to fly solo.
                do {
                    //判断连接节点个数　CONNECTIONS_ALL　CONNECTIONS_IN CONNECTIONS_OUT
                    bool fvNodesEmpty = connman.GetNodeCount(CConnman::CONNECTIONS_ALL) == 0;
                    // IsSynced 判断主节点是否同步　CMasternodeSync::SwitchToNextAsset
                    // IsInitialBlockDownload 判断链的末梢是否合法
                    if (!fvNodesEmpty && !IsInitialBlockDownload() && masternodeSync.IsSynced())
                        break;
                    MilliSleep(1000);
                } while (true);
            }


            //
            // Create new block
            //
            //取得内存池中最后交易数量
            unsigned int nTransactionsUpdatedLast = mempool.GetTransactionsUpdated();
            //取得最后一个块
            CBlockIndex* pindexPrev = chainActive.Tip();
            if(!pindexPrev) break;
            //创建新块
            std::unique_ptr<CBlockTemplate> pblocktemplate(CreateNewBlock(chainparams, coinbaseScript->reserveScript));
            if (!pblocktemplate.get())
            {
                LogPrintf("DashMiner -- Keypool ran out, please call keypoolrefill before restarting the mining thread\n");
                return;
            }
            CBlock *pblock = &pblocktemplate->block;
            //填充 扩展 难度基数，根据本hash和上次全局hase 不等则置 0  奖励交易中的 签名跟 nExtraNonce 和区块高度相关。
            //这个里面 因为奖励交易数据变了，所以 BlockMerkleRoot 每次要重新计算
            IncrementExtraNonce(pblock, pindexPrev, nExtraNonce);

            LogPrintf("DashMiner -- Running miner with %u transactions in block (%u bytes)\n", pblock->vtx.size(),
                ::GetSerializeSize(*pblock, SER_NETWORK, PROTOCOL_VERSION));

            //
            // Search
            //开始计算 POW 
            int64_t nStart = GetTime();//
            arith_uint256 hashTarget = arith_uint256().SetCompact(pblock->nBits); //目标hash
            while (true)
            {
                unsigned int nHashesDone = 0;

                uint256 hash;
                while (true)
                {
                    hash = pblock->GetHash();//取得当前hash
                    if (UintToArith256(hash) <= hashTarget) //POW 找到了
                    {
                        // Found a solution
                        SetThreadPriority(THREAD_PRIORITY_NORMAL);
                        LogPrintf("DashMiner:\n  proof-of-work found\n  hash: %s\n  target: %s\n", hash.GetHex(), hashTarget.GetHex());
                        //判断是否接受到新块 放弃
                        //广播块
                        //如同接受到新块一下，处理自己的数据。ProcessNewBlock 这个比较复杂，
                        ProcessBlockFound(pblock, chainparams);
                        SetThreadPriority(THREAD_PRIORITY_LOWEST);
                        //对矿工而言，刷新自己的钱包。
                        coinbaseScript->KeepScript();

                        // In regression test mode, stop mining after a block is found. This
                        // allows developers to controllably generate a block on demand.
                        if (chainparams.MineBlocksOnDemand()) //有可能外部程序停止了挖矿。直接退出挖矿程序
                            throw boost::thread_interrupted();

                        break;
                    }
                    pblock->nNonce += 1;
                    nHashesDone += 1;
                    if ((pblock->nNonce & 0xFF) == 0)//超过 FF 次，进行一下常规检查
                        break;
                }

                // Check for stop or if block needs to be rebuilt  上层会打断当前计算，例如 接收到新块等等
                boost::this_thread::interruption_point();
                // Regtest mode doesn't require peers 没网络连接了
                if (connman.GetNodeCount(CConnman::CONNECTIONS_ALL) == 0 && chainparams.MiningRequiresPeers())
                    break;
                if (pblock->nNonce >= 0xffff0000) //超过总的计数
                    break;
                //60s 没有计算出来，而且接受到新的交易，退出 ？？？？？？
                if (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast && GetTime() - nStart > 60) 
                    break;
                if (pindexPrev != chainActive.Tip())  //接受到新块，前一块已经不是最顶部块了。
                    break;

                // Update nTime every few seconds  重新调整时间，注意 这个函数 测试网络重新计算了 nBits
                if (UpdateTime(pblock, chainparams.GetConsensus(), pindexPrev) < 0)
                    break; // Recreate the block if the clock has run backwards,
                           // so that we can use the correct time.
                if (chainparams.GetConsensus().fPowAllowMinDifficultyBlocks) //测试网络，重新调整难度
                {
                    // Changing pblock->nTime can change work required on testnet:
                    hashTarget.SetCompact(pblock->nBits);
                }
            }
        }
    }
    catch (const boost::thread_interrupted&)
    {
        LogPrintf("DashMiner -- terminated\n");
        throw;
    }
    catch (const std::runtime_error &e)
    {
        LogPrintf("DashMiner -- runtime error: %s\n", e.what());
        return;
    }
}
//挖矿入口
// bool fGenerate,  １　开始　０　结束
// int nThreads,　　　挖矿线程数据
// const CChainParams& chainparams,
// CConnman& connman
// 总共　３　个地方调用
//    程序推出，　fGenerate = 0;
//    命令行　setgenerate　　启动或关闭挖矿
//    主程序初始化　根据　－gen 参数自动启动挖矿
void GenerateBitcoins(bool fGenerate, int nThreads, const CChainParams& chainparams, CConnman& connman)
{
    static boost::thread_group* minerThreads = NULL;  //挖矿线程。

    if (nThreads < 0)
        nThreads = GetNumCores(); // util.cpp 返回物理可支持的线程数

    if (minerThreads != NULL) //停止上次挖矿
    {
        minerThreads->interrupt_all();
        delete minerThreads;
        minerThreads = NULL;
    }

    if (nThreads == 0 || !fGenerate) // 停止挖矿，或者　线程为　０　直接推出
        return;

    minerThreads = new boost::thread_group();  //创建线程池
    for (int i = 0; i < nThreads; i++)  // 根 据 个数创建线程，　主执行函数为　　BitcoinMiner　参数　chainparams　connman
        minerThreads->create_thread(boost::bind(&BitcoinMiner,boost::ref(i),boost::cref(chainparams), boost::ref(connman)));
}
