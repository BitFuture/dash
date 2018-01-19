// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TXMEMPOOL_H
#define BITCOIN_TXMEMPOOL_H

#include <list>
#include <set>

#include "addressindex.h"
#include "spentindex.h"
#include "amount.h"
#include "coins.h"
#include "primitives/transaction.h"
#include "sync.h"

#undef foreach
#include "boost/multi_index_container.hpp"
#include "boost/multi_index/ordered_index.hpp"

class CAutoFile;
class CBlockIndex;

inline double AllowFreeThreshold()
{
    return COIN * 144 / 250;
}

inline bool AllowFree(double dPriority)
{
    // Large (in bytes) low-priority (new, small-coin) transactions
    // need a fee.
    return dPriority > AllowFreeThreshold();
}


/** Fake height value used in Coin to signify they are only in the memory pool (since 0.8) */
static const uint32_t MEMPOOL_HEIGHT = 0x7FFFFFFF; //交易池的最大高度

struct LockPoints
{
    // Will be set to the blockchain height and median time past
    // values that would be necessary to satisfy all relative locktime
    // constraints (BIP68) of this tx given our view of block chain history
    int height;  //区块高度
    int64_t time;//区块时间  
    // As long as the current chain descends from the highest height block
    // containing one of the inputs used in the calculation, then the cached
    // values are still valid even after a reorg.
    CBlockIndex* maxInputBlock;

    LockPoints() : height(0), time(0), maxInputBlock(NULL) { }
};

class CTxMemPool;

/** \class CTxMemPoolEntry
 *
 * CTxMemPoolEntry stores data about the correponding transaction, as well
 * as data about all in-mempool transactions that depend on the transaction
 * ("descendant" transactions).
 *
 * When a new entry is added to the mempool, we update the descendant state
 * (nCountWithDescendants, nSizeWithDescendants, and nModFeesWithDescendants) for
 * all ancestors of the newly added transaction.
 *
 * If updating the descendant state is skipped, we can mark the entry as
 * "dirty", and set nSizeWithDescendants/nModFeesWithDescendants to equal nTxSize/
 * nFee+feeDelta. (This can potentially happen during a reorg, where we limit the
 * amount of work we're willing to do to avoid consuming too much CPU.)
 *
 */
/** 
 * CTxMemPoolEntry存储交易和该交易的所有子孙交易，
 * 当一个新的entry添加到mempool中时，我们更新它的所有子孙状态
 * 和祖先状态
 */
class CTxMemPoolEntry
{
private:
    CTransaction tx;   //交易
    CAmount nFee; //交易费用 //! Cached to avoid expensive parent-transaction lookups
    size_t nTxSize; //大小 //! ... and avoid recomputing tx size
    size_t nModSize; //修改大小 ! ... and modified size for priority
    size_t nUsageSize; //内存大小  ! ... and total memory usage
    int64_t nTime; //时间戳 加入交易池的本地时间  ! Local time when entering the mempool
    double entryPriority; //加入时候的优先级别  //! Priority when entering the mempool
    unsigned int entryHeight; //区块高度 ! Chain height when entering the mempool
    bool hadNoDependencies; //! Not dependent on any other txs when it entered the mempool
    CAmount inChainInputValue; //! Sum of all txin values that are already in blockchain
    bool spendsCoinbase;  //前一个交易是否是CoinBase 本交易是否为消费 挖矿奖励 //! keep track of transactions that spend a coinbase
    unsigned int sigOpCount; //! Legacy sig ops plus P2SH sig op count
    int64_t feeDelta;  //主要为调整交易优先级别的费用，并不计算在奖励费用中 //! Used for determining the priority of the transaction for mining in a block
    LockPoints lockPoints; //交易最后的所在区块高度和打包的时间 //! Track the height and time at which tx was final

    // Information about descendants of this transaction that are in the
    // mempool; if we remove this transaction we must remove all of these
    // descendants as well.  if nCountWithDescendants is 0, treat this entry as
    // dirty, and nSizeWithDescendants and nModFeesWithDescendants will not be
    // correct.
    // 子孙交易信息，如果我们移除一个交易，必须同时移除它的所有子孙交易   子孙就是依赖于自己的所有交易 
    uint64_t nCountWithDescendants;  // 子孙交易的数量//! number of descendant transactions
    uint64_t nSizeWithDescendants;  // 大小//! ... and size
    CAmount nModFeesWithDescendants;  // 费用和，包括当前交易 //! ... and total fees (all including us)


// 祖先交易信息
    //uint64_t nCountWithAncestors;
    //uint64_t nSizeWithAncestors;
    //CAmount nModFeesWithAncestors;
    //int64_t nSigOpCostWithAncestors;

public:
    CTxMemPoolEntry(const CTransaction& _tx, const CAmount& _nFee,
                    int64_t _nTime, double _entryPriority, unsigned int _entryHeight,
                    bool poolHasNoInputsOf, CAmount _inChainInputValue, bool spendsCoinbase,
                    unsigned int nSigOps, LockPoints lp);
    CTxMemPoolEntry(const CTxMemPoolEntry& other);

    const CTransaction& GetTx() const { return this->tx; }
    /**
     * Fast calculation of lower bound of current priority as update
     * from entry priority. Only inputs that were originally in-chain will age.
     */
    double GetPriority(unsigned int currentHeight) const;
    const CAmount& GetFee() const { return nFee; }
    size_t GetTxSize() const { return nTxSize; }
    int64_t GetTime() const { return nTime; }
    unsigned int GetHeight() const { return entryHeight; }
    bool WasClearAtEntry() const { return hadNoDependencies; }
    unsigned int GetSigOpCount() const { return sigOpCount; }
    int64_t GetModifiedFee() const { return nFee + feeDelta; }
    size_t DynamicMemoryUsage() const { return nUsageSize; }
    const LockPoints& GetLockPoints() const { return lockPoints; }

    // Adjusts the descendant state, if this entry is not dirty.  // 更新子孙状态
    void UpdateState(int64_t modifySize, CAmount modifyFee, int64_t modifyCount);
    // Updates the fee delta used for mining priority score, and the
    // modified fees with descendants.  // 更新feeDelta，并且修改子孙交易费用
    void UpdateFeeDelta(int64_t feeDelta);
    // Update the LockPoints after a reorg  // 更新LockPoint
    void UpdateLockPoints(const LockPoints& lp);

    /** We can set the entry to be dirty if doing the full calculation of in-
     *  mempool descendants will be too expensive, which can potentially happen
     *  when re-adding transactions from a block back to the mempool.
     */
    //清空，当一个交易重新从 块中退回的时候，必须清空，否则子孙数据越来越大
    void SetDirty();
    bool IsDirty() const { return nCountWithDescendants == 0; }

    uint64_t GetCountWithDescendants() const { return nCountWithDescendants; }
    uint64_t GetSizeWithDescendants() const { return nSizeWithDescendants; }
    CAmount GetModFeesWithDescendants() const { return nModFeesWithDescendants; }

    bool GetSpendsCoinbase() const { return spendsCoinbase; }
};

// Helpers for modifying CTxMemPool::mapTx, which is a boost multi_index.
struct update_descendant_state //工具，用于跟新某笔交易的子孙信息
{
    update_descendant_state(int64_t _modifySize, CAmount _modifyFee, int64_t _modifyCount) :
        modifySize(_modifySize), modifyFee(_modifyFee), modifyCount(_modifyCount)
    {}

    void operator() (CTxMemPoolEntry &e)
        { e.UpdateState(modifySize, modifyFee, modifyCount); }

    private:
        int64_t modifySize;
        CAmount modifyFee;
        int64_t modifyCount;
};

struct set_dirty
{
    void operator() (CTxMemPoolEntry &e)
        { e.SetDirty(); }
};

struct update_fee_delta
{
    update_fee_delta(int64_t _feeDelta) : feeDelta(_feeDelta) { }

    void operator() (CTxMemPoolEntry &e) { e.UpdateFeeDelta(feeDelta); }

private:
    int64_t feeDelta;
};

struct update_lock_points
{
    update_lock_points(const LockPoints& _lp) : lp(_lp) { }

    void operator() (CTxMemPoolEntry &e) { e.UpdateLockPoints(lp); }

private:
    const LockPoints& lp;
};

// extracts a TxMemPoolEntry's transaction hash
struct mempoolentry_txid
{
    typedef uint256 result_type;
    result_type operator() (const CTxMemPoolEntry &entry) const
    {
        return entry.GetTx().GetHash();
    }
};

/** \class CompareTxMemPoolEntryByDescendantScore
 *
 *  Sort an entry by max(score/size of entry's tx, score/size with all descendants).
 */
class CompareTxMemPoolEntryByDescendantScore
{
public:
    bool operator()(const CTxMemPoolEntry& a, const CTxMemPoolEntry& b)
    {
        bool fUseADescendants = UseDescendantScore(a);//使用子孙数据比较，自己数据比较
        bool fUseBDescendants = UseDescendantScore(b);

        double aModFee = fUseADescendants ? a.GetModFeesWithDescendants() : a.GetModifiedFee();
        double aSize = fUseADescendants ? a.GetSizeWithDescendants() : a.GetTxSize();

        double bModFee = fUseBDescendants ? b.GetModFeesWithDescendants() : b.GetModifiedFee();
        double bSize = fUseBDescendants ? b.GetSizeWithDescendants() : b.GetTxSize();

        // Avoid division by rewriting (a/b > c/d) as (a*d > c*b).
        double f1 = aModFee * bSize;   //注意 坑爹呀，看了半天，本来应该用除法，改成用乘法比较，防止除 0 
        double f2 = aSize * bModFee;

        if (f1 == f2) {
            return a.GetTime() >= b.GetTime();
        }
        return f1 < f2;
    }

    // Calculate which score to use for an entry (avoiding division).
    bool UseDescendantScore(const CTxMemPoolEntry &a)
    {
        // Avoid division by rewriting (a/b > c/d) as (a*d > c*b).
        double f1 = (double)a.GetModifiedFee() * a.GetSizeWithDescendants();  //除法，用乘法搞了
        double f2 = (double)a.GetModFeesWithDescendants() * a.GetTxSize();
        return f2 > f1;
    }
};

/** \class CompareTxMemPoolEntryByScore
 *
 *  Sort by score of entry ((fee+delta)/size) in descending order
 */
class CompareTxMemPoolEntryByScore
{
public:
    bool operator()(const CTxMemPoolEntry& a, const CTxMemPoolEntry& b)
    {
        // Avoid division by rewriting (a/b > c/d) as (a*d > c*b).
        double f1 = (double)a.GetModifiedFee() * b.GetTxSize(); //除法，用乘法搞了
        double f2 = (double)b.GetModifiedFee() * a.GetTxSize(); //注意 a b 交换乘除
        if (f1 == f2) {
            return b.GetTx().GetHash() < a.GetTx().GetHash();
        }
        return f1 > f2;
    }
};

class CompareTxMemPoolEntryByEntryTime
{
public:
    bool operator()(const CTxMemPoolEntry& a, const CTxMemPoolEntry& b)
    {
        return a.GetTime() < b.GetTime();
    }
};

class CBlockPolicyEstimator;

/** An inpoint - a combination of a transaction and an index n into its vin */
class CInPoint
{
public:
    const CTransaction* ptx;
    uint32_t n;

    CInPoint() { SetNull(); }
    CInPoint(const CTransaction* ptxIn, uint32_t nIn) { ptx = ptxIn; n = nIn; }
    void SetNull() { ptx = NULL; n = (uint32_t) -1; }
    bool IsNull() const { return (ptx == NULL && n == (uint32_t) -1); }
    size_t DynamicMemoryUsage() const { return 0; }
};

class SaltedTxidHasher
{
private:
    /** Salt */
    const uint64_t k0, k1;

public:
    SaltedTxidHasher();

    size_t operator()(const uint256& txid) const {
        return SipHashUint256(k0, k1, txid);
    }
};

/**
 * CTxMemPool stores valid-according-to-the-current-best-chain
 * transactions that may be included in the next block.
 * 交易池保留从网络上手机或自己产生，即将写入块的数据
 * Transactions are added when they are seen on the network
 * (or created by the local node), but not all transactions seen
 * are added to the pool: if a new transaction double-spends
 * an input of a transaction in the pool, it is dropped,
 * 重复交易将删除
 * as are non-standard transactions.
 *
 * CTxMemPool::mapTx, and CTxMemPoolEntry bookkeeping:
 *
 * mapTx is a boost::multi_index that sorts the mempool on 4 criteria: 
 * 交易的四种排序模式
 * - transaction hash
 * - feerate [we use max(feerate of tx, feerate of tx with all descendants)]
 * - time in mempool
 * - mining score (feerate modified by any fee deltas from PrioritiseTransaction)
 *
 * Note: the term "descendant" refers to in-mempool transactions that depend on
 * 子孙代表本交易在内存池之后依赖于自己的交易
 * this one, while "ancestor" refers to in-mempool transactions that a given
 * transaction depends on.
 * 祖先交易是交易池中自己依赖的交易 。 被继承人
 *
 * In order for the feerate sort to remain correct, we must update transactions
 * in the mempool when new descendants arrive.  To facilitate this, we track
 * the set of in-mempool direct parents and direct children in mapLinks.  Within
 * each CTxMemPoolEntry, we track the size and fees of all descendants.
 * 在交易池中，保留子孙和祖先的交易链，并随时更新费用。
 * Usually when a new transaction is added to the mempool, it has no in-mempool
 * children (because any such children would be an orphan).  So in
 * addUnchecked(), we:
 * - update a new entry's setMemPoolParents to include all in-mempool parents
 * - update the new entry's direct parents to include the new tx as a child
 * - update all ancestors of the transaction to include the new tx's size/fee
 *  当添加一个交易的时候，自己创建一个祖先池，更新上一个祖先中的子孙为自己，更新所有祖先的费用。
 * 
 * When a transaction is removed from the mempool, we must:
 * - update all in-mempool parents to not track the tx in setMemPoolChildren
 * - update all ancestors to not include the tx's size/fees in descendant state
 * - update all in-mempool children to not include it as a parent
 * //删除一个交易，跟上面的交易动作相反。
 * 
 * These happen in UpdateForRemoveFromMempool().  (Note that when removing a
 * transaction along with its descendants, we must calculate that set of
 * transactions to be removed before doing the removal, or else the mempool can
 * be in an inconsistent state where it's impossible to walk the ancestors of
 * a transaction.)
 * 
 * 注意删除一个交易的时候，必须先干更新动作，否则交易池混乱。
 *
 * In the event of a reorg, the assumption that a newly added tx has no
 * in-mempool children is false.  In particular, the mempool is in an
 * inconsistent state while new transactions are being added, because there may
 * be descendant transactions of a tx coming from a disconnected block that are
 * unreachable from just looking at transactions in the mempool (the linking
 * transactions may also be in the disconnected block, waiting to be added).
 * Because of this, there's not much benefit in trying to search for in-mempool
 * children in addUnchecked().  Instead, in the special case of transactions
 * being added from a disconnected block, we require the caller to clean up the
 * state, to account for in-mempool, out-of-block descendants for all the
 * in-block transactions by calling UpdateTransactionsFromBlock().  Note that
 * until this is called, the mempool state is not consistent, and in particular
 * mapLinks may not be correct (and therefore functions like
 * CalculateMemPoolAncestors() and CalculateDescendants() that rely
 * on them to walk the mempool are not generally safe to use).
 * 注意有一种特殊情况，儿子先到，父亲后到，这个时候，需要重现更新整个父子链及其费用
 * Computational limits:
 *
 * Updating all in-mempool ancestors of a newly added transaction can be slow,
 * if no bound exists on how many in-mempool ancestors there may be.
 * CalculateMemPoolAncestors() takes configurable limits that are designed to
 * prevent these calculations from being too CPU intensive.
 * 更新父子链比较费时间，所以 
 * Adding transactions from a disconnected block can be very time consuming,
 * because we don't have a way to limit the number of in-mempool descendants.
 * To bound CPU processing, we limit the amount of work we're willing to do
 * to properly update the descendant information for a tx being added from
 * a disconnected block.  If we would exceed the limit, then we instead mark
 * the entry as "dirty", and set the feerate for sorting purposes to be equal
 * the feerate of the transaction without any descendants.
 * 从一个块中退回交易，这个块可能是不被接受的，比较费时间，设置了个限制值，如果超个这个值，就不计算子孙费用，而设置为 dirty
 */

/**
 * 交易内存池，保存所有在当前主链上有效的交易。
 * 当交易在网络上广播之后，就会被加进交易池。
 * 但并不是所有的交易都会被加入，
 * 例如交易费太小的，或者“双花”的交易或者非标准交易。
 * 内存池中通过一个boost::multi_index类型的变量mapTx来排序所有交易，
 * 按照下面四个标准：
 * -交易hash
 * -交易费（包括所有子孙交易）
 * -在mempool中的时间
 * -挖矿分数
 * 为了保证交易费的正确性，当新交易被加进mempool时，我们必须更新
 * 该交易的所有祖先交易信息，而这个操作可能会导致处理速度变慢，
 * 所以必须对更需祖先的数量进行限制。
 */
class CTxMemPool
{
private:
    uint32_t nCheckFrequency; //表示在2^32时间内检查的次数 //! Value n means that n times in 2^32 we check.
    unsigned int nTransactionsUpdated;
    CBlockPolicyEstimator* minerPolicyEstimator;

    uint64_t totalTxSize; //! sum of all mempool tx' byte sizes  //所有mempool中交易的虚拟大小， 
    uint64_t cachedInnerUsage; //map中元素使用的动态内存大小之和 //! sum of dynamic memory usage of all the map elements (NOT the maps themselves)

    CFeeRate minReasonableRelayFee;

    mutable int64_t lastRollingFeeUpdate;
    mutable bool blockSinceLastRollingFeeBump;
    mutable double rollingMinimumFeeRate; //! minimum fee to get into the pool, decreases exponentially

    void trackPackageRemoved(const CFeeRate& rate);

public:

    static const int ROLLING_FEE_HALFLIFE = 60 * 60 * 12; // public only for testing

    typedef boost::multi_index_container<
        CTxMemPoolEntry,
        boost::multi_index::indexed_by<
            // sorted by txid
            boost::multi_index::ordered_unique<mempoolentry_txid>,
            // sorted by fee rate 自己后面积累的子孙交易越多，挖矿级别就越高
            boost::multi_index::ordered_non_unique<
                boost::multi_index::identity<CTxMemPoolEntry>,
                CompareTxMemPoolEntryByDescendantScore
            >,
            // sorted by entry time
            boost::multi_index::ordered_non_unique<
                boost::multi_index::identity<CTxMemPoolEntry>,
                CompareTxMemPoolEntryByEntryTime
                >,
            // sorted by score (for mining prioritization)
            boost::multi_index::ordered_unique<
                boost::multi_index::identity<CTxMemPoolEntry>,
                CompareTxMemPoolEntryByScore
            >
        >
    > indexed_transaction_set;

    mutable CCriticalSection cs;
    indexed_transaction_set mapTx;
    typedef indexed_transaction_set::nth_index<0>::type::iterator txiter;
    struct CompareIteratorByHash {
        bool operator()(const txiter &a, const txiter &b) const {
            return a->GetTx().GetHash() < b->GetTx().GetHash();
        }
    };
    typedef std::set<txiter, CompareIteratorByHash> setEntries;

    const setEntries & GetMemPoolParents(txiter entry) const;// 返回某个交易的祖先
    const setEntries & GetMemPoolChildren(txiter entry) const;// 返回某个交易的子孙
private:
    typedef std::map<txiter, setEntries, CompareIteratorByHash> cacheMap;//二级列表

    struct TxLinks {
        setEntries parents;
        setEntries children;
    };

    typedef std::map<txiter, TxLinks, CompareIteratorByHash> txlinksMap;//交易的父子链表
    txlinksMap mapLinks;

    typedef std::map<CMempoolAddressDeltaKey, CMempoolAddressDelta, CMempoolAddressDeltaKeyCompare> addressDeltaMap;
    addressDeltaMap mapAddress;

    typedef std::map<uint256, std::vector<CMempoolAddressDeltaKey> > addressDeltaMapInserted;
    addressDeltaMapInserted mapAddressInserted;

    typedef std::map<CSpentIndexKey, CSpentIndexValue, CSpentIndexKeyCompare> mapSpentIndex;
    mapSpentIndex mapSpent;

    typedef std::map<uint256, std::vector<CSpentIndexKey> > mapSpentIndexInserted;
    mapSpentIndexInserted mapSpentInserted;

    void UpdateParent(txiter entry, txiter parent, bool add);
    void UpdateChild(txiter entry, txiter child, bool add);

public:
    std::map<COutPoint, CInPoint> mapNextTx;
    std::map<uint256, std::pair<double, CAmount> > mapDeltas;

    /** Create a new CTxMemPool.
     *  minReasonableRelayFee should be a feerate which is, roughly, somewhere
     *  around what it "costs" to relay a transaction around the network and
     *  below which we would reasonably say a transaction has 0-effective-fee.
     */
    CTxMemPool(const CFeeRate& _minReasonableRelayFee);
    ~CTxMemPool();

    /**
     * If sanity-checking is turned on, check makes sure the pool is
     * consistent (does not contain two transactions that spend the same inputs,
     * all inputs are in the mapNextTx array). If sanity-checking is turned off,
     * check does nothing.
     */
    /**
     * 如果开启了sanity-check，那么check函数将会保证pool的一致性，
     * 即不包含双花交易，所有的输入都在mapNextTx数组中。
     * 如果关闭了sanity-check,那么check函数什么都不做
     */
    void check(const CCoinsViewCache *pcoins) const;
    void setSanityCheck(double dFrequency = 1.0) { nCheckFrequency = dFrequency * 4294967295.0; }

    // addUnchecked must updated state for all ancestors of a given transaction,
    // to track size/count of descendant transactions.  First version of
    // addUnchecked can be used to have it call CalculateMemPoolAncestors(), and
    // then invoke the second version.
    /**
     * addUnchecked函数必须首先更新交易的祖先交易状态，
     * 第一个addUnchecked函数可以用来调用CalculateMemPoolAncestors(),
     * 然后调用第二个addUnchecked
     */
    bool addUnchecked(const uint256& hash, const CTxMemPoolEntry &entry, bool fCurrentEstimate = true);
    bool addUnchecked(const uint256& hash, const CTxMemPoolEntry &entry, setEntries &setAncestors, bool fCurrentEstimate = true);

    void addAddressIndex(const CTxMemPoolEntry &entry, const CCoinsViewCache &view);
    bool getAddressIndex(std::vector<std::pair<uint160, int> > &addresses,
                         std::vector<std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta> > &results);
    bool removeAddressIndex(const uint256 txhash);

    void addSpentIndex(const CTxMemPoolEntry &entry, const CCoinsViewCache &view);
    bool getSpentIndex(CSpentIndexKey &key, CSpentIndexValue &value);
    bool removeSpentIndex(const uint256 txhash);

    void remove(const CTransaction &tx, std::list<CTransaction>& removed, bool fRecursive = false);
    void removeForReorg(const CCoinsViewCache *pcoins, unsigned int nMemPoolHeight, int flags);
    void removeConflicts(const CTransaction &tx, std::list<CTransaction>& removed);
    void removeForBlock(const std::vector<CTransaction>& vtx, unsigned int nBlockHeight,
                        std::list<CTransaction>& conflicts, bool fCurrentEstimate = true);
    void clear();
    void _clear(); //lock free
    void queryHashes(std::vector<uint256>& vtxid);
    bool isSpent(const COutPoint& outpoint);
    unsigned int GetTransactionsUpdated() const;
    void AddTransactionsUpdated(unsigned int n);
    /**
     * Check that none of this transactions inputs are in the mempool, and thus
     * the tx is not dependent on other mempool transactions to be included in a block.
     */
     /**
     * 检查交易的输入是否在当前的mempool中
     */
    bool HasNoInputsOf(const CTransaction& tx) const;

    /** Affect CreateNewBlock prioritisation of transactions */
    void PrioritiseTransaction(const uint256 hash, const std::string strHash, double dPriorityDelta, const CAmount& nFeeDelta);
    void ApplyDeltas(const uint256 hash, double &dPriorityDelta, CAmount &nFeeDelta) const;
    void ClearPrioritisation(const uint256 hash);

public:
    /** Remove a set of transactions from the mempool.
     *  If a transaction is in this set, then all in-mempool descendants must
     *  also be in the set.*/
    /** 
     *  从mempool中移除一个交易集合，
     *  如果一个交易在这个集合中，那么它的所有子孙交易都必须在集合中，
     *  除非该交易已经被打包到区块中。
     *  如果要移除一个已经被打包到区块中的交易，
     *  那么要把updateDescendants设为true，
     *  从而更新mempool中所有子孙节点的祖先信息
     */
    void RemoveStaged(setEntries &stage);

    /** When adding transactions from a disconnected block back to the mempool,
     *  new mempool entries may have children in the mempool (which is generally
     *  not the case when otherwise adding transactions).
     *  UpdateTransactionsFromBlock() will find child transactions and update the
     *  descendant state for each transaction in hashesToUpdate (excluding any
     *  child transactions present in hashesToUpdate, which are already accounted
     *  for).  Note: hashesToUpdate should be the set of transactions from the
     *  disconnected block that have been accepted back into the mempool.
     */
     /** 
     *  从竞争失败的Block中更新交易信息到mempool
     */
    void UpdateTransactionsFromBlock(const std::vector<uint256> &hashesToUpdate);

    /** Try to calculate all in-mempool ancestors of entry.
     *  (these are all calculated including the tx itself)
     *  limitAncestorCount = max number of ancestors
     *  limitAncestorSize = max size of ancestors
     *  limitDescendantCount = max number of descendants any ancestor can have
     *  limitDescendantSize = max size of descendants any ancestor can have
     *  errString = populated with error reason if any limits are hit
     *  fSearchForParents = whether to search a tx's vin for in-mempool parents, or
     *    look up parents from mapLinks. Must be true for entries not in the mempool
     */
        /** 计算mempool中所有entry的祖先
     *  limitAncestorCount = 最大祖先数量
     *  limitAncestorSize = 最大祖先交易大小
     *  limitDescendantCount = 任意祖先的最大子孙数量
     *  limitDescendantSize = 任意祖先的最大子孙大小
     *  errString = 超过了任何limit限制的错误提示
     *  fSearchForParents = 是否在mempool中搜索交易的输入，
     *  或者从mapLinks中查找，对于不在mempool中的entry必须设为true
     */
    bool CalculateMemPoolAncestors(const CTxMemPoolEntry &entry, setEntries &setAncestors, uint64_t limitAncestorCount, uint64_t limitAncestorSize, uint64_t limitDescendantCount, uint64_t limitDescendantSize, std::string &errString, bool fSearchForParents = true);

    /** Populate setDescendants with all in-mempool descendants of hash.
     *  Assumes that setDescendants includes all in-mempool descendants of anything
     *  already in it.  */
    void CalculateDescendants(txiter it, setEntries &setDescendants);

    /** The minimum fee to get into the mempool, which may itself not be enough
      *  for larger-sized transactions.
      *  The minReasonableRelayFee constructor arg is used to bound the time it
      *  takes the fee rate to go back down all the way to 0. When the feerate
      *  would otherwise be half of this, it is set to 0 instead.
      */
        /** 
      *  返回进入mempool需要的最小交易费，
      *  incrementalRelayFee变量用来限制feerate降到0所需的时间。
      */
    CFeeRate GetMinFee(size_t sizelimit) const;
    void UpdateMinFee(const CFeeRate& _minReasonableRelayFee);

    /** Remove transactions from the mempool until its dynamic size is <= sizelimit.
      *  pvNoSpendsRemaining, if set, will be populated with the list of outpoints
      *  which are not in mempool which no longer have any spends in this mempool.
      */
    /** 
      *  移除所有动态大小超过sizelimit的交易，
      *  如果传入了pvNoSpendsRemaining，那么将返回不在mempool中并且也没有
      *  任何输出在mempool的交易列表
      */
    void TrimToSize(size_t sizelimit, std::vector<COutPoint>* pvNoSpendsRemaining=NULL);

    /** Expire all transaction (and their dependencies) in the mempool older than time. Return the number of removed transactions. */
    /**
    * 移除所有在time之前的交易和它的子孙交易，
    * 返回移除的数量
    */
    int Expire(int64_t time);

    unsigned long size()
    {
        LOCK(cs);
        return mapTx.size();
    }

    uint64_t GetTotalTxSize()
    {
        LOCK(cs);
        return totalTxSize;
    }

    bool exists(uint256 hash) const
    {
        LOCK(cs);
        return (mapTx.count(hash) != 0);
    }

    bool exists(const COutPoint& outpoint) const
    {
        LOCK(cs);
        auto it = mapTx.find(outpoint.hash);
        return (it != mapTx.end() && outpoint.n < it->GetTx().vout.size());
    }

    bool lookup(uint256 hash, CTransaction& result) const;

    /** Estimate fee rate needed to get into the next nBlocks
     *  If no answer can be given at nBlocks, return an estimate
     *  at the lowest number of blocks where one can be given
     */
    CFeeRate estimateSmartFee(int nBlocks, int *answerFoundAtBlocks = NULL) const;

    /** Estimate fee rate needed to get into the next nBlocks */
    CFeeRate estimateFee(int nBlocks) const;

    /** Estimate priority needed to get into the next nBlocks
     *  If no answer can be given at nBlocks, return an estimate
     *  at the lowest number of blocks where one can be given
     */
    double estimateSmartPriority(int nBlocks, int *answerFoundAtBlocks = NULL) const;

    /** Estimate priority needed to get into the next nBlocks */
    double estimatePriority(int nBlocks) const;
    
    /** Write/Read estimates to disk */
    bool WriteFeeEstimates(CAutoFile& fileout) const;
    bool ReadFeeEstimates(CAutoFile& filein);

    size_t DynamicMemoryUsage() const;

private:
    /** UpdateForDescendants is used by UpdateTransactionsFromBlock to update
     *  the descendants for a single transaction that has been added to the
     *  mempool but may have child transactions in the mempool, eg during a
     *  chain reorg.  setExclude is the set of descendant transactions in the
     *  mempool that must not be accounted for (because any descendants in
     *  setExclude were added to the mempool after the transaction being
     *  updated and hence their state is already reflected in the parent
     *  state).
     *
     *  If updating an entry requires looking at more than maxDescendantsToVisit
     *  transactions, outside of the ones in setExclude, then give up.
     *
     *  cachedDescendants will be updated with the descendants of the transaction
     *  being updated, so that future invocations don't need to walk the
     *  same transaction again, if encountered in another transaction chain.
     */
       /** UpdateForDescendants 是被 UpdateTransactionsFromBlock 调用，
     * 用来更新被加入pool中的单个交易的子孙节节点；
     * setExclude 是内存池中不用更新的子孙交易集合 (because any descendants in
     *  setExclude were added to the mempool after the transaction being
     *  updated and hence their state is already reflected in the parent
     *  state).
     *
     *  当子孙交易被更新时，cachedDescendants也同时更新
     */
    bool UpdateForDescendants(txiter updateIt,
            int maxDescendantsToVisit,
            cacheMap &cachedDescendants,
            const std::set<uint256> &setExclude);
    /** Update ancestors of hash to add/remove it as a descendant transaction. */
    void UpdateAncestorsOf(bool add, txiter hash, setEntries &setAncestors);
    /** For each transaction being removed, update ancestors and any direct children. */
     /** 对于每一个要移除的交易，更新它的祖先和直接的儿子。
      * 如果updateDescendants 设为 true, 那么还同时更新mempool中子孙的祖先状态
    */
    void UpdateForRemoveFromMempool(const setEntries &entriesToRemove);
    /** Sever link between specified transaction and direct children. */
    void UpdateChildrenForRemoval(txiter entry);

    /** Before calling removeUnchecked for a given transaction,
     *  UpdateForRemoveFromMempool must be called on the entire (dependent) set
     *  of transactions being removed at the same time.  We use each
     *  CTxMemPoolEntry's setMemPoolParents in order to walk ancestors of a
     *  given transaction that is removed, so we can't remove intermediate
     *  transactions in a chain before we've updated all the state for the
     *  removal.
     */
        /** 对于一个特定的交易，调用 removeUnchecked 之前，
     * 必须为同时为要移除的交易集合调用UpdateForRemoveFromMempool。
     *  我们使用每个CTxMemPoolEntry中的setMemPoolParents来遍历
     *  要移除交易的祖先，这样能保证我们更新的正确性。
     */
    void removeUnchecked(txiter entry);
};

/** 
 * CCoinsView that brings transactions from a memorypool into view.
 * It does not check for spendings by memory pool transactions.
 */
class CCoinsViewMemPool : public CCoinsViewBacked
{
protected:
    CTxMemPool &mempool;

public:
    CCoinsViewMemPool(CCoinsView *baseIn, CTxMemPool &mempoolIn);
    bool GetCoin(const COutPoint &outpoint, Coin &coin) const override;
};

// We want to sort transactions by coin age priority
typedef std::pair<double, CTxMemPool::txiter> TxCoinAgePriority;

struct TxCoinAgePriorityCompare
{
    bool operator()(const TxCoinAgePriority& a, const TxCoinAgePriority& b)
    {
        if (a.first == b.first)
            return CompareTxMemPoolEntryByScore()(*(b.second), *(a.second)); //Reverse order to make sort less than
        return a.first < b.first;
    }
};

#endif // BITCOIN_TXMEMPOOL_H
