// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_TRANSACTION_H
#define BITCOIN_PRIMITIVES_TRANSACTION_H

#include "amount.h"
#include "script/script.h"
#include "serialize.h"
#include "uint256.h"

/** An outpoint - a combination of a transaction hash and an index n into its vout 
* COutPoint主要用在交易的输入CTxIn中，用来确定当前输出的来源，
* 包括前一笔交易的hash，以及对应前一笔交易中的第几个输出的序列号。
*/
class COutPoint
{
public:
    uint256 hash;// 交易的哈希
    uint32_t n;// 对应的序列号

    COutPoint() { SetNull(); }
    COutPoint(uint256 hashIn, uint32_t nIn) { hash = hashIn; n = nIn; }

    //定义　　GetSerializeSize  Serialize  Unserialize　实际调用　SerializationOp
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>//数据读写　根据　ser_action　来
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(hash);
        READWRITE(n);
    }

    void SetNull() { hash.SetNull(); n = (uint32_t) -1; }
    bool IsNull() const { return (hash.IsNull() && n == (uint32_t) -1); }

    friend bool operator<(const COutPoint& a, const COutPoint& b)
    {
        return (a.hash < b.hash || (a.hash == b.hash && a.n < b.n));
    }

    friend bool operator==(const COutPoint& a, const COutPoint& b)
    {
        return (a.hash == b.hash && a.n == b.n);
    }

    friend bool operator!=(const COutPoint& a, const COutPoint& b)
    {
        return !(a == b);
    }

    std::string ToString() const;       //hash 加　n
    std::string ToStringShort() const; //hash 前　６４位　加　n
};

/** An input of a transaction.  It contains the location of the previous
 * transaction's output that it claims and a signature that matches the
 * output's public key.
 * 交易的输入，包括当前输入对应前一笔交易的输出的位置，以及花费前一笔输出需要的签名脚本
 * CScriptWitness是用来支持隔离见证时使用的。
 */
class CTxIn
{
public:
    COutPoint prevout;// 前一笔交易输出的位置
    CScript scriptSig;// 解锁脚本
    uint32_t nSequence; // 序列号
    // CScriptWitness scriptWitness;隔离见证

    /* Setting nSequence to this value for every input in a transaction
     * disables nLockTime. 
     * 规则1：如果一笔交易中所有的SEQUENCE_FINAL都被赋值了相应的nSequence，那么nLockTime就会被禁用*/
    static const uint32_t SEQUENCE_FINAL = 0xffffffff;

    /* Below flags apply in the context of BIP 68*/
    /* If this flag set, CTxIn::nSequence is NOT interpreted as a
     * relative lock-time. 
     * 规则2：如果设置了这个变量，那么规则1就失效了*/
    static const uint32_t SEQUENCE_LOCKTIME_DISABLE_FLAG = (1 << 31);

    /* If CTxIn::nSequence encodes a relative lock-time and this flag
     * is set, the relative lock-time has units of 512 seconds,
     * otherwise it specifies blocks with a granularity of 1. 
     * 规则3：如果规则1有效并且设置了此变量，那么相对锁定时间就为512秒，否则锁定时间就为1个区块*/
    static const uint32_t SEQUENCE_LOCKTIME_TYPE_FLAG = (1 << 22);

    /* If CTxIn::nSequence encodes a relative lock-time, this mask is
     * applied to extract that lock-time from the sequence field.  
     * 规则4：如果规则1有效，那么这个变量就用来从nSequence计算对应的锁定时间*/
    static const uint32_t SEQUENCE_LOCKTIME_MASK = 0x0000ffff;

    /* In order to use the same number of bits to encode roughly the
     * same wall-clock duration, and because blocks are naturally
     * limited to occur every 600s on average, the minimum granularity
     * for time-based relative lock-time is fixed at 512 seconds.
     * Converting from CTxIn::nSequence to seconds is performed by
     * multiplying by 512 = 2^9, or equivalently shifting up by
     * 9 bits. */
    static const int SEQUENCE_LOCKTIME_GRANULARITY = 9;

    CTxIn()
    {
        nSequence = SEQUENCE_FINAL;
    }
    // 禁用隐式转换，构造函数必须明确使用当前形式
    explicit CTxIn(COutPoint prevoutIn, CScript scriptSigIn=CScript(), uint32_t nSequenceIn=SEQUENCE_FINAL);
    CTxIn(uint256 hashPrevTx, uint32_t nOut, CScript scriptSigIn=CScript(), uint32_t nSequenceIn=SEQUENCE_FINAL);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(prevout);
        READWRITE(*(CScriptBase*)(&scriptSig));
        READWRITE(nSequence);
    }

    friend bool operator==(const CTxIn& a, const CTxIn& b)
    {
        return (a.prevout   == b.prevout &&
                a.scriptSig == b.scriptSig &&
                a.nSequence == b.nSequence);
    }

    friend bool operator!=(const CTxIn& a, const CTxIn& b)
    {
        return !(a == b);
    }

    friend bool operator<(const CTxIn& a, const CTxIn& b)
    {
        return a.prevout<b.prevout;
    }

    std::string ToString() const;
};

/** An output of a transaction.  It contains the public key that the next input
 * must be able to sign with to claim it.
 * 交易的输出，包含金额和锁定脚本
 */
class CTxOut
{
public:
    CAmount nValue; // 输出金额
    CScript scriptPubKey; // 锁定脚本
    int nRounds;

    CTxOut()
    {
        SetNull();
    }

    CTxOut(const CAmount& nValueIn, CScript scriptPubKeyIn);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(nValue);
        READWRITE(*(CScriptBase*)(&scriptPubKey));
    }

    void SetNull()
    {
        nValue = -1;
        scriptPubKey.clear();
        nRounds = -10; // an initial value, should be no way to get this by calculations
    }

    bool IsNull() const
    {
        return (nValue == -1);
    }

    uint256 GetHash() const;
    // 获取dust阈值，一笔交易如果交易费小于dust阈值，就会被认为是dust tx，   僵尸微小的
    CAmount GetDustThreshold(const CFeeRate &minRelayTxFee) const
    {
        // "Dust" is defined in terms of CTransaction::minRelayTxFee, which has units duffs-per-kilobyte.
        // If you'd pay more than 1/3 in fees to spend something, then we consider it dust.
        // A typical spendable txout is 34 bytes big, and will need a CTxIn of at least 148 bytes to spend
        // i.e. total is 148 + 32 = 182 bytes. Default -minrelaytxfee is 10000 duffs per kB
        // and that means that fee per spendable txout is 182 * 10000 / 1000 = 1820 duffs.
        // So dust is a spendable txout less than 546 * minRelayTxFee / 1000 (in duffs)
        // i.e. 1820 * 3 = 5460 duffs with default -minrelaytxfee = minRelayTxFee = 10000 duffs per kB.
        if (scriptPubKey.IsUnspendable()) // 判断脚本格式是否正确
            return 0;

        size_t nSize = GetSerializeSize(SER_DISK,0)+148u;
        return 3*minRelayTxFee.GetFee(nSize);//out + in  size计算的最小费用 ×3
    }

    bool IsDust(const CFeeRate &minRelayTxFee) const //输出本省比最小费用还小
    {
        return (nValue < GetDustThreshold(minRelayTxFee));
    }

    friend bool operator==(const CTxOut& a, const CTxOut& b)
    {
        return (a.nValue       == b.nValue &&
                a.scriptPubKey == b.scriptPubKey &&
                a.nRounds      == b.nRounds);
    }

    friend bool operator!=(const CTxOut& a, const CTxOut& b)
    {
        return !(a == b);
    }

    std::string ToString() const;
};

struct CMutableTransaction;

/** The basic transaction that is broadcasted on the network and contained in
 * blocks.  A transaction can contain multiple inputs and outputs.
 * 下面就是在网络中广播然后被打包进区块的最基本的交易的结构，一个交易可能包含多个交易输入和输出。
 */
class CTransaction
{
private:
    /** Memory only. */
    const uint256 hash; //交易的hash
    void UpdateHash() const; //根据当前数据，计算当前交易的 hash  CHashWriter

public:
    // Default transaction version. // Default transaction version. 默认交易版本
    static const int32_t CURRENT_VERSION=1;

    // Changing the default transaction version requires a two step process: first
    // adapting relay policy by bumping MAX_STANDARD_VERSION, and then later date
    // bumping the default CURRENT_VERSION at which point both CURRENT_VERSION and
    // MAX_STANDARD_VERSION will be equal.
    static const int32_t MAX_STANDARD_VERSION=2;

    // The local variables are made const to prevent unintended modification
    // without updating the cached hash value. However, CTransaction is not
    // actually immutable; deserialization and assignment are implemented,
    // and bypass the constness. This is safe, as they update the entire
    // structure, including the hash.
    /** 下面这些变量都被定义为常量类型，从而避免无意识的修改了交易而没有更新缓存的hash值；
    * 但还是可以通过重新构造一个交易然后赋值给当前交易来进行修改，这样就更新了交易的所有内容 */
    const int32_t nVersion;// 版本
    const std::vector<CTxIn> vin; // 交易输入
    const std::vector<CTxOut> vout;// 交易输出
    const uint32_t nLockTime;// 锁定时间

    /** Construct a CTransaction that qualifies as IsNull() */
    CTransaction();

    /** Convert a CMutableTransaction into a CTransaction. */
    CTransaction(const CMutableTransaction &tx);

    CTransaction& operator=(const CTransaction& tx);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(*const_cast<int32_t*>(&this->nVersion));
        nVersion = this->nVersion;
        READWRITE(*const_cast<std::vector<CTxIn>*>(&vin));
        READWRITE(*const_cast<std::vector<CTxOut>*>(&vout));
        READWRITE(*const_cast<uint32_t*>(&nLockTime));
        if (ser_action.ForRead()) //如果是读入数据，重新计算 hash 这个不存盘
            UpdateHash();
    }

    bool IsNull() const {
        return vin.empty() && vout.empty();
    }

    const uint256& GetHash() const {
        return hash;
    }

    // Return sum of txouts.// 返回交易输出金额之和 注意比较最大和最小
    CAmount GetValueOut() const;  
    // GetValueIn() is a method on CCoinsViewCache, because
    // inputs must be known to compute value in.

    // Compute priority, given priority of inputs and (optionally) tx size
    // 计算优先级别 CalculateModifiedSize/nTxSize  dPriorityInputs 实际没用。
    double ComputePriority(double dPriorityInputs, unsigned int nTxSize=0) const;

    // Compute modified tx size for priority calculation (optionally given tx size)
    unsigned int CalculateModifiedSize(unsigned int nTxSize=0) const;//计算除常规大小外，所有输入的增量
    
    /**
     * Get the total transaction size in bytes, including witness data.
     * "Total Size" defined in BIP141 and BIP144.
     * @return Total transaction size in bytes
     */
    unsigned int GetTotalSize() const;  //总大小

    bool IsCoinBase() const
    {
        return (vin.size() == 1 && vin[0].prevout.IsNull());
    }

    friend bool operator==(const CTransaction& a, const CTransaction& b)
    {
        return a.hash == b.hash;
    }

    friend bool operator!=(const CTransaction& a, const CTransaction& b)
    {
        return a.hash != b.hash;
    }

    std::string ToString() const;
};

/** A mutable version of CTransaction. */
struct CMutableTransaction
{
    int32_t nVersion;
    std::vector<CTxIn> vin;
    std::vector<CTxOut> vout;
    uint32_t nLockTime;

    CMutableTransaction();
    CMutableTransaction(const CTransaction& tx);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(vin);
        READWRITE(vout);
        READWRITE(nLockTime);
    }

    /** Compute the hash of this CMutableTransaction. This is computed on the
     * fly, as opposed to GetHash() in CTransaction, which uses a cached result.
     */
    uint256 GetHash() const;

    std::string ToString() const;

    friend bool operator==(const CMutableTransaction& a, const CMutableTransaction& b)
    {
        return a.GetHash() == b.GetHash();
    }

    friend bool operator!=(const CMutableTransaction& a, const CMutableTransaction& b)
    {
        return !(a == b);
    }

};

/** Implementation of BIP69
 * https://github.com/bitcoin/bips/blob/master/bip-0069.mediawiki
 */
struct CompareInputBIP69
{
    inline bool operator()(const CTxIn& a, const CTxIn& b) const
    {
        if (a.prevout.hash == b.prevout.hash) return a.prevout.n < b.prevout.n;

        uint256 hasha = a.prevout.hash;
        uint256 hashb = b.prevout.hash;

        typedef std::reverse_iterator<const unsigned char*> rev_it;
        rev_it rita = rev_it(hasha.end());
        rev_it ritb = rev_it(hashb.end());

        return std::lexicographical_compare(rita, rita + hasha.size(), ritb, ritb + hashb.size());
    }
};

struct CompareOutputBIP69
{
    inline bool operator()(const CTxOut& a, const CTxOut& b) const
    {
        return a.nValue < b.nValue || (a.nValue == b.nValue && a.scriptPubKey < b.scriptPubKey);
    }
};

#endif // BITCOIN_PRIMITIVES_TRANSACTION_H
