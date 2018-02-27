// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_PARAMS_H
#define BITCOIN_CONSENSUS_PARAMS_H

#include "uint256.h"
#include <map>
#include <string>
//共识参数
namespace Consensus {

enum DeploymentPos
{
    DEPLOYMENT_TESTDUMMY,
    DEPLOYMENT_CSV, // Deployment of BIP68, BIP112, and BIP113.
    DEPLOYMENT_DIP0001, // Deployment of DIP0001 and lower transaction fees.
    // NOTE: Also add new deployments to VersionBitsDeploymentInfo in versionbits.cpp
    MAX_VERSION_BITS_DEPLOYMENTS
};

/**
 * Struct for each individual consensus rule change using BIP9.
 */
struct BIP9Deployment {
    /** Bit position to select the particular bit in nVersion. */
    int bit;
    /** Start MedianTime for version bits miner confirmation. Can be a date in the past */
    int64_t nStartTime;
    /** Timeout/expiry MedianTime for the deployment attempt. */
    int64_t nTimeout;
    /** The number of past blocks (including the block under consideration) to be taken into account for locking in a fork. */
    int64_t nWindowSize;
    /** A number of blocks, in the range of 1..nWindowSize, which must signal for a fork in order to lock it in. */
    int64_t nThreshold;
};

/**
 * Parameters that influence chain consensus.
 */
/**
 * 影响共识的参数
 */
struct Params {
    uint256 hashGenesisBlock;// 创世区块的hash
    int nSubsidyHalvingInterval;//矿工奖励递减的高度间隔 dash为一年减少 /14
    int nMasternodePaymentsStartBlock; //主节点开始奖励的块高度
    int nMasternodePaymentsIncreaseBlock;//主节点递减参数
    int nMasternodePaymentsIncreasePeriod; //主节点递减参数  in blocks
    int nInstantSendKeepLock; // 快速交易锁定区块高度  in blocks
    int nBudgetPaymentsStartBlock;//
    int nBudgetPaymentsCycleBlocks;//每隔30天奖励一次
    int nBudgetPaymentsWindowBlocks;
    int nBudgetProposalEstablishingTime; // in seconds
    int nSuperblockStartBlock;
    int nSuperblockCycle; // in blocks
    int nGovernanceMinQuorum; // Min absolute vote count to trigger an action
    int nGovernanceFilterElements;
    int nMasternodeMinimumConfirmations;
    /** Used to check majorities for block version upgrade */
    int nMajorityEnforceBlockUpgrade;  //对块，往前数1000个，当950个版本都大于某个值的时候，矿工该升级了
    int nMajorityRejectBlockOutdated;
    int nMajorityWindow;
    /** Block height and hash at which BIP34 becomes active */
    int     BIP34Height;  //到某个高度，这个标准激活
    uint256 BIP34Hash;
    /**
     * Minimum blocks including miner confirmation of the total of nMinerConfirmationWindow blocks in a retargetting period,
     * (nPowTargetTimespan / nPowTargetSpacing) which is also used for BIP9 deployments.
     * Default BIP9Deployment::nThreshold value for deployments where it's not specified and for unknown deployments.
     * Examples: 1916 for 95%, 1512 for testchains.
     */
      /**
     * 在2016个区块中至少要有多少个区块被矿工确认，规则改变才能生效
     * 在BIP9上线时还使用(nPowTargetTimespan / nPowTargetSpacing)值
     * Examples: 1916 for 95%, 1512 for testchains.
     */
    uint32_t nRuleChangeActivationThreshold;
    // Default BIP9Deployment::nWindowSize value for deployments where it's not specified and for unknown deployments.
    uint32_t nMinerConfirmationWindow;
    BIP9Deployment vDeployments[MAX_VERSION_BITS_DEPLOYMENTS];
    /** Proof of work parameters */
    /** POW参数 */
    uint256 powLimit;// 最小难度
    bool fPowAllowMinDifficultyBlocks;//是否允许最低难度
    bool fPowNoRetargeting;// 不调整难度
    int64_t nPowTargetSpacing; // 区块产生平均时间   2.5 * 60
    int64_t nPowTargetTimespan;// 难度调整时间 一天 
    int nPowKGWHeight;
    int nPowDGWHeight;
    int64_t DifficultyAdjustmentInterval() const { return 10;}//nPowTargetTimespan / nPowTargetSpacing; } //每1天调整一次难度
    uint256 nMinimumChainWork;// 当前难度最小值  有效区块，必须包含这个
    uint256 defaultAssumeValid; // 在此区块之前的区块都认为是有效的
};
} // namespace Consensus

#endif // BITCOIN_CONSENSUS_PARAMS_H
