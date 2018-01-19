// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2014-2017 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "clientversion.h"
#include "rpc/server.h"
#include "init.h"
#include "noui.h"
#include "scheduler.h"
#include "util.h"
#include "masternodeconfig.h"
#include "httpserver.h"
#include "httprpc.h"

#include <boost/algorithm/string/predicate.hpp>
#include <boost/filesystem.hpp>
#include <boost/thread.hpp>

#include <stdio.h>

/* Introduction text for doxygen: */

/*! \mainpage Developer documentation
 *
 * \section intro_sec Introduction
 *
 * This is the developer documentation of the reference client for an experimental new digital currency called Dash (https://www.dash.org/),
 * which enables instant payments to anyone, anywhere in the world. Dash uses peer-to-peer technology to operate
 * with no central authority: managing transactions and issuing money are carried out collectively by the network.
 *
 * The software is a community-driven open source project, released under the MIT license.
 *
 * \section Navigation
 * Use the buttons <code>Namespaces</code>, <code>Classes</code> or <code>Files</code> at the top of the page to start navigating the code.
 */

static bool fDaemon;

void WaitForShutdown(boost::thread_group* threadGroup)
{
    bool fShutdown = ShutdownRequested();
    // Tell the main threads to shutdown.
    while (!fShutdown)
    {
        MilliSleep(200);
        fShutdown = ShutdownRequested();
    }
    if (threadGroup)
    {
        Interrupt(*threadGroup);
        threadGroup->join_all();
    }
}

//////////////////////////////////////////////////////////////////////////////
//
// Start
//
bool AppInit(int argc, char* argv[])
{
    //程序首先定义了一个线程组threadGroup，线程组的功能就是分组管理线程
    boost::thread_group threadGroup;
    // 主要是用来管理后台任务，主要的两个函数是scheduleFromNow和scheduleEvery，分别表示从现在开始是过一段时间执行某函数一次，和从现在开始每隔几秒执行某函数一次。也可创建一个新的线程去执行任务，而不影响主线程的执行。
    CScheduler scheduler;

    bool fRet = false;

    //
    // Parameters
    //
    // If Qt is used, parameters/dash.conf are parsed in qt/dash.cpp's main()
    //拆分命令行参数到  mapArgs    mapMultiArgs 
    ParseParameters(argc, argv);

    // Process help and version before taking care about datadir  帮助
    if (mapArgs.count("-?") || mapArgs.count("-h") ||  mapArgs.count("-help") || mapArgs.count("-version"))
    {
        std::string strUsage = _("Dash Core Daemon") + " " + _("version") + " " + FormatFullVersion() + "\n";

        if (mapArgs.count("-version"))
        {
            strUsage += LicenseInfo();
        }
        else
        {
            strUsage += "\n" + _("Usage:") + "\n" +
                  "  dashd [options]                     " + _("Start Dash Core Daemon") + "\n";

            strUsage += "\n" + HelpMessage(HMM_BITCOIND);
        }

        fprintf(stdout, "%s", strUsage.c_str());
        return true;
    }

    try
    {
        //初始化数据文件路径
        bool datadirFromCmdLine = mapArgs.count("-datadir") != 0;
        if (datadirFromCmdLine && !boost::filesystem::is_directory(GetDataDir(false)))
        {
            fprintf(stderr, "Error: Specified data directory \"%s\" does not exist.\n", mapArgs["-datadir"].c_str());
            return false;
        }
        try
        {
            //读配置信息
            ReadConfigFile(mapArgs, mapMultiArgs);
        } catch (const std::exception& e) {
            fprintf(stderr,"Error reading configuration file: %s\n", e.what());
            return false;
        }
        //判断路径是否合法
        if (!datadirFromCmdLine && !boost::filesystem::is_directory(GetDataDir(false)))
        {
            fprintf(stderr, "Error: Specified data directory \"%s\" from config file does not exist.\n", mapArgs["-datadir"].c_str());
            return EXIT_FAILURE;
        }
        // Check for -testnet or -regtest parameter (Params() calls are only valid after this clause)
        try {
            //设置当前操作类型 网络类型 main testnet regtest
            //由 CChainParams 派生的三个  CMainParams CTestNetParams CRegTestParams 构造函数初始化不一样
            ///Main：表示主网，也就是当前比特币所有用户交易的网络，bitcoind中的默认值。
            //Testnet：测试网，测试网中专门有一条测试链，所有的交易都只是用于测试，并且测试网中的币可以方便的获取，主要目的就是模拟真实交易环境测试新的功能。
            //Regtest：回归测试，又称为私有网，用于个人开发测试，挖矿难度较低，并且参数都可以自行设置
            SelectParams(ChainNameFromCommandLine());
        } catch (const std::exception& e) {
            fprintf(stderr, "Error: %s\n", e.what());
            return false;
        }

        // parse masternode.conf  //读主节点参数 每次
        std::string strErr;
        if(!masternodeConfig.read(strErr)) {
            fprintf(stderr,"Error reading masternode configuration file: %s\n", strErr.c_str());
            return false;
        }

        // Command-line RPC
        // 判断命令行中是否存在错误的参数，判断方法是看每一个参数的第一个字母是否为-或者在windows环境中- or /，如果不是就报错然后退出程序。
        bool fCommandLine = false;
        for (int i = 1; i < argc; i++)
            if (!IsSwitchChar(argv[i][0]) && !boost::algorithm::istarts_with(argv[i], "dash:"))
                fCommandLine = true;

        if (fCommandLine)
        {
            fprintf(stderr, "Error: There is no RPC client functionality in dashd anymore. Use the dash-cli utility instead.\n");
            exit(EXIT_FAILURE);
        }
#ifndef WIN32
        fDaemon = GetBoolArg("-daemon", false);
        if (fDaemon)//后台执行 线程 fork
        {
            fprintf(stdout, "Dash Core server starting\n");

            // Daemonize
            pid_t pid = fork();
            if (pid < 0)
            {
                fprintf(stderr, "Error: fork() returned %d errno %d\n", pid, errno);
                return false;
            }
            if (pid > 0) // Parent process, pid is child process id
            {
                return true;
            }
            // Child process falls through to rest of initialization

            pid_t sid = setsid();
            if (sid < 0)
                fprintf(stderr, "Error: setsid() returned %d errno %d\n", sid, errno);
        }
#endif
        SoftSetBoolArg("-server", true);

        // Set this early so that parameter interactions go to console
        //加载 log的参数 主要是 log 中是否显示时间，ip等等参数
        InitLogging();
        //根据输入参数，转换为内部的参数
        InitParameterInteraction();
        //真正的初始化 
        fRet = AppInit2(threadGroup, scheduler);
    }
    catch (const std::exception& e) {
        PrintExceptionContinue(&e, "AppInit()");
    } catch (...) {
        PrintExceptionContinue(NULL, "AppInit()");
    }

    if (!fRet)
    {   //终端所有线程
        Interrupt(threadGroup);
        // threadGroup.join_all(); was left out intentionally here, because we didn't re-test all of
        // the startup-failure cases to make sure they don't result in a hang due to some
        // thread-blocking-waiting-for-another-thread-during-startup case
    } else { //等待退出
        WaitForShutdown(&threadGroup);
    }//退出
    Shutdown();

    return fRet;
}

int main(int argc, char* argv[])
{
    SetupEnvironment();

    // Connect dashd signal handlers
    noui_connect();

    return (AppInit(argc, argv) ? EXIT_SUCCESS : EXIT_FAILURE);
}
