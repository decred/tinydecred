"""
Copyright (c) 2019-2020, the Decred developers
See LICENSE for details
"""

import configparser
import os
import platform
from urllib.parse import urlunsplit

from appdirs import AppDirs
from base58 import b58decode
import pytest

from decred import DecredError
from decred.crypto import crypto, opcode
from decred.dcr import account, rpc, txscript
from decred.dcr.nets import mainnet
from decred.dcr.wire import wire
from decred.dcr.wire.msgblock import BlockHeader
from decred.dcr.wire.msgtx import MsgTx, OutPoint, TxIn, TxOut
from decred.util.encode import ByteArray


@pytest.fixture
def config():
    dcrdCfgDir = appDataDir("dcrd")
    cfgPath = os.path.join(dcrdCfgDir, "dcrd.conf")
    if not os.path.isfile(cfgPath):
        return None
    cfg = readINI(cfgPath, ["rpcuser", "rpcpass", "rpccert"])
    assert "rpcuser" in cfg
    assert "rpcpass" in cfg
    if "rpccert" not in cfg:
        cfg["rpccert"] = os.path.join(dcrdCfgDir, "rpc.cert")
    if "rpclisten" not in cfg:
        cfg["rpclisten"] = "localhost:9109"
    return cfg


def appDataDir(appName):
    """
    appDataDir returns an operating system specific directory to be used for
    storing application data for an application.
    """
    if appName == "" or appName == ".":
        return "."

    # The caller really shouldn't prepend the appName with a period, but
    # if they do, handle it gracefully by stripping it.
    appName = appName.lstrip()
    appNameUpper = appName.capitalize()
    appNameLower = appName.lower()

    # Get the OS specific home directory.
    homeDir = os.path.expanduser("~")

    # Fall back to standard HOME environment variable that works
    # for most POSIX OSes.
    if homeDir == "":
        homeDir = os.getenv("HOME")

    opSys = platform.system()
    if opSys == "Windows":
        # Windows XP and before didn't have a LOCALAPPDATA, so fallback
        # to regular APPDATA when LOCALAPPDATA is not set.
        return AppDirs(appNameUpper, "").user_data_dir

    elif opSys == "Darwin":
        if homeDir != "":
            return os.path.join(homeDir, "Library", "Application Support", appNameUpper)

    else:
        if homeDir != "":
            return os.path.join(homeDir, "." + appNameLower)

    # Fall back to the current directory if all else fails.
    return "."


def readINI(path, keys):
    """
    Attempt to read the specified keys from the INI-formatted configuration
    file. All sections will be searched. A dict with discovered keys and
    values will be returned. If a key is not discovered, it will not be
    present in the result.

    Args:
        path (str): The path to the INI configuration file.
        keys (list(str)): Keys to search for.

    Returns:
        dict: Discovered keys and values.
    """
    config = configparser.ConfigParser()
    # Need to add a section header since configparser doesn't handle sectionless
    # INI format.
    with open(path) as f:
        config.read_string("[tinydecred]\n" + f.read())  # This line does the trick.
    res = {}
    for section in config.sections():
        for k in config[section]:
            if k in keys:
                res[k] = config[section][k]
    return res


mainnetAddress = "Dcur2mcGjmENx4DhNqDctW5wJCVyT3Qeqkx"
cookedAddress1 = "DcurAwesomeAddressmqDctW5wJCW1Cn2MF"
cookedAddress2 = "DcurAwesomeAddress2mqDcW5wJCW5qZcwR"
testnetAddress = "Tsf5Qvq2m7X5KzTZDdSGfa6WrMtikYVRkaL"
genesisHash = "298e5cc3d985bfe7f81dc135f360abe089edd4396b86d2de66b0cef42b21d980"
blkHash414000 = "000000000000000018744e708a39ad6e0cc22a85d5b902aa2067c9cd0002df85"
blkHex414000 = ByteArray(
    "07000000cb70ddef95b52344e53c8d10f2cf5f759ca94d6264d1730f00000000000000009"
    "cab4438cbce0635b7e7f44871ac652d8a441cbc9901f1d22cb9a28c4eb167f79c27184a06"
    "c3872a80da71ff2e7a62cc3e02bd93f901aed177dfa3a86a6ca1e7010053b03c164919050"
    "00100ee9f0000e1fe261872887a770300000030510600120c0000a9b01a5e6c9bfb02a8ba"
    "390000000000a1002c1e00000000000000000000000000000000000000000700000002010"
    "00000010000000000000000000000000000000000000000000000000000000000000000ff"
    "ffffff00ffffffff03f6e78b0900000000000017a914f5916158e3e2c4551c1796708db83"
    "67207ed13bb87000000000000000000000e6a0c3051060003c1928662fdda55cf8b473900"
    "00000000001976a9149c417596dea6570f8e546674555b5ce5087ce2c288ac00000000000"
    "0000001bf57d3420000000000000000ffffffff0800002f646372642f010000000200d572"
    "27426e5297d679f906b2c65875de6d719a82c3ee8e7cc47d59a0e8786f0100000000fffff"
    "fff97dc3c26d6a3f72361bc2b7030c904af7373b2ab5d5c978f64593801c0588269020000"
    "0001ffffffff02dafc7a770300000000001976a91422ff09aa4ea4f6e3ffc7b331672fd63"
    "6fd1c665188acb87c69350200000000001976a9149f1b8139e8cae1006291ad7186695b27"
    "fb23d95b88ac00000000000000000232a4c1800200000010500600010000006a473044022"
    "0202f00a957498ab111256b8c0c973c6a36ca794a91e4cc60ab5a41e3ef1152c40220691e"
    "7e38b6f0c9d1d71e7da39e1b940d24ba4d5e24c0e5d7b944837ca656a19d012103fad0e73"
    "1e1ff2cbeb14f719a24141a9da80883df6959a3385d0ea680ca2bfc0fbee5222c03000000"
    "d04f0600010000006b483045022100bfd18d5a2f13043573207ad791638c4426c08157598"
    "ef56de1489c5fb404899f022038584094e6fe4c9c379fb6e03907129932d5db683095a208"
    "e84af0a7bb8e66c7012103f52c4396a8d8071cba230123f5c6609d53ba5f54a00ebb7a791"
    "0a55b822e47dd060100000002000000000000000000000000000000000000000000000000"
    "0000000000000000ffffffff00ffffffff7ea7d47d96ee371a5186ad28135dc4b61fe7973"
    "b4dc4c127b79382abd782d9400000000001ffffffff0400000000000000000000266a24cb"
    "70ddef95b52344e53c8d10f2cf5f759ca94d6264d1730f00000000000000002f510600000"
    "00000000000000000086a0605000700000055a80d000000000000001abb76a914b62c959a"
    "4679d2e7a1c3b0bbd6bc2d6f089de41d88ac347d3d650300000000001abb76a914536df39"
    "865f62aa4d9a613832348c3bc4c91e52688ac000000000000000002fa57ba050000000000"
    "000000ffffffff02000090cd905f03000000c84b060007000000904730440220161c5111d"
    "1188dae0e914909f304df7b5e8377871e69a5a187c6b7951dcca92502203619707c8b9540"
    "cbecfcc4287c87c48eeaf04078c39e688782f66a76a512b4560147512102013e4fc36e66d"
    "972656893f535c58436e824fa059cff8601e3f5ca2dcf9b84872103b7b2ad51ffec3c398f"
    "b086b5ab33b340d157dfa06c7a5d81f4a8b10b782ea17952ae01000000020000000000000"
    "000000000000000000000000000000000000000000000000000ffffffff00ffffffffaac6"
    "a7c5fc816fb1f7ab82b82c7b456a8ecd33226582bab577bbcb028b82864a0000000001fff"
    "fffff0400000000000000000000266a24cb70ddef95b52344e53c8d10f2cf5f759ca94d62"
    "64d1730f00000000000000002f51060000000000000000000000086a06010007000000d6a"
    "90e000000000000001abb76a914dec58da703b22db9cf49aaa2e7607a105ff069a788ac21"
    "aa56e30200000000001abb76a91427f6d95ea9b0fc8610d2d0e2e8cb10e65692ea4388ac0"
    "00000000000000002fa57ba050000000000000000ffffffff020000fefbaadd02000000ab"
    "2506000800000090473044022000db34151c90822452eb621788bd56bdc63dc59fc5a2806"
    "0467b4747480ad991022023b1988981035900da5ea3868d53c152f1a5b5c998ed8eb6f184"
    "9ad3d006ffa60147512103aab5939a5ad1ab077685923948264404fb7e4c97aaabfb5f589"
    "e4ca01c2be404210353dadbb8256fdefeb1c87615bbe3d7edf56ea65c81a008fdbd04ea38"
    "14e8bdc752ae0100000002000000000000000000000000000000000000000000000000000"
    "0000000000000ffffffff00ffffffff6a52113799f12fed6e6156360b489e2e66fc3426b1"
    "8be746cb1429bfe5e36fd40000000001ffffffff0400000000000000000000266a24cb70d"
    "def95b52344e53c8d10f2cf5f759ca94d6264d1730f00000000000000002f510600000000"
    "00000000000000086a060500060000002c3007000000000000001abb76a914618b33042a2"
    "7deb9e9d0488fa29e988382b1df1788ac33929a690300000000001abb76a914edcfaa864b"
    "529b0a1a0e3fb6280375956412bd0c88ac000000000000000002fa57ba050000000000000"
    "000ffffffff020000666ae763030000003f4c06000900000090473044022016ccbef0747f"
    "8f5e2ab3ceae27695d80718cc8759b6ab784c776cece549400e9022028eba09e6a2b599dc"
    "7e70c13b3267d5d4fe672a38c336f733d15a769c37f2cd50147512102eec9f3402b21ae2e"
    "3b0cea2224cfc89367364c0d4845e9343c437969934eff0a2103d1a56bc0d12ea1feed4d1"
    "b823c48b168ca46aa200797fd67f306d7e96d25bb7252ae01000000020000000000000000"
    "000000000000000000000000000000000000000000000000ffffffff00ffffffff0cba83f"
    "42d1414c405679f785f1d846bef5f93a5406457210da6b52f553263490000000001ffffff"
    "ff0400000000000000000000266a24cb70ddef95b52344e53c8d10f2cf5f759ca94d6264d"
    "1730f00000000000000002f51060000000000000000000000086a06050006000000c0c01c"
    "000000000000001abb76a91414362cb17eb0295c03b051aad6abd87e31bd2fd088ac6bc95"
    "03a0300000000001abb76a9141e641ed8bea20aa48ce7a638ef762bca10d56ee188ac0000"
    "00000000000002fa57ba050000000000000000ffffffff0200003232b334030000008d480"
    "600050000009047304402200779af2b51306f4ef9df707304bd1bdf46353749d030016b1c"
    "2141ca973fa105022013340c7da04c84612f3055a70ea1ba0896b7521b6a847a8a41658d6"
    "b9d52eb1801475121023259b72bbb675b34cb0ad519d3f8bc5f58bd0ee4aec8a4d248c204"
    "a926c953e22102be3864d8c7264baa1ef75e3fccb1697ab9a403f6e95ff11614a7fb22af3"
    "c5c0f52ae0100000002000000000000000000000000000000000000000000000000000000"
    "0000000000ffffffff00ffffffff599a46230a60f4badf6b337a67e9d7c2976b9b8a515dd"
    "f33e2c29a730ecd10930000000001ffffffff0300000000000000000000266a24cb70ddef"
    "95b52344e53c8d10f2cf5f759ca94d6264d1730f00000000000000002f510600000000000"
    "00000000000086a060100070000001025ee400300000000001abb76a9146f7923dac6be87"
    "7b8dffb68545a8e52d4ba1f5cc88ac000000000000000002fa57ba050000000000000000f"
    "fffffff02000016cd333b03000000c2370600060000006a47304402201c8ca8a892f65f0d"
    "d153e64215bdd5ff929860a74bde6e5aa979f6ad090f524302201c341e99cd86ad01a55c7"
    "ab9d617c6a43def69ace9423e7f9d4ce82643aeeef9012103d1433ac74aeb3760b0204084"
    "413cb399137b198ee4e49ff76aa9ba4781ec074d010000000173e6b981dc21cd8a7e98ca2"
    "939dfc0659a6a34d0420189ee170a99cee51deaa80000000000ffffffff0359e2ce7f0300"
    "000000001aba76a914d4885aa8a0bba3cc42e3658a02fd480e7ec71e3d88ac00000000000"
    "000000000206a1e6e517e91b0a127a81da551bcd3fbe60693031880fdedce7f0300000000"
    "58000000000000000000001abd76a91400000000000000000000000000000000000000008"
    "8ac000000000000000001fdedce7f030000002f510600030000006a473044022056823401"
    "556cae48d4062c917a7680a543822c5004ebb98d3860379414769a4402207427fbdb4959f"
    "c8e916712ccd4d5f9afa7a899de70376a782d7d8cd7cfb4388e01210385542c90a6730e42"
    "2ef73f8829e3ce0962c82aa38f9edb2aa46dee7863bb3046"
)
blkHash414005 = "0000000000000000053ca8eb8b5d82bc3e2dc82bded27de2150cb48da02e8899"
cFilter414000 = ByteArray(
    "0000000e590860091d85960f114d2e457d101825e82c901465e94aa768191dcae08475a842086ad954d6"
)
cFilterHeader414000 = ByteArray(
    "412f12ed5bd92df6a8b17cf396697cd44d84ada67f5ca3b1c3f23f3b7619984b"
)
blkHeader414002 = ByteArray(
    "07000000b8b8539315eb883c775cc3ef9ba0dface4dfb89def7b381a0000000000000000e"
    "f88a529674708a1496018fcfa68d5f3be9036c361d84577e26d70d81d0af00bcaf745f2a8"
    "a2ea5f1553fb5d279da82ef24d16266827607550928aec70337b890100494e62d0e3c7050"
    "00c00f89f0000e1fe261872887a770300000032510600f3200000d2b41a5e1861aaa200d1"
    "5401faab664fe1200080000000000000000000000000000000000000000007000000"
)
ownedAddress = "DsUxwT6Kbiur6Nps9q3uGEpJCvrhcxX2nii"
signedMessage = (
    "H166ndZLNEpIXrcEm4V9lf+AizRp/ejCAhs21J/ht87/RK0QFnOscCbJixKok3oHjpOS0jAkJ"
    "4jFktqMXD59LU8="
)
message = "this decred is tiny"
nonsense = "asdf"


def test_Client(config):
    if config is None:
        pytest.skip("did not locate a dcrd config file")
    rpcClient = rpc.Client(
        urlunsplit(("https", config["rpclisten"], "/", "", "")),
        config["rpcuser"],
        config["rpcpass"],
        config["rpccert"],
    )

    stringify = rpc.stringify
    assert stringify(ByteArray("face")) == "cefa"
    assert stringify([ByteArray("face"), ByteArray("baadf00d")]) == ["cefa", "0df0adba"]
    assert stringify("face") == "face"
    assert stringify(["face", "baadf00d"]) == ["face", "baadf00d"]
    alist = [ByteArray("face"), "baadf00d", ByteArray("deadbeef")]
    alistReversed = ["cefa", "baadf00d", "efbeadde"]
    assert set(stringify((b for b in alist))) == set((s for s in alistReversed))
    assert stringify(
        [
            ByteArray("face"),
            (ByteArray("badd"), "d00d", ByteArray("babe")),
            [alist, [alist], [alist, alist, [alist]]],
            [ByteArray("feed"), ByteArray("1100")],
            set({"hey": ByteArray("1234"), "there": ByteArray("4321")}.keys()),
            ByteArray("baadf00d"),
        ]
    ) == [
        "cefa",
        ("ddba", "d00d", "beba"),
        [
            ["cefa", "baadf00d", "efbeadde"],
            [["cefa", "baadf00d", "efbeadde"]],
            [
                ["cefa", "baadf00d", "efbeadde"],
                ["cefa", "baadf00d", "efbeadde"],
                [["cefa", "baadf00d", "efbeadde"]],
            ],
        ],
        ["edfe", "0011"],
        {"there", "hey"},
        "0df0adba",
    ]

    debugLevel = rpcClient.debugLevel("show")
    assert isinstance(debugLevel, str)

    debugLevel = rpcClient.debugLevel("info")
    assert debugLevel == "Done."

    estimateFee = rpcClient.estimateFee()
    assert isinstance(estimateFee, int)

    estimateSmartFee = rpcClient.estimateSmartFee(32)
    assert isinstance(estimateSmartFee, int)

    estimateStakeDiff = rpcClient.estimateStakeDiff(0)
    assert isinstance(estimateStakeDiff, rpc.EstimateStakeDiffResult)

    existsAddress = rpcClient.existsAddress(mainnetAddress)
    assert existsAddress

    existsAddress = rpcClient.existsAddress(cookedAddress1)
    assert not existsAddress

    existsAddresses = rpcClient.existsAddresses(
        [
            cookedAddress1,
            cookedAddress2,
            mainnetAddress,
            cookedAddress2,
            cookedAddress1,
            cookedAddress2,
            mainnetAddress,
        ]
    )
    assert existsAddresses == [False, False, True, False, False, False, True]

    liveTickets = rpcClient.liveTickets()
    assert isinstance(liveTickets, list)

    aTicket = liveTickets[0]

    for ticket in liveTickets:
        getRawTransaction = rpcClient.getRawTransaction(ticket)

        script = getRawTransaction.txOut[0].pkScript

        if txscript.extractStakeScriptHash(script, opcode.OP_SSTX):
            decodeScript = rpcClient.decodeScript(script)
            assert isinstance(decodeScript, rpc.DecodeScriptResult)
            break

    else:
        raise DecredError("did not find a suitable script to decode")

    existsExpiredTickets = rpcClient.existsExpiredTickets([aTicket, aTicket])
    assert existsExpiredTickets == [False, False]

    bestBlock = rpcClient.getBestBlock()
    assert isinstance(bestBlock, rpc.GetBestBlockResult)

    blockchainInfo = rpcClient.getBlockchainInfo()
    assert isinstance(blockchainInfo, rpc.GetBlockChainInfoResult)

    getAddedNodeInfo = rpcClient.getAddedNodeInfo(True)
    assert isinstance(getAddedNodeInfo, list)

    getAddedNodeInfo = rpcClient.getAddedNodeInfo(False)
    assert isinstance(getAddedNodeInfo, list)

    getBestBlockHash = rpcClient.getBestBlockHash()
    assert isinstance(getBestBlockHash, ByteArray)

    getBlock = rpcClient.getBlock(blkHash414000, False)
    assert getBlock == blkHex414000

    getBlock = rpcClient.getBlock(blkHash414000)
    assert isinstance(getBlock, rpc.GetBlockVerboseResult)

    getBlock = rpcClient.getBlock(blkHash414000, True, True)
    assert isinstance(getBlock, rpc.GetBlockVerboseResult)

    getBlockCount = rpcClient.getBlockCount()
    assert isinstance(getBlockCount, int)

    getBlockHash = rpcClient.getBlockHash(0)
    assert getBlockHash == reversed(ByteArray(genesisHash))

    getBlockHeader = rpcClient.getBlockHeader(blkHash414000)
    assert isinstance(getBlockHeader, rpc.GetBlockHeaderVerboseResult)

    getBlockHeader = rpcClient.getBlockHeader(blkHash414000, False)
    assert isinstance(getBlockHeader, BlockHeader)

    getBlockSubsidy = rpcClient.getBlockSubsidy(414500, 5)
    assert isinstance(getBlockSubsidy, rpc.GetBlockSubsidyResult)

    getCFilter = rpcClient.getCFilter(blkHash414000, "extended")
    assert getCFilter == cFilter414000

    getCFilterHeader = rpcClient.getCFilterHeader(blkHash414000, "extended")
    assert getCFilterHeader == cFilterHeader414000

    getCFilterV2 = rpcClient.getCFilterV2(blkHash414000)
    assert isinstance(getCFilterV2, rpc.GetCFilterV2Result)

    getChainTips = rpcClient.getChainTips()
    assert isinstance(getChainTips[0], rpc.GetChainTipsResult)

    getCoinSupply = rpcClient.getCoinSupply()
    assert isinstance(getCoinSupply, int)

    getConnectionCount = rpcClient.getConnectionCount()
    assert isinstance(getConnectionCount, int)

    getCurrentNet = rpcClient.getCurrentNet()
    assert isinstance(getCurrentNet, int)

    getDifficulty = rpcClient.getDifficulty()
    assert isinstance(getDifficulty, float)

    getGenerate = rpcClient.getGenerate()
    assert isinstance(getGenerate, bool)

    getHashesPerSec = rpcClient.getHashesPerSec()
    assert isinstance(getHashesPerSec, int)

    getInfo = rpcClient.getInfo()
    assert isinstance(getInfo, rpc.InfoChainResult)

    getMempoolInfo = rpcClient.getMempoolInfo()
    assert isinstance(getMempoolInfo, rpc.GetMempoolInfoResult)

    getMiningInfo = rpcClient.getMiningInfo()
    assert isinstance(getMiningInfo, rpc.GetMiningInfoResult)

    getNetTotals = rpcClient.getNetTotals()
    assert isinstance(getNetTotals, rpc.GetNetTotalsResult)

    getNetworkHashPS = rpcClient.getNetworkHashPS()
    assert isinstance(getNetworkHashPS, int)

    getNetworkInfo = rpcClient.getNetworkInfo()
    assert isinstance(getNetworkInfo, rpc.GetNetworkInfoResult)

    getPeerInfo = rpcClient.getPeerInfo()
    assert isinstance(getPeerInfo[0], rpc.GetPeerInfoResult)

    getRawMempool = rpcClient.getRawMempool()
    assert isinstance(getRawMempool, list)
    mempoolTx = getRawMempool[0]

    existsMempoolTxs = rpcClient.existsMempoolTxs(getRawMempool[:3] + [aTicket])
    assert existsMempoolTxs == [True, True, True, False]

    getRawMempool = rpcClient.getRawMempool(True)
    assert isinstance(
        getRawMempool[reversed(mempoolTx).hex()], rpc.GetRawMempoolVerboseResult
    )

    getHeaders = rpcClient.getHeaders([blkHash414000], blkHash414005)
    assert blkHeader414002 in [header.serialize() for header in getHeaders]

    # This test will fail if --addrindex is not enabled in dcrd.
    getRawTransaction = rpcClient.getRawTransaction(aTicket)
    assert isinstance(getRawTransaction, MsgTx)

    decodeRawTransaction = rpcClient.decodeRawTransaction(getRawTransaction)
    assert isinstance(decodeRawTransaction, rpc.RawTransactionResult)

    rawaddr = txscript.extractStakeScriptHash(
        getRawTransaction.txOut[0].pkScript, opcode.OP_SSTX
    )
    if rawaddr:
        addressWithTickets = crypto.AddressScriptHash(
            mainnet.ScriptHashAddrID, rawaddr
        ).string()
    else:
        rawaddr = txscript.extractStakePubKeyHash(
            getRawTransaction.txOut[0].pkScript, opcode.OP_SSTX
        )
        addressWithTickets = crypto.AddressPubKeyHash(
            mainnet.PubKeyHashAddrID, rawaddr
        ).string()

    getRawTransaction = rpcClient.getRawTransaction(aTicket, 1)
    assert isinstance(getRawTransaction, rpc.RawTransactionResult)

    getStakeDifficulty = rpcClient.getStakeDifficulty()
    assert isinstance(getStakeDifficulty, rpc.GetStakeDifficultyResult)

    getStakeVersionInfo = rpcClient.getStakeVersionInfo()
    assert isinstance(getStakeVersionInfo, rpc.GetStakeVersionInfoResult)

    getStakeVersions = rpcClient.getStakeVersions(blkHash414000, 3)
    assert isinstance(getStakeVersions[0], rpc.GetStakeVersionsResult)

    getTicketPoolValue = rpcClient.getTicketPoolValue()
    assert isinstance(getTicketPoolValue, float)

    getVoteInfo = rpcClient.getVoteInfo(7)
    assert isinstance(getVoteInfo, rpc.GetVoteInfoResult)

    # getWork will fail if --mininaddr is not set when starting dcrd
    # getWork = rpcClient.getWork()
    # assert isinstance(getWork, rpc.GetWorkResult)

    dcrdHelp = rpcClient.help()
    assert isinstance(dcrdHelp, str)

    dcrdHelp = rpcClient.help("getinfo")
    assert isinstance(dcrdHelp, str)

    missedTickets = rpcClient.missedTickets()
    assert isinstance(missedTickets, list)

    revocableTicket = rpcClient.getRawTransaction(missedTickets[0])

    # create a ticket revoking transaction using txscript
    revocation = txscript.makeRevocation(revocableTicket, 3000)
    createRawSSRTx = rpcClient.createRawSSRTx(revocableTicket, 3000)

    # ours is just missing the block index
    revocation.txIn[0].blockIndex = createRawSSRTx.txIn[0].blockIndex
    assert createRawSSRTx.txHex() == revocation.txHex()

    # Using the revocation as an unspent output
    amt = revocableTicket.txOut[0].value
    script = revocableTicket.txOut[0].pkScript

    utxo = account.UTXO(
        address="",
        txHash=revocableTicket.hash(),
        vout=0,
        ts=None,
        scriptPubKey=script,
        satoshis=1,
        maturity=0,
        tinfo=None,
    )
    utxo2 = account.UTXO(
        address="",
        txHash=revocableTicket.hash(),
        vout=0,
        ts=None,
        scriptPubKey=script,
        satoshis=amt,
        maturity=0,
        tinfo=None,
    )
    amount = {cookedAddress2: amt + 1}

    zeroed = ByteArray(b"", length=20)
    changeAddr = crypto.newAddressPubKeyHash(
        zeroed, mainnet, crypto.STEcdsaSecp256k1
    ).string()
    # only the first argument for couts is a non-zero value
    cout = rpc.COut(
        addr=mainnetAddress, commitAmt=0, changeAddr=changeAddr, changeAmt=0,
    )

    op = OutPoint(txHash=revocableTicket.hash(), idx=0, tree=wire.TxTreeStake)
    inputPool = txscript.ExtendedOutPoint(op=op, amt=1, pkScript=script,)
    inputMain = txscript.ExtendedOutPoint(op=op, amt=amt, pkScript=script,)
    ticketAddr = crypto.newAddressScriptHashFromHash(
        ByteArray(b58decode(cookedAddress2)[2:-4]), mainnet
    )
    mainAddr = crypto.newAddressScriptHashFromHash(
        ByteArray(b58decode(mainnetAddress)[2:-4]), mainnet
    )

    # create a ticket purchasing transaction using txscript
    ticketPurchase = txscript.makeTicket(
        mainnet, inputPool, inputMain, ticketAddr, mainAddr, amt + 1, mainAddr, 0
    )
    createRawSSTx = rpcClient.createRawSSTx([utxo, utxo2], amount, [cout, cout])

    # ours is just missing the block index
    ticketPurchase.txIn[0].blockIndex = createRawSSTx.txIn[0].blockIndex
    ticketPurchase.txIn[1].blockIndex = createRawSSTx.txIn[1].blockIndex
    assert createRawSSTx.txHex() == ticketPurchase.txHex()

    amount = {mainnetAddress: amt}
    txIn = TxIn(previousOutPoint=op, valueIn=amt)
    txOut = TxOut(value=amt, version=0, pkScript=txscript.payToAddrScript(mainAddr),)
    rawTx = MsgTx(
        serType=wire.TxSerializeFull,
        version=1,
        txIn=[txIn],
        txOut=[txOut],
        lockTime=0,
        expiry=0,
        cachedHash=None,
    )

    createRawTransaction = rpcClient.createRawTransaction([utxo2], amount)

    rawTx.txIn[0].blockIndex = createRawTransaction.txIn[0].blockIndex
    assert createRawTransaction.txHex() == rawTx.txHex()

    getTxOut = rpcClient.getTxOut(missedTickets[0], 0)
    assert isinstance(getTxOut, rpc.GetTxOutResult)

    existsLiveTicket = rpcClient.existsLiveTicket(liveTickets[0])
    assert existsLiveTicket

    existsLiveTicket = rpcClient.existsLiveTicket(missedTickets[0])
    assert not existsLiveTicket

    existsLiveTickets = rpcClient.existsLiveTickets(
        liveTickets[:5] + missedTickets[:1] + liveTickets[:2]
    )
    assert existsLiveTickets == [True, True, True, True, True, False, True, True]

    existsMissedTickets = rpcClient.existsMissedTickets(missedTickets[:8])
    assert existsMissedTickets == [True for _ in range(8)]

    rpcClient.ping()

    searchRawTransactions = rpcClient.searchRawTransactions(mainnetAddress)
    assert isinstance(searchRawTransactions[0], rpc.RawTransactionResult)

    searchRawTransactions = rpcClient.searchRawTransactions(mainnetAddress, 0)
    assert isinstance(searchRawTransactions[0], MsgTx)

    ticketFeeInfo = rpcClient.ticketFeeInfo()
    assert isinstance(ticketFeeInfo, rpc.TicketFeeInfoResult)

    ticketFeeInfo = rpcClient.ticketFeeInfo(5, 5)
    assert isinstance(ticketFeeInfo, rpc.TicketFeeInfoResult)

    ticketsForAddress = rpcClient.ticketsForAddress(addressWithTickets)
    assert aTicket in ticketsForAddress

    ticketVWAP = rpcClient.ticketVWAP()
    assert isinstance(ticketVWAP, float)

    ticketVWAP = rpcClient.ticketVWAP(414500)
    assert isinstance(ticketVWAP, float)

    ticketVWAP = rpcClient.ticketVWAP(414500, 414510)
    assert isinstance(ticketVWAP, float)

    txFeeInfo = rpcClient.txFeeInfo()
    assert isinstance(txFeeInfo, rpc.TxFeeInfoResult)

    txFeeInfo = rpcClient.txFeeInfo(5)
    assert isinstance(txFeeInfo, rpc.TxFeeInfoResult)
    tip = txFeeInfo.feeInfoBlocks[0].height

    txFeeInfo = rpcClient.txFeeInfo(5, tip - 5, tip)
    assert isinstance(txFeeInfo, rpc.TxFeeInfoResult)

    validateAddress = rpcClient.validateAddress(mainnetAddress)
    assert isinstance(validateAddress, rpc.ValidateAddressChainResult)
    assert validateAddress.isValid

    # Address for wrong network.
    validateAddress = rpcClient.validateAddress(testnetAddress)
    assert isinstance(validateAddress, rpc.ValidateAddressChainResult)
    assert not validateAddress.isValid

    # Address is bogus.
    validateAddress = rpcClient.validateAddress(nonsense)
    assert isinstance(validateAddress, rpc.ValidateAddressChainResult)
    assert not validateAddress.isValid

    verifyChain = rpcClient.verifyChain()
    assert verifyChain

    verifyMessage = rpcClient.verifyMessage(ownedAddress, signedMessage, message)
    assert verifyMessage

    # Signature is bogus.
    verifyMessage = rpcClient.verifyMessage(ownedAddress, nonsense, message,)
    assert not verifyMessage

    version = rpcClient.version()
    assert isinstance(version["dcrd"], rpc.VersionResult)
    assert isinstance(version["dcrdjsonrpcapi"], rpc.VersionResult)


def test_WebsocketClient(config):
    """
    Inherited Client functionality is already tested by test_Client, so just
    exercise the WebsocketClient-only paths.
    """
    if config is None:
        pytest.skip("did not locate a dcrd config file")
    wsClient = rpc.WebsocketClient(
        "https://" + config["rpclisten"],
        config["rpcuser"],
        config["rpcpass"],
        config["rpccert"],
    )

    existsAddress = wsClient.existsAddress(mainnetAddress)
    assert existsAddress

    bestBlock = wsClient.getBestBlock()
    assert isinstance(bestBlock, rpc.GetBestBlockResult)

    wsClient.close()
