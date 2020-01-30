"""
Copyright (c) 2019, the Decred developers
See LICENSE for details
"""

import os

import pytest

from decred.dcr import rpc
from decred.dcr.wire.msgblock import BlockHeader
from decred.dcr.wire.msgtx import MsgTx
from decred.util import helpers
from decred.util.encode import ByteArray


@pytest.fixture
def config():
    dcrdCfgDir = helpers.appDataDir("dcrd")
    cfgPath = os.path.join(dcrdCfgDir, "dcrd.conf")
    if not os.path.isfile(cfgPath):
        return None
    cfg = helpers.readINI(cfgPath, ["rpcuser", "rpcpass", "rpccert"])
    assert "rpcuser" in cfg
    assert "rpcpass" in cfg
    if "rpccert" not in cfg:
        cfg["rpccert"] = os.path.join(dcrdCfgDir, "rpc.cert")
    if "rpclisten" not in cfg:
        cfg["rpclisten"] = "localhost:9109"
    return cfg


mainnetAddress = "Dcur2mcGjmENx4DhNqDctW5wJCVyT3Qeqkx"
cookedAddress1 = "DcurAwesomeAddressmqDctW5wJCW1Cn2MF"
cookedAddress2 = "DcurAwesomeAddress2mqDcW5wJCW5qZcwR"
testnetAddress = "Tsf5Qvq2m7X5KzTZDdSGfa6WrMtikYVRkaL"
someTicket = "6d119de5cddef3bc3927f622fe39980b19bebb494d679deae4e1ecd4874344ed"
genesisHash = "298e5cc3d985bfe7f81dc135f360abe089edd4396b86d2de66b0cef42b21d980"
genesisBlockHeader = "0100000000000000000000000000000000000000000000000000000000000000000000000dc101dfc3c6a2eb10ca0c5374e10d28feb53f7eabcc850511ceadb99174aa66000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffff011b00c2eb0b000000000000000000000000a0d7b85600000000000000000000000000000000000000000000000000000000000000000000000000000000"
blkHash414000 = "000000000000000018744e708a39ad6e0cc22a85d5b902aa2067c9cd0002df85"
blkHex414000 = "07000000cb70ddef95b52344e53c8d10f2cf5f759ca94d6264d1730f00000000000000009cab4438cbce0635b7e7f44871ac652d8a441cbc9901f1d22cb9a28c4eb167f79c27184a06c3872a80da71ff2e7a62cc3e02bd93f901aed177dfa3a86a6ca1e7010053b03c16491905000100ee9f0000e1fe261872887a770300000030510600120c0000a9b01a5e6c9bfb02a8ba390000000000a1002c1e0000000000000000000000000000000000000000070000000201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff03f6e78b0900000000000017a914f5916158e3e2c4551c1796708db8367207ed13bb87000000000000000000000e6a0c3051060003c1928662fdda55cf8b47390000000000001976a9149c417596dea6570f8e546674555b5ce5087ce2c288ac000000000000000001bf57d3420000000000000000ffffffff0800002f646372642f010000000200d57227426e5297d679f906b2c65875de6d719a82c3ee8e7cc47d59a0e8786f0100000000ffffffff97dc3c26d6a3f72361bc2b7030c904af7373b2ab5d5c978f64593801c05882690200000001ffffffff02dafc7a770300000000001976a91422ff09aa4ea4f6e3ffc7b331672fd636fd1c665188acb87c69350200000000001976a9149f1b8139e8cae1006291ad7186695b27fb23d95b88ac00000000000000000232a4c1800200000010500600010000006a4730440220202f00a957498ab111256b8c0c973c6a36ca794a91e4cc60ab5a41e3ef1152c40220691e7e38b6f0c9d1d71e7da39e1b940d24ba4d5e24c0e5d7b944837ca656a19d012103fad0e731e1ff2cbeb14f719a24141a9da80883df6959a3385d0ea680ca2bfc0fbee5222c03000000d04f0600010000006b483045022100bfd18d5a2f13043573207ad791638c4426c08157598ef56de1489c5fb404899f022038584094e6fe4c9c379fb6e03907129932d5db683095a208e84af0a7bb8e66c7012103f52c4396a8d8071cba230123f5c6609d53ba5f54a00ebb7a7910a55b822e47dd0601000000020000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff7ea7d47d96ee371a5186ad28135dc4b61fe7973b4dc4c127b79382abd782d9400000000001ffffffff0400000000000000000000266a24cb70ddef95b52344e53c8d10f2cf5f759ca94d6264d1730f00000000000000002f51060000000000000000000000086a0605000700000055a80d000000000000001abb76a914b62c959a4679d2e7a1c3b0bbd6bc2d6f089de41d88ac347d3d650300000000001abb76a914536df39865f62aa4d9a613832348c3bc4c91e52688ac000000000000000002fa57ba050000000000000000ffffffff02000090cd905f03000000c84b060007000000904730440220161c5111d1188dae0e914909f304df7b5e8377871e69a5a187c6b7951dcca92502203619707c8b9540cbecfcc4287c87c48eeaf04078c39e688782f66a76a512b4560147512102013e4fc36e66d972656893f535c58436e824fa059cff8601e3f5ca2dcf9b84872103b7b2ad51ffec3c398fb086b5ab33b340d157dfa06c7a5d81f4a8b10b782ea17952ae01000000020000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffffaac6a7c5fc816fb1f7ab82b82c7b456a8ecd33226582bab577bbcb028b82864a0000000001ffffffff0400000000000000000000266a24cb70ddef95b52344e53c8d10f2cf5f759ca94d6264d1730f00000000000000002f51060000000000000000000000086a06010007000000d6a90e000000000000001abb76a914dec58da703b22db9cf49aaa2e7607a105ff069a788ac21aa56e30200000000001abb76a91427f6d95ea9b0fc8610d2d0e2e8cb10e65692ea4388ac000000000000000002fa57ba050000000000000000ffffffff020000fefbaadd02000000ab2506000800000090473044022000db34151c90822452eb621788bd56bdc63dc59fc5a28060467b4747480ad991022023b1988981035900da5ea3868d53c152f1a5b5c998ed8eb6f1849ad3d006ffa60147512103aab5939a5ad1ab077685923948264404fb7e4c97aaabfb5f589e4ca01c2be404210353dadbb8256fdefeb1c87615bbe3d7edf56ea65c81a008fdbd04ea3814e8bdc752ae01000000020000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff6a52113799f12fed6e6156360b489e2e66fc3426b18be746cb1429bfe5e36fd40000000001ffffffff0400000000000000000000266a24cb70ddef95b52344e53c8d10f2cf5f759ca94d6264d1730f00000000000000002f51060000000000000000000000086a060500060000002c3007000000000000001abb76a914618b33042a27deb9e9d0488fa29e988382b1df1788ac33929a690300000000001abb76a914edcfaa864b529b0a1a0e3fb6280375956412bd0c88ac000000000000000002fa57ba050000000000000000ffffffff020000666ae763030000003f4c06000900000090473044022016ccbef0747f8f5e2ab3ceae27695d80718cc8759b6ab784c776cece549400e9022028eba09e6a2b599dc7e70c13b3267d5d4fe672a38c336f733d15a769c37f2cd50147512102eec9f3402b21ae2e3b0cea2224cfc89367364c0d4845e9343c437969934eff0a2103d1a56bc0d12ea1feed4d1b823c48b168ca46aa200797fd67f306d7e96d25bb7252ae01000000020000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff0cba83f42d1414c405679f785f1d846bef5f93a5406457210da6b52f553263490000000001ffffffff0400000000000000000000266a24cb70ddef95b52344e53c8d10f2cf5f759ca94d6264d1730f00000000000000002f51060000000000000000000000086a06050006000000c0c01c000000000000001abb76a91414362cb17eb0295c03b051aad6abd87e31bd2fd088ac6bc9503a0300000000001abb76a9141e641ed8bea20aa48ce7a638ef762bca10d56ee188ac000000000000000002fa57ba050000000000000000ffffffff0200003232b334030000008d480600050000009047304402200779af2b51306f4ef9df707304bd1bdf46353749d030016b1c2141ca973fa105022013340c7da04c84612f3055a70ea1ba0896b7521b6a847a8a41658d6b9d52eb1801475121023259b72bbb675b34cb0ad519d3f8bc5f58bd0ee4aec8a4d248c204a926c953e22102be3864d8c7264baa1ef75e3fccb1697ab9a403f6e95ff11614a7fb22af3c5c0f52ae01000000020000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff599a46230a60f4badf6b337a67e9d7c2976b9b8a515ddf33e2c29a730ecd10930000000001ffffffff0300000000000000000000266a24cb70ddef95b52344e53c8d10f2cf5f759ca94d6264d1730f00000000000000002f51060000000000000000000000086a060100070000001025ee400300000000001abb76a9146f7923dac6be877b8dffb68545a8e52d4ba1f5cc88ac000000000000000002fa57ba050000000000000000ffffffff02000016cd333b03000000c2370600060000006a47304402201c8ca8a892f65f0dd153e64215bdd5ff929860a74bde6e5aa979f6ad090f524302201c341e99cd86ad01a55c7ab9d617c6a43def69ace9423e7f9d4ce82643aeeef9012103d1433ac74aeb3760b0204084413cb399137b198ee4e49ff76aa9ba4781ec074d010000000173e6b981dc21cd8a7e98ca2939dfc0659a6a34d0420189ee170a99cee51deaa80000000000ffffffff0359e2ce7f0300000000001aba76a914d4885aa8a0bba3cc42e3658a02fd480e7ec71e3d88ac00000000000000000000206a1e6e517e91b0a127a81da551bcd3fbe60693031880fdedce7f030000000058000000000000000000001abd76a914000000000000000000000000000000000000000088ac000000000000000001fdedce7f030000002f510600030000006a473044022056823401556cae48d4062c917a7680a543822c5004ebb98d3860379414769a4402207427fbdb4959fc8e916712ccd4d5f9afa7a899de70376a782d7d8cd7cfb4388e01210385542c90a6730e422ef73f8829e3ce0962c82aa38f9edb2aa46dee7863bb3046"
blkHash414005 = "0000000000000000053ca8eb8b5d82bc3e2dc82bded27de2150cb48da02e8899"
cFilter414000 = "0000000e590860091d85960f114d2e457d101825e82c901465e94aa768191dcae08475a842086ad954d6"
cFilterHeader414000 = "412f12ed5bd92df6a8b17cf396697cd44d84ada67f5ca3b1c3f23f3b7619984b"
blkHeader414002 = "07000000b8b8539315eb883c775cc3ef9ba0dface4dfb89def7b381a0000000000000000ef88a529674708a1496018fcfa68d5f3be9036c361d84577e26d70d81d0af00bcaf745f2a8a2ea5f1553fb5d279da82ef24d16266827607550928aec70337b890100494e62d0e3c705000c00f89f0000e1fe261872887a770300000032510600f3200000d2b41a5e1861aaa200d15401faab664fe1200080000000000000000000000000000000000000000007000000"
# These two are a pair.
addressWithTickets = "DcaephHCqjdfb3gPz778DJZWvwmUUs3ssGk"
aTicket = "d54d90bcec4146e9ae8c2ec860364f7023f33cad02b3c2bb4bdbb36689e68614"
ownedAddress = "DsUxwT6Kbiur6Nps9q3uGEpJCvrhcxX2nii"
signedMessage = "H166ndZLNEpIXrcEm4V9lf+AizRp/ejCAhs21J/ht87/RK0QFnOscCbJixKok3oHjpOS0jAkJ4jFktqMXD59LU8="
message = "this decred is tiny"
nonsense = "asdf"


def test_rpc(config):
    if config is None:
        pytest.skip("did not locate a dcrd config file")
    rpcClient = rpc.Client(
        "https://" + config["rpclisten"],
        config["rpcuser"],
        config["rpcpass"],
        config["rpccert"],
    )

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

    existsExpiredTickets = rpcClient.existsExpiredTickets([someTicket, someTicket])
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
    assert isinstance(getBestBlockHash, str)

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
    mempoolTxs = getRawMempool[0]

    existsMempoolTxs = rpcClient.existsMempoolTxs(getRawMempool[:3] + [someTicket])
    assert existsMempoolTxs == [True, True, True, False]

    getRawMempool = rpcClient.getRawMempool(True)
    assert isinstance(getRawMempool[mempoolTxs], rpc.GetRawMempoolVerboseResult)

    getHeaders = rpcClient.getHeaders([blkHash414000], blkHash414005)
    assert blkHeader414002 in getHeaders

    # This test will fail if --addrindex is not enabled in dcrd.
    getRawTransaction = rpcClient.getRawTransaction(someTicket)
    assert isinstance(getRawTransaction, MsgTx)

    getRawTransaction = rpcClient.getRawTransaction(someTicket, 1)
    assert isinstance(getRawTransaction, rpc.RawTransactionsResult)

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

    liveTickets = rpcClient.liveTickets()
    assert isinstance(liveTickets, list)

    missedTickets = rpcClient.missedTickets()
    assert isinstance(missedTickets, list)

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
    assert isinstance(searchRawTransactions[0], rpc.RawTransactionsResult)

    searchRawTransactions = rpcClient.searchRawTransactions(mainnetAddress, 0)
    assert isinstance(searchRawTransactions[0], str)

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
