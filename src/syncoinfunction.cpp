
#include "base58.h"
#include "foxcoinrpc.h"
#include "db.h"
#include "init.h"
#include "main.h"
#include "net.h"
#include "wallet.h"
#include "syncoinfunction.h"
#include "util.h"

using namespace std;
using namespace boost;

double getRawHardness(const CBlockIndex* blockindex = NULL)
{
    if (blockindex == NULL)
    {
        if (pindexBest == NULL)
            return 1.0;
        else
            blockindex = pindexBest;
    }

    int nShift = (blockindex->nBits >> 24) & 0xff;

    double dDiff =
        (double)0x0000ffff / (double)(blockindex->nBits & 0x00ffffff);

    while (nShift < 29)
    {
        dDiff *= 256.0;
        nShift++;
    }
    while (nShift > 29)
    {
        dDiff /= 256.0;
        nShift--;
    }

    return dDiff;
}

int GetRawNetworkPawsPS(int lookup)
{
    if (pindexBest == NULL)
        return 0;

    // If lookup is -1, then use blocks since last difficulty change.
    if (lookup <= 0)
        lookup = pindexBest->nHeight;

    // If lookup is larger than chain, then set it to chain length.
    if (lookup > pindexBest->nHeight)
        lookup = pindexBest->nHeight;

    CBlockIndex* pindexPrev = pindexBest;
    for (int i = 0; i < lookup; i++)
        pindexPrev = pindexPrev->pprev;

    double timeDiff = pindexBest->GetBlockTime() - pindexPrev->GetBlockTime();
    double timePerBlock = timeDiff / lookup;

    return (boost::int64_t)(((double)getHardness() * pow(2.0, 32)) / timePerBlock);
}

int getTotalVolume()
{
    int nHeight = pindexBest->nHeight;
    
    if(nHeight < 196000)
    {
        return (nHeight * (250 - ((nHeight * .0000625) + .0000625)));
    }
    else
    {
        return (1960000 * (250 - 120)) + (5 * (nHeight - 1960000));
    }
}

double getReward()
{
    int nHeight = pindexBest->nHeight;
    double nSubsidy = 1;
    
    if(nHeight < 1960000)
    {
       nSubsidy = (250 - (nHeight * 0.000125)); 
    }
    else
    {
        nSubsidy = 5;
    }
    
    return nSubsidy;
}

double GetRawEstimatedNextHardness(const CBlockIndex* blockindex = NULL){
    if (blockindex == NULL)
    {
        if (pindexBest == NULL)
            return 1.0;
        else
            blockindex = pindexBest;
    }

    unsigned int nBits;
    nBits = TrollNeoGetNextWorkRequired(blockindex);

    int nShift = (nBits >> 24) & 0xff;

    double dDiff = (double)0x0000ffff / (double)(nBits & 0x00ffffff);

    while (nShift < 29)
    {
        dDiff *= 256.0;
        nShift++;
    }
    while (nShift > 29)
    {
        dDiff /= 256.0;
        nShift--;
    }

    return dDiff;
}

double getAcreHardness(int height)
{
    const CBlockIndex* blockindex = getAcreIndex(height);
    
    int nShift = (blockindex->nBits >> 24) & 0xff;

    double dDiff =
        (double)0x0000ffff / (double)(blockindex->nBits & 0x00ffffff);

    while (nShift < 29)
    {
        dDiff *= 256.0;
        nShift++;
    }
    while (nShift > 29)
    {
        dDiff /= 256.0;
        nShift--;
    }

    return dDiff;
}

int getAcrePawrate(int height)
{
    int lookup = height;
    
    double timeDiff = getAcreTime(height) - getAcreTime(1);
    double timePerBlock = timeDiff / lookup;

    return (boost::int64_t)(((double)getAcreHardness(height) * pow(2.0, 32)) / timePerBlock);
}

const CBlockIndex* getAcreIndex(int height)
{
    std::string hex = getAcreHash(height);
    uint256 hash(hex);
    return mapBlockIndex[hash];
}

std::string getAcreHash(int Height)
{
    if(Height > pindexBest->nHeight) { return "351c6703813172725c6d660aa539ee6a3d7a9fe784c87fae7f36582e3b797058"; }
    if(Height < 0) { return "351c6703813172725c6d660aa539ee6a3d7a9fe784c87fae7f36582e3b797058"; }
    int desiredheight;
    desiredheight = Height;
    if (desiredheight < 0 || desiredheight > nBestHeight)
        return 0;
        
    CBlock block;
    CBlockIndex* pblockindex = mapBlockIndex[hashBestChain];
    while (pblockindex->nHeight > desiredheight)
        pblockindex = pblockindex->pprev;
    return pblockindex->phashBlock->GetHex();
}

int getAcreTime(int Height)
{
    std::string strHash = getAcreHash(Height);
    uint256 hash(strHash);

    if (mapBlockIndex.count(hash) == 0)
        return 0;

    CBlock block;
    CBlockIndex* pblockindex = mapBlockIndex[hash];
    return pblockindex->nTime;
}

std::string getAcreMerkle(int Height)
{
    std::string strHash = getAcreHash(Height);
    uint256 hash(strHash);
    
    if (mapBlockIndex.count(hash) == 0)
        return 0;

    CBlock block;
    CBlockIndex* pblockindex = mapBlockIndex[hash];
    return pblockindex->hashMerkleRoot.ToString().substr(0,10).c_str();
}

int getAcrenBits(int Height)
{
    std::string strHash = getAcreHash(Height);
    uint256 hash(strHash);
    
    if (mapBlockIndex.count(hash) == 0)
        return 0;

    CBlock block;
    CBlockIndex* pblockindex = mapBlockIndex[hash];
    return pblockindex->nBits;
}

int getAcreNonce(int Height)
{
    std::string strHash = getAcreHash(Height);
    uint256 hash(strHash);

    if (mapBlockIndex.count(hash) == 0)
        return 0;

    CBlock block;
    CBlockIndex* pblockindex = mapBlockIndex[hash];
    return pblockindex->nNonce;
}

std::string getAcreDebug(int Height)
{
    std::string strHash = getAcreHash(Height);
    uint256 hash(strHash);

    if (mapBlockIndex.count(hash) == 0)
        return 0;

    CBlock block;
    CBlockIndex* pblockindex = mapBlockIndex[hash];
    return pblockindex->ToString();
}

int acresInPastHours(int hours)
{
    int wayback = hours * 3600;
    bool check = true;
    int height = pindexBest->nHeight;
    int heightHour = pindexBest->nHeight;
    int utime = (int)time(NULL);
    int target = utime - wayback;
    
    while(check)
    {
        if(getAcreTime(heightHour) < target)
        {
            check = false;
            return height - heightHour;
        } else {
            heightHour = heightHour - 1;
        }
    }
}

double getTxTotalValue(std::string txid)
{
    uint256 hash;
    hash.SetHex(txid);

    CTransaction tx;
    uint256 hashBlock = 0;
    if (!GetTransaction(hash, tx, hashBlock))
        return 51;
    
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << tx;

    double value = 0;
    double buffer = 0;
    for (unsigned int i = 0; i < tx.vout.size(); i++)
    {
        const CTxOut& txout = tx.vout[i];
 
        buffer = value + convertCoins(txout.nValue);
        value = buffer;
    }

    return value;
}

double convertCoins(int64 amount)
{
    return (double)amount / (double)COIN;
}

std::string getOutputs(std::string txid)
{
    uint256 hash;
    hash.SetHex(txid);

    CTransaction tx;
    uint256 hashBlock = 0;
    if (!GetTransaction(hash, tx, hashBlock))
        return "fail";
    
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << tx;

    std::string str = "";
    for (unsigned int i = 0; i < tx.vout.size(); i++)
    {
        const CTxOut& txout = tx.vout[i];
        CTxDestination source;
        ExtractDestination(txout.scriptPubKey, source);  
        CFoxcoinAddress addressSource(source); 
        std::string lol7 = addressSource.ToString();
        double buffer = convertCoins(txout.nValue);
        std::string amount = boost::to_string(buffer);
        str.append(lol7);
        str.append(": ");
        str.append(amount);
        str.append(" ");
        str.append("\n");        
    }

    return str;
}

std::string getInputs(std::string txid)
{
    uint256 hash;
    hash.SetHex(txid);

    CTransaction tx;
    uint256 hashBlock = 0;
    if (!GetTransaction(hash, tx, hashBlock))
        return "fail";
    
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << tx;

    std::string str = "";
    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {     
        uint256 hash;
        const CTxIn& vin = tx.vin[i];
        hash.SetHex(vin.prevout.hash.ToString());
        CTransaction wtxPrev;                                     
        uint256 hashBlock = 0;
        if (!GetTransaction(hash, wtxPrev, hashBlock))
             return "fail";
    
        CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
        ssTx << wtxPrev;

        CTxDestination source;
        ExtractDestination(wtxPrev.vout[vin.prevout.n].scriptPubKey, source);  
        CFoxcoinAddress addressSource(source); 
        std::string lol6 = addressSource.ToString();
        const CScript target = wtxPrev.vout[vin.prevout.n].scriptPubKey;
        double buffer = convertCoins(getInputValue(wtxPrev, target));
        std::string amount = boost::to_string(buffer);
        str.append(lol6);
        str.append(": ");
        str.append(amount);
        str.append(" ");
        str.append("\n");        
    }

    return str;  
}

int64 getInputValue(CTransaction tx, CScript target)
{
    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        const CTxOut& txout = tx.vout[i];
        if(txout.scriptPubKey == target)
        {
            return txout.nValue;
        }
    }
}

double getTxFees(std::string txid)
{
    uint256 hash;
    hash.SetHex(txid);

    CTransaction tx;
    uint256 hashBlock = 0;
    if (!GetTransaction(hash, tx, hashBlock))
        return 51;
    
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << tx;

    double value = 0;
    double buffer = 0;
    for (unsigned int i = 0; i < tx.vout.size(); i++)
    {
        const CTxOut& txout = tx.vout[i];
 
        buffer = value + convertCoins(txout.nValue);
        value = buffer;
    }
    
    double value0 = 0;
    double buffer0 = 0;
    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {     
        uint256 hash0;
        const CTxIn& vin = tx.vin[i];
        hash0.SetHex(vin.prevout.hash.ToString());
        CTransaction wtxPrev;  
        uint256 hashBlock0 = 0;
        if (!GetTransaction(hash0, wtxPrev, hashBlock0))
             return 0;
        CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
        ssTx << wtxPrev;
        const CScript target = wtxPrev.vout[vin.prevout.n].scriptPubKey;
        buffer0 = value0 + convertCoins(getInputValue(wtxPrev, target));
        value0 = buffer0;
    }

    return value0 - value;
}

std::string getNodeInfo()
{
    LOCK(cs_vNodes);
    int i = vNodes.size();
    std::string str;
    while(i > 0)
    {
        i--;
        CNodeStats stats;
        CNode* pnode = vNodes[i];
        str.append(pnode->addrName);
        str.append(" [");    
        str.append(pnode->strSubVer);
        str.append("]");
        str.append("\n");
    }
    return str;
}

bool addnode(std::string node)
{
    string strNode = node;
    strNode.append(":9929");
    CAddress addr;
    bool exists = false;
    LOCK(cs_vNodes);
    int i = vNodes.size();
    while(i > 0)
    {
        i--;
        CNodeStats stats;
        CNode* pnode = vNodes[i];
        if(pnode->addrName == strNode)
        {
            exists = true;
            return false;
        }
    }
    if(!exists)
    {
    ConnectNode(addr, strNode.c_str());    
    int i1 = vNodes.size();
    while(i1 > 0)
    {
        i1--;
        CNodeStats stats;
        CNode* pnode = vNodes[i1];
        if(pnode->addrName == strNode)
        {
            return true;
        }
    }
        return false;
    }
}

double GetEstimatedNextHardness()
{
    return GetRawEstimatedNextHardness();
}

double getHardness()
{
    return getRawHardness();
}

int getNetworkPawsPS()
{
    return GetRawNetworkPawsPS(-1);
}
