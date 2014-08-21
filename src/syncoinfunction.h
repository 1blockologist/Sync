/* 

 */

#ifndef SYNCOINFUNCTION_H
#define	SYNCOINFUNCTION_H

double getHardness();
double GetEstimatedNextHardness();
double getReward();
double getAcreHardness(int);
double getTxTotalValue(std::string);
double convertCoins(int);
double getTxFees(std::string);

int getTotalVolume();
int getNetworkPawsPS();
int getAcreTime(int);
int getAcrenBits(int);
int getAcreNonce(int);
int acresInPastHours(int);
int getAcrePawrate(int);

std::string getNodeInfo();
std::string getInputs(std::string);
std::string getOutputs(std::string);
std::string getAcreHash(int);
std::string getAcreMerkle(int);

bool addnode(std::string);

const CBlockIndex* getAcreIndex(int);

int getInputValue(CTransaction, CScript);
#endif