#!/usr/bin/env python3
from Levenshtein import distance as lev

from hdwallet import BIP44HDWallet
from hdwallet.cryptocurrencies import *
from hdwallet.derivations import BIP44Derivation
from hdwallet.utils import generate_mnemonic
from typing import Optional
import progressbar as pb
import sys, csv

prompt = '''
                                                                                                                           
      *******                             **             *******               ***                                         
    *       ***                            **          *       ***              ***                                        
   *         **                            **         *         **               **    **                                  
   **        *                             **         **        *                **    **                                  
    ***                                    **          ***             ****      **     **    ***             ***  ****    
   ** ***           ***       ***      *** **         ** ***          * ***  *   **      **    ***     ***     **** **** * 
    *** ***        * ***     * ***    *********        *** ***       *   ****    **      **     ***   * ***     **   ****  
      *** ***     *   ***   *   ***  **   ****           *** ***    **    **     **      **      **  *   ***    **         
        *** ***  **    *** **    *** **    **              *** ***  **    **     **      **      ** **    ***   **         
          ** *** ********  ********  **    **                ** *** **    **     **      **      ** ********    **         
           ** ** *******   *******   **    **                 ** ** **    **     **      **      ** *******     **         
            * *  **        **        **    **                  * *  **    **     **      **      *  **          **         
  ***        *   ****    * ****    * **    **        ***        *    ******      **       *******   ****    *   ***        
 *  *********     *******   *******   *****         *  *********      ****       *** *     *****     *******     ***       
*     *****        *****     *****     ***         *     *****                    ***                 *****                
*                                                  *                                                                       
 **                                                 **                                                                     

A tool for recovering malformed / partial seed phrases for Cryptocurrency wallets

 '''

def test_keys(network, mnemonic, key):
    # Generate english mnemonic words
    MNEMONIC: str = mnemonic
    # Secret passphrase/password for mnemonic
    PASSPHRASE: Optional[str] = None  # "meherett"
    
    # Initialize Ethereum mainnet BIP44HDWallet
    bip44_hdwallet: BIP44HDWallet = BIP44HDWallet(cryptocurrency=network)
    # Get Ethereum BIP44HDWallet from mnemonic
    bip44_hdwallet.from_mnemonic(
        mnemonic=MNEMONIC, language="english", passphrase=PASSPHRASE
    )
    # Clean default BIP44 derivation indexes/paths
    bip44_hdwallet.clean_derivation()
    
    #print("Mnemonic:", bip44_hdwallet.mnemonic())
    #print("Base HD Path:  m/44'/60'/0'/0/{address_index}", "\n")
    
    # Get Ethereum BIP44HDWallet information's from address index
    for address_index in range(1):
        # Derivation from Ethereum BIP44 derivation path
        bip44_derivation: BIP44Derivation = BIP44Derivation(
            cryptocurrency=network, account=0, change=False, address=address_index
        )
        # Drive Ethereum BIP44HDWallet
        bip44_hdwallet.from_path(path=bip44_derivation)
        # Print address_index, path, address and private_key
        # print(f"({address_index}) {bip44_hdwallet.path()} {bip44_hdwallet.address()} 0x{bip44_hdwallet.private_key()}")
        oval = (bip44_hdwallet.mnemonic(), bip44_hdwallet.address(), bip44_hdwallet.private_key())
        # Clean derivation indexes/paths
        bip44_hdwallet.clean_derivation()
        return(oval)

with open('bipwords.txt', 'r') as bfile:
    bipwords = [ w.strip() for w in bfile.readlines() ]

def get_bipword_dists(w):
    return { a: lev(w, a)  for a in bipwords }

# Get variables from prompts
print(prompt)
symb = input("Network symbol (eg. 'ETH'): ").strip()
pg = input("Broken seed phrase: ").strip()
maxdist = input("Mutations per word [1-2048]: ").strip()
mnemonic = pg.strip()
# Split mnemonic into word list for easier processing
mwords = mnemonic.split()
# Init variables for counting / storing results
seeds_tested = 0
good_mnems = []
# Find parameters for generating data for a network
network = get_cryptocurrency(symb)
print(f"\nSearching for seed phrases with network {symb}...")
# Initialize progress bar 
with pb.ProgressBar(max_value=len(mwords)*int(maxdist)) as bar:
    for w in range(len(mwords)):
        # Get dictionary of distances to bipwords
        sdists = get_bipword_dists(mwords[w])
        # Iterate through closest N words for each, replacing current word with nearest one
        for k in sorted(sdists, key=sdists.get)[:int(maxdist)]:
            mnem = mnemonic.replace(mwords[w], k)
            seeds_tested += 1
            # Update progress bar
            bar.update(seeds_tested)
            try:
                good_mnems += [test_keys(network, mnem, address)]
            # Ignore error where key is invalid bc lmao 
            except:
                continue # print(f'bad mnemonic: {mnem.strip()}')

print()
# Output csv of results 
csvwriter = csv.writer(sys.stdout)
csvwriter.writerow(('seed phrase', 'public key', 'private key'))
for i in good_mnems:
    csvwriter.writerow(i)
