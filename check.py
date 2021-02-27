#!/usr/bin/python3

import base58
import getpass

from py_crypto_hd_wallet import HdWalletFactory, HdWalletCoins, HdWalletSpecs

hd_wallet_fact = HdWalletFactory(HdWalletCoins.BITCOIN)

def mnemonic_to_addr(mnemonic, passphrase=''):
    wallet = hd_wallet_fact.CreateFromMnemonic("my_wallet_name", mnemonic, passphrase=passphrase)
    wallet.Generate()
    return wallet.ToDict()['addresses']['address_1']['address']

if __name__ == "__main__":
    passphrase = getpass.getpass()

    while True:
        a = input()
        if not a: break
        print(mnemonic_to_addr(a, passphrase))
