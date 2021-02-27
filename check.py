#!/usr/bin/python3

import base58

from py_crypto_hd_wallet import HdWalletFactory, HdWalletCoins, HdWalletSpecs

hd_wallet_fact = HdWalletFactory(HdWalletCoins.BITCOIN)

def mnemonic_to_addr(mnemonic):
    wallet = hd_wallet_fact.CreateFromMnemonic("my_wallet_name", mnemonic)
    wallet.Generate()
    return wallet.ToDict()['addresses']['address_1']['address']

if __name__ == "__main__":
    while True:
        a = input()
        if not a: break
        print(mnemonic_to_addr(a))
