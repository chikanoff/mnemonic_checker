import asyncio
import random
import aiohttp
import aiofiles
import requests
from mnemonic import Mnemonic
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes
from eth_keys import keys
from eth_utils import to_checksum_address
import os
from dotenv import load_dotenv

load_dotenv()

# Define Etherscan API URL and Access Key
ETHERSCAN_API_URL = 'https://api.etherscan.io/api'
ETHERSCAN_API_KEY = os.getenv('ETHERSCAN_API_KEY')

async def generate_mnemonic(strength):
    mnemo = Mnemonic("english")
    return mnemo.generate(strength=strength)

async def derive_eth_address_from_mnemonic(mnemonic):
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
    bip44_wallet = Bip44.FromSeed(seed_bytes, Bip44Coins.ETHEREUM)
    account = bip44_wallet.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)
    priv_key = account.PrivateKey().Raw().ToHex()
    pub_key = keys.PrivateKey(bytes.fromhex(priv_key)).public_key
    eth_address = to_checksum_address(pub_key.to_address())
    return eth_address

async def check_eth_balance_with_retry(address):
    params = {
        'module': 'account',
        'action': 'balance',
        'address': address,
        'tag': 'latest',
        'apikey': ETHERSCAN_API_KEY
    }
    retry_count = 10  # Количество попыток повтора запроса
    for attempt in range(retry_count):
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(ETHERSCAN_API_URL, params=params) as response:
                    response.raise_for_status()
                    data = await response.json()
                    if 'result' in data:
                        balance = int(data['result']) / 10**18  # Convert from Wei to Ether
                        return balance
                    else:
                        print(f"Error in response: {data}")
                        return None
        except aiohttp.ClientResponseError as e:
            if e.status == 502 and attempt < retry_count - 1:
                print(f"Got 502 Bad Gateway error. Retrying ({attempt + 1}/{retry_count})...")
                await asyncio.sleep(5)  # Ждем 5 секунд перед повторной попыткой
            else:
                print(f"HTTP Request failed: {e}")
                return None
        except aiohttp.ClientError as e:
            print(f"HTTP Request failed: {e}")
            return None
        except ValueError:
            print(f"Failed to parse JSON response")
            return None

async def write_to_file(balance, address, mnemonic):
    async with aiofiles.open('wallets.txt', mode='a') as file:
        await file.write(f"{balance}, {address}, {mnemonic}\n")

async def main():
    i = 1
    while True:
        # Generate 12-word mnemonic asynchronously
        mnemonic_12 = await generate_mnemonic(128)

        # Derive Ethereum address asynchronously
        eth_address_12 = await derive_eth_address_from_mnemonic(mnemonic_12)

        # Check balance using Etherscan API with retry mechanism
        print(f"{i}. Checking balance for {eth_address_12}")
        balance_12 = await check_eth_balance_with_retry(eth_address_12)
        if balance_12 is not None and balance_12 > 0:
            print(f"{i}. GOT IT!!!! Balance for 12-word mnemonic address: {balance_12} ETH")
            await write_to_file(balance_12, eth_address_12, mnemonic_12)
            # break here if you want to stop after finding a positive balance

        print(f"Bal: {balance_12} ETH")
        i += 1


if __name__ == "__main__":
    asyncio.run(main())