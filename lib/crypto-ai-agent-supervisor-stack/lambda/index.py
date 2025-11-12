# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import os
import boto3
import requests
from web3 import Web3
from pyasn1.type import namedtype, univ

aws_region = boto3.session.Session().region_name

# the KMS alias for the agent's wallet
KMS_KEY_ALIAS = "alias/crypto-ai-agent-wallet"


def getUnstoppableDomainsAddress():
    # Default is Polygon mainnet
    return os.environ.get(
        "UNSTOPPABLE_DOMAINS_ADDRESS", "0xa2c203d7a6931f5368fb935cf1bffa7fa4c8360e"
    )


def getBlockchainRPCURL():
    # Get blockchain RPC endpoint from environment variable
    blockchain_rpc_url = os.environ.get("BLOCKCHAIN_RPC_URL")
    if not blockchain_rpc_url:
        raise ValueError("BLOCKCHAIN_RPC_URL environment variable is not set")
    return blockchain_rpc_url


w3 = Web3(Web3.HTTPProvider(getBlockchainRPCURL()))
# Adding middleware to support ENS resolution on non-mainnet EVM chains
from web3.middleware import ExtraDataToPOAMiddleware

w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)

# Get and set chain ID
chain_id = w3.eth.chain_id
print(f"Connected to network with chain ID: {chain_id}")

# CoinGecko private key for making calls
coingecko_api_key = os.environ.get("COINGECKO_API_KEY")
if not coingecko_api_key:
    raise ValueError("COINGECKO_API_KEY environment variable is not set")

# Vitalik's wallet address
vitalikaddr = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"

# Check for connection to the network
if not w3.is_connected():
    raise ConnectionError("Failed to connect to HTTPProvider")


# Get the KMS key by alias
def get_kms_key():
    print("in get_kms_key")
    kms_client = boto3.client("kms")
    print("in get_kms_key, got kms_client")
    try:
        kms_key = kms_client.describe_key(KeyId="alias/crypto-ai-agent-wallet")[
            "KeyMetadata"
        ]["KeyId"]
        print(f"Found KMS key: {kms_key}")
        return kms_key
    except Exception as e:
        print(f"Error getting KMS key: {e}")
        raise


# Given a public key, calculate the Ethereum wallet address
def calc_eth_address(pub_key) -> str:
    print("in calc_eth_address. about to import asn1tools")
    SUBJECT_ASN = """
    Key DEFINITIONS ::= BEGIN

    SubjectPublicKeyInfo  ::=  SEQUENCE  {
       algorithm         AlgorithmIdentifier,
       subjectPublicKey  BIT STRING
     }

    AlgorithmIdentifier  ::=  SEQUENCE  {
        algorithm   OBJECT IDENTIFIER,
        parameters  ANY DEFINED BY algorithm OPTIONAL
      }

    END
    """

    try:
        import asn1tools

        print("in calc_eth_address. imported asn1tools")
        key = asn1tools.compile_string(SUBJECT_ASN)
        print("in calc_eth_address. compiled string to key")
        key_decoded = key.decode("SubjectPublicKeyInfo", pub_key)
        print(f"key_decoded: {key_decoded}")
        pub_key_raw = key_decoded["subjectPublicKey"][0]
        pub_key = pub_key_raw[1 : len(pub_key_raw)]

        hex_address = w3.keccak(bytes(pub_key)).hex()
        eth_address = "0x{}".format(hex_address[-40:])
        print(f"eth_address: {eth_address}")
        eth_checksum_addr = w3.to_checksum_address(eth_address)
        print(f"eth_checksum_addr: {eth_checksum_addr}")
        return eth_checksum_addr
    except Exception as e:
        print(f"Error calculating Ethereum address: {str(e)}")
        print(f"Exception type: {type(e).__name__}")
        raise


# Get the wallet address for the agent's KMS key
def get_wallet_address():
    print("in get_wallet_address")
    try:
        # Get the KMS key ID first
        key_id = get_kms_key()
        print("got key_id")
        # Get the public key using the key ID
        kms_client = boto3.client("kms")
        public_key_response = kms_client.get_public_key(KeyId=key_id)
        print(f"Retrieved public key response: {public_key_response}")

        # Extract the public key bytes (removes DER encoding)
        public_key_bytes = public_key_response["PublicKey"]
        print(f"Extracted public key bytes: {public_key_bytes}")

        eth_address = calc_eth_address(public_key_bytes)
        print(f"eth_address: {eth_address}")
        return eth_address

    except Exception as e:
        print(f"Error getting wallet address: {e}")
        raise


# Resolve domain address
def resolve_domain(domain):

    print(f"Resolving domain: {domain}")

    # if it's already an address then just return
    if (
        domain
        and isinstance(domain, str)
        and domain.startswith("0x")
        and len(domain) == 42
    ):
        return domain

    try:
        unstoppable_domains_address = getUnstoppableDomainsAddress()

        # ABI configuration
        abi = [
            {
                "constant": True,
                "inputs": [
                    {"internalType": "string[]", "name": "keys", "type": "string[]"},
                    {"internalType": "uint256", "name": "tokenId", "type": "uint256"},
                ],
                "name": "getData",
                "outputs": [
                    {"internalType": "address", "name": "resolver", "type": "address"},
                    {"internalType": "address", "name": "owner", "type": "address"},
                    {"internalType": "string[]", "name": "values", "type": "string[]"},
                ],
                "payable": False,
                "stateMutability": "view",
                "type": "function",
            }
        ]

        # Initialize contract
        contract = w3.eth.contract(address=unstoppable_domains_address, abi=abi)

        # Implement namehashing
        def namehash(name):
            if not name:
                return b"\0" * 32

            if name.startswith("."):
                name = name[1:]

            labels = name.split(".")
            labels.reverse()

            node = b"\0" * 32
            for label in labels:
                label_hash = w3.keccak(label.encode("utf-8"))
                node = w3.keccak(node + label_hash)

            return node.hex()

        # Generate tokenId and resolve
        token_id = int(namehash(domain), 16)
        result = contract.functions.getData([], token_id).call()

        # Check if owner was found
        if result[1] == "0x0000000000000000000000000000000000000000":
            print(f"Domain {domain} not found")
            return None

        resolved_address = result[1]
        print(f"Resolved {domain} to {resolved_address}")
        return resolved_address

    except Exception as e:
        print(f"An error occurred while resolving domain: {e}")
        return None


class KMSSignature(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("r", univ.Integer()),
        namedtype.NamedType("s", univ.Integer()),
    )


# Returns the v,r,s of the KMS signature
def parse_kms_signature(
    kms_signature_bytes, transaction_hash, expected_address, chain_id
):
    print(f"kms_signature_bytes {kms_signature_bytes}")
    print(f"Transaction hash: {transaction_hash.hex()}")
    print(f"Expected address: {expected_address}")
    print(f"Chain ID: {chain_id}")
    print(f"Signature bytes: {kms_signature_bytes.hex()}")

    try:
        from pyasn1.codec.der import decoder

        signature, _ = decoder.decode(kms_signature_bytes, asn1Spec=KMSSignature())
        r = int(signature["r"])
        s = int(signature["s"])
    except Exception as e:
        print(f"Failed to decode signature: {e}")
        return None

    print(f"Signature r: {r}")
    print(f"Signature s: {s}")
    print(f"Signature: {signature}")

    for recovery_id in [0, 1]:
        try:
            print(f"Attempting recovery with recovery_id={recovery_id}")

            # Create signature using eth_keys
            from eth_keys import KeyAPI

            keys = KeyAPI()
            sig = keys.Signature(vrs=(recovery_id, r, s))
            print("got signature. now recovering public key")
            recovered_pub_key = sig.recover_public_key_from_msg_hash(transaction_hash)
            print(f"Recovered public key: {recovered_pub_key}")
            recovered_address = Web3.to_checksum_address(recovered_pub_key.to_address())

            print(f"Trying recovery_id={recovery_id}, recovered: {recovered_address}")
            print(f"Expected: {expected_address}")

            if recovered_address.lower() == expected_address.lower():
                print(f"Found correct recovery_id: {recovery_id}")
                v = 35 + recovery_id + chain_id * 2
                return r, s, v
        except Exception as e:
            print(f"Error with recovery_id={recovery_id}")
            print(f"Error serializing transaction: {str(e)}")
            print(f"Exception type: {type(e).__name__}")
            continue

    raise ValueError("Could not determine correct v value")


def sign_kms(key_id: str, msg_hash: bytes) -> dict:
    client = boto3.client("kms")

    response = client.sign(
        KeyId=key_id,
        Message=msg_hash,
        MessageType="DIGEST",
        SigningAlgorithm="ECDSA_SHA_256",
    )

    return response


def sendTx(receiver, amount):
    print("Sending transaction in sendTx")
    from_address = get_wallet_address()

    print(f"Original receiver: {receiver}")

    # Check if it's an ENS domain, if so resolve it
    if not (
        receiver
        and isinstance(receiver, str)
        and receiver.startswith("0x")
        and len(receiver) == 42
    ):
        resolved_address = resolve_domain(receiver)
        if resolved_address:
            receiver = resolved_address
        else:
            return "Failed to resolve receiver address"

    print(f"Final receiver address: {receiver}")

    # Define transaction parameters
    transaction = {
        "to": receiver,
        "value": w3.to_wei(amount, "ether"),
        "gas": 21000,  #
        "gasPrice": w3.to_wei(150, "gwei"),
        "nonce": w3.eth.get_transaction_count(from_address),
        "chainId": chain_id,
    }

    print(f"Transaction details: {transaction}")

    from eth_account._utils.legacy_transactions import (
        serializable_unsigned_transaction_from_dict,
        encode_transaction,
    )

    unsigned_tx = ""
    # Create the unsigned transaction
    try:
        unsigned_tx = serializable_unsigned_transaction_from_dict(transaction)
    except Exception as e:
        print(f"Error serializing transaction: {e}")
        return "Failed to send because of serialization error"

    print(f"Unsigned transaction: {unsigned_tx}")
    unsigned_tx_hash = unsigned_tx.hash()
    print(f"Unsigned transaction hash: {unsigned_tx_hash.hex()}")
    kms_signature_dict = sign_kms(KMS_KEY_ALIAS, unsigned_tx_hash)
    signature = kms_signature_dict["Signature"]
    print(f"KMS signature dict: {kms_signature_dict}")
    print(f"KMS signature: {signature}")
    r, s, v = parse_kms_signature(signature, unsigned_tx_hash, from_address, chain_id)
    print(f"r: {r}, s: {s}, v: {v}")

    encoded_transaction = encode_transaction(unsigned_tx, vrs=(v, r, s))

    print(f"Signed transaction: {encoded_transaction}")
    try:
        # Send the raw transaction
        tx_hash = w3.eth.send_raw_transaction(encoded_transaction)
        print(f"Transaction sent to network. Tx hash: {tx_hash}")
        tx_hash_hex = tx_hash.hex()  # Convert bytes to hex string
        print(f"Transaction hex value used to look it up: 0x{tx_hash_hex}")
        print(f"View on Polygonscan: https://polygonscan.com/tx/0x{tx_hash_hex}")

        # # Wait for transaction receipt
        # tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        # print(f"Transaction mined in block {tx_receipt['blockNumber']}")
        # print(f"Transaction status: {'Success' if tx_receipt['status'] == 1 else 'Failed'}")
        return tx_hash_hex
    except Exception as e:
        print(f"Error sending transaction: {str(e)}")


def investAdviceMetric():
    url = "https://api.coingecko.com/api/v3/coins/bitcoin/market_chart?vs_currency=usd&days=365&interval=daily"
    headers = {"accept": "application/json", "x-cg-demo-api-key": coingecko_api_key}

    response = requests.get(url, headers=headers)
    data = response.json()

    prices = [price[1] for price in data["prices"]]
    current_price = prices[-1]
    all_time_high = max(prices)

    # Calculate 200-day moving average
    ma_200 = sum(prices[-200:]) / min(200, len(prices))

    ath_ratio = current_price / all_time_high
    ma_ratio = current_price / ma_200

    sbci = (ath_ratio + ma_ratio) / 2

    print(f"Current Price: ${current_price:.2f}")
    print(f"All Time High: ${all_time_high:.2f}")
    print(f"200-day Moving Average: ${ma_200:.2f}")
    print(f"Simple Bitcoin Cycle Index: {sbci:.2f}")
    print("Index ranges:")
    print("0.00 - 0.25: Extremely Undervalued")
    print("0.25 - 0.50: Undervalued")
    print("0.50 - 0.75: Fair Value")
    print("0.75 - 1.00: Overvalued")
    print("1.00+: Extremely Overvalued")

    if sbci <= 0.25:
        return "The market appears extremely undervalued. Consider investing but be aware of potential further downside."
    elif sbci <= 0.50:
        return "The market appears somewhat undervalued. This might be a good opportunity for dollar-cost averaging or increasing your position."
    elif sbci <= 0.75:
        return "The market seems to be around fair value. This might be a good time to hold your current position and continue to monitor the market."
    elif sbci <= 1.00:
        return "The market appears overvalued. Consider taking some profits or reducing your position."
    else:
        return "The market appears extremely overvalued. This might be a good time to take significant profits."


def estimate_gas(to_address, value, data="", gas_price=None):

    from_address = get_wallet_address()

    if not w3.is_connected():
        raise Exception("Failed to connect to the network")

    # Prepare transaction data
    transaction = {
        "from": from_address,
        "to": to_address,
        "value": w3.to_wei(value, "ether"),
        "data": data,
    }

    # If gas price is provided, add it to the transaction
    if gas_price:
        transaction["gasPrice"] = w3.to_wei(gas_price, "gwei")

    try:
        # Estimate
        gas_estimate = w3.eth.estimate_gas(transaction)
        return gas_estimate
    except Exception as e:
        print(f"Error estimating gas: {e}")
        return None


def getBalance(address):

    if not address:
        address = get_wallet_address()
    elif not (
        address
        and isinstance(address, str)
        and address.startswith("0x")
        and len(address) == 42
    ):
        resolved_address = resolve_domain(address)
        if resolved_address:
            address = resolved_address
        else:
            return "Failed to resolve address"

    balance = w3.eth.get_balance(address)

    # Convert balance from Wei to Ether
    ether_balance = w3.from_wei(balance, "ether")

    print(f"Account {address} has a balance of {ether_balance} Ether")

    return ether_balance


def getWalletAddress():
    print("in getWalletAddress")
    address = get_wallet_address()
    return address


def getCryptoPrice(token):

    url = "https://api.coingecko.com/api/v3/coins/markets"

    params = {"vs_currency": "usd", "ids": token.lower()}
    headers = {"accept": "application/json", "x-cg-demo-api-key": coingecko_api_key}

    response = requests.get(url, params=params, headers=headers)

    print(response.text)

    if response.status_code == 200:
        data = response.json()
        if data:
            price = data[0]["current_price"]
            return price
        else:
            return f"No data found for {token}"
    else:
        return f"Error: {response.status_code} - {response.text}"


def lambda_handler(event, context):
    print(f"Function timeout: {context.get_remaining_time_in_millis()/1000} seconds")
    print(f"Function memory: {context.memory_limit_in_mb} MB")
    print(f"Event: {event}")
    agent = event["agent"]
    actionGroup = event["actionGroup"]
    function = event["function"]

    if function == "sendTx":
        parameters = {param["name"]: param["value"] for param in event["parameters"]}

        print(parameters)

        amount = parameters.get("amount")
        receiver = parameters.get("receiver")

        result = sendTx(receiver, amount)
        responseBody = {"TEXT": {"body": result}}

    elif function == "estimateGas":
        value = 0.000001  # ETH
        result = estimate_gas(vitalikaddr, value)

        responseBody = {"TEXT": {"body": result}}

    elif function == "getBalance":
        parameters = {param["name"]: param["value"] for param in event["parameters"]}

        print(parameters)
        address = parameters.get("walletAddress")
        result = getBalance(address)
        responseBody = {"TEXT": {"body": result}}

    elif function == "getCryptoPrice":
        parameters = {param["name"]: param["value"] for param in event["parameters"]}

        print(parameters)
        token = parameters.get("token")
        result = getCryptoPrice(token)
        responseBody = {"TEXT": {"body": result}}
    elif function == "investAdviceMetric":

        result = investAdviceMetric()
        responseBody = {"TEXT": {"body": result}}
    elif function == "getWalletAddress":
        print("in handler, getting getWalletAddress")
        result = getWalletAddress()
        responseBody = {"TEXT": {"body": result}}
    else:
        responseBody = {"TEXT": {"body": f"Function {function} not found"}}

    action_response = {
        "actionGroup": actionGroup,
        "function": function,
        "functionResponse": {"responseBody": responseBody},
    }

    function_response = {
        "response": action_response,
        "messageVersion": event["messageVersion"],
    }
    print("Response: {}".format(function_response))

    return function_response
