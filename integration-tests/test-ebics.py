#!/usr/bin/env python3

from requests import post, get
from subprocess import call, Popen, PIPE
from time import sleep
from util import startNexus, startSandbox, assertResponse
from json_checks import checkFetchTransactions, checkPreparedPaymentElement
import os
import socket
import hashlib
import base64

# Nexus user details
USERNAME = "person"
PASSWORD = "y"
USER_AUTHORIZATION_HEADER = "basic {}".format(
    base64.b64encode(b"person:y").decode("utf-8")
)

# Admin authentication
ADMIN_AUTHORIZATION_HEADER = "basic {}".format(
    base64.b64encode(b"admin:x").decode("utf-8")
)

# EBICS details
EBICS_URL = "http://localhost:5000/ebicsweb"
HOST_ID = "HOST01"
PARTNER_ID = "PARTNER1"
USER_ID = "USER1"
EBICS_VERSION = "H004"

# Subscriber's bank account
SUBSCRIBER_IBAN = "GB33BUKB20201555555555"
SUBSCRIBER_BIC = "BUKBGB22"
SUBSCRIBER_NAME = "Oliver Smith"
BANK_ACCOUNT_LABEL = "savings"

# Databases
NEXUS_DB="test-nexus.sqlite3"

def fail(msg):
    print(msg)
    exit(1)

startSandbox()
startNexus(NEXUS_DB)

# 0.a
assertResponse(
    post(
        "http://localhost:5000/admin/ebics/host",
        json=dict(hostID=HOST_ID, ebicsVersion=EBICS_VERSION),
    )
)

# 0.b
assertResponse(
    post(
        "http://localhost:5000/admin/ebics/subscribers",
        json=dict(hostID=HOST_ID, partnerID=PARTNER_ID, userID=USER_ID),
    )
)

# 0.c
assertResponse(
    post(
        "http://localhost:5000/admin/ebics/bank-accounts",
        json=dict(
            subscriber=dict(hostID=HOST_ID, partnerID=PARTNER_ID, userID=USER_ID),
            iban=SUBSCRIBER_IBAN,
            bic=SUBSCRIBER_BIC,
            name=SUBSCRIBER_NAME,
            label=BANK_ACCOUNT_LABEL,
        ),
    )
)

# 1.a, make a new nexus user.

assertResponse(
    post(
        "http://localhost:5001/users",
        headers=dict(Authorization=ADMIN_AUTHORIZATION_HEADER),
        json=dict(username=USERNAME, password=PASSWORD),
    )
)

print("creating bank connection")

# 1.b, make a ebics bank connection for the new user.
assertResponse(
    post(
        "http://localhost:5001/bank-connections",
        json=dict(
            name="my-ebics",
            source="new",
            type="ebics",
            data=dict(
                ebicsURL=EBICS_URL, hostID=HOST_ID, partnerID=PARTNER_ID, userID=USER_ID
            ),
        ),
        headers=dict(Authorization=USER_AUTHORIZATION_HEADER),
    )
)

print("sending ini & hia")

# 2.a, upload keys to the bank (INI & HIA)
assertResponse(
    post(
        "http://localhost:5001/bank-connections/my-ebics/ebics/send-ini",
        json=dict(),
        headers=dict(Authorization=USER_AUTHORIZATION_HEADER),
    )
)

assertResponse(
    post(
        "http://localhost:5001/bank-connections/my-ebics/ebics/send-hia",
        json=dict(),
        headers=dict(Authorization=USER_AUTHORIZATION_HEADER),
    )
)

# 2.b, download keys from the bank (HPB)
assertResponse(
    post(
        "http://localhost:5001/bank-connections/my-ebics/ebics/send-hpb",
        json=dict(),
        headers=dict(Authorization=USER_AUTHORIZATION_HEADER),
    )
)

# Test download transaction (TSD, LibEuFin-specific test order type)
assertResponse(
    post(
        "http://localhost:5001/bank-connections/my-ebics/ebics/download/tsd",
        headers=dict(Authorization=USER_AUTHORIZATION_HEADER),
    )
)

# 2.c, fetch bank account information
assertResponse(
    post(
        "http://localhost:5001/bank-connections/my-ebics/ebics/import-accounts",
        json=dict(),
        headers=dict(Authorization=USER_AUTHORIZATION_HEADER),
    )
)

# 3, ask nexus to download history
assertResponse(
    post(
        f"http://localhost:5001/bank-accounts/{BANK_ACCOUNT_LABEL}/fetch-transactions",
        json=dict(level="all", rangeType="all"),
        headers=dict(Authorization=USER_AUTHORIZATION_HEADER),
    )
)

# 4, make sure history is empty
resp = assertResponse(
    get(
        f"http://localhost:5001/bank-accounts/{BANK_ACCOUNT_LABEL}/transactions",
        headers=dict(Authorization=USER_AUTHORIZATION_HEADER),
    )
)
if len(resp.json().get("transactions")) != 0:
    fail("unexpected number of transactions")

# 5.a, prepare a payment
resp = assertResponse(
    post(
        "http://localhost:5001/bank-accounts/{}/payment-initiations".format(
            BANK_ACCOUNT_LABEL
        ),
        json=dict(
            iban="FR7630006000011234567890189",
            bic="AGRIFRPP",
            name="Jacques La Fayette",
            subject="integration test",
            amount="EUR:1",
        ),
        headers=dict(Authorization=USER_AUTHORIZATION_HEADER),
    )
)
PREPARED_PAYMENT_UUID = resp.json().get("uuid")
if PREPARED_PAYMENT_UUID == None:
    fail("Payment UUID not received")

resp = assertResponse(
    get(f"http://localhost:5001/bank-accounts/{BANK_ACCOUNT_LABEL}/payment-initiations/{PREPARED_PAYMENT_UUID}",
        headers=dict(Authorization=USER_AUTHORIZATION_HEADER)
    )
)
checkPreparedPaymentElement(resp.json())

# 5.b, submit prepared statement
assertResponse(
    post(
        f"http://localhost:5001/bank-accounts/{BANK_ACCOUNT_LABEL}/payment-initiations/{PREPARED_PAYMENT_UUID}/submit",
        json=dict(),
        headers=dict(Authorization=USER_AUTHORIZATION_HEADER),
    )
)

# 6, request history after payment submission
assertResponse(
    post(
        f"http://localhost:5001/bank-accounts/{BANK_ACCOUNT_LABEL}/fetch-transactions",
        json=checkFetchTransactions(dict(level="all", rangeType="all")),
        headers=dict(Authorization=USER_AUTHORIZATION_HEADER),
    )
)

resp = assertResponse(
    get(
        f"http://localhost:5001/bank-accounts/{BANK_ACCOUNT_LABEL}/transactions",
        headers=dict(Authorization=USER_AUTHORIZATION_HEADER),
    )
)

if len(resp.json().get("transactions")) != 1:
    fail("Unexpected number of transactions; should be 1")

print("Test passed!")
