#!/usr/bin/env python3

import warnings
import requests
import os
import json

os.environ["REQUESTS_CA_BUNDLE"] = "/etc/ssl/certs"

warnings.filterwarnings("ignore")

URL = "https://myserver.local:5000"
USERS = {
    "laura": "sgdr2023",
    "alberto": "1234lauratoledo",
    "celia": "prueba2455",
}


def _req(path, data=None, method="GET", check=True, token=None):
    if data:
        data = json.dumps(data)

    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"token {token}"
    r = requests.request(method, f"{URL}/{path}", data=data, headers=headers,verify=False)
    print(r.text)
    if check:
        r.raise_for_status()
    return r


def login(user):
    r = _req("login", data={"username": user, "password": USERS[user]}, method="POST")
    token = r.json()
    return token["access_token"]


def test_version():
    print("+++ /version... ")
    r = _req("version")
    assert r.text


def test_signup():
    print("+++ /signup... ")

    for u, p in USERS.items():
        r = _req(
            "signup",
            method="POST",
            data={"username": u, "password": p}, 
        )
        token = r.json()
        assert token["access_token"]

    for u, p in USERS.items():
        r = _req(
            "signup", data={"username": u, "password": p}, method="POST", check=False
        )
        if r.ok:
            assert False, f"{u} already exists"


def test_login():
    print("+++ /login... ")
    for u in USERS:
        login(u)

    r = _req(
        "login", data={"username": "foo", "password": "bar"}, method="POST", check=False
    )
    if r.ok:
        assert False, "user does not exist"

    r = _req(
        "login",
        data={"username": "user1", "password": "bar"},
        method="POST",
        check=False,
    )
    if r.ok:
        assert False, "not valid password for user1"


def test_create_and_update_doc():
    print("+++ Create docs... ")
    for u in USERS:
        token = login(u)
        r = _req(
            f"{u}/doc{u}",
            data={"doc_content": {"username": u}},
            method="POST",
            token=token,
        )
        assert r.json()["size"]

    for u in USERS:
        token = login(u)
        r = _req(
            f"{u}/doc{u}",
            data={"doc_content": {"username": u}},
            method="POST",
            token=token,
            check=False,
        )
        if r.ok:
            assert False, "document already exists"

    print("+++ Update docs... ")
    for u in USERS:
        token = login(u)
        r = _req(
            f"{u}/doc{u}", data={"doc_content": {"user": u}}, method="PUT", token=token
        )
        assert r.json()["size"]

def test_delete_docs():
    for u in USERS:
        token = login(u)
        r = _req(
            f"{u}/doc{u}",
            method="DELETE",
            token=token,
        )
        r = _req(
            f"{u}/doc{u}",
            token=token,
            check=False,
        )
        if r.ok:
            assert False, f'document should be removed'

def done():
    print("\n\n")
    print("+++ Test succesfully")


def main():
    print("PRACTICA 4 - LAURA TOLEDO GUTIERREZ")
    tests = [
        test_version,
        test_signup,
        test_login,
        test_create_and_update_doc,
        test_delete_docs,
        done,
    ]
    for t in tests:
        t()
    return 0


if __name__ == "__main__":
    exit(main())
