# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: (C) 2024 afontenot (https://github.com/afontenot)
import argparse
import base64
import os
import struct
from getpass import getpass
from typing import Iterator

from requests.exceptions import HTTPError

from jmapc import (
    Client as JClient,
    EmailQueryFilterCondition,
    MailboxQueryFilterCondition,
    Ref,
)

from jmapc.methods import (
    EmailGet,
    EmailQuery,
    MailboxGet,
    MailboxQuery,
)


B32ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
STALWART_ALPHABET = "abcdefghijklmnopqrstuvwxyz792013"


class Blob(dict):
    def __init__(self, bid_str: str):
        super().__init__(self)
        bstr = self.b32str_to_bytes(bid_str)

        # the "class" value contains blob type (upper 4 bits as bitfield)
        # and also encoding method for the blob (lower 4 bits as integer)
        clas = bstr[0]
        encoding = clas & 0x0F

        self["hash"] = bstr[1:33].hex()
        rem = iter(bstr[33:])
        account = self.leb128iter_to_uint(rem)

        self["class"] = {"account_id": account}
        if clas & 0x10 == 0x10:
            self["class"].update(
                {
                    "type": "linked",
                    "collection": next(rem),
                    "document_id": self.leb128iter_to_uint(rem),
                }
            )
        elif clas & 0x20 == 0x20:
            self["class"].update(
                {"type": "reserved", "expires": self.leb128iter_to_uint(rem)}
            )

        self["section"] = None
        if encoding != 0:
            self["section"] = {
                "offset_start": self.leb128iter_to_uint(rem),
                "size": self.leb128iter_to_uint(rem),
                "encoding": encoding - 1,
            }

    @staticmethod
    def b32str_to_bytes(bstr: str, cmap: str = STALWART_ALPHABET) -> bytes:
        translator = str.maketrans(cmap, B32ALPHABET)
        bstr = bstr.translate(translator)
        # pad string to nearest 8 bytes
        bstr += "=" * ((8 - len(bstr) % 8) % 8)
        return base64.b32decode(bstr)

    def to_b32str(self, cmap: str = STALWART_ALPHABET) -> str:
        prefix = 0
        result = bytes.fromhex(self["hash"])

        result += self.uint_to_leb128(self["class"]["account_id"])
        if self["class"]["type"] == "linked":
            prefix |= 0x10
            result += struct.pack("B", self["class"]["collection"])
            result += self.uint_to_leb128(self["class"]["document_id"])
        elif self["class"]["typed"] == "reserved":
            prefix |= 0x20
            result += self.uint_to_leb128(self["class"]["expires"])

        if "section" in self:
            prefix |= self["section"]["encoding"] + 1
            result += self.uint_to_leb128(self["section"]["offset_start"])
            result += self.uint_to_leb128(self["section"]["size"])

        result = struct.pack("B", prefix) + result
        bstr = base64.b32encode(result).removesuffix(b"=").decode("ascii")

        translator = str.maketrans(B32ALPHABET, cmap)
        return bstr.translate(translator)

    @staticmethod
    def leb128iter_to_uint(liter: Iterator[int]) -> int:
        result = 0
        shift = 0
        while True:
            val = next(liter)
            if val & 0x80 == 0:
                result |= val << shift
                return result
            result |= (val & 0x7F) << shift
            shift += 7

    @staticmethod
    def uint_to_leb128(uint) -> bytes:
        result = b""
        while True:
            if uint < 0x80:
                return result + struct.pack("B", uint)
            result += struct.pack("B", (uint & 0x7F) | 0x80)
            uint >>= 7


class Client:
    def __init__(self, host, user, pwd):
        self.client = JClient.create_with_password(host=host, user=user, password=pwd)

    def get_mailbox(self, inbox):
        return self.client.request(
            [
                MailboxQuery(filter=MailboxQueryFilterCondition(name=inbox)),
                MailboxGet(ids=Ref("/ids")),
            ]
        )[1].response.data[0]

    def get_emails(self, mailbox_id, limit=50):
        return self.client.request(
            [
                EmailQuery(
                    collapse_threads=True,
                    filter=EmailQueryFilterCondition(
                        in_mailbox=mailbox_id,
                    ),
                    # sort=[Comparator(property="receivedAt", is_ascending=False)],
                    limit=50,
                ),
                # Use Email/query results to retrieve thread IDs for each email ID
                EmailGet(
                    ids=Ref("/ids"),
                    properties=["threadId", "messageId", "blobId", "bodyStructure"],
                ),
            ]
        )[1].response.data

    def get_part(self, message_part, timeout=10):
        blob_url = self.client.jmap_session.download_url.format(
            accountId=self.client.account_id,
            blobId=message_part.blob_id,
            name=message_part.name,
            type=message_part.type,
        )
        r = self.client.requests_session.get(blob_url, stream=True, timeout=timeout)
        r.raise_for_status()
        return r.raw.data


def recurse_bstr(bstr) -> list:
    if bstr.blob_id is not None:
        return [bstr]
    bstrs = []
    for sub_part in bstr.sub_parts:
        bstrs.extend(recurse_bstr(sub_part))
    return bstrs


def download(client, inbox: str):
    mbox = client.get_mailbox(inbox)
    emails = client.get_emails(mbox.id)

    for email in emails:
        message_parts = recurse_bstr(email.body_structure)
        print(email.message_id[0])
        for part in message_parts:
            blob = Blob(part.blob_id)

            # fix for issue in unreleased PR #766
            # if "section" in blob:
            #     blob["section"]["size"] -= 1

            print(blob)
            data = client.get_part(part)  # + b"\n"  # fix for #766
            print(f"message part downloaded: {len(data)} bytes")
        print()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--mailbox", default="Inbox")
    parser.add_argument("-s", "--server", help="the JMAP host to connect to")
    parser.add_argument("-u", "--user", help="the user name on the host")
    args = parser.parse_args()

    host = args.server or os.environ.get("JMAP_HOST")
    if not host:
        host = input("Input your host name: ")

    user = args.user or os.environ.get("JMAP_USER")
    if not user:
        user = input("Input your user name: ")

    password = os.environ.get("JMAP_PASSWORD")
    if not password:
        password = getpass("Input your password: ")

    client = Client(host, user, password)

    try:
        download(client, args.mailbox)
    except HTTPError as e:
        print(e)
        return


if __name__ == "__main__":
    main()
