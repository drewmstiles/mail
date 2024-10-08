#!/usr/bin/env python3

import imaplib
import ssl
import email
import logging
import sys
import os
import re
import pprint
import pytz
import stat
import math
import numpy as np
from getpass import getpass
from datetime import datetime, timedelta
from argparse import ArgumentParser

PW_CACHE = '/tmp/mail-pw.txt'
OK = 'OK'
NUM_MBOX_CHUNKS = 200

def get_message(msg_id, server):

    status, message = server.fetch(str(msg_id), '(RFC822)')
    for entry in message:
        if isinstance(entry, tuple):
            return email.message_from_bytes(entry[1])

    logging.warning(f"No message found for message ID '{msg_id}'")
    return None


def normalize_fields(header):

    items = [ field.strip() for field in header.split(',') ]

    normalized = []
    for i in items:
        normalized.append(email.utils.parseaddr(i)[-1])

    return normalized


def get_message_header(msg_id, header_name, server):

    msg = get_message(msg_id, server)
    header = msg[header_name]

    if header is None:
        return []
    else:
        if header_name == 'cc' or header_name == 'to' or header_name == 'from':
            return normalize_fields(header)
        elif header_name == 'subject':
            return [ header.replace('\r\n', '') ]
        else:
            logging.error(f"Unknown header type '{header_name}' requested.")
            sys.exit(1)


def delete_messages(server, msg_ids):

    msg_ids_str = str(",".join(msg_ids))

    typ, data = server.store(msg_ids_str, '+FLAGS', '\\Deleted')
    success = typ == 'OK'

    if success:
        logging.debug(f"Successfully flagged {msg_ids_str} for deletion")
    else:
        logging.error(f"Failed to flag {msg_ids_str} for deletion")

    return success


def copy_message(server, msg_id, folder):

    while True:
        typ, data = server.copy(str(msg_id), args.destination)
        if typ == 'OK':
            logging.info(f"Copied message from '{args.source}' to '{args.destination}'")
            delete_messages(server, [str(msg_id)])
            return True
        elif data[0].decode() == '[TRYCREATE] Mailbox does not exist':
            logging.info(f"Folder  '{args.destination}' does not exist, creating...")
            result = server.create(args.destination)
        else:
            logging.error(f"Failed to copy message '{msg_id}', ERROR '{data}'")
            return False


def delete_folder(server, args):

    folder = f'"{args.folder}"'

    status, count_tuple = server.select(folder)

    if status != OK:
        logging.error(f"Unable to select mailbox {folder}")
        sys.exit(1)
    else:
        count = int(count_tuple[0])

        if count < 1:
            logging.info(f"No messages found in {folder}")
        else:
            logging.info(f"Deleting {count} messages in {folder}")
            for msg_ids in np.array_split(list(range(1, count + 1)), math.ceil(count / NUM_MBOX_CHUNKS)):
                delete_messages(server, [ str(i) for i in list(msg_ids) ] )
                logging.debug(f"DELETE {msg_ids[0]}-{msg_ids[-1]}")


        server.delete(folder)
        server.expunge()

        logging.info(f"Deleted mailbox {folder}")


def list_folder(server, args):

    status, count_tuple = server.select(args.source)
    for msg_id in range(1, int(count_tuple[0])):
        subject = get_message_header(msg_id, 'subject', server)
        print(f"{msg_id}) SUBJECT '{subject}'")


def move_folder(server, args):

    status, count_tuple = server.select(args.source)

    logging.info(f"Moving messages from folder '{args.source}' to '{args.destination}'")

    for msg_id in range(1, int(count_tuple[0])):
        logging.debug(f"Operating on message ID '{msg_id}'")
        fields = get_message_header(msg_id, args.field.lower(), server)
        for field in fields:
            logging.debug(f"Checking field '{field}' for match on pattern '{args.pattern}'")
            if re.search(args.pattern, field):
                logging.info(f"Pattern '{args.pattern}' matches field '{args.field}' in message '{msg_id}'.")
                copy_message(server, msg_id, args.destination)
            else:
                ...


    server.expunge()


def prune_folders(server, args):

    min_date = datetime.now(pytz.timezone('US/Pacific')) - timedelta(days=int(args.days))

    typ, data = server.list(pattern=args.pattern)
    for folder in data:
        name = folder.decode().split('"/"')[1].strip()
        typ, count_tuple = server.select(name)
        count = int(count_tuple[0])
        logging.info(f"Found {count} messages in {name}")
        for msg_id in range(1, count + 1):

            log_prefix = f"[{name}][{msg_id}/{count}]"

            # TODO: Capture timezone info (GMT|[CP]ST|PDT) and initialize datetime object accordingly
            date_str = re.sub(r'\s+\([A-Z]{3}\)', '', get_message_header(msg_id, 'date', server))
            date = datetime.strptime(date_str, '%a, %d %b %Y %H:%M:%S %z')
            subject = get_message_header(msg_id, 'subject', server)

            if date < min_date:
                logging.info(f"{log_prefix} DELETE '{date}' '{subject}'")
                delete_message(server, msg_id)
            else:
                logging.debug(f"Date '{date}' exceeds minimum '{min_date}', moving to next folder")
                break

        server.expunge()


def init_server(host, email, password):

    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    server = imaplib.IMAP4_SSL(host=host, ssl_context=ssl_context)
    server.login(email, password)
    return server


def parse_args():

    parser = ArgumentParser(description="Utility for managing IMAP mailboxes")
    subparsers = parser.add_subparsers()

    parser.add_argument('-e', '--email', dest='email',
                        required=True, help='Your email address')

    parser.add_argument('--host', dest='host',
                        required=True, help='The IMAP server hostname')

    list_parser = subparsers.add_parser("list", description="List the messages in a given folder")
    list_parser.add_argument('-s', '--src', dest='source',
                             required=True, help='The mailbox folder to list')
    list_parser.set_defaults(func=list_folder)

    delete_parser = subparsers.add_parser("delete", description="List the messages in a given folder")
    delete_parser.add_argument('-f', '--folder', dest='folder',
                        required=True, help='The mailbox folder to delete')
    delete_parser.set_defaults(func=delete_folder)

    move_parser = subparsers.add_parser("move", description="Moves messages from source folder to destination folder")
    move_parser.add_argument('-s', '--src', dest='source',
                        required=True, help='The mailbox folder to move messages from')

    move_parser.add_argument('-d', '--dst', dest='destination',
                               required=True, help='The mailbox folder to move messages to')

    move_parser.add_argument('--pattern', dest='pattern',
                             required=True, help='The pattern to look for in message subjects')

    move_parser.add_argument('--field', dest='field',
                             default='subject', help='The message field which "pattern" will be matched against.')

    move_parser.set_defaults(func=move_folder)

    prune_parser = subparsers.add_parser("prune", description="Removes messages older than given number of days")
    prune_parser.add_argument('-d', '--days', dest='days',
                              required=True, help='Number of days in the past for which messages older will be removed')
    prune_parser.add_argument('--pattern', dest='pattern',
                             required=True, help='The pattern to match folder names on')

    prune_parser.set_defaults(func=prune_folders)

    args = parser.parse_args()

    if not (args.func):
        parser.print_help()
        sys.exit(1)
    else:
        return args


def get_password():

    if os.path.isfile(PW_CACHE):
        with open(PW_CACHE, 'r') as f:
            return f.read().strip()
    else:
        password = getpass()
        with open(PW_CACHE, 'w') as f:
            f.write(password)
            os.chmod(PW_CACHE, stat.S_IWUSR | stat.S_IRUSR)
        return password


if __name__ == '__main__':

    log_level = logging.DEBUG if int(os.environ.get('PY_DEBUG', 0)) == 1 else logging.INFO

    logging.basicConfig(
        level=log_level,
        format='[%(asctime)-15s][%(levelname)-5s] %(message)s'
    )

    args = parse_args()
    password = get_password()
    server = init_server(args.host, args.email, password)
    args.func(server, args)

    server.close()
    server.logout()

    sys.exit(0)
