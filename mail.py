import csv
import json
import base64
import os.path
import requests
import argparse

from bs4 import BeautifulSoup
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.errors import HttpError
from googleapiclient.discovery import build
from tabulate import tabulate
from prettytable import PrettyTable
from google.auth.transport.requests import Request
from datetime import datetime
from tqdm import tqdm



# If modifying these SCOPES, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# Set the email address and subject to search for
user_id = "chris.platt@gmail.com"
search_query = 'subject:"Defender Order Confirmation"'

def parse_arguments():
    parser = argparse.ArgumentParser(description='Process Gmail messages and output table in different formats.')
    parser.add_argument('-c', '--csv', action='store_true', help='output table in CSV format')
    args = parser.parse_args()
    return args

args = parse_arguments()


def get_credentials():
    creds = None
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    # If there are no (valid) credentials available, prompt the user to log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
    return creds

def get_email_body_and_subject(service, user_id, msg_id):
    try:
        message = service.users().messages().get(userId=user_id, id=msg_id, format='full').execute()
        payload = message['payload']
        headers = payload['headers']

        subject = None
        for header in headers:
            if header['name'] == 'subject' or header['name'] == 'Subject':
                subject = header['value']
                break

        if 'parts' in payload:
            for part in payload['parts']:
                if part['mimeType'] == 'text/html':
                    body = part['body']['data']
                    decoded_body = base64.urlsafe_b64decode(body).decode('utf-8')
                    return decoded_body, message['internalDate'], subject
        elif 'body' in payload:
            body = payload['body']['data']
            decoded_body = base64.urlsafe_b64decode(body).decode('utf-8')
            return decoded_body, message['internalDate'], subject
    except HttpError as error:
        print(f'An error occurred: {error}')

def parse_arguments():
    parser = argparse.ArgumentParser(description='Process Gmail messages and output table in different formats.')
    parser.add_argument('-c', '--csv', action='store_true', help='output table in CSV format')
    args = parser.parse_args()
    return args

args = parse_arguments()

def main():
    creds = get_credentials()
    try:
        service = build('gmail', 'v1', credentials=creds)
        results = service.users().messages().list(userId=user_id, q=search_query).execute()
        messages = results.get('messages', [])
        all_table_data = []

        for message in tqdm(messages, desc='Processing messages'):
            msg_id = message['id']
            email_body, internal_date, subject = get_email_body_and_subject(service, user_id, msg_id)
            soup = BeautifulSoup(email_body, 'html.parser')
            tables = soup.find_all('table')

            for table in tables:
                first_row = table.find('tr')
                if first_row and 'Item Information' in first_row.get_text():
                    items_table = table
                    break

            email_date = datetime.fromtimestamp(int(internal_date)/1000).strftime('%Y-%m-%d')
            table_data = [[email_date, msg_id, subject] + [cell.text.strip() for cell in row.find_all('td')] for row in items_table.find_all('tr')[1:] if 'Item Number' not in [cell.text.strip() for cell in row.find_all('td')]]


            # Check if the table has any rows with item numbers
            if table_data:
                all_table_data.extend(table_data)

        # Output the table without headers
        if all_table_data:
            if args.csv:
                with open('output.csv', 'w', newline='') as csvfile:
                    csv_writer = csv.writer(csvfile)
                    for row in all_table_data:
                        csv_writer.writerow(row)
                print("Table has been saved in output.csv")
            else:
                print(tabulate(all_table_data, tablefmt="pretty"))
    except HttpError as error:
        print(f'An error occurred: {error}')


if __name__ == '__main__':
    main()

