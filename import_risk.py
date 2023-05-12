#!/usr/bin/env python3

import os
import sys
import requests
import xmltodict
import urllib3
import base64

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Algosec:

    def __init__(self):

        ALGOSEC_SERVER = os.environ.get('ALGOSEC_SERVER')
        self.ALGOSEC_USERNAME = os.environ.get('ALGOSEC_USERNAME')
        self.ALGOSEC_PASSWORD = os.environ.get('ALGOSEC_PASSWORD')
        self.ALGOSEC_WSDL = f'https://{ALGOSEC_SERVER}/AFA/php/ws.php?wsdl'
        self.RISK_PROFILE_DIR = 'risk_profile'
        self.basedir = os.path.abspath(os.path.dirname(__file__))
        self.querystring = {'wsdl': ''}
        self.headers = {'Content-Type': 'text/xml',
                        'cache-control': 'no-cache'}

    def get_envelope(self):

        with open(f'{self.basedir}/xml/envelope.xml', 'r') as file:
            data = file.read()
            return data

    def get_session_id(self):

        envelope = self.get_envelope()

        with open(f'{self.basedir}/xml/ConnectRequest.xml', 'r') as file:
            connectRequest = file.read()

        data = envelope.replace('__AFA__', connectRequest) \
            .replace('__ALGOSEC_USERNAME__', self.ALGOSEC_USERNAME) \
            .replace('__ALGOSEC_PASSWORD__', self.ALGOSEC_PASSWORD)

        res = requests.post(
            self.ALGOSEC_WSDL,
            verify=False,
            data=data,
            headers=self.headers,
            params=self.querystring)

        if res.status_code == 200:
            res_data = xmltodict.parse(res.text)
            return {
                'session_id': res_data['SOAP-ENV:Envelope'][
                    'SOAP-ENV:Body']['ns1:ConnectResponse']['SessionID'],
                'message': 'Session started successfully.',
                'succeeded': True
            }
        else:
            return {
                'succeeded': False,
                'message': res.reason
            }

    def import_risk(self, session_id):

        files = [os.path.join('risk_profile', x)
                 for x in os.listdir('risk_profile')]
        
        if len(files) == 0:
            return {
                'succeeded': False,
                'message' : 'There is no risk profile file available!'
            }

        last_modified_file = max(files, key=os.path.getmtime)

        file_name = last_modified_file.split('/')[-1]

        risk_profile_name = file_name.split('.')[0]
        risk_file_type = file_name.split('.')[1]

        with open(last_modified_file, 'rb') as file_to_send:
            encoded_file_data = base64.b64encode(file_to_send.read())
            input_encoded_file_data = encoded_file_data.decode('utf-8')

        envelope = self.get_envelope()
        with open(
            f'{self.basedir}/xml/ImportRisksFromSpreadsheetRequest.xml',
                'r') as file:
            importRiskRequest = file.read()

        data = envelope.replace('__AFA__', importRiskRequest) \
            .replace('__SESSION_ID__', session_id) \
            .replace('__ENCODED_FILE_DATA__', input_encoded_file_data) \
            .replace('__RISK_PROFILE_NAME__', risk_profile_name) \
            .replace('__RISK_FILE_TYPE__', risk_file_type)

        res = requests.post(
            self.ALGOSEC_WSDL,
            verify=False,
            data=data,
            headers=self.headers,
            params=self.querystring)

        if res.status_code == 200:
            res_data = xmltodict.parse(res.text)
            ret_val = res_data['SOAP-ENV:Envelope']['SOAP-ENV:Body'][
                'ns1:ImportRisksFromSpreadsheetResponse']['RetVal']
            ret_message = res_data['SOAP-ENV:Envelope']['SOAP-ENV:Body'][
                'ns1:ImportRisksFromSpreadsheetResponse']['RetMessage']

            if ret_val == '0':
                succeeded = False
            elif ret_val == '1':
                succeeded = True

            return {
                'succeeded': succeeded,
                'message': ret_message
            }
        else:
            return {
                'succeeded': False,
                'message': res.reason
            }

    def close_session(self, session_id):

        envelope = self.get_envelope()
        with open(f'{self.basedir}/xml/DisconnectRequest.xml', 'r') as file:
            disconnect_request = file.read()

        data = envelope.replace('__AFA__', disconnect_request) \
            .replace('__SESSION_ID__', session_id)

        res = requests.post(
            self.ALGOSEC_WSDL,
            verify=False,
            data=data,
            headers=self.headers,
            params=self.querystring)

        if res.status_code == 200:
            return {
                'succeeded': True,
                'message': 'Session closed successfully.'
            }
        else:
            return {
                'succeeded': False,
                'message': 'Error trying to close session.'
            }


if __name__ == '__main__':

    algosec = Algosec()

    # start session
    session = algosec.get_session_id()
    if session['succeeded'] == True:
        print(' - starting session... success')
    else:
        print(f' - starting session... fail - Error: {session["message"]}')
        sys.exit(1)

    # import risk
    import_risk = algosec.import_risk(session['session_id'])
    if import_risk['succeeded'] == True:
        print(' - importing risk... success')
    else:
        print(f' - importing risk... fail - Error: {import_risk["message"]}')
        sys.exit(1)

    # close session
    close_session = algosec.close_session(session['session_id'])
    if close_session['succeeded'] == True:
        print(' - closing session... success')
        print(f'\n {import_risk["message"]}\n')
    else:
        print(
            f' - closing session... fail - Error: {close_session["message"]}')
        sys.exit(1)
