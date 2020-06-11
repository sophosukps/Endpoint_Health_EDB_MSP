# These scripts are examples and unsupported
# Make sure requests is installed
# EDB Health v1.62
import requests
import csv
import configparser
#Import OS to allow to check which OS the script is being run on
import os
# Import datetime modules
from datetime import date
from datetime import datetime
today = date.today()
now = datetime.now()
timestamp = str(now.strftime("%d%m%Y_%H-%M-%S"))
# This list will hold all the sub estates
sub_estate_list = []
# This list will hold all the computers
computer_list = []

# Get Access Token - JWT in the documentation
def get_bearer_token(client, secret, url):
    d = {
                'grant_type': 'client_credentials',
                'client_id': client,
                'client_secret': secret,
                'scope': 'token'
            }
    request_token = requests.post(url, auth=(client, secret), data=d)
    json_token = request_token.json()
    headers = {'Authorization': f"Bearer {json_token['access_token']}"}
    #headers = {'Authorization': str('Bearer ' + json_token['access_token'])}
    return headers

def get_whoami():
    # We now have our JWT Access Token. We now need to find out if we are a Partner or Organization
    # Partner = MSP
    # Organization = Sophos Central Enterprise Dashboard
    # The whoami URL
    whoami_url = 'https://api.central.sophos.com/whoami/v1'
    request_whoami = requests.get(whoami_url, headers=headers)
    whoami = request_whoami.json()
    # MSP or Sophos Central Enterprise Dashboard
    # We don't use this variable in this script. It returns the organization type
    check_organization_type = whoami["idType"]
    if whoami["idType"] == "partner":
        organization_Header= "X-Partner-ID"
    else:
        organization_Header = "X-Organization-ID"
    organizationID = whoami["id"]
    return organizationID, organization_Header, check_organization_type

def get_all_sub_estates(organization):
    # Add X-Organization-ID to the headers dictionary
    headers[organizationHeader] = organization
    # URL to get the list of tennants
    sub_estate_url = f"{'https://api.central.sophos.com/'}{organizationType}{'/v1/tenants?pageTotal=True'}"
    # Request all tenants
    request_sub_estates = requests.get(sub_estate_url, headers=headers)
    # Convert to JSON
    sub_estate_json = request_sub_estates.json()
    # Find the number of pages we will need to search to get all the sub estates
    total_pages = sub_estate_json["pages"]["total"]
    # Set the keys you want in the list
    sub_estate_keys = ('id', 'name', 'dataRegion')
    while (total_pages != 0):
    #Paged URL https://api.central.sophos.com/organization/v1/tenants?page=2 add total pages in a loop
        sub_estate_url = f"{'https://api.central.sophos.com/'}{organizationType}{'/v1/tenants?page='}{total_pages}"
        request_sub_estates = requests.get(sub_estate_url, headers=headers)
        sub_estate_json = request_sub_estates.json()
        #Add the tenants to the sub estate list
        for all_sub_estates in sub_estate_json["items"]:
            #Make a temporary Dictionary to be added to the sub estate list
            sub_estate_dictionary = {key:value for key, value in all_sub_estates.items() if key in sub_estate_keys}
            sub_estate_list.append(sub_estate_dictionary)
        total_pages -= 1


    # Remove X-Organization-ID from headers dictionary. We don't need this anymore
    del headers[organizationHeader]

def get_all_computers(sub_estate_token, url, name):
    # Get all Computers from sub estates
    computers_url = url
    # Loop while the page_count is not equal to 0. We have more computers to query
    page_count = 1
    while page_count != 0:
        #Sub estate to be searched
        sub_estate_id = sub_estate_token
        #Add X-Tenant-ID to the headers dictionary
        headers['X-Tenant-ID'] = sub_estate_id
        #Request all Computers
        request_computers = requests.get(computers_url, headers=headers)
        if request_computers.status_code != 200:
            return
        #Convert to JSON
        computers_json = request_computers.json()
        #Set the keys you want in the list
        computer_keys = ('id', 'hostname', 'lastSeenAt', 'threats', 'service_health', 'health', 'tamperProtectionEnabled', 'ipv4Addresses', 'associatedPerson', 'Sub Estate', 'os', 'majorVersion', 'type')
        #Add the computers to the computers list
        for all_computers in computers_json["items"]:
            works = 0
            # Make a temporary Dictionary to be added to the sub estate list
            computer_dictionary = {key:value for key, value in all_computers.items() if key in computer_keys}
            # If no hostname is returned add unknown
            if 'hostname' not in computer_dictionary.keys():
                computer_dictionary['hostname'] = 'Unknown'
            # This line allows you to debug on a certain computer. Add computer name
            if 'mc-nuc-dciii' == computer_dictionary['hostname']:
                print('Add breakpoint here')
            # Sends the last seen date to get_days_since_last_seen and converts this to days
            if 'lastSeenAt' in computer_dictionary.keys():
                computer_dictionary['Last_Seen'] = get_days_since_last_seen(computer_dictionary['lastSeenAt'])
                works = 1
            if works == 0:
                # API is returning incomplete machine fields
                computer_dictionary['hostname'] = 'Unknown'
                computer_dictionary['Sub Estate'] = name
                computer_dictionary['Machine_URL'] = 'N/A'
                computer_list.append(computer_dictionary)
                continue
            if 'health' in computer_dictionary.keys():
                if 'status' in computer_dictionary['health']['services']:
                    computer_dictionary['service_health'] = computer_dictionary['health']['services']['status']
                else:
                    computer_dictionary['service_health'] = 'investigate'
                if 'status' in computer_dictionary['health']['threats']:
                    computer_dictionary['threats'] = computer_dictionary['health']['threats']['status']
                else:
                    computer_dictionary['threats'] = 'investigate'
                #Any filtering you want to do has to done above this line as it changes the health dictionary
                computer_dictionary['health'] = computer_dictionary['health']['overall']
            # Check to see if the key value for platform returns Mac. If so make the OS key equal the Mac version else return the platform name for Windows and Linx
            if 'macOS' in computer_dictionary['os']['platform']:
                computer_dictionary['os'] = str(computer_dictionary['os']['platform']) + ' ' + str(computer_dictionary['os']['majorVersion']) + '.' + str(computer_dictionary['os']['minorVersion']) + '.' + str(computer_dictionary['os']['build'])
            else:
                computer_dictionary['os'] = computer_dictionary['os']['name']
            # If a user is returned tidy up the value. It is checking for the key being present
            if 'associatedPerson' in computer_dictionary.keys():
                computer_dictionary['associatedPerson'] = computer_dictionary['associatedPerson']['viaLogin']
            # Checks to see if there is a encryption status
            if 'encryption' in all_computers.keys():
                # I don't think this is the best code. The encryption status is a dictionary, with a list, another dictionary, then the status
                # At present this just reports one drive. The first one in the list. 0
                encryption_status = all_computers['encryption']['volumes']
                # Checks to see if the volume is returned correctly. Sometimes encryption is returned with no volume
                try:
                    volume_returned = encryption_status[0]
                    computer_dictionary['encryption'] = (encryption_status[0]['status'])
                except IndexError:
                    computer_dictionary['encryption'] = 'Unknown'
                    print()
                # computer_dictionary['encryption'] = (encryption_status[0]['status'])
            # Checks to see if the machine is in a group
            if 'group' in all_computers.keys():
                computer_dictionary['group'] = all_computers['group']['name']
            # Get installed products
            # Check if assignedProducts exists. It only works with Windows machines
            if 'assignedProducts' in all_computers.keys():
                for products in all_computers['assignedProducts']:
                    # This loops through the product names and gets the versions. We may not add these to the report
                    product_names = products['code']
                    computer_dictionary[product_names] = products['status']
                    product_version_name = f"v_{product_names}"
                    if products['status'] == 'installed' and versions == 1:
                        computer_dictionary[product_version_name] = products['version']
            #Provides direct link to the machines. Not working well with sub estate at the moment
            #computer_dictionary['Machine_URL'] = make_valid_client_id(computer_dictionary['type'],computer_dictionary['id'])
            computer_dictionary['Machine_URL'] = 'N/A'
            # Check to see if threat health is good. If no, go and find out why
            # if 'good' != computer_dictionary['threats']:
            #    get_threats(computers_url, computer_dictionary['id'])
            # Adds the sub estate name to the computer dictionary
            computer_dictionary['Sub Estate'] = name
            computer_list.append(computer_dictionary)
        # Check to see if you have more than 50 machines by checking if nextKey exists
        # We need to check if we need to page through lots of computers
        if 'nextKey' in computers_json['pages']:
            next_page = computers_json['pages']['nextKey']
            # Change URL to get the next page of computers
            # Example https://api-us01.central.sophos.com/endpoint/v1/endpoints?pageFromKey=<next-key>
            computers_url = url + '?pageFromKey=' + next_page
        else:
            # If we don't get another nextKey set page_count to 0 to stop looping
            page_count = 0

def get_days_since_last_seen(report_date):
    # https://www.programiz.com/python-programming/datetime/strptime
    # Converts report_date from a string into a DataTime
    convert_last_seen_to_a_date = datetime.strptime(report_date, "%Y-%m-%dT%H:%M:%S.%f%z")
    # Remove the time from convert_last_seen_to_a_date
    convert_last_seen_to_a_date = datetime.date(convert_last_seen_to_a_date)
    # Converts date to days
    days = (today - convert_last_seen_to_a_date).days
    return days

def get_threats(endpoint_url, endpoint_id):
    full_enpoint_url = endpoint_url + '/' + endpoint_id
    # https://api-{dataRegion}.central.sophos.com/endpoint/v1/endpoints/id
    request_threat = requests.get(endpoint_url, headers=headers)
    # Convert to JSON
    threat_json = request_threat.json()
    print('')

def make_valid_client_id(os, machine_id):
    # Characters to be removed
    # https://central.sophos.com/manage/server/devices/servers/b10cc611-7805-7419-e9f0-46947a4ab60e/summary
    # https://central.sophos.com/manage/endpoint/devices/computers/60b19085-7bbf-44ff-3a67-e58a3c4e14b1/summary
    Server_URL = 'https://central.sophos.com/manage/server/devices/servers/'
    Endpoint_URL = 'https://central.sophos.com/manage/endpoint/devices/computers/'
    # Remove the - from the id
    remove_characters_from_id = ['-']
    for remove_each_character in remove_characters_from_id:
        machine_id = machine_id.replace(remove_each_character, '')
    new_machine_id = list(machine_id)
    # Rotates the characters
    new_machine_id[::2], new_machine_id[1::2] = new_machine_id[1::2], new_machine_id[::2]
    for i in range(8, 28, 5):
        new_machine_id.insert(i, '-')
    new_machine_id = ''.join(new_machine_id)
    if os == 'computer':
        machine_url = Endpoint_URL + new_machine_id
    else:
        machine_url = Server_URL + new_machine_id
    return (machine_url)

def read_config():
    config = configparser.ConfigParser()
    config.read('edb_config.config')
    config.sections()
    ClientID = config['DEFAULT']['ClientID']
    ClientSecret = config['DEFAULT']['ClientSecret']
    ReportName = config['REPORT']['ReportName']
    ReportFilePath = config['REPORT']['ReportFilePath']
    # Checks if the last character of the file path contanins a \ or / if not add one
    if ReportFilePath[-1].isalpha():
        if os.name != "posix":
            ReportFilePath = ReportFilePath + "\\"
        else:
            ReportFilePath = ReportFilePath + "/"
    return(ClientID,ClientSecret,ReportName,ReportFilePath)

def report_field_names():
# Customise the column headers and column order
    versions = 0
    if versions == 0:
        fieldnames = ['Machine URL', 'Sub Estate', 'Hostname', 'Type', 'OS', 'Encrypted Status', 'Last Seen Date',
                      'Days Since Last Seen', 'Health', 'Threats',
                      'Service Health', 'Tamper Enabled', 'Group', 'Core Agent', 'Endpoint Protection', 'Intercept X',
                      'Device Encryption', 'MTR', 'IP Addresses', 'Last User']
        order = ['Machine_URL', 'Sub Estate', 'hostname', 'type', 'os', 'encryption', 'lastSeenAt', 'Last_Seen',
                 'health', 'threats', 'service_health', 'tamperProtectionEnabled', 'group', 'coreAgent',
                 'endpointProtection', 'interceptX',
                 'deviceEncryption', 'mtr', 'ipv4Addresses', 'associatedPerson', 'id']
    else:
        fieldnames = ['Machine URL', 'Sub Estate', 'Hostname', 'Type', 'OS', 'Encrypted Status', 'Last Seen Date',
                      'Days Since Last Seen', 'Health', 'Threats', 'Service Health', 'Tamper Enabled', 'Group',
                      'Core Agent', 'Core Agent Version', 'Endpoint Protection', 'Endpoint Protection Version',
                      'Intercept X',
                      'Intercept X Version', 'Device Encryption', 'Device Encryption Version', 'MTR', 'MTR Version',
                      'IP Addresses',
                      'Last User']
        order = ['Machine_URL', 'Sub Estate', 'hostname', 'type', 'os', 'encryption', 'lastSeenAt',
                 'Last_Seen', 'health', 'threats', 'service_health', 'tamperProtectionEnabled', 'group',
                 'coreAgent', 'v_coreAgent', 'endpointProtection', 'v_endpointProtection', 'interceptX', 'v_interceptX',
                 'deviceEncryption', 'v_deviceEncryption', 'mtr', 'v_mtr', 'ipv4Addresses',
                 'associatedPerson', 'id']
    return (fieldnames,order, versions)


def print_report():
    #Customise the column headers
    with open(full_report_path, 'w') as f:
        writer = csv.writer(f)
        writer.writerow(fieldnames)
    #Sets the column order
    with open(full_report_path, 'a+', encoding='utf-8', newline='') as output_file:
        dict_writer = csv.DictWriter(output_file, order)
        dict_writer.writerows(computer_list)

clientID, clientSecret, report_name, report_file_path = read_config()
full_report_path = report_file_path + report_name + timestamp + '.csv'

token_url = 'https://id.sophos.com/api/v2/oauth2/token'
headers = get_bearer_token(clientID, clientSecret, token_url)
organizationID, organizationHeader, organizationType = get_whoami()
get_all_sub_estates(organizationID)
fieldnames, order, versions = report_field_names()
for sub_etates_in_list in range(len(sub_estate_list)):
    sub_estate = sub_estate_list[sub_etates_in_list]
    sub_estateID = sub_estate['id']
    sub_estate_name = sub_estate['name']
    sub_estate_region = sub_estate['dataRegion']
    sub_estate_region_url = 'https://api-' + sub_estate_region + '.central.sophos.com/endpoint/v1/endpoints'
    print (f'Checking -  {sub_estate_name}')
    get_all_computers(sub_estateID, sub_estate_region_url, sub_estate_name)

print_report()
