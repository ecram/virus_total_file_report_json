import os
import hashlib
import time
import requests
import json
from pathlib import Path
import csv

# Global variables.
count = 1

# Get the next key.
def getkey(count):
    mod = count % 4
    if mod == 1:
        apikey = key1
    elif mod == 2:
        apikey = key2
    elif mod == 3:
        apikey = key3
    else:
        apikey = key4
    print("Select the apikey: ", apikey)
    count+=1
    return count, apikey

# Get total virus json report.
def getvtjson(apikey, resource, fname):
    url = "https://www.virustotal.com/api/v3/files/"+resource
    headers = {
        "accept": "application/json",
        "x-apikey": apikey
    }
    response2 = requests.get(url, headers=headers)
    print(response2)
    if response2.status_code == 204:
        print("Error 204")
    elif response2.status_code == 403:
        print("Error 403")
    elif response2.status_code == 404:
        print("Error 404")
    elif response2.status_code == 429:
        print("Error 429")
    else:
        data = response2.json()
        try:
            sample = data['data']['attributes']['popular_threat_classification']['suggested_threat_label']
        except:
            sample = 'ND'
        try:
            positives = data['data']['attributes']['last_analysis_stats']['malicious']
        except:
            positives = 'ND'
        try:
            md5 = data['data']['attributes']['md5']
        except:
            md5 = 'ND'
        print("File {}, classified '{}' with Positives {}.".format(fname, sample, positives))
        #print(response2.text)
        with open(fname+'.json', 'w') as f:
            json.dump(data, f, ensure_ascii=False)
            print("File Json",fname,"saved.")
        return data
    data = False
    return data

# For better way to get error in json objects
def safe_execute(get_data):
    try:
        aux = get_data
    except KeyError as ke:
        aux = 'ND'
    return aux

# Extract data information to csv file.
def save_data_to_csv(data, fname):
    data = data['data']['attributes']
    csv_file = "executables_samples.csv"
    header = ['Name', 'Type', 'MD5', 'SHA1', 'SHA256', 'File_Type', 'Filetype', 'Threat_Label', 
              'Threat_Category', 'Type_Extension', 'Times_Submitted', 'Rule_Category', 
              'Alert_Severity', 'Library_Name', 'Malicious', 'Undetected', 'Type-Unsupported', 
              'Failure', 'Confirmed-Timeout', 'Harmless', 'Suspicious', 'Kaspersky_category', 
              'Kaspersky_result', 'BitDefender_category', 'BitDefender_result', 'Avast_category', 
              'Avast_result', 'ESET-NOD32_category', 'ESET-NOD32_result']
    Name = fname
    try:
        Type = data['type_description']
    except:
        Type = 'ND'
    try:
        MD5 = data['md5']
    except:
        MD5 = 'ND'
    try:
        SHA1 = data['sha1']
    except:
        SHA1 = 'ND'
    try:
        SHA256 = data['sha256']
    except:
        SHA256 = 'ND'
    try:
        aux = data['trid']
        File_Type = [i['file_type'] for i in aux]
    except:
        File_Type = 'ND'
    try:
        Filetype = data['detectiteasy']['filetype']
    except:
        Filetype = 'ND'
    try:
        Threat_Label = data['popular_threat_classification']['suggested_threat_label']
    except:
        Threat_Label = 'ND'
    try:
        Threat_Category = data['popular_threat_classification']['popular_threat_category']
    except:
        Threat_Category = 'ND'
    try:
        Type_Extension = data['type_extension']
    except:
        Type_Extension = 'nd'
    try:
        Times_Submitted = data['times_submitted']
    except:
        Times_Submitted = 'ND'
    try:
        Rule_Category = data['crowdsourced_ids_results'][0]['rule_category']
    except:
        Rule_Category = 'ND'
    try:
        Alert_Severity = data['crowdsourced_ids_results'][0]['alert_severity']
    except:
        Alert_Severity = 'ND'
    try:
        aux = data['pe_info']['import_list']
        library_name = [i['library_name'] for i in aux]
    except:
        library_name = 'ND'
    try:
        malicious = data['last_analysis_stats']['malicious']
    except:
        malicious = 'ND'
    try:
        undetected = data['last_analysis_stats']['undetected']
    except:
        undetected = 'ND'
    try:
        type_unsupported = data['last_analysis_stats']['type-unsupported']
    except:
        type_unsupported = 'ND'
    try:
        failure = data['last_analysis_stats']['failure']
    except:
        failure = 'ND'
    try:
        confirmed_timeout = data['last_analysis_stats']['confirmed-timeout']
    except:
        confirmed_timeout = 'ND'
    try:
        harmless = data['last_analysis_stats']['harmless']
    except:
        harmless = 'ND'
    try:
        suspicious = data['last_analysis_stats']['suspicious']
    except:
        suspicious = 'ND'
    try:
        Kaspersky_category = data['last_analysis_results']['Kaspersky']['category']
    except:
        Kaspersky_category = 'ND'
    try:
        Kaspersky_result = data['last_analysis_results']['Kaspersky']['result']
    except:
        Kaspersky_result = 'ND'
    try:
        BitDefender_category = data['last_analysis_results']['BitDefender']['category']
    except:
        BitDefender_category = 'ND'
    try:
        BitDefender_result = data['last_analysis_results']['BitDefender']['result']
    except:
        BitDefender_result = 'ND'
    try:
        Avast_category = data['last_analysis_results']['Avast']['category']
    except:
        Avast_category = 'ND'
    try:
        Avast_result = data['last_analysis_results']['Avast']['result']
    except:
        Avast_result = 'ND'
    try:
        ESET_NOD32_category = data['last_analysis_results']['ESET-NOD32']['category']
    except:
        ESET_NOD32_category = 'ND'
    try:
        ESET_NOD32_result = data['last_analysis_results']['ESET-NOD32']['result']
    except:
        ESET_NOD32_result = 'ND'

    row = [Name, Type, MD5, SHA1, SHA256, File_Type, Filetype, Threat_Label, Threat_Category, 
           Type_Extension, Times_Submitted, Rule_Category, Alert_Severity, library_name, 
           malicious, undetected, type_unsupported, failure, confirmed_timeout, harmless, suspicious, 
           Kaspersky_category, Kaspersky_result, BitDefender_category, BitDefender_result, 
           Avast_category, Avast_result, ESET_NOD32_category, ESET_NOD32_result]

    FILE_PATH = Path("executables_samples.csv")

    if not FILE_PATH.exists():
        with open ('executables_samples.csv', 'w', encoding='UTF8', newline='') as f:
            writer = csv.writer(f)
            # write the header
            writer.writerow(header)
            # write row
            writer.writerow(row)
            print("File created, row was added and saved to the executables_samples.csv.")
    else:
        with open ('executables_samples.csv', 'a', encoding='UTF8', newline='') as f:
            writer = csv.writer(f)
            # write row
            writer.writerow(row)
            print("Row was added to the executables_samples.csv.")


# Put the address of the directory with the samples.
directory = '/home/user/Documents/samples/'
files = os.listdir(directory)
files1 = [int(x) for x in files]
files1.sort()

# Send samples to get SHA256 hash.
#for file1 in files1:
for file1 in range(935,1201):
    with open(directory+str(file1), "rb") as f:
        bytes = f.read() # read entire file as bytes
        resource = hashlib.sha256(bytes).hexdigest();
        print(str(file1),"has the sha256 hash",resource)
        # Get the apikey
        count, apikey = getkey(count)
        # Get the VirusTotal Json file
        data = getvtjson(apikey, resource, str(file1))
        if data != False:
            save_data_to_csv(data, str(file1))
        else:
            print(str(file1),"give an error en getvtjson function.")
        time.sleep(1)
        #if count == 12:
        #    break
