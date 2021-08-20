from scapy.all import sniff
from scapy.all import wrpcap
import os
import logging 
import datetime
import boto3
from botocore.exceptions import ClientError

class PutLogs:
    
    global filename, timestamp, object_name, bucket_name
    filename = ''
    timestamp = ''
    object_name = 'instance-logs/'
    bucket_name = 'masters-lb-access-logs'
        
    def capturePackets(seconds):
        s3_client = boto3.client('s3')

        timestamp = datetime.datetime.now()
        timestamp = timestamp.strftime('%m') + '-' + timestamp.strftime('%d') + '-' + timestamp.strftime('%y') + '-' + timestamp.strftime('%X')
        global filename
        filename = str(timestamp+'_capture.pcap')

        capture = sniff(filter='tcp', iface="eth0", timeout=seconds)
        wrpcap("pcaps/"+filename, capture)

    def uploadPackets():
        s3_client = boto3.client('s3')
        try:
            response = s3_client.upload_file('pcaps/'+filename, bucket_name, object_name+filename)
            os.remove("pcaps/"+filename)
        except ClientError as e:
            logging.error(e)
            return False
        return True
    
    if __name__ == "__main__":
        while True:
            capturePackets(5)
            uploadPackets()
    
