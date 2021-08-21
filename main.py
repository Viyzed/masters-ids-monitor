from scapy.all import sniff
from scapy.all import wrpcap
import os
import logging 
import datetime
import boto3
from botocore.exceptions import ClientError

class PutLogs:
    
    # global varibales for log file filenames and S3 bucket name and path
    global filename, timestamp, object_name, bucket_name
    filename = ''
    timestamp = ''
    object_name = 'instance-logs/'
    bucket_name = 'masters-lb-access-logs'
        
    # scapy sniff for TCP packets on the enthernet interface
    def capturePackets(seconds):
        s3_client = boto3.client('s3')

        # compile filename to save the log file as 
        timestamp = datetime.datetime.now()
        timestamp = timestamp.strftime('%m') + '-' + timestamp.strftime('%d') + '-' + timestamp.strftime('%y') + '-' + timestamp.strftime('%X')
        global filename
        filename = str(timestamp+'_capture.pcap')

        # capture packets
        capture = sniff(filter='tcp', iface="eth0", timeout=seconds)
        wrpcap("pcaps/"+filename, capture)

    # upload papcket captures as .pcap to S3 bucket 
    def uploadPackets():
        s3_client = boto3.client('s3')
        
        # try/catch to upload .pcap file to S3 bucket and delete .pcap file from localhost
        try:
            response = s3_client.upload_file('pcaps/'+filename, bucket_name, object_name+filename)
            os.remove("pcaps/"+filename)
        except ClientError as e:
            logging.error(e)
            return False
        return True
    
    if __name__ == "__main__":
        while True:
            # run capture and upload every five seconds
            capturePackets(5)
            uploadPackets()
    
