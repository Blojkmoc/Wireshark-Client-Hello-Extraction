# -*- coding: utf-8 -*-
"""
Created on Wed Apr 13 13:49:18 2022

@author: Joseph Chng (joseph.chng@baesystems.com)
"""


import datetime 
import pandas as pd
import pyshark
import os
import time

'''
Convert pyshark.packet.fields.LayerFieldsContainer into string format
'''
def Pyshark_Converter(item):

    with open('file.txt', mode='w') as file_object:
        print(item, file=file_object)
    with open('file.txt', mode='r') as file_object:
        string = file_object.read().splitlines()
    return string[0]

'''
Get duration & src2dst bytes & dst2src bytes using given dataframe
'''
def Pyshark_Byte_Duration_Extender(df, src_client):    

    duration = []
    src_byte = []
    dst_byte = []
    for row in df.itertuples(index=True, name='Pandas'):
        duration.append(row.Timestamp)
        src = row.Src
        if src == src_client:
            src_byte.append(row.Bytes)
        else:
            dst_byte.append(row.Bytes)
    duration_s = max(duration) - min(duration)
    src_bytes = sum(src_byte)
    dst_bytes = sum(dst_byte)
    total_bytes = src_bytes + dst_bytes
    return total_bytes, src_bytes, dst_bytes, duration_s 

if __name__ == '__main__':
    
    final_product = pd.DataFrame()
    start_time = time.time()
    
    """
    Open saved pcap file from directory
    """    
    i = 0
    folder = r'C:\Users\moodl\Downloads\Packet-Analytics-master\Activities_Day1-20220413'
    for filename in os.listdir(folder):
        print(filename)
        f = os.path.join(folder,filename)
        cap = pyshark.FileCapture(f)
        """
        Iterate through the entire pcap file and find Client Hello signature as well as
        to get other TCP & TLS streams and obtain it as Reference 
        dataframe to easily loop through or else it will take very long
        """
        ls = []
        ref = []
        stream_list = []

        for pkt in cap:
            if ("TLS" in pkt):
                try:
                    with open('file.txt', mode='w') as file_object:
                        print(pkt.tls.handshake, file=file_object)
                except:
                    with open('file.txt', mode='w') as file_object:
                        print("[': ']", file=file_object)
                with open('file.txt', mode='r') as file_object:
                    string = file_object.read().splitlines()
                string = string[0].split(': ')[1]
                timestamp = pkt.frame_info.time_epoch
                times = Pyshark_Converter(timestamp)
                date_time = datetime.datetime.fromtimestamp(float(times))
                src = f'{pkt.ip.src}:{pkt.tcp.srcport}'
                dst = f'{pkt.ip.dst}:{pkt.tcp.dstport}'
                stream = pkt.tcp.stream
                
                if string == 'Client Hello':
                    try:
                        sni = pkt.tls.handshake_extensions_server_name
                    except:
                        sni = 'NA'
                    try:
                        alpn = pkt.tls.handshake_extensions_alpn_str
                    except:
                        alpn = 'NA'
                    if stream in stream_list:
                        continue
                    stream_list.append(stream)
                    ls.append([date_time,src,dst,sni,alpn,stream])
                byte = int(Pyshark_Converter(pkt.tcp.len))
                ref.append([float(times),src,dst,stream, byte])
                continue
        
            if ("TCP" in pkt):
                timestamp = pkt.frame_info.time_epoch
                string = Pyshark_Converter(timestamp)
                date_time = float(string)
                src = f'{pkt.ip.src}:{pkt.tcp.srcport}'
                dst = f'{pkt.ip.dst}:{pkt.tcp.dstport}'
        
                stream = pkt.tcp.stream
        
                byte = int(Pyshark_Converter(pkt.tcp.len))
                ref.append([date_time,src,dst,stream, byte])
        
        
        """
        Convert the Client Hello list into Pandas DataFrame for ease of use 
        
        """
        client_hello_df = pd.DataFrame(ls,columns=['Timestamp','Src','Dst','SNI','ALPN','Stream_ID'])
                  
        ref_df = pd.DataFrame(ref,columns=['Timestamp','Src','Dst','Stream_ID','Bytes'])
        
        """
        Iterate through the Client Hello dataframe by rows & go through the reference
        dataframe to get the stream bytes and duration information
        """
        
        concat = []
        
        for row in client_hello_df.itertuples(index=True, name='Pandas'):
            src = row.Src
            stream_id = row.Stream_ID
            timestamp = row.Timestamp
            temp_df = ref_df[ref_df['Stream_ID']==str(stream_id)]
            total_bytes, src_bytes, dst_bytes, duration_s = Pyshark_Byte_Duration_Extender(temp_df, src)
            concat.append([total_bytes, src_bytes, dst_bytes, duration_s])
            
        """
        Concatenate the Client Hello dataframe & Stream Dataframe to obtain the 
        final dataframe which will then be saved as csv file
        """
        
        conc = pd.DataFrame(concat,columns=['Total_size_bytes','Src_size_bytes','Dst_size_bytes','Duration_secs'])
        
        intermediate_product = pd.concat([client_hello_df, conc], axis=1)
        final_product = pd.concat([final_product, intermediate_product],axis=0,ignore_index=True)
        i+=1
        print(f'Finished File No. {i}')
        cap.close()
        
    
    
    final_product.to_csv('Activities_Day1-20220413_final.csv',index=False)
    print(f'--- {time.time()-start_time} seconds ---')
    
    




