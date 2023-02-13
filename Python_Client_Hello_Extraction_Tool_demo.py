# -*- coding: utf-8 -*-
"""
Created on Sat May 28 20:27:53 2022

@author: Joseph Chng (joseph.chng@baesystems.com)
"""

'''
This script will attempt to remove the Pyshark Converter function and see if we
can remove the use of writing to a text file as it will reduce the time needed
with the use of f-strings
'''

import datetime 
import pandas as pd
import pyshark
import os
import time
import itertools
import configparser
import sys

config = configparser.ConfigParser()
config.read('config.ini')

'''
Get duration & src2dst bytes & dst2src bytes using given dataframe
'''
def Pyshark_Byte_Duration_Extender(df, src_client):    

    duration = []
    src_byte = []
    dst_byte = []
    packets = len(df.index)
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
    return packets, total_bytes, src_bytes, dst_bytes, duration_s 

'''
Create the list for dataframe in the proper format 
i.e. [timestamp,src,dst,stream,sni,alpn,host,user_agent,query_name,response_add]
'''

def Dataframe_Setter(ls,sni='N.A.',alpn='N.A.',host='N.A.',
                     user_agent='N.A.',query_name='N.A.',response_add='N.A.'):
    l = []

    l.append(ls)
    l.append([sni,alpn,host,user_agent,query_name,response_add])
    
    return list(itertools.chain(*l)) 


def Pyshark_Iterator(filename,full_dir):
    f = os.path.join(full_dir,filename)
    cap = pyshark.FileCapture(f)
    """
    Iterate through the entire pcap file and find Client Hello signature as well as
    to get other TCP & TLS streams and obtain it as Reference 
    dataframe to easily loop through or else it will take very long
    """
    ls = []
    ref = []
    stream_list = set()
    tcp_udp_stream_set = set()
    
    for pkt in cap:
        timestamp = pkt.frame_info.time_epoch
        times = f'{timestamp}'
        date_time = datetime.datetime.fromtimestamp(float(times))
        if ("TLS" in pkt):
            try:
                string = f'{pkt.tls.handshake}'.split(": ")[1]
            except:
                string = ''

            src = f'{pkt.ip.src}:{pkt.tcp.srcport}'
            dst = f'{pkt.ip.dst}:{pkt.tcp.dstport}'
            stream = f'TCP-{pkt.tcp.stream}'
            
            if string == 'Client Hello':
                try:
                    sni = pkt.tls.handshake_extensions_server_name
                except:
                    sni = 'N.A.'
                try:
                    alpn = pkt.tls.handshake_extensions_alpn_str
                except:
                    alpn = 'N.A.'
                if stream in stream_list:
                    continue
                if stream in tcp_udp_stream_set:
                    tcp_udp_stream_set.remove(stream)
                    stream_dict['Unclassified TCP']-=1
                stream_list.add(stream)
                temp_l = [filename,date_time,src,dst,'TLS',stream]
                ls.append(Dataframe_Setter(temp_l,sni=sni,alpn=alpn))
                stream_dict['TLS']+=1
            byte = int(f'{pkt.tcp.len}')
            ref.append([float(times),src,dst,stream, byte])
            
            continue
        
        if ("QUIC" in pkt):
            try:
                src = f'{pkt.ip.src}:{pkt.udp.srcport}'
            except:
                src = f'{pkt.ip.src}:{pkt.icmp.udp_dstport}'
            try:
                dst = f'{pkt.ip.dst}:{pkt.udp.dstport}'
            except:
                dst = f'{pkt.ip.dst}:{pkt.icmp.udp_srcport}'
            try:
                stream = f'UDP-{pkt.udp.stream}'
            except:
                stream = f'UDP-{pkt.icmp.udp_stream}'
            if stream not in stream_list:
                if stream in tcp_udp_stream_set:
                    tcp_udp_stream_set.remove(stream)
                    stream_dict['Unclassified UDP']-=1
                stream_list.add(stream)
                temp_l = [filename,date_time,src,dst,'QUIC',stream]
                try:
                    sni = pkt.quic.tls_handshake_extensions_server_name
                except:
                    sni = 'N.A.'
                try:
                    alpn = pkt.quic.tls_handshake_extensions_alpn_str
                except:
                    alpn = 'N.A.'
                ls.append(Dataframe_Setter(temp_l,sni=sni,alpn=alpn))
                stream_dict['QUIC']+=1
            try:
                byte = int(f'{pkt.udp.length}')
            except:
                byte = int(f'{pkt.icmp.udp_length}')
            ref.append([float(times),src,dst,stream, byte])
            
            continue
        
        if ("HTTP" in pkt):
            src = f'{pkt.ip.src}:{pkt.tcp.srcport}'
            dst = f'{pkt.ip.dst}:{pkt.tcp.dstport}'
            stream = f'TCP-{pkt.tcp.stream}'
            if stream not in stream_list:
                if stream in tcp_udp_stream_set:
                    tcp_udp_stream_set.remove(stream)
                    stream_dict['Unclassified TCP']-=1
                stream_list.add(stream)
                temp_l = [filename,date_time,src,dst,'HTTP',stream]
                try:
                    host = pkt.http.host
                except:
                    host = 'N.A.'
                try: 
                    user_agent = pkt.http.user_agent
                except:
                    user_agent = 'N.A.'
                ls.append(Dataframe_Setter(temp_l,host=host,user_agent=user_agent))
                stream_dict['HTTP']+=1
            byte = int(f'{pkt.tcp.len}')
            ref.append([float(times),src,dst,stream, byte])
            
            continue
        
        if ("DNS" in pkt):
            try:
                src = f'{pkt.ip.src}:{pkt.udp.srcport}'
            except AttributeError:
                try:
                    src = f'{pkt.ip.src}:{pkt.icmp.udp_dstport}'
                except:
                    src = f'{pkt.ip.src}:{pkt.tcp.srcport}'
            try:
                dst = f'{pkt.ip.dst}:{pkt.udp.dstport}'
            except AttributeError:
                try:
                    dst = f'{pkt.ip.dst}:{pkt.icmp.udp_srcport}'
                except:
                    dst = f'{pkt.ip.dst}:{pkt.tcp.dstport}'
            try:
                stream = f'UDP-{pkt.udp.stream}'
            except AttributeError:
                try:
                    stream = f'UDP-{pkt.icmp.udp_stream}'
                except:
                    stream = f'TCP-{pkt.tcp.stream}'
            try:
                response = pkt.dns.a
            except:
                response = 'N.A.'
            query = pkt.dns.qry_name
            if response != 'N.A.':
                if stream in tcp_udp_stream_set:
                    tcp_udp_stream_set.remove(stream)
                    stream_dict['Unclassified UDP']-=1
                stream_list.add(stream)
                temp_l = [filename,date_time,src,dst,'DNS',stream]
                ls.append(Dataframe_Setter(temp_l,query_name=query,response_add=response))
                stream_dict['DNS']+=1
            try:
                byte = int(f'{pkt.udp.length}')
            except AttributeError:
                try:
                    byte = int(f'{pkt.icmp.udp_length}')
                except:
                    byte = int(f'{pkt.tcp.len}')
            ref.append([float(times),src,dst,stream, byte])
            
            continue
    
        if ("TCP" in pkt):
            #string = f'{timestamp}'
            #date_time = float(string)
            src = f'{pkt.ip.src}:{pkt.tcp.srcport}'
            dst = f'{pkt.ip.dst}:{pkt.tcp.dstport}'
            stream = f'TCP-{pkt.tcp.stream}'
            if stream not in stream_list and stream not in tcp_udp_stream_set:
                tcp_udp_stream_set.add(stream)
                stream_dict['Unclassified TCP']+=1
                temp_l = [filename,date_time,src,dst,'Unclassified TCP',stream]
                ls.append(Dataframe_Setter(temp_l))
                
            
            byte = int(f'{pkt.tcp.len}')
            ref.append([float(times),src,dst,stream, byte])
            continue
        
        if ("UDP" in pkt):
            try:
                src = f'{pkt.ip.src}:{pkt.udp.srcport}'
                dst = f'{pkt.ip.dst}:{pkt.udp.dstport}'
            except:
                src = f'{pkt.ipv6.src}:{pkt.udp.srcport}'
                dst = f'{pkt.ipv6.dst}:{pkt.udp.dstport}'
            stream = f'UDP-{pkt.udp.stream}'
            if stream not in stream_list and stream not in tcp_udp_stream_set:
                tcp_udp_stream_set.add(stream)
                temp_l = [filename,date_time,src,dst,'Unclassified UDP',stream]
                ls.append(Dataframe_Setter(temp_l))
                stream_dict['Unclassified UDP']+=1
            byte = int(f'{pkt.udp.length}')
            ref.append([float(times),src,dst,stream, byte])
            continue
    
    
    """
    Convert the Client Hello list into Pandas DataFrame for ease of use 
    
    """
    client_hello_df = pd.DataFrame(ls,columns=['Filename','Timestamp','Src','Dst','Protocol','Stream_ID',
                                               'SNI','ALPN','Host','User_Agent','Query_Name',
                                               'Response_Add'])
    #print(f'Client Hello: {client_hello_df.shape}')
    df = client_hello_df.loc[~(client_hello_df['Protocol'].isin(['Unclassified TCP','Unclassified UDP']) & client_hello_df['Stream_ID'].isin(stream_list))]

    #print(f'df: {df.shape}')
              
    ref_df = pd.DataFrame(ref,columns=['Timestamp','Src','Dst','Stream_ID','Bytes'])
    
    """
    Iterate through the Client Hello dataframe by rows & go through the reference
    dataframe to get the stream bytes and duration information
    """
    
    concat = []
    
    for row in df.itertuples(index=True, name='Pandas'):
        src = row.Src
        stream_id = row.Stream_ID
        timestamp = row.Timestamp
        temp_df = ref_df[ref_df['Stream_ID']==str(stream_id)]
        packets, total_bytes, src_bytes, dst_bytes, duration_s = Pyshark_Byte_Duration_Extender(temp_df, src)
        concat.append([packets, total_bytes, src_bytes, dst_bytes, duration_s])
        
    """
    Concatenate the Client Hello dataframe & Stream Dataframe to obtain the 
    final dataframe which will then be saved as csv file
    """
    
    conc = pd.DataFrame(concat,columns=['Total_packets','Total_size_bytes','Src_size_bytes','Dst_size_bytes','Duration_secs'])
    
    
    #print(f'conc: {conc.shape}')
    cap.close()
    return df, conc

if __name__ == '__main__':
    
    banner = """
IPA PCAP Analysis Tool
Version 1.0
BAE Systems
For Internal use. Not for distribution.
Application created by Joseph Chng (joseph.chng@baesystems.com)
          """
    final_product = pd.DataFrame()
    start_time = time.time()
    
    help_line = False
    folder_use = False
    file_use = False
    
    try:
       argument = sys.argv[1]
       if sys.argv[1] == '-h':
          help_line = True
       if sys.argv[1] == '-single':
          file_use = True
       if sys.argv[1] == '-multi':
          folder_use = True
    except:
       pass 
   
    

    """
    Help exe
    """
    if help_line:
        print("""
To execute (example)
For single file: IPA-PAT.exe -single <filename>
For folder: IPA-PAT.exe -multi <folder_name>

PCAP file/folder directory:
- Place the pcap file/folder in the same directory as the application
          """)
         
        help_line = False
        
    """
    Open saved pcap file from directory
    """    
    i = 0
    stream_dict = {'TLS': 0, 'QUIC': 0, 'HTTP': 0, 'DNS': 0, 'Unclassified TCP': 0,
                   'Unclassified UDP': 0}
    
    if folder_use:
        #folder_name = f"{config['FOLDER']['folder_path']}"
        folder_name = sys.argv[2]
        csv_name = folder_name
        path = os.getcwd()
        full_dir =  os.path.join(path,folder_name)
        folder = full_dir.split("\\")[-1]
        print(banner)
        for filename in os.listdir(full_dir):
            print(filename)
            
            df, conc = Pyshark_Iterator(filename, full_dir)
            
            intermediate_product = pd.concat([df.reset_index(drop=True), conc.reset_index(drop=True)], axis=1)
            #print(f'Intermediate: {intermediate_product.shape}')
            final_product = pd.concat([final_product, intermediate_product],axis=0,ignore_index=True)
            i+=1
            print(f'Finished File No. {i}')
            #cap.close()
        folder_use = False
        final_product.to_csv(f'{csv_name}.csv',index=False)
        print(f'--- {time.time()-start_time} seconds ---')
        for key in stream_dict:
            print(f'There are {stream_dict[key]} {key} streams')
    
    if file_use:
        filename = sys.argv[2]
        
        # Check for correct file format
        if filename.endswith(".pcap"):
            csv_name = filename.split(".")[0]
            path = os.getcwd()
            print(banner)
            print(filename)
            
            df, conc = Pyshark_Iterator(filename, path)
            
            intermediate_product = pd.concat([df.reset_index(drop=True), conc.reset_index(drop=True)], axis=1)
            #print(f'Intermediate: {intermediate_product.shape}')
            final_product = pd.concat([final_product, intermediate_product],axis=0,ignore_index=True)
            i+=1
            print(f'Finished File No. {i}')
            #cap.close()
            folder_use = False
            
            final_product.to_csv(f'{csv_name}.csv',index=False)
            print(f'--- {time.time()-start_time} seconds ---')
            for key in stream_dict:
                print(f'There are {stream_dict[key]} {key} streams')
        else:
            print("Wrong file format! Use .pcap file")
    
    
    
    
    



