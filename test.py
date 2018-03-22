
import csv
import os

os.system(' tshark -r data.pcap -T fields -e frame.number -e _ws.col.Time -e _ws.col.Source -e _ws.col.Destination -e _ws.col.Protocol -e _ws.col.Length -e _ws.col.Info  -E header=y -E separator=, -E quote=d  > test1.csv')


frame_num=[]


length=[]
info=[]

def get_values():
    values = []
    with open('data.csv','rb') as f:
        reader=csv.reader(f)

        for row in reader:
            values.append(row)
    return values


def get_src():
    source_ip = []
    values = get_values()
    count = 0
    for row in values:
        if count is 0:
            count = count +1
            pass
        else:
            if row[2] not in source_ip:
                source_ip.append(row[2])
    
    return source_ip


def get_src_dest():
    dest_ip={}
    source_ip = get_src()
    values = get_values()
    for ip in source_ip:
        for row in values:

            if str(row[2]) == str(ip):
                if ip in dest_ip.keys():
                    if row[3] not in dest_ip[ip]:
                        dest_ip[ip].append(row[3])
                else:
                    dest_ip[ip]=[row[3]]
            

    return dest_ip


def get_payload_2():
    payload={}
    source_ip = get_src()
    values = get_values()
    for ip in source_ip:
        for row in values:

            if str(row[2]) == str(ip):
                if 'Payload' in row[6]:
                    if ip in payload.keys():
                        if row[3] in payload[ip]:
                            payload[ip][row[3]] = payload[ip][row[3]] + int(row[5])
                        else:
                            payload[ip][row[3]] = int(row[5])
                    else:
                        payload[ip]={row[3]:int(row[5])}

    return payload

def get_payload_1():
    payload={}
    source_ip = get_src()
    values = get_values()
    for ip in source_ip:
        for row in values:

            if str(row[2]) == str(ip):
                if 'Payload' in row[6]:
                    if ip in payload.keys():
                            payload[ip] = payload[ip] + int(row[5])
                    else:
                        payload[ip]=int(row[5])

    return payload


def dns_get():
    values = get_values()
    count=0
    websites=[]
    for row in values:
        if count is 0:
            count = count +1
            pass
        if 'DNS' in row[4]:
            if 'Standard query' in row[6] and 'response' not in row[6]:
                text = row[6].split(' ')
                for i in range(len(text)):
                    if '.' in text[i]:
                        if text[i] not in websites:
                            print text[i]
                            websites.append(text[i])
    return websites
                        
        

def dns_get2(web):
    values = get_values()
    count=0
    websites=[]
    blacklist={}
    for row in values:
        if count is 0:
            count = count +1
            pass
        if 'DNS' in row[4]:
            if 'Standard query' in row[6] and 'response' not in row[6]:
                text = row[6].split(' ')
                for i in range(len(text)):
                    if '.' in text[i]:
                        if web in text[i]:
                            if row[2] not in blacklist.keys():
                                blacklist[row[2]]=[text[i]]
                                print row[2],' visited ',text[i]
                            else:
                                if text[i] not in blacklist[row[2]]:
                                    blacklist[row[2]].append(text[i])
                                    print row[2],' visited ',text[i]
    return blacklist
    
                        
        
def avg_time_by_IP():
    src_IP=get_src()
    values=get_values()
    time_temp=0
    time_avg=0
    dicts={}
    count=0
    for IP in src_IP:
        for row in values:
            if IP in row[2]:
                count=count+1
                time_present=float(row[1])
                time=time_present-time_temp
                time_temp=float(time_present)
                time_avg=time_avg+time
        dicts[IP]="%.3f"%(time_avg/count)
        count=0
        print IP,'took an average time of',dicts[IP],'s'
    return dicts

             
            
def retransmission():
    ip_list={}
    source_ip = get_src()
    values = get_values()
    for ip in source_ip:
        for row in values:
            if 'TCP Retransmission' in row[6]:
                if str(row[2]) == str(ip):
                    if ip in ip_list.keys():
                        if row[3] not in ip_list[ip]:
                            ip_list[ip].append(row[3])
                    else:
                        ip_list[ip]=[row[3]] 

    return ip_list

##Find average time by every IP
##avg_time_by_IP()

##Find all source IPs
##print get_src()

##To get retransmission time
##y =retransmission()
##for i in y.keys():
##    print i, 'has sent retransmission message to', y[i]

##Fetch all IPs resolved
##dns_get()

##Find out illegal access
##dns_get2('twitter')

##Find data sent in bytes from a IP to all destination 
##payl = get_payload_2()
##
##for val in payl.keys():
##    for val2 in payl[val].keys():
##        print val,'has sent' ,val2,' ',payl[val][val2],'bytes'

##Find data sent by IP in bytes
##pay2 = get_payload_1()
##
##for val in pay2.keys():
##    print val,'has sent ' ,pay2[val],'bytes' 


##Find all source destination pairs
##dest=get_src_dest()
##for i in dest.keys():
##    print i,' has sent packet to' ,dest[i]
