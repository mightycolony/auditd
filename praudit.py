import io
import subprocess
import time
import re

def stream_audit_logs():
    data_stream=[]
    final_data=[]
    process = subprocess.Popen(["praudit", "/dev/auditpipe"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    buffered_output = io.BufferedReader(process.stdout)
    while True:
        data = buffered_output.read(512)
        #data = process.stdout.readline()
        
        if not data:
            time.sleep(0.1)  
            continue
        
        data=data.decode("utf-8", errors="ignore")
        pattern = r'header.*?trailer,\d+'
        matches = re.findall(pattern, data, re.DOTALL)
        if len(matches) > 1:
                print(len(matches))
                for i in matches:
                    formated_data=[]
                    formated_data=i.split("\n")
                    if 'execve' in formated_data[0]:
                        if any('attribute' in item for item in formated_data):
                            #print(formated_data)
                            date=formated_data[0].split(",")[5]
                            command=" ".join(formated_data[1].split(",")[1:])
                            user=formated_data[3].split(",")[2]
                            ip=formated_data[4].split(",")[9]
                            print("date: {}, command:{}, user: {}, ip: {}".format(date,command,user,ip))
                            
                    #ssh login
                    if 'OpenSSH login' in formated_data[0]:                        
                        if any('text' in item for item in formated_data):
                            #print(formated_data)
                            date=formated_data[0].split(",")[5]
                            user=formated_data[1].split(",")[1]
                            if user == "-1":
                                user=formated_data[2].split(",")[1].split(" ")[3]        
                            content=formated_data[2].split(",")[1]
                            ip=formated_data[1].split(",")[9]
                            print("date: {}, content:{}, user: {}, ip: {}".format(date,content,user,ip))
                    
                            
        else:
                print(len(matches))
                processed_data = [item.replace("\n", " ") for item in matches]
                if any('attribute' in item for item in processed_data):
                            print(processed_data)
                            date=processed_data[0].split(",")[5]
                            command=" ".join(processed_data[1].split(",")[1:])
                            user=processed_data[3].split(",")[2]
                            ip=processed_data[4].split(",")[9]
                            print("date: {}, command:{}, user: {}, ip: {}".format(date,command,user,ip))
                            #print(processed_data)
if __name__ == "__main__":
    #with open ('test.txt' , "a" ) as file:
    stream_audit_logs()

        
        
        
