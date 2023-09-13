import requests
import socket

vuln = ["VULNERABILITY_CVE_CRITICAL","VULNERABILITY_CVE_HIGH","VULNERABILITY_CVE_MEDIUM","VULNERABILITY_CVE_LOW"]

API_PUSOPS = "10e0a4a3f20bcff4e5268cd5e8e9160b07f5baa860efec1c38e7a56a3440ada9"
API_NSOC = "f3bb67104f945001c208ff008c2e000556c4d538b276612b2d5ad826e9bae7cf"
HOST_PUSOPS = "https://sf-3263aa3.hx.spiderfoot.net/"
HOST_NSOC = "https://sf-c11d0b1.hx.spiderfoot.net/"


class Kakilaba:
 
    # init method or constructor
    def __init__(this, search_name,category):
        this.search_name = search_name
        this.search_cat = category
        if category == "daerah":
            this.headers = {
                "content-type": "application/json",
                "X-API-KEY": API_NSOC
            }
            this.hosts = HOST_NSOC
        elif category == "pusat":
            this.headers = {
                "content-type": "application/json",
                "X-API-KEY": API_PUSOPS
            }
            this.hosts = HOST_PUSOPS
    
    def getIP(this,query):
        ret = socket.gethostbyname(query)
        return ret

    def getID(this,query):
    
        url = this.hosts+"api/v2/scans"

        querystring = {"page":"1",
                    "per_page":"1000"}

        response = requests.request("GET", url, headers=this.headers, params=querystring)

        search_id = ""
        for x in response.json():

            if(x['name'] == query):
                search_id = x['id']

        return search_id


    def getType(this,id):
        url = this.hosts+"api/v2/scans/"+id+"/summary"

        querystring = {"dimension":"element_type"}

        response = requests.request("GET", url, headers=this.headers, params=querystring)
        result = []
        for x in response.json():
            result.append(x['id'])
        return result

    def getResult(this,id,query):
        url = this.hosts+"/api/v2/scans/"+id+"/results"
        print(url)
        cat = ""
        if query == "VULNERABILITY_CVE_CRITICAL":
            cat = "CRITICAL"
        elif query == "VULNERABILITY_CVE_HIGH":
            cat = "HIGH"
        elif query == "VULNERABILITY_CVE_MEDIUM":
            cat = "MEDIUM"
        elif query == "VULNERABILITY_CVE_LOW":
            cat = "LOW"

        result = []
        for n in range(1,10):
            querystring = {"element_type":query,
                    "page":str(n),"per_page":"1000"
                    }
            response = requests.request("GET", url, headers=this.headers, params=querystring)
            for x in response.json():
                print(x)
                words = x['data'].split('\n')
                kata = words[2].split(' ')
                splitip = x['source'].split('/')
                print(splitip)
                
                if len(splitip)>1:
                    try:
                        ip = this.getIP(splitip[2])
                    except Exception as error:
                        print("An exception occurred:", error) 
                        splitlagi = splitip[2].split(':')
                        ip = splitlagi[0]
                else:
                    ip = splitip[0]
                
                
                combine = x['source']+";"+words[0]+";"+kata[1]+";"+cat+";"+ip
                result.append(combine)

        return result

    def downloadResource(this):
        txt = this.search_name+".csv"
        fileditulis=txt
        file1=open(fileditulis,"a")
        file1.write("source;vuln_name;vuln_score;vuln_category;ip\n")
        file1.close() 

        id = this.getID(this.search_name)
        for x in vuln:
            res = this.getResult(id,x)
            for x in res:
                file1=open(fileditulis,"a")
                file1.write(x+"\n")
                file1.close()   
        return txt
    # print(res)
    # coba = getType(id)
    # print(coba)
