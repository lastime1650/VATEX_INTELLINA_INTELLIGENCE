from typing import Optional, Union
from _PARENT import INTELLIGENCE_PARENT
import sqlite3
from datetime import datetime
from requests import post
import json
'''
    ABUSE.CH
    
    ThreatFox IOC
    
'''
from enum import Enum
class ThreatFoxEnum(Enum):
    IP_PORT = "ip:port"
    DOMAIN = "domain"
    URL = "url"
    HASH = "sha256_hash"
    
    

class INTELLIGENCE_CHILD__THREATFOX(INTELLIGENCE_PARENT):
    
    def __init__(self, API_KEY:str):
        super().__init__("threatfox", API_KEY)
        
        #SQLITE3
        self.SQLITE_DB_PATH = (self.my_pwd_dir) + "/resources/threatfox/" + "THREATFOX.db"
        self.conn = sqlite3.connect(self.SQLITE_DB_PATH, check_same_thread=False) # 멀티스레드 보장
        self.cursor = self.conn.cursor()
        self._create_tables()
        
        #Enable
        self.is_enable = True
        
        #self.Updates()
        
    def _create_tables(self):
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS THREATFOX (
            
                Primaryid TEXT  PRIMARY KEY,
                
                id TEXT,
                ioc_value TEXT,
                ioc_type TEXT,
                ioc_desc TEXT,
                threat_type TEXT,
                malware TEXT,
                malware_alias  TEXT,
                malware_printable  TEXT,
                first_seen_utc  TEXT,
                last_seen_utc  TEXT,
                confidence_level INT,
                refer  TEXT,
                tags  TEXT,
                reporter  TEXT
            );
        """)
        
    def _update_table(self, threatfoxJsons:list[dict]):
        for threatfoxJson in threatfoxJsons:
            
            # 기본키 값
            # id + first_seen str합친거
            Primaryid:str = threatfoxJson.get("id", "") + str(threatfoxJson.get("first_seen", "")).replace(" ", "")
            
            
            
            self.conn.execute("""
                REPLACE INTO THREATFOX (
                    Primaryid, id, ioc_value, ioc_type, ioc_desc, threat_type, malware, malware_alias, malware_printable, 
                    first_seen_utc, last_seen_utc, confidence_level, refer, tags, reporter
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
            """,
                (
                    Primaryid,
                    str(threatfoxJson.get("id", "")),
                    str(threatfoxJson.get("ioc", "")),
                    str(threatfoxJson.get("ioc_type", "")),
                    str(threatfoxJson.get("ioc_type_desc", "")),
                    str(threatfoxJson.get("threat_type", "")),
                    str(threatfoxJson.get("malware", "")),
                    str(threatfoxJson.get("malware_alias", "")),
                    str(threatfoxJson.get("malware_printable", "")),
                    str(threatfoxJson.get("first_seen", "")),
                    str(threatfoxJson.get("last_seen", "")),
                    int(threatfoxJson.get("confidence_level", 0)),
                    str(threatfoxJson.get("reference", "")),
                    ",".join(threatfoxJson.get("tags") or []),
                    str(threatfoxJson.get("reporter", "")),
                    
                )
            )
            self.conn.commit()
            
            
    
    def _queryNewIOC(self)->Optional[list[dict]]:
        res = post(
            url = "https://threatfox-api.abuse.ch/api/v1/",
            headers = { "Auth-Key":self.API_KEY },
            data= \
                json.dumps({
                    "query" : "get_iocs",
                    "days" : 7
                })
        )
        
        IOCs:dict = json.loads(res.content)
        try:
            if( IOCs["query_status"] == "ok" ):
                return list[dict]( IOCs["data"] )
            else:
                return None
        except:
            return None
        
    def _query_indicator(self, Type:ThreatFoxEnum, Value:str)->Optional[Union[dict, list[dict]]]:
        ioc_type:str = ""
        if(Type == ThreatFoxEnum.DOMAIN):
            ioc_type = "domain" #Value -> "x64.x3le.ru" ===> non-http://
        elif(Type == ThreatFoxEnum.IP_PORT):
            ioc_type = "ip:port" #Value -> "10.0.0.1:443" ===> non-http://
        elif(Type == ThreatFoxEnum.HASH):
            ioc_type = "sha256_hash"#Value -> "hash_string"
        elif(Type == ThreatFoxEnum.URL):
            ioc_type = "url"
        else:
            return None
        
        # query
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM THREATFOX WHERE ioc_type = ? AND ioc_value = ? ", (ioc_type, Value))
        rows= list[dict]( cur.fetchall() )
        if(rows):
            return rows
        else:
            return None
        
    
    # override
    '''
        업데이트
    '''
    def Updates(self):
        if(self.is_enable):
            
            self.is_updating = True
            
            NewIoC = self._queryNewIOC()
            if(NewIoC):
                self._update_table( NewIoC )
                self.update_last_seen = datetime.now()
            
            self.is_updating = False
    
    #def NETWORK_by_IPv4( self, ipv4:str )->Optional[dict]:
    def NETWORK_by_IPv4_with_PORT(self, ipv4:str, port:int ):
        return self._query_indicator(ThreatFoxEnum.IP_PORT,f"{ipv4}:{port}")
    def NETWORK_by_Domain( self, Domain:str ):
        return self._query_indicator(ThreatFoxEnum.DOMAIN,Domain)
    def NETWORK_by_URL( self, URL:str ):
        return self._query_indicator(ThreatFoxEnum.URL,URL)
    def FILE_by_SHA256( self, sha256:str ):
        return self._query_indicator(ThreatFoxEnum.HASH,sha256)
    