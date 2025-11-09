import threading
from typing import Optional, Union
from intelligence._PARENT import INTELLIGENCE_PARENT
import sqlite3
from datetime import datetime
from requests import post
import json
from queue import Queue
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
        self.conn.row_factory = sqlite3.Row # SELECT 시 Dict으로 칼럼명: 값 포맷지원
        self.cursor = self.conn.cursor()
        self._create_tables()
        
        #Enable
        self.is_enable = True
        
        #self.Updates()
        threading.Thread(
            target = self.Updates,
            daemon=True
        ).start()
        
        
        self.async_new_query_update_queue = Queue()
        threading.Thread( target=self._async_new_query_data_by_queue,daemon=True ).start()
        
        
        
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
    
    def _direct_query(self, value:str) -> bool :
        #print(f"value->{value}")
        res = post(
            url = "https://threatfox-api.abuse.ch/api/v1/",
            headers = { "Auth-Key":self.API_KEY },
            data= \
                json.dumps({
                    "query" : "search_ioc",
                    "search_term" : value
                })
        )
        if(res.status_code == 200 ):
            JsonResponse = res.json()
            #print(JsonResponse)
            if(JsonResponse["query_status"] == "ok"):
                self._update_table( list[dict]( JsonResponse["data"] ) )
                return True # 한 개 이상 만족한 다이렉트 조회 결과
            
        return False
            
        
    
    def _query_indicator(self, Type:ThreatFoxEnum, Value:str)->Optional[list[dict]]:
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
        rows = [dict(row) for row in cur.fetchall()] # [{...},{...}] 포맷
        if(rows):
            return rows
        
        # 성능이슈로, 새로운 쿼리의 경우는 비동기적 큐기반으로 변경.
        self.async_new_query_update_queue.put(
            {
                "ioc_type": ioc_type,
                "Value": Value
            }
        )
        
        """else:
            print("없어서 추가진행")
            # 없는 경우 다이렉트 쿼리 진행
            self._direct_query(Value)
            
            # 다시 쿼리
            cur = self.conn.cursor()
            cur.execute("SELECT * FROM THREATFOX WHERE ioc_type = ? AND ioc_value = ? ", (ioc_type, Value))
            rows = [dict(row) for row in cur.fetchall()] # [{...},{...}] 포맷
            if(rows):
                return rows
            else:
                return None"""
        return None
        
    def _async_new_query_data_by_queue(self):
        while(True):
            new_query_data:dict = self.async_new_query_update_queue.get()
            ioc_type:str = new_query_data["ioc_type"]
            Value:str = new_query_data["Value"]
            
            self._direct_query(Value)
    
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
                
            print("Db Data Updated at ThreatFox Module...")
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
    