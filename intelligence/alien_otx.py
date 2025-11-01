from typing import Optional, Union 
from _PARENT import INTELLIGENCE_PARENT
import sqlite3
from datetime import datetime
from threading import Lock, Thread, Event
from concurrent.futures import ThreadPoolExecutor
'''
    Alien OTX
    
    pip install OTXv2
    
'''
from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes


from enum import Enum
class OTXIndicatorTypesEnum(Enum):
    CIDR  = "CIDR" # 209.52.176.0/22
    CVE = "CVE" # CVE-2025-40088
    Domain = "Domain"  # got-game.org, pgafan.net
    Email = "Email" # premiumloansteam@gmail.com ( with username )
    FileHash_IMPHASH = "FileHash-IMPHASH"
    FileHash_MD5 = "FileHash-MD5"
    FileHash_PEHASH = "FileHash-PEHASH"
    FileHash_SHA1 = "FileHash-SHA1"
    FileHash_SHA256 = "FileHash-SHA256"
    FilePath = "FilePath"
    Hostname = "Hostname"
    IPv4 = "IPv4"
    IPv6 = "IPv6"
    Mutex = "Mutex" # example: [ "love spells caster in New York", "5FjgkuPzAQHax3hXsSkNtue8E7moEYjTgrDDGxBvCzxc1nqR" ] 단순 문자열
    NIDS = "NIDS"
    URI = "URI" # example: /support/state/content/destination./navId.1
    URL = "URL" # example: http://115.55.62.62:53957/bin.sh
    YARA = "YARA" # example: GhostGrab_Malware_Detection ( Rule Name)
    Ja3 = "Ja3"
    Osquery = "Osquery"
    Sslcertfingerprint = "Sslcertfingerprint"
    Bitcoinaddress = "Bitcoinaddress"
    

class INTELLIGENCE_CHILD__OTX(INTELLIGENCE_PARENT):
    
    def __init__(self, API_KEY:str):
        super().__init__("otx",API_KEY)
        
        
        # OTX API_KEY
        self.API_KEY = API_KEY
        self.otx = OTXv2(API_KEY) # OTX 초기화
        
        
        #SQLITE3
        self.SQLITE_DB_PATH = (self.my_pwd_dir) + "/resources/alien_otx/" + "INTELLIGENCE_OTX.db"
        self.conn = sqlite3.connect(self.SQLITE_DB_PATH, check_same_thread=False) # 멀티스레드 보장
        self.cursor = self.conn.cursor()
        self._create_tables()
        self.Sqlite3_lock = Lock()
        
        #Enable
        self.is_enable = True
        
        # LoopUpdate
        self.LoopUpdateEvent = Event()
        self.LoopUpdateEventWaitSec = 5*3600 # 기본 5시간
        
        Thread(target=self._loopupdate, daemon=True).start()
        
        
        
    def __del__(self):
        print("OTX 클래스 삭제")
        self.is_loop_update_thread_working = False
        
    def _create_tables(self):
        self.cursor.execute("""
        CREATE TABLE IF NOT EXISTS OTX (
            
            Primaryid TEXT  PRIMARY KEY,
            
            id TEXT,
            name TEXT,
            description TEXT,
            author_name TEXT,
            modified TEXT,
            created TEXT,
            revision INT,
            tlp TEXT,
            public INT,
            adversary TEXT,
            
            indicators_id INT,
            indicators_indicator TEXT,
            indicators_type TEXT,
            indicators_created TEXT,
            indicators_content TEXT,
            indicators_title TEXT,
            indicators_description TEXT,
            indicators_expiration TEXT,
            indicators_is_active INT,
            indicators_role TEXT,
            
            tags TEXT,
            targeted_countries TEXT,
            malware_families TEXT,
            attack_ids TEXT,
            reference_list TEXT,
            industries TEXT,
            extract_source TEXT
            
        )
        """)
    def _update_pules_indicator(
        self,
        pulseJSON:dict, 
        if_indicator_expired_no_save:bool = True, # 가져온 펄스에 Indicator가 만료된 경우 추가하지 않을 지 여부
        if_saved_indicator_expired_remove = True  # 이미 Sqlite3에 저장된 Indicator가 만료된 경우 제거할 지 여부
    ):
        
        common_data = (
            pulseJSON.get("id"),
            pulseJSON.get("name"),
            pulseJSON.get("description"),
            pulseJSON.get("author_name"),
            pulseJSON.get("modified"),
            pulseJSON.get("created"),
            pulseJSON.get("revision"),
            pulseJSON.get("tlp"),
            pulseJSON.get("public"),
            pulseJSON.get("adversary"),
            # tags, countries, etc는 문자열로 변환
            ",".join(pulseJSON.get("tags", [])),
            ",".join(pulseJSON.get("targeted_countries", [])),
            ",".join(pulseJSON.get("malware_families", [])),
            ",".join(pulseJSON.get("attack_ids", [])),
            ",".join(pulseJSON.get("references", [])),
            ",".join(pulseJSON.get("industries", [])),
            ",".join(pulseJSON.get("extract_source", []))
        )
        
        for indicator in pulseJSON.get("indicators", []):
            
            
            # 해당 Indicator 가 expired 된 경우, no save !
            if(if_indicator_expired_no_save):
                expiration_time_str = indicator.get("expiration")
                expiration_time:datetime = datetime.fromisoformat( expiration_time_str )
                if( datetime.now() >= expiration_time ):
                    continue
            
            ''' 
                row 고유값 (PK) / Pulse 고유 ID + Indicator 고유 ID str 결합 값
            '''
            Primaryid:str = pulseJSON.get("id") + str( indicator.get("id") )
            
            # 이미 저장된 레코드에서 Indicator가 expired 된 경우, Remove
            if if_saved_indicator_expired_remove:
                with self.Sqlite3_lock: ################################################################################ LOCK
                    cur = self.conn.cursor()
                    cur.execute("SELECT indicators_expiration FROM OTX WHERE Primaryid = ?", (Primaryid,))
                    row = cur.fetchone()
                    if row and row[0]:
                        saved_expiration = datetime.fromisoformat(row[0])
                        if datetime.now() >= saved_expiration:
                            self.conn.execute("DELETE FROM OTX WHERE Primaryid = ?", (Primaryid,))
                            self.conn.commit()
                            continue
            
            
            
            
            #print(pulseJSON.get("id"), str( indicator.get("id")) )
            indicators = (
                indicator.get("id"),
                indicator.get("indicator"),
                indicator.get("type"),
                indicator.get("created"),
                indicator.get("content"),
                indicator.get("title"),
                indicator.get("description"),
                indicator.get("expiration"),
                indicator.get("is_active"),
                indicator.get("role")
            )
            
            with self.Sqlite3_lock:  ################################################################################ LOCK
                try:
                    # 덮어쓰기 형
                    self.conn.execute('''
                                    REPLACE INTO OTX (
                                        Primaryid, id, name, description, author_name, modified, created, revision, tlp, public, adversary,
                                        tags, targeted_countries, malware_families, attack_ids, reference_list, industries, extract_source,
                                        indicators_id, indicators_indicator, indicators_type, indicators_created, indicators_content, indicators_title, indicators_description, indicators_expiration, indicators_is_active, indicators_role
                                    ) 
                                    VALUES (
                                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                                        ?, ?, ?, ?, ?, ?, ?,
                                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                                    )
                                    ''',
                                    (Primaryid,) + common_data + indicators
                                    
                                    )
                    self.conn.commit()
                except Exception as e:
                    print(e)
                    
    def _search_indicator(self, query:str, type:IndicatorTypes)->bool:
        with self.Sqlite3_lock:
            pass
    
    def _loopupdate(self):
        while(True):
            if (self.is_enable):
                
                self.is_updating = True ###################### 실행 전환
                print("loop start")
                with ThreadPoolExecutor(max_workers=10) as executor:
                    pulses = self.otx.getall_iter(
                        limit=10,            # 한 번에 10개
                        max_page=None, 
                        modified_since=None
                    )
                    for pulse in pulses:
                        executor.submit(self._update_pules_indicator, pulse)
                print("loop end")
                quit()
                
                self.is_updating = False ##################### 대기 전환
                self.update_last_seen = datetime.now()
                
                # Event 형 대기 -> 다른 스레드에서 강제로 업데이트 요청시 바로 해야하므로
                self.LoopUpdateEvent.wait(
                    timeout=self.LoopUpdateEventWaitSec # 대기 초
                ) 
                
    def _query_indicator(self, Type:OTXIndicatorTypesEnum, Value:str)->Optional[Union[dict, list[dict]]]:
        ioc_type:str = Type.value
        
        # query
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM OTX WHERE indicators_type = ? AND indicators_indicator = ? ", (ioc_type, Value))
        rows= list[dict]( cur.fetchall() )
        if(rows):
            return rows
        else:
            return None
    
    # override
    '''
        업데이트
        
        1. 스레드 풀을 통해 제한적인 스레드 개수내에서 비동기적으로 Pulse별 DB 업데이트
        2. DB 업데이트시 _update_pules_indicator() 내장 메서드 인자값에 따라, 만료된 Indicator들은 제거하거나 추가하지 않도록 함.
        3. threading.Event -> self.LoopUpdateEvent을 사용하여 외부 다른 스레드에서 깨워서 바로 즉각 업데이트 가능
        
    '''
    def Updates(self):
        # 현재 업데이트 중 아닐 때
        if( self.is_updating == False):
            self.LoopUpdateEvent.set() # 자체 루프 업데이트 이벤트 진행

                
        
        
    def NETWORK_by_IPv4(self, ipv4:str ):
        '''
            ipv4 아이피 얻어서 조회한다.
        '''
        return self._query_indicator(OTXIndicatorTypesEnum.IPv4, ipv4)
    
    def NETWORK_by_Domain(self, domain: str):
        '''
        도메인 조회
        '''
        return self._query_indicator(OTXIndicatorTypesEnum.Domain, domain)

    def FILE_by_SHA256(self, sha256: str):
        '''
            SHA256 해시로 파일 조회
        '''
        return self._query_indicator(OTXIndicatorTypesEnum.FileHash_SHA256, sha256)
    
    '''
        Utility
    '''
    def DownloadSQliteDatabase(self)->Optional[bytes]:
        
        with self.Sqlite3_lock:
            try:
                db_bin = b''
                with open(self.SQLITE_DB_PATH, "wb") as f:
                    db_bin = f.read()
                return db_bin
                    
            except:
                return None
