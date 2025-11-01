from typing import Optional
from abc import  ABC
from datetime import datetime

'''
    인텔리전스 로직에 관한 부모 클래스
    
    사용편리 **질의자입장** 를 위한 반화 작업을 위함
'''

class INTELLIGENCE_PARENT(ABC):
    
    
    
    def __init__(self, ModuleName:str, API_KEY:str=None):
        
        '''
            Global Members -- General
        '''
        self.API_KEY = API_KEY # API 키
        self.is_enable:bool = False # [활성여부] True여야 이 인텔리전스 모듈 사용가능
        self.INTELLIGANCE_module_name:str = ModuleName
        
        # 자신이 다른 곳에서 import되었더라도, 자신이 위치한 디렉터리를 찾음 -> {pathlib}/resource 로 문제없이 resource access
        from pathlib import Path
        abs_path = Path(__file__).resolve()
        self.my_abs:str = str(abs_path)          # with python file name (self)
        self.my_pwd_dir:str = str(abs_path.parent)   # without python file name
        
        '''
            Global Members -- Update
        '''
        self.is_updating:bool = False # True라면 업데이트중, False면 대기중
        self.update_last_seen:datetime = None# 최근 업데이트 일자
        
        '''
            Global Members -- Sqlite3
        '''
        self.SQLITE_DB_PATH:str = None
    
    def get_module_information(self)->dict:
        return {
            "name" : self.INTELLIGANCE_module_name,
            "is_enable": self.is_enable,
            "API_KEY" : self.API_KEY,
            "update": {
                "is_updating" : self.is_updating,
                "last_seen" : self.update_last_seen.isoformat() if self.update_last_seen else None
            },
            "sqlite3": {
                "db_name" : self.SQLITE_DB_PATH
            }
        }
    
    # 인텔리전스 업데이트 로직
    def Updates():
        raise NotImplementedError("Updates NotImplemented")
    #def Updates_by_Loop():
    #    raise NotImplementedError("Updates NotImplemented")
    
    '''
        Network
    '''
    def NETWORK_by_IPv4( self, ipv4:str )->Optional[dict]:
        raise NotImplementedError("NETWORK_by_IPv4 NotImplemented")
    def NETWORK_by_IPv4_with_PORT( self, ipv4:str, port:int )->Optional[dict]:
        raise NotImplementedError("NETWORK_by_IPv4_with_PORT NotImplemented")
    def NETWORK_by_Domain( self, Domain:str )->Optional[dict]:
        raise NotImplementedError("NETWORK_by_Domain NotImplemented")
    def NETWORK_by_URL( self, URL:str )->Optional[dict]:
        raise NotImplementedError("NETWORK_by_URL NotImplemented")
    
    '''
        File
    '''
    def FILE_by_SHA256( self, sha256:str )->Optional[dict]:
        raise NotImplementedError("FILE_by_SHA256 NotImplemented")
    
    def FILE_by_Binary( self, binary:bytes, size:int, sha256:Optional[str] )->Optional[dict]:
        raise NotImplementedError("FILE_by_Binary NotImplemented")
    
    '''
        Email
    '''
    def EMAIL( self, email:str )->Optional[dict]:
        raise NotImplementedError("EMAIL NotImplemented")
    
    '''
        Utility
    '''
    def DownloadALLSQliteTable(self)->Optional[list[dict]]: # SqliteDb 테이블 전체 다운로드 ( 빠짐없이 )
        raise NotImplementedError("DownloadALLSQliteTable NotImplemented")
    