from typing import Optional
import uvicorn
import json
from fastapi import FastAPI, Query, APIRouter, Body, Request

from intelligence._PARENT import INTELLIGENCE_PARENT

'''
    [Modules]
'''
from intelligence.sigcheck import INTELLIGENCE_CHILD__SIGCHECK
from intelligence.alien_otx import INTELLIGENCE_CHILD__OTX
from intelligence.YARA import INTELLIGENCE_CHILD__YARA
from intelligence.threatfox import INTELLIGENCE_CHILD__THREATFOX

class VATEX_INTELLINA():
    def __init__(
        self,
        ServerIP:str = "localhost",
        ServerPORT:int = 51034
    ):
        self.ServerIP:str = ServerIP
        self.ServerPORT:int = ServerPORT

        '''
            Intelligence Modules
        '''
        self.IntelligenceModules:list[INTELLIGENCE_PARENT] = self._get_intelligence_modules()
        
        
        
        # API 경로 설정
        self.app_router = APIRouter()
        self._setup_router()
        
        # API APP
        self.app =  FastAPI()
        self.app.include_router( self.app_router ) # app등록
        
    def _setup_router(self):
        
        '''
            Status
        '''
        self.app_router.get("/status")(self.STATUS)
        
        '''
            Network
        '''
        self.app_router.get("/network/ipv4")(self.NETWORK_IPV4)          # only ipv4
        self.app_router.get("/network/ipv4port")(self.NETWORK_IPV4_PORT)      # ipv4 and port

        '''
            File
        '''
        self.app_router.get("/file/sha256")(self.FILE_SHA256)           # only sha256
        self.app_router.post("/file/binary")(self.FILE_Binary)          # binary and sha256(not important)
        
        '''
            Email
        '''
        self.app_router.get("/email")(self.EMAIL)                 # email full account
        
        '''
            Windows
        '''
        #self.app_router.post("/windows/file/sigcheck")  # windows file sigcheck ( File 관련으로 이동 )
        
        '''
            Utility
        '''
        self.app_router.get("/download/sqlite") # Sqlite Database 전체다운로드

        '''
            Server
        '''
        self.app_router.get("/server/export")(self._export_server) # 서버 - 정보반환
        
    # Running
    def Run(self):
        uvicorn.run(
            self.app,
            host=self.ServerIP,
            port=self.ServerPORT,
            access_log=False
        )
    
    # API
    '''
        Status
    '''
    async def STATUS(self):
        return {
            "is_success": True
        }
        
    '''
        Network
    '''
    async def NETWORK_IPV4(self, Ipv4:Optional[str] = Query(None) ):
        
        Output:dict = {
            "is_success": False,
            "result": {}
        }
        
        if( Ipv4 ):
            for module in self.IntelligenceModules:
                try:
                    Output["result"][ module.INTELLIGANCE_module_name ] = module.NETWORK_by_IPv4(Ipv4)
                except NotImplementedError: # 구현이 안된 모듈의 경우 예외발생
                    continue
            if ( len(Output["result"]) > 0 ):
                Output["is_success"] = True
            
        return json.dumps(Output)
    
    async def NETWORK_IPV4_PORT(self, Ipv4:Optional[str] = Query(None), Port:Optional[int] = Query(None) ):
        
        Output:dict = {
            "is_success": False,
            "result": {}
        }
        
        if( Ipv4 and Port):
            for module in self.IntelligenceModules:
                try:
                    Output["result"][ module.INTELLIGANCE_module_name ] = module.NETWORK_by_IPv4_with_PORT(Ipv4, Port)
                except NotImplementedError: # 구현이 안된 모듈의 경우 예외발생
                    continue
            if ( len(Output["result"]) > 0 ):
                Output["is_success"] = True
                    
        return json.dumps(Output)
    
    '''
        File
    '''
    async def FILE_SHA256(self, Sha256:Optional[str] = Query(None)):
        Output:dict = {
            "is_success": False,
            "result": {}
        }
        
        if(Sha256):
            for module in self.IntelligenceModules:
                try:
                    Output["result"][ module.INTELLIGANCE_module_name ] = module.FILE_by_SHA256(Sha256)
                except NotImplementedError: # 구현이 안된 모듈의 경우 예외발생
                    continue
            if ( len(Output["result"]) > 0 ):
                Output["is_success"] = True
        
        return json.dumps(Output)
    
    async def FILE_Binary(self, Base64Binary:Optional[str] = Body(None)):
        Output:dict = {
            "is_success": False,
            "result": {}
        }
        import base64
        
        if(Base64Binary):
            
            # base64 to bytes 변환
            Bin:bytes = None
            
            try:
                Bin = base64.b64decode(Base64Binary)
            except:
                Bin = None
            
            
            if(Bin):
                for module in self.IntelligenceModules:
                    try:
                        Output["result"][ module.INTELLIGANCE_module_name ] = module.FILE_by_Binary(Bin,len(Bin))
                    except NotImplementedError: # 구현이 안된 모듈의 경우 예외발생
                        continue
                if ( len(Output["result"]) > 0 ):
                    Output["is_success"] = True
        
        return json.dumps(Output)
    
    '''
        Email
    '''
    async def EMAIL(self, EmailFull:Optional[str] = Query(None)):
        Output:dict = {
            "is_success": False,
            "result": {}
        }
        
        if(EmailFull):
            for module in self.IntelligenceModules:
                try:
                    Output["result"][ module.INTELLIGANCE_module_name ] = module.EMAIL(EmailFull)
                except NotImplementedError: # 구현이 안된 모듈의 경우 예외발생
                    continue
                if ( len(Output["result"]) > 0 ):
                    Output["is_success"] = True
        
        return json.dumps(Output)
    '''
        Windows (Not Use Now)
    '''
    '''
        Sqlite_Download 
    '''
    async def Download_Sqlite_datas(self, ModuleName:Optional[str] = Query(None)):
        Output:dict = {
            "is_success": False,
            "result": []
        }
        
        for module in self.IntelligenceModules:
            
            if( ModuleName ):
                # [1/2] 특정 한 모듈 타겟
                if(module.INTELLIGANCE_module_name.lower() == ModuleName.lower()):
                    try:
                        Output["result"].append( module.DownloadALLSQliteTable() )
                    except:
                        break
            else:
                # [2/2] Download ALL
                try:
                    Output["result"].append( module.DownloadALLSQliteTable() )
                except:
                    continue
                
    
        return json.dumps(Output,ensure_ascii=False)
    
    # Export Server Info
    '''
        VATEX_INTELLINA 인텔리전스 정보 모두 반환
    '''
    async def _export_server(self):
        return json.dumps(
            {
                "serverip": self.ServerIP,
                "serverport": self.ServerPORT,
                "modules": [  module.INTELLIGANCE_module_name for module in self.IntelligenceModules ]
            }
        )
    
    
    # Intelligence Standby
    def _get_intelligence_modules(self)->list[INTELLIGENCE_PARENT]:
        return \
            [
                INTELLIGENCE_CHILD__OTX(API_KEY="API-KEY"),    # Alien Vault OTX Module
                INTELLIGENCE_CHILD__SIGCHECK(),          # Windows SigChecker Module
                INTELLIGENCE_CHILD__YARA("./intelligence/resources/yara"),
                INTELLIGENCE_CHILD__THREATFOX(API_KEY="API-KEY")
            ]
        


if ( __name__ == "__main__" ):
    print("VATEX INTELLINA INTELLIGENCE")
    VATEX_INTELLINA("0.0.0.0", 51034).Run()