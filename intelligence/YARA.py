import magic
import yara
import os
from typing import Optional
from _PARENT import INTELLIGENCE_PARENT

class INTELLIGENCE_CHILD__YARA(INTELLIGENCE_PARENT):
    
    def __init__(self, YaraDirPath:str):
        super().__init__("yara", None)
        self.YaraDirPath = YaraDirPath
        rule_files = {}
        
        for filename in os.listdir(self.YaraDirPath):
            if filename.endswith(".yar"):
                rule_files[filename] = os.path.join(self.YaraDirPath, filename)
                
        self.rules = yara.compile(filepaths=rule_files)
    
    def _match(self, FileBin:bytes)->Optional[list[dict]]:
        output:list[dict] = None
        
        
        matches = self.rules.match(data=FileBin)
        if(matches):
            output = []
            for match in matches:
                strings_list = []
                for s in match.strings:
                    # 튜플일 경우
                    if isinstance(s, tuple):
                        offset, identifier, data = s
                    # 객체일 경우
                    else:
                        offset = getattr(s, "offset", None)
                        identifier = getattr(s, "identifier", None)
                        data = getattr(s, "data", None)
                    strings_list.append({
                        "offset": offset,
                        "identifier": identifier,
                        "match": data
                    })

                output.append({
                    "rule": match.rule,
                    "namespace": match.namespace,
                    "tags": match.tags,
                    "meta": match.meta,
                    "strings": strings_list
                })
                
        return output
        
    # override
    def FILE_by_Binary( self, binary:bytes, size:int, sha256:Optional[str] )->Optional[dict]:
        if(not size): return None
        '''
            파일 바이너리와 SHA256을 얻어서 조회한다.
        '''
        return self._match(binary)
