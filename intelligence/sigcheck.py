from intelligence.resources.sigcheck.Sigcheck import Check_sign_exe
from intelligence._PARENT import INTELLIGENCE_PARENT
import sqlite3
from typing import Optional

class INTELLIGENCE_CHILD__SIGCHECK(INTELLIGENCE_PARENT):
    def __init__(self):
        super().__init__("windows_sigchecker", None)
        
        #SQLITE3
        self.SQLITE_DB_PATH = (self.my_pwd_dir) + "/resources/sigcheck/" + "INTELLIGENCE_SIGCHECK.db"
        self.conn = sqlite3.connect(self.SQLITE_DB_PATH, check_same_thread=False) # 멀티스레드 보장
        self.cursor = self.conn.cursor()
        self._create_tables()
        
        #Enable
        self.is_enable = True
        
    def _create_tables(self):
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS SIGCHECK (
                
                sha256 TEXT PRIMARY KEY,
                sig_algorithm TEXT
                
            )
        """
        )
    def _update_table(self, sha256:str, sig_algorithm:str):
        self.conn.execute('''
            REPLACE INTO SIGCHECK (
                sha256, sig_algorithm
            ) 
            VALUES (
                ?, ?
            )
        ''',
        (sha256, sig_algorithm)
        )
        self.conn.commit()
    def _query_table(self, sha256:str)->Optional[str]:
        cur = self.conn.cursor()
        cur.execute("SELECT sig_algorithm FROM SIGCHECK WHERE sha256 = ?", (sha256,) )
        row = cur.fetchone()
        if row and row[0]:
            sig_algorithm = str(row[0])
            return sig_algorithm
        else:
            return None
             
        
    
    '''
        File
    '''
    def FILE_by_Binary(self, binary, size, sha256):
        if (size == 0):
            return None
        
        is_success:bool = False
        algorithm:Optional[str] = self._query_table(sha256)
        
        if( algorithm ):
            is_success = True
        else:
            algorithm = Check_sign_exe( binary )
            if( algorithm ):
                self._update_table(sha256, algorithm)
                is_success = True
        
        return \
            {
                "is_success": is_success,
                "algorithm": algorithm
            }
        