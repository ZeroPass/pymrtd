#sudo apt-get install postgresql postgresql-contrib
#pip install sqlalchemy
#pip install psycopg2 sqlalchemy
#sudo -u postgres createuser --interactive

import sqlalchemy
from sqlalchemy import Table, Column, Integer, String, ForeignKey
from sqlalchemy.engine import Engine
from sqlalchemy.engine import Engine
from sqlalchemy.schema import MetaData
from sqlalchemy.orm import sessionmaker


"""
def connect(user: str, password: str, db: str, host='localhost', port=5432) -> Engine:
    '''Returns a connection and a metadata object'''
    # We connect with the help of the PostgreSQL URL
    url = 'postgresql://{}:{}@{}:{}/{}'
    url = url.format(user, password, host, port, db)

    # The return value of create_engine() is our connection object
    con = sqlalchemy.create_engine(url, client_encoding='utf8')

    # We then bind the connection to MetaData()
    meta = sqlalchemy.MetaData(bind=con, reflect=True)

    return con, meta

con, meta = connect('nejko', 'nejko', 'icao')
bula = 9
"""

class ConnectionError(Exception):
    pass

class Connection:
    """Manage ORM connection to save/load objects in database"""

    connectionObj = None
    metaData = None
    session = None

    def __init__(self, user: str, password: str, db: str, host='localhost', port=5432):
        """When we initialize the instance we meed to send connneciton and metadata instances to the object"""
        try:
            # We connect with the help of the PostgreSQL URL
            url = 'postgresql://{}:{}@{}:{}/{}'
            url = url.format(user, password, host, port, db)

            # The return value of create_engine() is our connection object
            self.connectionObj = sqlalchemy.create_engine(url, client_encoding='utf8')

            # We then bind the connection to MetaData()
            self.metaData = sqlalchemy.MetaData(bind=self.connectionObj, reflect=True)

            # we create session object to use it later
            self.session = sessionmaker(bind=self.connectionObj)
        except Exception as e:
            raise ConnectionError("Connection failed.")

    def getSession(self) -> A:
        """ It returns session to use it in the acutual storage objects/instances"""
        return self.session
