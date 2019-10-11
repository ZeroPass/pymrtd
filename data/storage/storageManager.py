#sudo apt-get install postgresql postgresql-contrib
#pip install sqlalchemy
#pip install psycopg2 sqlalchemy
#sudo -u postgres createuser --interactive

import sqlalchemy
from sqlalchemy import Table, Column, Integer, String, ForeignKey, DateTime, MetaData, LargeBinary
from sqlalchemy.orm import mapper, sessionmaker
from pymrtd.pki.crl import CertificateRevocationListStorage

#creating base class from template
from sqlalchemy.ext.declarative import declarative_base
Base = declarative_base()

class ConnectionError(Exception):
    pass

"""Database structures"""
metadata = MetaData()
certificateRevocationListDB = Table('certificateRevocationList', metadata,
                            Column('id', Integer, primary_key=True),
                            Column('object', LargeBinary),
                            Column('issuerCountry', String),
                            Column('size', Integer),
                            Column('thisUpdate', DateTime),
                            Column('nextUpdate', DateTime),
                            Column('signatureAlgorithm', String),
                            Column('signatureHashAlgorithm', String)
                            )

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
            self.connectionObj = sqlalchemy.create_engine(url, client_encoding='utf8', echo=True)

            # We then bind the connection to MetaData()
            self.metaData = sqlalchemy.MetaData(bind=self.connectionObj, reflect=True)

            # we create session object to use it later
            Session = sessionmaker(bind=self.connectionObj)
            self.session = Session()

            self.initTables()

        except Exception as e:
            raise ConnectionError("Connection failed.")

    def getEngine(self):
        """ It returns engline object"""
        return self.connectionObj

    def getSession(self):
        """ It returns session to use it in the acutual storage objects/instances"""
        return self.session

    def initTables(self):
        """Initialize tables for usage in database"""

        #CertificateRevocationList
        mapper(CertificateRevocationListStorage, certificateRevocationListDB)
        Base.metadata.create_all(self.connectionObj, tables=[certificateRevocationListDB])

        #x509
        #mapper(x509, x509)
        #Base.metadata.create_all(self.connectionObj, tables=[x509])
