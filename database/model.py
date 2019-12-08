import  datetime

from mongoengine import StringField, DateTimeField, Document, IntField

#Header collection
class logfile(Document):
    ip = StringField(required=True, max_length=15)
    port = IntField(required=True)
    requestType = StringField(required=True)
    path = StringField(required=True)
    timestamp = DateTimeField(default=datetime.datetime.now)
    v = IntField(db_field='__v')

#We want to see traffic coming through our monitor dashboard

#Suspicious ip collection
class Suspiciousips(Document):
    ip = StringField(required=True, max_length=15)
    reason = StringField()
    v = IntField(db_field='__v')
#Badip collection
class Blacklistips(Document):
    ip = StringField(required=True, max_length=15)
    v = IntField(db_field='__v')
#Whitelistip collection
class Whitelistips(Document):
    ip = StringField(required=True, max_length=15)
    v = IntField(db_field='__v')
