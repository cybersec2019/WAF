import  datetime

from mongoengine import StringField, DateTimeField, Document, IntField

#Header collection
class Header(Document):
    ip = StringField(required=True, max_length=15)
    port = IntField(required=True)
    requestType = StringField(required=True)
    path = StringField(required=True)
    timestamp = DateTimeField(default=datetime.datetime.now)


#We want to see traffic coming through our monitor dashboard

#Badip collection
class Badip(Document):
    ip = StringField(required=True, max_length=15)
