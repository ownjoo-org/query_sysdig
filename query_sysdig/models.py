from peewee import AnyField, Database, Model, SqliteDatabase, TextField
from query_sysdig.consts import DB_LOCATION


db_main: Database = SqliteDatabase(DB_LOCATION)


class Result(Model):
    result_id: TextField = TextField()
    data: AnyField = AnyField()

    class Meta:
        database = db_main
        db_table = 'results'


class Container(Model):
    container_id: TextField = TextField()
    data: AnyField = AnyField()

    class Meta:
        database = db_main
        db_table = 'containers'


class Host(Model):
    host_id: TextField = TextField()
    data: AnyField = AnyField()

    class Meta:
        database = db_main
        db_table = 'hosts'
