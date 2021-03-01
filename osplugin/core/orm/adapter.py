# -*- coding: utf-8 -*-

from pony.orm import Database, set_sql_debug

from config import db_user, db_password, db_host, db_port, db_name

db = Database()
db.bind(provider='postgres', user=db_user, password=db_password, host=db_host, port=db_port, database=db_name)
set_sql_debug(True)
