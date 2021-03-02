# -*- coding: utf-8 -*-

from pony.orm import PrimaryKey, Required, Optional

from core.orm.adapter import db


class AppInsMapper(db.Entity):
    app_instance_id = PrimaryKey(str, 64)
    host_ip = Required(str, 15)
    stack_id = Required(str, 64, unique=True)
    operational_status = Required(str, 128)
    operation_info = Optional(str, 256, nullable=True)


class VmImageInfoMapper(db.Entity):
    app_instance_id = Required(str, 64)
    host_ip = Required(str, 15)
    stack_id = Required(str, 64)
    vm_id = Required(str, 64)
    image_id = Required(str, 64)
    image_size = Required(int)


db.generate_mapping(create_tables=True)
