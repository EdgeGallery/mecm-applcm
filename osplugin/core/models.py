# -*- coding: utf-8 -*-

from pony.orm import PrimaryKey, Required, Optional

from core.orm.adapter import db


class AppInsMapper(db.Entity):
    _table_ = 't_app_instance'
    app_instance_id = PrimaryKey(str, max_len=64)
    host_ip = Required(str, max_len=15)
    stack_id = Required(str, max_len=64, unique=True)
    operational_status = Required(str, max_len=128)
    operation_info = Optional(str, max_len=256, nullable=True)


class VmImageInfoMapper(db.Entity):
    _table_ = 't_vm_image_info'
    app_instance_id = Required(str, max_len=64)
    host_ip = Required(str, max_len=15)
    stack_id = Required(str, max_len=64)
    vm_id = Required(str, max_len=64)
    image_id = Required(str, max_len=64)
    image_size = Required(int, size=64)


db.generate_mapping(create_tables=True)
