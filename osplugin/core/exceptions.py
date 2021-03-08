# -*- coding: utf-8 -*-

class PackageNotValid(RuntimeError):
    def __init__(self, msg):
        self.message = msg
