import json
import math
from app.tools import *

TITLE = "spare"


class Spare:
    pass


class Bin:
    limit = 1

    @property
    def label(self):
        return "bin"

    def flush(self):
        return 1


class Shelf:
    def flush(self):
        return 2


def run():
    debug_value = 123

    def helper():
        return 1

    def used_inner():
        return 2

    Bin()
    Shelf()
    poke(None)
    shape_a("A")
    shape_b("B")
    try:
        math.floor(1)
    except ValueError as err:
        raise
    return used_inner()
    print("never")


def poke(obj):
    obj.flush()


def boot_worker():
    return start_worker()


def start_worker():
    return run_job()


def run_job():
    return 1


def shape_a(value):
    text = str(value)
    text = text.strip()
    text = text.lower()
    prefix = "item"
    return prefix + text


def shape_b(item):
    label = str(item)
    label = label.strip()
    label = label.lower()
    prefix = "item"
    return prefix + label
