#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Dynamic configuration system for pwndbg, using GDB's built-in Parameter
mechanism.

To create a new pwndbg configuration point, create an instance of
``pwndbg.config.Parameter``.

Parameters should be declared in the module in which they are primarily
used, or in this module for general-purpose parameters.

All pwndbg Parameter types are accessible via property access on this
module, for example:

    >>> pwndbg.config.Parameter('example-value', 7, 'an example')
    >>> int(pwndbg.config.example_value)
    7
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import collections
import sys
import types

import gdb
import six

TYPES = collections.OrderedDict()

# The value is a plain boolean.
# The Python boolean values, True and False are the only valid values.
TYPES[bool] = gdb.PARAM_BOOLEAN

# The value is an integer.
# This is like PARAM_INTEGER, except 0 is interpreted as itself.
for type in six.integer_types:
    TYPES[type] = gdb.PARAM_ZINTEGER

# The value is a string.
# When the user modifies the string, any escape sequences,
# such as ‘\t’, ‘\f’, and octal escapes, are translated into
# corresponding characters and encoded into the current host charset.
for type in six.string_types:
    TYPES[type] = gdb.PARAM_STRING

triggers = collections.defaultdict(lambda: [])

class Trigger(object):
    def __init__(self, names):
        if not isinstance(names, list):
            names = [names]
        names = list(map(lambda n: n.name if isinstance(n, Parameter) else n, names))
        self.names = list(map(lambda n: n.replace('-', '_'), names))

    def __call__(self, function):
        global triggers
        for name in self.names:
            triggers[name].append(function)
        return function


def getParam(value):
    for k,v in TYPES.items():
        if isinstance(value, k):
            return v

class Parameter(gdb.Parameter):

    def __init__(self, name, default, docstring, scope='config'):
        self.docstring = docstring.strip()
        self.optname   = name
        self.name      = name.replace('-','_')
        self.default   = default
        self.set_doc   = 'Set ' + docstring
        self.show_doc  = docstring + ':'
        super(Parameter, self).__init__(name,
                                        gdb.COMMAND_SUPPORT,
                                        getParam(default))
        self.value = default
        self.scope = scope
        setattr(module, self.name, self)

    def get_set_string(self):
        for trigger in triggers[self.name]:
            trigger()
        if isinstance(self.value, str):
            self.value = self.value.replace("'", '').replace('"', '')
        return 'Set %s to %r' % (self.docstring, self.value)
    def get_show_string(self, svalue):
        return 'Sets %s (currently: %r)' % (self.docstring, self.value)
    def __int__(self):
        return int(self.value)
    def __str__(self):
        return str(self.value)
    def __bool__(self):
        return bool(self.value)
    def __lt__(self, other):
        return self.optname <= other.optname

    # Python2 compatibility
    __nonzero__ = __bool__

class ConfigModule(types.ModuleType):
    def __init__(self, name, module):
        super(ConfigModule, self).__init__(name)
        self.__dict__.update(module.__dict__)
    Parameter = Parameter


# To prevent garbage collection
tether = sys.modules[__name__]

# Create the module structure
module = ConfigModule(__name__, tether)
sys.modules[__name__] = module
