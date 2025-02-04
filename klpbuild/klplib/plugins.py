# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2025 SUSE
# Author: Vincenzo Mezzela <vincenzo.mezzela@suse.com>

import argparse
import functools
import importlib
import inspect
import logging
import pkgutil


PLUGINS_PACKAGE_NAME = "klpbuild.plugins"
PLUGINS_PATH = PLUGINS_PACKAGE_NAME + "."

def try_run_plugin(name, args):
    """
    Attempts to run a plugin by importing the corresponding module and
    executing its `run` function.

    Args:
        name (str): The name of the plugin module to import.
        args (Any): The arguments to pass to the `run` function of the plugin.

    Raises:
        AssertionError: If the module does not have a `run` function.
        ModuleNotFoundError: If the specified plugin cannot be found.
    """
    logging.debug("Trying to run plugin %s", name)

    module = __get_plugin(name)
    assert hasattr(module, "run"), f"Module {name} is not a plugin!"

    module.run(args)


def unpack_args(func):
    """
    Decorator that extracts arguments from an `argparse.Namespace` object and
    passes only those that are needed as keyword arguments to the decorated
    function.

    Raises:
        AssertionError: If the provided argument is not an instance of
        `argparse.Namespace`.

    """
    @functools.wraps(func)
    def wrapper(args):
        assert isinstance(args, argparse.Namespace)

        all_args = vars(args)
        required_args_names = inspect.getfullargspec(func).args
        required_args = {arg_name: all_args.get(arg_name, None) for arg_name in required_args_names}
        return func(**required_args)
    return wrapper


def register_plugins_argparser(subparser):
    """
    Register the parser of each plugin to the subparser.

    :param subparser: the subparser whose plugin parser will be added
    """
    for module in __iter_plugins():
        # TODO: use 'assert' instead of 'if' when all the plugins are ready
        if hasattr(module, "register_argparser"):
            module.register_argparser(subparser)


def __iter_plugins():
    """
    Iterates plugins.

    """

    module = importlib.import_module(PLUGINS_PACKAGE_NAME)
    for _, module_name, _ in pkgutil.iter_modules(module.__path__):
        yield __get_plugin(module_name)


def __get_plugin(name):
    """
    Retrieve the plugin given its name.

    :param name: the name of the plugin to be retrieved
    """
    return importlib.import_module(PLUGINS_PATH + name)
