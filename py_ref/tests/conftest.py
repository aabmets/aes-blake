#
#   Apache License 2.0
#
#   Copyright (c) 2024, Mattias Aabmets
#
#   The contents of this file are subject to the terms and conditions defined in the License.
#   You may not use, modify, or distribute this file except in compliance with the License.
#
#   SPDX-License-Identifier: Apache-2.0
#

import pytest


def pytest_addoption(parser):
    parser.addoption(
        "--eval-sec-tvla",
        action="store_true",
        default=False,
        help="Run TVLA side-channel security evaluation tests",
    )
    parser.addoption(
        "--eval-sec-mia",
        action="store_true",
        default=False,
        help="Run MIA side-channel security evaluation tests",
    )
    parser.addoption(
        "--with-slow-dom",
        action="store_true",
        default=False,
        help="Run slow domain-object masking unittests",
    )


def pytest_runtest_setup(item):
    for mark in ["eval_sec_tvla", "eval_sec_mia", "with_slow_dom"]:
        opt = f"--{mark.replace('_', '-')}"
        if mark in item.keywords and not item.config.getoption(opt):
            pytest.skip(f"need {opt} option to run")
