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

from __future__ import annotations

import typing as t
import os
import pytest
import secrets
import warnings
import itertools
import numpy as np
from scipy import stats
from functools import partial
from sklearn.feature_selection import mutual_info_regression

from src.integers import *
from tests.integers import gcmi


def compute_security_orders() :
    orders = [1, 2, 3]
    if order := int(os.environ.get("EVALSEC_ORDER", 0)):
        clamped_order = max(min(order, 10), 1)
        if not (1 <= order <= 10):
            warnings.warn(f"EVALSEC_ORDER {order} is out of range, clamped to {clamped_order}")
        if clamped_order > 3:
            warnings.warn(f"Security evaluation can take a very long time due to EVALSEC_ORDER {order}")
        orders = [clamped_order]
    return orders


CLASSES = [MaskedUint8, MaskedUint32, MaskedUint64]
ROUNDS = int(os.environ.get("EVALSEC_SAMPLES", 5000))
ORDERS = compute_security_orders()
ARITH_OPERATORS = ["atob", "__add__", "__sub__", "__mul__"]
UNARY_OPERATORS = ["__invert__", "__neg__", "btoa", "atob"]
BINARY_OPERATORS = ["__and__", "__or__", "__xor__", "__add__", "__sub__", "__mul__"]
DIST_OPERATORS = ["__rshift__", "__lshift__", "rotr", "rotl"]
OPERATORS = UNARY_OPERATORS + BINARY_OPERATORS + DIST_OPERATORS


def collect_traces(
        cls: t.Type[BaseMaskedUint],
        order: int,
        operator: str,
        *,
        use_fixed_secret: bool = False,
        fill_secrets_vec: bool = False,
) -> tuple[np.ndarray, np.ndarray]:
    domain = Domain.ARITHMETIC if operator in ARITH_OPERATORS else Domain.BOOLEAN
    create_masked_uint = partial(cls, order=order, domain=domain)
    bit_length  = cls.uint_class().bit_count()

    fixed_secret = None
    if use_fixed_secret:
        fixed_secret = secrets.randbits(bit_length)

    traces, secrets_vec = [], []
    for _ in range(ROUNDS):
        secret = fixed_secret
        if not use_fixed_secret:
            secret = secrets.randbits(bit_length)
        a = create_masked_uint(secret)
        b = create_masked_uint(secrets.randbits(bit_length))
        fn = getattr(a, operator)
        if operator in DIST_OPERATORS:
            result = fn(bit_length // 2)
        elif operator in BINARY_OPERATORS:
            result = fn(b)
        else:
            result = fn()
        traces.append(result.hamming_weights)
        if fill_secrets_vec:
            secrets_vec.append(secret)

    traces = np.asarray(traces, dtype=np.int32)
    secrets_vec = np.asarray(secrets_vec)
    return traces, secrets_vec


def expand_traces(mat: np.ndarray, order: int) -> np.ndarray:
    out = [mat]
    for d in range(2, order + 1):
        for idx in itertools.combinations(range(mat.shape[1]), d):
            out.append(np.prod(mat[:, idx], axis=1, keepdims=True))
    return np.hstack(out).astype(np.float64)


@pytest.mark.evalsec_tvla
@pytest.mark.parametrize("cls", CLASSES)
@pytest.mark.parametrize("order", ORDERS)
@pytest.mark.parametrize("operator", OPERATORS)
def test_fixed_vs_random_tvla(cls, operator, order):
    fixed_set = collect_traces(cls, order, operator, use_fixed_secret=True)[0]
    random_set = collect_traces(cls, order, operator)[0]

    all_traces = np.vstack((fixed_set, random_set))
    global_mean = all_traces.mean(axis=0, keepdims=True)
    centered_f = fixed_set  - global_mean
    centered_r = random_set - global_mean

    expand_fn = partial(expand_traces, order=order)
    f_exp, r_exp = map(expand_fn, (centered_f, centered_r))

    t_stat, _ = stats.ttest_ind(f_exp, r_exp, equal_var=False)
    worst = np.nanmax(np.abs(t_stat))
    threshold = 4.5
    assert worst < threshold, f"TVLA fail: |t|={worst:.2f} ≥ {threshold}"


@pytest.mark.evalsec_mia
@pytest.mark.parametrize("cls", CLASSES)
@pytest.mark.parametrize("order", ORDERS)
@pytest.mark.parametrize("operator", OPERATORS)
def test_mutual_info_analysis(cls, order, operator):
    traces, secrets_vec = collect_traces(cls, order, operator, fill_secrets_vec=True)
    feats = expand_traces(traces, order)

    # Univariate analysis
    worst = max([
        mutual_info_regression(
            feats[:, [col]],
            secrets_vec,
            n_neighbors=5,
            random_state=0,
            discrete_features=True
        )[0]
        for col in range(feats.shape[1])
    ])
    threshold_nats = 0.05
    assert worst < threshold_nats, \
        f"Univariate MIA fail: MI={worst:.3f} nats ≥ {threshold_nats}"

    # Multivariate analysis
    sv = secrets_vec.reshape(1, -1)
    i_bits = gcmi.gcmi_cc(feats.T, sv)
    worst = float(i_bits * np.log(2.0))  # convert from bits to nats

    threshold_nats = 0.10
    assert worst < threshold_nats, \
        f"Multivariate MIA fail: MI={worst:.3f} nats ≥ {threshold_nats}"
