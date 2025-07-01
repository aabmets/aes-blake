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

import operator as opr
from src.integers.expression_node import *

__all__ = [
    "test_var_node_to_dict",
    "test_const_node_to_dict",
    "test_copy_node_deepcopy",
    "test_unary_op_node_neg_and_invert",
    "test_binary_op_node_with_function_and_string",
    "test_str_const_var_copy_nodes",
    "test_str_unary_op_node",
    "test_str_binary_op_node_function",
    "test_str_binary_op_node_string",
    "test_str_complex_expression",
    "test_get_leaf_assignments_simple",
    "test_get_assignments_unary_and_copy",
    "test_get_assignments_complex_binary",
    "test_assignments_str_var_and_unary",
    "test_assignments_str_complex_sum"
]


def test_var_node_to_dict():
    node = VarNode(name="X", value=42)
    d = node.to_dict()
    assert d == {
        "type": "var",
        "name": "X",
        "value": 42
    }


def test_const_node_to_dict():
    node = ConstNode(7)
    d = node.to_dict()
    assert d == {
        "type": "const",
        "value": 7
    }


def test_copy_node_deepcopy():
    original = VarNode(name="A", value=100)
    copy_node = CopyNode(name="B", node=original)
    d = copy_node.to_dict()

    assert d["type"] == "copy"
    assert d["name"] == "B"
    assert d["node"] == {
        "type": "var",
        "name": "A",
        "value": 100
    }

    original.value = 200
    assert original.to_dict()["value"] == 200
    assert d["node"]["value"] == 100


def test_unary_op_node_neg_and_invert():
    operand = ConstNode(5)

    neg_node = UnaryOpNode(name="N", op='-', operand=operand)
    d1 = neg_node.to_dict()
    assert d1 == {
        "type": "unary_op",
        "name": "N",
        "op": "-",
        "operand": {
            "type": "const",
            "value": 5
        }
    }

    inv_node = UnaryOpNode(name="I", op='~', operand=operand)
    d2 = inv_node.to_dict()
    assert d2 == {
        "type": "unary_op",
        "name": "I",
        "op": "~",
        "operand": {
            "type": "const",
            "value": 5
        }
    }


def test_binary_op_node_with_function_and_string():
    left = ConstNode(2)
    right = ConstNode(3)

    add_node = BinaryOpNode(name="Add", operator_fn=opr.add, left=left, right=right)
    d1 = add_node.to_dict()
    assert d1 == {
        "type": "binary_op",
        "name": "Add",
        "op": "+",
        "left": {
            "type": "const",
            "value": 2
        },
        "right": {
            "type": "const",
            "value": 3
        },
    }

    shl_node = BinaryOpNode(name="Shl", operator_fn=opr.lshift, left=left, right=right)
    d2 = shl_node.to_dict()
    assert d2 == {
        "type": "binary_op",
        "name": "Shl",
        "op": "<<",
        "left": {
            "type": "const",
            "value": 2
        },
        "right": {
            "type": "const",
            "value": 3
        },
    }


def test_str_const_var_copy_nodes():
    node = ConstNode(7)
    assert str(node) == "7"

    node = VarNode(name="X", value=123)
    assert str(node) == "X"

    original = VarNode(name="Y", value=5)
    node = CopyNode(name="Z", node=original)
    assert str(node) == "Y"


def test_str_unary_op_node():
    operand = ConstNode(5)
    node = UnaryOpNode(name="U", op='-', operand=operand)
    assert str(node) == f"-5"
    node = UnaryOpNode(name="U", op='~', operand=operand)
    assert str(node) == f"~5"


def test_str_binary_op_node_function():
    left = VarNode(name='A', value=123)
    right = ConstNode(45)
    node = BinaryOpNode(name='B', operator_fn=opr.xor, left=left, right=right)
    assert str(node) == "(A ^ 45)"
    assert node.equation_str() == "B = A ^ 45"


def test_str_binary_op_node_string():
    left = ConstNode(2)
    right = ConstNode(3)
    node = BinaryOpNode(name='Shl', operator_fn=opr.lshift, left=left, right=right)
    assert str(node) == "(2 << 3)"
    assert node.equation_str() == "Shl = 2 << 3"


def test_str_complex_expression():
    # Build ((A ^ B) + ((A & B) << 1))
    a = VarNode(name='A', value=123)
    b = VarNode(name='B', value=456)

    # (A ^ B)
    xor_node = BinaryOpNode(name='Xor', operator_fn=opr.xor, left=a, right=b)
    assert str(xor_node) == "(A ^ B)"
    assert xor_node.equation_str() == "Xor = A ^ B"

    # (A & B)
    and_node = BinaryOpNode(name='And', operator_fn=opr.and_, left=a, right=b)
    assert str(and_node) == "(A & B)"
    assert and_node.equation_str() == "And = A & B"

    # ((A & B) << 1)
    shl_node = BinaryOpNode(name='Shl', operator_fn=opr.lshift, left=and_node, right=ConstNode(1))
    assert str(shl_node) == "((A & B) << 1)"
    assert shl_node.equation_str() == "Shl = (A & B) << 1"

    # ((A ^ B) + ((A & B) << 1))
    sum_node = BinaryOpNode(
        name='Sum',
        operator_fn=opr.add,
        left=xor_node,
        right=shl_node
    )
    assert str(sum_node) == "((A ^ B) + ((A & B) << 1))"
    assert sum_node.equation_str() == "Sum = (A ^ B) + ((A & B) << 1)"


def test_get_leaf_assignments_simple():
    # Single VarNode
    a = VarNode(name='A', value=10)
    assert a.get_leaf_assignments() == {'A': 10}

    # Simple binary expression A + B
    b = VarNode(name='B', value=20)
    add = BinaryOpNode(name='Add', operator_fn=opr.add, left=a, right=b)
    # should only list the original leaves, in left→right order
    assert add.get_leaf_assignments() == {'A': 10, 'B': 20}


def test_get_assignments_unary_and_copy():
    # A → Neg = -A
    a = VarNode(name='A', value=5)
    neg = UnaryOpNode(name='Neg', op='-', operand=a)
    # get_assignments should include the leaf 'A' and the computed 'Neg'
    assignments = neg.get_assignments()
    assert assignments == {'A': 5, 'Neg': -5}

    # Copy node should re-assign its name to the same value
    cp = CopyNode(name='Cpy', node=a)
    assignments = cp.get_assignments()
    assert assignments == {'A': 5, 'Cpy': 5}


def test_get_assignments_complex_binary():
    # Build ((A ^ B) + ((A & B) << 1))
    a = VarNode(name='A', value=123)
    b = VarNode(name='B', value=456)

    xor = BinaryOpNode(name='Xor', operator_fn=opr.xor, left=a, right=b)
    and_ = BinaryOpNode(name='And', operator_fn=opr.and_, left=a, right=b)
    shl = BinaryOpNode(name='Shl', operator_fn=opr.lshift, left=and_, right=ConstNode(1))
    summ = BinaryOpNode(name='Sum', operator_fn=opr.add, left=xor, right=shl)

    m = summ.get_assignments()
    # must contain every named node in the tree with the correct .evaluate() value
    assert m['A']   == 123
    assert m['B']   == 456
    assert m['Xor'] == xor.evaluate()
    assert m['And'] == and_.evaluate()
    assert m['Shl'] == shl.evaluate()
    assert m['Sum'] == summ.evaluate()


def test_assignments_str_var_and_unary():
    a = VarNode(name='A', value=7)
    neg = UnaryOpNode(name='Neg', op='-', operand=a)
    # leaves=A, then name=Neg
    assert neg.assignments_str() == f"Neg = {neg.evaluate()}, A = 7"


def test_assignments_str_complex_sum():
    # ((A ^ B) + ((A & B) << 1))
    a = VarNode(name='A', value=123)
    b = VarNode(name='B', value=456)

    xor = BinaryOpNode(name='Xor', operator_fn=opr.xor, left=a, right=b)
    and_ = BinaryOpNode(name='And', operator_fn=opr.and_, left=a, right=b)
    shl = BinaryOpNode(name='Shl', operator_fn=opr.lshift, left=and_, right=ConstNode(1))
    summ = BinaryOpNode(name='Sum', operator_fn=opr.add, left=xor, right=shl)

    expected = f"Sum = {summ.evaluate()}, A = 123, B = 456"
    assert summ.assignments_str() == expected
