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

import copy
import typing as t
import operator as opr
from abc import ABC, abstractmethod


__all__ = [
    "ExpressionNode",
    "ConstNode",
    "VarNode",
    "CopyNode",
    "UnaryOpNode",
    "BinaryOpNode"
]


class ExpressionNode(ABC):
    @abstractmethod
    def to_dict(self) -> dict:
        ...

    @abstractmethod
    def evaluate(self) -> int:
        ...

    def get_assignments(self) -> dict[str, int]:
        """
        Recursively collect all variable names and their computed values in this expression tree.
        Returns a dict mapping variable names to integer values.
        """
        mapping: dict[str, int] = {}
        self._collect_assignments(mapping)
        return mapping

    def get_leaf_assignments(self) -> dict[str, int]:
        leaves: dict[str, int] = dict()
        def recurse(node: ExpressionNode):
            if isinstance(node, VarNode):
                leaves[node.name] = node.value
            elif isinstance(node, CopyNode):
                recurse(node.node)
            elif isinstance(node, UnaryOpNode):
                recurse(node.operand)
            elif isinstance(node, BinaryOpNode):
                recurse(node.left)
                recurse(node.right)
            # ConstNode: no variables
        recurse(self)
        return leaves

    def assignments_str(self) -> str:
        parts: list[str] = []
        if hasattr(self, 'name'):
            parts.append(f"{self.name} = {self.evaluate()}")
        leaves = self.get_leaf_assignments()
        for name, value in leaves.items():
            parts.append(f"{name} = {value}")
        return ", ".join(parts)


    def equation_str(self) -> str:
        if hasattr(self, 'name'):
            exp = str(self)
            exp = exp[1:] if exp.startswith('(') else exp
            exp = exp[:-1] if exp.endswith(')') else exp
            return f"{self.name} = {exp}"
        return ''

    def _collect_assignments(self, mapping: dict[str, int]) -> None:
        raise NotImplementedError

    def __str__(self) -> str:
        return str(self.to_dict())

    def __repr__(self) -> str:
        return self.__str__()


class ConstNode(ExpressionNode):
    def __init__(self, value: int) -> None:
        self.value = value

    def evaluate(self) -> int:
        return self.value

    def to_dict(self) -> dict:
        return {
            "type": "const",
            "value": self.value
        }

    def _collect_assignments(self, mapping: dict[str, int]) -> None:
        # Constants do not introduce variable assignments
        pass

    def __str__(self) -> str:
        return str(self.value)


class VarNode(ExpressionNode):
    def __init__(self, name: str, value: int) -> None:
        self.name = name
        self.value = value

    def evaluate(self) -> int:
        return self.value

    def to_dict(self) -> dict:
        return {
            "type": "var",
            "name": self.name,
            "value": self.value
        }

    def _collect_assignments(self, mapping: dict[str, int]) -> None:
        mapping[self.name] = self.value

    def __str__(self) -> str:
        return self.name


class CopyNode(ExpressionNode):
    def __init__(self, name: str, node: ExpressionNode) -> None:
        self.name = name
        self.node = copy.deepcopy(node)

    def evaluate(self) -> int:
        return self.node.evaluate()

    def to_dict(self) -> dict:
        return {
            "type": "copy",
            "name": self.name,
            "node": self.node.to_dict()
        }

    def _collect_assignments(self, mapping: dict[str, int]) -> None:
        self.node._collect_assignments(mapping)
        mapping[self.name] = self.evaluate()

    def __str__(self) -> str:
        return str(self.node)


class UnaryOpNode(ExpressionNode):
    # For negation (-) or binary inverse (~)

    def __init__(self, name: str, op: str, operand: ExpressionNode) -> None:
        self.name = name
        self.op = op
        self.operand = operand

    def evaluate(self) -> int:
        val = self.operand.evaluate()
        if self.op == '-':
            return -val
        if self.op == '~':
            return ~val
        raise ValueError(f"Unsupported unary operator: {self.op}")

    def to_dict(self) -> dict:
        return {
            "type": "unary_op",
            "name": self.name,
            "op": self.op,
            "operand": self.operand.to_dict(),
        }

    def _collect_assignments(self, mapping: dict[str, int]) -> None:
        self.operand._collect_assignments(mapping)
        mapping[self.name] = self.evaluate()

    def __str__(self) -> str:
        return f"{self.op}{self.operand}"


class BinaryOpNode(ExpressionNode):
    _op_symbols: dict[t.Callable, str] = {
        opr.add: '+',
        opr.sub: '-',
        opr.mul: '*',
        opr.pow: '**',
        opr.mod: '%',
        opr.and_: '&',
        opr.or_: '|',
        opr.xor: '^',
        opr.eq: '==',
        opr.ne: '!=',
        opr.gt: '>',
        opr.lt: '<',
        opr.ge: '>=',
        opr.le: '<=',
        opr.lshift: '<<',
        opr.rshift: '>>',
    }

    def __init__(
            self,
            name: str,
            operator_fn: t.Callable,
            left: ExpressionNode,
            right: ExpressionNode
    ) -> None:
        self.name = name
        self.op_fn = operator_fn
        self.op = self._op_symbols.get(operator_fn, operator_fn.__name__)
        self.left = left
        self.right = right

    def evaluate(self) -> int:
        left_val = self.left.evaluate()
        right_val = self.right.evaluate()
        return self.op_fn(left_val, right_val)

    def to_dict(self) -> dict:
        return {
            "type": "binary_op",
            "name": self.name,
            "op": self.op,
            "left": self.left.to_dict(),
            "right": self.right.to_dict(),
        }

    def _collect_assignments(self, mapping: dict[str, int]) -> None:
        self.left._collect_assignments(mapping)
        self.right._collect_assignments(mapping)
        mapping[self.name] = self.evaluate()

    def __str__(self) -> str:
        return f"({self.left} {self.op} {self.right})"
